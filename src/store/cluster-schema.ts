/**
 * OneGate cluster: which tables replicate, and the change-capture triggers.
 *
 * Every table in the database is classified here as either SHARED (its rows
 * replicate to every node of a cluster) or LOCAL (it never leaves the node).
 * The classification is the single source of truth for both the capture
 * triggers and the apply side, and test/cluster-schema.test.ts fails when a
 * table or a column appears that is not classified, so a schema change cannot
 * silently stop replicating (or silently start leaking node-local state).
 *
 * Change capture is done with SQLite triggers rather than by instrumenting the
 * Store methods, so a write from any code path (including future ones, and the
 * FK cascades SQLite performs on our behalf) is captured. The triggers are TEMP
 * triggers, installed per connection by a Store whose node is a cluster member
 * (see Store.syncClusterCapture). That choice is deliberate:
 *  - a node that never ran `cluster init`/`join` has no triggers at all, so its
 *    write path is byte-for-byte what it was before clustering existed;
 *  - nothing persistent references cluster objects, so an older OneGate build
 *    (a rollback) or the sqlite3 shell can still write to the database. Their
 *    writes are simply not captured, which docs/CLUSTER.md calls out.
 */

/** One replicated table: its primary key and the columns that travel. */
export interface SharedTableSpec {
  table: string;
  /** Primary-key columns, in declaration order. */
  pk: readonly string[];
  /** Every replicated column, primary key included. */
  columns: readonly string[];
  /**
   * Columns that exist on the table but deliberately never replicate. They are
   * left out of the row image and never written on apply.
   */
  excluded?: readonly string[];
  /**
   * Row filter (SQL over `alias.col`). Only matching rows replicate. Used for
   * `settings`, where most keys are node-local.
   */
  filter?: (alias: string) => string;
}

/**
 * Settings keys that replicate. Everything else in `settings` is node-local:
 * the cluster's own state (`cluster.*`: node id, cluster secret, advertise URL),
 * and the upstream access-token caches (`oauth_access_token:*`,
 * `gcp_access_token:*`, `github_app_token:*`, `docker_hub_jwt:*`), which each
 * node mints for itself. An allow list rather than a deny list: a future setting
 * stays on its node until someone decides it should be shared, which is the
 * failure mode that cannot leak node identity into a peer.
 */
export const SHARED_SETTING_KEYS: readonly string[] = ["admin_token_hash"];

/** Prefix of the node-local settings that hold this node's cluster state. */
export const CLUSTER_SETTING_PREFIX = "cluster.";

function settingsFilter(alias: string): string {
  return `${alias}.key IN (${SHARED_SETTING_KEYS.map(sqlString).join(", ")})`;
}

export const SHARED_TABLES: readonly SharedTableSpec[] = [
  { table: "projects", pk: ["id"], columns: ["id", "name", "created_at"] },
  {
    table: "agents",
    pk: ["id"],
    columns: ["id", "name", "token_hash", "project_id", "default_policy", "created_at"],
  },
  {
    table: "credentials",
    pk: ["id"],
    columns: ["id", "integration_id", "name", "data", "created_at"],
  },
  {
    table: "rules",
    pk: ["id"],
    columns: [
      "id",
      "scope",
      "subject_id",
      "integration_id",
      "methods",
      "path_glob",
      "effect",
      "created_at",
      "expires_at",
      "lease_ttl_seconds",
      "connection_id",
      "connection_scope",
      "created_by",
      "action",
    ],
  },
  {
    table: "integration_leases",
    pk: ["integration_id"],
    columns: ["integration_id", "ttl_seconds", "updated_at"],
  },
  {
    table: "connections",
    pk: ["id"],
    columns: [
      "id",
      "kind",
      "vendor",
      "name",
      "data",
      "owner_agent_id",
      "is_default",
      "lease_ttl_seconds",
      "inactive_at",
      "inactive_reason",
      "created_at",
      "updated_at",
    ],
    // A per-node counter of consecutive upstream 401s. Each node counts what IT
    // saw; the outcome (inactive_at) is what replicates.
    excluded: ["auth_failures"],
  },
  {
    table: "connection_grants",
    pk: ["connection_id", "scope", "subject_id"],
    columns: ["connection_id", "scope", "subject_id", "created_at"],
  },
  {
    table: "agent_app_config",
    pk: ["agent_id", "integration_id"],
    columns: ["agent_id", "integration_id", "connection_id", "updated_at"],
  },
  {
    table: "agent_llm_config",
    pk: ["agent_id"],
    columns: ["agent_id", "enabled", "strategy", "vendor_strategies", "connection_ids", "updated_at"],
  },
  {
    table: "agent_notify",
    pk: ["agent_id"],
    columns: ["agent_id", "webhook_url", "created_at", "updated_at"],
  },
  {
    table: "onboarding_links",
    pk: ["token_hash"],
    columns: [
      "token_hash",
      "agent_id",
      "integration_id",
      "scopes",
      "connection_name",
      "created_at",
      "expires_at",
      "used_at",
      "rule_id",
    ],
  },
  {
    table: "approvals",
    pk: ["id"],
    columns: [
      "id",
      "agent_id",
      "integration_id",
      "rule_id",
      "method",
      "path",
      "token_hash",
      "status",
      "created_at",
      "expires_at",
      "decided_at",
    ],
  },
  { table: "settings", pk: ["key"], columns: ["key", "value"], filter: settingsFilter },
  { table: "cluster_peers", pk: ["node_id"], columns: ["node_id", "url", "added_at"] },
];

/**
 * Tables that never leave the node. Per-node observations (audit, usage, the
 * LLM router's rotation state, the owner-notification outbox) and the cluster
 * machinery's own bookkeeping.
 */
export const LOCAL_TABLES: readonly string[] = [
  "audit",
  "llm_usage",
  "llm_strategy_state",
  "owner_notifications",
  "cluster_changelog",
  "cluster_row_meta",
  "cluster_cursors",
  "cluster_acks",
  "cluster_conflicts",
  "cluster_join_tokens",
];

const SHARED_BY_NAME = new Map(SHARED_TABLES.map((s) => [s.table, s]));

export function sharedTableSpec(table: string): SharedTableSpec | undefined {
  return SHARED_BY_NAME.get(table);
}

/**
 * Cluster tables. Created on every database (empty tables cost nothing and an
 * older build ignores them), so an upgrade is purely additive.
 */
export const CLUSTER_SCHEMA = `
-- Cluster membership. Replicated, so every node learns every peer and pulls
-- from it directly (full mesh).
CREATE TABLE IF NOT EXISTS cluster_peers (
  node_id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  added_at TEXT NOT NULL
);
-- Changes made ON THIS NODE to shared tables, in commit order. Peers pull it.
-- ts is the writing node's clock in ms; origin is always this node's id.
CREATE TABLE IF NOT EXISTS cluster_changelog (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  tbl TEXT NOT NULL,
  pk TEXT NOT NULL,
  op TEXT NOT NULL CHECK (op IN ('upsert','delete')),
  row TEXT,
  ts INTEGER NOT NULL,
  origin TEXT NOT NULL
);
-- The winning version of every replicated row this node has seen, tombstones
-- included. Last-writer-wins compares (ts, origin) against it.
CREATE TABLE IF NOT EXISTS cluster_row_meta (
  tbl TEXT NOT NULL,
  pk TEXT NOT NULL,
  ts INTEGER NOT NULL,
  origin TEXT NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tbl, pk)
);
-- Per peer: how far into ITS changelog this node has applied, plus health.
CREATE TABLE IF NOT EXISTS cluster_cursors (
  peer_node_id TEXT PRIMARY KEY,
  seq INTEGER NOT NULL DEFAULT 0,
  remote_head INTEGER,
  last_ok_at TEXT,
  last_error TEXT,
  last_error_at TEXT,
  clock_skew_ms INTEGER
);
-- Per peer: how far into THIS node's changelog the peer has pulled (its last
-- 'since'). Drives changelog compaction.
CREATE TABLE IF NOT EXISTS cluster_acks (
  peer_node_id TEXT PRIMARY KEY,
  seq INTEGER NOT NULL,
  at TEXT NOT NULL
);
-- Unique-constraint collisions resolved on this node (two nodes created the
-- same name concurrently). Kept for operators; never replicated.
CREATE TABLE IF NOT EXISTS cluster_conflicts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  tbl TEXT NOT NULL,
  winner_pk TEXT NOT NULL,
  loser_pk TEXT NOT NULL,
  detail TEXT
);
-- Single-use join tokens minted on this node. id is the SHA-256 of the token;
-- sealed_key is the token-derived payload key, sealed with the DB key and
-- erased on use (see src/cluster/crypto.ts for why it is kept at all).
CREATE TABLE IF NOT EXISTS cluster_join_tokens (
  id TEXT PRIMARY KEY,
  sealed_key TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
`;

/** Connection-scoped table whose presence suppresses capture while applying. */
export const CAPTURE_GUARD_TABLE = "og_cluster_guard";

/** ms since the epoch, as SQLite computes it inside a trigger. */
const NOW_MS = "CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)";

export function sqlString(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}

/** A node id is embedded in trigger SQL, so it is restricted to a safe alphabet. */
export function isValidNodeId(id: string): boolean {
  return /^[A-Za-z0-9_-]{4,64}$/.test(id);
}

function pkExpr(spec: SharedTableSpec, alias: string): string {
  return `json_array(${spec.pk.map((c) => `${alias}.${c}`).join(", ")})`;
}

function rowExpr(spec: SharedTableSpec, alias: string): string {
  return `json_object(${spec.columns.map((c) => `'${c}', ${alias}.${c}`).join(", ")})`;
}

/**
 * Trigger body: bump the row's version in cluster_row_meta, then append the
 * change carrying that version. The new ts is max(now, previous ts + 1), so a
 * local edit always supersedes the version this node last saw for the row,
 * even when that version came from a peer whose clock runs ahead. It also keeps
 * two edits within the same millisecond ordered.
 */
function captureBody(spec: SharedTableSpec, alias: string, op: "upsert" | "delete", nodeId: string): string {
  const tbl = sqlString(spec.table);
  const pk = pkExpr(spec, alias);
  const origin = sqlString(nodeId);
  const row = op === "upsert" ? rowExpr(spec, alias) : "NULL";
  return `
  INSERT INTO cluster_row_meta (tbl, pk, ts, origin, deleted)
    VALUES (${tbl}, ${pk},
      MAX(${NOW_MS}, COALESCE((SELECT ts + 1 FROM cluster_row_meta WHERE tbl = ${tbl} AND pk = ${pk}), 0)),
      ${origin}, ${op === "delete" ? 1 : 0})
    ON CONFLICT (tbl, pk) DO UPDATE SET ts = excluded.ts, origin = excluded.origin, deleted = excluded.deleted;
  INSERT INTO cluster_changelog (tbl, pk, op, row, ts, origin)
    SELECT ${tbl}, ${pk}, '${op}', ${row}, ts, ${origin} FROM cluster_row_meta WHERE tbl = ${tbl} AND pk = ${pk};`;
}

/** Names of the capture triggers for a table (used to drop them). */
export function captureTriggerNames(spec: SharedTableSpec): string[] {
  return ["ins", "upd", "updpk", "del"].map((s) => `og_cluster_${spec.table}_${s}`);
}

/**
 * TEMP trigger DDL for one shared table. UPDATE triggers are column-scoped
 * (`UPDATE OF <replicated columns>`) and skip no-op updates, so a write that
 * touches only an excluded column (connections.auth_failures, bumped on every
 * upstream response) never reaches the changelog.
 */
export function captureTriggerSql(spec: SharedTableSpec, nodeId: string): string[] {
  if (!isValidNodeId(nodeId)) throw new Error(`invalid cluster node id: ${nodeId}`);
  const [ins, upd, updpk, del] = captureTriggerNames(spec);
  const guard = `NOT EXISTS (SELECT 1 FROM ${CAPTURE_GUARD_TABLE})`;
  const f = (alias: string) => (spec.filter ? ` AND ${spec.filter(alias)}` : "");
  const changed = `${rowExpr(spec, "OLD")} IS NOT ${rowExpr(spec, "NEW")}`;
  const pkChanged = `${pkExpr(spec, "OLD")} IS NOT ${pkExpr(spec, "NEW")}`;
  return [
    `CREATE TEMP TRIGGER IF NOT EXISTS ${ins} AFTER INSERT ON main.${spec.table}
     WHEN ${guard}${f("NEW")}
     BEGIN${captureBody(spec, "NEW", "upsert", nodeId)}
     END`,
    `CREATE TEMP TRIGGER IF NOT EXISTS ${upd} AFTER UPDATE OF ${spec.columns.join(", ")} ON main.${spec.table}
     WHEN ${guard}${f("NEW")} AND ${changed}
     BEGIN${captureBody(spec, "NEW", "upsert", nodeId)}
     END`,
    // A primary-key change is a delete of the old identity plus an upsert of
    // the new one (the upd trigger above covers the upsert).
    `CREATE TEMP TRIGGER IF NOT EXISTS ${updpk} AFTER UPDATE OF ${spec.pk.join(", ")} ON main.${spec.table}
     WHEN ${guard}${f("OLD")} AND ${pkChanged}
     BEGIN${captureBody(spec, "OLD", "delete", nodeId)}
     END`,
    `CREATE TEMP TRIGGER IF NOT EXISTS ${del} AFTER DELETE ON main.${spec.table}
     WHEN ${guard}${f("OLD")}
     BEGIN${captureBody(spec, "OLD", "delete", nodeId)}
     END`,
  ];
}

/** Minimal surface of node:sqlite's DatabaseSync used here. */
interface Execer {
  exec(sql: string): void;
}

/** Installs the capture triggers (and the apply guard table) on a connection. */
export function installCapture(db: Execer, nodeId: string): void {
  db.exec(`CREATE TEMP TABLE IF NOT EXISTS ${CAPTURE_GUARD_TABLE} (active INTEGER)`);
  for (const spec of SHARED_TABLES) {
    for (const sql of captureTriggerSql(spec, nodeId)) db.exec(sql);
  }
}

/** Drops every capture trigger from a connection. */
export function removeCapture(db: Execer): void {
  for (const spec of SHARED_TABLES) {
    for (const name of captureTriggerNames(spec)) db.exec(`DROP TRIGGER IF EXISTS temp.${name}`);
  }
}
