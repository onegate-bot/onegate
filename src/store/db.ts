/**
 * Persistence layer on top of Node's built-in sqlite (node:sqlite, Node >= 22.13).
 * Synchronous API, WAL mode. One Store per process.
 */

import { createRequire } from "node:module";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { SecretBox, loadSecretKey } from "./secret-box.js";
import type {
  Agent,
  AgentAppConfig,
  AgentLlmConfig,
  AuditEntry,
  Connection,
  ConnectionKind,
  ConnectionScope,
  Credential,
  Decision,
  DefaultPolicy,
  IntegrationLease,
  LlmStrategy,
  LlmStrategyState,
  LlmUsageEvent,
  OnboardingLink,
  OwnerNotification,
  OwnerNotificationStatus,
  Project,
  Rule,
  RuleScope,
} from "../types.js";
import { auditReason, auditSource } from "../audit-meta.js";

// node:sqlite is a prefix-only builtin; bundlers (vite/vitest) fail to
// resolve a bare ESM import of it, so load it via createRequire.
const requireBuiltin = createRequire(import.meta.url);
const { DatabaseSync } = requireBuiltin("node:sqlite") as typeof import("node:sqlite");
type DatabaseSync = import("node:sqlite").DatabaseSync;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  token_hash TEXT NOT NULL UNIQUE,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  default_policy TEXT NOT NULL DEFAULT 'deny-unmatched',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  integration_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  data TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rules (
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL CHECK (scope IN ('agent','project')),
  subject_id TEXT NOT NULL,
  integration_id TEXT NOT NULL,
  methods TEXT NOT NULL,
  path_glob TEXT NOT NULL,
  effect TEXT NOT NULL CHECK (effect IN ('allow','deny')),
  created_at TEXT NOT NULL,
  expires_at TEXT,
  lease_ttl_seconds INTEGER,
  connection_id TEXT,
  connection_scope TEXT CHECK (connection_scope IN ('only','except'))
);
CREATE INDEX IF NOT EXISTS idx_rules_subject ON rules(scope, subject_id);
-- Time-boxed integrations: presence of a row marks the integration as
-- time-boxed by default; ttl_seconds is the default access-lease duration.
CREATE TABLE IF NOT EXISTS integration_leases (
  integration_id TEXT PRIMARY KEY,
  ttl_seconds INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  agent_id TEXT,
  agent_name TEXT,
  integration_id TEXT,
  host TEXT NOT NULL,
  method TEXT,
  path TEXT,
  decision TEXT NOT NULL,
  rule_id TEXT,
  status INTEGER,
  connection_id TEXT,
  connection_name TEXT,
  llm_vendor TEXT,
  llm_strategy TEXT,
  llm_failover INTEGER
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS connections (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('app','llm')),
  vendor TEXT NOT NULL,
  name TEXT NOT NULL,
  data TEXT NOT NULL,
  owner_agent_id TEXT,
  is_default INTEGER NOT NULL DEFAULT 0,
  lease_ttl_seconds INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_connections_vendor ON connections(kind, vendor);
CREATE TABLE IF NOT EXISTS connection_grants (
  connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
  scope TEXT NOT NULL CHECK (scope IN ('agent','project')),
  subject_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (connection_id, scope, subject_id)
);
CREATE INDEX IF NOT EXISTS idx_connection_grants_subject ON connection_grants(scope, subject_id);
CREATE TABLE IF NOT EXISTS agent_app_config (
  agent_id TEXT NOT NULL,
  integration_id TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (agent_id, integration_id)
);
CREATE TABLE IF NOT EXISTS agent_llm_config (
  agent_id TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 0,
  strategy TEXT NOT NULL DEFAULT 'fallback' CHECK (strategy IN ('fallback','round-robin')),
  vendor_strategies TEXT,
  connection_ids TEXT NOT NULL DEFAULT '[]',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS llm_strategy_state (
  agent_id TEXT NOT NULL,
  vendor TEXT NOT NULL,
  active_index INTEGER NOT NULL DEFAULT 0,
  rr_cursor INTEGER NOT NULL DEFAULT -1,
  calls_since_fallback INTEGER NOT NULL DEFAULT 0,
  cooldowns TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (agent_id, vendor)
);
CREATE TABLE IF NOT EXISTS llm_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  connection_name TEXT,
  agent_id TEXT,
  vendor TEXT,
  model TEXT,
  strategy TEXT,
  requests INTEGER NOT NULL DEFAULT 0,
  errors INTEGER NOT NULL DEFAULT 0,
  input_tokens INTEGER,
  output_tokens INTEGER,
  selected INTEGER NOT NULL DEFAULT 1,
  failover INTEGER NOT NULL DEFAULT 0,
  status INTEGER
);
CREATE INDEX IF NOT EXISTS idx_llm_usage_conn ON llm_usage(connection_id, ts);
-- ESTIMATED conversational turns derived from the raw request log. OneGate only
-- sees HTTP LLM requests, not turns, so a turn is inferred: a new turn opens
-- when an agent's gap since its previous request exceeds 60000 ms (mirrors
-- TURN_GAP_MS in db.ts). The "estimated" in the view name is deliberate: these
-- counts are a HEURISTIC, not exact. Roll up with
--   SELECT agent_id, vendor, model, SUM(is_turn_start) AS estimated_turns
--   FROM llm_turns_estimated GROUP BY agent_id, vendor, model;
CREATE VIEW IF NOT EXISTS llm_turns_estimated AS
  WITH ordered AS (
    SELECT agent_id, vendor, model, ts,
           LAG(ts) OVER (PARTITION BY agent_id ORDER BY ts, id) AS prev_ts
    FROM llm_usage
  )
  SELECT agent_id, vendor, model, ts,
         CASE
           WHEN prev_ts IS NULL
                OR (julianday(ts) - julianday(prev_ts)) * 86400000.0 > 60000
           THEN 1 ELSE 0
         END AS is_turn_start
  FROM ordered;
CREATE TABLE IF NOT EXISTS onboarding_links (
  token_hash TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  integration_id TEXT NOT NULL,
  scopes TEXT,
  connection_name TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  rule_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_onboarding_links_agent ON onboarding_links(agent_id);
CREATE TABLE IF NOT EXISTS agent_notify (
  agent_id TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
  webhook_url TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS owner_notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id TEXT NOT NULL,
  integration_id TEXT NOT NULL,
  connect_token TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  last_attempt_at TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  dedup_key TEXT
);
CREATE INDEX IF NOT EXISTS idx_owner_notifications_pair ON owner_notifications(agent_id, integration_id);
`;

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function newId(prefix: string): string {
  return `${prefix}_${randomBytes(8).toString("hex")}`;
}

/** Generates a new agent token. Only its hash is stored. */
export function newAgentToken(): string {
  return `og_${randomBytes(24).toString("hex")}`;
}

function now(): string {
  return new Date().toISOString();
}

/**
 * Clamp a list `limit` to [1, max], defaulting to `def` when unset. Defends
 * against a caller passing a negative, zero, or non-integer limit: SQLite treats
 * `LIMIT -1` as "no limit", so an unclamped negative value would return the
 * entire table (memory/latency DoS). Non-finite/non-integer values fall back to
 * the default. The API layer rejects such values with a 400; this is
 * defense-in-depth so the store never emits an unbounded query.
 */
function clampLimit(limit: number | undefined, def: number, max: number): number {
  if (limit === undefined || !Number.isInteger(limit)) return def;
  return Math.max(1, Math.min(limit, max));
}

/**
 * Integrations that are time-boxed out of the box, with their default access
 * lease (seconds). Seeded idempotently on boot (INSERT OR IGNORE), so an
 * operator can later change or clear a TTL without it being reset. Hetzner
 * (infrastructure control) defaults to an 8h lease; every other integration is
 * regular (non-time-boxed) unless an operator marks it via `integrations lease`.
 */
export const DEFAULT_INTEGRATION_LEASES: ReadonlyArray<readonly [string, number]> = [
  ["hetzner", 8 * 60 * 60],
];

/** WHERE clause + params for an optional ISO time range over llm_usage.ts. */
function usageRange(range: { since?: string; until?: string }): {
  where: string;
  params: string[];
} {
  const clauses: string[] = [];
  const params: string[] = [];
  if (range.since) {
    clauses.push("ts >= ?");
    params.push(range.since);
  }
  if (range.until) {
    clauses.push("ts <= ?");
    params.push(range.until);
  }
  return { where: clauses.length ? ` WHERE ${clauses.join(" AND ")}` : "", params };
}

/**
 * Inactivity gap (ms) that separates one conversational turn from the next.
 *
 * A bot processes inbound messages serially, so the pause between turns
 * (waiting for the next user message) is normally far larger than the
 * sub-second gaps between the agentic loop's internal LLM requests inside a
 * single turn. Grouping requests by this gap yields a turn count.
 *
 * This is a HEURISTIC, so every turn count derived from it is an ESTIMATE,
 * never a billing-grade count: a tool call that runs longer than the gap
 * splits one turn into two, and a rapid follow-up shorter than the gap merges
 * two turns into one. The DB exposes it through the `llm_turns_estimated`
 * view (named so raw analytics see the "estimated" label) and the API/UI tag
 * the numbers "estimate" for the same reason.
 */
export const TURN_GAP_MS = 60_000;

/**
 * Segment an agent's LLM requests into estimated turns. `rows` MUST be ordered
 * by agent then ascending ts. A new turn opens whenever the gap from the same
 * agent's previous request exceeds `gapMs`; the turn is attributed to the
 * (vendor, model) of the request that opened it. ESTIMATE only (see
 * TURN_GAP_MS). Returns a map keyed `agentId|vendor|model`.
 */
export function segmentTurns(
  rows: Array<{ agentId: string | null; vendor: string | null; model: string | null; ts: string }>,
  gapMs: number = TURN_GAP_MS,
): Map<string, { agentId: string | null; vendor: string | null; model: string | null; turns: number }> {
  const out = new Map<
    string,
    { agentId: string | null; vendor: string | null; model: string | null; turns: number }
  >();
  let prevAgent: string | null | undefined;
  let prevMs = 0;
  for (const r of rows) {
    const ms = Date.parse(r.ts);
    const sameAgent = prevAgent !== undefined && r.agentId === prevAgent;
    const isTurnStart = !sameAgent || !Number.isFinite(ms) || !Number.isFinite(prevMs) || ms - prevMs > gapMs;
    if (isTurnStart) {
      const key = `${r.agentId ?? ""}|${r.vendor ?? ""}|${r.model ?? ""}`;
      const cur = out.get(key);
      if (cur) cur.turns += 1;
      else out.set(key, { agentId: r.agentId, vendor: r.vendor, model: r.model, turns: 1 });
    }
    prevAgent = r.agentId;
    prevMs = ms;
  }
  return out;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
type Row = Record<string, any>;

function rowToAgent(r: Row): Agent {
  return {
    id: r.id,
    name: r.name,
    tokenHash: r.token_hash,
    projectId: r.project_id ?? null,
    defaultPolicy: r.default_policy as DefaultPolicy,
    createdAt: r.created_at,
  };
}

function rowToRule(r: Row): Rule {
  return {
    id: r.id,
    scope: r.scope as RuleScope,
    subjectId: r.subject_id,
    integrationId: r.integration_id,
    methods: JSON.parse(r.methods),
    pathGlob: r.path_glob,
    effect: r.effect,
    createdAt: r.created_at,
    expiresAt: r.expires_at ?? null,
    leaseTtlSeconds: r.lease_ttl_seconds ?? null,
    connectionId: r.connection_id ?? null,
    connectionScope: r.connection_scope ? (r.connection_scope as Rule["connectionScope"]) : undefined,
  };
}

function rowToOnboardingLink(r: Row): OnboardingLink {
  return {
    // Only the hash is stored. The plaintext token lives solely in the connect
    // URL delivered at mint time. Callers that hold the plaintext (redemption
    // via getOnboardingLink) get it re-attached there; list/admin reads surface
    // the hash, which is enough to identify and revoke a link.
    tokenHash: r.token_hash,
    token: r.token_hash,
    agentId: r.agent_id,
    integrationId: r.integration_id,
    scopes: r.scopes ? JSON.parse(r.scopes) : null,
    connectionName: r.connection_name ?? null,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    usedAt: r.used_at ?? null,
    ruleId: r.rule_id ?? null,
  };
}

/**
 * Isolates a single undecryptable secret row. A row sealed under a rotated or
 * different key, or a truncated/corrupt envelope, makes `box.open` throw (bad
 * GCM tag or JSON.parse). Without isolation one such row would take down the
 * whole `rowTo*` map path (and thus the vendor's connection list and all proxy
 * resolution for it), block boot from `encryptSecretsAtRest`, or (for the
 * `agent_notify` webhook URL) throw from inside the proxy's deny path, where
 * the async request handler's promise is unobserved and the throw becomes a
 * process-killing unhandled rejection. We log the row id (never the ciphertext
 * or any secret material) and let the caller skip it.
 */
function safeOpen<T = Record<string, string>>(box: SecretBox, data: string, rowId: string): T | null {
  try {
    return box.open<T>(data);
  } catch {
    console.warn(`onegate: skipping undecryptable secret row id=${rowId} (bad key or corrupt envelope)`);
    return null;
  }
}

function rowToCredential(r: Row, box: SecretBox): Credential | null {
  const data = safeOpen(box, r.data, r.id);
  if (data === null) return null;
  return {
    id: r.id,
    integrationId: r.integration_id,
    name: r.name,
    data,
    createdAt: r.created_at,
  };
}

function rowToConnection(r: Row, box: SecretBox): Connection | null {
  const data = safeOpen(box, r.data, r.id);
  if (data === null) return null;
  return {
    id: r.id,
    kind: r.kind as ConnectionKind,
    vendor: r.vendor,
    name: r.name,
    data,
    ownerAgentId: r.owner_agent_id ?? null,
    isDefault: r.is_default === 1,
    leaseTtlSeconds: r.lease_ttl_seconds ?? null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function rowToAgentAppConfig(r: Row): AgentAppConfig {
  return {
    agentId: r.agent_id,
    integrationId: r.integration_id,
    connectionId: r.connection_id,
    updatedAt: r.updated_at,
  };
}

function rowToAgentLlmConfig(r: Row): AgentLlmConfig {
  return {
    agentId: r.agent_id,
    enabled: r.enabled === 1,
    strategy: r.strategy as LlmStrategy,
    ...(r.vendor_strategies != null
      ? { vendorStrategies: JSON.parse(r.vendor_strategies) as Record<string, LlmStrategy> }
      : {}),
    connectionIds: JSON.parse(r.connection_ids),
    updatedAt: r.updated_at,
  };
}

function rowToLlmStrategyState(r: Row): LlmStrategyState {
  return {
    agentId: r.agent_id,
    vendor: r.vendor,
    activeIndex: Number(r.active_index),
    rrCursor: Number(r.rr_cursor),
    callsSinceFallback: Number(r.calls_since_fallback),
    cooldowns: JSON.parse(r.cooldowns),
    updatedAt: r.updated_at,
  };
}

function rowToOwnerNotification(r: Row): OwnerNotification {
  return {
    id: Number(r.id),
    agentId: r.agent_id,
    integrationId: r.integration_id,
    connectToken: r.connect_token ?? null,
    status: r.status as OwnerNotificationStatus,
    createdAt: r.created_at,
    deliveredAt: r.delivered_at ?? null,
    lastAttemptAt: r.last_attempt_at ?? null,
    attempts: Number(r.attempts),
    error: r.error ?? null,
    dedupKey: r.dedup_key ?? null,
  };
}

function rowToLlmUsageEvent(r: Row): LlmUsageEvent {
  return {
    id: Number(r.id),
    ts: r.ts,
    connectionId: r.connection_id,
    connectionName: r.connection_name ?? null,
    agentId: r.agent_id ?? null,
    vendor: r.vendor ?? null,
    strategy: (r.strategy as LlmStrategy | null) ?? null,
    requests: Number(r.requests),
    errors: Number(r.errors),
    inputTokens: r.input_tokens === null || r.input_tokens === undefined ? null : Number(r.input_tokens),
    outputTokens: r.output_tokens === null || r.output_tokens === undefined ? null : Number(r.output_tokens),
    selected: r.selected === 1,
    failover: r.failover === 1,
    status: r.status === null || r.status === undefined ? null : Number(r.status),
  };
}

export class Store {
  private db: DatabaseSync;
  private secrets: SecretBox;

  constructor(dbPath: string) {
    if (dbPath !== ":memory:") mkdirSync(dirname(dbPath), { recursive: true });
    this.secrets = new SecretBox(loadSecretKey(dbPath));
    this.db = new DatabaseSync(dbPath);
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec("PRAGMA foreign_keys = ON");
    this.db.exec(SCHEMA);
    this.migrate();
    this.encryptSecretsAtRest();
    this.hashCapabilityTokensAtRest();
  }

  /**
   * Runs `fn` inside a single SQLite transaction (IMMEDIATE, so the write lock
   * is taken up front). Commits if `fn` returns normally, rolls back and
   * rethrows on any error, so a multi-statement mutation is all-or-nothing.
   * node:sqlite has no better-sqlite3-style `db.transaction()` helper, so this
   * wraps the BEGIN/COMMIT/ROLLBACK exec calls. Not reentrant (SQLite has no
   * nested transactions) - never call `tx` from inside another `tx`.
   */
  private tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (err) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // A ROLLBACK can fail if no transaction is open (e.g. it was already
        // aborted by SQLite). Swallow it so the original error propagates.
      }
      throw err;
    }
  }

  /**
   * Idempotent column additions for databases created before the LLM
   * routing feature. CREATE TABLE IF NOT EXISTS does not alter existing
   * tables, so the audit table's LLM columns are added here when missing.
   */
  private migrate(): void {
    const have = new Set(
      (this.db.prepare("PRAGMA table_info(audit)").all() as Row[]).map((r) => String(r.name)),
    );
    const wanted: Array<[string, string]> = [
      ["connection_id", "TEXT"],
      ["connection_name", "TEXT"],
      ["llm_vendor", "TEXT"],
      ["llm_strategy", "TEXT"],
      ["llm_failover", "INTEGER"],
    ];
    for (const [name, type] of wanted) {
      if (!have.has(name)) this.db.exec(`ALTER TABLE audit ADD COLUMN ${name} ${type}`);
    }
    // owner_agent_id was added to connections for agent-bound app accounts.
    // Databases created before that need it backfilled (defaults to null =
    // tenant-wide, the pre-existing behavior for every LLM connection).
    const connCols = new Set(
      (this.db.prepare("PRAGMA table_info(connections)").all() as Row[]).map((r) => String(r.name)),
    );
    if (!connCols.has("owner_agent_id")) {
      this.db.exec("ALTER TABLE connections ADD COLUMN owner_agent_id TEXT");
    }
    // model was added to llm_usage for per-model usage analytics. Databases
    // created before that need it backfilled (defaults to null = unknown model,
    // which the rollups render as "(unknown)").
    const usageCols = new Set(
      (this.db.prepare("PRAGMA table_info(llm_usage)").all() as Row[]).map((r) => String(r.name)),
    );
    if (!usageCols.has("model")) {
      this.db.exec("ALTER TABLE llm_usage ADD COLUMN model TEXT");
    }
    // Access-lease columns. Databases created before time-boxing need the
    // rule/connection lease columns and the owner_notifications dedup key.
    // All default to NULL = no lease / legacy behavior, so existing rows are
    // untouched (never time-boxed unless re-connected under a time-boxed
    // integration).
    const ruleCols = new Set(
      (this.db.prepare("PRAGMA table_info(rules)").all() as Row[]).map((r) => String(r.name)),
    );
    if (!ruleCols.has("expires_at")) this.db.exec("ALTER TABLE rules ADD COLUMN expires_at TEXT");
    if (!ruleCols.has("lease_ttl_seconds"))
      this.db.exec("ALTER TABLE rules ADD COLUMN lease_ttl_seconds INTEGER");
    // Connection-scoping columns. NULL = the rule applies regardless of which
    // connection a request resolved to (legacy behavior). Added after the lease
    // columns so a legacy DB gets them via ALTER, never assumed present in a
    // query before this point.
    if (!ruleCols.has("connection_id"))
      this.db.exec("ALTER TABLE rules ADD COLUMN connection_id TEXT");
    if (!ruleCols.has("connection_scope"))
      this.db.exec(
        "ALTER TABLE rules ADD COLUMN connection_scope TEXT CHECK (connection_scope IN ('only','except'))",
      );
    if (!connCols.has("lease_ttl_seconds"))
      this.db.exec("ALTER TABLE connections ADD COLUMN lease_ttl_seconds INTEGER");
    const linkCols = new Set(
      (this.db.prepare("PRAGMA table_info(onboarding_links)").all() as Row[]).map((r) => String(r.name)),
    );
    if (!linkCols.has("rule_id")) this.db.exec("ALTER TABLE onboarding_links ADD COLUMN rule_id TEXT");
    const notifyCols = new Set(
      (this.db.prepare("PRAGMA table_info(owner_notifications)").all() as Row[]).map((r) =>
        String(r.name),
      ),
    );
    if (!notifyCols.has("dedup_key"))
      this.db.exec("ALTER TABLE owner_notifications ADD COLUMN dedup_key TEXT");
    const llmCfgCols = new Set(
      (this.db.prepare("PRAGMA table_info(agent_llm_config)").all() as Row[]).map((r) =>
        String(r.name),
      ),
    );
    if (!llmCfgCols.has("vendor_strategies"))
      this.db.exec("ALTER TABLE agent_llm_config ADD COLUMN vendor_strategies TEXT");
    // The dedup index is created here (not in the upfront schema DDL) so it
    // never references dedup_key before the ALTER TABLE above has added it on a
    // pre-time-boxing database.
    this.db.exec(
      "CREATE INDEX IF NOT EXISTS idx_owner_notifications_dedup ON owner_notifications(dedup_key)",
    );
    // Seed the default time-boxed integrations. INSERT OR IGNORE so an operator
    // who later changes or clears the TTL is never overwritten on boot.
    for (const [integrationId, ttl] of DEFAULT_INTEGRATION_LEASES) {
      this.db
        .prepare(
          "INSERT OR IGNORE INTO integration_leases (integration_id, ttl_seconds, updated_at) VALUES (?, ?, ?)",
        )
        .run(integrationId, ttl, now());
    }
  }

  /**
   * One-time at-rest encryption of pre-existing secret blobs. Rows written
   * before envelope encryption existed hold plain JSON; re-seal them so a
   * leaked DB file never exposes plaintext. Already-sealed rows are skipped,
   * so this is idempotent and cheap on every subsequent boot.
   */
  private encryptSecretsAtRest(): void {
    for (const table of ["credentials", "connections"] as const) {
      const rows = this.db.prepare(`SELECT id, data FROM ${table}`).all() as Row[];
      const update = this.db.prepare(`UPDATE ${table} SET data = ? WHERE id = ?`);
      for (const r of rows) {
        if (typeof r.data !== "string" || this.secrets.isSealed(r.data)) continue;
        // Re-seal the existing plaintext value verbatim (open() parses the
        // legacy JSON, seal() wraps it) so no secret is altered. Isolate a
        // single unparseable legacy blob: skip it and leave the row as-is so
        // one corrupt row cannot block boot (the row is later skipped by the
        // rowTo* mappers too). Never log the row's data.
        try {
          update.run(this.secrets.seal(this.secrets.open(r.data)), r.id);
        } catch {
          console.warn(
            `onegate: skipping unparseable legacy secret row id=${r.id} in ${table} during at-rest migration`,
          );
        }
      }
    }
  }

  /**
   * One-time hash-at-rest of connect-capability tokens. Onboarding-link tokens
   * and owner-notification connect tokens are BEARER CAPABILITIES: possessing
   * one lets the holder drive the connect wizard for an agent and attach a
   * credential. They were historically stored in cleartext while credential /
   * connection secrets (and even agent_notify webhook URLs) are sealed, so a
   * leaked DB file yielded working onboarding-hijack links. We now store only
   * the SHA-256 hash (mirroring agent tokens), redeeming by hashing the
   * presented token. This migration rewrites any pre-existing plaintext rows to
   * their hash in place so old links keep working (the plaintext in the already
   * delivered URL still hashes to the stored value), and is idempotent: rows
   * already holding a hash are skipped.
   */
  private hashCapabilityTokensAtRest(): void {
    // onboarding_links: legacy DBs have a plaintext `token` PRIMARY KEY column
    // instead of the current `token_hash` column. Rebuild the table, hashing
    // each token into token_hash. Already-migrated DBs (token_hash present) are
    // left untouched.
    const linkCols = new Set(
      (this.db.prepare("PRAGMA table_info(onboarding_links)").all() as Row[]).map((r) =>
        String(r.name),
      ),
    );
    if (linkCols.has("token") && !linkCols.has("token_hash")) {
      this.db.exec("ALTER TABLE onboarding_links RENAME TO onboarding_links_legacy");
      this.db.exec(`CREATE TABLE onboarding_links (
        token_hash TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        integration_id TEXT NOT NULL,
        scopes TEXT,
        connection_name TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        rule_id TEXT
      )`);
      this.db.exec("CREATE INDEX IF NOT EXISTS idx_onboarding_links_agent ON onboarding_links(agent_id)");
      const legacyCols = new Set(
        (this.db.prepare("PRAGMA table_info(onboarding_links_legacy)").all() as Row[]).map((r) =>
          String(r.name),
        ),
      );
      const rows = this.db.prepare("SELECT * FROM onboarding_links_legacy").all() as Row[];
      const insert = this.db.prepare(
        "INSERT OR IGNORE INTO onboarding_links (token_hash, agent_id, integration_id, scopes, connection_name, created_at, expires_at, used_at, rule_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      );
      for (const r of rows) {
        insert.run(
          hashToken(String(r.token)),
          r.agent_id,
          r.integration_id,
          r.scopes ?? null,
          r.connection_name ?? null,
          r.created_at,
          r.expires_at,
          r.used_at ?? null,
          legacyCols.has("rule_id") ? (r.rule_id ?? null) : null,
        );
      }
      this.db.exec("DROP TABLE onboarding_links_legacy");
    }
    // owner_notifications.connect_token now holds the hash, not the plaintext.
    // Hash any legacy plaintext rows in place. A row already holding a hash
    // (64 lowercase hex chars) is left alone so this is idempotent.
    const notifRows = this.db
      .prepare("SELECT id, connect_token FROM owner_notifications WHERE connect_token IS NOT NULL")
      .all() as Row[];
    const updateNotif = this.db.prepare(
      "UPDATE owner_notifications SET connect_token = ? WHERE id = ?",
    );
    for (const r of notifRows) {
      const tok = String(r.connect_token);
      if (/^[0-9a-f]{64}$/.test(tok)) continue;
      updateNotif.run(hashToken(tok), r.id);
    }
  }

  close(): void {
    this.db.close();
  }

  // ---- settings ----

  getSetting(key: string): string | null {
    const r = this.db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as
      | Row
      | undefined;
    return r ? r.value : null;
  }

  setSetting(key: string, value: string): void {
    this.db
      .prepare(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
      )
      .run(key, value);
  }

  deleteSetting(key: string): void {
    this.db.prepare("DELETE FROM settings WHERE key = ?").run(key);
  }

  // ---- projects ----

  createProject(name: string): Project {
    const p: Project = { id: newId("pr"), name, createdAt: now() };
    this.db
      .prepare("INSERT INTO projects (id, name, created_at) VALUES (?, ?, ?)")
      .run(p.id, p.name, p.createdAt);
    return p;
  }

  listProjects(): Project[] {
    return (this.db.prepare("SELECT * FROM projects ORDER BY name").all() as Row[]).map((r) => ({
      id: r.id,
      name: r.name,
      createdAt: r.created_at,
    }));
  }

  getProject(id: string): Project | null {
    const r = this.db.prepare("SELECT * FROM projects WHERE id = ?").get(id) as Row | undefined;
    return r ? { id: r.id, name: r.name, createdAt: r.created_at } : null;
  }

  deleteProject(id: string): void {
    this.db.prepare("DELETE FROM rules WHERE scope = 'project' AND subject_id = ?").run(id);
    this.db.prepare("DELETE FROM connection_grants WHERE scope = 'project' AND subject_id = ?").run(id);
    this.db.prepare("DELETE FROM projects WHERE id = ?").run(id);
  }

  // ---- agents ----

  /** Creates an agent and returns it together with its one-time-visible token. */
  createAgent(
    name: string,
    opts: { projectId?: string | null; defaultPolicy?: DefaultPolicy } = {},
  ): { agent: Agent; token: string } {
    const token = newAgentToken();
    const agent: Agent = {
      id: newId("ag"),
      name,
      tokenHash: hashToken(token),
      projectId: opts.projectId ?? null,
      defaultPolicy: opts.defaultPolicy ?? "deny-unmatched",
      createdAt: now(),
    };
    this.db
      .prepare(
        "INSERT INTO agents (id, name, token_hash, project_id, default_policy, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(agent.id, agent.name, agent.tokenHash, agent.projectId, agent.defaultPolicy, agent.createdAt);
    return { agent, token };
  }

  listAgents(): Agent[] {
    return (this.db.prepare("SELECT * FROM agents ORDER BY name").all() as Row[]).map(rowToAgent);
  }

  getAgent(id: string): Agent | null {
    const r = this.db.prepare("SELECT * FROM agents WHERE id = ?").get(id) as Row | undefined;
    return r ? rowToAgent(r) : null;
  }

  getAgentByToken(token: string): Agent | null {
    const r = this.db
      .prepare("SELECT * FROM agents WHERE token_hash = ?")
      .get(hashToken(token)) as Row | undefined;
    return r ? rowToAgent(r) : null;
  }

  updateAgent(
    id: string,
    patch: { name?: string; projectId?: string | null; defaultPolicy?: DefaultPolicy },
  ): Agent | null {
    const cur = this.getAgent(id);
    if (!cur) return null;
    const next = {
      name: patch.name ?? cur.name,
      projectId: patch.projectId === undefined ? cur.projectId : patch.projectId,
      defaultPolicy: patch.defaultPolicy ?? cur.defaultPolicy,
    };
    this.db
      .prepare("UPDATE agents SET name = ?, project_id = ?, default_policy = ? WHERE id = ?")
      .run(next.name, next.projectId, next.defaultPolicy, id);
    return this.getAgent(id);
  }

  /** Replaces the agent's token. Returns the new token. */
  rotateAgentToken(id: string): string | null {
    if (!this.getAgent(id)) return null;
    const token = newAgentToken();
    this.db.prepare("UPDATE agents SET token_hash = ? WHERE id = ?").run(hashToken(token), id);
    return token;
  }

  deleteAgent(id: string): void {
    // All-or-nothing: an interrupted delete must never leave the DB in a state
    // where the credential/authz-bearing rows disagree (e.g. rules/grants gone
    // while the agent token still authenticates = fail-open, or the agent row
    // gone while onboarding links / notifications dangle as orphans). The whole
    // cascade runs inside one transaction.
    this.tx(() => {
      // Remove the authz-bearing rows (token via the agents row, plus rules and
      // grants) together with the rest of the agent's footprint.
      this.db.prepare("DELETE FROM rules WHERE scope = 'agent' AND subject_id = ?").run(id);
      this.db.prepare("DELETE FROM agent_llm_config WHERE agent_id = ?").run(id);
      this.db.prepare("DELETE FROM llm_strategy_state WHERE agent_id = ?").run(id);
      this.db.prepare("DELETE FROM agent_app_config WHERE agent_id = ?").run(id);
      // App connections bound to this agent are no longer reachable, drop them.
      this.db.prepare("DELETE FROM connections WHERE kind = 'app' AND owner_agent_id = ?").run(id);
      // Drop grants that named this agent as their subject (cascade handles the
      // connection-side; this clears the agent-subject side).
      this.db
        .prepare("DELETE FROM connection_grants WHERE scope = 'agent' AND subject_id = ?")
        .run(id);
      // Onboarding links and owner notifications reference the agent by id but
      // have no FK cascade, so clear them here to avoid orphans (a leftover
      // onboarding link would otherwise still be redeemable for a dead agent).
      this.db.prepare("DELETE FROM onboarding_links WHERE agent_id = ?").run(id);
      this.db.prepare("DELETE FROM owner_notifications WHERE agent_id = ?").run(id);
      // agent_notify has an ON DELETE CASCADE FK, so it clears with the row.
      this.db.prepare("DELETE FROM agents WHERE id = ?").run(id);
    });
  }

  // ---- credentials ----

  /** Inserts or replaces the credential for an integration (one per integration). */
  setCredential(integrationId: string, name: string, data: Record<string, string>): Credential {
    const c: Credential = { id: newId("cr"), integrationId, name, data, createdAt: now() };
    this.db
      .prepare(
        `INSERT INTO credentials (id, integration_id, name, data, created_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(integration_id) DO UPDATE SET name = excluded.name, data = excluded.data`,
      )
      .run(c.id, c.integrationId, c.name, this.secrets.seal(c.data), c.createdAt);
    return this.getCredential(integrationId)!;
  }

  getCredential(integrationId: string): Credential | null {
    const r = this.db
      .prepare("SELECT * FROM credentials WHERE integration_id = ?")
      .get(integrationId) as Row | undefined;
    return r ? rowToCredential(r, this.secrets) : null;
  }

  listCredentials(): Credential[] {
    return (this.db.prepare("SELECT * FROM credentials ORDER BY integration_id").all() as Row[])
      .map((r) => rowToCredential(r, this.secrets))
      .filter((c): c is Credential => c !== null);
  }

  deleteCredential(integrationId: string): void {
    this.db.prepare("DELETE FROM credentials WHERE integration_id = ?").run(integrationId);
  }

  // ---- connections (multi-credential) ----
  //
  // Apps keep the single-credential `credentials` table above as the legacy
  // fallback. Connections add the multi-per-vendor model that LLM routing and
  // multi-account app integrations need. The store enforces exactly one
  // default per (kind, vendor, owner-bucket): the tenant-wide bucket
  // (ownerAgentId null) and each agent-owned bucket each have their own
  // default. The first connection of a bucket becomes its default
  // automatically, setting another default demotes the previous one in the
  // same bucket, and deleting a default promotes the oldest remaining
  // connection in that bucket. LLM connections always use the null bucket.

  createConnection(input: {
    kind: ConnectionKind;
    vendor: string;
    name: string;
    data: Record<string, string>;
    ownerAgentId?: string | null;
    isDefault?: boolean;
    /** Owner lease override: null = inherit, 0 = always-on, >0 = custom seconds. */
    leaseTtlSeconds?: number | null;
  }): Connection {
    const ts = now();
    const ownerAgentId = input.kind === "app" ? input.ownerAgentId ?? null : null;
    const existing = this.listConnections({ kind: input.kind, vendor: input.vendor, ownerAgentId });
    const isDefault = input.isDefault === true || existing.length === 0;
    const id = newId("conn");
    if (isDefault) this.clearDefaultConnection(input.kind, input.vendor, ownerAgentId);
    this.db
      .prepare(
        "INSERT INTO connections (id, kind, vendor, name, data, owner_agent_id, is_default, lease_ttl_seconds, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        id,
        input.kind,
        input.vendor,
        input.name,
        this.secrets.seal(input.data),
        ownerAgentId,
        isDefault ? 1 : 0,
        input.leaseTtlSeconds ?? null,
        ts,
        ts,
      );
    return this.getConnection(id)!;
  }

  getConnection(id: string): Connection | null {
    const r = this.db.prepare("SELECT * FROM connections WHERE id = ?").get(id) as Row | undefined;
    return r ? rowToConnection(r, this.secrets) : null;
  }

  /**
   * Lists connections. `ownerAgentId` filters by the owner bucket: omit it for
   * all rows, pass `null` for only tenant-wide rows, or an agent id for that
   * agent's bucket.
   */
  listConnections(
    filter: { kind?: ConnectionKind; vendor?: string; ownerAgentId?: string | null } = {},
  ): Connection[] {
    const where: string[] = [];
    const params: string[] = [];
    if (filter.kind) {
      where.push("kind = ?");
      params.push(filter.kind);
    }
    if (filter.vendor) {
      where.push("vendor = ?");
      params.push(filter.vendor);
    }
    if ("ownerAgentId" in filter) {
      if (filter.ownerAgentId === null) {
        where.push("owner_agent_id IS NULL");
      } else if (filter.ownerAgentId !== undefined) {
        where.push("owner_agent_id = ?");
        params.push(filter.ownerAgentId);
      }
    }
    const sql = `SELECT * FROM connections${where.length ? ` WHERE ${where.join(" AND ")}` : ""} ORDER BY created_at, rowid`;
    return (this.db.prepare(sql).all(...params) as Row[])
      .map((r) => rowToConnection(r, this.secrets))
      .filter((c): c is Connection => c !== null);
  }

  /**
   * App connections this agent may use, resolved purely by grants
   * (default-deny): a connection is included only if it is GRANTED to this
   * agent (scope='agent', subject_id=agentId) or to its project
   * (scope='project', subject_id=agent.projectId). The legacy `owner_agent_id`
   * column is no longer consulted. Returns empty when the agent has no grants.
   */
  listAppConnectionsForAgent(agentId: string, vendor?: string): Connection[] {
    const agent = this.getAgent(agentId);
    if (!agent) return [];
    const subjectClause = agent.projectId
      ? "(g.scope = 'agent' AND g.subject_id = ?) OR (g.scope = 'project' AND g.subject_id = ?)"
      : "(g.scope = 'agent' AND g.subject_id = ?)";
    const params: string[] = agent.projectId ? [agentId, agent.projectId] : [agentId];
    let vendorClause = "";
    if (vendor) {
      vendorClause = " AND c.vendor = ?";
      params.push(vendor);
    }
    const sql = `SELECT DISTINCT c.* FROM connections c JOIN connection_grants g ON g.connection_id = c.id WHERE c.kind = 'app' AND (${subjectClause})${vendorClause} ORDER BY c.created_at, c.rowid`;
    return (this.db.prepare(sql).all(...params) as Row[])
      .map((r) => rowToConnection(r, this.secrets))
      .filter((c): c is Connection => c !== null);
  }

  // ---- connection grants (default-deny authorization) ----

  /** Grants an app connection to an agent or project. Idempotent. */
  grantConnection(connectionId: string, scope: RuleScope, subjectId: string): void {
    this.db
      .prepare(
        "INSERT OR IGNORE INTO connection_grants (connection_id, scope, subject_id, created_at) VALUES (?, ?, ?, ?)",
      )
      .run(connectionId, scope, subjectId, now());
  }

  /** Removes a grant. No-op if absent. */
  revokeConnection(connectionId: string, scope: RuleScope, subjectId: string): void {
    this.db
      .prepare(
        "DELETE FROM connection_grants WHERE connection_id = ? AND scope = ? AND subject_id = ?",
      )
      .run(connectionId, scope, subjectId);
  }

  /** Lists the grants on a connection, resolving each subject's display name. */
  listGrantsForConnection(
    connectionId: string,
  ): { scope: RuleScope; subjectId: string; subjectName: string | null; createdAt: string }[] {
    const rows = this.db
      .prepare(
        "SELECT scope, subject_id, created_at FROM connection_grants WHERE connection_id = ? ORDER BY created_at, rowid",
      )
      .all(connectionId) as Row[];
    return rows.map((r) => {
      const scope = r.scope as RuleScope;
      let subjectName: string | null = null;
      if (scope === "agent") subjectName = this.getAgent(r.subject_id)?.name ?? null;
      else subjectName = this.getProject(r.subject_id)?.name ?? null;
      return { scope, subjectId: r.subject_id, subjectName, createdAt: r.created_at };
    });
  }

  /** Number of grants on a connection (cheap, for list views). */
  countGrantsForConnection(connectionId: string): number {
    const r = this.db
      .prepare("SELECT COUNT(*) AS n FROM connection_grants WHERE connection_id = ?")
      .get(connectionId) as { n: number };
    return r.n;
  }

  /** App connections granted to this agent (alias of listAppConnectionsForAgent). */
  listGrantedConnectionsForAgent(agentId: string, vendor?: string): Connection[] {
    return this.listAppConnectionsForAgent(agentId, vendor);
  }

  /** True if the connection is granted to the agent directly or via its project. */
  isConnectionGrantedToAgent(connectionId: string, agentId: string): boolean {
    const agent = this.getAgent(agentId);
    if (!agent) return false;
    const subjectClause = agent.projectId
      ? "(scope = 'agent' AND subject_id = ?) OR (scope = 'project' AND subject_id = ?)"
      : "(scope = 'agent' AND subject_id = ?)";
    const params: string[] = agent.projectId ? [agentId, agent.projectId] : [agentId];
    const r = this.db
      .prepare(
        `SELECT 1 FROM connection_grants WHERE connection_id = ? AND (${subjectClause}) LIMIT 1`,
      )
      .get(connectionId, ...params) as Row | undefined;
    return !!r;
  }

  getDefaultConnection(
    kind: ConnectionKind,
    vendor: string,
    ownerAgentId: string | null = null,
  ): Connection | null {
    const r =
      ownerAgentId === null
        ? (this.db
            .prepare(
              "SELECT * FROM connections WHERE kind = ? AND vendor = ? AND owner_agent_id IS NULL AND is_default = 1",
            )
            .get(kind, vendor) as Row | undefined)
        : (this.db
            .prepare(
              "SELECT * FROM connections WHERE kind = ? AND vendor = ? AND owner_agent_id = ? AND is_default = 1",
            )
            .get(kind, vendor, ownerAgentId) as Row | undefined);
    return r ? rowToConnection(r, this.secrets) : null;
  }

  /**
   * Patches a connection. `isDefault: true` moves the bucket default here;
   * `isDefault: false` on the current default is ignored (a bucket with
   * connections always has exactly one default). The owner bucket cannot be
   * changed here.
   */
  updateConnection(
    id: string,
    patch: { name?: string; data?: Record<string, string>; isDefault?: boolean },
  ): Connection | null {
    const cur = this.getConnection(id);
    if (!cur) return null;
    const makeDefault = patch.isDefault === true && !cur.isDefault;
    if (makeDefault) this.clearDefaultConnection(cur.kind, cur.vendor, cur.ownerAgentId);
    this.db
      .prepare("UPDATE connections SET name = ?, data = ?, is_default = ?, updated_at = ? WHERE id = ?")
      .run(
        patch.name ?? cur.name,
        this.secrets.seal(patch.data ?? cur.data),
        makeDefault || cur.isDefault ? 1 : 0,
        now(),
        id,
      );
    return this.getConnection(id);
  }

  deleteConnection(id: string): void {
    const cur = this.getConnection(id);
    if (!cur) return;
    // Deleting a connection and promoting the next default must be atomic: an
    // interrupt between the two would leave a vendor with no default connection
    // (or, with grants cascaded off, in a half-torn state). Run both together.
    this.tx(() => {
      this.db.prepare("DELETE FROM connections WHERE id = ?").run(id);
      if (cur.isDefault) {
        const next = this.listConnections({
          kind: cur.kind,
          vendor: cur.vendor,
          ownerAgentId: cur.ownerAgentId,
        })[0];
        if (next) {
          this.db
            .prepare("UPDATE connections SET is_default = 1, updated_at = ? WHERE id = ?")
            .run(now(), next.id);
        }
      }
    });
  }

  private clearDefaultConnection(
    kind: ConnectionKind,
    vendor: string,
    ownerAgentId: string | null,
  ): void {
    if (ownerAgentId === null) {
      this.db
        .prepare(
          "UPDATE connections SET is_default = 0 WHERE kind = ? AND vendor = ? AND owner_agent_id IS NULL AND is_default = 1",
        )
        .run(kind, vendor);
    } else {
      this.db
        .prepare(
          "UPDATE connections SET is_default = 0 WHERE kind = ? AND vendor = ? AND owner_agent_id = ? AND is_default = 1",
        )
        .run(kind, vendor, ownerAgentId);
    }
  }

  // ---- per-agent app-connection selection ----
  //
  // An agent_app_config row is the agent's saved choice of which app
  // connection to use for an integration when no x-onegate-connection header
  // is sent. Absent = fall through to the tenant-wide default app connection,
  // then the legacy credentials row.

  getAgentAppConfig(agentId: string, integrationId: string): AgentAppConfig | null {
    const r = this.db
      .prepare("SELECT * FROM agent_app_config WHERE agent_id = ? AND integration_id = ?")
      .get(agentId, integrationId) as Row | undefined;
    return r ? rowToAgentAppConfig(r) : null;
  }

  listAgentAppConfigs(agentId: string): AgentAppConfig[] {
    return (
      this.db
        .prepare("SELECT * FROM agent_app_config WHERE agent_id = ? ORDER BY integration_id")
        .all(agentId) as Row[]
    ).map(rowToAgentAppConfig);
  }

  setAgentAppConfig(agentId: string, integrationId: string, connectionId: string): AgentAppConfig {
    this.db
      .prepare(
        `INSERT INTO agent_app_config (agent_id, integration_id, connection_id, updated_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(agent_id, integration_id) DO UPDATE SET connection_id = excluded.connection_id,
           updated_at = excluded.updated_at`,
      )
      .run(agentId, integrationId, connectionId, now());
    return this.getAgentAppConfig(agentId, integrationId)!;
  }

  clearAgentAppConfig(agentId: string, integrationId: string): void {
    this.db
      .prepare("DELETE FROM agent_app_config WHERE agent_id = ? AND integration_id = ?")
      .run(agentId, integrationId);
  }

  deleteAgentAppConfigsForAgent(agentId: string): void {
    this.db.prepare("DELETE FROM agent_app_config WHERE agent_id = ?").run(agentId);
  }

  /**
   * Drops a connection id from every agent_app_config that references it (used
   * when an app connection is deleted). Returns the affected agent ids.
   */
  removeConnectionFromAppConfigs(connectionId: string): string[] {
    const rows = this.db
      .prepare("SELECT agent_id FROM agent_app_config WHERE connection_id = ?")
      .all(connectionId) as Row[];
    const affected = rows.map((r) => String(r.agent_id));
    this.db.prepare("DELETE FROM agent_app_config WHERE connection_id = ?").run(connectionId);
    return affected;
  }

  /**
   * Picks the app connection an (agent, integration) request should use under
   * default-deny grants, or null to fall through to the legacy credentials
   * path. Resolution order (see DESIGN #4992):
   *   1. Candidate set = named app connections for this integration GRANTED to
   *      the agent (directly or via its project).
   *   2. header value (name or id): in candidate set -> use; names a connection
   *      that exists but is not granted -> error "connection_not_granted";
   *      names nothing at all -> error "unknown_connection".
   *   3. the agent's saved agent_app_config choice, if still in the candidate set.
   *   4. the candidate-set default (is_default), else the sole candidate if there
   *      is exactly one.
   *   5. if NO named app connections exist for this integration AT ALL -> null
   *      (legacy getCredential fallback, e.g. Gaty's github). UNCHANGED.
   *   6. else (named connections exist but none granted) -> default-deny ->
   *      error "connection_not_granted".
   */
  resolveAppConnection(
    agentId: string,
    integrationId: string,
    headerValue?: string | null,
  ):
    | { connection: Connection }
    | { error: "unknown_connection" }
    | { error: "connection_not_granted" }
    | null {
    const candidates = this.listAppConnectionsForAgent(agentId, integrationId);
    // Any named app connection for this integration at all (across every agent).
    const anyForIntegration =
      this.listConnections({ kind: "app", vendor: integrationId }).length > 0;

    if (headerValue && headerValue.trim()) {
      const wanted = headerValue.trim();
      const match = candidates.find((c) => c.id === wanted || c.name === wanted);
      if (match) return { connection: match };
      // Distinguish "exists but not granted" from "names nothing".
      const existsSomewhere = this.listConnections({ kind: "app", vendor: integrationId }).some(
        (c) => c.id === wanted || c.name === wanted,
      );
      return existsSomewhere ? { error: "connection_not_granted" } : { error: "unknown_connection" };
    }

    const saved = this.getAgentAppConfig(agentId, integrationId);
    if (saved) {
      const conn = candidates.find((c) => c.id === saved.connectionId);
      if (conn) return { connection: conn };
    }

    if (candidates.length > 0) {
      const def = candidates.find((c) => c.isDefault);
      if (def) return { connection: def };
      if (candidates.length === 1) return { connection: candidates[0] };
      // Multiple granted, none default, none chosen: pick the oldest (stable).
      return { connection: candidates[0] };
    }

    // No granted candidates. Fall through to legacy ONLY if there are no named
    // app connections for this integration at all (back-compat, Gaty path).
    if (!anyForIntegration) return null;

    return { error: "connection_not_granted" };
  }

  // ---- per-agent LLM routing config ----

  listAgentLlmConfigs(): AgentLlmConfig[] {
    return (this.db.prepare("SELECT * FROM agent_llm_config ORDER BY agent_id").all() as Row[]).map(
      rowToAgentLlmConfig,
    );
  }

  /**
   * Removes a connection id from every agent_llm_config that references it
   * (used when a connection is deleted). Returns the affected agent ids.
   */
  removeConnectionFromLlmConfigs(connectionId: string): string[] {
    const affected: string[] = [];
    for (const cfg of this.listAgentLlmConfigs()) {
      if (!cfg.connectionIds.includes(connectionId)) continue;
      this.setAgentLlmConfig(cfg.agentId, {
        enabled: cfg.enabled,
        strategy: cfg.strategy,
        vendorStrategies: cfg.vendorStrategies,
        connectionIds: cfg.connectionIds.filter((id) => id !== connectionId),
      });
      affected.push(cfg.agentId);
    }
    return affected;
  }

  getAgentLlmConfig(agentId: string): AgentLlmConfig | null {
    const r = this.db
      .prepare("SELECT * FROM agent_llm_config WHERE agent_id = ?")
      .get(agentId) as Row | undefined;
    return r ? rowToAgentLlmConfig(r) : null;
  }

  setAgentLlmConfig(
    agentId: string,
    config: {
      enabled: boolean;
      strategy: LlmStrategy;
      vendorStrategies?: Record<string, LlmStrategy>;
      connectionIds: string[];
    },
  ): AgentLlmConfig {
    this.db
      .prepare(
        `INSERT INTO agent_llm_config (agent_id, enabled, strategy, vendor_strategies, connection_ids, updated_at) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(agent_id) DO UPDATE SET enabled = excluded.enabled, strategy = excluded.strategy,
           vendor_strategies = excluded.vendor_strategies,
           connection_ids = excluded.connection_ids, updated_at = excluded.updated_at`,
      )
      .run(
        agentId,
        config.enabled ? 1 : 0,
        config.strategy,
        config.vendorStrategies ? JSON.stringify(config.vendorStrategies) : null,
        JSON.stringify(config.connectionIds),
        now(),
      );
    return this.getAgentLlmConfig(agentId)!;
  }

  deleteAgentLlmConfig(agentId: string): void {
    this.db.prepare("DELETE FROM agent_llm_config WHERE agent_id = ?").run(agentId);
    this.db.prepare("DELETE FROM llm_strategy_state WHERE agent_id = ?").run(agentId);
  }

  // ---- persisted strategy state (per agent + vendor) ----

  /** Returns the persisted state, or fresh counters when none exists yet. */
  getLlmStrategyState(agentId: string, vendor: string): LlmStrategyState {
    const r = this.db
      .prepare("SELECT * FROM llm_strategy_state WHERE agent_id = ? AND vendor = ?")
      .get(agentId, vendor) as Row | undefined;
    if (r) return rowToLlmStrategyState(r);
    return {
      agentId,
      vendor,
      activeIndex: 0,
      rrCursor: -1,
      callsSinceFallback: 0,
      cooldowns: {},
      updatedAt: now(),
    };
  }

  setLlmStrategyState(
    agentId: string,
    vendor: string,
    state: {
      activeIndex: number;
      rrCursor: number;
      callsSinceFallback: number;
      cooldowns: Record<string, number>;
    },
  ): void {
    this.db
      .prepare(
        `INSERT INTO llm_strategy_state (agent_id, vendor, active_index, rr_cursor, calls_since_fallback, cooldowns, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(agent_id, vendor) DO UPDATE SET active_index = excluded.active_index,
           rr_cursor = excluded.rr_cursor, calls_since_fallback = excluded.calls_since_fallback,
           cooldowns = excluded.cooldowns, updated_at = excluded.updated_at`,
      )
      .run(
        agentId,
        vendor,
        state.activeIndex,
        state.rrCursor,
        state.callsSinceFallback,
        JSON.stringify(state.cooldowns),
        now(),
      );
  }

  /** Drops the persisted strategy counters for an agent (fresh start). */
  clearLlmStrategyState(agentId: string): void {
    this.db.prepare("DELETE FROM llm_strategy_state WHERE agent_id = ?").run(agentId);
  }

  // ---- LLM usage (selection event log + per-connection counters) ----

  recordLlmUsage(event: {
    connectionId: string;
    connectionName?: string | null;
    agentId?: string | null;
    vendor?: string | null;
    model?: string | null;
    strategy?: LlmStrategy | null;
    requests?: number;
    errors?: number;
    inputTokens?: number | null;
    outputTokens?: number | null;
    selected?: boolean;
    failover?: boolean;
    status?: number | null;
  }): void {
    this.db
      .prepare(
        `INSERT INTO llm_usage (ts, connection_id, connection_name, agent_id, vendor, model, strategy, requests, errors, input_tokens, output_tokens, selected, failover, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        now(),
        event.connectionId,
        event.connectionName ?? null,
        event.agentId ?? null,
        event.vendor ?? null,
        event.model ?? null,
        event.strategy ?? null,
        event.requests ?? 1,
        event.errors ?? 0,
        event.inputTokens ?? null,
        event.outputTokens ?? null,
        event.selected === false ? 0 : 1,
        event.failover ? 1 : 0,
        event.status ?? null,
      );
  }

  listLlmUsage(
    opts: { limit?: number; connectionId?: string; agentId?: string; since?: string; until?: string } = {},
  ): LlmUsageEvent[] {
    const limit = clampLimit(opts.limit, 200, 1000);
    const where: string[] = [];
    const params: (string | number)[] = [];
    if (opts.connectionId) {
      where.push("connection_id = ?");
      params.push(opts.connectionId);
    }
    if (opts.agentId) {
      where.push("agent_id = ?");
      params.push(opts.agentId);
    }
    if (opts.since) {
      where.push("ts >= ?");
      params.push(opts.since);
    }
    if (opts.until) {
      where.push("ts <= ?");
      params.push(opts.until);
    }
    const sql = `SELECT * FROM llm_usage${where.length ? ` WHERE ${where.join(" AND ")}` : ""} ORDER BY id DESC LIMIT ?`;
    return (this.db.prepare(sql).all(...params, limit) as Row[]).map(rowToLlmUsageEvent);
  }

  /**
   * Request/error/failover/token totals over an optional ISO time range,
   * grouped per connection. Tokens sum what the proxy could parse (null
   * token rows count as 0).
   */
  llmUsageByConnection(range: { since?: string; until?: string } = {}): Array<{
    connectionId: string;
    connectionName: string | null;
    vendor: string | null;
    requests: number;
    errors: number;
    failovers: number;
    inputTokens: number;
    outputTokens: number;
    lastUsed: string | null;
  }> {
    const { where, params } = usageRange(range);
    const rows = this.db
      .prepare(
        `SELECT connection_id, MAX(connection_name) AS connection_name, MAX(vendor) AS vendor,
                SUM(requests) AS requests, SUM(errors) AS errors, SUM(failover) AS failovers,
                COALESCE(SUM(input_tokens), 0) AS input_tokens, COALESCE(SUM(output_tokens), 0) AS output_tokens,
                MAX(ts) AS last_used
         FROM llm_usage${where} GROUP BY connection_id ORDER BY connection_id`,
      )
      .all(...params) as Row[];
    return rows.map((r) => ({
      connectionId: r.connection_id,
      connectionName: r.connection_name ?? null,
      vendor: r.vendor ?? null,
      requests: Number(r.requests),
      errors: Number(r.errors),
      failovers: Number(r.failovers),
      inputTokens: Number(r.input_tokens),
      outputTokens: Number(r.output_tokens),
      lastUsed: r.last_used ?? null,
    }));
  }

  /** Same totals as llmUsageByConnection, grouped per vendor. */
  llmUsageByVendor(range: { since?: string; until?: string } = {}): Array<{
    vendor: string | null;
    requests: number;
    errors: number;
    failovers: number;
    inputTokens: number;
    outputTokens: number;
    lastUsed: string | null;
  }> {
    const { where, params } = usageRange(range);
    const rows = this.db
      .prepare(
        `SELECT vendor, SUM(requests) AS requests, SUM(errors) AS errors, SUM(failover) AS failovers,
                COALESCE(SUM(input_tokens), 0) AS input_tokens, COALESCE(SUM(output_tokens), 0) AS output_tokens,
                MAX(ts) AS last_used
         FROM llm_usage${where} GROUP BY vendor ORDER BY vendor`,
      )
      .all(...params) as Row[];
    return rows.map((r) => ({
      vendor: r.vendor ?? null,
      requests: Number(r.requests),
      errors: Number(r.errors),
      failovers: Number(r.failovers),
      inputTokens: Number(r.input_tokens),
      outputTokens: Number(r.output_tokens),
      lastUsed: r.last_used ?? null,
    }));
  }

  /**
   * Same totals as llmUsageByConnection, grouped per (vendor, model). Rows
   * written before per-model tracking, or requests whose model could not be
   * parsed, carry a null model and roll up under a null model key (callers
   * render it as "(unknown)").
   */
  llmUsageByModel(range: { since?: string; until?: string } = {}): Array<{
    vendor: string | null;
    model: string | null;
    requests: number;
    errors: number;
    failovers: number;
    inputTokens: number;
    outputTokens: number;
    lastUsed: string | null;
  }> {
    const { where, params } = usageRange(range);
    const rows = this.db
      .prepare(
        `SELECT vendor, model, SUM(requests) AS requests, SUM(errors) AS errors, SUM(failover) AS failovers,
                COALESCE(SUM(input_tokens), 0) AS input_tokens, COALESCE(SUM(output_tokens), 0) AS output_tokens,
                MAX(ts) AS last_used
         FROM llm_usage${where} GROUP BY vendor, model ORDER BY requests DESC`,
      )
      .all(...params) as Row[];
    return rows.map((r) => ({
      vendor: r.vendor ?? null,
      model: r.model ?? null,
      requests: Number(r.requests),
      errors: Number(r.errors),
      failovers: Number(r.failovers),
      inputTokens: Number(r.input_tokens),
      outputTokens: Number(r.output_tokens),
      lastUsed: r.last_used ?? null,
    }));
  }

  /**
   * Per (agent, vendor, model) totals over an optional range. This is the
   * "per bot per model" breakdown, the finest rollup the usage log supports.
   */
  llmUsageByAgentModel(range: { since?: string; until?: string } = {}): Array<{
    agentId: string | null;
    vendor: string | null;
    model: string | null;
    requests: number;
    errors: number;
    failovers: number;
    inputTokens: number;
    outputTokens: number;
    lastUsed: string | null;
  }> {
    const { where, params } = usageRange(range);
    const rows = this.db
      .prepare(
        `SELECT agent_id, vendor, model, SUM(requests) AS requests, SUM(errors) AS errors, SUM(failover) AS failovers,
                COALESCE(SUM(input_tokens), 0) AS input_tokens, COALESCE(SUM(output_tokens), 0) AS output_tokens,
                MAX(ts) AS last_used
         FROM llm_usage${where} GROUP BY agent_id, vendor, model ORDER BY requests DESC`,
      )
      .all(...params) as Row[];
    return rows.map((r) => ({
      agentId: r.agent_id ?? null,
      vendor: r.vendor ?? null,
      model: r.model ?? null,
      requests: Number(r.requests),
      errors: Number(r.errors),
      failovers: Number(r.failovers),
      inputTokens: Number(r.input_tokens),
      outputTokens: Number(r.output_tokens),
      lastUsed: r.last_used ?? null,
    }));
  }

  /**
   * ESTIMATED turns per (agent, vendor, model) over an optional range.
   *
   * OneGate only sees HTTP LLM requests, not conversational turns, so this is
   * derived by segmenting each agent's requests on an inactivity gap
   * (TURN_GAP_MS). It is an ESTIMATE (see segmentTurns / the
   * `llm_turns_estimated` view), never an exact count.
   */
  estimatedTurnsByAgentModel(range: { since?: string; until?: string } = {}): Array<{
    agentId: string | null;
    vendor: string | null;
    model: string | null;
    estimatedTurns: number;
  }> {
    const { where, params } = usageRange(range);
    const rows = this.db
      .prepare(
        `SELECT agent_id, vendor, model, ts FROM llm_usage${where} ORDER BY agent_id, ts, id`,
      )
      .all(...params) as Row[];
    const segmented = segmentTurns(
      rows.map((r) => ({
        agentId: r.agent_id ?? null,
        vendor: r.vendor ?? null,
        model: r.model ?? null,
        ts: String(r.ts),
      })),
    );
    return [...segmented.values()]
      .map((v) => ({
        agentId: v.agentId,
        vendor: v.vendor,
        model: v.model,
        estimatedTurns: v.turns,
      }))
      .sort((a, b) => b.estimatedTurns - a.estimatedTurns);
  }

  /** ESTIMATED turns per (vendor, model), summed across agents. See
   * estimatedTurnsByAgentModel / segmentTurns. ESTIMATE only. */
  estimatedTurnsByModel(range: { since?: string; until?: string } = {}): Array<{
    vendor: string | null;
    model: string | null;
    estimatedTurns: number;
  }> {
    const byModel = new Map<string, { vendor: string | null; model: string | null; estimatedTurns: number }>();
    for (const r of this.estimatedTurnsByAgentModel(range)) {
      const key = `${r.vendor ?? ""}|${r.model ?? ""}`;
      const cur = byModel.get(key);
      if (cur) cur.estimatedTurns += r.estimatedTurns;
      else byModel.set(key, { vendor: r.vendor, model: r.model, estimatedTurns: r.estimatedTurns });
    }
    return [...byModel.values()].sort((a, b) => b.estimatedTurns - a.estimatedTurns);
  }

  /** Per-connection request/error/token totals, rolled up from the event log. */
  llmUsageTotals(): Array<{
    connectionId: string;
    requests: number;
    errors: number;
    inputTokens: number;
    outputTokens: number;
  }> {
    const rows = this.db
      .prepare(
        `SELECT connection_id, SUM(requests) AS requests, SUM(errors) AS errors,
                COALESCE(SUM(input_tokens), 0) AS input_tokens, COALESCE(SUM(output_tokens), 0) AS output_tokens
         FROM llm_usage GROUP BY connection_id ORDER BY connection_id`,
      )
      .all() as Row[];
    return rows.map((r) => ({
      connectionId: r.connection_id,
      requests: Number(r.requests),
      errors: Number(r.errors),
      inputTokens: Number(r.input_tokens),
      outputTokens: Number(r.output_tokens),
    }));
  }

  // ---- rules ----

  createRule(input: {
    scope: RuleScope;
    subjectId: string;
    integrationId: string;
    methods: string[];
    pathGlob: string;
    effect: "allow" | "deny";
    /** Access lease: absolute expiry (ISO) after which an allow rule lapses. */
    expiresAt?: string | null;
    /** Lease duration (seconds) recorded so renewals can re-stamp expiresAt. */
    leaseTtlSeconds?: number | null;
    /** Pin this rule to a specific app connection (with connectionScope). */
    connectionId?: string | null;
    /** "only" = applies for that connection, "except" = applies for all others. */
    connectionScope?: ConnectionScope;
  }): Rule {
    const r: Rule = {
      id: newId("rl"),
      ...input,
      methods: input.methods.map((m) => m.toUpperCase()),
      createdAt: now(),
      expiresAt: input.expiresAt ?? null,
      leaseTtlSeconds: input.leaseTtlSeconds ?? null,
      connectionId: input.connectionId ?? null,
      connectionScope: input.connectionScope,
    };
    this.db
      .prepare(
        "INSERT INTO rules (id, scope, subject_id, integration_id, methods, path_glob, effect, created_at, expires_at, lease_ttl_seconds, connection_id, connection_scope) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        r.id,
        r.scope,
        r.subjectId,
        r.integrationId,
        JSON.stringify(r.methods),
        r.pathGlob,
        r.effect,
        r.createdAt,
        r.expiresAt ?? null,
        r.leaseTtlSeconds ?? null,
        r.connectionId ?? null,
        r.connectionScope ?? null,
      );
    return r;
  }

  getRule(id: string): Rule | null {
    const r = this.db.prepare("SELECT * FROM rules WHERE id = ?").get(id) as Row | undefined;
    return r ? rowToRule(r) : null;
  }

  /**
   * Sets (or clears) an allow rule's access lease. `expiresAt` null clears the
   * lease (always-on); `leaseTtlSeconds` is recorded for later renewals.
   */
  stampRuleLease(id: string, expiresAt: string | null, leaseTtlSeconds: number | null): void {
    this.db
      .prepare("UPDATE rules SET expires_at = ?, lease_ttl_seconds = ? WHERE id = ?")
      .run(expiresAt, leaseTtlSeconds, id);
  }

  /**
   * One-tap renewal: re-stamps a rule's `expires_at` to now + its recorded
   * lease TTL, WITHOUT re-entering the credential. No-op (returns the rule
   * unchanged) when the rule has no lease TTL (always-on). Returns null if the
   * rule does not exist.
   */
  renewRule(id: string): Rule | null {
    const rule = this.getRule(id);
    if (!rule) return null;
    const ttl = rule.leaseTtlSeconds ?? null;
    if (!ttl || ttl <= 0) return rule;
    const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
    this.db.prepare("UPDATE rules SET expires_at = ? WHERE id = ?").run(expiresAt, id);
    return this.getRule(id);
  }

  // ---- integration leases (time-boxed defaults) ----

  /** The default lease TTL (seconds) for a time-boxed integration, or null. */
  getIntegrationLease(integrationId: string): number | null {
    const r = this.db
      .prepare("SELECT ttl_seconds FROM integration_leases WHERE integration_id = ?")
      .get(integrationId) as Row | undefined;
    return r ? Number(r.ttl_seconds) : null;
  }

  listIntegrationLeases(): IntegrationLease[] {
    return (
      this.db.prepare("SELECT * FROM integration_leases ORDER BY integration_id").all() as Row[]
    ).map((r) => ({
      integrationId: r.integration_id,
      ttlSeconds: Number(r.ttl_seconds),
      updatedAt: r.updated_at,
    }));
  }

  /** Marks an integration time-boxed with a default lease TTL (seconds). */
  setIntegrationLease(integrationId: string, ttlSeconds: number): void {
    this.db
      .prepare(
        `INSERT INTO integration_leases (integration_id, ttl_seconds, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(integration_id) DO UPDATE SET ttl_seconds = excluded.ttl_seconds, updated_at = excluded.updated_at`,
      )
      .run(integrationId, ttlSeconds, now());
  }

  /** Removes the time-box, making the integration regular (non-time-boxed). */
  clearIntegrationLease(integrationId: string): void {
    this.db.prepare("DELETE FROM integration_leases WHERE integration_id = ?").run(integrationId);
  }

  /**
   * Resolves the effective access-lease TTL (seconds) for a new/renewed allow
   * rule: the owner's per-connection override wins (0 = always-on = no lease),
   * else the integration default, else no lease. Returns null = no lease.
   */
  effectiveLeaseTtlSeconds(integrationId: string, connectionLeaseTtl: number | null): number | null {
    if (connectionLeaseTtl !== null && connectionLeaseTtl !== undefined) {
      return connectionLeaseTtl === 0 ? null : connectionLeaseTtl;
    }
    const def = this.getIntegrationLease(integrationId);
    return def && def > 0 ? def : null;
  }

  listRules(filter: { scope?: RuleScope; subjectId?: string } = {}): Rule[] {
    if (filter.scope && filter.subjectId) {
      return (
        this.db
          .prepare("SELECT * FROM rules WHERE scope = ? AND subject_id = ? ORDER BY created_at")
          .all(filter.scope, filter.subjectId) as Row[]
      ).map(rowToRule);
    }
    return (this.db.prepare("SELECT * FROM rules ORDER BY created_at").all() as Row[]).map(rowToRule);
  }

  /** All rules that apply to an agent: its own plus its project's. */
  rulesForAgent(agent: Agent): Rule[] {
    const own = this.listRules({ scope: "agent", subjectId: agent.id });
    const proj = agent.projectId
      ? this.listRules({ scope: "project", subjectId: agent.projectId })
      : [];
    return [...own, ...proj];
  }

  deleteRule(id: string): void {
    this.db.prepare("DELETE FROM rules WHERE id = ?").run(id);
  }

  // ---- onboarding links (connect wizard) ----

  createOnboardingLink(input: {
    agentId: string;
    integrationId: string;
    scopes?: string[] | null;
    connectionName?: string | null;
    ttlDays?: number;
    /** Set for a RENEWAL link: the allow rule whose lease it re-stamps. */
    ruleId?: string | null;
  }): OnboardingLink {
    const ttlDays = input.ttlDays && input.ttlDays > 0 ? input.ttlDays : 7;
    const createdAt = now();
    const expiresAt = new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000).toISOString();
    const scopes = input.scopes && input.scopes.length ? input.scopes : null;
    const token = randomBytes(24).toString("hex");
    const link: OnboardingLink = {
      // Plaintext token: returned to the caller (goes into the connect URL) but
      // never persisted. Only tokenHash is stored.
      token,
      tokenHash: hashToken(token),
      agentId: input.agentId,
      integrationId: input.integrationId,
      scopes,
      connectionName: input.connectionName ?? null,
      createdAt,
      expiresAt,
      usedAt: null,
      ruleId: input.ruleId ?? null,
    };
    this.db
      .prepare(
        "INSERT INTO onboarding_links (token_hash, agent_id, integration_id, scopes, connection_name, created_at, expires_at, used_at, rule_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        link.tokenHash,
        link.agentId,
        link.integrationId,
        link.scopes ? JSON.stringify(link.scopes) : null,
        link.connectionName,
        link.createdAt,
        link.expiresAt,
        link.usedAt,
        link.ruleId ?? null,
      );
    return link;
  }

  /**
   * The most recent still-valid (unused, unexpired) RENEWAL link for an allow
   * rule, or null. Lets the proxy reuse one live renewal link across repeated
   * lapsed-lease hits instead of minting a fresh one each request.
   */
  activeRenewalLinkFor(_ruleId: string): OnboardingLink | null {
    // Reuse is disabled: only the token hash is stored, so a live link's
    // plaintext token cannot be recovered to rebuild a redeemable URL. Callers
    // mint a fresh link each time; owner-notification dedup (time window /
    // dedupKey) still prevents duplicate notifications.
    return null;
  }

  getOnboardingLink(token: string): OnboardingLink | null {
    const r = this.db
      .prepare("SELECT * FROM onboarding_links WHERE token_hash = ?")
      .get(hashToken(token)) as Row | undefined;
    if (!r) return null;
    // Re-attach the presented plaintext so redemption flows that rebuild the
    // connect URL from link.token continue to emit a redeemable token.
    return { ...rowToOnboardingLink(r), token };
  }

  /**
   * The most recent still-valid (unused, unexpired) onboarding link for an
   * agent+integration, or null. Lets a caller reuse a live link instead of
   * minting a fresh one on every failed request (e.g. a bot retrying a call to
   * an unconnected integration), keeping the onboarding_links table bounded.
   */
  activeOnboardingLinkFor(_agentId: string, _integrationId: string): OnboardingLink | null {
    // Reuse is disabled: only the token hash is stored, so a live link's
    // plaintext token cannot be recovered to rebuild a redeemable URL. Callers
    // mint a fresh link each time; owner-notification dedup (time window /
    // dedupKey) still prevents duplicate notifications.
    return null;
  }

  /** A link is valid iff it exists, is unused, and has not expired. */
  isOnboardingLinkValid(link: OnboardingLink | null): link is OnboardingLink {
    if (!link) return false;
    if (link.usedAt) return false;
    return new Date(link.expiresAt).getTime() > Date.now();
  }

  markOnboardingLinkUsed(token: string): void {
    this.db
      .prepare("UPDATE onboarding_links SET used_at = ? WHERE token_hash = ?")
      .run(now(), hashToken(token));
  }

  listOnboardingLinks(agentId?: string): OnboardingLink[] {
    const rows = agentId
      ? (this.db
          .prepare("SELECT * FROM onboarding_links WHERE agent_id = ? ORDER BY created_at DESC")
          .all(agentId) as Row[])
      : (this.db
          .prepare("SELECT * FROM onboarding_links ORDER BY created_at DESC")
          .all() as Row[]);
    return rows.map(rowToOnboardingLink);
  }

  deleteOnboardingLink(token: string): void {
    // Accept either the plaintext token (from a connect URL) or the stored hash
    // itself (which is what the admin list surfaces). The two never collide: a
    // plaintext token is 48 hex chars, a hash is 64. This keeps admin
    // revoke-from-list working without exposing the plaintext.
    this.db
      .prepare("DELETE FROM onboarding_links WHERE token_hash = ? OR token_hash = ?")
      .run(hashToken(token), token);
  }

  // ---- per-agent notify webhook (owner notification config) ----

  /**
   * Sets (or replaces) the notify webhook URL for an agent. The URL is sealed
   * with the SecretBox so a leaked DB does not expose the token embedded in the
   * webhook URL (e.g. a Telegram bot hook).
   */
  setAgentNotify(agentId: string, webhookUrl: string): void {
    const ts = now();
    this.db
      .prepare(
        `INSERT INTO agent_notify (agent_id, webhook_url, created_at, updated_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(agent_id) DO UPDATE SET webhook_url = excluded.webhook_url, updated_at = excluded.updated_at`,
      )
      .run(agentId, this.secrets.seal(webhookUrl), ts, ts);
  }

  /**
   * Returns the decrypted webhook URL for an agent, or null if not set.
   *
   * An undecryptable row (rotated key, restored key mismatch, corrupt envelope)
   * degrades to "no webhook configured" rather than throwing: the main caller is
   * `maybeNotifyOwner` on the proxy's deny path, whose async handler promise is
   * never awaited, so a throw there would surface as an unhandled rejection and
   * kill the gateway process for every agent, not just the one with the bad row.
   */
  getAgentNotify(agentId: string): string | null {
    const r = this.db
      .prepare("SELECT webhook_url FROM agent_notify WHERE agent_id = ?")
      .get(agentId) as Row | undefined;
    if (!r) return null;
    return safeOpen<string>(this.secrets, r.webhook_url, `agent_notify:${agentId}`);
  }

  /** Removes the notify webhook config for an agent. No-op if not set. */
  clearAgentNotify(agentId: string): void {
    this.db.prepare("DELETE FROM agent_notify WHERE agent_id = ?").run(agentId);
  }

  // ---- owner notifications (dedup + delivery tracking) ----

  /**
   * Returns the most recent owner_notification for (agentId, integrationId)
   * created at or after `sinceIso`, for dedup. Returns null if none exists
   * within the window, meaning a new notification may be sent.
   */
  findRecentOwnerNotification(
    agentId: string,
    integrationId: string,
    sinceIso: string,
  ): OwnerNotification | null {
    const r = this.db
      .prepare(
        "SELECT * FROM owner_notifications WHERE agent_id = ? AND integration_id = ? AND created_at >= ? ORDER BY id DESC LIMIT 1",
      )
      .get(agentId, integrationId, sinceIso) as Row | undefined;
    return r ? rowToOwnerNotification(r) : null;
  }

  /**
   * Returns the most recent owner_notification carrying `dedupKey`, or null.
   * Used for lease-lapse dedup: the key is `lease:<ruleId>:<expiresAt>`, so each
   * distinct lapse is a new key (always reaches the owner) while repeated
   * requests within one lapse collapse to a single notification.
   */
  findOwnerNotificationByDedupKey(dedupKey: string): OwnerNotification | null {
    const r = this.db
      .prepare(
        "SELECT * FROM owner_notifications WHERE dedup_key = ? ORDER BY id DESC LIMIT 1",
      )
      .get(dedupKey) as Row | undefined;
    return r ? rowToOwnerNotification(r) : null;
  }

  /** Inserts a new owner_notification row with status "pending". */
  enqueueOwnerNotification(input: {
    agentId: string;
    integrationId: string;
    connectToken: string | null;
    dedupKey?: string | null;
  }): OwnerNotification {
    const ts = now();
    // The connect token is a bearer capability, so persist only its hash (the
    // plaintext lives in the delivered connect URL). It is stored purely for
    // tracking/audit here and is never redeemed by lookup, so a hash suffices.
    const connectTokenHash = input.connectToken ? hashToken(input.connectToken) : null;
    const result = this.db
      .prepare(
        "INSERT INTO owner_notifications (agent_id, integration_id, connect_token, status, created_at, delivered_at, last_attempt_at, attempts, error, dedup_key) VALUES (?, ?, ?, 'pending', ?, NULL, NULL, 0, NULL, ?)",
      )
      .run(input.agentId, input.integrationId, connectTokenHash, ts, input.dedupKey ?? null);
    const id = Number(result.lastInsertRowid);
    return rowToOwnerNotification(
      this.db.prepare("SELECT * FROM owner_notifications WHERE id = ?").get(id) as Row,
    );
  }

  /** Updates status, deliveredAt, error, and optionally increments attempts. */
  markOwnerNotification(
    id: number,
    patch: {
      status: OwnerNotificationStatus;
      deliveredAt?: string | null;
      error?: string | null;
      incrementAttempt?: boolean;
    },
  ): void {
    const ts = now();
    this.db
      .prepare(
        `UPDATE owner_notifications SET
           status = ?,
           delivered_at = CASE WHEN ? IS NOT NULL THEN ? ELSE delivered_at END,
           last_attempt_at = ?,
           attempts = CASE WHEN ? THEN attempts + 1 ELSE attempts END,
           error = ?
         WHERE id = ?`,
      )
      .run(
        patch.status,
        patch.deliveredAt ?? null,
        patch.deliveredAt ?? null,
        ts,
        patch.incrementAttempt ? 1 : 0,
        patch.error ?? null,
        id,
      );
  }

  /** Lists owner_notifications most-recent-first. */
  listOwnerNotifications(opts: { limit?: number; status?: OwnerNotificationStatus } = {}): OwnerNotification[] {
    const limit = clampLimit(opts.limit, 100, 500);
    if (opts.status) {
      return (
        this.db
          .prepare("SELECT * FROM owner_notifications WHERE status = ? ORDER BY id DESC LIMIT ?")
          .all(opts.status, limit) as Row[]
      ).map(rowToOwnerNotification);
    }
    return (
      this.db
        .prepare("SELECT * FROM owner_notifications ORDER BY id DESC LIMIT ?")
        .all(limit) as Row[]
    ).map(rowToOwnerNotification);
  }

  // ---- audit ----

  audit(entry: {
    agentId?: string | null;
    agentName?: string | null;
    integrationId?: string | null;
    host: string;
    method?: string | null;
    path?: string | null;
    decision: Decision;
    ruleId?: string | null;
    status?: number | null;
    connectionId?: string | null;
    connectionName?: string | null;
    llmVendor?: string | null;
    llmStrategy?: LlmStrategy | null;
    llmFailover?: boolean;
  }): void {
    this.db
      .prepare(
        "INSERT INTO audit (ts, agent_id, agent_name, integration_id, host, method, path, decision, rule_id, status, connection_id, connection_name, llm_vendor, llm_strategy, llm_failover) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        now(),
        entry.agentId ?? null,
        entry.agentName ?? null,
        entry.integrationId ?? null,
        entry.host,
        entry.method ?? null,
        entry.path ?? null,
        entry.decision,
        entry.ruleId ?? null,
        entry.status ?? null,
        entry.connectionId ?? null,
        entry.connectionName ?? null,
        entry.llmVendor ?? null,
        entry.llmStrategy ?? null,
        entry.llmFailover === undefined ? null : entry.llmFailover ? 1 : 0,
      );
  }

  listAudit(opts: { limit?: number; agentId?: string } = {}): AuditEntry[] {
    const limit = clampLimit(opts.limit, 200, 1000);
    const rows = opts.agentId
      ? (this.db
          .prepare("SELECT * FROM audit WHERE agent_id = ? ORDER BY id DESC LIMIT ?")
          .all(opts.agentId, limit) as Row[])
      : (this.db.prepare("SELECT * FROM audit ORDER BY id DESC LIMIT ?").all(limit) as Row[]);
    return rows.map((r) => {
      const decision = r.decision as Decision;
      const ruleId = r.rule_id ?? null;
      const status = r.status === null || r.status === undefined ? null : Number(r.status);
      return {
        id: Number(r.id),
        ts: r.ts,
        agentId: r.agent_id ?? null,
        agentName: r.agent_name ?? null,
        integrationId: r.integration_id ?? null,
        host: r.host,
        method: r.method ?? null,
        path: r.path ?? null,
        decision,
        ruleId,
        status,
        source: auditSource(decision),
        reason: auditReason({ decision, ruleId, status }),
        connectionId: r.connection_id ?? null,
        connectionName: r.connection_name ?? null,
        llmVendor: r.llm_vendor ?? null,
        llmStrategy: (r.llm_strategy as LlmStrategy | null) ?? null,
        llmFailover: r.llm_failover === null || r.llm_failover === undefined ? null : r.llm_failover === 1,
      };
    });
  }
}
