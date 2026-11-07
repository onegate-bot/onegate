/**
 * OneGate cluster: the database side of replication.
 *
 * Model (docs/CLUSTER.md has the operator view):
 *  - Every node accepts writes. Capture triggers (src/store/cluster-schema.ts)
 *    append each local change of a shared table to `cluster_changelog`, stamped
 *    with a version (ts = writer's clock in ms, origin = writer's node id).
 *  - A node serves ONLY its own changes; every node pulls from every peer (full
 *    mesh, membership itself replicates through `cluster_peers`). No relaying
 *    means no loops and no duplicate delivery, at the price that a node lost
 *    for good takes the tail its peers had not pulled yet with it.
 *  - Apply is last-writer-wins per row: a remote change lands only if its
 *    (ts, origin) beats the version in `cluster_row_meta`. Ties on ts break on
 *    origin, so every node picks the same winner whatever order it pulls in.
 *  - Two nodes creating different rows that collide on a UNIQUE column (two
 *    agents both named "bob") resolve the same way: the newer version survives
 *    and the resolving node writes a CAPTURED tombstone for the loser, so the
 *    resolution itself replicates and nodes that never saw the collision still
 *    converge.
 */

import { randomBytes } from "node:crypto";
import type { Store } from "../store/db.js";
import type { SecretBox } from "../store/secret-box.js";
import {
  CAPTURE_GUARD_TABLE,
  CLUSTER_SETTING_PREFIX,
  SHARED_TABLES,
  isValidNodeId,
  sharedTableSpec,
  type SharedTableSpec,
} from "../store/cluster-schema.js";
import { deriveClusterKeys, joinMasterKey, joinTokenId, newJoinToken, type ClusterKeys } from "./crypto.js";

type DatabaseSync = import("node:sqlite").DatabaseSync;
/* eslint-disable @typescript-eslint/no-explicit-any */
type Row = Record<string, any>;

const KEY_NODE_ID = `${CLUSTER_SETTING_PREFIX}node_id`;
const KEY_CLUSTER_ID = `${CLUSTER_SETTING_PREFIX}id`;
const KEY_SECRET = `${CLUSTER_SETTING_PREFIX}secret`;
const KEY_ADVERTISE = `${CLUSTER_SETTING_PREFIX}advertise_url`;

/** Upper bound on one page of changes served to a peer. */
export const MAX_CHANGES_PAGE = 1000;
/** Default and maximum lifetime of a join token. */
export const DEFAULT_JOIN_TTL_SECONDS = 15 * 60;
export const MAX_JOIN_TTL_SECONDS = 24 * 60 * 60;

/** An error carrying the HTTP status the cluster listener / admin API returns. */
export class ClusterError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message?: string,
  ) {
    super(message ?? code);
    this.name = "ClusterError";
  }
}

export interface ClusterChange {
  seq: number;
  tbl: string;
  /** JSON array of the primary-key values. */
  pk: string;
  op: "upsert" | "delete";
  /** JSON object of the replicated columns; null for a delete. */
  row: string | null;
  ts: number;
  origin: string;
}

export interface RowMeta {
  tbl: string;
  pk: string;
  ts: number;
  origin: string;
  deleted: number;
}

/** Everything a joining node needs to start from this node's state. */
export interface ClusterSnapshot {
  nodeId: string;
  clusterId: string;
  /** This node's changelog head; the snapshot is consistent with it. */
  head: number;
  /** Where to start pulling from each node: this node's cursors plus itself at `head`. */
  cursors: Record<string, number>;
  tables: Record<string, Row[]>;
  meta: RowMeta[];
}

export interface ClusterPeer {
  nodeId: string;
  url: string;
  addedAt: string;
}

export interface PeerStatus extends ClusterPeer {
  self: boolean;
  /** Last applied seq of the peer's changelog. */
  cursor: number | null;
  remoteHead: number | null;
  lag: number | null;
  lastOkAt: string | null;
  lastError: string | null;
  lastErrorAt: string | null;
  clockSkewMs: number | null;
}

export interface ClusterStatus {
  enabled: boolean;
  nodeId: string | null;
  clusterId: string | null;
  advertiseUrl: string | null;
  /** Whether this node is still listed in cluster_peers (false after a remote `peers remove`). */
  member: boolean;
  head: number;
  changelogRows: number;
  conflicts: number;
  peers: PeerStatus[];
}

export interface ApplyResult {
  applied: number;
  skipped: number;
  conflicts: number;
}

function nowIso(): string {
  return new Date().toISOString();
}

/** (ts, origin) ordering. Deterministic on every node. */
export function isNewer(a: { ts: number; origin: string }, b: { ts: number; origin: string }): boolean {
  return a.ts > b.ts || (a.ts === b.ts && a.origin > b.origin);
}

export function validateClusterUrl(raw: unknown): string {
  if (typeof raw !== "string" || !raw.trim()) throw new ClusterError(400, "url_required");
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new ClusterError(400, "invalid_url", `not a URL: ${raw}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new ClusterError(400, "invalid_url", "cluster URLs must be http:// or https://");
  }
  return u.origin;
}

export class ClusterState {
  private readonly db: DatabaseSync;
  private readonly secrets: SecretBox;
  private uniqueIndexCache = new Map<string, string[][]>();

  constructor(private readonly store: Store) {
    const internals = store.clusterInternals();
    this.db = internals.db;
    this.secrets = internals.secrets;
  }

  // ---- identity & membership ----

  /** This node's id, or null if it was never given one. */
  peekNodeId(): string | null {
    return this.store.getSetting(KEY_NODE_ID);
  }

  /** This node's id, generated and persisted on first use. */
  nodeId(): string {
    const existing = this.peekNodeId();
    if (existing) return existing;
    const id = `ogn_${randomBytes(8).toString("hex")}`;
    this.store.setSetting(KEY_NODE_ID, id);
    return id;
  }

  isEnabled(): boolean {
    return this.store.getSetting(KEY_CLUSTER_ID) !== null && this.peekNodeId() !== null;
  }

  clusterId(): string | null {
    return this.store.getSetting(KEY_CLUSTER_ID);
  }

  advertiseUrl(): string | null {
    return this.store.getSetting(KEY_ADVERTISE);
  }

  private requireEnabled(): { nodeId: string; clusterId: string } {
    const clusterId = this.clusterId();
    const nodeId = this.peekNodeId();
    if (!clusterId || !nodeId) throw new ClusterError(409, "cluster_not_initialized", "this node is not in a cluster");
    return { nodeId, clusterId };
  }

  /** The shared cluster secret (sealed at rest with the DB key). */
  secret(): string {
    this.requireEnabled();
    const sealed = this.store.getSetting(KEY_SECRET);
    if (!sealed) throw new ClusterError(500, "cluster_secret_missing");
    return this.secrets.open<string>(sealed);
  }

  keys(): ClusterKeys {
    const { clusterId } = this.requireEnabled();
    return deriveClusterKeys(this.secret(), clusterId);
  }

  /**
   * `onegate cluster init`: makes this node the first member of a new cluster.
   * Existing rows are not copied into the changelog; a joiner bootstraps from
   * a snapshot instead (GET /cluster/v1/snapshot or the join exchange).
   */
  init(advertiseUrl: string): ClusterStatus {
    if (this.isEnabled()) throw new ClusterError(409, "already_in_cluster", `this node is already in cluster ${this.clusterId()}`);
    const url = validateClusterUrl(advertiseUrl);
    const nodeId = this.nodeId();
    this.store.setSetting(KEY_CLUSTER_ID, `ogc_${randomBytes(8).toString("hex")}`);
    this.store.setSetting(KEY_SECRET, this.secrets.seal(randomBytes(32).toString("base64url")));
    this.store.setSetting(KEY_ADVERTISE, url);
    this.store.syncClusterCapture();
    this.upsertPeer(nodeId, url);
    return this.status();
  }

  listPeers(): ClusterPeer[] {
    return (this.db.prepare("SELECT node_id, url, added_at FROM cluster_peers ORDER BY added_at, node_id").all() as Row[]).map(
      (r) => ({ nodeId: String(r.node_id), url: String(r.url), addedAt: String(r.added_at) }),
    );
  }

  /** Adds or re-points a peer. A captured write, so every node learns it. */
  upsertPeer(nodeId: string, url: string): ClusterPeer {
    this.requireEnabled();
    if (!isValidNodeId(nodeId)) throw new ClusterError(400, "invalid_node_id");
    const clean = validateClusterUrl(url);
    this.db
      .prepare(
        "INSERT INTO cluster_peers (node_id, url, added_at) VALUES (?, ?, ?) ON CONFLICT(node_id) DO UPDATE SET url = excluded.url",
      )
      .run(nodeId, clean, nowIso());
    return this.listPeers().find((p) => p.nodeId === nodeId)!;
  }

  /** Removes a peer everywhere (captured). Returns false if it was not listed. */
  removePeer(nodeId: string): boolean {
    this.requireEnabled();
    return Number(this.db.prepare("DELETE FROM cluster_peers WHERE node_id = ?").run(nodeId).changes) > 0;
  }

  /**
   * `onegate cluster leave`: this node stops replicating. Shared config stays
   * as it is (the node keeps serving it standalone); the cluster bookkeeping
   * and the cluster secret are erased. The node id is kept, so a later re-join
   * continues its changelog sequence instead of restarting at 1 (which peers
   * still holding a cursor for it would otherwise skip). Telling the peers to
   * drop this node is the caller's job (ClusterRuntime.leave announces it; an
   * operator can also run `cluster peers remove` on any remaining node).
   */
  leave(): void {
    this.requireEnabled();
    for (const k of [KEY_CLUSTER_ID, KEY_SECRET, KEY_ADVERTISE]) this.store.deleteSetting(k);
    this.store.syncClusterCapture();
    this.tx(() => {
      for (const t of ["cluster_changelog", "cluster_row_meta", "cluster_cursors", "cluster_acks", "cluster_conflicts", "cluster_join_tokens", "cluster_peers"]) {
        this.db.exec(`DELETE FROM ${t}`);
      }
    });
  }

  // ---- serving ----

  /** Highest seq ever assigned in this node's changelog (survives compaction). */
  head(): number {
    const r = this.db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'cluster_changelog'").get() as Row | undefined;
    return r ? Number(r.seq) : 0;
  }

  /**
   * One page of this node's own changes after `since`. Records `since` as the
   * requester's acknowledgement, which is what lets compaction drop history.
   */
  changesSince(since: number, limit: number, requester: string): { changes: ClusterChange[]; head: number; more: boolean } {
    this.requireEnabled();
    if (!Number.isInteger(since) || since < 0) throw new ClusterError(400, "invalid_since");
    const lim = Number.isInteger(limit) && limit > 0 ? Math.min(limit, MAX_CHANGES_PAGE) : 500;
    const head = this.head();
    if (since > head) {
      // Our sequence went backwards: this node's database was restored from
      // an older copy. Changes the peer believes it has are gone; say so
      // instead of silently serving a gap.
      throw new ClusterError(409, "cursor_ahead", `cursor ${since} is ahead of this node's head ${head}`);
    }
    const min = this.db.prepare("SELECT MIN(seq) AS m FROM cluster_changelog").get() as Row;
    const oldest = min.m === null ? head + 1 : Number(min.m);
    if (since + 1 < oldest) {
      throw new ClusterError(410, "cursor_compacted", `changes after ${since} were compacted; re-join the node`);
    }
    const changes = (
      this.db.prepare("SELECT seq, tbl, pk, op, row, ts, origin FROM cluster_changelog WHERE seq > ? ORDER BY seq LIMIT ?").all(since, lim) as Row[]
    ).map((r) => ({
      seq: Number(r.seq),
      tbl: String(r.tbl),
      pk: String(r.pk),
      op: r.op as ClusterChange["op"],
      row: r.row === null ? null : String(r.row),
      ts: Number(r.ts),
      origin: String(r.origin),
    }));
    if (isValidNodeId(requester)) {
      this.db
        .prepare(
          "INSERT INTO cluster_acks (peer_node_id, seq, at) VALUES (?, ?, ?) ON CONFLICT(peer_node_id) DO UPDATE SET seq = excluded.seq, at = excluded.at",
        )
        .run(requester, since, nowIso());
    }
    const last = changes.length ? changes[changes.length - 1].seq : since;
    return { changes, head, more: last < head && changes.length === lim };
  }

  /** A consistent copy of every shared row, the LWW versions, and the cursors. */
  snapshot(): ClusterSnapshot {
    const { nodeId, clusterId } = this.requireEnabled();
    this.db.exec("BEGIN");
    try {
      const tables: Record<string, Row[]> = {};
      for (const spec of SHARED_TABLES) {
        const where = spec.filter ? ` WHERE ${spec.filter(spec.table)}` : "";
        tables[spec.table] = (this.db.prepare(`SELECT ${spec.columns.join(", ")} FROM ${spec.table}${where}`).all() as Row[]).map((r) => ({ ...r }));
      }
      const meta = (this.db.prepare("SELECT tbl, pk, ts, origin, deleted FROM cluster_row_meta").all() as Row[]).map((r) => ({
        tbl: String(r.tbl),
        pk: String(r.pk),
        ts: Number(r.ts),
        origin: String(r.origin),
        deleted: Number(r.deleted),
      }));
      const head = this.head();
      const cursors: Record<string, number> = {};
      for (const r of this.db.prepare("SELECT peer_node_id, seq FROM cluster_cursors").all() as Row[]) {
        cursors[String(r.peer_node_id)] = Number(r.seq);
      }
      cursors[nodeId] = head;
      this.db.exec("COMMIT");
      return { nodeId, clusterId, head, cursors, tables, meta };
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  // ---- applying ----

  private tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const out = fn();
      this.db.exec("COMMIT");
      return out;
    } catch (err) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // already rolled back by SQLite; keep the original error
      }
      throw err;
    }
  }

  /**
   * Runs `fn` as an apply transaction: capture suppressed (the guard row), and
   * foreign keys OFF. FK enforcement is off because changes from different
   * origins arrive in pull order, not causal order: a grant made on node B may
   * arrive before the connection it references, made on node C. Every FK
   * effect (CASCADE, SET NULL) was already captured as its own change on the
   * node where it happened, so nothing is lost by not re-running them here; an
   * orphan is transient until the parent arrives. PRAGMA foreign_keys is a
   * no-op inside a transaction, hence outside.
   */
  private applyTx<T>(fn: () => T): T {
    this.db.exec("PRAGMA foreign_keys = OFF");
    try {
      return this.tx(() => {
        this.db.exec(`CREATE TEMP TABLE IF NOT EXISTS ${CAPTURE_GUARD_TABLE} (active INTEGER)`);
        this.db.exec(`INSERT INTO ${CAPTURE_GUARD_TABLE} (active) VALUES (1)`);
        const out = fn();
        this.db.exec(`DELETE FROM ${CAPTURE_GUARD_TABLE}`);
        return out;
      });
    } finally {
      this.db.exec("PRAGMA foreign_keys = ON");
    }
  }

  /**
   * Applies one page of a peer's changes and advances that peer's cursor, in
   * one transaction: either the whole page lands with the cursor, or nothing
   * does and the same page is pulled again.
   */
  applyChanges(peerNodeId: string, changes: ClusterChange[], remoteHead: number | null): ApplyResult {
    const { nodeId } = this.requireEnabled();
    const result: ApplyResult = { applied: 0, skipped: 0, conflicts: 0 };
    this.applyTx(() => {
      const cur = this.db.prepare("SELECT seq FROM cluster_cursors WHERE peer_node_id = ?").get(peerNodeId) as Row | undefined;
      let cursor = cur ? Number(cur.seq) : 0;
      for (const c of changes) {
        // Only own-origin changes are served, in seq order.
        if (c.origin !== peerNodeId) throw new ClusterError(502, "foreign_origin", `peer ${peerNodeId} served a change from ${c.origin}`);
        if (!Number.isInteger(c.seq) || c.seq <= cursor) continue;
        const r = this.applyOne(c, nodeId);
        if (r === "applied") result.applied++;
        else if (r === "skipped") result.skipped++;
        else result.conflicts++;
        cursor = c.seq;
      }
      this.db
        .prepare(
          `INSERT INTO cluster_cursors (peer_node_id, seq, remote_head, last_ok_at, last_error, last_error_at)
           VALUES (?, ?, ?, ?, NULL, NULL)
           ON CONFLICT(peer_node_id) DO UPDATE SET seq = excluded.seq, remote_head = excluded.remote_head,
             last_ok_at = excluded.last_ok_at, last_error = NULL, last_error_at = NULL`,
        )
        .run(peerNodeId, cursor, remoteHead, nowIso());
    });
    return result;
  }

  /** Last applied seq of a peer's changelog (0 if never pulled). */
  cursorFor(peerNodeId: string): number {
    const r = this.db.prepare("SELECT seq FROM cluster_cursors WHERE peer_node_id = ?").get(peerNodeId) as Row | undefined;
    return r ? Number(r.seq) : 0;
  }

  /** Records a failed pull for status. Never throws. */
  recordPullError(peerNodeId: string, message: string): void {
    try {
      this.db
        .prepare(
          `INSERT INTO cluster_cursors (peer_node_id, seq, last_error, last_error_at) VALUES (?, 0, ?, ?)
           ON CONFLICT(peer_node_id) DO UPDATE SET last_error = excluded.last_error, last_error_at = excluded.last_error_at`,
        )
        .run(peerNodeId, message.slice(0, 500), nowIso());
    } catch {
      // status bookkeeping only
    }
  }

  /** Records the observed clock difference to a peer (peer minus us, ms). */
  recordClockSkew(peerNodeId: string, skewMs: number): void {
    this.db.prepare("UPDATE cluster_cursors SET clock_skew_ms = ? WHERE peer_node_id = ?").run(Math.round(skewMs), peerNodeId);
  }

  /** Canonical pk key, computed by SQLite so it matches what triggers write. */
  private pkKey(values: unknown[]): string {
    const r = this.db.prepare(`SELECT json_array(${values.map(() => "?").join(", ")}) AS k`).get(...(values as any[])) as Row;
    return String(r.k);
  }

  private getMeta(tbl: string, pk: string): RowMeta | null {
    const r = this.db.prepare("SELECT tbl, pk, ts, origin, deleted FROM cluster_row_meta WHERE tbl = ? AND pk = ?").get(tbl, pk) as Row | undefined;
    return r ? { tbl, pk, ts: Number(r.ts), origin: String(r.origin), deleted: Number(r.deleted) } : null;
  }

  private setMeta(tbl: string, pk: string, ts: number, origin: string, deleted: boolean): void {
    this.db
      .prepare(
        `INSERT INTO cluster_row_meta (tbl, pk, ts, origin, deleted) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(tbl, pk) DO UPDATE SET ts = excluded.ts, origin = excluded.origin, deleted = excluded.deleted`,
      )
      .run(tbl, pk, ts, origin, deleted ? 1 : 0);
  }

  /**
   * Writes a delete AUTHORED BY THIS NODE while capture is suppressed: the
   * tombstone for the loser of a unique-constraint collision.
   *
   * Its ts is deliberately the smallest that beats the losing version
   * (loser ts + 1), NOT the wall clock. Nodes may resolve the same collision
   * from different versions of the loser: one sees an old version of row X
   * lose to Y, another sees X's newer edit beat Y. A wall-clock tombstone
   * would then outrank X's newer edit everywhere and both rows would die. A
   * minimal tombstone kills only the version that actually lost, so the
   * newest versions decide, as they should.
   */
  private captureDelete(spec: SharedTableSpec, pkValues: unknown[], pk: string, floorTs: number, nodeId: string): void {
    const prev = this.getMeta(spec.table, pk);
    const ts = Math.max(floorTs + 1, prev ? prev.ts + 1 : 0);
    this.db.prepare(`DELETE FROM ${spec.table} WHERE ${spec.pk.map((c) => `${c} = ?`).join(" AND ")}`).run(...(pkValues as any[]));
    this.setMeta(spec.table, pk, ts, nodeId, true);
    this.db
      .prepare("INSERT INTO cluster_changelog (tbl, pk, op, row, ts, origin) VALUES (?, ?, 'delete', NULL, ?, ?)")
      .run(spec.table, pk, ts, nodeId);
  }

  /** UNIQUE constraints of a table other than its primary key, as column lists. */
  private uniqueIndexes(table: string): string[][] {
    const cached = this.uniqueIndexCache.get(table);
    if (cached) return cached;
    const out: string[][] = [];
    for (const idx of this.db.prepare(`PRAGMA index_list(${table})`).all() as Row[]) {
      if (Number(idx.unique) !== 1 || idx.origin === "pk" || Number(idx.partial) === 1) continue;
      const cols = (this.db.prepare(`PRAGMA index_info(${JSON.stringify(String(idx.name))})`).all() as Row[]).map((c) => String(c.name));
      out.push(cols);
    }
    this.uniqueIndexCache.set(table, out);
    return out;
  }

  private recordConflict(tbl: string, winner: string, loser: string, detail: string): void {
    this.db
      .prepare("INSERT INTO cluster_conflicts (at, tbl, winner_pk, loser_pk, detail) VALUES (?, ?, ?, ?, ?)")
      .run(nowIso(), tbl, winner, loser, detail);
    console.warn(`onegate cluster: ${tbl} unique collision resolved: ${winner} kept, ${loser} removed (${detail})`);
  }

  private applyOne(c: ClusterChange, nodeId: string): "applied" | "skipped" | "conflict" {
    const spec = sharedTableSpec(c.tbl);
    if (!spec) throw new ClusterError(502, "unknown_table", `peer sent a change for unreplicated table ${c.tbl}`);
    let pkValues: unknown[];
    try {
      pkValues = JSON.parse(c.pk);
    } catch {
      throw new ClusterError(502, "bad_change", `unparseable pk for ${c.tbl}`);
    }
    if (!Array.isArray(pkValues) || pkValues.length !== spec.pk.length || pkValues.some((v) => typeof v !== "string" && typeof v !== "number")) {
      throw new ClusterError(502, "bad_change", `malformed pk for ${c.tbl}`);
    }
    // Row filters reference primary-key columns only (settings: key), so a
    // change is checkable even when it is a delete without a row image. This is
    // what stops a peer from overwriting this node's local settings.
    if (spec.filter) {
      const cols = spec.pk.map((col, i) => `? AS ${col}`).join(", ");
      const ok = this.db.prepare(`SELECT 1 AS ok FROM (SELECT ${cols}) AS r WHERE ${spec.filter("r")}`).get(...(pkValues as any[]));
      if (!ok) throw new ClusterError(502, "filtered_row", `peer sent a node-local ${c.tbl} row`);
    }
    const pk = this.pkKey(pkValues);
    const meta = this.getMeta(spec.table, pk);
    if (meta && !isNewer(c, meta)) return "skipped";
    const wherePk = spec.pk.map((col) => `${col} = ?`).join(" AND ");

    if (c.op === "delete") {
      this.db.prepare(`DELETE FROM ${spec.table} WHERE ${wherePk}`).run(...(pkValues as any[]));
      this.setMeta(spec.table, pk, c.ts, c.origin, true);
      return "applied";
    }
    if (c.op !== "upsert" || c.row === null) throw new ClusterError(502, "bad_change", `bad op for ${c.tbl}`);
    let row: Row;
    try {
      row = JSON.parse(c.row);
    } catch {
      throw new ClusterError(502, "bad_change", `unparseable row for ${c.tbl}`);
    }
    // Only columns this build knows AND the peer sent. A column a newer peer
    // added is ignored; one an older peer lacks keeps its local value/default.
    const cols = spec.columns.filter((col) => Object.prototype.hasOwnProperty.call(row, col));
    if (spec.pk.some((col, i) => row[col] !== pkValues[i])) throw new ClusterError(502, "bad_change", `row/pk mismatch for ${c.tbl}`);

    // Unique-constraint collisions with a DIFFERENT row (same name, other id).
    let conflict = false;
    for (const idxCols of this.uniqueIndexes(spec.table)) {
      if (idxCols.some((col) => row[col] === null || row[col] === undefined)) continue;
      const others = this.db
        .prepare(`SELECT ${spec.pk.join(", ")} FROM ${spec.table} WHERE ${idxCols.map((col) => `${col} = ?`).join(" AND ")} AND NOT (${wherePk})`)
        .all(...idxCols.map((col) => row[col]), ...(pkValues as any[])) as Row[];
      for (const other of others) {
        const otherValues = spec.pk.map((col) => other[col]);
        const otherPk = this.pkKey(otherValues);
        const otherMeta = this.getMeta(spec.table, otherPk) ?? { ts: 0, origin: "" };
        const detail = `${idxCols.join(",")}=${idxCols.map((col) => String(row[col])).join(",")}`;
        if (isNewer(c, otherMeta)) {
          this.captureDelete(spec, otherValues, otherPk, otherMeta.ts, nodeId);
          this.recordConflict(spec.table, pk, otherPk, detail);
          conflict = true;
        } else {
          // The incoming version loses: tombstone it (and any older local copy
          // of the same row) with a version that beats it everywhere.
          this.captureDelete(spec, pkValues, pk, c.ts, nodeId);
          this.recordConflict(spec.table, otherPk, pk, detail);
          return "conflict";
        }
      }
    }

    let wasInactive = false;
    if (spec.table === "connections") {
      const before = this.db.prepare("SELECT inactive_at FROM connections WHERE id = ?").get(pkValues[0] as string) as Row | undefined;
      wasInactive = !!before?.inactive_at;
    }
    const updates = cols.filter((col) => !spec.pk.includes(col));
    this.db
      .prepare(
        `INSERT INTO ${spec.table} (${cols.join(", ")}) VALUES (${cols.map(() => "?").join(", ")})
         ON CONFLICT (${spec.pk.join(", ")}) DO ${updates.length ? `UPDATE SET ${updates.map((col) => `${col} = excluded.${col}`).join(", ")}` : "NOTHING"}`,
      )
      .run(...cols.map((col) => row[col]));
    // An admin `activate` elsewhere cleared inactive_at: give this node's own
    // failure counter the same fresh budget a local activate would, otherwise a
    // single 401 here would bench the connection again at once. The counter
    // itself never travels; this only resets it on the inactive->active edge.
    if (wasInactive && row.inactive_at === null) {
      this.db.prepare("UPDATE connections SET auth_failures = 0 WHERE id = ?").run(pkValues[0] as string);
    }
    this.setMeta(spec.table, pk, c.ts, c.origin, false);
    return conflict ? "conflict" : "applied";
  }

  // ---- join ----

  /** True when the node holds shared config a join would overwrite. */
  hasLocalConfig(defaultLeases: ReadonlyArray<readonly [string, number]>): boolean {
    for (const spec of SHARED_TABLES) {
      if (spec.table === "settings" || spec.table === "cluster_peers") continue;
      if (spec.table === "integration_leases") {
        const seeded = new Map(defaultLeases.map(([id, ttl]) => [id, ttl]));
        const rows = this.db.prepare("SELECT integration_id, ttl_seconds FROM integration_leases").all() as Row[];
        if (rows.some((r) => seeded.get(String(r.integration_id)) !== Number(r.ttl_seconds))) return true;
        continue;
      }
      if (this.db.prepare(`SELECT 1 FROM ${spec.table} LIMIT 1`).get()) return true;
    }
    return false;
  }

  /** Mints a single-use join token. Only its hash and a DB-key-sealed derived key are kept. */
  mintJoinToken(ttlSeconds: number = DEFAULT_JOIN_TTL_SECONDS): { token: string; expiresAt: string } {
    this.requireEnabled();
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 30 || ttlSeconds > MAX_JOIN_TTL_SECONDS) {
      throw new ClusterError(400, "invalid_ttl", `ttl must be between 30s and ${MAX_JOIN_TTL_SECONDS}s`);
    }
    this.purgeJoinTokens();
    const token = newJoinToken();
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
    this.db
      .prepare("INSERT INTO cluster_join_tokens (id, sealed_key, created_at, expires_at) VALUES (?, ?, ?, ?)")
      .run(joinTokenId(token), this.secrets.seal(joinMasterKey(token).toString("base64")), nowIso(), expiresAt);
    return { token, expiresAt };
  }

  /** Erases the sealed key of every expired, unused token. */
  private purgeJoinTokens(): void {
    this.db.prepare("UPDATE cluster_join_tokens SET sealed_key = NULL WHERE used_at IS NULL AND expires_at <= ?").run(nowIso());
  }

  /** The token-derived master key for a pending join, or a 401/410 ClusterError. */
  joinMaster(id: string): Buffer {
    this.requireEnabled();
    this.purgeJoinTokens();
    const r = this.db.prepare("SELECT sealed_key, expires_at, used_at FROM cluster_join_tokens WHERE id = ?").get(id) as Row | undefined;
    if (!r) throw new ClusterError(401, "invalid_join_token");
    if (r.used_at) throw new ClusterError(410, "join_token_used");
    if (!r.sealed_key || String(r.expires_at) <= nowIso()) throw new ClusterError(410, "join_token_expired");
    return Buffer.from(this.secrets.open<string>(String(r.sealed_key)), "base64");
  }

  /** Atomically spends a join token. False if it was spent or expired meanwhile. */
  claimJoinToken(id: string): boolean {
    const ts = nowIso();
    return (
      Number(
        this.db
          .prepare("UPDATE cluster_join_tokens SET used_at = ?, sealed_key = NULL WHERE id = ? AND used_at IS NULL AND expires_at > ?")
          .run(ts, id, ts).changes,
      ) === 1
    );
  }

  /**
   * Joiner side: replaces this node's shared config with a peer's snapshot and
   * makes the node a member. The Store must already be open with the cluster's
   * DB key (the caller writes it first), since the secret is sealed with it.
   */
  loadJoin(input: { clusterId: string; clusterSecret: string; snapshot: ClusterSnapshot; nodeId: string; advertiseUrl: string }): void {
    if (!isValidNodeId(input.nodeId)) throw new ClusterError(400, "invalid_node_id");
    const snap = input.snapshot;
    this.applyTx(() => {
      for (const spec of SHARED_TABLES) {
        const where = spec.filter ? ` WHERE ${spec.filter(spec.table)}` : "";
        this.db.exec(`DELETE FROM ${spec.table}${where}`);
        for (const row of snap.tables[spec.table] ?? []) {
          const cols = spec.columns.filter((col) => Object.prototype.hasOwnProperty.call(row, col));
          this.db
            .prepare(`INSERT INTO ${spec.table} (${cols.join(", ")}) VALUES (${cols.map(() => "?").join(", ")})`)
            .run(...cols.map((col) => row[col]));
        }
      }
      for (const t of ["cluster_row_meta", "cluster_cursors", "cluster_acks", "cluster_conflicts", "cluster_changelog", "cluster_join_tokens"]) {
        this.db.exec(`DELETE FROM ${t}`);
      }
      const insMeta = this.db.prepare("INSERT INTO cluster_row_meta (tbl, pk, ts, origin, deleted) VALUES (?, ?, ?, ?, ?)");
      for (const m of snap.meta) insMeta.run(m.tbl, m.pk, m.ts, m.origin, m.deleted);
      const insCursor = this.db.prepare("INSERT INTO cluster_cursors (peer_node_id, seq) VALUES (?, ?)");
      for (const [peer, seq] of Object.entries(snap.cursors)) {
        if (peer !== input.nodeId) insCursor.run(peer, seq);
      }
      // Cached upstream tokens sealed under this node's previous DB key can no
      // longer be opened; drop them so they are simply re-minted.
      for (const r of this.db.prepare("SELECT key, value FROM settings").all() as Row[]) {
        const v = String(r.value);
        if (!this.secrets.isSealed(v)) continue;
        try {
          this.secrets.open(v);
        } catch {
          this.db.prepare("DELETE FROM settings WHERE key = ?").run(r.key);
        }
      }
      const set = this.db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value");
      set.run(KEY_NODE_ID, input.nodeId);
      set.run(KEY_CLUSTER_ID, input.clusterId);
      set.run(KEY_SECRET, this.secrets.seal(input.clusterSecret));
      set.run(KEY_ADVERTISE, input.advertiseUrl);
    });
    this.store.syncClusterCapture();
  }

  // ---- maintenance & status ----

  /**
   * Drops changelog entries every current peer has pulled past AND that are
   * older than `retentionMs`. A peer that has never pulled holds everything, so
   * history is only lost for a node that was removed from the cluster.
   */
  compact(retentionMs: number, nowMs: number = Date.now()): number {
    if (!this.isEnabled()) return 0;
    const self = this.peekNodeId();
    const peers = this.listPeers().filter((p) => p.nodeId !== self);
    let minAck = this.head();
    for (const p of peers) {
      const r = this.db.prepare("SELECT seq FROM cluster_acks WHERE peer_node_id = ?").get(p.nodeId) as Row | undefined;
      minAck = Math.min(minAck, r ? Number(r.seq) : 0);
    }
    return Number(
      this.db.prepare("DELETE FROM cluster_changelog WHERE seq <= ? AND ts < ?").run(minAck, nowMs - retentionMs).changes,
    );
  }

  conflictCount(): number {
    return Number((this.db.prepare("SELECT COUNT(*) AS n FROM cluster_conflicts").get() as Row).n);
  }

  status(): ClusterStatus {
    const nodeId = this.peekNodeId();
    const enabled = this.isEnabled();
    const peers = enabled ? this.listPeers() : [];
    const cursors = new Map<string, Row>();
    for (const r of this.db.prepare("SELECT * FROM cluster_cursors").all() as Row[]) cursors.set(String(r.peer_node_id), r);
    return {
      enabled,
      nodeId,
      clusterId: this.clusterId(),
      advertiseUrl: this.advertiseUrl(),
      member: peers.some((p) => p.nodeId === nodeId),
      head: this.head(),
      changelogRows: Number((this.db.prepare("SELECT COUNT(*) AS n FROM cluster_changelog").get() as Row).n),
      conflicts: this.conflictCount(),
      peers: peers.map((p) => {
        const c = cursors.get(p.nodeId);
        const self = p.nodeId === nodeId;
        const cursor = !self && c ? Number(c.seq) : null;
        const remoteHead = !self && c && c.remote_head !== null ? Number(c.remote_head) : null;
        return {
          ...p,
          self,
          cursor,
          remoteHead,
          lag: cursor !== null && remoteHead !== null ? Math.max(0, remoteHead - cursor) : null,
          lastOkAt: c?.last_ok_at ?? null,
          lastError: c?.last_error ?? null,
          lastErrorAt: c?.last_error_at ?? null,
          clockSkewMs: c && c.clock_skew_ms !== null ? Number(c.clock_skew_ms) : null,
        };
      }),
    };
  }
}
