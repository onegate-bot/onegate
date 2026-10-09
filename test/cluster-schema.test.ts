/**
 * Schema guards for OneGate cluster.
 *
 * The drift guard is the important one: every table must be classified as
 * shared or local, and every column of a shared table must be either
 * replicated or explicitly excluded. Adding a column to (say) `connections`
 * without touching src/store/cluster-schema.ts fails here, instead of the new
 * column silently never replicating.
 */

import { describe, it, expect, afterEach } from "vitest";
import { createRequire } from "node:module";
import { join } from "node:path";
import { Store } from "../src/store/db.js";
import { LOCAL_TABLES, SHARED_TABLES, captureTriggerSql, isValidNodeId } from "../src/store/cluster-schema.js";
import { ClusterState } from "../src/cluster/state.js";
import { cleanupDirs, tempDir } from "./cluster-harness.js";

const requireBuiltin = createRequire(import.meta.url);
const { DatabaseSync } = requireBuiltin("node:sqlite") as typeof import("node:sqlite");
type Db = import("node:sqlite").DatabaseSync;
type Row = Record<string, unknown>;

afterEach(() => cleanupDirs());

/** Every classification problem in a database's schema; empty when clean. */
function schemaProblems(db: Db): string[] {
  const problems: string[] = [];
  const tables = (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all() as Row[]).map((r) =>
    String(r.name),
  );
  const shared = new Map(SHARED_TABLES.map((s) => [s.table, s]));
  for (const t of tables) {
    if (shared.has(t) === LOCAL_TABLES.includes(t)) problems.push(`table ${t} must be exactly one of shared/local`);
  }
  for (const spec of SHARED_TABLES) {
    if (!tables.includes(spec.table)) {
      problems.push(`shared table ${spec.table} does not exist`);
      continue;
    }
    const info = db.prepare(`PRAGMA table_info(${spec.table})`).all() as Row[];
    const actual = new Set(info.map((c) => String(c.name)));
    const declared = new Set([...spec.columns, ...(spec.excluded ?? [])]);
    for (const c of actual) if (!declared.has(c)) problems.push(`${spec.table}.${c} is neither replicated nor excluded`);
    for (const c of declared) if (!actual.has(c)) problems.push(`${spec.table}.${c} is declared but does not exist`);
    for (const c of spec.excluded ?? []) if (spec.columns.includes(c)) problems.push(`${spec.table}.${c} is both replicated and excluded`);
    const pk = info.filter((c) => Number(c.pk) > 0).sort((x, y) => Number(x.pk) - Number(y.pk)).map((c) => String(c.name));
    if (JSON.stringify(pk) !== JSON.stringify(spec.pk)) problems.push(`${spec.table} pk is ${pk.join(",")}, spec says ${spec.pk.join(",")}`);
    for (const c of spec.pk) if (!spec.columns.includes(c)) problems.push(`${spec.table}.${c} is a pk column but not replicated`);
  }
  return problems;
}

describe("schema drift guard", () => {
  it("every table and every shared column is classified", () => {
    const store = new Store(":memory:");
    expect(schemaProblems(store.clusterInternals().db)).toEqual([]);
    store.close();
  });

  it("FAILS when a shared table gains an unclassified column", () => {
    const store = new Store(":memory:");
    const db = store.clusterInternals().db;
    db.exec("ALTER TABLE connections ADD COLUMN surprise TEXT");
    expect(schemaProblems(db)).toEqual(["connections.surprise is neither replicated nor excluded"]);
    store.close();
  });

  it("FAILS when a table is added without being classified", () => {
    const store = new Store(":memory:");
    const db = store.clusterInternals().db;
    db.exec("CREATE TABLE brand_new (id TEXT PRIMARY KEY)");
    expect(schemaProblems(db)).toEqual(["table brand_new must be exactly one of shared/local"]);
    store.close();
  });

  it("every trigger compiles and refuses an unsafe node id", () => {
    expect(isValidNodeId("ogn_0123abcd")).toBe(true);
    expect(isValidNodeId("x'); DROP TABLE agents; --")).toBe(false);
    expect(() => captureTriggerSql(SHARED_TABLES[0], "bad id")).toThrow(/invalid cluster node id/);
  });
});

describe("upgrade and rollback", () => {
  it("opening a pre-cluster database adds the cluster tables and keeps every row", () => {
    const dir = tempDir("schema");
    const path = join(dir, "onegate.db");
    const store = new Store(path);
    const { agent, token } = store.createAgent("bot");
    store.close();
    // Make it look like a database written by a build that predates clustering.
    const old = new DatabaseSync(path);
    for (const t of ["cluster_peers", "cluster_changelog", "cluster_row_meta", "cluster_cursors", "cluster_acks", "cluster_conflicts", "cluster_join_tokens"]) {
      old.exec(`DROP TABLE ${t}`);
    }
    old.close();
    const upgraded = new Store(path);
    expect(upgraded.getAgentByToken(token)?.id).toBe(agent.id);
    expect(schemaProblems(upgraded.clusterInternals().db)).toEqual([]);
    expect(new ClusterState(upgraded).isEnabled()).toBe(false);
    upgraded.close();
  });

  it("a clustered database stays writable by an older build: nothing persistent references cluster objects", () => {
    const dir = tempDir("schema");
    const path = join(dir, "onegate.db");
    const store = new Store(path);
    new ClusterState(store).init("http://127.0.0.1:9");
    store.createAgent("bot");
    // Capture is active on this connection...
    expect((store.clusterInternals().db.prepare("SELECT COUNT(*) AS n FROM sqlite_temp_master WHERE type = 'trigger'").get() as Row).n).toBeGreaterThan(0);
    store.close();
    // ...but the file has no triggers, so a connection without OneGate's
    // cluster code (an older build, the sqlite3 shell) can use every table with
    // the queries it always ran.
    const legacy = new DatabaseSync(path);
    legacy.exec("PRAGMA foreign_keys = ON");
    expect(legacy.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'trigger'").get()).toMatchObject({ n: 0 });
    legacy.prepare("INSERT INTO projects (id, name, created_at) VALUES ('pr_legacy', 'legacy', '2026-01-01')").run();
    legacy.prepare("UPDATE agents SET name = 'renamed-by-old-build'").run();
    legacy.prepare("DELETE FROM projects WHERE id = 'pr_legacy'").run();
    expect(legacy.prepare("SELECT name FROM agents").get()).toMatchObject({ name: "renamed-by-old-build" });
    legacy.close();
    // Reopened by this build, the node is still a member and captures again.
    const again = new Store(path);
    expect(new ClusterState(again).isEnabled()).toBe(true);
    const head = new ClusterState(again).head();
    again.createProject("captured-again");
    expect(new ClusterState(again).head()).toBe(head + 1);
    again.close();
  });

  it("leaving removes capture from the live connection", () => {
    const store = new Store(":memory:");
    const st = new ClusterState(store);
    st.init("http://127.0.0.1:9");
    st.leave();
    const head = st.head();
    store.createProject("after-leave");
    expect(st.head()).toBe(head);
    expect(st.status()).toMatchObject({ enabled: false, peers: [] });
    expect(st.peekNodeId()).toMatch(/^ogn_/); // kept for a later re-join
    store.close();
  });
});
