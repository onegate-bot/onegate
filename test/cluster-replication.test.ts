/**
 * OneGate cluster replication: every node accepts writes and converges.
 *
 * Each test builds a real in-process cluster (test/cluster-harness.ts): data
 * dirs, file-backed stores, and cluster listeners on ephemeral ports. Nodes
 * replicate only when a test calls pollOnce()/syncAll(), so pull order is under
 * the test's control, which is what the convergence tests rely on.
 */

import { describe, it, expect, afterEach } from "vitest";
import { Store, AUTH_FAILURE_DEACTIVATE_AFTER } from "../src/store/db.js";
import { ClusterState } from "../src/cluster/state.js";
import { cleanupDirs, makeCluster, startNode, stopAll, syncAll, type TestNode } from "./cluster-harness.js";

let nodes: TestNode[] = [];

afterEach(async () => {
  await stopAll(nodes);
  nodes = [];
  cleanupDirs();
});

/** Raw row access, for asserting on columns the Store API does not expose. */
function raw(store: Store, sql: string, ...params: Array<string | number>): Record<string, unknown>[] {
  return store.clusterInternals().db.prepare(sql).all(...params) as Record<string, unknown>[];
}

function authFailures(store: Store, id: string): number {
  return Number(raw(store, "SELECT auth_failures FROM connections WHERE id = ?", id)[0].auth_failures);
}

describe("writes replicate both ways", () => {
  it("an agent created on A authenticates on B with the same token, and vice versa", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    const fromA = a.store.createAgent("bot-a");
    const fromB = b.store.createAgent("bot-b");
    await syncAll(nodes);
    expect(b.store.getAgentByToken(fromA.token)?.id).toBe(fromA.agent.id);
    expect(a.store.getAgentByToken(fromB.token)?.id).toBe(fromB.agent.id);
  });

  it("rules, sealed connections and grants made on one node work on the other", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    const { agent } = a.store.createAgent("bot");
    const conn = a.store.createConnection({ kind: "app", vendor: "github", name: "gh", data: { token: "ghp_secret" } });
    a.store.grantConnection(conn.id, "agent", agent.id);
    const rule = a.store.createRule({ scope: "agent", subjectId: agent.id, integrationId: "github", methods: ["GET"], pathGlob: "/**", effect: "allow" });
    await syncAll(nodes);
    // The sealed blob opens on B: the DB key is shared.
    expect(b.store.getConnection(conn.id)?.data).toEqual({ token: "ghp_secret" });
    expect(b.store.isConnectionGrantedToAgent(conn.id, agent.id)).toBe(true);
    expect(b.store.getRule(rule.id)?.methods).toEqual(["GET"]);
  });

  it("a delete propagates", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    const p = a.store.createProject("ops");
    await syncAll(nodes);
    expect(b.store.getProject(p.id)).not.toBeNull();
    b.store.deleteProject(p.id);
    await syncAll(nodes);
    expect(a.store.getProject(p.id)).toBeNull();
  });

  it("the shared admin token setting replicates, so one admin token works on every node", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    a.store.setSetting("admin_token_hash", "h-1");
    await syncAll(nodes);
    expect(b.store.getSetting("admin_token_hash")).toBe("h-1");
  });
});

describe("conflicts converge on every node", () => {
  it("concurrent updates of the same row pick the same winner whatever the pull order", async () => {
    for (const order of [[0, 1, 2], [2, 1, 0], [1, 2, 0]]) {
      nodes = await makeCluster(3);
      const { agent } = nodes[0].store.createAgent("bot");
      await syncAll(nodes);
      nodes[0].store.updateAgent(agent.id, { name: "from-a" });
      nodes[1].store.updateAgent(agent.id, { name: "from-b" });
      nodes[2].store.updateAgent(agent.id, { name: "from-c" });
      await syncAll(order.map((i) => nodes[i]));
      const names = nodes.map((n) => n.store.getAgent(agent.id)?.name);
      expect(new Set(names).size).toBe(1);
      await stopAll(nodes);
      nodes = [];
    }
  });

  it("a tie on ts is broken by origin, deterministically", async () => {
    nodes = await makeCluster(1);
    const [a] = nodes;
    const st = new ClusterState(a.store);
    const p = a.store.createProject("p");
    const pk = JSON.stringify([p.id]);
    const ts = Number(raw(a.store, "SELECT ts FROM cluster_row_meta WHERE tbl = 'projects' AND pk = ?", pk)[0].ts);
    const change = (origin: string, name: string) => ({
      seq: 1,
      tbl: "projects",
      pk,
      op: "upsert" as const,
      row: JSON.stringify({ id: p.id, name, created_at: p.createdAt }),
      ts,
      origin,
    });
    // Same ts, origin sorts above ours: it wins.
    expect(st.applyChanges("ogn_zzzzzzzz", [change("ogn_zzzzzzzz", "hi")], 1).applied).toBe(1);
    expect(a.store.getProject(p.id)?.name).toBe("hi");
    // Same ts, origin sorts below the stored winner: it loses.
    expect(st.applyChanges("ogn_00000000", [change("ogn_00000000", "lo")], 1).skipped).toBe(1);
    expect(a.store.getProject(p.id)?.name).toBe("hi");
  });

  it("two nodes creating the same agent name converge on one survivor everywhere", async () => {
    nodes = await makeCluster(3);
    const [a, b, c] = nodes;
    const onA = a.store.createAgent("bob");
    await new Promise((r) => setTimeout(r, 5));
    const onB = b.store.createAgent("bob"); // newer: wins
    // C hears from A first, then B; A hears from B; B hears from A.
    await c.runtime.pullPeer({ nodeId: a.nodeId, url: a.url, addedAt: "" });
    await c.runtime.pullPeer({ nodeId: b.nodeId, url: b.url, addedAt: "" });
    await syncAll(nodes);
    for (const n of nodes) {
      const bobs = n.store.listAgents().filter((x) => x.name === "bob");
      expect(bobs.map((x) => x.id)).toEqual([onB.agent.id]);
      expect(n.store.getAgentByToken(onA.token)).toBeNull();
    }
    expect(new ClusterState(a.store).conflictCount() + new ClusterState(c.store).conflictCount()).toBeGreaterThan(0);
  });

  it("a collision a node never saw directly still converges through the replicated tombstone", async () => {
    nodes = await makeCluster(3);
    const [a, b, c] = nodes;
    const x = a.store.createProject("shared-name");
    await new Promise((r) => setTimeout(r, 5));
    const y = b.store.createProject("shared-name"); // newer: wins
    // A resolves the collision: it deletes its own x, and that delete is captured.
    await a.runtime.pullPeer({ nodeId: b.nodeId, url: b.url, addedAt: "" });
    expect(a.store.getProject(x.id)).toBeNull();
    // The winner is then deleted on B.
    b.store.deleteProject(y.id);
    // C hears from B first (y created, y deleted), then from A (x created...).
    // Without A's replicated tombstone C would keep x, which no other node has.
    await c.runtime.pullPeer({ nodeId: b.nodeId, url: b.url, addedAt: "" });
    await c.runtime.pullPeer({ nodeId: a.nodeId, url: a.url, addedAt: "" });
    await syncAll(nodes);
    for (const n of nodes) expect(n.store.listProjects().filter((p) => p.name === "shared-name")).toEqual([]);
  });

  it("the newest versions decide a collision, even when nodes resolve it from different versions", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    const x = a.store.createAgent("bob");
    await new Promise((r) => setTimeout(r, 5));
    const y = b.store.createAgent("bob");
    await new Promise((r) => setTimeout(r, 5));
    // x is edited after y was created: x's latest version is the newest.
    a.store.updateAgent(x.agent.id, { defaultPolicy: "allow-all" });
    // B first sees x's OLD version (loses to y), then its new one (beats y).
    // A only ever compares y against x's new version. Both must keep x.
    await syncAll(nodes);
    for (const n of nodes) {
      expect(n.store.listAgents().map((ag) => ag.id)).toEqual([x.agent.id]);
      expect(n.store.getAgentByToken(y.token)).toBeNull();
    }
  });

});

describe("ordering", () => {
  it("a grant that arrives before its connection is kept and becomes effective when the connection lands", async () => {
    nodes = await makeCluster(3);
    const [a, b, c] = nodes;
    const { agent } = a.store.createAgent("bot");
    await syncAll(nodes);
    // Connection made on B; B's grant to the agent is made on C after C sees it.
    const conn = b.store.createConnection({ kind: "app", vendor: "github", name: "gh", data: { token: "t" } });
    await c.runtime.pullPeer({ nodeId: b.nodeId, url: b.url, addedAt: "" });
    c.store.grantConnection(conn.id, "agent", agent.id);
    // A hears from C before B: the grant arrives first (FK parent missing).
    await a.runtime.pullPeer({ nodeId: c.nodeId, url: c.url, addedAt: "" });
    expect(raw(a.store, "SELECT * FROM connection_grants WHERE connection_id = ?", conn.id)).toHaveLength(1);
    expect(a.store.getConnection(conn.id)).toBeNull();
    await a.runtime.pullPeer({ nodeId: b.nodeId, url: b.url, addedAt: "" });
    expect(a.store.isConnectionGrantedToAgent(conn.id, agent.id)).toBe(true);
  });

  it("a cascaded delete on the origin is captured and replayed", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    const { agent } = a.store.createAgent("bot");
    const conn = a.store.createConnection({ kind: "app", vendor: "github", name: "gh", data: { token: "t" } });
    a.store.grantConnection(conn.id, "agent", agent.id);
    await syncAll(nodes);
    a.store.deleteConnection(conn.id);
    await syncAll(nodes);
    expect(raw(b.store, "SELECT * FROM connection_grants WHERE connection_id = ?", conn.id)).toHaveLength(0);
  });
});

describe("connections: the outcome replicates, the per-node counter does not", () => {
  it(`${AUTH_FAILURE_DEACTIVATE_AFTER}x401 on A benches it on B; activate on B restores it on A`, async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    const conn = a.store.createConnection({ kind: "llm", vendor: "anthropic", name: "k", data: { apiKey: "x" } });
    await syncAll(nodes);
    for (let i = 0; i < AUTH_FAILURE_DEACTIVATE_AFTER; i++) a.store.recordConnectionAuthOutcome(conn.id, false, 401);
    expect(a.store.getConnection(conn.id)?.inactiveAt).toBeTruthy();
    await syncAll(nodes);
    expect(b.store.getConnection(conn.id)?.inactiveAt).toBeTruthy();
    // B's counter is its own: it never saw a 401.
    expect(authFailures(b.store, conn.id)).toBe(0);

    b.store.setConnectionActive(conn.id, true);
    await syncAll(nodes);
    expect(a.store.getConnection(conn.id)?.inactiveAt).toBeUndefined();
    // The activation edge gives A a fresh budget too.
    expect(authFailures(a.store, conn.id)).toBe(0);
  });

  it("failure-count churn never reaches the changelog, and an apply never overwrites the counter", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    const conn = a.store.createConnection({ kind: "llm", vendor: "anthropic", name: "k", data: { apiKey: "x" } });
    await syncAll(nodes);
    const before = new ClusterState(a.store).head();
    a.store.recordConnectionAuthOutcome(conn.id, false, 401);
    a.store.recordConnectionAuthOutcome(conn.id, true);
    a.store.recordConnectionAuthOutcome(conn.id, false, 401);
    expect(new ClusterState(a.store).head()).toBe(before);
    b.store.recordConnectionAuthOutcome(conn.id, false, 401);
    a.store.updateConnection(conn.id, { name: "renamed" });
    await syncAll(nodes);
    expect(b.store.getConnection(conn.id)?.name).toBe("renamed");
    expect(authFailures(b.store, conn.id)).toBe(1);
    const image = raw(a.store, "SELECT row FROM cluster_changelog WHERE tbl = 'connections' ORDER BY seq DESC LIMIT 1")[0].row as string;
    expect(JSON.parse(image)).not.toHaveProperty("auth_failures");
  });
});

describe("local state stays local", () => {
  it("audit, usage, router state, notifications, token caches and cluster settings never leave the node", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    const { agent } = a.store.createAgent("bot");
    a.store.audit({ agentId: agent.id, agentName: "bot", integrationId: null, host: "h", method: "GET", path: "/", decision: "allow", ruleId: null, status: 200 });
    a.store.recordLlmUsage({ connectionId: "c", agentId: agent.id, vendor: "v", requests: 1 });
    a.store.setSecretSetting("oauth_access_token:github:c1", { token: "upstream" });
    a.store.setSetting("some_future_setting", "local-by-default");
    await syncAll(nodes);
    expect(b.store.listAudit({ limit: 10 })).toHaveLength(0);
    expect(raw(b.store, "SELECT * FROM llm_usage")).toHaveLength(0);
    expect(b.store.getSetting("oauth_access_token:github:c1")).toBeNull();
    expect(b.store.getSetting("some_future_setting")).toBeNull();
    expect(b.store.getSetting("cluster.node_id")).toBe(b.nodeId);
    const tables = new Set(raw(a.store, "SELECT DISTINCT tbl FROM cluster_changelog").map((r) => r.tbl));
    for (const t of ["audit", "llm_usage", "llm_strategy_state", "owner_notifications"]) expect(tables.has(t)).toBe(false);
  });

  it("a peer cannot push a node-local settings row", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    const st = new ClusterState(b.store);
    expect(() =>
      st.applyChanges(a.nodeId, [{ seq: 999, tbl: "settings", pk: JSON.stringify(["cluster.secret"]), op: "upsert", row: JSON.stringify({ key: "cluster.secret", value: "x" }), ts: Date.now(), origin: a.nodeId }], 999),
    ).toThrow(/node-local/);
    expect(() =>
      st.applyChanges(a.nodeId, [{ seq: 999, tbl: "audit", pk: "[1]", op: "delete", row: null, ts: Date.now(), origin: a.nodeId }], 999),
    ).toThrow(/unreplicated table/);
    expect(() =>
      st.applyChanges(a.nodeId, [{ seq: 999, tbl: "projects", pk: '["p"]', op: "delete", row: null, ts: Date.now(), origin: "someone-else" }], 999),
    ).toThrow(/from someone-else/);
  });
});

describe("non-cluster nodes are unchanged", () => {
  it("a node that never ran cluster init has no capture triggers and no changelog growth", async () => {
    const solo = await startNode();
    nodes = [solo];
    const { agent } = solo.store.createAgent("bot");
    solo.store.createRule({ scope: "agent", subjectId: agent.id, integrationId: "x", methods: ["*"], pathGlob: "/**", effect: "allow" });
    expect(raw(solo.store, "SELECT name FROM sqlite_temp_master WHERE type = 'trigger'")).toHaveLength(0);
    expect(raw(solo.store, "SELECT name FROM sqlite_master WHERE type = 'trigger'")).toHaveLength(0);
    expect(raw(solo.store, "SELECT * FROM cluster_changelog")).toHaveLength(0);
    expect(raw(solo.store, "SELECT * FROM cluster_row_meta")).toHaveLength(0);
    expect(solo.runtime.status().enabled).toBe(false);
    await solo.runtime.pollOnce(); // no-op
  });
});

describe("availability", () => {
  it("a peer that is down is retried, and catches up when it is back", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    await b.stop();
    const p = a.store.createProject("while-b-down");
    await a.runtime.pollOnce();
    const st = a.runtime.status().peers.find((x) => x.nodeId === b.nodeId)!;
    expect(st.lastError).toMatch(/cannot reach/);
    await b.restart();
    // B's own writes while A could not reach it also flow once both are up.
    const q = b.store.createProject("written-on-b");
    await new Promise((r) => setTimeout(r, 10));
    await syncAll(nodes);
    expect(b.store.getProject(p.id)).not.toBeNull();
    expect(a.store.getProject(q.id)).not.toBeNull();
    expect(a.runtime.status().peers.find((x) => x.nodeId === b.nodeId)!.lastError).toBeNull();
    expect(a.runtime.status().peers.find((x) => x.nodeId === b.nodeId)!.lag).toBe(0);
  });

  it("split brain: both sides keep accepting writes and converge on heal", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    const shared = a.store.createProject("shared");
    await syncAll(nodes);
    await b.stop();
    a.store.createProject("only-a");
    await b.restart();
    await a.stop();
    b.store.createProject("only-b");
    b.store.deleteProject(shared.id);
    await a.restart();
    await syncAll(nodes);
    const names = (n: TestNode) => n.store.listProjects().map((p) => p.name).sort();
    expect(names(a)).toEqual(["only-a", "only-b"]);
    expect(names(b)).toEqual(names(a));
  });

  it("a three-node mesh converges, including a node that only ever talks to one peer first", async () => {
    nodes = await makeCluster(3);
    const [a, b, c] = nodes;
    const ids = [a.store.createProject("pa").id, b.store.createProject("pb").id, c.store.createProject("pc").id];
    await syncAll(nodes);
    for (const n of nodes) for (const id of ids) expect(n.store.getProject(id)).not.toBeNull();
    for (const n of nodes) {
      expect(n.runtime.status().peers.map((p) => p.nodeId).sort()).toEqual([a.nodeId, b.nodeId, c.nodeId].sort());
    }
  });

  it("pages through a large backlog", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    for (let i = 0; i < 1200; i++) a.store.setIntegrationLease(`int-${i}`, 60 + i);
    await b.runtime.pollOnce();
    expect(b.store.listIntegrationLeases().length).toBeGreaterThanOrEqual(1200);
    expect(b.runtime.status().peers.find((p) => p.nodeId === a.nodeId)!.lag).toBe(0);
  });
});
