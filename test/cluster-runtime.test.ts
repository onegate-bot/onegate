/**
 * The cluster runtime on a live gateway: the replication timer, backoff,
 * membership changes made by another process, and changelog compaction.
 */

import { describe, it, expect, afterEach } from "vitest";
import { ClusterRuntime, DEFAULT_RETENTION_MS, parseClusterListen, retentionMsFromEnv } from "../src/cluster/runtime.js";
import { ClusterState } from "../src/cluster/state.js";
import { clusterCall } from "../src/cluster/client.js";
import { Store } from "../src/store/db.js";
import { cleanupDirs, makeCluster, startFirstNode, stopAll, syncAll, type TestNode } from "./cluster-harness.js";

let nodes: TestNode[] = [];

afterEach(async () => {
  await stopAll(nodes);
  nodes = [];
  cleanupDirs();
});

async function waitFor(cond: () => boolean, ms = 3000): Promise<void> {
  const until = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > until) throw new Error("timed out waiting for condition");
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("replication loop", () => {
  it("once started, a write on one node shows up on the other without anyone polling by hand", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    a.runtime.refresh();
    b.runtime.refresh();
    const p = a.store.createProject("live");
    await waitFor(() => b.store.getProject(p.id) !== null);
    const q = b.store.createProject("live-back");
    await waitFor(() => a.store.getProject(q.id) !== null);
  });

  it("stops when the node leaves from another process, and does nothing for a standalone node", async () => {
    nodes = await makeCluster(2);
    const [a] = nodes;
    a.runtime.refresh();
    expect((a.runtime as unknown as { running: boolean }).running).toBe(true);
    // `cluster leave` run by another process against the same DB.
    const other = new Store(`${a.dir}/onegate.db`);
    new ClusterState(other).leave();
    other.close();
    await waitFor(() => !(a.runtime as unknown as { running: boolean }).running);
    a.runtime.refresh(); // standalone: stays stopped
    expect((a.runtime as unknown as { running: boolean }).running).toBe(false);
  });

  it("a peer listed under the wrong URL is reported, not trusted", async () => {
    nodes = await makeCluster(3);
    const [a, b, c] = nodes;
    // Point A's entry for B at C's listener.
    a.store.clusterInternals().db.prepare("UPDATE cluster_peers SET url = ? WHERE node_id = ?").run(c.url, b.nodeId);
    await a.runtime.pollOnce();
    expect(a.runtime.status().peers.find((p) => p.nodeId === b.nodeId)!.lastError).toMatch(/expected/);
  });
});

describe("changelog compaction", () => {
  it("keeps history until every peer pulled past it, then drops it; a cursor behind the horizon gets 410", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    for (let i = 0; i < 5; i++) a.store.createProject(`p${i}`);
    const st = new ClusterState(a.store);
    // B has not pulled yet: nothing may go, even with zero retention.
    expect(st.compact(0, Date.now() + 1)).toBe(0);
    await syncAll(nodes);
    // B's next pull acknowledges the head.
    await b.runtime.pollOnce();
    expect(st.compact(DEFAULT_RETENTION_MS)).toBe(0); // too recent
    expect(st.compact(0, Date.now() + 1)).toBeGreaterThan(0);
    a.store.createProject("after-compaction");
    await b.runtime.pollOnce();
    expect(b.store.listProjects().map((p) => p.name)).toContain("after-compaction");
    // A peer that comes back with an ancient cursor must re-join.
    const err = await clusterCall({ url: a.url, method: "GET", path: "/cluster/v1/changes?since=0", keys: b.runtime.state.keys(), nodeId: b.nodeId }).catch((e) => e);
    expect(String(err)).toMatch(/cursor_compacted/);
  });

  it("a single-node cluster compacts everything past retention", async () => {
    const a = await startFirstNode();
    nodes = [a];
    a.store.createProject("x");
    expect(new ClusterState(a.store).compact(0, Date.now() + 1)).toBeGreaterThan(0);
    expect(new ClusterState(a.store).head()).toBeGreaterThan(0);
  });

  it("compaction is a no-op for a standalone node", () => {
    const store = new Store(":memory:");
    expect(new ClusterState(store).compact(0)).toBe(0);
    store.close();
  });
});

describe("leave", () => {
  it("lists peers it could not tell", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    await b.stop();
    const r = await a.runtime.leave();
    expect(r).toEqual({ announced: [], unreachable: [b.nodeId] });
    await b.restart();
  });
});

describe("configuration parsing", () => {
  it("ONEGATE_CLUSTER_LISTEN", () => {
    expect(parseClusterListen(undefined, "0.0.0.0")).toBeNull();
    expect(parseClusterListen("  ", "0.0.0.0")).toBeNull();
    expect(parseClusterListen("9443", "0.0.0.0")).toEqual({ host: "0.0.0.0", port: 9443 });
    expect(parseClusterListen("100.64.0.1:9443", "0.0.0.0")).toEqual({ host: "100.64.0.1", port: 9443 });
    expect(parseClusterListen("[fd7a::1]:9443", "0.0.0.0")).toEqual({ host: "fd7a::1", port: 9443 });
    expect(() => parseClusterListen("host:99999", "0.0.0.0")).toThrow(/ONEGATE_CLUSTER_LISTEN/);
    expect(() => parseClusterListen("nope", "0.0.0.0")).toThrow(/ONEGATE_CLUSTER_LISTEN/);
  });

  it("ONEGATE_CLUSTER_RETENTION_DAYS", () => {
    expect(retentionMsFromEnv(undefined)).toBe(DEFAULT_RETENTION_MS);
    expect(retentionMsFromEnv("2")).toBe(2 * 86_400_000);
    expect(retentionMsFromEnv("-1")).toBe(DEFAULT_RETENTION_MS);
  });

  it("a runtime with no listener reports listening: null and closes cleanly", async () => {
    const store = new Store(":memory:");
    const rt = new ClusterRuntime({ store });
    expect(rt.listening()).toBeNull();
    expect(rt.status().listening).toBeNull();
    await rt.close();
    store.close();
  });
});
