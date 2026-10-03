/**
 * In-process OneGate cluster for tests: each node is a real data dir, a real
 * Store (node:sqlite file), and a real cluster listener on an ephemeral port.
 * Replication is driven by calling pollOnce() rather than by the timer, so a
 * test controls exactly who pulls from whom and in what order.
 */

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import { initCa, caPaths } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { ClusterRuntime } from "../src/cluster/runtime.js";
import { joinCluster } from "../src/cluster/join.js";

export interface TestNode {
  dir: string;
  store: Store;
  runtime: ClusterRuntime;
  url: string;
  nodeId: string;
  /** Stops the listener and closes the store (data dir kept). */
  stop(): Promise<void>;
  /** Re-opens the store and listener on the same port after stop(). */
  restart(): Promise<void>;
}

export async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
  });
}

function caFilesFor(dir: string) {
  return () => {
    const p = caPaths(dir);
    return { cert: readFileSync(p.certPath, "utf8"), key: readFileSync(p.keyPath, "utf8") };
  };
}

const dirs: string[] = [];

export function tempDir(label = "cluster"): string {
  const d = mkdtempSync(join(tmpdir(), `onegate-${label}-`));
  dirs.push(d);
  return d;
}

export function cleanupDirs(): void {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
}

async function open(dir: string, port: number): Promise<{ store: Store; runtime: ClusterRuntime }> {
  const store = new Store(join(dir, "onegate.db"));
  const runtime = new ClusterRuntime({ store, caFiles: caFilesFor(dir), pollIntervalMs: 1 });
  await runtime.listen(port, "127.0.0.1");
  return { store, runtime };
}

function wrap(dir: string, port: number, store: Store, runtime: ClusterRuntime): TestNode {
  const node: TestNode = {
    dir,
    store,
    runtime,
    url: `http://127.0.0.1:${port}`,
    nodeId: runtime.state.peekNodeId() ?? "",
    async stop() {
      await node.runtime.close();
      node.store.close();
    },
    async restart() {
      const o = await open(dir, port);
      node.store = o.store;
      node.runtime = o.runtime;
    },
  };
  return node;
}

/** A standalone, initialized (`onegate init`) node that is not in a cluster. */
export async function startNode(): Promise<TestNode> {
  const dir = tempDir();
  initCa(dir);
  const port = await freePort();
  const { store, runtime } = await open(dir, port);
  return wrap(dir, port, store, runtime);
}

/** Starts node A and runs `cluster init` on it. */
export async function startFirstNode(): Promise<TestNode> {
  const node = await startNode();
  node.runtime.state.init(node.url);
  node.nodeId = node.runtime.state.peekNodeId()!;
  return node;
}

/** Joins a brand-new node (empty data dir) through `via`. */
export async function joinNewNode(via: TestNode): Promise<TestNode> {
  const dir = tempDir();
  const port = await freePort();
  const { token } = via.runtime.state.mintJoinToken();
  await joinCluster({ dataDir: dir, peerUrl: via.url, token, advertiseUrl: `http://127.0.0.1:${port}` });
  const { store, runtime } = await open(dir, port);
  return wrap(dir, port, store, runtime);
}

export async function makeCluster(n: number): Promise<TestNode[]> {
  const first = await startFirstNode();
  const nodes = [first];
  for (let i = 1; i < n; i++) nodes.push(await joinNewNode(first));
  return nodes;
}

/** Every node pulls from every peer, `rounds` times. */
export async function syncAll(nodes: TestNode[], rounds = 3): Promise<void> {
  for (let r = 0; r < rounds; r++) {
    for (const n of nodes) await n.runtime.pollOnce();
    // Let any peer backoff (1ms * 2^failures in tests) expire.
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

export async function stopAll(nodes: TestNode[]): Promise<void> {
  for (const n of nodes) await n.stop().catch(() => {});
}
