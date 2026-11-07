/**
 * Cluster transport security: requests are HMAC-signed with a replay window
 * and nonce cache; responses are sealed to the request that asked for them.
 */

import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import {
  NonceCache,
  REPLAY_WINDOW_MS,
  deriveClusterKeys,
  openJson,
  parseDurationSeconds,
  responseAad,
  sealJson,
  signRequest,
  verifyRequest,
} from "../src/cluster/crypto.js";
import { clusterCall, ClusterHttpError } from "../src/cluster/client.js";
import { cleanupDirs, makeCluster, startFirstNode, stopAll, type TestNode } from "./cluster-harness.js";

let nodes: TestNode[] = [];

afterEach(async () => {
  await stopAll(nodes);
  nodes = [];
  cleanupDirs();
});

const keys = deriveClusterKeys("secret", "ogc_test");

function verify(headers: Record<string, string>, over: Partial<{ method: string; path: string; body: string; nowMs: number; nonces: NonceCache }> = {}) {
  return verifyRequest(keys, {
    method: over.method ?? "GET",
    path: over.path ?? "/cluster/v1/changes?since=0",
    headers,
    body: over.body ?? "",
    nonces: over.nonces ?? new NonceCache(),
    nowMs: over.nowMs,
  });
}

describe("request signatures", () => {
  it("accepts a correctly signed request once, and rejects its replay", () => {
    const nonces = new NonceCache();
    const h = signRequest(keys, { method: "GET", path: "/cluster/v1/changes?since=0", nodeId: "ogn_a" });
    expect(verify(h, { nonces }).ok).toBe(true);
    expect(verify(h, { nonces })).toEqual({ ok: false, reason: "replayed_request" });
  });

  it("rejects a tampered path, method, body or node id", () => {
    const h = signRequest(keys, { method: "POST", path: "/cluster/v1/leave", nodeId: "ogn_a", body: "{}" });
    expect(verify(h, { method: "POST", path: "/cluster/v1/leave", body: "{}" }).ok).toBe(true);
    expect(verify(h, { method: "POST", path: "/cluster/v1/leave?x", body: "{}" })).toMatchObject({ reason: "bad_signature" });
    expect(verify(h, { method: "GET", path: "/cluster/v1/leave", body: "{}" })).toMatchObject({ reason: "bad_signature" });
    expect(verify(h, { method: "POST", path: "/cluster/v1/leave", body: "{ }" })).toMatchObject({ reason: "bad_signature" });
    expect(verify({ ...h, "x-onegate-node": "ogn_b" }, { method: "POST", path: "/cluster/v1/leave", body: "{}" })).toMatchObject({ reason: "bad_signature" });
  });

  it("rejects stale or future timestamps, missing headers, and a different secret", () => {
    const old = signRequest(keys, { method: "GET", path: "/p", nodeId: "n", nowMs: Date.now() - REPLAY_WINDOW_MS - 1000 });
    expect(verify(old, { path: "/p" })).toMatchObject({ reason: "stale_request" });
    const future = signRequest(keys, { method: "GET", path: "/p", nodeId: "n", nowMs: Date.now() + REPLAY_WINDOW_MS + 1000 });
    expect(verify(future, { path: "/p" })).toMatchObject({ reason: "stale_request" });
    expect(verify({}, { path: "/p" })).toMatchObject({ reason: "missing_signature" });
    const other = signRequest(deriveClusterKeys("other", "ogc_test"), { method: "GET", path: "/p", nodeId: "n" });
    expect(verify(other, { path: "/p" })).toMatchObject({ reason: "bad_signature" });
  });

  it("forgets nonces once they are outside the window", () => {
    const nonces = new NonceCache();
    expect(nonces.remember("n1", 0)).toBe(true);
    expect(nonces.remember("n1", 1)).toBe(false);
    expect(nonces.remember("n2", 10 * REPLAY_WINDOW_MS)).toBe(true);
    expect(nonces.remember("n1", 10 * REPLAY_WINDOW_MS)).toBe(true);
  });
});

describe("sealed bodies", () => {
  it("open only with the same key and the same request binding", () => {
    const sealed = sealJson(keys.seal, responseAad("nonce-1"), { hello: "world" });
    expect(openJson(keys.seal, responseAad("nonce-1"), sealed)).toEqual({ hello: "world" });
    expect(() => openJson(keys.seal, responseAad("nonce-2"), sealed)).toThrow();
    expect(() => openJson(deriveClusterKeys("x", "y").seal, responseAad("nonce-1"), sealed)).toThrow();
    expect(() => openJson(keys.seal, "a", "AAAA")).toThrow(/too short/);
  });

  it("parses durations", () => {
    expect(parseDurationSeconds("15m")).toBe(900);
    expect(parseDurationSeconds("2h")).toBe(7200);
    expect(parseDurationSeconds("90")).toBe(90);
    expect(parseDurationSeconds("1d")).toBe(86400);
    expect(parseDurationSeconds("soon")).toBeNull();
  });
});

describe("the cluster listener", () => {
  it("rejects unsigned, wrongly signed and replayed requests with 401", async () => {
    const a = await startFirstNode();
    nodes = [a];
    const get = (headers: Record<string, string>, path = "/cluster/v1/changes?since=0") =>
      new Promise<number>((resolve, reject) => {
        http.get(new URL(path, a.url), { headers }, (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        }).on("error", reject);
      });
    expect(await get({})).toBe(401);
    const wrong = signRequest(deriveClusterKeys("guess", a.runtime.state.clusterId()!), { method: "GET", path: "/cluster/v1/changes?since=0", nodeId: "ogn_evil" });
    expect(await get(wrong)).toBe(401);
    const good = signRequest(a.runtime.state.keys(), { method: "GET", path: "/cluster/v1/changes?since=0", nodeId: "ogn_peer0" });
    expect(await get(good)).toBe(200);
    expect(await get(good)).toBe(401); // replay
    const unknown = signRequest(a.runtime.state.keys(), { method: "GET", path: "/cluster/v1/nope", nodeId: "ogn_peer0" });
    expect(await get(unknown, "/cluster/v1/nope")).toBe(404);
  });

  it("a response forged without the cluster secret is refused by the client", async () => {
    const a = await startFirstNode();
    nodes = [a];
    const forger = http.createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ sealed: sealJson(Buffer.alloc(32), "x", { changes: [] }) }));
    });
    await new Promise<void>((r) => forger.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${(forger.address() as { port: number }).port}`;
    try {
      await expect(
        clusterCall({ url, method: "GET", path: "/cluster/v1/hello", keys: a.runtime.state.keys(), nodeId: "ogn_a0000000" }),
      ).rejects.toThrow(/failed authentication/);
    } finally {
      forger.close();
    }
  });

  it("surfaces peer errors and unreachable peers as ClusterHttpError", async () => {
    const a = await startFirstNode();
    nodes = [a];
    const err = await clusterCall({ url: a.url, method: "GET", path: "/cluster/v1/changes?since=999", keys: a.runtime.state.keys(), nodeId: "ogn_b0000000" }).catch((e) => e);
    expect(err).toBeInstanceOf(ClusterHttpError);
    expect((err as ClusterHttpError).status).toBe(409);
    const down = await clusterCall({ url: "http://127.0.0.1:1", method: "GET", path: "/cluster/v1/hello", keys: a.runtime.state.keys(), nodeId: "ogn_b0000000" }).catch((e) => e);
    expect((down as ClusterHttpError).status).toBe(0);
  });

  it("serves a consistent snapshot to a signed peer", async () => {
    nodes = await makeCluster(2);
    const [a, b] = nodes;
    a.store.createProject("snap");
    const snap = await clusterCall<{ head: number; cursors: Record<string, number>; tables: Record<string, unknown[]> }>({
      url: a.url,
      method: "GET",
      path: "/cluster/v1/snapshot",
      keys: b.runtime.state.keys(),
      nodeId: b.nodeId,
    });
    expect(snap.cursors[a.nodeId]).toBe(snap.head);
    expect(snap.tables.projects).toHaveLength(1);
    expect(snap.tables.settings.every((r) => (r as { key: string }).key === "admin_token_hash")).toBe(true);
  });
});
