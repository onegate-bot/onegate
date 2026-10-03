/**
 * Joining a OneGate cluster: the join token, the protected join exchange, and
 * what a joined node ends up holding (same DB key, same CA, same config).
 */

import { describe, it, expect, afterEach } from "vitest";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import http from "node:http";
import { caPaths } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { joinCluster } from "../src/cluster/join.js";
import { requestJoin } from "../src/cluster/client.js";
import { ClusterState } from "../src/cluster/state.js";
import { joinTokenId, openJson } from "../src/cluster/crypto.js";
import { cleanupDirs, freePort, joinNewNode, startFirstNode, startNode, stopAll, syncAll, tempDir, type TestNode } from "./cluster-harness.js";

let nodes: TestNode[] = [];

afterEach(async () => {
  await stopAll(nodes);
  nodes = [];
  cleanupDirs();
  delete process.env.ONEGATE_DB_KEY;
});

describe("a joined node", () => {
  it("shares the DB key and the root CA, and starts from a full snapshot", async () => {
    const a = await startFirstNode();
    nodes = [a];
    const { agent, token } = a.store.createAgent("existing-before-join");
    const conn = a.store.createConnection({ kind: "llm", vendor: "anthropic", name: "k", data: { apiKey: "sk-1" } });
    const b = await joinNewNode(a);
    nodes.push(b);
    expect(readFileSync(caPaths(b.dir).certPath, "utf8")).toBe(readFileSync(caPaths(a.dir).certPath, "utf8"));
    expect(readFileSync(join(b.dir, "db-secret.key"), "utf8").trim()).toBe(readFileSync(join(a.dir, "db-secret.key"), "utf8").trim());
    expect(statSync(join(b.dir, "db-secret.key")).mode & 0o777).toBe(0o600);
    expect(statSync(caPaths(b.dir).keyPath).mode & 0o777).toBe(0o600);
    expect(b.store.getAgentByToken(token)?.id).toBe(agent.id);
    expect(b.store.getConnection(conn.id)?.data).toEqual({ apiKey: "sk-1" });
    // Both nodes list both members; A's change log carries the new member.
    await syncAll(nodes);
    for (const n of nodes) expect(n.runtime.status().peers).toHaveLength(2);
  });

  it("a third node joining through the second still pulls everything from the first", async () => {
    const a = await startFirstNode();
    nodes = [a];
    const b = await joinNewNode(a);
    nodes.push(b);
    await syncAll(nodes);
    const p = a.store.createProject("made-on-a-after-b-joined");
    await syncAll(nodes);
    const c = await joinNewNode(b);
    nodes.push(c);
    expect(c.store.getProject(p.id)).not.toBeNull();
    const q = a.store.createProject("made-on-a-after-c-joined");
    await syncAll(nodes);
    expect(c.store.getProject(q.id)).not.toBeNull();
    expect(a.runtime.status().peers.map((x) => x.nodeId)).toContain(c.nodeId);
  });

  it("replaces a CA from a previous `onegate init` and drops its leaf cache", async () => {
    const a = await startFirstNode();
    nodes = [a];
    const fresh = await startNode(); // has its own CA, but no config
    await fresh.stop();
    const leafDir = caPaths(fresh.dir).certsDir;
    mkdirSync(leafDir, { recursive: true });
    writeFileSync(join(leafDir, "old.pem"), "leaf signed by the old CA");
    const { token } = a.runtime.state.mintJoinToken();
    const r = await joinCluster({ dataDir: fresh.dir, peerUrl: a.url, token, advertiseUrl: "http://127.0.0.1:1" });
    expect(r.replacedCa).toBe(true);
    expect(existsSync(join(leafDir, "old.pem"))).toBe(false);
    expect(readFileSync(caPaths(fresh.dir).certPath, "utf8")).toBe(readFileSync(caPaths(a.dir).certPath, "utf8"));
  });
});

describe("join refuses unsafe situations", () => {
  it("refuses a node that already has config, unless --replace-local-config", async () => {
    const a = await startFirstNode();
    nodes = [a];
    a.store.createAgent("cluster-agent");
    const dir = tempDir();
    const local = new Store(join(dir, "onegate.db"));
    local.createAgent("local-only");
    local.close();
    const mint = () => a.runtime.state.mintJoinToken().token;
    await expect(joinCluster({ dataDir: dir, peerUrl: a.url, token: mint(), advertiseUrl: "http://127.0.0.1:1" })).rejects.toThrow(
      /replace-local-config/,
    );
    const r = await joinCluster({ dataDir: dir, peerUrl: a.url, token: mint(), advertiseUrl: "http://127.0.0.1:1", replaceLocalConfig: true });
    expect(r.replacedConfig).toBe(true);
    const joined = new Store(join(dir, "onegate.db"));
    expect(joined.listAgents().map((x) => x.name)).toEqual(["cluster-agent"]);
    joined.close();
  });

  it("refuses a node that is already in a cluster", async () => {
    const a = await startFirstNode();
    nodes = [a];
    const b = await joinNewNode(a);
    nodes.push(b);
    await b.stop();
    await expect(
      joinCluster({ dataDir: b.dir, peerUrl: a.url, token: a.runtime.state.mintJoinToken().token, advertiseUrl: "http://127.0.0.1:1" }),
    ).rejects.toThrow(/already in cluster/);
    await b.restart();
  });

  it("refuses while ONEGATE_DB_KEY is set, and rejects malformed tokens and URLs", async () => {
    const dir = tempDir();
    process.env.ONEGATE_DB_KEY = "a".repeat(64);
    await expect(joinCluster({ dataDir: dir, peerUrl: "http://x", token: "ogj_x", advertiseUrl: "http://y" })).rejects.toThrow(/ONEGATE_DB_KEY/);
    delete process.env.ONEGATE_DB_KEY;
    await expect(joinCluster({ dataDir: dir, peerUrl: "http://x", token: "nope", advertiseUrl: "http://y" })).rejects.toThrow(/not a join token/);
    const token = "ogj_" + "A".repeat(43);
    await expect(joinCluster({ dataDir: dir, peerUrl: "ftp://x", token, advertiseUrl: "http://y" })).rejects.toThrow(/http/);
  });
});

describe("join tokens", () => {
  it("are single use", async () => {
    const a = await startFirstNode();
    nodes = [a];
    const { token } = a.runtime.state.mintJoinToken();
    await requestJoin({ url: a.url, token, nodeId: "ogn_first000", advertiseUrl: "http://127.0.0.1:1" });
    await expect(requestJoin({ url: a.url, token, nodeId: "ogn_second00", advertiseUrl: "http://127.0.0.1:2" })).rejects.toThrow(
      /join_token_used/,
    );
  });

  it("expire, and the stored derived key is erased on expiry and on use", async () => {
    const a = await startFirstNode();
    nodes = [a];
    const st = a.runtime.state;
    const { token } = st.mintJoinToken(30);
    const db = a.store.clusterInternals().db;
    db.prepare("UPDATE cluster_join_tokens SET expires_at = ? WHERE id = ?").run(new Date(Date.now() - 1000).toISOString(), joinTokenId(token));
    await expect(requestJoin({ url: a.url, token, nodeId: "ogn_late0000", advertiseUrl: "http://127.0.0.1:1" })).rejects.toThrow(
      /join_token_expired/,
    );
    const row = db.prepare("SELECT sealed_key FROM cluster_join_tokens WHERE id = ?").get(joinTokenId(token)) as { sealed_key: string | null };
    expect(row.sealed_key).toBeNull();

    const used = st.mintJoinToken();
    await requestJoin({ url: a.url, token: used.token, nodeId: "ogn_ontime00", advertiseUrl: "http://127.0.0.1:1" });
    const usedRow = db.prepare("SELECT sealed_key, used_at FROM cluster_join_tokens WHERE id = ?").get(joinTokenId(used.token)) as {
      sealed_key: string | null;
      used_at: string | null;
    };
    expect(usedRow.sealed_key).toBeNull();
    expect(usedRow.used_at).toBeTruthy();
    // Never the plaintext token.
    const all = JSON.stringify(db.prepare("SELECT * FROM cluster_join_tokens").all());
    expect(all).not.toContain(used.token);
  });

  it("an unknown token is rejected, and a wrong token for a known id does not burn it", async () => {
    const a = await startFirstNode();
    nodes = [a];
    await expect(requestJoin({ url: a.url, token: "ogj_" + "B".repeat(43), nodeId: "ogn_x0000000", advertiseUrl: "http://h" })).rejects.toThrow(
      /invalid_join_token/,
    );
    const { token } = a.runtime.state.mintJoinToken();
    // Right id, body sealed under a different key: rejected, token survives.
    const res = await rawPost(a.url, "/cluster/v1/join", { "x-onegate-join-id": joinTokenId(token) }, JSON.stringify({ nonce: "n", sealed: Buffer.alloc(40).toString("base64") }));
    expect(res.status).toBe(401);
    await requestJoin({ url: a.url, token, nodeId: "ogn_real0000", advertiseUrl: "http://127.0.0.1:1" });
  });

  it("validates ttl bounds", async () => {
    const a = await startFirstNode();
    nodes = [a];
    expect(() => a.runtime.state.mintJoinToken(5)).toThrow(/ttl/);
    expect(() => a.runtime.state.mintJoinToken(10 * 86400)).toThrow(/ttl/);
  });
});

function rawPost(url: string, path: string, headers: Record<string, string>, body: string): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(new URL(path, url), { method: "POST", headers: { "content-type": "application/json", ...headers } }, (res) => {
      let text = "";
      res.on("data", (c) => (text += c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

describe("the join payload on the wire", () => {
  it("is unreadable without the token: no key, secret or CA material in clear", async () => {
    const a = await startFirstNode();
    nodes = [a];
    a.store.createConnection({ kind: "llm", vendor: "anthropic", name: "k", data: { apiKey: "sk-visible?" } });
    const { token } = a.runtime.state.mintJoinToken();
    // A passive observer: capture the raw response bytes through a relay.
    let captured = "";
    const relayPort = await freePort();
    const relay = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        // Only the join route is relayed, by a constant path: forwarding the
        // incoming req.url verbatim is what CodeQL flags as request forgery.
        if (req.url !== "/cluster/v1/join") {
          res.writeHead(404).end();
          return;
        }
        const up = http.request(new URL("/cluster/v1/join", a.url), { method: req.method, headers: req.headers }, (upRes) => {
          const out: Buffer[] = [];
          upRes.on("data", (c) => out.push(c));
          upRes.on("end", () => {
            captured = Buffer.concat(out).toString("utf8");
            res.writeHead(upRes.statusCode ?? 500, upRes.headers);
            res.end(Buffer.concat(out));
          });
        });
        up.end(Buffer.concat(chunks));
      });
    });
    await new Promise<void>((r) => relay.listen(relayPort, "127.0.0.1", r));
    try {
      const payload = await requestJoin({ url: `http://127.0.0.1:${relayPort}`, token, nodeId: "ogn_watched0", advertiseUrl: "http://127.0.0.1:1" });
      const dbKey = readFileSync(join(a.dir, "db-secret.key"), "utf8").trim();
      expect(payload.dbKey).toBe(dbKey);
      expect(captured).not.toContain(dbKey);
      expect(captured).not.toContain("PRIVATE KEY");
      expect(captured).not.toContain(payload.clusterSecret);
      expect(captured).not.toContain("anthropic");
      // And a guessed key does not open it.
      const sealed = JSON.parse(captured).sealed as string;
      expect(() => openJson(Buffer.alloc(32), "x", sealed)).toThrow();
    } finally {
      relay.close();
    }
  });

  it("a node that is not in a cluster refuses joins", async () => {
    const solo = await startNode();
    nodes = [solo];
    await expect(requestJoin({ url: solo.url, token: "ogj_" + "C".repeat(43), nodeId: "ogn_x0000000", advertiseUrl: "http://h" })).rejects.toThrow(
      /cluster_not_initialized/,
    );
    expect(() => new ClusterState(solo.store).mintJoinToken()).toThrow(/not in a cluster/);
  });
});
