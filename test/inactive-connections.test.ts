/**
 * Inactive connections: a credential that upstream keeps rejecting (401) is
 * taken out of rotation, so it stops costing a failed request on every turn
 * and routing falls back to the connections that still work. An admin puts it
 * back with `onegate connections activate`.
 *
 * A stub https server plays both an LLM vendor and an app vendor. Its response
 * is driven by the injected x-api-key: "key-401" is a revoked credential,
 * "key-429" a rate-limited one, anything else succeeds.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { initCa } from "../src/ca.js";
import { Store, AUTH_FAILURE_DEACTIVATE_AFTER } from "../src/store/db.js";
import { Registry } from "../src/integrations/types.js";
import { GatewayProxy } from "../src/proxy/server.js";
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";

const LLM_HOST = "api.llm-vendor.test";
const APP_HOST = "api.app-vendor.test";
const LLM = "llmvendor";
const APP = "appvendor";

let dir: string;
let store: Store;
let proxy: GatewayProxy;
let proxyPort: number;
let stub: https.Server;
let caPem: string;
let admin: http.Server;
let adminPort: number;
let adminToken: string;
/** x-api-key values the stub saw, in order. */
let seen: string[] = [];

let registry: Registry;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-inactive-"));
  const ca = initCa(dir);
  caPem = ca.rootPem;
  store = new Store(":memory:");

  stub = https.createServer(
    {
      SNICallback: (servername, cb) => {
        const leaf = ca.leafFor(servername);
        cb(null, tls.createSecureContext({ key: leaf.key, cert: leaf.cert }));
      },
    },
    (req, res) => {
      req.resume();
      req.on("end", () => {
        const key = String(req.headers["x-api-key"] ?? "");
        seen.push(key);
        const status = key === "key-401" ? 401 : key === "key-429" ? 429 : 200;
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify({ key, status }));
      });
    },
  );
  await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
  const stubPort = (stub.address() as { port: number }).port;

  registry = new Registry();
  registry.register({
    id: LLM,
    title: "Example LLM Vendor",
    hosts: [LLM_HOST],
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    needsBody: true,
    llm: {
      vendor: LLM,
      inject(ctx) {
        ctx.headers["x-api-key"] = ctx.credential.data.apiKey;
      },
    },
    inject(ctx) {
      ctx.headers["x-api-key"] = `legacy-${ctx.credential.data.apiKey}`;
    },
  });
  registry.register({
    id: APP,
    title: "Example App Vendor",
    hosts: [APP_HOST],
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    inject(ctx) {
      ctx.headers["x-api-key"] = ctx.credential.data.apiKey;
    },
  });

  proxy = new GatewayProxy({
    ca,
    store,
    registry,
    upstreamTls: { ca: caPem },
    upstreamLookup: () => ({ host: "127.0.0.1", port: stubPort }),
  });
  proxyPort = await proxy.listen(0, "127.0.0.1");

  adminToken = ensureAdminToken(store)!;
  admin = http.createServer(createAdminApp({ store, registry, ca, version: "test" }));
  await new Promise<void>((r) => admin.listen(0, "127.0.0.1", r));
  adminPort = (admin.address() as { port: number }).port;
});

afterAll(async () => {
  await proxy.close();
  stub.closeAllConnections();
  stub.close();
  admin.close();
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  seen = [];
});

/** A fresh agent allowed to call both vendors. */
function newAgent(name: string): { id: string; token: string } {
  const { agent, token } = store.createAgent(name, { defaultPolicy: "deny-unmatched" });
  for (const integrationId of [LLM, APP]) {
    store.createRule({
      scope: "agent",
      subjectId: agent.id,
      integrationId,
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
  }
  return { id: agent.id, token };
}

function llmConn(name: string, apiKey: string) {
  return store.createConnection({ kind: "llm", vendor: LLM, name, data: { apiKey } });
}

function viaProxy(
  token: string,
  host: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const connectReq = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "CONNECT",
      path: `${host}:443`,
      headers: { "proxy-authorization": "Basic " + Buffer.from(`agent:${token}`).toString("base64") },
      agent: false,
    });
    connectReq.on("connect", (connectRes, socket) => {
      if (connectRes.statusCode !== 200) {
        socket.destroy();
        reject(new Error(`CONNECT ${connectRes.statusCode}`));
        return;
      }
      const tlsSocket = tls.connect({ socket, servername: host, ca: caPem }, () => {
        const req = https.request(
          {
            createConnection: () => tlsSocket,
            host,
            method: "POST",
            path: "/v1/messages",
            headers: { "content-type": "application/json", ...headers },
          },
          (res) => {
            let body = "";
            res.on("data", (c) => (body += c));
            res.on("end", () => {
              let json: any = null;
              try {
                json = JSON.parse(body);
              } catch {
                json = body;
              }
              resolve({ status: res.statusCode ?? 0, json });
              tlsSocket.end();
            });
          },
        );
        req.on("error", reject);
        req.end("{}");
      });
      tlsSocket.on("error", reject);
    });
    connectReq.on("error", reject);
    connectReq.end();
  });
}

function adminPost(path: string, body: unknown = {}): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request(
      {
        host: "127.0.0.1",
        port: adminPort,
        method: "POST",
        path,
        agent: false,
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload),
          authorization: `Bearer ${adminToken}`,
        },
      },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, json: text ? JSON.parse(text) : null }));
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

describe("store: counting auth failures", () => {
  it("a new connection is active and carries no inactive fields", () => {
    const c = llmConn("fresh", "key-good");
    expect(c.inactiveAt).toBeUndefined();
    expect(store.getConnection(c.id)!.inactiveAt).toBeUndefined();
  });

  it(`deactivates on the ${AUTH_FAILURE_DEACTIVATE_AFTER}th consecutive 401, and reports it exactly once`, () => {
    const c = llmConn("counting", "key-401");
    const results: boolean[] = [];
    for (let i = 0; i < AUTH_FAILURE_DEACTIVATE_AFTER + 2; i++) {
      results.push(store.recordConnectionAuthOutcome(c.id, false, 401));
    }
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(results[AUTH_FAILURE_DEACTIVATE_AFTER - 1]).toBe(true);
    const after = store.getConnection(c.id)!;
    expect(after.inactiveAt).toBeTruthy();
    expect(after.inactiveReason).toContain("401");
  });

  it("a success in between resets the count, so failures must be consecutive", () => {
    const c = llmConn("flaky", "key-401");
    for (let round = 0; round < 3; round++) {
      for (let i = 0; i < AUTH_FAILURE_DEACTIVATE_AFTER - 1; i++) {
        store.recordConnectionAuthOutcome(c.id, false, 401);
      }
      store.recordConnectionAuthOutcome(c.id, true);
    }
    expect(store.getConnection(c.id)!.inactiveAt).toBeUndefined();
  });

  it("an admin can bench a connection by hand and put it back", () => {
    const c = llmConn("manual", "key-good");
    const off = store.setConnectionActive(c.id, false, "rotating the key")!;
    expect(off.inactiveAt).toBeTruthy();
    expect(off.inactiveReason).toBe("deactivated by admin: rotating the key");
    const on = store.setConnectionActive(c.id, true)!;
    expect(on.inactiveAt).toBeUndefined();
    expect(store.setConnectionActive("conn_missing", true)).toBeNull();
  });

  it("reactivating clears the failure count, so the connection gets a full fresh budget", () => {
    const c = llmConn("reset", "key-401");
    for (let i = 0; i < AUTH_FAILURE_DEACTIVATE_AFTER; i++) store.recordConnectionAuthOutcome(c.id, false, 401);
    store.setConnectionActive(c.id, true);
    for (let i = 0; i < AUTH_FAILURE_DEACTIVATE_AFTER - 1; i++) {
      expect(store.recordConnectionAuthOutcome(c.id, false, 401)).toBe(false);
    }
    expect(store.getConnection(c.id)!.inactiveAt).toBeUndefined();
  });
});

describe("LLM routing skips inactive connections and fails over on 401", () => {
  it("round-robin with one revoked key: every request still succeeds, and the key is benched", async () => {
    const agent = newAgent("rr-agent");
    const dead = llmConn("rr-dead", "key-401");
    const good = llmConn("rr-good", "key-good");
    store.setAgentLlmConfig(agent.id, { enabled: true, strategy: "round-robin", connectionIds: [dead.id, good.id] });

    // Round-robin with a 10-call cooldown after an error: drive enough
    // requests for the dead key to be selected the threshold number of times.
    for (let i = 0; i < 40 && !store.getConnection(dead.id)!.inactiveAt; i++) {
      const r = await viaProxy(agent.token, LLM_HOST);
      // The agent never sees the 401: the request fails over to the good key.
      expect(r.status).toBe(200);
      expect(r.json.key).toBe("key-good");
    }
    expect(store.getConnection(dead.id)!.inactiveAt).toBeTruthy();

    // Clear round-robin cooldowns first: otherwise the 10-call cooldown alone
    // could keep the dead key out of the next few requests, and this check
    // would pass without the inactive state doing anything.
    store.setLlmStrategyState(agent.id, LLM, { activeIndex: 0, rrCursor: -1, callsSinceFallback: 0, cooldowns: {} });
    seen = [];
    for (let i = 0; i < 6; i++) expect((await viaProxy(agent.token, LLM_HOST)).status).toBe(200);
    expect(seen).not.toContain("key-401"); // benched: never tried again
    expect(seen.every((k) => k === "key-good")).toBe(true);

    const events = store.listAudit({ agentId: agent.id, limit: 1000 }).filter((a) => a.decision === "connection_deactivated");
    expect(events).toHaveLength(1);
    expect(events[0].connectionName).toBe("rr-dead");
  });

  it("fallback with a revoked primary: the first request fails over instead of returning 401", async () => {
    const agent = newAgent("fb-agent");
    const dead = llmConn("fb-dead", "key-401");
    const good = llmConn("fb-good", "key-good");
    store.setAgentLlmConfig(agent.id, { enabled: true, strategy: "fallback", connectionIds: [dead.id, good.id] });
    const r = await viaProxy(agent.token, LLM_HOST);
    expect(r.status).toBe(200);
    expect(seen).toEqual(["key-401", "key-good"]);
  });

  it("429 is transient: it fails over as before and never benches the key", async () => {
    const agent = newAgent("rl-agent");
    const limited = llmConn("rl-limited", "key-429");
    const good = llmConn("rl-good", "key-good");
    store.setAgentLlmConfig(agent.id, { enabled: true, strategy: "fallback", connectionIds: [limited.id, good.id] });
    for (let i = 0; i < 30; i++) {
      store.setLlmStrategyState(agent.id, LLM, { activeIndex: 0, rrCursor: -1, callsSinceFallback: 0, cooldowns: {} });
      expect((await viaProxy(agent.token, LLM_HOST)).status).toBe(200);
    }
    expect(seen.filter((k) => k === "key-429").length).toBeGreaterThan(AUTH_FAILURE_DEACTIVATE_AFTER);
    expect(store.getConnection(limited.id)!.inactiveAt).toBeUndefined();
  });

  it("every connection inactive: a clear 503, the vendor is not called, and it is audited", async () => {
    const agent = newAgent("dead-agent");
    const a = llmConn("dead-a", "key-good");
    const b = llmConn("dead-b", "key-good");
    store.setConnectionActive(a.id, false);
    store.setConnectionActive(b.id, false);
    store.setAgentLlmConfig(agent.id, { enabled: true, strategy: "round-robin", connectionIds: [a.id, b.id] });
    const r = await viaProxy(agent.token, LLM_HOST);
    expect(r.status).toBe(503);
    expect(r.json.error).toBe("onegate_connection_inactive");
    expect(r.json.inactive_connections.map((c: any) => c.name).sort()).toEqual(["dead-a", "dead-b"]);
    expect(r.json.message).toContain("onegate connections activate");
    expect(seen).toEqual([]); // no silent fall-through to the legacy credential
    expect(store.listAudit({ agentId: agent.id, limit: 5 })[0].decision).toBe("connection_inactive");
  });

  it("an admin reactivation puts the connection straight back into rotation", async () => {
    const agent = newAgent("revive-agent");
    const c = llmConn("revive", "key-good");
    store.setConnectionActive(c.id, false);
    store.setAgentLlmConfig(agent.id, { enabled: true, strategy: "fallback", connectionIds: [c.id] });
    expect((await viaProxy(agent.token, LLM_HOST)).status).toBe(503);
    const res = await adminPost(`/api/connections/${c.id}/activate`);
    expect(res.status).toBe(200);
    expect(res.json.inactiveAt).toBeUndefined();
    expect((await viaProxy(agent.token, LLM_HOST)).status).toBe(200);
  });
});

describe("app connections skip inactive credentials", () => {
  it("after the default is benched by repeated 401s, requests resolve to the next granted connection", async () => {
    const agent = newAgent("app-agent");
    const dead = store.createConnection({ kind: "app", vendor: APP, name: "app-dead", data: { apiKey: "key-401" }, isDefault: true });
    const good = store.createConnection({ kind: "app", vendor: APP, name: "app-good", data: { apiKey: "key-good" } });
    store.grantConnection(dead.id, "agent", agent.id);
    store.grantConnection(good.id, "agent", agent.id);

    // App requests are not retried in-request: the agent sees the 401s that
    // bench the credential, then every later request uses the good one.
    for (let i = 0; i < AUTH_FAILURE_DEACTIVATE_AFTER; i++) {
      expect((await viaProxy(agent.token, APP_HOST)).status).toBe(401);
    }
    expect(store.getConnection(dead.id)!.inactiveAt).toBeTruthy();
    const r = await viaProxy(agent.token, APP_HOST);
    expect(r.status).toBe(200);
    expect(r.json.key).toBe("key-good");
  });

  it("naming an inactive connection explicitly is refused with a clear 503, not substituted", async () => {
    const agent = newAgent("named-agent");
    const off = store.createConnection({ kind: "app", vendor: APP, name: "named-off", data: { apiKey: "key-good" } });
    const on = store.createConnection({ kind: "app", vendor: APP, name: "named-on", data: { apiKey: "key-good" } });
    store.grantConnection(off.id, "agent", agent.id);
    store.grantConnection(on.id, "agent", agent.id);
    store.setConnectionActive(off.id, false);
    const r = await viaProxy(agent.token, APP_HOST, { "x-onegate-connection": "named-off" });
    expect(r.status).toBe(503);
    expect(r.json.inactive_connections).toEqual([{ id: off.id, name: "named-off" }]);
    expect(seen).toEqual([]);
  });

  it("when every granted connection is inactive the error says so, instead of 'not granted'", () => {
    const agent = newAgent("all-off-agent");
    const c = store.createConnection({ kind: "app", vendor: APP, name: "only-one", data: { apiKey: "key-good" } });
    store.grantConnection(c.id, "agent", agent.id);
    store.setConnectionActive(c.id, false);
    expect(store.resolveAppConnection(agent.id, APP)).toEqual({
      error: "connection_inactive",
      connections: [{ id: c.id, name: "only-one" }],
    });
  });
});

describe("admin API", () => {
  it("deactivate records the reason; activate clears it; unknown ids 404", async () => {
    const c = llmConn("api-conn", "key-good");
    const off = await adminPost(`/api/connections/${c.id}/deactivate`, { reason: "key leaked" });
    expect(off.status).toBe(200);
    expect(off.json.inactiveReason).toBe("deactivated by admin: key leaked");
    expect(off.json.data).toBeUndefined(); // the public shape never carries the secret

    const on = await adminPost(`/api/connections/${c.id}/activate`);
    expect(on.status).toBe(200);
    expect(on.json.inactiveAt).toBeUndefined();

    expect((await adminPost("/api/connections/conn_missing/activate")).status).toBe(404);
    expect((await adminPost(`/api/connections/${c.id}/deactivate`, { reason: 42 })).status).toBe(400);
  });
});
