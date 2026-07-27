/**
 * End-to-end tests for LLM connection routing through the gateway proxy.
 *
 * A stub https server plays an LLM vendor whose behavior is driven by the
 * injected x-api-key value (200 for healthy keys, 429/500 for failing ones),
 * so strategy selection, in-request failover and the legacy back-compat
 * paths can all be observed from the outside.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { initCa } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { Registry } from "../src/integrations/types.js";
import { GatewayProxy } from "../src/proxy/server.js";
import type { Connection } from "../src/types.js";

const LLM_HOST = "api.llm-vendor.test";
const VENDOR = "llmvendor";

let dir: string;
let store: Store;
let proxy: GatewayProxy;
let proxyPort: number;
let stub: https.Server;
let caPem: string;
/** x-api-key values the stub saw, in order. */
let seenKeys: string[] = [];
let seenBodies: string[] = [];
/** Full request header sets the stub saw, in order. */
let seenHeaders: http.IncomingHttpHeaders[] = [];

let routedToken: string;
let routedAgentId: string;
let legacyToken: string;

let connA: Connection;
let connB: Connection;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-llm-proxy-"));
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
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const key = String(req.headers["x-api-key"] ?? "");
        seenKeys.push(key);
        seenBodies.push(body);
        seenHeaders.push(req.headers);
        if (key === "key-429") {
          res.writeHead(429, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "rate_limited" }));
          return;
        }
        if (key === "key-500") {
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "server_error" }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, key }));
      });
    },
  );
  await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
  const stubPort = (stub.address() as { port: number }).port;

  const registry = new Registry();
  registry.register({
    id: VENDOR,
    title: "Example LLM Vendor",
    hosts: [LLM_HOST],
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    needsBody: true,
    llm: {
      vendor: VENDOR,
      inject(ctx) {
        const apiKey = ctx.credential.data.apiKey;
        if (!apiKey) throw new Error('connection has no "apiKey" field');
        ctx.headers["x-api-key"] = apiKey;
      },
    },
    inject(ctx) {
      // Distinct marker so tests can tell the legacy app path from routing.
      ctx.headers["x-api-key"] = `app-cred-${ctx.credential.data.apiKey}`;
    },
  });

  store.setCredential(VENDOR, "app key", { apiKey: "legacy" });

  const routed = store.createAgent("routed-agent", { defaultPolicy: "deny-unmatched" });
  routedToken = routed.token;
  routedAgentId = routed.agent.id;
  const legacy = store.createAgent("legacy-agent", { defaultPolicy: "deny-unmatched" });
  legacyToken = legacy.token;
  for (const agentId of [routedAgentId, legacy.agent.id]) {
    store.createRule({
      scope: "agent",
      subjectId: agentId,
      integrationId: VENDOR,
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
  }

  connA = store.createConnection({ kind: "llm", vendor: VENDOR, name: "primary", data: { apiKey: "key-good" } });
  connB = store.createConnection({ kind: "llm", vendor: VENDOR, name: "backup", data: { apiKey: "key-b" } });

  proxy = new GatewayProxy({
    ca,
    store,
    registry,
    upstreamTls: { ca: caPem },
    upstreamLookup: () => ({ host: "127.0.0.1", port: stubPort }),
  });
  proxyPort = await proxy.listen(0, "127.0.0.1");
});

afterAll(async () => {
  await proxy.close();
  stub.closeAllConnections();
  stub.close();
  rmSync(dir, { recursive: true, force: true });
});

function viaProxy(opts: {
  token: string;
  method?: string;
  path?: string;
  body?: string;
  headers?: Record<string, string>;
}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const connectReq = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "CONNECT",
      path: `${LLM_HOST}:443`,
      headers: {
        "proxy-authorization": "Basic " + Buffer.from(`agent:${opts.token}`).toString("base64"),
      },
      agent: false,
    });
    connectReq.on("connect", (connectRes, socket) => {
      if (connectRes.statusCode !== 200) {
        socket.destroy();
        reject(new Error(`CONNECT ${connectRes.statusCode}`));
        return;
      }
      const tlsSocket = tls.connect({ socket, servername: LLM_HOST, ca: caPem }, () => {
        const req = https.request(
          {
            createConnection: () => tlsSocket,
            host: LLM_HOST,
            method: opts.method ?? "POST",
            path: opts.path ?? "/v1/messages",
            headers: { "content-type": "application/json", ...(opts.headers ?? {}) },
          },
          (res) => {
            let body = "";
            res.on("data", (c) => (body += c));
            res.on("end", () => {
              resolve({ status: res.statusCode ?? 0, body });
              tlsSocket.end();
            });
          },
        );
        req.on("error", reject);
        if (opts.body) req.write(opts.body);
        req.end();
      });
      tlsSocket.on("error", reject);
    });
    connectReq.on("error", reject);
    connectReq.end();
  });
}

function reset(): void {
  seenKeys = [];
  seenBodies = [];
  seenHeaders = [];
}

describe("legacy back-compat (no LLM config)", () => {
  it("an agent without an LLM config gets the app credential, exactly as today", async () => {
    reset();
    const r = await viaProxy({ token: legacyToken, body: "{}" });
    expect(r.status).toBe(200);
    expect(seenKeys).toEqual(["app-cred-legacy"]);
  });

  it("a DISABLED LLM config also takes the legacy path", async () => {
    reset();
    store.setAgentLlmConfig(routedAgentId, {
      enabled: false,
      strategy: "fallback",
      connectionIds: [connA.id, connB.id],
    });
    const r = await viaProxy({ token: routedToken, body: "{}" });
    expect(r.status).toBe(200);
    expect(seenKeys).toEqual(["app-cred-legacy"]);
    store.deleteAgentLlmConfig(routedAgentId);
  });

  it("an enabled config with no connections of this vendor falls back to the legacy path", async () => {
    reset();
    store.setAgentLlmConfig(routedAgentId, {
      enabled: true,
      strategy: "fallback",
      connectionIds: ["conn_gone"],
    });
    const r = await viaProxy({ token: routedToken, body: "{}" });
    expect(r.status).toBe(200);
    expect(seenKeys).toEqual(["app-cred-legacy"]);
    store.deleteAgentLlmConfig(routedAgentId);
  });

  it("without an app credential the legacy path still returns no_credential", async () => {
    reset();
    store.deleteCredential(VENDOR);
    try {
      const r = await viaProxy({ token: legacyToken, body: "{}" });
      expect(r.status).toBe(502);
      expect(JSON.parse(r.body).error).toBe("onegate_no_credential");
      expect(seenKeys).toEqual([]);
    } finally {
      store.setCredential(VENDOR, "app key", { apiKey: "legacy" });
    }
  });
});

describe("strategy-routed requests", () => {
  it("selects the primary connection and injects its key", async () => {
    reset();
    store.setAgentLlmConfig(routedAgentId, {
      enabled: true,
      strategy: "fallback",
      connectionIds: [connA.id, connB.id],
    });
    const r = await viaProxy({ token: routedToken, body: '{"prompt":"hi"}' });
    expect(r.status).toBe(200);
    expect(seenKeys).toEqual(["key-good"]);
    expect(seenBodies).toEqual(['{"prompt":"hi"}']);
  });

  it("audits the selected connection, vendor and strategy", () => {
    const entry = store.listAudit({ limit: 5 }).find((e) => e.connectionId === connA.id);
    expect(entry?.decision).toBe("allow");
    expect(entry?.connectionName).toBe("primary");
    expect(entry?.llmVendor).toBe(VENDOR);
    expect(entry?.llmStrategy).toBe("fallback");
    expect(entry?.llmFailover).toBe(false);
    expect(entry?.status).toBe(200);
  });

  it("records a usage row for the selection", () => {
    const rows = store.listLlmUsage({ connectionId: connA.id });
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0].errors).toBe(0);
    expect(rows[0].agentId).toBe(routedAgentId);
    expect(rows[0].strategy).toBe("fallback");
  });

  it("fails over in-request on a 429, replaying the buffered body", async () => {
    reset();
    store.updateConnection(connA.id, { data: { apiKey: "key-429" } });
    const r = await viaProxy({ token: routedToken, body: '{"prompt":"retry me"}' });
    expect(r.status).toBe(200);
    expect(JSON.parse(r.body).key).toBe("key-b");
    expect(seenKeys).toEqual(["key-429", "key-b"]);
    // The exact same body went out on both attempts.
    expect(seenBodies).toEqual(['{"prompt":"retry me"}', '{"prompt":"retry me"}']);
  });

  it("marks the failover in audit and usage, and advances the persisted state", () => {
    const entry = store.listAudit({ limit: 5 }).find((e) => e.connectionId === connB.id);
    expect(entry?.llmFailover).toBe(true);
    expect(entry?.status).toBe(200);
    const errored = store.listLlmUsage({ connectionId: connA.id })[0];
    expect(errored.errors).toBe(1);
    expect(errored.status).toBe(429);
    const state = store.getLlmStrategyState(routedAgentId, VENDOR);
    expect(state.activeIndex).toBe(1);
  });

  it("subsequent requests go straight to the fallback connection", async () => {
    reset();
    const r = await viaProxy({ token: routedToken, body: "{}" });
    expect(r.status).toBe(200);
    expect(seenKeys).toEqual(["key-b"]);
  });

  it("retries only once: a second failure is streamed back to the client", async () => {
    reset();
    // Both connections now error. State currently points at B (key-b).
    store.updateConnection(connA.id, { data: { apiKey: "key-429" } });
    store.updateConnection(connB.id, { data: { apiKey: "key-500" } });
    const r = await viaProxy({ token: routedToken, body: "{}" });
    // B errors with 500, the single retry goes to... fallback advances from
    // index 1 which is already last, so there is no retry and the 500 is
    // surfaced as-is.
    expect(r.status).toBe(500);
    expect(seenKeys).toEqual(["key-500"]);
    const entry = store.listAudit({ limit: 5 }).find((e) => e.connectionId === connB.id);
    expect(entry?.status).toBe(500);
  });

  it("an injection failure on the selected connection fails over too", async () => {
    reset();
    // Heal B, break A so it cannot inject at all. Reset state to primary.
    store.updateConnection(connA.id, { data: {} });
    store.updateConnection(connB.id, { data: { apiKey: "key-b" } });
    store.setLlmStrategyState(routedAgentId, VENDOR, {
      activeIndex: 0,
      rrCursor: -1,
      callsSinceFallback: 0,
      cooldowns: {},
    });
    const r = await viaProxy({ token: routedToken, body: "{}" });
    expect(r.status).toBe(200);
    expect(seenKeys).toEqual(["key-b"]);
    const errored = store.listLlmUsage({ connectionId: connA.id })[0];
    expect(errored.errors).toBe(1);
    expect(errored.status).toBeNull();
  });
});

describe("round-robin routing", () => {
  it("alternates connections across requests", async () => {
    reset();
    store.updateConnection(connA.id, { data: { apiKey: "key-good" } });
    const rr = store.createAgent("rr-agent", { defaultPolicy: "deny-unmatched" });
    store.createRule({
      scope: "agent",
      subjectId: rr.agent.id,
      integrationId: VENDOR,
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
    store.setAgentLlmConfig(rr.agent.id, {
      enabled: true,
      strategy: "round-robin",
      connectionIds: [connA.id, connB.id],
    });
    for (let i = 0; i < 4; i++) {
      const r = await viaProxy({ token: rr.token, body: "{}" });
      expect(r.status).toBe(200);
    }
    expect(seenKeys).toEqual(["key-good", "key-b", "key-good", "key-b"]);
    const entry = store.listAudit({ limit: 3 })[0];
    expect(entry.llmStrategy).toBe("round-robin");
  });
});

describe("per-vendor strategy override", () => {
  it("a vendor override wins over the global strategy", async () => {
    reset();
    store.updateConnection(connA.id, { data: { apiKey: "key-good" } });
    const vs = store.createAgent("vendor-override-agent", { defaultPolicy: "deny-unmatched" });
    store.createRule({
      scope: "agent",
      subjectId: vs.agent.id,
      integrationId: VENDOR,
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
    // Global strategy is fallback, but this vendor is pinned to round-robin.
    store.setAgentLlmConfig(vs.agent.id, {
      enabled: true,
      strategy: "fallback",
      vendorStrategies: { [VENDOR]: "round-robin" },
      connectionIds: [connA.id, connB.id],
    });
    for (let i = 0; i < 4; i++) {
      const r = await viaProxy({ token: vs.token, body: "{}" });
      expect(r.status).toBe(200);
    }
    expect(seenKeys).toEqual(["key-good", "key-b", "key-good", "key-b"]);
    expect(store.listAudit({ limit: 3 })[0].llmStrategy).toBe("round-robin");
  });

  it("an override for another vendor leaves this vendor on the global strategy", async () => {
    reset();
    store.updateConnection(connA.id, { data: { apiKey: "key-good" } });
    const other = store.createAgent("other-vendor-override-agent", { defaultPolicy: "deny-unmatched" });
    store.createRule({
      scope: "agent",
      subjectId: other.agent.id,
      integrationId: VENDOR,
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
    // The override names a vendor this request never touches, so the global
    // fallback strategy still applies here.
    store.setAgentLlmConfig(other.agent.id, {
      enabled: true,
      strategy: "fallback",
      vendorStrategies: { someothervendor: "round-robin" },
      connectionIds: [connA.id, connB.id],
    });
    for (let i = 0; i < 3; i++) {
      const r = await viaProxy({ token: other.token, body: "{}" });
      expect(r.status).toBe(200);
    }
    expect(seenKeys).toEqual(["key-good", "key-good", "key-good"]);
    expect(store.listAudit({ limit: 3 })[0].llmStrategy).toBe("fallback");
  });
});

describe("upstream header hygiene on the LLM-routed path", () => {
  it("strips x-onegate-connection so the internal routing control never reaches the vendor", async () => {
    reset();
    store.updateConnection(connA.id, { data: { apiKey: "key-good" } });
    // Earlier failover tests leave persisted strategy counters behind, which
    // would otherwise pin this agent to the backup connection.
    store.clearLlmStrategyState(routedAgentId);
    store.setAgentLlmConfig(routedAgentId, {
      enabled: true,
      strategy: "fallback",
      connectionIds: [connA.id, connB.id],
    });

    const r = await viaProxy({
      token: routedToken,
      body: "{}",
      headers: {
        // OneGate-internal routing control. It selects a stored connection and
        // is meaningless to the vendor, but it carries operator-meaningful
        // connection ids/names, so it must not be forwarded upstream.
        "x-onegate-connection": "conn_secret_tenant_name",
        // A caller header with no special meaning must still pass through, so
        // this proves the fix strips precisely, not broadly.
        "x-passthrough-marker": "keep-me",
      },
    });

    expect(r.status).toBe(200);
    expect(seenHeaders).toHaveLength(1);
    expect(seenHeaders[0]["x-onegate-connection"]).toBeUndefined();
    expect(seenHeaders[0]["x-passthrough-marker"]).toBe("keep-me");
  });

  it("strips the caller's authorization header on the LLM-routed path", async () => {
    reset();
    store.updateConnection(connA.id, { data: { apiKey: "key-good" } });
    store.clearLlmStrategyState(routedAgentId);
    store.setAgentLlmConfig(routedAgentId, {
      enabled: true,
      strategy: "fallback",
      connectionIds: [connA.id, connB.id],
    });

    const r = await viaProxy({
      token: routedToken,
      body: "{}",
      headers: { authorization: "Bearer caller-token-should-not-leak" },
    });

    expect(r.status).toBe(200);
    expect(seenHeaders).toHaveLength(1);
    expect(seenHeaders[0].authorization).toBeUndefined();
    // The injected vendor credential is what actually authenticates upstream.
    expect(seenKeys).toEqual(["key-good"]);
  });

  it("also strips x-onegate-connection when the request fails over to the backup connection", async () => {
    reset();
    // Primary returns 429 so the request must fail over to the backup, giving
    // two upstream attempts whose headers both have to be clean.
    store.updateConnection(connA.id, { data: { apiKey: "key-429" } });
    store.clearLlmStrategyState(routedAgentId);
    store.setAgentLlmConfig(routedAgentId, {
      enabled: true,
      strategy: "fallback",
      connectionIds: [connA.id, connB.id],
    });

    const r = await viaProxy({
      token: routedToken,
      body: "{}",
      headers: { "x-onegate-connection": "conn_secret_tenant_name" },
    });

    expect(r.status).toBe(200);
    // Both the failed attempt and the retry must be clean.
    expect(seenHeaders).toHaveLength(2);
    for (const h of seenHeaders) expect(h["x-onegate-connection"]).toBeUndefined();

    store.updateConnection(connA.id, { data: { apiKey: "key-good" } });
  });
});
