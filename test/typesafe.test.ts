/**
 * End-to-end tests for TypeSafe (Jev) as a routed LLM vendor, using the real
 * built-in integration. A stub https server answers for api.typesafe.ai and
 * its response is driven by the injected Bearer key: "ts-529" is overloaded,
 * "ts-401" is a revoked key, "ts-429" is rate limited, anything else returns
 * a Jev evaluation (typed answers plus usage.input_tokens/output_tokens).
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { initCa } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { Registry } from "../src/integrations/types.js";
import { typesafe } from "../src/integrations/typesafe.js";
import { GatewayProxy } from "../src/proxy/server.js";
import type { Connection } from "../src/types.js";

const HOST = "api.typesafe.ai";
const VENDOR = "typesafe";

const JEV_REQUEST = JSON.stringify({
  state: "Help! My payouts have been failing for 3 days.",
  model: "jev-latest",
  questions: { is_urgent: { type: "noul", instructions: "Does this convey urgency?" } },
});

let dir: string;
let store: Store;
let proxy: GatewayProxy;
let proxyPort: number;
let stub: https.Server;
let caPem: string;
/** Authorization headers the stub saw, in order. */
let seen: string[] = [];
let seenBodies: string[] = [];

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-typesafe-"));
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
        const auth = String(req.headers.authorization ?? "");
        seen.push(auth);
        seenBodies.push(body);
        const fail = (status: number, type: string) => {
          res.writeHead(status, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: { type } }));
        };
        if (auth === "Bearer ts-529") return fail(529, "overloaded");
        if (auth === "Bearer ts-401") return fail(401, "unauthorized");
        if (auth === "Bearer ts-429") return fail(429, "rate_limited");
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            model: "jev-1.13.0",
            answers: { is_urgent: { type: "noul", noul: 0.95 } },
            usage: { input_tokens: 296, output_tokens: 20 },
            auth,
          }),
        );
      });
    },
  );
  await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
  const stubPort = (stub.address() as { port: number }).port;

  const registry = new Registry();
  registry.register(typesafe);

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

beforeEach(() => {
  seen = [];
  seenBodies = [];
});

/** An agent allowed to POST evaluations and list models. */
function newAgent(name: string): { id: string; token: string } {
  const { agent, token } = store.createAgent(name, { defaultPolicy: "deny-unmatched" });
  for (const pathGlob of ["/v1/systemone", "/v1/models"]) {
    store.createRule({
      scope: "agent",
      subjectId: agent.id,
      integrationId: VENDOR,
      methods: pathGlob === "/v1/models" ? ["GET"] : ["POST"],
      pathGlob,
      effect: "allow",
    });
  }
  return { id: agent.id, token };
}

function conn(name: string, apiKey: string): Connection {
  return store.createConnection({ kind: "llm", vendor: VENDOR, name, data: { apiKey } });
}

function viaProxy(
  token: string,
  opts: { method?: string; path?: string; body?: string } = {},
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const connectReq = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "CONNECT",
      path: `${HOST}:443`,
      headers: {
        "proxy-authorization": "Basic " + Buffer.from(`agent:${token}`).toString("base64"),
      },
      agent: false,
    });
    connectReq.on("connect", (connectRes, socket) => {
      if (connectRes.statusCode !== 200) {
        socket.destroy();
        reject(new Error(`CONNECT ${connectRes.statusCode}`));
        return;
      }
      const tlsSocket = tls.connect({ socket, servername: HOST, ca: caPem }, () => {
        const body = opts.method === "GET" ? undefined : (opts.body ?? JEV_REQUEST);
        const req = https.request(
          {
            createConnection: () => tlsSocket,
            host: HOST,
            method: opts.method ?? "POST",
            path: opts.path ?? "/v1/systemone",
            // The agent only ever holds a placeholder key, as with the TypeSafe SDK
            // pointed at the gateway (TYPESAFE_API_KEY=placeholder).
            headers: { "content-type": "application/json", authorization: "Bearer placeholder" },
          },
          (res) => {
            let text = "";
            res.on("data", (c) => (text += c));
            res.on("end", () => {
              resolve({ status: res.statusCode ?? 0, body: text });
              tlsSocket.end();
            });
          },
        );
        req.on("error", reject);
        if (body) req.write(body);
        req.end();
      });
      tlsSocket.on("error", reject);
    });
    connectReq.on("error", reject);
    connectReq.end();
  });
}

describe("typesafe app credential path", () => {
  it("replaces the agent's placeholder with the real Bearer key", async () => {
    store.setCredential(VENDOR, "app key", { apiKey: "ts-app-key" });
    try {
      const agent = newAgent("ts-legacy");
      const r = await viaProxy(agent.token);
      expect(r.status).toBe(200);
      expect(seen).toEqual(["Bearer ts-app-key"]);
      expect(JSON.parse(r.body).answers.is_urgent.noul).toBe(0.95);
    } finally {
      store.deleteCredential(VENDOR);
    }
  });
});

describe("typesafe strategy-routed requests", () => {
  it("injects the selected connection's key and records Jev token usage", async () => {
    const agent = newAgent("ts-routed");
    const primary = conn("jev-primary", "ts-key-a");
    const backup = conn("jev-backup", "ts-key-b");
    store.setAgentLlmConfig(agent.id, {
      enabled: true,
      strategy: "fallback",
      connectionIds: [primary.id, backup.id],
    });

    const r = await viaProxy(agent.token);
    expect(r.status).toBe(200);
    expect(seen).toEqual(["Bearer ts-key-a"]);
    expect(seenBodies).toEqual([JEV_REQUEST]);

    const row = store.listLlmUsage({ connectionId: primary.id })[0];
    expect(row.vendor).toBe(VENDOR);
    expect(row.errors).toBe(0);
    expect(row.inputTokens).toBe(296);
    expect(row.outputTokens).toBe(20);

    const entry = store.listAudit({ agentId: agent.id, limit: 1 })[0];
    expect(entry.llmVendor).toBe(VENDOR);
    expect(entry.connectionName).toBe("jev-primary");
  });

  it("GET /v1/models is routed too", async () => {
    const agent = newAgent("ts-models");
    const c = conn("jev-models", "ts-key-m");
    store.setAgentLlmConfig(agent.id, { enabled: true, strategy: "fallback", connectionIds: [c.id] });
    const r = await viaProxy(agent.token, { method: "GET", path: "/v1/models" });
    expect(r.status).toBe(200);
    expect(seen).toEqual(["Bearer ts-key-m"]);
  });

  it("fails over in-request on a 529 (overloaded), replaying the buffered body", async () => {
    const agent = newAgent("ts-529");
    const overloaded = conn("jev-overloaded", "ts-529");
    const healthy = conn("jev-healthy", "ts-key-h");
    store.setAgentLlmConfig(agent.id, {
      enabled: true,
      strategy: "fallback",
      connectionIds: [overloaded.id, healthy.id],
    });

    const r = await viaProxy(agent.token);
    expect(r.status).toBe(200);
    expect(JSON.parse(r.body).auth).toBe("Bearer ts-key-h");
    expect(seen).toEqual(["Bearer ts-529", "Bearer ts-key-h"]);
    expect(seenBodies).toEqual([JEV_REQUEST, JEV_REQUEST]);

    const errored = store.listLlmUsage({ connectionId: overloaded.id })[0];
    expect(errored.errors).toBe(1);
    expect(errored.status).toBe(529);
    const served = store.listLlmUsage({ connectionId: healthy.id })[0];
    expect(served.failover).toBe(true);
    expect(served.inputTokens).toBe(296);
    expect(store.getLlmStrategyState(agent.id, VENDOR).activeIndex).toBe(1);
    // 529 is transient, not an auth failure: the key stays in rotation.
    expect(store.getConnection(overloaded.id)!.inactiveAt).toBeUndefined();
  });

  it("round-robin cools down a 429'd connection and still serves the request", async () => {
    const agent = newAgent("ts-429");
    const limited = conn("jev-limited", "ts-429");
    const healthy = conn("jev-ok", "ts-key-ok");
    store.setAgentLlmConfig(agent.id, {
      enabled: true,
      strategy: "round-robin",
      connectionIds: [limited.id, healthy.id],
    });
    const r = await viaProxy(agent.token);
    expect(r.status).toBe(200);
    expect(seen).toEqual(["Bearer ts-429", "Bearer ts-key-ok"]);
    expect(store.getLlmStrategyState(agent.id, VENDOR).cooldowns[limited.id]).toBeGreaterThan(0);
  });

  it("consecutive 401s bench a revoked key while requests keep succeeding", async () => {
    const agent = newAgent("ts-401");
    const dead = conn("jev-revoked", "ts-401");
    const good = conn("jev-good", "ts-key-g");
    store.setAgentLlmConfig(agent.id, {
      enabled: true,
      strategy: "round-robin",
      connectionIds: [dead.id, good.id],
    });
    for (let i = 0; i < 40 && !store.getConnection(dead.id)!.inactiveAt; i++) {
      const r = await viaProxy(agent.token);
      expect(r.status).toBe(200);
      expect(JSON.parse(r.body).auth).toBe("Bearer ts-key-g");
    }
    expect(store.getConnection(dead.id)!.inactiveAt).toBeTruthy();
    expect(store.getConnection(good.id)!.inactiveAt).toBeUndefined();
  });
});
