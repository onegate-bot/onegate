/**
 * Regression test for issue #4: connection-scoped rules must be enforced on the
 * LLM-routed path, not just the app-connection path.
 *
 * The LLM path picks its own connection (round-robin/fallback over the agent's
 * enabled connections) inside handleLlmRequest and injects that connection's
 * credential. Before the fix, it returned before the phase-2 connection-scoped
 * re-evaluation ran, so a rule like "deny this LLM integration EXCEPT via
 * connection X" was silently unenforced on the routed path.
 *
 * Here a stub vendor echoes the injected x-api-key so we can tell WHICH
 * connection served the request. A DENY-except rule pins the integration to
 * connB; with the flag ON a fallback-routed request that selects connA (the
 * non-target) must be denied 403, while a request that resolves to connB is
 * allowed 200. With the flag OFF the rule is inert and the request flows.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
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

const LLM_HOST = "api.llm-vendor-scope.test";
const VENDOR = "scopevendor";

let dir: string;
let store: Store;
let proxy: GatewayProxy;
let proxyPort: number;
let stub: https.Server;
let caPem: string;
let seenKeys: string[] = [];

let agentToken: string;
let agentId: string;
let connA: Connection; // non-target of the "only via B" pin
let connB: Connection; // target connection

const flagBefore = process.env.ONEGATE_CONNECTION_SCOPED_RULES;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-llm-scope-"));
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
      req.on("data", () => {});
      req.on("end", () => {
        seenKeys.push(String(req.headers["x-api-key"] ?? ""));
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      });
    },
  );
  await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
  const stubPort = (stub.address() as { port: number }).port;

  const registry = new Registry();
  registry.register({
    id: VENDOR,
    title: "Scope Test LLM Vendor",
    hosts: [LLM_HOST],
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    needsBody: true,
    llm: {
      vendor: VENDOR,
      inject(ctx) {
        ctx.headers["x-api-key"] = ctx.credential.data.apiKey ?? "";
      },
    },
    inject(ctx) {
      ctx.headers["x-api-key"] = `app-cred-${ctx.credential.data.apiKey}`;
    },
  });

  const a = store.createAgent("scope-agent", { defaultPolicy: "deny-unmatched" });
  agentToken = a.token;
  agentId = a.agent.id;
  // Broad allow so phase-1 passes; the pin rides on top of this.
  store.createRule({
    scope: "agent",
    subjectId: agentId,
    integrationId: VENDOR,
    methods: ["*"],
    pathGlob: "/**",
    effect: "allow",
  });

  connA = store.createConnection({ kind: "llm", vendor: VENDOR, name: "conn-a", data: { apiKey: "key-a" } });
  connB = store.createConnection({ kind: "llm", vendor: VENDOR, name: "conn-b", data: { apiKey: "key-b" } });

  // Pin: DENY the LLM integration EXCEPT when the request uses connB.
  store.createRule({
    scope: "agent",
    subjectId: agentId,
    integrationId: VENDOR,
    methods: ["*"],
    pathGlob: "/**",
    effect: "deny",
    connectionId: connB.id,
    connectionScope: "except",
  });

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
  if (flagBefore === undefined) delete process.env.ONEGATE_CONNECTION_SCOPED_RULES;
  else process.env.ONEGATE_CONNECTION_SCOPED_RULES = flagBefore;
});

beforeEach(() => {
  seenKeys = [];
});

function viaProxy(): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const connectReq = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "CONNECT",
      path: `${LLM_HOST}:443`,
      headers: {
        "proxy-authorization": "Basic " + Buffer.from(`agent:${agentToken}`).toString("base64"),
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
            method: "POST",
            path: "/v1/messages",
            headers: { "content-type": "application/json" },
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
        req.write("{}");
        req.end();
      });
      tlsSocket.on("error", reject);
    });
    connectReq.on("error", reject);
    connectReq.end();
  });
}

/** Force the LLM strategy to select the given connection index next. */
function pointStrategyAt(index: number): void {
  store.setLlmStrategyState(agentId, VENDOR, {
    activeIndex: index,
    rrCursor: index - 1,
    callsSinceFallback: 0,
    cooldowns: {},
  });
}

describe("connection-scoped rules on the LLM-routed path (issue #4)", () => {
  describe("flag ON", () => {
    beforeEach(() => {
      process.env.ONEGATE_CONNECTION_SCOPED_RULES = "1";
      store.setAgentLlmConfig(agentId, {
        enabled: true,
        strategy: "fallback",
        connectionIds: [connA.id, connB.id], // primary is the NON-target
      });
    });
    afterEach(() => store.deleteAgentLlmConfig(agentId));

    it("DENIES when the route selects the non-target connection", async () => {
      pointStrategyAt(0); // connA, the excepted (denied) connection
      const r = await viaProxy();
      expect(r.status).toBe(403);
      expect(JSON.parse(r.body).error).toBe("onegate_policy_denied");
      // Denied before any credential injection reached the vendor.
      expect(seenKeys).toEqual([]);
      const entry = store.listAudit({ limit: 1 })[0];
      expect(entry.decision).toBe("deny");
      expect(entry.status).toBe(403);
    });

    it("ALLOWS when the route selects the target connection", async () => {
      pointStrategyAt(1); // connB, the pinned/allowed connection
      const r = await viaProxy();
      expect(r.status).toBe(200);
      expect(seenKeys).toEqual(["key-b"]);
    });
  });

  describe("flag OFF (default) — rule is inert", () => {
    beforeEach(() => {
      delete process.env.ONEGATE_CONNECTION_SCOPED_RULES;
      store.setAgentLlmConfig(agentId, {
        enabled: true,
        strategy: "fallback",
        connectionIds: [connA.id, connB.id],
      });
    });
    afterEach(() => store.deleteAgentLlmConfig(agentId));

    it("selecting the non-target connection is NOT denied (behavior unchanged)", async () => {
      pointStrategyAt(0); // connA
      const r = await viaProxy();
      expect(r.status).toBe(200);
      expect(seenKeys).toEqual(["key-a"]);
    });
  });
});
