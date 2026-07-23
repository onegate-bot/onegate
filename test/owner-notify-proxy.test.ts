/**
 * SS1 proxy behavior: a default-deny of a KNOWN CREDENTIAL integration fires a
 * proactive owner-notify webhook (deduped), while explicit-deny, no-webhook, and
 * non-credential denies do not.
 *
 *   client --CONNECT--> GatewayProxy --(policy deny 403 over TLS)
 *
 * The deny path never reaches an upstream, so no stub vendor server is needed.
 * notifyFetch is stubbed to capture the outbound webhook POSTs.
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

const CRED_HOST = "api.cred-vendor.com";
const BARE_HOST = "api.bare-vendor.com";
const WEBHOOK = "https://hook.test/deliver/tok_secret";

let dir: string;
let store: Store;
let registry: Registry;
let proxy: GatewayProxy;
let proxyPort: number;
let caPem: string;

let hookAgentToken: string;
let noHookAgentToken: string;
let explicitDenyToken: string;

/** Captured outbound webhook POSTs. */
let notifyCalls: Array<{ url: string; body: any }> = [];

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-notify-"));
  const ca = initCa(dir);
  caPem = ca.rootPem;
  store = new Store(":memory:");

  registry = new Registry();
  // A credential integration (connectFlowKind === "credential").
  registry.register({
    id: "credvendor",
    title: "Cred Vendor",
    hosts: [CRED_HOST],
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    inject(ctx) {
      ctx.headers.authorization = `Bearer ${ctx.credential.data.apiKey}`;
    },
  });
  // A non-credential integration (no oauth, no credentialFields → connectFlowKind null).
  registry.register({
    id: "barevendor",
    title: "Bare Vendor",
    hosts: [BARE_HOST],
    credentialFields: [],
    inject() {
      /* nothing to inject */
    },
  });

  // Agent with a notify webhook, no allow rule → default-deny + notify.
  const withHook = store.createAgent("hook-agent", { defaultPolicy: "deny-unmatched" });
  hookAgentToken = withHook.token;
  store.setAgentNotify(withHook.agent.id, WEBHOOK);

  // Agent with NO webhook → default-deny, no notify.
  const noHook = store.createAgent("nohook-agent", { defaultPolicy: "deny-unmatched" });
  noHookAgentToken = noHook.token;

  // Agent with a webhook but an EXPLICIT deny rule → real policy decision, no notify.
  const explicit = store.createAgent("explicit-deny-agent", { defaultPolicy: "deny-unmatched" });
  explicitDenyToken = explicit.token;
  store.setAgentNotify(explicit.agent.id, WEBHOOK);
  store.createRule({
    scope: "agent",
    subjectId: explicit.agent.id,
    integrationId: "credvendor",
    methods: ["*"],
    pathGlob: "/**",
    effect: "deny",
  });

  proxy = new GatewayProxy({
    ca,
    store,
    registry,
    upstreamTls: { ca: caPem },
    upstreamLookup: () => ({ host: "127.0.0.1", port: 1 }),
    notifyFetch: (async (url: string, init: any) => {
      notifyCalls.push({ url, body: JSON.parse(String(init.body)) });
      return { ok: true, status: 200 } as Response;
    }) as unknown as typeof fetch,
  });
  proxyPort = await proxy.listen(0, "127.0.0.1");
});

afterAll(async () => {
  await proxy.close();
  rmSync(dir, { recursive: true, force: true });
});

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Fires a request through the proxy; resolves with the 403/502 body. */
function viaProxy(opts: {
  token: string;
  host: string;
  path?: string;
}): Promise<{ status: number; body: string }> {
  const host = opts.host;
  return new Promise((resolve, reject) => {
    const connectReq = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "CONNECT",
      path: `${host}:443`,
      headers: {
        "proxy-authorization": "Basic " + Buffer.from(`agent:${opts.token}`).toString("base64"),
      },
      agent: false,
    });
    connectReq.on("connect", (connectRes, socket) => {
      if (connectRes.statusCode !== 200) {
        socket.destroy();
        resolve({ status: 0, body: "" });
        return;
      }
      const tlsSocket = tls.connect({ socket, servername: host, ca: caPem }, () => {
        const req = https.request(
          {
            createConnection: () => tlsSocket,
            host,
            method: "GET",
            path: opts.path ?? "/v1/thing",
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
        req.end();
      });
      tlsSocket.on("error", reject);
    });
    connectReq.on("error", reject);
    connectReq.end();
  });
}

describe("SS1 owner deny-notification", () => {
  it("default-deny of a credential integration with a webhook fires the notify", async () => {
    notifyCalls = [];
    const r = await viaProxy({ token: hookAgentToken, host: CRED_HOST });
    expect(r.status).toBe(403);
    await delay(60);

    expect(notifyCalls).toHaveLength(1);
    const call = notifyCalls[0];
    expect(call.url).toBe(WEBHOOK);
    expect(call.body.type).toBe("onegate.owner_notify");
    expect(call.body.integrationId).toBe("credvendor");
    expect(call.body.integrationTitle).toBe("Cred Vendor");
    expect(call.body.agentName).toBe("hook-agent");
    expect(call.body.reason).toBe("policy_default_deny");
    expect(call.body.connectUrl).toMatch(/\/connect\/credvendor\/[A-Za-z0-9_-]+$/);

    // An owner_notification row was recorded and marked delivered.
    const rows = store.listOwnerNotifications({ limit: 50 });
    const mine = rows.filter((n) => n.integrationId === "credvendor" && n.status !== "suppressed");
    expect(mine.length).toBe(1);
    expect(mine[0].status).toBe("delivered");
  });

  it("dedups: a second immediate deny for the same pair does not re-notify", async () => {
    notifyCalls = [];
    const r = await viaProxy({ token: hookAgentToken, host: CRED_HOST });
    expect(r.status).toBe(403);
    await delay(60);
    expect(notifyCalls).toHaveLength(0);
  });

  it("does not notify when the agent has no webhook configured", async () => {
    notifyCalls = [];
    const r = await viaProxy({ token: noHookAgentToken, host: CRED_HOST });
    expect(r.status).toBe(403);
    await delay(60);
    expect(notifyCalls).toHaveLength(0);
    expect(store.getAgentNotify).toBeTypeOf("function");
  });

  it("does not notify on an explicit deny rule (real policy decision)", async () => {
    notifyCalls = [];
    const r = await viaProxy({ token: explicitDenyToken, host: CRED_HOST });
    expect(r.status).toBe(403);
    // Explicit deny carries no connect_url and must not notify.
    expect(JSON.parse(r.body).connect_url).toBeUndefined();
    await delay(60);
    expect(notifyCalls).toHaveLength(0);
  });

  it("does not notify for a non-credential integration (connectFlowKind null)", async () => {
    notifyCalls = [];
    const r = await viaProxy({ token: hookAgentToken, host: BARE_HOST });
    expect(r.status).toBe(403);
    await delay(60);
    expect(notifyCalls).toHaveLength(0);
  });
});
