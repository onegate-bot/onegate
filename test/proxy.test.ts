/**
 * End-to-end proxy test, fully local:
 *
 *   client --CONNECT--> GatewayProxy --TLS--> stub "vendor" https server
 *
 * The stub plays api.example-vendor.com; upstreamLookup routes the gateway's
 * outbound connection to it. The client trusts the OneGate root CA, the
 * gateway trusts the stub's CA (upstreamTls.ca = same test CA for simplicity).
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { initCa } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { Registry } from "../src/integrations/types.js";
import { GatewayProxy } from "../src/proxy/server.js";

const VENDOR_HOST = "api.example-vendor.com";
const SIGNER_HOST = "sign.example-vendor.com";
const OAUTH_HOST = "api.oauth-vendor.com";

let dir: string;
let store: Store;
let registry: Registry;
let proxy: GatewayProxy;
let proxyPort: number;
let stub: https.Server;
let stubPort: number;
let caPem: string;
let agentToken: string;
let deniedToken: string;
/** What the stub saw on the last request. */
let lastSeen: {
  auth?: string;
  path?: string;
  method?: string;
  body?: string;
  bodySha?: string;
  contentLength?: string;
} = {};

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-proxy-"));
  const ca = initCa(dir);
  caPem = ca.rootPem;
  store = new Store(":memory:");

  // Stub vendor: echoes what it received. Uses a leaf from the same CA so the
  // gateway can verify it via upstreamTls.ca.
  const stubLeaf = ca.leafFor(VENDOR_HOST);
  const stubOpts: https.ServerOptions = {
    key: stubLeaf.key,
    cert: stubLeaf.cert,
    // The stub plays multiple vendor hosts; serve a matching leaf per SNI.
    SNICallback: (servername, cb) => {
      const leaf = ca.leafFor(servername);
      cb(null, tls.createSecureContext({ key: leaf.key, cert: leaf.cert }));
    },
  };
  stub = https.createServer(stubOpts, (req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      lastSeen = {
        auth: req.headers.authorization as string | undefined,
        path: req.url,
        method: req.method,
        body,
        bodySha: req.headers["x-body-sha256"] as string | undefined,
        contentLength: req.headers["content-length"] as string | undefined,
      };
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, path: req.url }));
    });
  });
  await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
  stubPort = (stub.address() as { port: number }).port;

  registry = new Registry();
  registry.register({
    id: "vendor",
    title: "Example Vendor",
    hosts: [VENDOR_HOST],
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    inject(ctx) {
      ctx.headers.authorization = `Bearer ${ctx.credential.data.apiKey}`;
      // Exercise URL-path credential rewriting (the telegram-bot pattern).
      if (ctx.path.startsWith("/v1/pathcred/")) {
        ctx.path = ctx.path.replace("/placeholder/", "/real-secret-key/");
      }
    },
  });

  // A body-signing integration (the AWS SigV4 shape): needsBody makes the
  // gateway buffer the request body and expose it to inject.
  registry.register({
    id: "signer",
    title: "Example Signer",
    hosts: [SIGNER_HOST],
    needsBody: true,
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    inject(ctx) {
      ctx.headers.authorization = `Signed ${ctx.credential.data.apiKey}`;
      ctx.headers["x-body-sha256"] = createHash("sha256")
        .update(ctx.body ?? Buffer.alloc(0))
        .digest("hex");
    },
  });

  // An OAuth-connectable integration with NO stored connection: the "not
  // connected yet" state a bot hits, where the proxy should hand back a
  // self-minted connect_url instead of just pointing at the admin UI.
  registry.register({
    id: "oauthvendor",
    title: "OAuth Vendor",
    hosts: [OAUTH_HOST],
    credentialFields: [
      { key: "clientId", label: "Client ID", secret: false },
      { key: "refreshToken", label: "Refresh token", secret: true },
    ],
    connect: { method: "oauth" },
    oauth: {
      authUrl: "https://oauth.example.com/auth",
      tokenUrl: "https://oauth.example.com/token",
      scopes: ["read"],
    },
    inject(ctx) {
      ctx.headers.authorization = `Bearer ${ctx.credential.data.refreshToken}`;
    },
  });

  store.setCredential("vendor", "test-key", { apiKey: "real-secret-key" });
  store.setCredential("signer", "signer-key", { apiKey: "signing-secret" });

  const allowed = store.createAgent("allowed-agent", { defaultPolicy: "deny-unmatched" });
  agentToken = allowed.token;
  store.createRule({
    scope: "agent",
    subjectId: allowed.agent.id,
    integrationId: "vendor",
    methods: ["GET", "POST"],
    pathGlob: "/v1/**",
    effect: "allow",
  });
  store.createRule({
    scope: "agent",
    subjectId: allowed.agent.id,
    integrationId: "vendor",
    methods: ["*"],
    pathGlob: "/v1/admin/**",
    effect: "deny",
  });
  store.createRule({
    scope: "agent",
    subjectId: allowed.agent.id,
    integrationId: "signer",
    methods: ["*"],
    pathGlob: "/**",
    effect: "allow",
  });
  // Allowed to call the OAuth vendor, but no connection is stored for it, so
  // this exercises the no_credential (502) + connect_url path.
  store.createRule({
    scope: "agent",
    subjectId: allowed.agent.id,
    integrationId: "oauthvendor",
    methods: ["*"],
    pathGlob: "/**",
    effect: "allow",
  });

  const denied = store.createAgent("denied-agent", { defaultPolicy: "deny-unmatched" });
  deniedToken = denied.token;

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

/** Sends a request through the proxy the way a real agent would. */
function viaProxy(opts: {
  token: string | null;
  method?: string;
  path: string;
  body?: string;
  headers?: Record<string, string>;
  host?: string;
}): Promise<{ status: number; body: string; connectStatus: number }> {
  const vendorHost = opts.host ?? VENDOR_HOST;
  return new Promise((resolve, reject) => {
    const connectHeaders: Record<string, string> = {};
    if (opts.token) {
      connectHeaders["proxy-authorization"] =
        "Basic " + Buffer.from(`agent:${opts.token}`).toString("base64");
    }
    const connectReq = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "CONNECT",
      path: `${vendorHost}:443`,
      headers: connectHeaders,
      agent: false,
    });
    connectReq.on("connect", (connectRes, socket) => {
      if (connectRes.statusCode !== 200) {
        socket.destroy();
        resolve({ status: 0, body: "", connectStatus: connectRes.statusCode ?? 0 });
        return;
      }
      const tlsSocket = tls.connect({ socket, servername: vendorHost, ca: caPem }, () => {
        const req = https.request(
          {
            // With createConnection set and agent left undefined, node uses
            // our already-established TLS socket instead of dialing itself.
            createConnection: () => tlsSocket,
            host: vendorHost,
            method: opts.method ?? "GET",
            path: opts.path,
            headers: opts.headers,
          },
          (res) => {
            let body = "";
            res.on("data", (c) => (body += c));
            res.on("end", () => {
              resolve({ status: res.statusCode ?? 0, body, connectStatus: 200 });
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

describe("agent auth", () => {
  it("rejects CONNECT without a valid token (407)", async () => {
    const r = await viaProxy({ token: null, path: "/v1/thing" });
    expect(r.connectStatus).toBe(407);
    const bad = await viaProxy({ token: "og_invalid", path: "/v1/thing" });
    expect(bad.connectStatus).toBe(407);
  });
});

describe("allowed traffic", () => {
  it("terminates TLS, injects the credential, bridges to the vendor", async () => {
    const r = await viaProxy({
      token: agentToken,
      path: "/v1/things?limit=2",
      headers: { authorization: "Bearer placeholder-from-agent" },
    });
    expect(r.status).toBe(200);
    expect(JSON.parse(r.body).ok).toBe(true);
    // The real key replaced the agent's placeholder.
    expect(lastSeen.auth).toBe("Bearer real-secret-key");
    expect(lastSeen.path).toBe("/v1/things?limit=2");
  });

  it("forwards request bodies", async () => {
    const r = await viaProxy({
      token: agentToken,
      method: "POST",
      path: "/v1/items",
      body: JSON.stringify({ a: 1 }),
      headers: { "content-type": "application/json" },
    });
    expect(r.status).toBe(200);
    expect(lastSeen.method).toBe("POST");
    expect(lastSeen.body).toBe('{"a":1}');
  });
});

describe("policy enforcement", () => {
  it("denies by explicit deny rule (admin subtree)", async () => {
    const r = await viaProxy({ token: agentToken, path: "/v1/admin/users" });
    expect(r.status).toBe(403);
    expect(JSON.parse(r.body).error).toBe("onegate_policy_denied");
  });

  it("denies methods outside the allow rule", async () => {
    const r = await viaProxy({ token: agentToken, method: "DELETE", path: "/v1/things" });
    expect(r.status).toBe(403);
  });

  it("denies an agent with no rules under deny-unmatched", async () => {
    const r = await viaProxy({ token: deniedToken, path: "/v1/things" });
    expect(r.status).toBe(403);
  });

  it("an explicit deny rule carries no connect_url (real policy decision)", async () => {
    const r = await viaProxy({ token: agentToken, path: "/v1/admin/users" });
    expect(r.status).toBe(403);
    expect(JSON.parse(r.body).connect_url).toBeUndefined();
  });

  it("a credential (non-OAuth) integration default-deny returns a self-minted connect_url", async () => {
    // denied-agent hitting the credential vendor: 403, and since the vendor is
    // connectable (it has credentialFields), the proxy hands back a connect_url
    // pointing at the paste wizard.
    const r = await viaProxy({ token: deniedToken, path: "/v1/things" });
    expect(r.status).toBe(403);
    const body = JSON.parse(r.body);
    expect(body.error).toBe("onegate_policy_denied");
    expect(body.connect_url).toMatch(/\/connect\/vendor\/[A-Za-z0-9_-]+$/);
  });
});

describe("self-service connect_url on not-connected errors", () => {
  it("default-deny on an OAuth integration returns a self-minted connect_url", async () => {
    const r = await viaProxy({ token: deniedToken, path: "/v1/thing", host: OAUTH_HOST });
    expect(r.status).toBe(403);
    const body = JSON.parse(r.body);
    expect(body.error).toBe("onegate_policy_denied");
    expect(body.connect_url).toMatch(/\/connect\/oauthvendor\/[A-Za-z0-9_-]+$/);
    expect(typeof body.connect_expires_at).toBe("string");
    expect(body.hint).toContain("owner");
  });

  it("allowed but no stored connection returns 502 with a connect_url", async () => {
    const r = await viaProxy({ token: agentToken, path: "/v1/thing", host: OAUTH_HOST });
    expect(r.status).toBe(502);
    const body = JSON.parse(r.body);
    expect(body.error).toBe("onegate_no_credential");
    expect(body.connect_url).toMatch(/\/connect\/oauthvendor\/[A-Za-z0-9_-]+$/);
  });

  it("reuses one live link across retries instead of minting a new one each time", async () => {
    const a = await viaProxy({ token: agentToken, path: "/v1/thing", host: OAUTH_HOST });
    const b = await viaProxy({ token: agentToken, path: "/v1/thing", host: OAUTH_HOST });
    expect(JSON.parse(a.body).connect_url).toBe(JSON.parse(b.body).connect_url);
  });
});

describe("audit", () => {
  it("recorded auth failures, allows and denies", () => {
    const decisions = store.listAudit({ limit: 100 }).map((e) => e.decision);
    expect(decisions).toContain("auth_failed");
    expect(decisions).toContain("allow");
    expect(decisions).toContain("deny");
  });

  it("allow entries carry the upstream status and rule id", () => {
    const allow = store.listAudit({ limit: 100 }).find((e) => e.decision === "allow");
    expect(allow?.status).toBe(200);
    expect(allow?.ruleId).toMatch(/^rl_/);
    expect(allow?.agentName).toBe("allowed-agent");
  });
});

describe("url path credential rewriting", () => {
  it("forwards the rewritten path upstream", async () => {
    const r = await viaProxy({ token: agentToken, path: "/v1/pathcred/placeholder/getMe" });
    expect(r.status).toBe(200);
    expect(JSON.parse(r.body).path).toBe("/v1/pathcred/real-secret-key/getMe");
  });
});

describe("body buffering for signing integrations", () => {
  it("exposes the body to inject and forwards it intact with content-length", async () => {
    const payload = JSON.stringify({ hello: "sigv4" });
    const r = await viaProxy({
      token: agentToken,
      method: "POST",
      path: "/v1/sign",
      body: payload,
      host: SIGNER_HOST,
    });
    expect(r.status).toBe(200);
    expect(lastSeen.body).toBe(payload);
    expect(lastSeen.auth).toBe("Signed signing-secret");
    expect(lastSeen.bodySha).toBe(createHash("sha256").update(payload).digest("hex"));
    expect(lastSeen.contentLength).toBe(String(Buffer.byteLength(payload)));
  });

  it("hashes the empty body for bodyless requests", async () => {
    const r = await viaProxy({ token: agentToken, path: "/v1/sign", host: SIGNER_HOST });
    expect(r.status).toBe(200);
    expect(lastSeen.bodySha).toBe(createHash("sha256").update("").digest("hex"));
  });

  it("rejects bodies above the buffering cap with 413", async () => {
    process.env.ONEGATE_MAX_BUFFERED_BODY = "8";
    try {
      const r = await viaProxy({
        token: agentToken,
        method: "POST",
        path: "/v1/sign",
        body: "way-more-than-eight-bytes",
        host: SIGNER_HOST,
      });
      expect(r.status).toBe(413);
      expect(r.body).toContain("onegate_body_too_large");
    } finally {
      delete process.env.ONEGATE_MAX_BUFFERED_BODY;
    }
  });

  it("audited the oversized body rejection", () => {
    const entry = store.listAudit({ limit: 50 }).find((e) => e.decision === "body_too_large");
    expect(entry?.integrationId).toBe("signer");
    expect(entry?.status).toBe(413);
  });
});

describe("app connections (multi-account, per-agent scope)", () => {
  // A dedicated integration on its own host so the legacy "vendor" path stays
  // free of app connections and provably unchanged.
  const APP_HOST = "api.app-vendor.com";
  let appToken: string;
  let appAgentId: string;
  let tenantConnId: string;
  let agentConnId: string;

  beforeAll(() => {
    registry.register({
      id: "appvendor",
      title: "App Vendor",
      hosts: [APP_HOST],
      credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
      inject(ctx) {
        ctx.headers.authorization = `Bearer ${ctx.credential.data.apiKey}`;
      },
    });
    const appAgent = store.createAgent("app-agent", { defaultPolicy: "deny-unmatched" });
    appToken = appAgent.token;
    appAgentId = appAgent.agent.id;
    store.createRule({
      scope: "agent",
      subjectId: appAgentId,
      integrationId: "appvendor",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
    // Two named accounts: a tenant-wide default and one bound to this agent.
    tenantConnId = store.createConnection({
      kind: "app",
      vendor: "appvendor",
      name: "vendor-shared",
      data: { apiKey: "tenant-key" },
      isDefault: true,
    }).id;
    agentConnId = store.createConnection({
      kind: "app",
      vendor: "appvendor",
      name: "vendor-mine",
      data: { apiKey: "agent-key" },
      ownerAgentId: appAgentId,
    }).id;
    // Default-deny: both connections start ungranted. Grant both to this agent
    // so the selection paths below have a candidate set.
    store.grantConnection(tenantConnId, "agent", appAgentId);
    store.grantConnection(agentConnId, "agent", appAgentId);
  });

  it("selects a connection by name via x-onegate-connection and strips the header", async () => {
    const r = await viaProxy({
      token: appToken,
      host: APP_HOST,
      path: "/v1/by-name",
      headers: { "x-onegate-connection": "vendor-mine" },
    });
    expect(r.status).toBe(200);
    expect(lastSeen.auth).toBe("Bearer agent-key");
    // The selection header must never reach upstream.
    expect(lastSeen.path).toBe("/v1/by-name");
  });

  it("selects a connection by id", async () => {
    const r = await viaProxy({
      token: appToken,
      host: APP_HOST,
      path: "/v1/by-id",
      headers: { "x-onegate-connection": agentConnId },
    });
    expect(r.status).toBe(200);
    expect(lastSeen.auth).toBe("Bearer agent-key");
  });

  it("returns 400 onegate_unknown_connection for an unpermitted header", async () => {
    const r = await viaProxy({
      token: appToken,
      host: APP_HOST,
      path: "/v1/nope",
      headers: { "x-onegate-connection": "does-not-exist" },
    });
    expect(r.status).toBe(400);
    expect(JSON.parse(r.body).error).toBe("onegate_unknown_connection");
    const entry = store.listAudit({ limit: 50 }).find((e) => e.decision === "unknown_connection");
    expect(entry?.status).toBe(400);
  });

  it("uses the agent's saved choice when no header is sent", async () => {
    store.setAgentAppConfig(appAgentId, "appvendor", agentConnId);
    try {
      const r = await viaProxy({ token: appToken, host: APP_HOST, path: "/v1/saved" });
      expect(r.status).toBe(200);
      expect(lastSeen.auth).toBe("Bearer agent-key");
    } finally {
      store.clearAgentAppConfig(appAgentId, "appvendor");
    }
  });

  it("falls back to the tenant-wide default when no header and no saved choice", async () => {
    const r = await viaProxy({ token: appToken, host: APP_HOST, path: "/v1/default" });
    expect(r.status).toBe(200);
    expect(lastSeen.auth).toBe("Bearer tenant-key");
  });

  it("records the selected connection on the allow audit", async () => {
    await viaProxy({
      token: appToken,
      host: APP_HOST,
      path: "/v1/audited",
      headers: { "x-onegate-connection": "vendor-mine" },
    });
    const entry = store
      .listAudit({ limit: 50 })
      .find((e) => e.decision === "allow" && e.path === "/v1/audited");
    expect(entry?.connectionId).toBe(agentConnId);
    expect(entry?.connectionName).toBe("vendor-mine");
  });

  it("blocks a header naming an existing-but-ungranted connection with 403", async () => {
    // A second agent that was NOT granted vendor-mine.
    const other = store.createAgent("app-agent-2", { defaultPolicy: "deny-unmatched" });
    store.createRule({
      scope: "agent",
      subjectId: other.agent.id,
      integrationId: "appvendor",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
    const r = await viaProxy({
      token: other.token,
      host: APP_HOST,
      path: "/v1/blocked",
      headers: { "x-onegate-connection": "vendor-mine" },
    });
    expect(r.status).toBe(403);
    expect(JSON.parse(r.body).error).toBe("onegate_connection_not_granted");
    const entry = store
      .listAudit({ limit: 50 })
      .find((e) => e.decision === "connection_not_granted" && e.path === "/v1/blocked");
    expect(entry?.status).toBe(403);
    store.deleteAgent(other.agent.id);
  });

  it("default-denies when named connections exist for the integration but none are granted", async () => {
    const other = store.createAgent("app-agent-3", { defaultPolicy: "deny-unmatched" });
    store.createRule({
      scope: "agent",
      subjectId: other.agent.id,
      integrationId: "appvendor",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
    // No header, no grant: default-deny (not a silent legacy fallthrough,
    // because named app connections DO exist for appvendor).
    const r = await viaProxy({ token: other.token, host: APP_HOST, path: "/v1/denied" });
    expect(r.status).toBe(403);
    expect(JSON.parse(r.body).error).toBe("onegate_connection_not_granted");
    store.deleteAgent(other.agent.id);
  });

  it("leaves the legacy shared-credential path unchanged (no app connections)", async () => {
    // The original "vendor" integration has no app connections, so allowed-agent
    // still gets the legacy credentials row, byte-identical to before.
    const r = await viaProxy({ token: agentToken, path: "/v1/legacy" });
    expect(r.status).toBe(200);
    expect(lastSeen.auth).toBe("Bearer real-secret-key");
    const entry = store
      .listAudit({ limit: 50 })
      .find((e) => e.decision === "allow" && e.path === "/v1/legacy");
    expect(entry?.connectionId).toBeNull();
  });

  it("leaves a connection-scoped rule inert while the feature flag is off", async () => {
    // Same pin, flag OFF (default): every connection still reaches the path.
    const pin = store.createRule({
      scope: "agent",
      subjectId: appAgentId,
      integrationId: "appvendor",
      methods: ["*"],
      pathGlob: "/v1/flagoff/**",
      effect: "deny",
      connectionScope: "except",
      connectionId: agentConnId,
    });
    try {
      const r = await viaProxy({
        token: appToken,
        host: APP_HOST,
        path: "/v1/flagoff/thing",
        headers: { "x-onegate-connection": "vendor-shared" },
      });
      expect(r.status).toBe(200);
      expect(lastSeen.auth).toBe("Bearer tenant-key");
    } finally {
      store.deleteRule(pin.id);
    }
  });

  it("enforces a connection-scoped DENY-except across both eval phases", async () => {
    // Ziv's model: keep the broad allow, then pin one path so only vendor-mine
    // may reach it. Every OTHER connection is denied by a phase-2 re-eval that
    // fires once the connection is resolved. Requires the feature flag on.
    process.env.ONEGATE_CONNECTION_SCOPED_RULES = "1";
    const pin = store.createRule({
      scope: "agent",
      subjectId: appAgentId,
      integrationId: "appvendor",
      methods: ["*"],
      pathGlob: "/v1/pinned/**",
      effect: "deny",
      connectionScope: "except",
      connectionId: agentConnId,
    });
    try {
      // The target connection (vendor-mine) still reaches the pinned path.
      const ok = await viaProxy({
        token: appToken,
        host: APP_HOST,
        path: "/v1/pinned/thing",
        headers: { "x-onegate-connection": "vendor-mine" },
      });
      expect(ok.status).toBe(200);
      expect(lastSeen.auth).toBe("Bearer agent-key");

      // A different connection (the tenant default) is blocked on the same path.
      const blocked = await viaProxy({
        token: appToken,
        host: APP_HOST,
        path: "/v1/pinned/thing",
        headers: { "x-onegate-connection": "vendor-shared" },
      });
      expect(blocked.status).toBe(403);
      expect(JSON.parse(blocked.body).error).toBe("onegate_policy_denied");
      const entry = store
        .listAudit({ limit: 50 })
        .find((e) => e.decision === "deny" && e.path === "/v1/pinned/thing");
      expect(entry?.ruleId).toBe(pin.id);

      // The pin does not touch other paths: vendor-shared still works elsewhere.
      const elsewhere = await viaProxy({
        token: appToken,
        host: APP_HOST,
        path: "/v1/unpinned",
        headers: { "x-onegate-connection": "vendor-shared" },
      });
      expect(elsewhere.status).toBe(200);
      expect(lastSeen.auth).toBe("Bearer tenant-key");
    } finally {
      store.deleteRule(pin.id);
      delete process.env.ONEGATE_CONNECTION_SCOPED_RULES;
    }
  });

  afterAll(() => {
    store.deleteConnection(tenantConnId);
    store.deleteConnection(agentConnId);
  });
});

describe("graceful shutdown", () => {
  it("close() resolves promptly even with a live (non-draining) tunnel open", async () => {
    const sdir = mkdtempSync(join(tmpdir(), "onegate-shutdown-"));
    const sca = initCa(sdir);
    const sstore = new Store(":memory:");
    const sreg = new Registry();
    // No integration: the host takes the opaque passthrough path, so the
    // tunnel stays open (like a persistent agent tunnel) until we close().
    const upstream = net.createServer((c) => c.on("data", () => {}));
    await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
    const upstreamPort = (upstream.address() as { port: number }).port;

    const sproxy = new GatewayProxy({
      ca: sca,
      store: sstore,
      registry: sreg,
      upstreamLookup: () => ({ host: "127.0.0.1", port: upstreamPort }),
    });
    const sport = await sproxy.listen(0, "127.0.0.1");
    const ag = sstore.createAgent("tunnel-agent", { defaultPolicy: "deny-unmatched" });

    // Open a CONNECT tunnel and keep it idle/open.
    await new Promise<void>((resolve, reject) => {
      const req = http.request({
        host: "127.0.0.1",
        port: sport,
        method: "CONNECT",
        path: "opaque.example.com:443",
        headers: {
          "proxy-authorization": "Basic " + Buffer.from(`agent:${ag.token}`).toString("base64"),
        },
        agent: false,
      });
      req.on("connect", (res) => {
        if (res.statusCode === 200) resolve();
        else reject(new Error(`connect status ${res.statusCode}`));
      });
      req.on("error", reject);
      req.end();
    });

    const start = Date.now();
    await sproxy.close();
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(1000);

    upstream.close();
    sstore.close();
    rmSync(sdir, { recursive: true, force: true });
  });
});
