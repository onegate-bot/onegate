/**
 * Self-connect wizard scoping (security regression suite).
 *
 * An agent can mint its own connect link (POST https://onegate.internal/connect-links),
 * open the public wizard and submit any credential, junk included. The wizard
 * then auto-wires a grant + allow rule. That rule used to be an agent-scoped
 * `* /**` allow for the WHOLE integration, so an agent limited by a narrow
 * project allow, but with the owner's real connection granted via the project,
 * could self-connect junk and then drive the owner's connection with any method
 * on any path. These tests pin the fix:
 *
 *  - the autowired rule authorizes only the connection the wizard created, with
 *    the connection-scoped-rules flag on AND off;
 *  - a request naming another granted connection gets exactly the pre-redeem
 *    verdict;
 *  - first-time onboarding (no prior rules) still works end to end;
 *  - an existing rule's lease is never re-stamped, extended or cleared;
 *  - self-mint is rate-limited and outstanding self-minted links are capped;
 *  - a failing vendor token endpoint's body never reaches the agent.
 *
 * Everything runs against local stub servers.
 */

import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { initCa } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { Registry, type Integration } from "../src/integrations/types.js";
import { GatewayProxy, SELF_MINT_MAX_OUTSTANDING, SELF_MINT_PER_HOUR } from "../src/proxy/server.js";
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";
import { DISCOVERY_HOST, buildDiscovery } from "../src/discovery.js";
import { oauthBearerToken } from "../src/integrations/oauth.js";
import { gcpAccessToken } from "../src/integrations/gcp.js";
import { generateKeyPairSync } from "node:crypto";

const VENDOR_HOST = "api.example-vendor.test";
const OAUTH_HOST = "api.example-oauth.test";
const VENDOR_SECRET_BODY = "VENDOR-INTERNAL-DETAIL client_id=cid-123 account=acme-prod";

interface Seen {
  method: string;
  path: string;
  auth: string | undefined;
}

interface Env {
  store: Store;
  registry: Registry;
  proxyPort: number;
  adminPort: number;
  caPem: string;
  seen: Seen[];
  close: () => Promise<void>;
}

const envs: Env[] = [];
const savedFlag = process.env.ONEGATE_CONNECTION_SCOPED_RULES;

afterEach(async () => {
  while (envs.length) await envs.pop()!.close();
  if (savedFlag === undefined) delete process.env.ONEGATE_CONNECTION_SCOPED_RULES;
  else process.env.ONEGATE_CONNECTION_SCOPED_RULES = savedFlag;
  delete process.env.ONEGATE_PUBLIC_URL;
});

async function setup(opts: { tokenEndpoint?: string } = {}): Promise<Env> {
  const dir = mkdtempSync(join(tmpdir(), "onegate-wizard-scope-"));
  const ca = initCa(dir);
  const caPem = ca.rootPem;
  const store = new Store(":memory:");
  const seen: Seen[] = [];

  const stubLeaf = ca.leafFor(VENDOR_HOST);
  const stub = https.createServer({ key: stubLeaf.key, cert: stubLeaf.cert }, (req, res) => {
    req.resume();
    req.on("end", () => {
      seen.push({ method: req.method ?? "", path: req.url ?? "", auth: req.headers.authorization });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
  const stubPort = (stub.address() as { port: number }).port;

  const registry = new Registry();
  registry.register({
    id: "vendor",
    title: "Vendor",
    hosts: [VENDOR_HOST],
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    connect: { method: "api_key" },
    inject(ctx) {
      ctx.headers.authorization = "Bearer " + ctx.credential.data.apiKey;
    },
  } as unknown as Integration);
  if (opts.tokenEndpoint) {
    const oauthInteg = {
      id: "oauthv",
      title: "OAuth Vendor",
      hosts: [OAUTH_HOST],
      credentialFields: [],
      oauth: {
        authUrl: "https://auth.invalid/authorize",
        tokenUrl: opts.tokenEndpoint,
        defaultScopes: [],
      },
      async inject(ctx: { headers: Record<string, string>; credential: never; store: Store }) {
        ctx.headers.authorization =
          "Bearer " + (await oauthBearerToken(oauthInteg, ctx.credential, ctx.store));
      },
    };
    registry.register(oauthInteg as unknown as Integration);
  }

  const proxy = new GatewayProxy({
    ca,
    store,
    registry,
    upstreamTls: { ca: caPem },
    upstreamLookup: () => ({ host: "127.0.0.1", port: stubPort }),
    log: () => {},
  });
  const proxyPort = await proxy.listen(0, "127.0.0.1");

  const app = createAdminApp({ store, registry, ca, version: "test" });
  const admin = http.createServer(app);
  await new Promise<void>((r) => admin.listen(0, "127.0.0.1", r));
  const adminPort = (admin.address() as { port: number }).port;
  process.env.ONEGATE_PUBLIC_URL = `http://127.0.0.1:${adminPort}`;

  const env: Env = {
    store,
    registry,
    proxyPort,
    adminPort,
    caPem,
    seen,
    close: async () => {
      await proxy.close();
      await new Promise<void>((r) => admin.close(() => r()));
      await new Promise<void>((r) => stub.close(() => r()));
      rmSync(dir, { recursive: true, force: true });
    },
  };
  envs.push(env);
  return env;
}

/** One request through the proxy (CONNECT + TLS + HTTP/1.1). */
function viaProxy(
  env: Env,
  token: string,
  opts: { host?: string; method?: string; path?: string; headers?: Record<string, string>; body?: string },
): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
  const host = opts.host ?? VENDOR_HOST;
  return new Promise((resolve, reject) => {
    const connectReq = http.request({
      host: "127.0.0.1",
      port: env.proxyPort,
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
      const tlsSocket = tls.connect({ socket, servername: host, ca: env.caPem }, () => {
        const headers: Record<string, string> = { ...(opts.headers ?? {}) };
        if (opts.body !== undefined) {
          headers["content-type"] = "application/json";
          headers["content-length"] = String(Buffer.byteLength(opts.body));
        }
        const req = http.request(
          {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            createConnection: () => tlsSocket as any,
            host,
            method: opts.method ?? "GET",
            path: opts.path ?? "/",
            headers,
          },
          (res) => {
            let body = "";
            res.on("data", (c) => (body += c));
            res.on("end", () => {
              resolve({ status: res.statusCode ?? 0, body, headers: res.headers });
              tlsSocket.end();
            });
          },
        );
        req.on("error", reject);
        if (opts.body !== undefined) req.write(opts.body);
        req.end();
      });
      tlsSocket.on("error", reject);
    });
    connectReq.on("error", reject);
    connectReq.end();
  });
}

function selfMint(env: Env, token: string, integrationId = "vendor") {
  return viaProxy(env, token, {
    host: DISCOVERY_HOST,
    method: "POST",
    path: "/connect-links",
    body: JSON.stringify({ integrationId }),
  });
}

async function submitWizard(env: Env, linkToken: string, apiKey: string): Promise<number> {
  const r = await fetch(`http://127.0.0.1:${env.adminPort}/connect/vendor/${linkToken}/submit`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ apiKey }).toString(),
  });
  await r.text();
  return r.status;
}

/** The reviewer's scenario: narrow project allow + owner connection via the project. */
function narrowAgentWithOwnerConnection(env: Env) {
  const project = env.store.createProject("team");
  const { agent, token } = env.store.createAgent("narrow", {
    defaultPolicy: "deny-unmatched",
    projectId: project.id,
  });
  const owner = env.store.createConnection({
    kind: "app",
    vendor: "vendor",
    name: "owner-prod",
    data: { apiKey: "OWNER-PROD-SECRET" },
  });
  env.store.grantConnection(owner.id, "project", project.id);
  env.store.createRule({
    scope: "project",
    subjectId: project.id,
    integrationId: "vendor",
    methods: ["GET"],
    pathGlob: "/v1/read/**",
    effect: "allow",
  });
  return { agent, token, owner };
}

describe.each([
  ["off", undefined],
  ["on", "1"],
])("self-minted wizard redeem with ONEGATE_CONNECTION_SCOPED_RULES %s", (_label, flag) => {
  it("does not widen access to another granted connection, and the new connection works", async () => {
    if (flag) process.env.ONEGATE_CONNECTION_SCOPED_RULES = flag;
    else delete process.env.ONEGATE_CONNECTION_SCOPED_RULES;
    const env = await setup();
    const { agent, token } = narrowAgentWithOwnerConnection(env);
    const probes = [
      { method: "DELETE", path: "/v1/everything" },
      { method: "POST", path: "/v1/read/x" },
      { method: "GET", path: "/v1/read/x" },
      { method: "GET", path: "/v1/other" },
    ];
    const verdicts = async () => {
      const out: number[] = [];
      for (const p of probes) {
        const r = await viaProxy(env, token, { ...p, headers: { "x-onegate-connection": "owner-prod" } });
        out.push(r.status);
      }
      return out;
    };

    const before = await verdicts();
    expect(before).toEqual([403, 403, 200, 403]);

    const mint = await selfMint(env, token);
    expect(mint.status).toBe(201);
    const linkToken = JSON.parse(mint.body).token as string;
    expect(env.store.getOnboardingLink(linkToken)?.mintedBy).toBe("agent");
    expect(await submitWizard(env, linkToken, "junk")).toBe(200);

    // The only rule added is pinned to the new connection.
    const own = env.store.rulesForAgent(env.store.getAgent(agent.id)!).filter((r) => r.scope === "agent");
    expect(own).toHaveLength(1);
    const created = env.store.getConnection(own[0].connectionId!)!;
    expect(created.ownerAgentId).toBe(agent.id);
    expect(own[0]).toMatchObject({ connectionScope: "only", connectionScopeEnforced: true });

    // Exactly the pre-redeem verdicts on the owner's connection.
    env.seen.length = 0;
    expect(await verdicts()).toEqual(before);
    // Upstream saw only the one allowed GET, with the owner's credential.
    expect(env.seen).toEqual([{ method: "GET", path: "/v1/read/x", auth: "Bearer OWNER-PROD-SECRET" }]);

    // The agent can use the connection it created, and only with its own key.
    env.seen.length = 0;
    const mine = await viaProxy(env, token, {
      method: "DELETE",
      path: "/v1/everything",
      headers: { "x-onegate-connection": created.id },
    });
    expect(mine.status).toBe(200);
    expect(env.seen).toEqual([{ method: "DELETE", path: "/v1/everything", auth: "Bearer junk" }]);
  });
});

describe("wizard autowire", () => {
  it("first-time onboarding with no prior rules connects and works without a header", async () => {
    const env = await setup();
    const { agent, token } = env.store.createAgent("fresh", { defaultPolicy: "deny-unmatched" });

    const before = await viaProxy(env, token, { method: "GET", path: "/v1/me" });
    expect(before.status).toBe(403);

    const mint = await selfMint(env, token);
    expect(await submitWizard(env, JSON.parse(mint.body).token, "my-own-key")).toBe(200);

    env.seen.length = 0;
    const r = await viaProxy(env, token, { method: "POST", path: "/v1/anything" });
    expect(r.status).toBe(200);
    expect(env.seen).toEqual([{ method: "POST", path: "/v1/anything", auth: "Bearer my-own-key" }]);

    // Discovery reports the integration as reachable via the scoped rule.
    const d = buildDiscovery(env.store, env.registry, env.store.getAgent(agent.id)!);
    expect(d.integrations.find((i) => i.id === "vendor")?.access).toBe("allowed");
  });

  it("an explicit deny still wins over the wizard rule", async () => {
    const env = await setup();
    const { agent, token } = env.store.createAgent("denied", { defaultPolicy: "deny-unmatched" });
    env.store.createRule({
      scope: "agent",
      subjectId: agent.id,
      integrationId: "vendor",
      methods: ["DELETE"],
      pathGlob: "/**",
      effect: "deny",
    });
    const mint = await selfMint(env, token);
    expect(await submitWizard(env, JSON.parse(mint.body).token, "k")).toBe(200);
    expect((await viaProxy(env, token, { method: "DELETE", path: "/v1/x" })).status).toBe(403);
    expect((await viaProxy(env, token, { method: "GET", path: "/v1/x" })).status).toBe(200);
  });

  it("never re-stamps, extends or clears an existing rule's lease", async () => {
    const env = await setup();
    const { agent, token } = env.store.createAgent("leased", { defaultPolicy: "deny-unmatched" });
    // An integration default lease that the old code would have re-stamped onto
    // the existing rule, and a second always-on rule it would have leased.
    env.store.setIntegrationLease("vendor", 7200);
    const leased = env.store.createRule({
      scope: "agent",
      subjectId: agent.id,
      integrationId: "vendor",
      methods: ["GET"],
      pathGlob: "/v1/**",
      effect: "allow",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      leaseTtlSeconds: 60,
    });
    const mint = await selfMint(env, token);
    expect(await submitWizard(env, JSON.parse(mint.body).token, "k")).toBe(200);
    expect(env.store.getRule(leased.id)).toEqual(leased);
    // The new connection's own rule carries its own lease.
    const added = env.store
      .rulesForAgent(env.store.getAgent(agent.id)!)
      .find((r) => r.id !== leased.id)!;
    expect(added.leaseTtlSeconds).toBe(7200);
    expect(added.connectionScope).toBe("only");
  });

  it("owner-minted links are recorded as such and wire the same connection-scoped rule", async () => {
    const env = await setup();
    const { agent } = env.store.createAgent("owned", { defaultPolicy: "deny-unmatched" });
    const r = await fetch(`http://127.0.0.1:${env.adminPort}/api/onboarding-links`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${ensureAdminToken(env.store)!}` },
      body: JSON.stringify({ agentId: agent.id, integrationId: "vendor" }),
    });
    expect(r.status).toBe(201);
    const { token: linkToken } = (await r.json()) as { token: string };
    expect(env.store.getOnboardingLink(linkToken)?.mintedBy).toBe("owner");
    expect(await submitWizard(env, linkToken, "k")).toBe(200);
    const rules = env.store.rulesForAgent(env.store.getAgent(agent.id)!);
    expect(rules).toHaveLength(1);
    expect(rules[0]).toMatchObject({ connectionScope: "only", connectionScopeEnforced: true });
  });
});

describe("self-mint limits", () => {
  it(`allows ${SELF_MINT_PER_HOUR} self-mints an hour, then answers 429`, async () => {
    const env = await setup();
    const { agent, token } = env.store.createAgent("minty", { defaultPolicy: "deny-unmatched" });
    for (let i = 0; i < SELF_MINT_PER_HOUR; i++) {
      const r = await selfMint(env, token);
      expect(r.status).toBe(201);
      // Spend each link so the outstanding cap is not what trips.
      expect(env.store.claimOnboardingLink(JSON.parse(r.body).token)).toBe(true);
    }
    const over = await selfMint(env, token);
    expect(over.status).toBe(429);
    expect(JSON.parse(over.body).error).toBe("rate_limited");
    expect(Number(over.headers["retry-after"])).toBeGreaterThan(0);
    expect(env.store.listOnboardingLinks(agent.id)).toHaveLength(SELF_MINT_PER_HOUR);

    // Per agent: another bot is unaffected.
    const other = env.store.createAgent("other", { defaultPolicy: "deny-unmatched" });
    expect((await selfMint(env, other.token)).status).toBe(201);
  });

  it(`caps outstanding unused self-minted links at ${SELF_MINT_MAX_OUTSTANDING}`, async () => {
    const env = await setup();
    const { agent, token } = env.store.createAgent("hoarder", { defaultPolicy: "deny-unmatched" });
    // Owner-minted links never count toward the agent's cap.
    env.store.createOnboardingLink({ agentId: agent.id, integrationId: "vendor", mintedBy: "owner" });
    const tokens: string[] = [];
    for (let i = 0; i < SELF_MINT_MAX_OUTSTANDING; i++) {
      const r = await selfMint(env, token);
      expect(r.status).toBe(201);
      tokens.push(JSON.parse(r.body).token);
    }
    const over = await selfMint(env, token);
    expect(over.status).toBe(429);
    expect(JSON.parse(over.body).error).toBe("too_many_outstanding_links");
    expect(env.store.countOutstandingSelfMintedLinks(agent.id)).toBe(SELF_MINT_MAX_OUTSTANDING);
    // Using one frees a slot.
    expect(await submitWizard(env, tokens[0], "k")).toBe(200);
    expect((await selfMint(env, token)).status).toBe(201);
  });
});

describe("token endpoint errors", () => {
  it("onegate_inject_failed carries no vendor body", async () => {
    const tokenSrv = http.createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_grant", error_description: VENDOR_SECRET_BODY }));
      });
    });
    await new Promise<void>((r) => tokenSrv.listen(0, "127.0.0.1", r));
    try {
      const url = `http://127.0.0.1:${(tokenSrv.address() as { port: number }).port}/token`;
      const env = await setup({ tokenEndpoint: url });
      const { agent, token } = env.store.createAgent("oauthy", { defaultPolicy: "deny-unmatched" });
      env.store.createRule({
        scope: "agent",
        subjectId: agent.id,
        integrationId: "oauthv",
        methods: ["*"],
        pathGlob: "/**",
        effect: "allow",
      });
      env.store.setCredential("oauthv", "OAuth", {
        clientId: "cid-123",
        clientSecret: "cs",
        refreshToken: "rt",
      });
      const r = await viaProxy(env, token, { host: OAUTH_HOST, method: "GET", path: "/v1/me" });
      expect(r.status).toBe(502);
      const body = JSON.parse(r.body);
      expect(body.error).toBe("onegate_inject_failed");
      expect(body.message).toMatch(/\(400\): invalid_grant/);
      expect(r.body).not.toContain("VENDOR-INTERNAL-DETAIL");
      expect(r.body).not.toContain("cid-123");
    } finally {
      await new Promise<void>((r) => tokenSrv.close(() => r()));
    }
  });

  it("non-JSON token endpoint bodies are not echoed either", async () => {
    const tokenSrv = http.createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        res.writeHead(200, { "content-type": "text/html" });
        res.end(`<html>${VENDOR_SECRET_BODY}</html>`);
      });
    });
    await new Promise<void>((r) => tokenSrv.listen(0, "127.0.0.1", r));
    try {
      const url = `http://127.0.0.1:${(tokenSrv.address() as { port: number }).port}/token`;
      const store = new Store(":memory:");
      const cred = store.setCredential("oauthv", "OAuth", { clientId: "c", clientSecret: "s", refreshToken: "rt" });
      const err = (await oauthBearerToken(
        { id: "oauthv", oauth: { authUrl: "https://a.invalid", tokenUrl: url, defaultScopes: [] } },
        cred,
        store,
      ).catch((e: unknown) => e)) as Error & { detail: string };
      expect(err.message).toMatch(/non-JSON response \(200\)/);
      expect(err.message).not.toContain("VENDOR-INTERNAL-DETAIL");
      expect(err.detail).toContain("VENDOR-INTERNAL-DETAIL");
    } finally {
      await new Promise<void>((r) => tokenSrv.close(() => r()));
    }
  });

  it("GCP token exchange failures keep the vendor body off the message", async () => {
    const tokenSrv = http.createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        res.writeHead(403, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "access_denied", error_description: VENDOR_SECRET_BODY }));
      });
    });
    await new Promise<void>((r) => tokenSrv.listen(0, "127.0.0.1", r));
    const saved = process.env.ONEGATE_GCP_TOKEN_URL;
    try {
      process.env.ONEGATE_GCP_TOKEN_URL = `http://127.0.0.1:${(tokenSrv.address() as { port: number }).port}/token`;
      const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const store = new Store(":memory:");
      const cred = store.setCredential("gcp", "SA", {
        serviceAccountJson: JSON.stringify({
          client_email: "sa@proj.iam.gserviceaccount.com",
          private_key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
        }),
      });
      const err = (await gcpAccessToken(cred, store).catch((e: unknown) => e)) as Error & { detail: string };
      expect(err.message).toBe("GCP token exchange failed (403)");
      expect(err.detail).toContain("VENDOR-INTERNAL-DETAIL");
    } finally {
      if (saved === undefined) delete process.env.ONEGATE_GCP_TOKEN_URL;
      else process.env.ONEGATE_GCP_TOKEN_URL = saved;
      await new Promise<void>((r) => tokenSrv.close(() => r()));
    }
  });
});
