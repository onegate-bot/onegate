/**
 * Inner-request paths of the TLS-terminating proxy that the broader e2e suites
 * do not reach: injection and upstream failures, response header hygiene, the
 * self-mint connect-link edge cases, owner-notify delivery outcomes, lapsed
 * access leases, approval-hold notification and fail-closed error handling,
 * and credential pinning for self-managed instance origins.
 */

import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from "vitest";
import net from "node:net";
import { startHarness, viaProxy, waitFor, type Harness } from "./proxy-harness.js";
import { DISCOVERY_HOST } from "../src/discovery.js";
import type { Connection } from "../src/types.js";

const VENDOR_HOST = "api.req-vendor.test";
const BARE_HOST = "api.bare-vendor.test";
const SAAS_HOST = "api.selfhost-saas.test";
const SELF_HOST = "git.acme.test";
const OTHER_SELF_HOST = "git.other.test";
const BASE = "https://gate.example.test/og";

let h: Harness;
let notifyImpl: (url: string, init: RequestInit) => Promise<Response>;
const notifyCalls: Array<{ url: string; body: any }> = [];

let mainToken: string;
let mainId: string;
let saasConn: Connection;
let selfConn: Connection;
let otherSelfConn: Connection;

const okNotify = async () => ({ ok: true, status: 200 }) as Response;

beforeAll(async () => {
  notifyImpl = okNotify;
  h = await startHarness({
    setup(registry, store) {
      registry.register({
        id: "reqvendor",
        title: "Req Vendor",
        hosts: [VENDOR_HOST],
        credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
        inject(ctx) {
          if (ctx.path.startsWith("/v1/inject-fail")) throw new Error("credential is malformed");
          ctx.headers.authorization = `Bearer ${ctx.credential.data.apiKey}`;
        },
      });
      // No connect flow at all (connectFlowKind null): no links, no notify.
      registry.register({
        id: "barevendor",
        title: "Bare Vendor",
        hosts: [BARE_HOST],
        credentialFields: [],
        inject() {},
      });
      // A SaaS integration that also ships self-managed (GitLab-shaped).
      registry.register({
        id: "selfhost",
        title: "Self Host",
        hosts: [SAAS_HOST],
        supportsInstanceOrigin: true,
        credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
        inject(ctx) {
          ctx.headers.authorization = `Bearer ${ctx.credential.data.apiKey}`;
        },
      });

      store.setCredential("reqvendor", "main", { apiKey: "vendor-secret" });
      store.setCredential("barevendor", "main", { apiKey: "unused" });

      const main = store.createAgent("main-agent", { defaultPolicy: "deny-unmatched" });
      mainToken = main.token;
      mainId = main.agent.id;
      for (const integrationId of ["reqvendor", "selfhost"]) {
        store.createRule({
          scope: "agent",
          subjectId: mainId,
          integrationId,
          methods: ["*"],
          pathGlob: "/**",
          effect: "allow",
        });
      }

      saasConn = store.createConnection({
        kind: "app",
        vendor: "selfhost",
        name: "saas",
        data: { apiKey: "saas-key" },
        isDefault: true,
      });
      selfConn = store.createConnection({
        kind: "app",
        vendor: "selfhost",
        name: "acme-self",
        data: { apiKey: "acme-self-key" },
        instanceOrigin: `https://${SELF_HOST}`,
      });
      otherSelfConn = store.createConnection({
        kind: "app",
        vendor: "selfhost",
        name: "other-self",
        data: { apiKey: "other-self-key" },
        instanceOrigin: `https://${OTHER_SELF_HOST}`,
      });
      store.grantConnection(saasConn.id, "agent", mainId);
      store.grantConnection(selfConn.id, "agent", mainId);
      // otherSelfConn is deliberately NOT granted to main-agent.
    },
    proxy: () => ({
      publicBaseUrl: BASE,
      notifyFetch: (async (url: string, init: RequestInit) => {
        notifyCalls.push({ url, body: JSON.parse(String(init.body)) });
        return notifyImpl(url, init);
      }) as unknown as typeof fetch,
    }),
  });
});

afterAll(async () => {
  await h.close();
});

afterEach(() => {
  vi.restoreAllMocks();
  h.resetStub();
  notifyImpl = okNotify;
  notifyCalls.length = 0;
});

function proxyOpts(): { upstreamLookup?: (host: string, port: number) => { host: string; port: number } } {
  return (h.proxy as unknown as { opts: ReturnType<typeof proxyOpts> }).opts;
}

/** A fresh deny-unmatched agent, optionally with an owner webhook. */
function newAgent(name: string, webhook?: string): { token: string; id: string } {
  const a = h.store.createAgent(name, { defaultPolicy: "deny-unmatched" });
  if (webhook) h.store.setAgentNotify(a.agent.id, webhook);
  return { token: a.token, id: a.agent.id };
}

function allow(agentId: string, integrationId: string, extra: Record<string, unknown> = {}) {
  return h.store.createRule({
    scope: "agent",
    subjectId: agentId,
    integrationId,
    methods: ["*"],
    pathGlob: "/**",
    effect: "allow",
    ...extra,
  });
}

function notificationsFor(agentId: string) {
  return h.store.listOwnerNotifications({ limit: 1000 }).filter((n) => n.agentId === agentId);
}

describe("upstream and injection failures on the integration path", () => {
  it("answers 502 onegate_inject_failed when the integration cannot inject, without calling the vendor", async () => {
    const r = await viaProxy(h, { host: VENDOR_HOST, token: mainToken, path: "/v1/inject-fail" });
    expect(r.status).toBe(502);
    expect(r.json).toEqual({ error: "onegate_inject_failed", message: "credential is malformed" });
    expect(h.seen).toHaveLength(0);
    expect(h.logs.some((l) => l.includes("inject failed for reqvendor"))).toBe(true);
  });

  it("answers 502 onegate_upstream_error when the vendor cannot be reached", async () => {
    const closed = net.createServer();
    await new Promise<void>((r) => closed.listen(0, "127.0.0.1", r));
    const deadPort = (closed.address() as net.AddressInfo).port;
    await new Promise<void>((r) => closed.close(() => r()));
    const opts = proxyOpts();
    const original = opts.upstreamLookup;
    opts.upstreamLookup = () => ({ host: "127.0.0.1", port: deadPort });
    try {
      const r = await viaProxy(h, { host: VENDOR_HOST, token: mainToken, path: "/v1/unreachable" });
      expect(r.status).toBe(502);
      expect(r.json.error).toBe("onegate_upstream_error");
      expect(r.json.message).toMatch(/ECONNREFUSED/);
    } finally {
      opts.upstreamLookup = original;
    }
  });

  it("tears the agent's response down when the vendor dies mid-body, and keeps serving", async () => {
    h.handler = (_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.write("partial-");
      setTimeout(() => res.socket?.destroy(), 20);
    };
    const outcome = await viaProxy(h, { host: VENDOR_HOST, token: mainToken, path: "/v1/midbody" }).then(
      (r) => `ended:${r.body}`,
      (err: Error) => `error:${err.message}`,
    );
    // Never a clean, silently short 200: the agent sees the stream abort.
    expect(outcome.startsWith("error:")).toBe(true);
    await waitFor(() => h.logs.some((l) => l.includes(`upstream response stream error for ${VENDOR_HOST}`)));

    h.resetStub();
    const next = await viaProxy(h, { host: VENDOR_HOST, token: mainToken, path: "/v1/after" });
    expect(next.status).toBe(200);
  });
});

describe("header hygiene", () => {
  it("relays end-to-end response headers but drops hop-by-hop ones", async () => {
    h.handler = (_req, res) => {
      res.writeHead(200, {
        "content-type": "application/json",
        "x-vendor-trace": "trace-123",
        "proxy-authenticate": 'Basic realm="vendor"',
        trailer: "x-checksum",
      });
      res.end("{}");
    };
    const r = await viaProxy(h, { host: VENDOR_HOST, token: mainToken, path: "/v1/headers" });
    expect(r.status).toBe(200);
    expect(r.headers["x-vendor-trace"]).toBe("trace-123");
    expect(r.headers["proxy-authenticate"]).toBeUndefined();
    expect(r.headers.trailer).toBeUndefined();
  });

  it("never forwards the agent's own authorization or in-tunnel proxy credentials upstream", async () => {
    const r = await viaProxy(h, {
      host: VENDOR_HOST,
      token: mainToken,
      path: "/v1/strip",
      headers: {
        authorization: `Bearer ${mainToken}`,
        "proxy-authorization": `Bearer ${mainToken}`,
        "x-keep-me": "yes",
      },
    });
    expect(r.status).toBe(200);
    const seen = h.seen[0].headers;
    expect(seen.authorization).toBe("Bearer vendor-secret");
    expect(seen["proxy-authorization"]).toBeUndefined();
    expect(seen["x-keep-me"]).toBe("yes");
    expect(JSON.stringify(seen)).not.toContain(mainToken);
  });
});

describe("self-mint connect links on the discovery host: edge cases", () => {
  function post(token: string, body: string | Buffer) {
    return viaProxy(h, {
      host: DISCOVERY_HOST,
      token,
      method: "POST",
      path: "/connect-links",
      body,
      headers: { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
    });
  }

  it("rejects a body that is not JSON (400 invalid_json) and mints nothing", async () => {
    const a = newAgent("selfmint-badjson");
    const r = await post(a.token, "{not json");
    expect(r.status).toBe(400);
    expect(r.json).toEqual({ error: "invalid_json" });
    expect(h.store.listOnboardingLinks(a.id)).toHaveLength(0);
  });

  it("treats an empty body as missing integrationId (400)", async () => {
    const a = newAgent("selfmint-empty");
    const r = await post(a.token, "");
    expect(r.status).toBe(400);
    expect(r.json).toEqual({ error: "integrationId is required" });
  });

  it("refuses a body over 64 KiB (413) and mints nothing", async () => {
    const a = newAgent("selfmint-huge");
    const huge = JSON.stringify({ integrationId: "reqvendor", pad: "x".repeat(70 * 1024) });
    const outcome = await post(a.token, huge).then(
      (r) => r,
      () => null, // the proxy destroys the request after answering; a reset is acceptable
    );
    if (outcome) {
      expect(outcome.status).toBe(413);
      expect(outcome.json).toEqual({ error: "body_too_large" });
    }
    expect(h.store.listOnboardingLinks(a.id)).toHaveLength(0);
  });

  it("honours scopes, a trimmed connectionName and a positive ttlDays", async () => {
    const a = newAgent("selfmint-opts");
    const before = Date.now();
    const r = await post(
      a.token,
      JSON.stringify({ integrationId: "reqvendor", scopes: ["read", 7], connectionName: "  Work  ", ttlDays: 2 }),
    );
    expect(r.status).toBe(201);
    expect(r.json.url).toBe(`${BASE}/connect/reqvendor/${r.json.token}`);
    const [link] = h.store.listOnboardingLinks(a.id);
    expect(link.agentId).toBe(a.id);
    expect(link.scopes).toEqual(["read", "7"]);
    expect(link.connectionName).toBe("Work");
    const ttlMs = Date.parse(link.expiresAt) - before;
    expect(ttlMs).toBeGreaterThan(2 * 86400_000 - 60_000);
    expect(ttlMs).toBeLessThan(2 * 86400_000 + 60_000);
  });

  it("rejects a non-positive ttlDays with 400 (no silent default)", async () => {
    const a = newAgent("selfmint-bad-ttl");
    const r = await post(a.token, JSON.stringify({ integrationId: "reqvendor", ttlDays: -3 }));
    expect(r.status).toBe(400);
    expect(h.store.listOnboardingLinks(a.id)).toHaveLength(0);
  });

  it("ignores a blank connectionName and defaults an omitted ttlDays to 7 days", async () => {
    const a = newAgent("selfmint-defaults");
    const before = Date.now();
    const r = await post(
      a.token,
      JSON.stringify({ integrationId: "reqvendor", scopes: "read", connectionName: "   " }),
    );
    expect(r.status).toBe(201);
    const [link] = h.store.listOnboardingLinks(a.id);
    expect(link.scopes).toBeNull();
    expect(link.connectionName).toBeNull();
    const ttlMs = Date.parse(link.expiresAt) - before;
    expect(ttlMs).toBeGreaterThan(7 * 86400_000 - 60_000);
  });

  it("serves discovery for GET / even with a query string", async () => {
    const r = await viaProxy(h, { host: DISCOVERY_HOST, token: mainToken, path: "/?verbose=1" });
    expect(r.status).toBe(200);
    expect(r.json.agent).toEqual({ id: mainId, name: "main-agent" });
  });
});

describe("owner-notify delivery outcomes", () => {
  async function denyAndWait(name: string): Promise<{ id: string; reply: Awaited<ReturnType<typeof viaProxy>> }> {
    const a = newAgent(name, "https://hook.test/owner");
    const reply = await viaProxy(h, { host: VENDOR_HOST, token: a.token, path: "/v1/thing" });
    await waitFor(() => notificationsFor(a.id).some((n) => n.status !== "pending"));
    return { id: a.id, reply };
  }

  it("marks the notification failed with the HTTP status when the webhook answers non-2xx", async () => {
    notifyImpl = async () => ({ ok: false, status: 500 }) as Response;
    const { id, reply } = await denyAndWait("notify-500");
    // The agent's answer is unaffected by the webhook outcome.
    expect(reply.status).toBe(403);
    expect(reply.json.error).toBe("onegate_policy_denied");
    const [row] = notificationsFor(id);
    expect(row).toMatchObject({ status: "failed", error: "HTTP 500", attempts: 1 });
    expect(notifyCalls[0].body).toMatchObject({ type: "onegate.owner_notify", reason: "policy_default_deny" });
    expect(h.logs.some((l) => l.includes(`owner-notify failed for agent ${id} / reqvendor: HTTP 500`))).toBe(true);
  });

  it("marks the notification failed with the error message when the webhook POST throws", async () => {
    notifyImpl = async () => {
      throw new Error("connect ECONNREFUSED hook.test");
    };
    const { id } = await denyAndWait("notify-throws");
    const [row] = notificationsFor(id);
    expect(row).toMatchObject({ status: "failed", error: "connect ECONNREFUSED hook.test" });
    expect(h.logs.some((l) => l.includes(`owner-notify error for agent ${id}`))).toBe(true);
  });

  it("stringifies a non-Error rejection from the webhook POST", async () => {
    notifyImpl = () => Promise.reject("socket closed");
    const { id } = await denyAndWait("notify-nonerror");
    expect(notificationsFor(id)[0]).toMatchObject({ status: "failed", error: "socket closed" });
  });
});

describe("lapsed access leases", () => {
  it("answers 403 onegate_lease_expired with a renewal link, and notifies the owner once per lapse", async () => {
    const a = newAgent("lease-agent", "https://hook.test/lease");
    const expiresAt = new Date(Date.now() - 60_000).toISOString();
    const rule = allow(a.id, "reqvendor", { expiresAt, leaseTtlSeconds: 3600 });

    const first = await viaProxy(h, { host: VENDOR_HOST, token: a.token, path: "/v1/leased" });
    expect(first.status).toBe(403);
    expect(first.json.error).toBe("onegate_lease_expired");
    // The agent never receives a redeemable renewal link; only the owner does.
    expect(first.json.connect_url).toBeUndefined();
    expect(JSON.stringify(first.json)).not.toMatch(/\/renew\//);
    expect(h.seen).toHaveLength(0);

    // The renewal link is agent-scoped and bound to the lapsed rule.
    const links = h.store.listOnboardingLinks(a.id);
    expect(links.length).toBeGreaterThanOrEqual(1);
    expect(links.every((l) => l.ruleId === rule.id && l.integrationId === "reqvendor")).toBe(true);

    await waitFor(() => notifyCalls.length === 1);
    expect(notifyCalls[0].body).toMatchObject({ reason: "lease_expired", agentId: a.id });
    expect(notifyCalls[0].body.connectUrl).toMatch(new RegExp(`^${BASE}/renew/`));
    const rows = notificationsFor(a.id);
    expect(rows).toHaveLength(1);
    expect(rows[0].dedupKey).toBe(`lease:${rule.id}:${expiresAt}`);

    // A retry within the same lapse is refused again but does not re-notify.
    const second = await viaProxy(h, { host: VENDOR_HOST, token: a.token, path: "/v1/leased" });
    expect(second.json.error).toBe("onegate_lease_expired");
    expect(notificationsFor(a.id)).toHaveLength(1);

    const audit = h.store.listAudit({ agentId: a.id, limit: 10 });
    expect(audit.every((e) => e.decision === "deny" && e.status === 403)).toBe(true);
  });

  it("offers no renewal link and sends no notification for an integration without a connect flow", async () => {
    const a = newAgent("lease-bare", "https://hook.test/lease-bare");
    allow(a.id, "barevendor", { expiresAt: new Date(Date.now() - 60_000).toISOString() });
    const r = await viaProxy(h, { host: BARE_HOST, token: a.token, path: "/anything" });
    expect(r.status).toBe(403);
    expect(r.json.error).toBe("onegate_lease_expired");
    expect(r.json.connect_url).toBeUndefined();
    expect(h.store.listOnboardingLinks(a.id)).toHaveLength(0);
    expect(notificationsFor(a.id)).toHaveLength(0);
  });
});

describe("approval holds: owner notification and fail-closed errors", () => {
  function heldAgent(name: string, webhook?: string): { token: string; id: string } {
    const a = newAgent(name, webhook);
    allow(a.id, "reqvendor");
    h.store.createRule({
      scope: "agent",
      subjectId: a.id,
      integrationId: "reqvendor",
      methods: ["*"],
      pathGlob: "/v1/held/**",
      effect: "deny",
      action: "require_approval",
    });
    return a;
  }

  it("notifies the owner with the approval link, and a retry reuses the approval without re-notifying", async () => {
    const a = heldAgent("approval-notify", "https://hook.test/approve");
    const first = await viaProxy(h, { host: VENDOR_HOST, token: a.token, method: "POST", path: "/v1/held/x", body: "{}" });
    expect(first.status).toBe(403);
    expect(first.json.error).toBe("onegate_approval_pending");
    // The agent never receives the decision link; only the owner's webhook does.
    expect(first.json.approval_url).toBeUndefined();
    expect(JSON.stringify(first.json)).not.toMatch(/\/approve\//);

    await waitFor(() => notificationsFor(a.id).some((n) => n.status === "delivered"));
    const rows = notificationsFor(a.id);
    expect(rows).toHaveLength(1);
    expect(rows[0].dedupKey).toBe(`approval:${first.json.approval_id}`);
    expect(rows[0].connectToken).toBeNull();
    expect(notifyCalls[0].body).toMatchObject({
      reason: "approval_required",
      connectUrl: expect.stringMatching(new RegExp(`^${BASE}/approve/`)),
      connectExpiresAt: first.json.approval_expires_at,
    });

    const retry = await viaProxy(h, { host: VENDOR_HOST, token: a.token, method: "POST", path: "/v1/held/x", body: "{}" });
    expect(retry.json.error).toBe("onegate_approval_pending");
    expect(retry.json.approval_id).toBe(first.json.approval_id);
    expect(retry.json.approval_url).toBeUndefined();
    expect(retry.json.hint).toMatch(/owner has been notified/);
    expect(notificationsFor(a.id)).toHaveLength(1);
    expect(h.seen).toHaveLength(0);
  });

  it("degrades to a plain refusal (never a forward) when the approval cannot be recorded", async () => {
    const a = heldAgent("approval-broken");
    vi.spyOn(h.store, "createApproval").mockImplementation(() => {
      throw new Error("database is locked");
    });
    const r = await viaProxy(h, { host: VENDOR_HOST, token: a.token, path: "/v1/held/y" });
    expect(r.status).toBe(403);
    expect(r.json.error).toBe("onegate_approval_pending");
    expect(r.json.message).toContain("approval could not be recorded, treat as denied");
    expect(r.json.approval_id).toBeUndefined();
    expect(h.seen).toHaveLength(0);
  });

  it("keeps the call held when redeeming an approved approval throws, and lets it through once it works", async () => {
    const a = heldAgent("approval-redeem-err");
    const held = await viaProxy(h, { host: VENDOR_HOST, token: a.token, path: "/v1/held/z" });
    expect(held.json.error).toBe("onegate_approval_pending");
    expect(h.store.decideApproval(held.json.approval_id, "approved")).not.toBeNull();

    const redeem = vi.spyOn(h.store, "redeemApproval").mockImplementation(() => {
      throw new Error("disk I/O error");
    });
    const blocked = await viaProxy(h, { host: VENDOR_HOST, token: a.token, path: "/v1/held/z" });
    expect(blocked.status).toBe(403);
    expect(blocked.json.error).toBe("onegate_approval_pending");
    expect(h.seen).toHaveLength(0);
    expect(h.logs.some((l) => l.includes("approval redemption failed for approval-redeem-err: disk I/O error"))).toBe(true);

    redeem.mockRestore();
    const ok = await viaProxy(h, { host: VENDOR_HOST, token: a.token, path: "/v1/held/z" });
    expect(ok.status).toBe(200);
    expect(h.seen.map((s) => s.path)).toEqual(["/v1/held/z"]);
    const allowRow = h.store.listAudit({ agentId: a.id, limit: 10 }).find((e) => e.decision === "allow");
    expect(allowRow?.approvalId).toBe(held.json.approval_id);
  });
});

describe("self-managed instance origins pin the credential to the claiming connection", () => {
  it("injects the claiming connection on its own host, even over the tenant default", async () => {
    const r = await viaProxy(h, { host: SELF_HOST, token: mainToken, path: "/api/v4/projects" });
    expect(r.status).toBe(200);
    expect(h.seen[0].headers.authorization).toBe("Bearer acme-self-key");
    expect(h.seen[0].headers.host).toBe(SELF_HOST);
    const entry = h.store.listAudit({ agentId: mainId, limit: 5 })[0];
    expect(entry).toMatchObject({ decision: "allow", host: SELF_HOST, connectionId: selfConn.id });
  });

  it("ignores an x-onegate-connection header that names a different connection", async () => {
    const r = await viaProxy(h, {
      host: SELF_HOST,
      token: mainToken,
      path: "/api/v4/user",
      headers: { "x-onegate-connection": "saas" },
    });
    expect(r.status).toBe(200);
    expect(h.seen[0].headers.authorization).toBe("Bearer acme-self-key");
    expect(h.seen[0].headers["x-onegate-connection"]).toBeUndefined();
  });

  it("uses normal resolution (the SaaS default) on the integration's own SaaS host", async () => {
    const r = await viaProxy(h, { host: SAAS_HOST, token: mainToken, path: "/api/v4/user" });
    expect(r.status).toBe(200);
    expect(h.seen[0].headers.authorization).toBe("Bearer saas-key");
  });

  it("refuses an instance host whose claiming connection is not granted, without substituting another credential", async () => {
    const r = await viaProxy(h, { host: OTHER_SELF_HOST, token: mainToken, path: "/api/v4/user" });
    expect(r.status).toBe(403);
    expect(r.json.error).toBe("onegate_connection_not_granted");
    expect(r.json.message).toContain(otherSelfConn.id);
    expect(h.seen).toHaveLength(0);
    const entry = h.store.listAudit({ agentId: mainId, limit: 5 })[0];
    expect(entry).toMatchObject({ decision: "connection_not_granted", host: OTHER_SELF_HOST, status: 403 });
  });
});

describe("connection-scoped ALLOW on a deny-by-default agent: resolution failures fail closed", () => {
  afterEach(() => {
    delete process.env.ONEGATE_CONNECTION_SCOPED_RULES;
  });

  it("denies (never forwards) when the deferred connection resolution names an unknown connection", async () => {
    process.env.ONEGATE_CONNECTION_SCOPED_RULES = "1";
    const a = newAgent("scoped-unknown");
    h.store.grantConnection(saasConn.id, "agent", a.id);
    // The ONLY rule: allow, but only via the saas connection. Phase 1 cannot
    // decide without the connection, so it defers to resolution.
    allow(a.id, "selfhost", { connectionScope: "only", connectionId: saasConn.id });

    const bad = await viaProxy(h, {
      host: SAAS_HOST,
      token: a.token,
      path: "/api/v4/user",
      headers: { "x-onegate-connection": "no-such-connection" },
    });
    expect(bad.status).toBe(400);
    expect(bad.json.error).toBe("onegate_unknown_connection");
    expect(h.seen).toHaveLength(0);
    // Exactly one audit row for the refusal (resolution ran once, not twice).
    const rows = h.store.listAudit({ agentId: a.id, limit: 10 });
    expect(rows.map((r) => r.decision)).toEqual(["unknown_connection"]);

    // Control: the scoped connection itself is let through by phase 2.
    const ok = await viaProxy(h, { host: SAAS_HOST, token: a.token, path: "/api/v4/user" });
    expect(ok.status).toBe(200);
    expect(h.seen[0].headers.authorization).toBe("Bearer saas-key");
  });
});
