/**
 * An agent must never be able to approve its own held call or renew its own
 * lapsed lease.
 *
 *   agent --CONNECT--> GatewayProxy --(403 hold | lease expired)--> agent
 *                          `--notify webhook (link)--> owner --POST /approve|/renew--> admin app
 *
 * Default mode: the agent's 403 carries no redeemable token at all. The link
 * goes to the owner's notify webhook only, and the agent polls a token-free
 * status endpoint on onegate.internal.
 *
 * Relay mode (ONEGATE_AGENT_RELAYS_OWNER_LINKS): the link IS in the agent's
 * 403, so every decision on it requires the owner PIN (or the admin token) and
 * a link locks after 5 wrong answers.
 *
 * Also: an approval is bound to the upstream host it was held for.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { DatabaseSync } from "node:sqlite";
import { initCa } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { Registry } from "../src/integrations/types.js";
import { GatewayProxy } from "../src/proxy/server.js";
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";
import {
  AGENT_RELAYS_OWNER_LINKS_ENV,
  OWNER_LINK_MAX_PIN_FAILURES,
  OWNER_PIN_SETTING,
  agentRelaysOwnerLinksFromEnv,
  agentRelaysOwnerLinksWarning,
  hashOwnerPin,
  ownerPinProblem,
  verifyOwnerPin,
} from "../src/util/owner-links.js";

const HOST_A = "api.gated-vendor.com";
const HOST_B = "uploads.gated-vendor.com";
const LEASE_HOST = "api.leased-vendor.com";
const PIN = "4821";

let dir: string;
let store: Store;
let proxy: GatewayProxy; // default mode
let relayProxy: GatewayProxy; // ONEGATE_AGENT_RELAYS_OWNER_LINKS
let proxyPort: number;
let relayPort: number;
let admin: http.Server;
let relayAdmin: http.Server;
let adminPort: number;
let relayAdminPort: number;
let adminToken: string;
let stub: https.Server;
let caPem: string;
let agentToken: string;
let agentId: string;
let otherToken: string;

/** Every request the stub vendor received. */
let seen: Array<{ host?: string; method?: string; path?: string; auth?: string; body: string }> = [];
/** Every owner-notify webhook payload. */
let notified: Array<Record<string, unknown>> = [];

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-self-redeem-"));
  const ca = initCa(dir);
  caPem = ca.rootPem;
  store = new Store(":memory:");

  const def = ca.leafFor(HOST_A);
  stub = https.createServer(
    {
      key: def.key,
      cert: def.cert,
      SNICallback: (name, cb) => {
        const leaf = ca.leafFor(name);
        cb(null, tls.createSecureContext({ key: leaf.key, cert: leaf.cert }));
      },
    },
    (req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        seen.push({ host: req.headers.host, method: req.method, path: req.url, auth: req.headers.authorization, body });
        res.writeHead(201, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      });
    },
  );
  await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
  const stubPort = (stub.address() as { port: number }).port;

  const registry = new Registry();
  for (const [id, hosts] of [
    ["gated", [HOST_A, HOST_B]],
    ["leased", [LEASE_HOST]],
  ] as const) {
    registry.register({
      id,
      title: id,
      hosts: [...hosts],
      credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
      inject(ctx) {
        ctx.headers.authorization = `Bearer ${ctx.credential.data.apiKey}`;
      },
    });
  }
  store.setCredential("gated", "main", { apiKey: "real-gated-key" });
  store.setCredential("leased", "main", { apiKey: "real-leased-key" });

  const created = store.createAgent("self-redeem-bot", { defaultPolicy: "deny-unmatched" });
  agentToken = created.token;
  agentId = created.agent.id;
  otherToken = store.createAgent("other-bot", { defaultPolicy: "deny-unmatched" }).token;
  store.setAgentNotify(agentId, "https://owner-hook.example.test/notify");
  store.createRule({ scope: "agent", subjectId: agentId, integrationId: "gated", methods: ["*"], pathGlob: "/**", effect: "allow" });
  store.createRule({
    scope: "agent",
    subjectId: agentId,
    integrationId: "gated",
    methods: ["*"],
    pathGlob: "/pay/**",
    effect: "deny",
    action: "require_approval",
  });

  const notifyFetch = (async (_url: string, init: { body: string }) => {
    notified.push(JSON.parse(init.body));
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;
  const common = {
    ca,
    store,
    registry,
    upstreamTls: { ca: caPem },
    upstreamLookup: () => ({ host: "127.0.0.1", port: stubPort }),
    publicBaseUrl: "https://gate.example.test",
    notifyFetch,
  };
  proxy = new GatewayProxy({ ...common, agentRelaysOwnerLinks: false });
  proxyPort = await proxy.listen(0, "127.0.0.1");
  relayProxy = new GatewayProxy({ ...common, agentRelaysOwnerLinks: true });
  relayPort = await relayProxy.listen(0, "127.0.0.1");

  adminToken = ensureAdminToken(store)!;
  admin = http.createServer(createAdminApp({ store, registry, ca, version: "test", agentRelaysOwnerLinks: false }));
  await new Promise<void>((r) => admin.listen(0, "127.0.0.1", r));
  adminPort = (admin.address() as { port: number }).port;
  relayAdmin = http.createServer(createAdminApp({ store, registry, ca, version: "test", agentRelaysOwnerLinks: true }));
  await new Promise<void>((r) => relayAdmin.listen(0, "127.0.0.1", r));
  relayAdminPort = (relayAdmin.address() as { port: number }).port;
});

afterAll(async () => {
  await proxy.close();
  await relayProxy.close();
  admin.close();
  relayAdmin.close();
  stub.close();
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  seen = [];
  notified = [];
});

interface Reply {
  status: number;
  raw: string;
  json: any;
}

/** One request through a proxy over a fresh CONNECT tunnel. */
function viaProxy(
  opts: { port?: number; token?: string; host?: string },
  method: string,
  path: string,
  body?: string,
): Promise<Reply> {
  const host = opts.host ?? HOST_A;
  return new Promise((resolve, reject) => {
    const connectReq = http.request({
      host: "127.0.0.1",
      port: opts.port ?? proxyPort,
      method: "CONNECT",
      path: `${host}:443`,
      headers: {
        "proxy-authorization": "Basic " + Buffer.from(`agent:${opts.token ?? agentToken}`).toString("base64"),
      },
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
            method,
            path,
            headers: body !== undefined ? { "content-type": "application/json" } : {},
          },
          (res) => {
            let raw = "";
            res.on("data", (c) => (raw += c));
            res.on("end", () => {
              tlsSocket.end();
              let json: any = null;
              try {
                json = JSON.parse(raw);
              } catch {
                json = raw;
              }
              resolve({ status: res.statusCode ?? 0, raw, json });
            });
          },
        );
        req.on("error", reject);
        if (body !== undefined) req.write(body);
        req.end();
      });
      tlsSocket.on("error", reject);
    });
    connectReq.on("error", reject);
    connectReq.end();
  });
}

/** POSTs a form to the admin listener's public pages. */
async function postForm(port: number, path: string, form: Record<string, string>): Promise<{ status: number; text: string }> {
  const r = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString(),
  });
  return { status: r.status, text: await r.text() };
}

/** Path of an owner link (`/approve/<token>` or `/renew/<token>`). */
const linkPath = (url: string): string => new URL(url).pathname;

/** The owner link the webhook was sent for an approval. */
function ownerApprovalLink(approvalId: string): string {
  const n = notified.find((p) => p.approvalId === approvalId);
  if (!n) throw new Error(`no owner notification for ${approvalId}`);
  return String(n.connectUrl);
}

/** Every 64-hex or 48-hex token the agent was handed anywhere in a body. */
function tokensIn(raw: string): string[] {
  return raw.match(/[0-9a-f]{32,}/g) ?? [];
}

/** Makes a fresh lapsed lease for the agent on `leased`, replacing earlier ones. */
let leaseRuleIds: string[] = [];
function lapsedLease() {
  for (const id of leaseRuleIds) store.deleteRule(id);
  const rule = store.createRule({
    scope: "agent",
    subjectId: agentId,
    integrationId: "leased",
    methods: ["*"],
    pathGlob: "/**",
    effect: "allow",
    expiresAt: new Date(Date.now() - 60_000 - Math.floor(Math.random() * 1e6)).toISOString(),
    leaseTtlSeconds: 3600,
  });
  leaseRuleIds = [rule.id];
  return rule;
}

describe("default mode: the agent never holds a redeemable link", () => {
  it("the approval-pending 403 has no /approve/ token, only an id and a status URL", async () => {
    const held = await viaProxy({}, "POST", "/pay/now", '{"a":100}');
    expect(held.status).toBe(403);
    expect(held.json.error).toBe("onegate_approval_pending");
    expect(held.raw).not.toMatch(/\/approve\//);
    expect(held.raw).not.toMatch(/\/renew\//);
    expect(held.json.approval_url).toBeUndefined();
    expect(held.json.approval_id).toMatch(/^apr_/);
    expect(held.json.approval_expires_at).toBeTruthy();
    expect(held.json.approval_status_url).toBe(`https://onegate.internal/approvals/${held.json.approval_id}`);
    expect(held.json.hint).toMatch(/owner has been notified/);
    expect(tokensIn(held.raw)).toEqual([]);
  });

  it("the agent cannot redeem anything it was given; the owner's webhook link still works end to end", async () => {
    const body = '{"a":250}';
    const held = await viaProxy({}, "POST", "/pay/now", body);
    const id = held.json.approval_id as string;

    // The reviewer's repro: everything the agent holds, tried as a token.
    for (const candidate of [id, ...tokensIn(held.raw), held.json.approval_expires_at]) {
      const r = await postForm(adminPort, `/approve/${encodeURIComponent(candidate)}`, { decision: "approve" });
      expect(r.status).toBe(410);
    }
    expect(store.getApproval(id)?.status).toBe("pending");
    const retry = await viaProxy({}, "POST", "/pay/now", body);
    expect(retry.status).toBe(403);
    expect(seen).toHaveLength(0);

    // The owner got the link on their webhook, with the approval id.
    const link = ownerApprovalLink(id);
    expect(link).toMatch(/^https:\/\/gate\.example\.test\/approve\/[0-9a-f]{48}$/);
    const n = notified.find((p) => p.approvalId === id)!;
    expect(n.reason).toBe("approval_required");

    // Default mode asks for no PIN: the owner approves with one tap.
    const page = await fetch(`http://127.0.0.1:${adminPort}${linkPath(link)}`);
    const html = await page.text();
    expect(html).not.toContain('name="pin"');
    expect(html).toContain(`${HOST_A}/pay/now`);
    expect((await postForm(adminPort, linkPath(link), { decision: "approve" })).status).toBe(200);

    const ok = await viaProxy({}, "POST", "/pay/now", body);
    expect(ok.status).toBe(201);
    expect(seen).toEqual([expect.objectContaining({ host: HOST_A, path: "/pay/now", auth: "Bearer real-gated-key", body })]);
  });

  it("the agent polls a token-free status endpoint scoped to itself", async () => {
    const held = await viaProxy({}, "POST", "/pay/later", "{}");
    const id = held.json.approval_id as string;
    const status = await viaProxy({ host: "onegate.internal" }, "GET", `/approvals/${id}`);
    expect(status.status).toBe(200);
    expect(status.json).toMatchObject({ id, status: "pending", used: false, host: HOST_A, method: "POST", path: "/pay/later" });
    expect(tokensIn(status.raw)).toEqual([]);

    // Another agent cannot read it, and the endpoint is read-only.
    expect((await viaProxy({ host: "onegate.internal", token: otherToken }, "GET", `/approvals/${id}`)).status).toBe(404);
    expect((await viaProxy({ host: "onegate.internal" }, "POST", `/approvals/${id}`, "{}")).status).toBe(405);
    expect((await viaProxy({ host: "onegate.internal" }, "GET", "/approvals/apr_missing")).status).toBe(404);

    // The owner decides; the poll reflects it, and then the spend.
    const r = await fetch(`http://127.0.0.1:${adminPort}/api/approvals/${id}/approve`, {
      method: "POST",
      headers: { authorization: `Bearer ${adminToken}` },
    });
    expect(r.status).toBe(200);
    expect((await viaProxy({ host: "onegate.internal" }, "GET", `/approvals/${id}`)).json.status).toBe("approved");
    expect((await viaProxy({}, "POST", "/pay/later", "{}")).status).toBe(201);
    expect((await viaProxy({ host: "onegate.internal" }, "GET", `/approvals/${id}`)).json.used).toBe(true);

    // A pending row past expiry reads as expired even before the sweep.
    const late = await viaProxy({}, "POST", "/pay/expired", "{}");
    const raw = (store as unknown as { db: DatabaseSync }).db;
    raw.prepare("UPDATE approvals SET expires_at = ? WHERE id = ?").run(new Date(Date.now() - 1000).toISOString(), late.json.approval_id);
    expect((await viaProxy({ host: "onegate.internal" }, "GET", `/approvals/${late.json.approval_id}`)).json.status).toBe("expired");
  });

  it("the lease-expired 403 has no renewal link; the owner's webhook renewal works", async () => {
    const rule = lapsedLease();
    const denied = await viaProxy({ host: LEASE_HOST }, "GET", "/servers");
    expect(denied.status).toBe(403);
    expect(denied.json.error).toBe("onegate_lease_expired");
    expect(denied.raw).not.toMatch(/\/renew\//);
    expect(denied.json.connect_url).toBeUndefined();
    expect(denied.json.rule_id).toBe(rule.id);
    expect(denied.json.hint).toMatch(/renewal link/);
    expect(tokensIn(denied.raw)).toEqual([]);

    const n = notified.find((p) => p.reason === "lease_expired")!;
    expect(String(n.connectUrl)).toMatch(/^https:\/\/gate\.example\.test\/renew\/[0-9a-f]+$/);
    expect((await postForm(adminPort, linkPath(String(n.connectUrl)), {})).status).toBe(200);
    const ok = await viaProxy({ host: LEASE_HOST }, "GET", "/servers");
    expect(ok.status).toBe(201);
    expect(seen.at(-1)).toMatchObject({ host: LEASE_HOST, auth: "Bearer real-leased-key" });
  });
});

describe("relay mode (ONEGATE_AGENT_RELAYS_OWNER_LINKS): links need the owner PIN", () => {
  beforeAll(async () => {
    const r = await fetch(`http://127.0.0.1:${adminPort}/api/settings/owner-pin`, {
      method: "PUT",
      headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
      body: JSON.stringify({ pin: PIN }),
    });
    expect(r.status).toBe(200);
  });

  it("the agent gets the link, but cannot approve without the PIN", async () => {
    const body = '{"relay":1}';
    const held = await viaProxy({ port: relayPort }, "POST", "/pay/relay", body);
    expect(held.json.approval_url).toMatch(/^https:\/\/gate\.example\.test\/approve\/[0-9a-f]{48}$/);
    const path = linkPath(held.json.approval_url);

    const page = await (await fetch(`http://127.0.0.1:${relayAdminPort}${path}`)).text();
    expect(page).toContain('name="pin"');
    expect(page).toContain("Your OneGate PIN");

    // No PIN, wrong PIN: refused, nothing decided.
    const none = await postForm(relayAdminPort, path, { decision: "approve" });
    expect(none.status).toBe(403);
    const wrong = await postForm(relayAdminPort, path, { decision: "approve", pin: "0000" });
    expect(wrong.status).toBe(403);
    expect(wrong.text).toContain("3 attempts left");
    expect(store.getApproval(held.json.approval_id)?.status).toBe("pending");
    expect((await viaProxy({ port: relayPort }, "POST", "/pay/relay", body)).status).toBe(403);
    expect(seen).toHaveLength(0);

    // The right PIN works and gives its attempt back.
    expect((await postForm(relayAdminPort, path, { decision: "approve", pin: PIN })).status).toBe(200);
    expect(store.approvalPinFailures(held.json.approval_id)).toBe(2);
    expect((await viaProxy({ port: relayPort }, "POST", "/pay/relay", body)).status).toBe(201);
    expect(seen).toHaveLength(1);
  });

  it(`a link locks after ${OWNER_LINK_MAX_PIN_FAILURES} wrong PINs, even against the right one`, async () => {
    const held = await viaProxy({ port: relayPort }, "POST", "/pay/brute", "{}");
    const path = linkPath(held.json.approval_url);
    for (let i = 0; i < OWNER_LINK_MAX_PIN_FAILURES; i++) {
      const r = await postForm(relayAdminPort, path, { decision: "approve", pin: String(1000 + i) });
      expect(r.status).toBe(403);
    }
    const locked = await postForm(relayAdminPort, path, { decision: "approve", pin: PIN });
    expect(locked.status).toBe(429);
    expect(locked.text).toContain("locked");
    expect(store.getApproval(held.json.approval_id)?.status).toBe("pending");
    expect((await viaProxy({ port: relayPort }, "POST", "/pay/brute", "{}")).status).toBe(403);
    expect(seen).toHaveLength(0);

    // The owner can still decide from the admin API.
    const r = await fetch(`http://127.0.0.1:${relayAdminPort}/api/approvals/${held.json.approval_id}/approve`, {
      method: "POST",
      headers: { authorization: `Bearer ${adminToken}` },
    });
    expect(r.status).toBe(200);
  });

  it("concurrent guesses cannot exceed the limit", async () => {
    const held = await viaProxy({ port: relayPort }, "POST", "/pay/race", "{}");
    const path = linkPath(held.json.approval_url);
    const replies = await Promise.all(
      Array.from({ length: 12 }, (_, i) => postForm(relayAdminPort, path, { decision: "approve", pin: String(2000 + i) })),
    );
    expect(replies.filter((r) => r.status === 403)).toHaveLength(OWNER_LINK_MAX_PIN_FAILURES);
    expect(replies.filter((r) => r.status === 429)).toHaveLength(12 - OWNER_LINK_MAX_PIN_FAILURES);
    expect(store.approvalPinFailures(held.json.approval_id)).toBe(OWNER_LINK_MAX_PIN_FAILURES);
  });

  it("the admin token is accepted as the second factor, and is the only one when no PIN is set", async () => {
    const held = await viaProxy({ port: relayPort }, "POST", "/pay/admin-token", "{}");
    expect((await postForm(relayAdminPort, linkPath(held.json.approval_url), { decision: "reject", pin: adminToken })).status).toBe(200);
    expect(store.getApproval(held.json.approval_id)?.status).toBe("rejected");

    const pinHash = store.getSetting(OWNER_PIN_SETTING)!;
    store.deleteSetting(OWNER_PIN_SETTING);
    try {
      const next = await viaProxy({ port: relayPort }, "POST", "/pay/admin-token-2", "{}");
      const path = linkPath(next.json.approval_url);
      expect(await (await fetch(`http://127.0.0.1:${relayAdminPort}${path}`)).text()).toContain("admin token");
      expect((await postForm(relayAdminPort, path, { decision: "approve", pin: PIN })).status).toBe(403);
      expect((await postForm(relayAdminPort, path, { decision: "approve", pin: adminToken })).status).toBe(200);
    } finally {
      store.setSetting(OWNER_PIN_SETTING, pinHash);
    }
  });

  it("the renewal link in the lease-expired 403 needs the PIN too", async () => {
    lapsedLease();
    const denied = await viaProxy({ port: relayPort, host: LEASE_HOST }, "GET", "/servers");
    expect(denied.json.error).toBe("onegate_lease_expired");
    expect(denied.json.connect_url).toMatch(/^https:\/\/gate\.example\.test\/renew\/[0-9a-f]+$/);
    const path = linkPath(denied.json.connect_url);
    expect(await (await fetch(`http://127.0.0.1:${relayAdminPort}${path}`)).text()).toContain('name="pin"');

    expect((await postForm(relayAdminPort, path, {})).status).toBe(403);
    expect((await postForm(relayAdminPort, path, { pin: "9999" })).status).toBe(403);
    expect((await viaProxy({ port: relayPort, host: LEASE_HOST }, "GET", "/servers")).status).toBe(403);
    expect((await postForm(relayAdminPort, path, { pin: PIN })).status).toBe(200);
    expect((await viaProxy({ port: relayPort, host: LEASE_HOST }, "GET", "/servers")).status).toBe(201);

    // A renewal link locks the same way.
    lapsedLease();
    const again = await viaProxy({ port: relayPort, host: LEASE_HOST }, "GET", "/servers");
    const p2 = linkPath(again.json.connect_url);
    for (let i = 0; i < OWNER_LINK_MAX_PIN_FAILURES; i++) {
      expect((await postForm(relayAdminPort, p2, { pin: "x".repeat(4 + i) })).status).toBe(403);
    }
    const locked = await postForm(relayAdminPort, p2, { pin: PIN });
    expect(locked.status).toBe(429);
  });
});

describe("approvals are bound to the upstream host", () => {
  it("an approval for host A is not spendable on host B of the same integration", async () => {
    const body = '{"host":"bound"}';
    const held = await viaProxy({ host: HOST_A }, "POST", "/pay/host", body);
    const id = held.json.approval_id as string;
    expect(store.getApproval(id)?.host).toBe(HOST_A);
    expect((await postForm(adminPort, linkPath(ownerApprovalLink(id)), { decision: "approve" })).status).toBe(200);

    // Same agent, integration, rule, method, path and body, other host: held
    // under a NEW approval, nothing forwarded, and A's approval is not spent.
    const onB = await viaProxy({ host: HOST_B }, "POST", "/pay/host", body);
    expect(onB.status).toBe(403);
    expect(onB.json.approval_id).not.toBe(id);
    expect(store.getApproval(onB.json.approval_id)?.host).toBe(HOST_B);
    expect(seen).toHaveLength(0);
    expect(store.getApproval(id)?.usedAt).toBeNull();

    const onA = await viaProxy({ host: HOST_A }, "POST", "/pay/host", body);
    expect(onA.status).toBe(201);
    expect(seen.map((s) => s.host)).toEqual([HOST_A]);
  });

  it("a legacy approval with no recorded host never redeems (fail closed)", () => {
    const s = new Store(":memory:");
    const req = { agentId: "ag_1", integrationId: "gated", ruleId: "rl_1", method: "POST", path: "/x", bodyHash: "h" };
    const legacy = s.createApproval(req);
    expect(legacy.host).toBeNull();
    s.decideApproval(legacy.id, "approved");
    expect(s.redeemApproval({ ...req, host: HOST_A })).toBeNull();
    s.close();
  });

  it("migrates an approvals table without host / pin_failures columns", () => {
    const file = join(mkdtempSync(join(tmpdir(), "og-approval-host-")), "onegate.db");
    const legacy = new DatabaseSync(file);
    legacy.exec(`CREATE TABLE approvals (
      id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, integration_id TEXT NOT NULL,
      rule_id TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','expired')),
      created_at TEXT NOT NULL, expires_at TEXT NOT NULL, decided_at TEXT, body_hash TEXT, used_at TEXT)`);
    const future = new Date(Date.now() + 3600_000).toISOString();
    legacy
      .prepare("INSERT INTO approvals VALUES ('apr_old', 'ag_1', 'gated', 'rl_1', 'POST', '/x', 'th', 'approved', ?, ?, ?, 'h', NULL)")
      .run(new Date().toISOString(), future, new Date().toISOString());
    legacy.close();
    const s = new Store(file);
    expect(s.getApproval("apr_old")?.host).toBeNull();
    expect(s.approvalPinFailures("apr_old")).toBe(0);
    expect(
      s.redeemApproval({ agentId: "ag_1", integrationId: "gated", ruleId: "rl_1", host: HOST_A, method: "POST", path: "/x", bodyHash: "h" }),
    ).toBeNull();
    s.close();
    rmSync(join(file, ".."), { recursive: true, force: true });
  });
});

describe("owner PIN admin API", () => {
  const api = (method: string, body?: unknown, token: string | null = adminToken) =>
    fetch(`http://127.0.0.1:${adminPort}/api/settings/owner-pin`, {
      method,
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(body ? { "content-type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });

  it("needs the admin token, validates the PIN, never returns it", async () => {
    expect((await api("GET", undefined, null)).status).toBe(401);
    expect((await api("PUT", { pin: "12" })).status).toBe(400);
    expect((await api("PUT", { pin: 1234 })).status).toBe(400);
    expect((await api("PUT", { pin: "12 34" })).status).toBe(400);
    const set = await api("PUT", { pin: "778899" });
    expect(await set.json()).toEqual({ set: true, required: false });
    const stored = store.getSetting(OWNER_PIN_SETTING)!;
    expect(stored).not.toContain("778899");
    expect(verifyOwnerPin("778899", stored)).toBe(true);
    expect(await (await api("GET")).json()).toEqual({ set: true, required: false });
    expect(await (await api("DELETE")).json()).toEqual({ set: false, required: false });
    expect(store.getSetting(OWNER_PIN_SETTING)).toBeNull();
    store.setSetting(OWNER_PIN_SETTING, hashOwnerPin(PIN));
  });
});

describe("owner-links helpers", () => {
  it("parses the opt-in env var", () => {
    expect(agentRelaysOwnerLinksFromEnv({})).toBe(false);
    for (const v of ["1", "true", "YES", " on "]) {
      expect(agentRelaysOwnerLinksFromEnv({ [AGENT_RELAYS_OWNER_LINKS_ENV]: v })).toBe(true);
    }
    for (const v of ["0", "false", "", "no"]) {
      expect(agentRelaysOwnerLinksFromEnv({ [AGENT_RELAYS_OWNER_LINKS_ENV]: v })).toBe(false);
    }
  });

  it("the proxy and admin app fall back to the environment", async () => {
    const prev = process.env[AGENT_RELAYS_OWNER_LINKS_ENV];
    process.env[AGENT_RELAYS_OWNER_LINKS_ENV] = "1";
    try {
      const p = new GatewayProxy({
        ca: initCa(mkdtempSync(join(tmpdir(), "og-relay-env-"))),
        store,
        registry: new Registry(),
      });
      expect((p as unknown as { agentRelaysOwnerLinks(): boolean }).agentRelaysOwnerLinks()).toBe(true);
      const app = http.createServer(createAdminApp({ store, registry: new Registry(), ca: { rootPem: "x" } as never, version: "t" }));
      await new Promise<void>((r) => app.listen(0, "127.0.0.1", r));
      const r = await fetch(`http://127.0.0.1:${(app.address() as { port: number }).port}/api/settings/owner-pin`, {
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect((await r.json()).required).toBe(true);
      app.close();
    } finally {
      if (prev === undefined) delete process.env[AGENT_RELAYS_OWNER_LINKS_ENV];
      else process.env[AGENT_RELAYS_OWNER_LINKS_ENV] = prev;
    }
  });

  it("hashes PINs with a salt and verifies timing-safe", () => {
    const a = hashOwnerPin("1234");
    const b = hashOwnerPin("1234");
    expect(a).not.toBe(b);
    expect(a).toMatch(/^scrypt\$[0-9a-f]{32}\$[0-9a-f]{64}$/);
    expect(verifyOwnerPin("1234", a)).toBe(true);
    expect(verifyOwnerPin("1235", a)).toBe(false);
    expect(verifyOwnerPin("1234", null)).toBe(false);
    expect(verifyOwnerPin("1234", "plain$aa$bb")).toBe(false);
    expect(verifyOwnerPin("1234", "scrypt$aa$bb")).toBe(false);
    expect(verifyOwnerPin("1234", "scrypt$aa")).toBe(false);
  });

  it("validates PINs and words the startup warning", () => {
    expect(ownerPinProblem("1234")).toBeNull();
    expect(ownerPinProblem("123")).toMatch(/4 to 64/);
    expect(ownerPinProblem("x".repeat(65))).toMatch(/4 to 64/);
    expect(ownerPinProblem(undefined)).toMatch(/string/);
    expect(ownerPinProblem("12\t34")).toMatch(/whitespace/);
    expect(agentRelaysOwnerLinksWarning(true)).toContain(AGENT_RELAYS_OWNER_LINKS_ENV);
    expect(agentRelaysOwnerLinksWarning(false)).toContain("no owner PIN is set");
  });
});
