/**
 * require_approval end to end: a held call, once approved by the owner, goes
 * through the proxy exactly once.
 *
 *   client --CONNECT--> GatewayProxy --(hold 403 | redeem + inject)--> stub vendor
 *   owner  --POST /approve/:token--> admin app
 *
 * The invariants under test: an approval is redeemable only by the identical
 * request (agent, integration, rule, method, path with query, body), only
 * while approved and unexpired, and only once, even under concurrent retries.
 * A rejected or expired approval never lets the call through.
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
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";

const VENDOR_HOST = "api.gated-vendor.com";

let dir: string;
let store: Store;
let proxy: GatewayProxy;
let proxyPort: number;
let admin: http.Server;
let adminPort: number;
let adminToken: string;
let stub: https.Server;
let caPem: string;
let agentToken: string;
let agentId: string;

/** Every request the stub vendor received, in order. */
let seen: Array<{ method?: string; path?: string; auth?: string; body: string }> = [];

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-approval-proxy-"));
  const ca = initCa(dir);
  caPem = ca.rootPem;
  store = new Store(":memory:");

  const stubLeaf = ca.leafFor(VENDOR_HOST);
  stub = https.createServer({ key: stubLeaf.key, cert: stubLeaf.cert }, (req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ method: req.method, path: req.url, auth: req.headers.authorization, body });
      res.writeHead(201, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
  const stubPort = (stub.address() as { port: number }).port;

  const registry = new Registry();
  registry.register({
    id: "gated",
    title: "Gated Vendor",
    hosts: [VENDOR_HOST],
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    inject(ctx) {
      ctx.headers.authorization = `Bearer ${ctx.credential.data.apiKey}`;
    },
  });
  store.setCredential("gated", "main", { apiKey: "real-vendor-key" });

  const created = store.createAgent("gated-bot", { defaultPolicy: "deny-unmatched" });
  agentToken = created.token;
  agentId = created.agent.id;
  store.createRule({
    scope: "agent",
    subjectId: agentId,
    integrationId: "gated",
    methods: ["*"],
    pathGlob: "/**",
    effect: "allow",
  });
  // Any method on an issues collection is held for the owner.
  store.createRule({
    scope: "agent",
    subjectId: agentId,
    integrationId: "gated",
    methods: ["*"],
    pathGlob: "/repos/*/issues",
    effect: "deny",
    action: "require_approval",
  });

  proxy = new GatewayProxy({
    ca,
    store,
    registry,
    upstreamTls: { ca: caPem },
    upstreamLookup: () => ({ host: "127.0.0.1", port: stubPort }),
    // The owner link is built on this base (see public-url.test.ts).
    publicBaseUrl: "https://gate.example.test/og",
  });
  proxyPort = await proxy.listen(0, "127.0.0.1");

  adminToken = ensureAdminToken(store)!;
  admin = http.createServer(createAdminApp({ store, registry, ca, version: "test" }));
  await new Promise<void>((r) => admin.listen(0, "127.0.0.1", r));
  adminPort = (admin.address() as { port: number }).port;
});

afterAll(async () => {
  await proxy.close();
  admin.close();
  stub.close();
  rmSync(dir, { recursive: true, force: true });
});

interface ProxyReply {
  status: number;
  json: any;
}

/** Sends one request through the proxy over a fresh CONNECT tunnel. */
function viaProxy(method: string, path: string, body?: string): Promise<ProxyReply> {
  return new Promise((resolve, reject) => {
    const connectReq = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "CONNECT",
      path: `${VENDOR_HOST}:443`,
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
      const tlsSocket = tls.connect({ socket, servername: VENDOR_HOST, ca: caPem }, () => {
        const req = https.request(
          {
            createConnection: () => tlsSocket,
            host: VENDOR_HOST,
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
              resolve({ status: res.statusCode ?? 0, json });
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

/** The owner's one-tap decision on the public /approve/:token page. */
async function ownerDecides(approvalUrl: string, decision: "approve" | "reject"): Promise<number> {
  const token = new URL(approvalUrl).pathname.split("/").pop()!;
  const r = await fetch(`http://127.0.0.1:${adminPort}/approve/${token}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: `decision=${decision}`,
  });
  return r.status;
}

/** The operator's decision through the admin API. */
async function adminDecides(id: string, verb: "approve" | "reject"): Promise<number> {
  const r = await fetch(`http://127.0.0.1:${adminPort}/api/approvals/${id}/${verb}`, {
    method: "POST",
    headers: { authorization: `Bearer ${adminToken}` },
  });
  return r.status;
}

/** Holds a fresh call and returns the pending reply (asserting it was held). */
async function hold(method: string, path: string, body?: string): Promise<ProxyReply> {
  const r = await viaProxy(method, path, body);
  expect(r.status).toBe(403);
  expect(r.json.error).toBe("onegate_approval_pending");
  return r;
}

describe("require_approval through the proxy", () => {
  it("held, approved by the owner, then the retry goes through exactly once", async () => {
    seen = [];
    const body = JSON.stringify({ title: "ship it" });
    const held = await hold("POST", "/repos/alpha/issues", body);
    expect(held.json.approval_url).toMatch(/^https:\/\/gate\.example\.test\/og\/approve\/[0-9a-f]{48}$/);
    expect(held.json.message).toContain("retry the identical request");
    expect(seen).toHaveLength(0);

    // A retry before the owner decides reuses the same approval (no new link).
    const again = await hold("POST", "/repos/alpha/issues", body);
    expect(again.json.approval_id).toBe(held.json.approval_id);
    expect(again.json.approval_url).toBeUndefined();

    expect(await ownerDecides(held.json.approval_url, "approve")).toBe(200);

    const ok = await viaProxy("POST", "/repos/alpha/issues", body);
    expect(ok.status).toBe(201);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      method: "POST",
      path: "/repos/alpha/issues",
      auth: "Bearer real-vendor-key",
      body,
    });
    expect(store.getApproval(held.json.approval_id)?.usedAt).not.toBeNull();

    // Audited as an allow, attributed to the approval and the gate rule.
    const row = store.listAudit({ agentId }).find((a) => a.decision === "allow")!;
    expect(row.approvalId).toBe(held.json.approval_id);
    expect(row.ruleId).toBe(store.getApproval(held.json.approval_id)?.ruleId);
    expect(row.reason).toContain(`owner approval ${held.json.approval_id}`);

    // The approval is spent: the next identical call is held again, fresh.
    const next = await hold("POST", "/repos/alpha/issues", body);
    expect(next.json.approval_id).not.toBe(held.json.approval_id);
    expect(next.json.approval_url).toBeDefined();
    expect(seen).toHaveLength(1);
  });

  it("a rejected approval stays blocked", async () => {
    seen = [];
    const held = await hold("DELETE", "/repos/beta/issues");
    expect(await ownerDecides(held.json.approval_url, "reject")).toBe(200);

    const retry = await hold("DELETE", "/repos/beta/issues");
    expect(retry.json.approval_id).not.toBe(held.json.approval_id);
    expect(seen).toHaveLength(0);
    const rejected = store.getApproval(held.json.approval_id)!;
    expect(rejected.status).toBe("rejected");
    expect(rejected.usedAt).toBeNull();
  });

  it("an approved but expired approval stays blocked", async () => {
    seen = [];
    const held = await hold("POST", "/repos/gamma/issues", "{}");
    expect(await adminDecides(held.json.approval_id, "approve")).toBe(200);
    // Age the approval past its expiry.
    const raw = (store as unknown as { db: import("node:sqlite").DatabaseSync }).db;
    raw
      .prepare("UPDATE approvals SET expires_at = ? WHERE id = ?")
      .run(new Date(Date.now() - 1000).toISOString(), held.json.approval_id);

    await hold("POST", "/repos/gamma/issues", "{}");
    expect(seen).toHaveLength(0);
    expect(store.getApproval(held.json.approval_id)?.usedAt).toBeNull();
  });

  it("a different method, path or query does not redeem it", async () => {
    seen = [];
    const held = await hold("POST", "/repos/delta/issues", "{}");
    expect(await adminDecides(held.json.approval_id, "approve")).toBe(200);

    await hold("PUT", "/repos/delta/issues", "{}");
    await hold("POST", "/repos/other/issues", "{}");
    await hold("POST", "/repos/delta/issues?force=1", "{}");
    expect(seen).toHaveLength(0);

    // None of those spent it: the identical request still goes through.
    const ok = await viaProxy("POST", "/repos/delta/issues", "{}");
    expect(ok.status).toBe(201);
    expect(seen).toHaveLength(1);
  });

  it("a different body does not redeem it", async () => {
    seen = [];
    const approved = JSON.stringify({ title: "harmless" });
    const swapped = JSON.stringify({ title: "something else entirely" });
    const held = await hold("POST", "/repos/epsilon/issues", approved);
    expect(await ownerDecides(held.json.approval_url, "approve")).toBe(200);

    // The swapped body is a different decision: held under a NEW approval.
    const other = await hold("POST", "/repos/epsilon/issues", swapped);
    expect(other.json.approval_id).not.toBe(held.json.approval_id);
    expect(other.json.approval_url).toBeDefined();
    expect(seen).toHaveLength(0);

    const ok = await viaProxy("POST", "/repos/epsilon/issues", approved);
    expect(ok.status).toBe(201);
    expect(seen.map((s) => s.body)).toEqual([approved]);
  });

  it("two concurrent retries: only one goes through", async () => {
    seen = [];
    const held = await hold("POST", "/repos/zeta/issues", "{}");
    expect(await ownerDecides(held.json.approval_url, "approve")).toBe(200);

    const replies = await Promise.all([
      viaProxy("POST", "/repos/zeta/issues", "{}"),
      viaProxy("POST", "/repos/zeta/issues", "{}"),
      viaProxy("POST", "/repos/zeta/issues", "{}"),
    ]);
    expect(replies.map((r) => r.status).sort()).toEqual([201, 403, 403]);
    expect(seen).toHaveLength(1);
  });

  it("a held body over the buffering cap is refused with 413", async () => {
    const prev = process.env.ONEGATE_MAX_BUFFERED_BODY;
    process.env.ONEGATE_MAX_BUFFERED_BODY = "8";
    try {
      const r = await viaProxy("POST", "/repos/eta/issues", "0123456789abcdef");
      expect(r.status).toBe(413);
      expect(r.json.error).toBe("onegate_body_too_large");
      expect(store.listApprovals(agentId).some((a) => a.path === "/repos/eta/issues")).toBe(false);
    } finally {
      if (prev === undefined) delete process.env.ONEGATE_MAX_BUFFERED_BODY;
      else process.env.ONEGATE_MAX_BUFFERED_BODY = prev;
    }
  });
});
