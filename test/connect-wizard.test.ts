/**
 * Connect wizard: a per-app, per-bot self-service OAuth connect flow.
 *
 * M2 admin mint  - POST/GET/DELETE /api/onboarding-links
 * M3 public page - GET /connect/:integrationId/:token renders the wizard,
 *                  POST .../start redirects to consent, invalid links are
 *                  handled with a friendly page (not a redirect).
 * M4 auto-wire   - the OAuth callback for a wizard-originated flow creates the
 *                  connection, grants it to the agent, ensures an agent allow
 *                  rule, and marks the link used. The plain (non-wizard) flow
 *                  is unchanged.
 *
 * Driven end to end against the real admin app with a stub GitLab token
 * endpoint (ONEGATE_OAUTH_*_URL_GITLAB), mirroring oauth-multi-connection.test.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/store/db.js";
import { initCa } from "../src/ca.js";
import { buildRegistry } from "../src/integrations/index.js";
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

let dir: string;
let store: Store;
let server: http.Server;
let port: number;
let adminToken: string;
let agentId: string;

let tokenServer: http.Server;
let tokenRespond: () => { status: number; body: unknown };

function api(
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; json: any; text: string }> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : JSON.stringify(body);
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path,
        agent: false,
        headers: {
          ...(payload
            ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) }
            : {}),
          authorization: `Bearer ${adminToken}`,
        },
      },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          let json: any = null;
          try {
            json = JSON.parse(text);
          } catch {
            /* non-JSON body */
          }
          resolve({ status: res.statusCode ?? 0, json, text });
        });
      },
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/** Unauthenticated GET (public wizard + callback pages). */
function get(path: string): Promise<{ status: number; text: string; location?: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "GET", path, agent: false },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text, location: res.headers.location }),
        );
      },
    );
    req.on("error", reject);
    req.end();
  });
}

/** Unauthenticated form POST (application/x-www-form-urlencoded). */
function postForm(
  path: string,
  fields: Record<string, string | string[]>,
): Promise<{ status: number; text: string; location?: string }> {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(fields)) {
    for (const one of Array.isArray(v) ? v : [v]) params.append(k, one);
  }
  const payload = params.toString();
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method: "POST",
        path,
        agent: false,
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "content-length": Buffer.byteLength(payload),
        },
      },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text, location: res.headers.location }),
        );
      },
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

beforeAll(async () => {
  tokenRespond = () => ({
    status: 200,
    body: { access_token: "gl_at_w", refresh_token: "gl_rt_w", expires_in: 3600, scope: "api" },
  });
  tokenServer = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const out = tokenRespond();
      res.writeHead(out.status, { "content-type": "application/json" });
      res.end(JSON.stringify(out.body));
    });
  });
  await new Promise<void>((r) => tokenServer.listen(0, "127.0.0.1", r));
  const tport = (tokenServer.address() as { port: number }).port;
  process.env.ONEGATE_OAUTH_TOKEN_URL_GITLAB = `http://127.0.0.1:${tport}/token`;
  process.env.ONEGATE_OAUTH_AUTH_URL_GITLAB = `http://127.0.0.1:${tport}/authorize`;

  dir = mkdtempSync(join(tmpdir(), "onegate-connect-wizard-"));
  store = new Store(":memory:");
  const ca = initCa(dir);
  const registry = await buildRegistry();
  adminToken = ensureAdminToken(store)!;
  const app = createAdminApp({ store, registry, ca, version: "test" });
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as { port: number }).port;
  // Point the wizard's public base at this test server so its consent redirect
  // URI and links resolve back here.
  process.env.ONEGATE_PUBLIC_URL = `http://127.0.0.1:${port}`;
  agentId = store.createAgent("wizard-agent").agent.id;
});

afterAll(() => {
  server.close();
  tokenServer.close();
  delete process.env.ONEGATE_OAUTH_TOKEN_URL_GITLAB;
  delete process.env.ONEGATE_OAUTH_AUTH_URL_GITLAB;
  delete process.env.ONEGATE_PUBLIC_URL;
  rmSync(dir, { recursive: true, force: true });
});

// ---- M2: admin mint routes ----

describe("M2 admin mint of onboarding links", () => {
  it("400s when agentId or integrationId is missing", async () => {
    const r = await api("POST", "/api/onboarding-links", { integrationId: "gitlab" });
    expect(r.status).toBe(400);
    const r2 = await api("POST", "/api/onboarding-links", { agentId });
    expect(r2.status).toBe(400);
  });

  it("404s unknown_agent for a missing agent", async () => {
    const r = await api("POST", "/api/onboarding-links", {
      agentId: "ag_missing",
      integrationId: "gitlab",
    });
    expect(r.status).toBe(404);
    expect(r.json.error).toBe("unknown_agent");
  });

  it("400s integration_not_connectable for a non-connectable integration", async () => {
    const r = await api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "anthropic", // LLM vendor: wired via routing, no connect wizard
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("integration_not_connectable");
  });

  it("mints a link for a credential (non-oauth) integration", async () => {
    const r = await api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "github", // PAT, credential flow
    });
    expect(r.status).toBe(201);
    expect(r.json.token).toMatch(/^[a-f0-9]{48}$/);
    expect(r.json.url).toContain(`/connect/github/${r.json.token}`);
  });

  it("mints a link and returns token, url and expiresAt", async () => {
    const r = await api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "gitlab",
      connectionName: "GitLab for wizard-agent",
      ttlDays: 3,
    });
    expect(r.status).toBe(201);
    expect(r.json.token).toMatch(/^[a-f0-9]{48}$/);
    expect(r.json.url).toContain(`/connect/gitlab/${r.json.token}`);
    expect(new Date(r.json.expiresAt).getTime()).toBeGreaterThan(Date.now());
  });

  it("lists links for an agent and DELETE revokes by token", async () => {
    const mint = await api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "gitlab",
    });
    const token = mint.json.token;
    // The list surfaces the stored hash as `token` (plaintext is unrecoverable).
    const tokenHash = sha256(token);
    const list = await api("GET", `/api/onboarding-links?agentId=${agentId}`);
    expect(list.status).toBe(200);
    const row = list.json.find((l: any) => l.token === tokenHash);
    expect(row).toBeTruthy();
    expect(row.integrationId).toBe("gitlab");
    expect(row.valid).toBe(true);

    // Revoke by the plaintext token (hash match); the admin route also accepts
    // the surfaced hash.
    const del = await api("DELETE", `/api/onboarding-links/${token}`);
    expect(del.status).toBe(204);
    const after = await api("GET", `/api/onboarding-links?agentId=${agentId}`);
    expect(after.json.find((l: any) => l.token === tokenHash)).toBeUndefined();
  });
});

// ---- M3: public wizard page + start ----

describe("M3 public wizard page", () => {
  it("renders the wizard with the redirect URI, guide and consent form", async () => {
    const mint = await api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "gitlab",
    });
    const page = await get(`/connect/gitlab/${mint.json.token}`);
    expect(page.status).toBe(200);
    expect(page.text).toContain(`/oauth/gitlab/callback`); // redirect URI shown
    expect(page.text).toContain(`/connect/gitlab/${mint.json.token}/start`); // form action
    expect(page.text).toContain("Client ID");
    expect(page.text).toContain("Client secret");
    // No secret is ever pre-filled.
    expect(page.text).not.toContain("gl_at_w");
    // Branded with the OneGate design shell.
    expect(page.text).toContain("og-card");
    expect(page.text).toContain('name="theme-color" content="#4f46e5"');
    expect(page.text).toContain("OneGate");
    // Paired vendor + OneGate logo header and the trust panel.
    expect(page.text).toContain("og-pair");
    expect(page.text).toContain('aria-label="GitLab logo"');
    expect(page.text).toContain('aria-label="OneGate logo"');
    expect(page.text).toContain("og-trust");
    expect(page.text).toContain("Your bot never sees this credential");
  });

  it("404s for an unknown integration", async () => {
    const page = await get(`/connect/not-a-real-integration/whatever`);
    expect(page.status).toBe(404);
  });

  it("shows a friendly 410 page (not a redirect) for an invalid token", async () => {
    const page = await get(`/connect/gitlab/deadbeeftoken`);
    expect(page.status).toBe(410);
    expect(page.location).toBeUndefined();
    expect(page.text).toContain("no longer valid");
    // Error pages are branded too.
    expect(page.text).toContain("og-card");
  });

  it("shows the friendly page for an expired link", async () => {
    const mint = await api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "gitlab",
    });
    (store as unknown as { db: { prepare(sql: string): { run(...a: unknown[]): void } } }).db
      .prepare("UPDATE onboarding_links SET expires_at = ? WHERE token_hash = ?")
      .run(new Date(Date.now() - 1000).toISOString(), sha256(mint.json.token));
    const page = await get(`/connect/gitlab/${mint.json.token}`);
    expect(page.status).toBe(410);
  });

  it("start with missing client id/secret returns a friendly 400, not a redirect", async () => {
    const mint = await api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "gitlab",
    });
    const r = await postForm(`/connect/gitlab/${mint.json.token}/start`, { clientId: "cid" });
    expect(r.status).toBe(400);
    expect(r.location).toBeUndefined();
  });

  it("start redirects to the provider consent screen with a state", async () => {
    const mint = await api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "gitlab",
    });
    const r = await postForm(`/connect/gitlab/${mint.json.token}/start`, {
      clientId: "cid",
      clientSecret: "csecret",
    });
    expect(r.status).toBe(302);
    expect(r.location).toBeTruthy();
    const url = new URL(r.location!);
    // Points at the stubbed gitlab auth endpoint, carries a state + our redirect.
    expect(url.searchParams.get("state")).toMatch(/^[a-f0-9]{32}$/);
    expect(url.searchParams.get("client_id")).toBe("cid");
    expect(url.searchParams.get("redirect_uri")).toContain("/oauth/gitlab/callback");
  });
});

// ---- M4: callback auto-wires connection + grant + rule ----

describe("M4 wizard callback auto-wire", () => {
  it("creates the connection, grants it, ensures an allow rule, and marks the link used", async () => {
    tokenRespond = () => ({
      status: 200,
      body: { access_token: "gl_at_wire", refresh_token: "gl_rt_wire", expires_in: 3600, scope: "api" },
    });
    const mint = await api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "gitlab",
      connectionName: "GitLab wired",
    });
    const token = mint.json.token;

    const start = await postForm(`/connect/gitlab/${token}/start`, {
      clientId: "cid",
      clientSecret: "csecret",
    });
    expect(start.status).toBe(302);
    const state = new URL(start.location!).searchParams.get("state");

    const cb = await get(`/oauth/gitlab/callback?state=${state}&code=auth_code_wire`);
    expect(cb.status).toBe(200);
    expect(cb.text).toContain("connected");
    // Wizard-aware page names the agent.
    expect(cb.text).toContain("wizard-agent");
    // Checkmark is an inline SVG (device-independent), never a bare ✓ glyph.
    expect(cb.text).toContain("#16a34a");
    expect(cb.text).not.toContain("✓");

    // Connection created with the wizard's connectionName + OAuth token data.
    const list = await api("GET", "/api/connections");
    const conn = list.json.apps.find((c: any) => c.name === "GitLab wired");
    expect(conn).toBeTruthy();
    expect(conn.vendor).toBe("gitlab");
    const stored = store.getConnection(conn.id)!;
    expect(stored.data.accessToken).toBe("gl_at_wire");
    expect(stored.data.refreshToken).toBe("gl_rt_wire");
    // Secret never serialized to the API.
    expect(list.text).not.toContain("gl_at_wire");

    // Granted to the agent (default-deny lifted for this one agent).
    const grants = await api("GET", `/api/connections/${conn.id}/grants`);
    expect(grants.json.some((g: any) => g.scope === "agent" && g.subjectId === agentId)).toBe(true);

    // Agent allow rule for gitlab exists.
    const agent = store.getAgent(agentId)!;
    const hasAllow = store
      .rulesForAgent(agent)
      .some(
        (r) =>
          r.scope === "agent" &&
          r.subjectId === agentId &&
          r.integrationId === "gitlab" &&
          r.effect === "allow",
      );
    expect(hasAllow).toBe(true);

    // Link is now used, so a re-visit shows the friendly page and start 410s.
    const revisit = await get(`/connect/gitlab/${token}`);
    expect(revisit.status).toBe(410);
    const reuse = await postForm(`/connect/gitlab/${token}/start`, {
      clientId: "cid",
      clientSecret: "csecret",
    });
    expect(reuse.status).toBe(410);
  });

  it("does not create a duplicate allow rule when the agent already has one", async () => {
    // Pre-seed an allow rule, then run a wizard connect and confirm no dupe.
    store.createRule({
      scope: "agent",
      subjectId: agentId,
      integrationId: "gitlab",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
    const before = store
      .rulesForAgent(store.getAgent(agentId)!)
      .filter((r) => r.integrationId === "gitlab" && r.effect === "allow").length;

    tokenRespond = () => ({
      status: 200,
      body: { access_token: "gl_at_dup", refresh_token: "gl_rt_dup", expires_in: 3600 },
    });
    const mint = await api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "gitlab",
      connectionName: "GitLab dup",
    });
    const start = await postForm(`/connect/gitlab/${mint.json.token}/start`, {
      clientId: "cid",
      clientSecret: "csecret",
    });
    const state = new URL(start.location!).searchParams.get("state");
    const cb = await get(`/oauth/gitlab/callback?state=${state}&code=auth_code_dup`);
    expect(cb.status).toBe(200);

    const after = store
      .rulesForAgent(store.getAgent(agentId)!)
      .filter((r) => r.integrationId === "gitlab" && r.effect === "allow").length;
    expect(after).toBe(before);
  });
});

// ---- Credential (non-OAuth) wizard: paste a credential + auto-wire ----

describe("credential wizard (non-oauth integrations)", () => {
  it("renders a paste form (not a consent redirect) for a credential integration", async () => {
    const mint = await api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "github", // PAT credential
    });
    const page = await get(`/connect/github/${mint.json.token}`);
    expect(page.status).toBe(200);
    // Posts the pasted credential back to the submit route.
    expect(page.text).toContain(`/connect/github/${mint.json.token}/submit`);
    // The declared credential field is present, secret rendered as a password input.
    expect(page.text).toContain('name="pat"');
    expect(page.text).toContain('type="password"');
    // No OAuth consent form action on a credential wizard.
    expect(page.text).not.toContain(`/connect/github/${mint.json.token}/start`);
    // Branded with the OneGate design shell.
    expect(page.text).toContain("og-card");
    expect(page.text).toContain("OneGate");
    // Paired vendor + OneGate logo header and the trust panel on the credential wizard too.
    expect(page.text).toContain("og-pair");
    expect(page.text).toContain('aria-label="GitHub logo"');
    expect(page.text).toContain('aria-label="OneGate logo"');
    expect(page.text).toContain("Your bot never sees this credential");
  });

  it("submit stores the connection, grants it, ensures an allow rule, and marks the link used", async () => {
    const mint = await api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "github",
      connectionName: "GitHub PAT wired",
    });
    const token = mint.json.token;

    const submit = await postForm(`/connect/github/${token}/submit`, {
      pat: "ghp_selfservice_token_value",
    });
    expect(submit.status).toBe(200);
    expect(submit.text).toContain("connected");
    expect(submit.text).toContain("wizard-agent");
    // Checkmark is an inline SVG, never a bare glyph, and the secret never leaks.
    expect(submit.text).not.toContain("✓");
    expect(submit.text).not.toContain("ghp_selfservice_token_value");

    // Connection created with the wizard name + pasted data.
    const list = await api("GET", "/api/connections");
    const conn = list.json.apps.find((c: any) => c.name === "GitHub PAT wired");
    expect(conn).toBeTruthy();
    expect(conn.vendor).toBe("github");
    const stored = store.getConnection(conn.id)!;
    expect(stored.data.pat).toBe("ghp_selfservice_token_value");
    // Secret never serialized to the API.
    expect(list.text).not.toContain("ghp_selfservice_token_value");

    // Granted to the agent.
    const grants = await api("GET", `/api/connections/${conn.id}/grants`);
    expect(grants.json.some((g: any) => g.scope === "agent" && g.subjectId === agentId)).toBe(true);

    // Agent allow rule for github exists.
    const hasAllow = store
      .rulesForAgent(store.getAgent(agentId)!)
      .some(
        (r) =>
          r.scope === "agent" &&
          r.subjectId === agentId &&
          r.integrationId === "github" &&
          r.effect === "allow",
      );
    expect(hasAllow).toBe(true);

    // Link is now used: re-visit shows the friendly page and re-submit 410s.
    const revisit = await get(`/connect/github/${token}`);
    expect(revisit.status).toBe(410);
    const reuse = await postForm(`/connect/github/${token}/submit`, { pat: "again" });
    expect(reuse.status).toBe(410);
  });

  it("submit with a missing required field returns a friendly 400, not a redirect", async () => {
    const mint = await api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "github",
    });
    const r = await postForm(`/connect/github/${mint.json.token}/submit`, { pat: "" });
    expect(r.status).toBe(400);
    expect(r.location).toBeUndefined();
    // Link stays valid so the owner can retry.
    const retry = await get(`/connect/github/${mint.json.token}`);
    expect(retry.status).toBe(200);
  });
});
