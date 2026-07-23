/**
 * FL1 multi-OAuth: OAuth integrations now hold multiple NAMED connections
 * (kind='app', vendor = integration id), created and updated by the OAuth
 * callback. These tests drive the real admin app end to end against a stub
 * token endpoint (GitLab descriptor, overridden via ONEGATE_OAUTH_*_URL_GITLAB):
 *
 *  - a direct POST /api/connections of an OAuth vendor is guided to the flow
 *  - oauth/start + callback with a connectionName creates a kind='app' connection
 *  - oauth/start + callback with a connectionId re-authorizes (updates) one
 *  - the new connection is denied to every bot until granted (default-deny)
 *  - DELETE purges the cached access token
 *  - start-route validation (connectionId / connectionName / ownerAgentId)
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/store/db.js";
import { initCa } from "../src/ca.js";
import { buildRegistry } from "../src/integrations/index.js";
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";
import { oauthBearerToken } from "../src/integrations/oauth.js";

let dir: string;
let store: Store;
let server: http.Server;
let port: number;
let adminToken: string;
let agentId: string;

// Stub GitLab token endpoint. authUrl is overridden too so oauth/start never
// points the browser at the real gitlab.com.
let tokenServer: http.Server;
let tokenUrl: string;
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

/** The callback route is unauthenticated; hit it without a token. */
function callback(path: string): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "GET", path, agent: false },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

/** Runs an oauth/start then its callback, returns the resulting state's outcome. */
async function connectOauth(body: Record<string, unknown>, code = "auth_code_1") {
  const start = await api("POST", "/api/integrations/gitlab/oauth/start", {
    clientId: "cid",
    clientSecret: "csecret",
    redirectBase: `http://127.0.0.1:${port}`,
    ...body,
  });
  if (start.status !== 200) return { start, callbackRes: null as any };
  const state = new URL(start.json.url).searchParams.get("state");
  const callbackRes = await callback(`/oauth/gitlab/callback?state=${state}&code=${code}`);
  return { start, callbackRes, state };
}

beforeAll(async () => {
  // Stub token endpoint first so the env override is set before any request.
  tokenRespond = () => ({
    status: 200,
    body: { access_token: "gl_at_1", refresh_token: "gl_rt_1", expires_in: 3600, scope: "api" },
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
  tokenUrl = `http://127.0.0.1:${tport}/token`;
  process.env.ONEGATE_OAUTH_TOKEN_URL_GITLAB = tokenUrl;
  process.env.ONEGATE_OAUTH_AUTH_URL_GITLAB = `http://127.0.0.1:${tport}/authorize`;

  dir = mkdtempSync(join(tmpdir(), "onegate-oauth-multi-"));
  store = new Store(":memory:");
  const ca = initCa(dir);
  const registry = await buildRegistry();
  adminToken = ensureAdminToken(store)!;
  const app = createAdminApp({ store, registry, ca, version: "test" });
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as { port: number }).port;
  agentId = store.createAgent("oauth-agent").agent.id;
});

afterAll(() => {
  server.close();
  tokenServer.close();
  delete process.env.ONEGATE_OAUTH_TOKEN_URL_GITLAB;
  delete process.env.ONEGATE_OAUTH_AUTH_URL_GITLAB;
  rmSync(dir, { recursive: true, force: true });
});

describe("direct POST of an OAuth vendor is guided to the connect flow", () => {
  it("rejects with oauth_connection and a pointer to oauth/start", async () => {
    const r = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "gitlab",
      name: "gl-direct",
      data: { accessToken: "x" },
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("oauth_connection");
    expect(r.json.message).toContain("oauth/start");
  });
});

describe("oauth/start + callback with a connectionName creates a named app connection", () => {
  let createdId: string;

  it("creates a kind='app' connection carrying the OAuth token data", async () => {
    const { start, callbackRes } = await connectOauth({
      connectionName: "GitLab work",
      ownerAgentId: null,
      isDefault: true,
    });
    expect(start.status).toBe(200);
    expect(callbackRes.status).toBe(200);
    expect(callbackRes.text).toContain("connected");

    const list = await api("GET", "/api/connections");
    const conn = list.json.apps.find((c: any) => c.name === "GitLab work");
    expect(conn).toBeTruthy();
    expect(conn.vendor).toBe("gitlab");
    expect(conn.legacy).toBe(false);
    expect(conn.isDefault).toBe(true);
    // Secret never serialized.
    expect(list.text).not.toContain("gl_at_1");
    expect(list.text).not.toContain("gl_rt_1");
    createdId = conn.id;

    // Stored data is the full OAuth credential shape (bypassed validateAppData).
    const stored = store.getConnection(createdId)!;
    expect(stored.kind).toBe("app");
    expect(stored.data.accessToken).toBe("gl_at_1");
    expect(stored.data.refreshToken).toBe("gl_rt_1");
    expect(stored.data.clientId).toBe("cid");
    expect(stored.data.expiresAt).toBeTruthy();
  });

  it("the new connection is denied to every bot until granted (default-deny)", async () => {
    const grants = await api("GET", `/api/connections/${createdId}/grants`);
    expect(grants.status).toBe(200);
    expect(grants.json).toEqual([]);
    // It is grantable like any other kind='app' connection.
    const g = await api("POST", `/api/connections/${createdId}/grants`, {
      scope: "agent",
      subjectId: agentId,
    });
    expect(g.status).toBe(201);
  });

  it("re-authorizing with the connectionId updates the same connection in place", async () => {
    tokenRespond = () => ({
      status: 200,
      body: { access_token: "gl_at_2", refresh_token: "gl_rt_2", expires_in: 7200, scope: "api" },
    });
    const before = store.getConnection(createdId)!;
    const { start, callbackRes } = await connectOauth(
      { connectionId: createdId },
      "auth_code_2",
    );
    expect(start.status).toBe(200);
    expect(callbackRes.status).toBe(200);

    const after = store.getConnection(createdId)!;
    expect(after.id).toBe(createdId);
    expect(after.name).toBe("GitLab work"); // name preserved
    expect(after.ownerAgentId).toBe(before.ownerAgentId);
    expect(after.data.accessToken).toBe("gl_at_2"); // token rotated in place
    expect(after.data.refreshToken).toBe("gl_rt_2");
    // No second connection was created.
    const list = await api("GET", "/api/connections");
    expect(list.json.apps.filter((c: any) => c.vendor === "gitlab").length).toBe(1);
  });

  it("DELETE purges the cached access token", async () => {
    const cacheKey = `oauth_access_token:gitlab:${createdId}`;
    store.setSetting(cacheKey, JSON.stringify({ token: "cached", exp: Date.now() + 1e6 }));
    expect(store.getSetting(cacheKey)).toBeTruthy();
    const del = await api("DELETE", `/api/connections/${createdId}`);
    expect(del.status).toBe(204);
    expect(store.getConnection(createdId)).toBeNull();
    expect(store.getSetting(cacheKey)).toBeNull();
  });
});

describe("oauth/start validation", () => {
  it("404s on an unknown connectionId", async () => {
    const r = await api("POST", "/api/integrations/gitlab/oauth/start", {
      clientId: "cid",
      clientSecret: "csecret",
      redirectBase: `http://127.0.0.1:${port}`,
      connectionId: "conn_does_not_exist",
    });
    expect(r.status).toBe(404);
    expect(r.json.error).toBe("unknown_connection");
  });

  it("404s when the connectionId belongs to a different vendor", async () => {
    const ghConn = store.createConnection({
      kind: "app",
      vendor: "github",
      name: "gh-pat",
      data: { pat: "ghp_xxxxxxxxxxxxxxxxxxxx" },
    });
    const r = await api("POST", "/api/integrations/gitlab/oauth/start", {
      clientId: "cid",
      clientSecret: "csecret",
      redirectBase: `http://127.0.0.1:${port}`,
      connectionId: ghConn.id,
    });
    expect(r.status).toBe(404);
    expect(r.json.error).toBe("unknown_connection");
  });

  it("rejects an empty connectionName", async () => {
    const r = await api("POST", "/api/integrations/gitlab/oauth/start", {
      clientId: "cid",
      clientSecret: "csecret",
      redirectBase: `http://127.0.0.1:${port}`,
      connectionName: "   ",
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("connectionName must be a non-empty string");
  });

  it("rejects an ownerAgentId that is not an existing agent", async () => {
    const r = await api("POST", "/api/integrations/gitlab/oauth/start", {
      clientId: "cid",
      clientSecret: "csecret",
      redirectBase: `http://127.0.0.1:${port}`,
      connectionName: "GitLab other",
      ownerAgentId: "ag_missing",
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("unknown ownerAgentId");
  });

  it("persists a rotated refresh token back onto the connection (not the legacy credentials table)", async () => {
    const gitlab = (await buildRegistry()).get("gitlab")!;
    const conn = store.createConnection({
      kind: "app",
      vendor: "gitlab",
      name: "GitLab rotate",
      data: {
        clientId: "cid",
        clientSecret: "csecret",
        accessToken: "stale",
        refreshToken: "rt_old",
        expiresAt: String(Math.floor(Date.now() / 1000) - 10), // already expired -> forces refresh
      },
    });
    // Drop any cached token so oauthBearerToken must hit the refresh path.
    store.deleteSetting(`oauth_access_token:gitlab:${conn.id}`);
    tokenRespond = () => ({
      status: 200,
      body: { access_token: "fresh_at", refresh_token: "rt_rotated", expires_in: 3600 },
    });
    const token = await oauthBearerToken(gitlab, store.getConnection(conn.id)!, store);
    expect(token).toBe("fresh_at");
    // The rotated refresh token landed on the connection row, not a legacy credential.
    expect(store.getConnection(conn.id)!.data.refreshToken).toBe("rt_rotated");
    expect(store.getCredential("gitlab")).toBeNull();
  });

  it("binds the new connection to an owner agent when ownerAgentId is given", async () => {
    tokenRespond = () => ({
      status: 200,
      body: { access_token: "gl_at_owned", refresh_token: "gl_rt_owned", expires_in: 3600 },
    });
    const { start, callbackRes } = await connectOauth(
      { connectionName: "GitLab mine", ownerAgentId: agentId },
      "auth_code_owned",
    );
    expect(start.status).toBe(200);
    expect(callbackRes.status).toBe(200);
    const list = await api("GET", "/api/connections");
    const conn = list.json.apps.find((c: any) => c.name === "GitLab mine");
    expect(conn.ownerAgentId).toBe(agentId);
    expect(conn.ownerAgentName).toBe("oauth-agent");
  });
});
