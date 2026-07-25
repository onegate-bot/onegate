import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/store/db.js";
import { initCa } from "../src/ca.js";
import { buildRegistry } from "../src/integrations/index.js";
import { createAdminApp, ensureAdminToken, resetAdminToken } from "../src/admin/api.js";

let dir: string;
let store: Store;
let server: http.Server;
let port: number;
let adminToken: string;
let tokenStub: http.Server;

function api(
  method: string,
  path: string,
  body?: unknown,
  token: string | null = adminToken,
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
          ...(payload ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } : {}),
          ...(token ? { authorization: `Bearer ${token}` } : {}),
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

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-admin-"));
  store = new Store(":memory:");
  const ca = initCa(dir);
  const registry = await buildRegistry();
  adminToken = ensureAdminToken(store)!;

  // Stub Google token endpoint for the OAuth code exchange.
  tokenStub = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const params = new URLSearchParams(body);
      if (params.get("grant_type") === "authorization_code" && params.get("code") === "good-code") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ access_token: "at", refresh_token: "rt_new", expires_in: 3600 }));
      } else {
        res.writeHead(400).end(JSON.stringify({ error: "invalid_grant" }));
      }
    });
  });
  await new Promise<void>((r) => tokenStub.listen(0, "127.0.0.1", r));
  const stubPort = (tokenStub.address() as { port: number }).port;

  const app = createAdminApp({
    store,
    registry,
    ca,
    version: "test",
    googleTokenUrl: `http://127.0.0.1:${stubPort}/token`,
  });
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as { port: number }).port;
});

afterAll(() => {
  server.close();
  tokenStub.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("auth", () => {
  it("health is public, api requires the admin token", async () => {
    expect((await api("GET", "/api/health", undefined, null)).status).toBe(200);
    expect((await api("GET", "/api/agents", undefined, null)).status).toBe(401);
    expect((await api("GET", "/api/agents", undefined, "oga_wrong")).status).toBe(401);
    expect((await api("GET", "/api/agents")).status).toBe(200);
  });

  it("ensureAdminToken only generates once; reset replaces it", () => {
    expect(ensureAdminToken(store)).toBeNull();
    const fresh = resetAdminToken(store);
    expect(fresh).toMatch(/^oga_/);
    adminToken = fresh;
  });

  it("serves the root CA publicly", async () => {
    const r = await api("GET", "/ca.pem", undefined, null);
    expect(r.status).toBe(200);
    expect(r.text).toContain("BEGIN CERTIFICATE");
  });
});

describe("agents + projects CRUD", () => {
  let agentId: string;
  let projectId: string;

  it("creates a project and an agent in it; token returned once", async () => {
    const proj = await api("POST", "/api/projects", { name: "research" });
    expect(proj.status).toBe(201);
    projectId = proj.json.id;

    const agent = await api("POST", "/api/agents", { name: "scout", projectId });
    expect(agent.status).toBe(201);
    expect(agent.json.token).toMatch(/^og_/);
    expect(agent.json.tokenHash).toBeUndefined();
    agentId = agent.json.id;

    const list = await api("GET", "/api/agents");
    expect(list.json).toHaveLength(1);
    expect(list.json[0].token).toBeUndefined();
  });

  it("validates input", async () => {
    expect((await api("POST", "/api/agents", {})).status).toBe(400);
    expect((await api("POST", "/api/projects", {})).status).toBe(400);
    expect((await api("POST", "/api/projects", { name: "research" })).status).toBe(409);
  });

  it("updates and rotates", async () => {
    const upd = await api("PATCH", `/api/agents/${agentId}`, { defaultPolicy: "allow-all" });
    expect(upd.json.defaultPolicy).toBe("allow-all");
    const rot = await api("POST", `/api/agents/${agentId}/rotate-token`);
    expect(rot.json.token).toMatch(/^og_/);
  });

  it("deletes", async () => {
    expect((await api("DELETE", `/api/agents/${agentId}`)).status).toBe(204);
    expect((await api("DELETE", `/api/projects/${projectId}`)).status).toBe(204);
  });

  // Delete answers 404 on an unknown id like its PATCH/rotate-token siblings,
  // so a typo'd or already-deleted id is not reported as a success.
  it("deleting an unknown agent is a 404, not a silent 204", async () => {
    const r = await api("DELETE", "/api/agents/ag_does_not_exist");
    expect(r.status).toBe(404);
    expect(r.json.error).toBe("not_found");
    // Same condition, same code as the siblings on this resource.
    expect((await api("PATCH", "/api/agents/ag_does_not_exist", { name: "x" })).json.error).toBe("not_found");
    expect((await api("POST", "/api/agents/ag_does_not_exist/rotate-token")).json.error).toBe("not_found");
  });

  it("a repeated delete of the same agent 404s the second time", async () => {
    const agent = await api("POST", "/api/agents", { name: "ephemeral" });
    expect((await api("DELETE", `/api/agents/${agent.json.id}`)).status).toBe(204);
    expect((await api("DELETE", `/api/agents/${agent.json.id}`)).status).toBe(404);
  });
});

describe("integrations + credentials + rules + audit", () => {
  it("lists integrations with connection state", async () => {
    const r = await api("GET", "/api/integrations");
    const github = r.json.find((i: any) => i.id === "github");
    expect(github.connected).toBe(false);

    await api("PUT", "/api/credentials/github", { name: "ziv", data: { pat: "ghp_x" } });
    const after = await api("GET", "/api/integrations");
    expect(after.json.find((i: any) => i.id === "github").connected).toBe(true);
  });

  it("includes an llm help prompt for every registered integration", async () => {
    const r = await api("GET", "/api/integrations");
    const registered = r.json.filter((i: any) => !i.orphaned);
    expect(registered.length).toBeGreaterThan(0);
    for (const integration of registered) {
      expect(typeof integration.llmHelpPrompt).toBe("string");
      expect(integration.llmHelpPrompt).toContain("OneGate");
      expect(integration.llmHelpPrompt).toContain(integration.title);
      expect(integration.llmHelpPrompt).toContain("numbered step-by-step instructions");
    }
  });

  it("rejects credentials for unknown integrations", async () => {
    expect((await api("PUT", "/api/credentials/nope", { data: { x: "1" } })).status).toBe(404);
  });

  it("rules CRUD with defaults", async () => {
    const agent = await api("POST", "/api/agents", { name: "ruler" });
    const r = await api("POST", "/api/rules", {
      scope: "agent",
      subjectId: agent.json.id,
      integrationId: "github",
      effect: "allow",
    });
    expect(r.status).toBe(201);
    expect(r.json.methods).toEqual(["*"]);
    expect(r.json.pathGlob).toBe("/**");
    expect((await api("DELETE", `/api/rules/${r.json.id}`)).status).toBe(204);
  });

  // Matches the renew sibling on the same resource, which already answers
  // 404 unknown_rule for a rule id that is not in the store.
  it("deleting an unknown rule is a 404 unknown_rule", async () => {
    const r = await api("DELETE", "/api/rules/rl_does_not_exist");
    expect(r.status).toBe(404);
    expect(r.json.error).toBe("unknown_rule");
    expect((await api("POST", "/api/rules/rl_does_not_exist/renew")).json.error).toBe("unknown_rule");
  });

  it("exposes the audit log", async () => {
    store.audit({ host: "api.github.com", decision: "allow", status: 200 });
    const r = await api("GET", "/api/audit?limit=5");
    expect(r.status).toBe(200);
    expect(r.json[0].host).toBe("api.github.com");
  });
});

describe("rule referential validation on create", () => {
  let agentId: string;
  let projectId: string;
  let connId: string;

  beforeAll(async () => {
    agentId = (await api("POST", "/api/agents", { name: "refbot" })).json.id;
    projectId = (await api("POST", "/api/projects", { name: "refproject" })).json.id;
    connId = store.createConnection({
      kind: "app",
      vendor: "github",
      name: "github-ref",
      data: { token: "ghp_ref" },
    }).id;
  });

  it("rejects an agent-scoped rule whose subject does not exist", async () => {
    const r = await api("POST", "/api/rules", {
      scope: "agent",
      subjectId: "ag_nope",
      integrationId: "github",
      effect: "allow",
    });
    expect(r.status).toBe(404);
    expect(r.json.error).toBe("unknown_agent");
  });

  it("rejects a project-scoped rule whose subject does not exist", async () => {
    const r = await api("POST", "/api/rules", {
      scope: "project",
      subjectId: "pr_nope",
      integrationId: "github",
      effect: "allow",
    });
    expect(r.status).toBe(404);
    expect(r.json.error).toBe("unknown_project");
  });

  it("rejects a rule naming an unregistered integration", async () => {
    const r = await api("POST", "/api/rules", {
      scope: "agent",
      subjectId: agentId,
      integrationId: "not_a_real_integration",
      effect: "allow",
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("unknown_integration");
  });

  // The dangerous case: a typo'd connection on a deny/except pin silently
  // becomes a blanket deny, because the exception can never match.
  it("rejects a connection-scoped rule whose connection does not exist", async () => {
    for (const connectionScope of ["only", "except"]) {
      const r = await api("POST", "/api/rules", {
        scope: "agent",
        subjectId: agentId,
        integrationId: "github",
        effect: "deny",
        connectionId: "conn_nope",
        connectionScope,
      });
      expect(r.status).toBe(404);
      expect(r.json.error).toBe("unknown_connection");
    }
  });

  it("still creates rules for both scopes when the subject exists", async () => {
    const a = await api("POST", "/api/rules", {
      scope: "agent",
      subjectId: agentId,
      integrationId: "github",
      effect: "allow",
    });
    expect(a.status).toBe(201);
    expect(a.json.subjectId).toBe(agentId);

    const p = await api("POST", "/api/rules", {
      scope: "project",
      subjectId: projectId,
      integrationId: "github",
      effect: "allow",
    });
    expect(p.status).toBe(201);
    expect(p.json.subjectId).toBe(projectId);
  });

  it("still creates connection-scoped rules with a valid connection", async () => {
    for (const connectionScope of ["only", "except"]) {
      const r = await api("POST", "/api/rules", {
        scope: "agent",
        subjectId: agentId,
        integrationId: "github",
        effect: "deny",
        pathGlob: "/repos/onegate-bot/onegate/**",
        connectionId: connId,
        connectionScope,
      });
      expect(r.status).toBe(201);
      expect(r.json.connectionId).toBe(connId);
      expect(r.json.connectionScope).toBe(connectionScope);
    }
  });

  it("keeps the existing required-field and connectionScope checks ahead of it", async () => {
    // Missing required fields still 400 before any lookup runs.
    expect((await api("POST", "/api/rules", { scope: "agent", subjectId: agentId })).status).toBe(400);
    // connectionId without connectionScope still 400, not a connection lookup.
    const r = await api("POST", "/api/rules", {
      scope: "agent",
      subjectId: agentId,
      integrationId: "github",
      effect: "allow",
      connectionId: connId,
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("connectionId requires connectionScope");
  });
});

describe("generic oauth routes", () => {
  it("rejects oauth start for unknown and non-oauth integrations", async () => {
    expect((await api("POST", "/api/integrations/nope/oauth/start", { clientId: "x" })).status).toBe(404);
    const r = await api("POST", "/api/integrations/github/oauth/start", {
      clientId: "x",
      clientSecret: "y",
      redirectBase: "http://localhost",
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("oauth_not_supported");
  });

  it("exposes connect metadata on the integrations list", async () => {
    const r = await api("GET", "/api/integrations");
    const google = r.json.find((i: any) => i.id === "google");
    expect(google.connect.method).toBe("oauth");
    expect(google.oauth.defaultScopes.length).toBeGreaterThan(0);
    expect(Array.isArray(google.scopePacks)).toBe(true);
    const github = r.json.find((i: any) => i.id === "github");
    expect(github.connect.method).toBe("api_key");
    expect(github.oauth).toBeNull();
  });

  it("rejects malformed scope overrides", async () => {
    const r = await api("POST", "/api/integrations/google/oauth/start", {
      clientId: "cid",
      clientSecret: "cs",
      redirectBase: "http://localhost",
      scopes: "not-an-array",
    });
    expect(r.status).toBe(400);
  });

  it("honors a custom scope selection", async () => {
    const r = await api("POST", "/api/integrations/google/oauth/start", {
      clientId: "cid",
      clientSecret: "cs",
      redirectBase: "http://localhost",
      scopes: ["https://www.googleapis.com/auth/spreadsheets"],
    });
    expect(r.status).toBe(200);
    const url = new URL(r.json.url);
    expect(url.searchParams.get("scope")).toBe("https://www.googleapis.com/auth/spreadsheets");
  });
});

describe("google oauth connect flow", () => {
  it("start returns a consent URL carrying state and scopes", async () => {
    const r = await api("POST", "/api/integrations/google/oauth/start", {
      clientId: "cid",
      clientSecret: "cs",
      redirectBase: `http://127.0.0.1:${port}`,
    });
    expect(r.status).toBe(200);
    const url = new URL(r.json.url);
    expect(url.searchParams.get("client_id")).toBe("cid");
    expect(url.searchParams.get("access_type")).toBe("offline");
    expect(url.searchParams.get("scope")).toContain("gmail");
    expect(url.searchParams.get("state")).toBeTruthy();
  });

  it("callback exchanges the code and stores the credential", async () => {
    const start = await api("POST", "/api/integrations/google/oauth/start", {
      clientId: "cid",
      clientSecret: "cs",
      redirectBase: `http://127.0.0.1:${port}`,
    });
    const state = new URL(start.json.url).searchParams.get("state")!;
    const cb = await api("GET", `/oauth/google/callback?code=good-code&state=${state}`, undefined, null);
    expect(cb.status).toBe(200);
    expect(cb.text).toContain("connected");
    const cred = store.getCredential("google");
    expect(cred?.data.refreshToken).toBe("rt_new");

    // State is single-use.
    const replay = await api("GET", `/oauth/google/callback?code=good-code&state=${state}`, undefined, null);
    expect(replay.status).toBe(400);
  });

  it("callback rejects unknown state and surfaces exchange failures", async () => {
    const bad = await api("GET", "/oauth/google/callback?code=x&state=bogus", undefined, null);
    expect(bad.status).toBe(400);

    const start = await api("POST", "/api/integrations/google/oauth/start", {
      clientId: "cid",
      clientSecret: "cs",
      redirectBase: `http://127.0.0.1:${port}`,
    });
    const state = new URL(start.json.url).searchParams.get("state")!;
    const cb = await api("GET", `/oauth/google/callback?code=bad-code&state=${state}`, undefined, null);
    expect(cb.status).toBe(502);
  });
});
