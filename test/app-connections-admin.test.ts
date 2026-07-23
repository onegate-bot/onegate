/**
 * Admin API tests for the per-agent and multi-account app integration surface:
 * named app connections (tenant-wide or agent-bound), the connection CRUD that
 * supports kind="app", and the per-agent app account selection endpoints
 * (GET/PUT /api/agents/:id/apps).
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

let dir: string;
let store: Store;
let server: http.Server;
let port: number;
let adminToken: string;
let agentId: string;
let otherAgentId: string;

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

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-app-admin-"));
  store = new Store(":memory:");
  const ca = initCa(dir);
  const registry = await buildRegistry();
  adminToken = ensureAdminToken(store)!;
  const app = createAdminApp({ store, registry, ca, version: "test" });
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as { port: number }).port;
  agentId = store.createAgent("app-agent").agent.id;
  otherAgentId = store.createAgent("other-agent").agent.id;
});

afterAll(() => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("app connection CRUD", () => {
  let sharedId: string;
  let mineId: string;

  it("rejects an unknown integration vendor", async () => {
    const r = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "not-an-integration",
      name: "x",
      data: { pat: "p" },
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("unknown_vendor");
  });

  it("rejects unknown fields and missing required fields", async () => {
    const unknownField = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "github",
      name: "x",
      data: { nope: "v" },
    });
    expect(unknownField.status).toBe(400);
    expect(unknownField.json.error).toBe("invalid_data");
    expect(unknownField.json.message).toContain("nope");

    const missing = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "github",
      name: "x",
      data: {},
    });
    expect(missing.status).toBe(400);
    expect(missing.json.error).toBe("invalid_data");
  });

  it("rejects an ownerAgentId that is not an existing agent", async () => {
    const r = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "github",
      name: "x",
      data: { pat: "ghp_aaaaaaaaaaaaaaaaaaaa" },
      ownerAgentId: "ag_missing",
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("unknown_agent");
  });

  it("creates a tenant-wide and an agent-bound connection without echoing the secret", async () => {
    const shared = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "github",
      name: "github-shared",
      data: { pat: "ghp_sharedtokenvalue1234" },
      isDefault: true,
    });
    expect(shared.status).toBe(201);
    expect(shared.json.kind).toBe("app");
    expect(shared.json.ownerAgentId).toBeNull();
    expect(shared.json.ownerAgentName).toBeNull();
    expect(shared.json.isDefault).toBe(true);
    expect(shared.json.data).toBeUndefined();
    expect(shared.text).not.toContain("ghp_sharedtokenvalue1234");
    expect(shared.json.secretPreview).toContain("...");
    sharedId = shared.json.id;

    const mine = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "github",
      name: "github-mine",
      data: { pat: "ghp_agentboundtoken9999" },
      ownerAgentId: agentId,
    });
    expect(mine.status).toBe(201);
    expect(mine.json.ownerAgentId).toBe(agentId);
    expect(mine.json.ownerAgentName).toBe("app-agent");
    // It is the first connection in its own agent-bound bucket so it is the
    // default of that bucket (each owner bucket tracks its own default).
    expect(mine.json.isDefault).toBe(true);
    expect(mine.text).not.toContain("ghp_agentboundtoken9999");
    mineId = mine.json.id;
  });

  it("lists app connections grouped under apps with owner info and no secret", async () => {
    const r = await api("GET", "/api/connections");
    expect(r.status).toBe(200);
    const shared = r.json.apps.find((c: any) => c.id === sharedId);
    const mine = r.json.apps.find((c: any) => c.id === mineId);
    expect(shared.ownerAgentId).toBeNull();
    expect(shared.legacy).toBe(false);
    expect(mine.ownerAgentId).toBe(agentId);
    expect(mine.ownerAgentName).toBe("app-agent");
    expect(r.text).not.toContain("ghp_sharedtokenvalue1234");
    expect(r.text).not.toContain("ghp_agentboundtoken9999");
  });

  it("edits an app connection's data via validateAppData and keeps the secret on empty data", async () => {
    const bad = await api("PUT", `/api/connections/${mineId}`, { data: { nope: "x" } });
    expect(bad.status).toBe(400);
    expect(bad.json.error).toBe("invalid_data");

    const keep = await api("PUT", `/api/connections/${mineId}`, { data: {} });
    expect(keep.status).toBe(200);
    expect(store.getConnection(mineId)!.data.pat).toBe("ghp_agentboundtoken9999");

    const replace = await api("PUT", `/api/connections/${mineId}`, {
      data: { pat: "ghp_replacementtoken5555" },
    });
    expect(replace.status).toBe(200);
    expect(store.getConnection(mineId)!.data.pat).toBe("ghp_replacementtoken5555");
  });

  it("refuses to change ownerAgentId on update", async () => {
    const move = await api("PUT", `/api/connections/${mineId}`, { ownerAgentId: otherAgentId });
    expect(move.status).toBe(400);
    expect(move.json.error).toBe("owner_immutable");
    // Sending the same owner is accepted (no-op).
    const same = await api("PUT", `/api/connections/${mineId}`, { ownerAgentId: agentId });
    expect(same.status).toBe(200);
  });

  it("deletes an app connection and clears any saved agent app choice", async () => {
    store.setAgentAppConfig(agentId, "github", mineId);
    expect(store.getAgentAppConfig(agentId, "github")).not.toBeNull();
    expect((await api("DELETE", `/api/connections/${mineId}`)).status).toBe(204);
    expect(store.getConnection(mineId)).toBeNull();
    expect(store.getAgentAppConfig(agentId, "github")).toBeNull();
  });
});

describe("per-agent app account selection", () => {
  let sharedId: string;
  let mineId: string;

  beforeAll(() => {
    sharedId = store.createConnection({
      kind: "app",
      vendor: "slack",
      name: "slack-shared",
      data: { token: "xoxb-shared" },
      isDefault: true,
    }).id;
    mineId = store.createConnection({
      kind: "app",
      vendor: "slack",
      name: "slack-mine",
      data: { token: "xoxb-mine" },
    }).id;
    // Default-deny: both connections start ungranted. Grant the shared one to
    // both agents and the "mine" one to app-agent only.
    store.grantConnection(sharedId, "agent", agentId);
    store.grantConnection(sharedId, "agent", otherAgentId);
    store.grantConnection(mineId, "agent", agentId);
  });

  it("404s for unknown agents", async () => {
    expect((await api("GET", "/api/agents/ag_missing/apps")).status).toBe(404);
    expect(
      (await api("PUT", "/api/agents/ag_missing/apps/slack", { connectionId: sharedId })).status,
    ).toBe(404);
  });

  it("lists available connections (those granted to this agent)", async () => {
    const r = await api("GET", `/api/agents/${agentId}/apps`);
    expect(r.status).toBe(200);
    const ids = r.json.available.map((c: any) => c.id);
    expect(ids).toContain(sharedId);
    expect(ids).toContain(mineId);
    expect(r.json.configs).toEqual([]);

    // The other agent only sees the shared connection it was granted.
    const other = await api("GET", `/api/agents/${otherAgentId}/apps`);
    const otherIds = other.json.available.map((c: any) => c.id);
    expect(otherIds).toContain(sharedId);
    expect(otherIds).not.toContain(mineId);
  });

  it("rejects an unknown integration and a non-granted connection", async () => {
    const unknownInt = await api("PUT", `/api/agents/${agentId}/apps/not-real`, {
      connectionId: sharedId,
    });
    expect(unknownInt.status).toBe(400);
    expect(unknownInt.json.error).toBe("unknown_integration");

    // "mine" is not granted to the other agent.
    const notPermitted = await api("PUT", `/api/agents/${otherAgentId}/apps/slack`, {
      connectionId: mineId,
    });
    expect(notPermitted.status).toBe(400);
    expect(notPermitted.json.error).toBe("unknown_connection");
  });

  it("saves and clears an agent's app account choice", async () => {
    const set = await api("PUT", `/api/agents/${agentId}/apps/slack`, { connectionId: mineId });
    expect(set.status).toBe(200);
    expect(set.json).toMatchObject({ agentId, integrationId: "slack", connectionId: mineId });
    expect(store.getAgentAppConfig(agentId, "slack")!.connectionId).toBe(mineId);

    const got = await api("GET", `/api/agents/${agentId}/apps`);
    expect(got.json.configs).toEqual([
      expect.objectContaining({ integrationId: "slack", connectionId: mineId }),
    ]);

    const clear = await api("PUT", `/api/agents/${agentId}/apps/slack`, { connectionId: null });
    expect(clear.status).toBe(200);
    expect(clear.json.connectionId).toBeNull();
    expect(store.getAgentAppConfig(agentId, "slack")).toBeNull();
  });
});

describe("connection grants (default-deny authorization)", () => {
  let connId: string;
  let projId: string;
  let projAgentId: string;

  beforeAll(() => {
    connId = store.createConnection({
      kind: "app",
      vendor: "github",
      name: "gh-grantable",
      data: { pat: "ghp_grantabletoken12345" },
    }).id;
    const proj = store.createProject("team-grants");
    projId = proj.id;
    projAgentId = store.createAgent("proj-member", { projectId: projId }).agent.id;
  });

  it("a freshly created app connection is granted to nobody", async () => {
    const r = await api("GET", `/api/connections/${connId}/grants`);
    expect(r.status).toBe(200);
    expect(r.json).toEqual([]);
    // And the list view shows grantCount 0.
    const list = await api("GET", "/api/connections");
    const entry = list.json.apps.find((c: any) => c.id === connId);
    expect(entry.grantCount).toBe(0);
  });

  it("grants to an agent and lists the grant from both sides", async () => {
    const g = await api("POST", `/api/connections/${connId}/grants`, {
      scope: "agent",
      subjectId: agentId,
    });
    expect(g.status).toBe(201);
    expect(g.json).toMatchObject({ connectionId: connId, scope: "agent", subjectId: agentId });

    const perConn = await api("GET", `/api/connections/${connId}/grants`);
    expect(perConn.json).toEqual([
      expect.objectContaining({ scope: "agent", subjectId: agentId, subjectName: "app-agent" }),
    ]);

    const perAgent = await api("GET", `/api/agents/${agentId}/connections`);
    expect(perAgent.status).toBe(200);
    const ids = perAgent.json.granted.map((c: any) => c.id);
    expect(ids).toContain(connId);
  });

  it("grants to a project and every member agent resolves it", async () => {
    const g = await api("POST", `/api/connections/${connId}/grants`, {
      scope: "project",
      subjectId: projId,
    });
    expect(g.status).toBe(201);
    const perAgent = await api("GET", `/api/agents/${projAgentId}/connections`);
    const ids = perAgent.json.granted.map((c: any) => c.id);
    expect(ids).toContain(connId);
  });

  it("grant is idempotent (re-grant is a 201 no-op)", async () => {
    const again = await api("POST", `/api/connections/${connId}/grants`, {
      scope: "agent",
      subjectId: agentId,
    });
    expect(again.status).toBe(201);
    const perConn = await api("GET", `/api/connections/${connId}/grants`);
    // agent grant + project grant = 2, no duplicate.
    expect(perConn.json.length).toBe(2);
  });

  it("rejects an unknown scope and a missing subject", async () => {
    const badScope = await api("POST", `/api/connections/${connId}/grants`, {
      scope: "user",
      subjectId: agentId,
    });
    expect(badScope.status).toBe(400);
    expect(badScope.json.error).toBe("invalid_scope");

    const missingAgent = await api("POST", `/api/connections/${connId}/grants`, {
      scope: "agent",
      subjectId: "ag_missing",
    });
    expect(missingAgent.status).toBe(404);
    expect(missingAgent.json.error).toBe("unknown_agent");

    const missingProject = await api("POST", `/api/connections/${connId}/grants`, {
      scope: "project",
      subjectId: "proj_missing",
    });
    expect(missingProject.status).toBe(404);
    expect(missingProject.json.error).toBe("unknown_project");
  });

  it("404s for grant routes on a non-existent or non-app connection", async () => {
    expect((await api("GET", "/api/connections/conn_missing/grants")).status).toBe(404);
    expect(
      (await api("POST", "/api/connections/conn_missing/grants", { scope: "agent", subjectId: agentId }))
        .status,
    ).toBe(404);
  });

  it("revokes a grant (204) and it disappears from both views", async () => {
    const del = await api("DELETE", `/api/connections/${connId}/grants/agent/${agentId}`);
    expect(del.status).toBe(204);
    const perConn = await api("GET", `/api/connections/${connId}/grants`);
    const subjects = perConn.json.map((g: any) => `${g.scope}:${g.subjectId}`);
    expect(subjects).not.toContain(`agent:${agentId}`);
    // Revoking a non-existent grant is a no-op 204.
    expect((await api("DELETE", `/api/connections/${connId}/grants/agent/${agentId}`)).status).toBe(
      204,
    );
  });
});
