/**
 * Admin API tests for LLM connections, per-agent LLM routing config, the
 * usage endpoint, and orphaned-credential surfacing (issue #3886).
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
          ...(payload ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } : {}),
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
  dir = mkdtempSync(join(tmpdir(), "onegate-llm-admin-"));
  store = new Store(":memory:");
  const ca = initCa(dir);
  const registry = await buildRegistry();
  adminToken = ensureAdminToken(store)!;
  const app = createAdminApp({ store, registry, ca, version: "test" });
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as { port: number }).port;
});

afterAll(() => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("connections CRUD", () => {
  let primaryId: string;
  let backupId: string;

  it("rejects bad create payloads", async () => {
    const badKind = await api("POST", "/api/connections", {
      kind: "weird",
      vendor: "github",
      name: "x",
      data: { pat: "p" },
    });
    expect(badKind.status).toBe(400);
    expect(badKind.json.error).toBe("unsupported_kind");

    const vendor = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "nope",
      name: "x",
      data: { apiKey: "k" },
    });
    expect(vendor.status).toBe(400);
    expect(vendor.json.error).toBe("unknown_vendor");
    expect(vendor.json.message).toContain("anthropic");

    const name = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "anthropic",
      name: "  ",
      data: { apiKey: "k" },
    });
    expect(name.status).toBe(400);
    expect(name.json.error).toBe("name_required");

    const noKey = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "anthropic",
      name: "x",
      data: {},
    });
    expect(noKey.status).toBe(400);
    expect(noKey.json.error).toBe("invalid_data");

    const nonString = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "gemini",
      name: "x",
      data: { apiKey: 42 },
    });
    expect(nonString.status).toBe(400);

    const openaiEmpty = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "openai",
      name: "x",
      data: { accountId: "acc" },
    });
    expect(openaiEmpty.status).toBe(400);
    expect(openaiEmpty.json.message).toContain("accessToken");
  });

  it("creates connections without echoing secrets; first per vendor is default", async () => {
    const a = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "anthropic",
      name: "Anthropic - prod",
      data: { apiKey: "sk-ant-1" },
    });
    expect(a.status).toBe(201);
    expect(a.json.isDefault).toBe(true);
    expect(a.json.data).toBeUndefined();
    expect(a.text).not.toContain("sk-ant-1");
    // A masked preview is returned, never the raw secret. "sk-ant-1" is 8
    // chars so only the last 4 are shown.
    expect(a.json.secretPreview).toBe("...nt-1");
    primaryId = a.json.id;

    const b = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "anthropic",
      name: "Anthropic - backup",
      data: { apiKey: "sk-ant-2" },
    });
    expect(b.status).toBe(201);
    expect(b.json.isDefault).toBe(false);
    backupId = b.json.id;
  });

  it("accepts both openai connect shapes", async () => {
    const key = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "openai",
      name: "OpenAI key",
      data: { apiKey: "sk-oai" },
    });
    expect(key.status).toBe(201);
    const oauth = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "openai",
      name: "OpenAI codex import",
      data: { accessToken: "at", accountId: "acc_1" },
    });
    expect(oauth.status).toBe(201);
  });

  it("lists connections grouped, with app credentials annotated", async () => {
    store.setCredential("github", "ziv", { pat: "ghp_LongPatToken1234567890" });
    const r = await api("GET", "/api/connections");
    expect(r.status).toBe(200);
    expect(r.json.llm.length).toBe(4);
    const anthropic = r.json.llm.filter((c: any) => c.vendor === "anthropic");
    expect(anthropic.map((c: any) => c.isDefault)).toEqual([true, false]);
    expect(r.text).not.toContain("sk-ant");
    expect(r.text).not.toContain("ghp_LongPatToken");
    const gh = r.json.apps.find((c: any) => c.vendor === "github");
    expect(gh.kind).toBe("app");
    expect(gh.integration.title).toBe("GitHub");
    expect(gh.orphaned).toBe(false);
    // App credential carries a masked preview of its primary secret field
    // (github pat). First 12 plus last 4, and never the raw value.
    expect(gh.secretPreview).toBe("ghp_LongPatT...7890");
    expect(gh.secretPreview).not.toContain("Token1234");
    // Every LLM connection carries a preview that is not the raw secret.
    for (const c of r.json.llm) {
      expect(typeof c.secretPreview).toBe("string");
      expect(c.secretPreview).toContain("...");
    }
  });

  it("flags app credentials of unregistered integrations as orphaned", async () => {
    store.setCredential("ghost", "old cred", { apiKey: "x" });
    const r = await api("GET", "/api/connections");
    const ghost = r.json.apps.find((c: any) => c.vendor === "ghost");
    expect(ghost.orphaned).toBe(true);
    expect(ghost.integration).toBeNull();
    store.deleteCredential("ghost");
  });

  it("edits name, data and default; validates against the vendor", async () => {
    const rename = await api("PUT", `/api/connections/${backupId}`, { name: "Anthropic - new backup" });
    expect(rename.status).toBe(200);
    expect(rename.json.name).toBe("Anthropic - new backup");

    // An empty data object means "keep the stored secret", not a validation
    // error. The stored secret must survive untouched.
    const keep = await api("PUT", `/api/connections/${backupId}`, { data: {} });
    expect(keep.status).toBe(200);
    expect(store.getConnection(backupId)!.data.apiKey).toBe("sk-ant-2");

    // A non-empty but invalid data shape still fails validation.
    const badData = await api("PUT", `/api/connections/${backupId}`, { data: { authMode: "weird" } });
    expect(badData.status).toBe(400);
    expect(badData.json.error).toBe("invalid_data");

    const move = await api("PUT", `/api/connections/${backupId}`, { isDefault: true });
    expect(move.json.isDefault).toBe(true);
    expect(store.getConnection(primaryId)!.isDefault).toBe(false);

    expect((await api("PUT", "/api/connections/conn_missing", { name: "x" })).status).toBe(404);
    expect((await api("PUT", `/api/connections/${backupId}`, { isDefault: "yes" })).status).toBe(400);
    expect((await api("PUT", `/api/connections/${backupId}`, { name: " " })).status).toBe(400);
  });

  it("delete removes the connection from agent configs and resets their state", async () => {
    const { agent } = store.createAgent("llm-user");
    store.setAgentLlmConfig(agent.id, {
      enabled: true,
      strategy: "fallback",
      connectionIds: [backupId, primaryId],
    });
    store.setLlmStrategyState(agent.id, "anthropic", {
      activeIndex: 1,
      rrCursor: 0,
      callsSinceFallback: 3,
      cooldowns: { [backupId]: 5 },
    });

    expect((await api("DELETE", `/api/connections/${backupId}`)).status).toBe(204);
    expect(store.getConnection(backupId)).toBeNull();
    expect(store.getAgentLlmConfig(agent.id)!.connectionIds).toEqual([primaryId]);
    const state = store.getLlmStrategyState(agent.id, "anthropic");
    expect(state.activeIndex).toBe(0);
    expect(state.cooldowns).toEqual({});
    // The deleted default moved to the remaining anthropic connection.
    expect(store.getConnection(primaryId)!.isDefault).toBe(true);
    // Deleting a missing connection is a no-op 204.
    expect((await api("DELETE", `/api/connections/${backupId}`)).status).toBe(204);
    store.deleteAgent(agent.id);
  });
});

describe("anthropic auth-token connections", () => {
  it("creates an auth-token connection (inferred from authToken) and persists it", async () => {
    const r = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "anthropic",
      name: "Anthropic - sub A",
      data: { authToken: "oat_sub_a" },
    });
    expect(r.status).toBe(201);
    expect(r.text).not.toContain("oat_sub_a");
    const conn = store.getConnection(r.json.id)!;
    expect(conn.vendor).toBe("anthropic");
    expect(conn.data.authToken).toBe("oat_sub_a");
    store.deleteConnection(conn.id);
  });

  it("creates an auth-token connection with an explicit authMode discriminator", async () => {
    const r = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "anthropic",
      name: "Anthropic - sub B",
      data: { authMode: "auth_token", authToken: "oat_sub_b" },
    });
    expect(r.status).toBe(201);
    const conn = store.getConnection(r.json.id)!;
    expect(conn.data.authMode).toBe("auth_token");
    expect(conn.data.authToken).toBe("oat_sub_b");
    store.deleteConnection(conn.id);
  });

  it("rejects an auth-token mode with no token, and a bad authMode value", async () => {
    const noToken = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "anthropic",
      name: "x",
      data: { authMode: "auth_token" },
    });
    expect(noToken.status).toBe(400);
    expect(noToken.json.error).toBe("invalid_data");
    expect(noToken.json.message).toContain("authToken");

    const badMode = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "anthropic",
      name: "x",
      data: { authMode: "weird", authToken: "t" },
    });
    expect(badMode.status).toBe(400);
    expect(badMode.json.error).toBe("invalid_data");
    expect(badMode.json.message).toContain("authMode");
  });

  it("still accepts an api-key connection and an explicit api_key authMode", async () => {
    const keyConn = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "anthropic",
      name: "Anthropic - key",
      data: { apiKey: "sk-ant-key" },
    });
    expect(keyConn.status).toBe(201);
    store.deleteConnection(keyConn.json.id);

    const explicit = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "anthropic",
      name: "Anthropic - explicit key",
      data: { authMode: "api_key", apiKey: "sk-ant-key2" },
    });
    expect(explicit.status).toBe(201);
    store.deleteConnection(explicit.json.id);

    const explicitNoKey = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "anthropic",
      name: "x",
      data: { authMode: "api_key" },
    });
    expect(explicitNoKey.status).toBe(400);
    expect(explicitNoKey.json.message).toContain("apiKey");
  });
});

describe("per-agent LLM config", () => {
  let agentId: string;
  let connId: string;

  beforeAll(() => {
    const { agent } = store.createAgent("router");
    agentId = agent.id;
    connId = store.createConnection({
      kind: "llm",
      vendor: "gemini",
      name: "Gemini",
      data: { apiKey: "AIza" },
    }).id;
  });

  it("404s for unknown agents", async () => {
    expect((await api("GET", "/api/agents/ag_missing/llm")).status).toBe(404);
    expect(
      (await api("PUT", "/api/agents/ag_missing/llm", { enabled: true, strategy: "fallback", connectionIds: [] }))
        .status,
    ).toBe(404);
  });

  it("returns a disabled default when no config exists", async () => {
    const r = await api("GET", `/api/agents/${agentId}/llm`);
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ agentId, enabled: false, strategy: "fallback", connectionIds: [] });
  });

  it("validates the config payload", async () => {
    const base = { enabled: true, strategy: "fallback", connectionIds: [connId] };
    expect((await api("PUT", `/api/agents/${agentId}/llm`, { ...base, enabled: "yes" })).status).toBe(400);
    expect((await api("PUT", `/api/agents/${agentId}/llm`, { ...base, strategy: "random" })).status).toBe(400);
    expect((await api("PUT", `/api/agents/${agentId}/llm`, { ...base, connectionIds: "x" })).status).toBe(400);
    expect(
      (await api("PUT", `/api/agents/${agentId}/llm`, { ...base, connectionIds: [connId, connId] })).status,
    ).toBe(400);
    const unknown = await api("PUT", `/api/agents/${agentId}/llm`, { ...base, connectionIds: ["conn_gone"] });
    expect(unknown.status).toBe(400);
    expect(unknown.json.error).toBe("unknown_connection");
  });

  it("sets the config and resets the agent's strategy state", async () => {
    store.setLlmStrategyState(agentId, "gemini", {
      activeIndex: 2,
      rrCursor: 1,
      callsSinceFallback: 7,
      cooldowns: { [connId]: 4 },
    });
    const r = await api("PUT", `/api/agents/${agentId}/llm`, {
      enabled: true,
      strategy: "round-robin",
      connectionIds: [connId],
    });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ enabled: true, strategy: "round-robin", connectionIds: [connId] });
    const state = store.getLlmStrategyState(agentId, "gemini");
    expect(state.activeIndex).toBe(0);
    expect(state.callsSinceFallback).toBe(0);
    expect(state.cooldowns).toEqual({});

    const got = await api("GET", `/api/agents/${agentId}/llm`);
    expect(got.json.strategy).toBe("round-robin");
  });
});

describe("usage endpoint", () => {
  let connId: string;

  beforeAll(() => {
    connId = store.createConnection({
      kind: "llm",
      vendor: "anthropic",
      name: "usage conn",
      data: { apiKey: "k" },
    }).id;
    store.recordLlmUsage({
      connectionId: connId,
      connectionName: "usage conn",
      agentId: "ag_1",
      vendor: "anthropic",
      strategy: "fallback",
      inputTokens: 100,
      outputTokens: 25,
      status: 200,
    });
    store.recordLlmUsage({
      connectionId: connId,
      connectionName: "usage conn",
      agentId: "ag_1",
      vendor: "anthropic",
      strategy: "fallback",
      errors: 1,
      failover: true,
      status: 429,
    });
  });

  it("rolls up per connection and per vendor with a recent log", async () => {
    const r = await api("GET", "/api/usage");
    expect(r.status).toBe(200);
    expect(r.json.since).toBeTruthy();
    const conn = r.json.connections.find((c: any) => c.connectionId === connId);
    expect(conn).toMatchObject({
      connectionName: "usage conn",
      vendor: "anthropic",
      requests: 2,
      errors: 1,
      failovers: 1,
      inputTokens: 100,
      outputTokens: 25,
    });
    const vendor = r.json.vendors.find((v: any) => v.vendor === "anthropic");
    expect(vendor.requests).toBeGreaterThanOrEqual(2);

    const recent = r.json.recent.filter((e: any) => e.connectionId === connId);
    expect(recent).toHaveLength(2);
    expect(recent[0]).toMatchObject({ outcome: "error", failover: true, status: 429 });
    expect(recent[1]).toMatchObject({
      outcome: "ok",
      failover: false,
      strategy: "fallback",
      inputTokens: 100,
      outputTokens: 25,
    });
  });

  it("honors the time range and limit", async () => {
    const future = await api("GET", `/api/usage?since=${encodeURIComponent("2099-01-01T00:00:00Z")}`);
    expect(future.json.connections).toEqual([]);
    expect(future.json.recent).toEqual([]);

    const past = await api("GET", `/api/usage?until=${encodeURIComponent("2000-01-01T00:00:00Z")}`);
    expect(past.json.connections).toEqual([]);

    const limited = await api("GET", "/api/usage?limit=1");
    expect(limited.json.recent).toHaveLength(1);
  });

  it("rejects malformed parameters", async () => {
    expect((await api("GET", "/api/usage?since=banana")).status).toBe(400);
    expect((await api("GET", "/api/usage?until=banana")).status).toBe(400);
    expect((await api("GET", "/api/usage?limit=0")).status).toBe(400);
    expect((await api("GET", "/api/usage?limit=x")).status).toBe(400);
  });
});

describe("orphaned credentials on /api/integrations (issue #3886)", () => {
  it("surfaces credentials of unregistered integrations with a disconnect path", async () => {
    store.setCredential("disabled-thing", "stranded cred", { apiKey: "x" });
    const r = await api("GET", "/api/integrations");
    const orphan = r.json.find((i: any) => i.id === "disabled-thing");
    expect(orphan).toBeTruthy();
    expect(orphan.orphaned).toBe(true);
    expect(orphan.connected).toBe(true);
    expect(orphan.credentialName).toBe("stranded cred");
    expect(r.json.find((i: any) => i.id === "github").orphaned).toBe(false);

    // DELETE /api/credentials/:id works without a registry check.
    expect((await api("DELETE", "/api/credentials/disabled-thing")).status).toBe(204);
    const after = await api("GET", "/api/integrations");
    expect(after.json.find((i: any) => i.id === "disabled-thing")).toBeUndefined();
  });
});

describe("connection authMode + hasSecret on /api/connections", () => {
  const ids: string[] = [];
  afterAll(() => {
    for (const id of ids) store.deleteConnection(id);
  });

  it("reports hasSecret and the anthropic auth mode without leaking the secret", async () => {
    const keyConn = store.createConnection({
      kind: "llm",
      vendor: "anthropic",
      name: "Anthropic - key",
      data: { authMode: "api_key", apiKey: "sk-ant-secretvalue" },
    });
    const tokenConn = store.createConnection({
      kind: "llm",
      vendor: "anthropic",
      name: "Anthropic - sub",
      data: { authToken: "oat_secretvalue" },
    });
    ids.push(keyConn.id, tokenConn.id);

    const r = await api("GET", "/api/connections");
    expect(r.status).toBe(200);
    const key = r.json.llm.find((c: any) => c.id === keyConn.id);
    const token = r.json.llm.find((c: any) => c.id === tokenConn.id);

    expect(key.authMode).toBe("api_key");
    expect(key.hasSecret).toBe(true);
    expect(token.authMode).toBe("auth_token"); // inferred from authToken presence
    expect(token.hasSecret).toBe(true);

    // The secret material is never present anywhere in the response.
    expect(r.text).not.toContain("sk-ant-secretvalue");
    expect(r.text).not.toContain("oat_secretvalue");
    expect(key.apiKey).toBeUndefined();
    expect(key.data).toBeUndefined();
    expect(token.authToken).toBeUndefined();
  });

  it("reports the openai auth mode (api_key vs auth_json) without the secret", async () => {
    const keyConn = store.createConnection({
      kind: "llm",
      vendor: "openai",
      name: "OpenAI - key",
      data: { apiKey: "sk-oai-secret" },
    });
    const importConn = store.createConnection({
      kind: "llm",
      vendor: "openai",
      name: "OpenAI - import",
      data: { accessToken: "at-secret", accountId: "acc_1" },
    });
    ids.push(keyConn.id, importConn.id);

    const r = await api("GET", "/api/connections");
    const key = r.json.llm.find((c: any) => c.id === keyConn.id);
    const imp = r.json.llm.find((c: any) => c.id === importConn.id);
    expect(key.authMode).toBe("api_key");
    expect(imp.authMode).toBe("auth_json");
    expect(imp.hasSecret).toBe(true);
    expect(r.text).not.toContain("sk-oai-secret");
    expect(r.text).not.toContain("at-secret");
  });

  it("app credentials carry hasSecret true and no secret", async () => {
    store.setCredential("github", "ziv", { pat: "ghp_xyz" });
    const r = await api("GET", "/api/connections");
    const gh = r.json.apps.find((c: any) => c.vendor === "github");
    expect(gh.hasSecret).toBe(true);
    expect(r.text).not.toContain("ghp_xyz");
  });

  it("update without data preserves the stored secret", async () => {
    const conn = store.createConnection({
      kind: "llm",
      vendor: "anthropic",
      name: "Anthropic - preserve",
      data: { authMode: "api_key", apiKey: "sk-ant-keepme" },
    });
    ids.push(conn.id);

    // Rename only, no data field at all.
    const renamed = await api("PUT", `/api/connections/${conn.id}`, { name: "Anthropic - renamed" });
    expect(renamed.status).toBe(200);
    expect(renamed.json.name).toBe("Anthropic - renamed");
    expect(renamed.json.hasSecret).toBe(true);
    expect(store.getConnection(conn.id)!.data.apiKey).toBe("sk-ant-keepme");

    // Replacing the secret works when a non-empty data is sent.
    const replaced = await api("PUT", `/api/connections/${conn.id}`, {
      data: { authMode: "api_key", apiKey: "sk-ant-new" },
    });
    expect(replaced.status).toBe(200);
    expect(store.getConnection(conn.id)!.data.apiKey).toBe("sk-ant-new");
  });
});

describe("audit Connection name on /api/audit", () => {
  it("resolves the stored connection id to its current name, falling back when deleted", async () => {
    const conn = store.createConnection({
      kind: "llm",
      vendor: "anthropic",
      name: "Audit Conn Original",
      data: { apiKey: "sk-ant-audit" },
    });
    const { agent } = store.createAgent("audit-agent");

    // An LLM-routed audit row references the connection.
    store.audit({
      agentId: agent.id,
      agentName: "audit-agent",
      host: "api.anthropic.com",
      method: "POST",
      path: "/v1/messages",
      decision: "allow",
      status: 200,
      connectionId: conn.id,
      connectionName: "Audit Conn Original",
      llmVendor: "anthropic",
      llmStrategy: "fallback",
      llmFailover: false,
    });
    // A non-LLM row has no connection.
    store.audit({
      host: "example.com",
      decision: "passthrough",
      status: 200,
    });

    let r = await api("GET", `/api/audit?agentId=${agent.id}`);
    expect(r.status).toBe(200);
    expect(r.json[0].llmConnectionName).toBe("Audit Conn Original");

    // Rename the connection: the audit endpoint reflects the CURRENT name.
    store.updateConnection(conn.id, { name: "Audit Conn Renamed" });
    r = await api("GET", `/api/audit?agentId=${agent.id}`);
    expect(r.json[0].llmConnectionName).toBe("Audit Conn Renamed");

    // A non-LLM-routed row has a null connection name.
    const all = await api("GET", "/api/audit");
    const passthrough = all.json.find((x: any) => x.host === "example.com");
    expect(passthrough.llmConnectionName).toBeNull();

    // Delete the connection: the endpoint falls back to the captured name.
    store.deleteConnection(conn.id);
    r = await api("GET", `/api/audit?agentId=${agent.id}`);
    expect(r.json[0].llmConnectionName).toBe("Audit Conn Original");

    store.deleteAgent(agent.id);
  });
});

describe("openrouter LLM connections", () => {
  it("creates an openrouter connection without echoing the secret", async () => {
    const r = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "openrouter",
      name: "OpenRouter - prod",
      data: { apiKey: "sk-or-v1-secret-key-value" },
    });
    expect(r.status).toBe(201);
    expect(r.json.vendor).toBe("openrouter");
    expect(r.json.data).toBeUndefined();
    expect(r.text).not.toContain("sk-or-v1-secret-key-value");
    expect(r.json.secretPreview).toBe("sk-or-v1-sec...alue");

    const noKey = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "openrouter",
      name: "OpenRouter - bad",
      data: {},
    });
    expect(noKey.status).toBe(400);
    expect(noKey.json.error).toBe("invalid_data");
  });
});

describe("derived LLM mode on agents list and per-agent llm endpoint", () => {
  it("list carries llmMode and the llm endpoint carries a matching mode", async () => {
    // Seed a connection (anthropic, llm).
    const conn = store.createConnection({
      kind: "llm",
      vendor: "anthropic",
      name: "Mode Test Conn",
      data: { apiKey: "k" },
    });

    // Agent A: enabled route + conn + allow rule => managed.
    const { agent: managed } = store.createAgent("mode-managed", { defaultPolicy: "deny-unmatched" });
    store.createRule({
      scope: "agent",
      subjectId: managed.id,
      integrationId: "anthropic",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
    store.setAgentLlmConfig(managed.id, {
      enabled: true,
      strategy: "fallback",
      connectionIds: [conn.id],
    });

    // Agent B: route DISABLED but conn attached => blocked (the Ezer bug).
    const { agent: blocked } = store.createAgent("mode-blocked", { defaultPolicy: "allow-all" });
    store.setAgentLlmConfig(blocked.id, {
      enabled: false,
      strategy: "fallback",
      connectionIds: [conn.id],
    });

    // Agent C: no route at all => passthrough.
    const { agent: passthrough } = store.createAgent("mode-passthrough", {
      defaultPolicy: "deny-unmatched",
    });

    const list = await api("GET", "/api/agents");
    expect(list.status).toBe(200);
    const byId = Object.fromEntries(list.json.map((a: any) => [a.id, a]));
    expect(byId[managed.id].llmMode).toBe("managed");
    expect(byId[blocked.id].llmMode).toBe("blocked");
    expect(byId[passthrough.id].llmMode).toBe("passthrough");

    const llmA = await api("GET", `/api/agents/${managed.id}/llm`);
    expect(llmA.status).toBe(200);
    expect(llmA.json.mode).toBe("managed");
    expect(llmA.json.enabled).toBe(true);

    const llmB = await api("GET", `/api/agents/${blocked.id}/llm`);
    expect(llmB.json.mode).toBe("blocked");

    const llmC = await api("GET", `/api/agents/${passthrough.id}/llm`);
    expect(llmC.json.mode).toBe("passthrough");
    expect(llmC.json.enabled).toBe(false);

    store.deleteAgent(managed.id);
    store.deleteAgent(blocked.id);
    store.deleteAgent(passthrough.id);
  });
});
