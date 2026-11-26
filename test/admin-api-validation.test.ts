/**
 * Admin API input validation and not-found handling for the authenticated
 * routes: every refusal must return a precise 4xx error code AND leave the
 * store unchanged. Complements admin.test.ts / app-connections-admin.test.ts /
 * llm-admin.test.ts, which cover the happy paths.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Registry } from "../src/integrations/types.js";
import { buildRegistry } from "../src/integrations/index.js";
import { ClusterError } from "../src/cluster/state.js";
import { hashToken } from "../src/store/db.js";
import { startAdmin, type AdminHarness } from "./admin-harness.js";

let h: AdminHarness;
let agentId: string;
let projectId: string;

beforeAll(async () => {
  h = await startAdmin({ publicBaseUrl: "https://gate.example" });
  agentId = h.store.createAgent("val-bot").agent.id;
  projectId = h.store.createProject("val-project").id;
});

afterAll(async () => {
  await h.close();
});

async function appConn(name: string, extra: Record<string, unknown> = {}) {
  const r = await h.api("POST", "/api/connections", {
    kind: "app",
    vendor: "hetzner",
    name,
    data: { apiToken: `hz-${name}` },
    ...extra,
  });
  expect(r.status).toBe(201);
  return r.json as { id: string };
}

async function llmConn(name: string) {
  const r = await h.api("POST", "/api/connections", {
    kind: "llm",
    vendor: "openai",
    name,
    data: { apiKey: "sk-test-openai" },
  });
  expect(r.status).toBe(201);
  return r.json as { id: string };
}

describe("agents and projects", () => {
  it("duplicate names are a 409 and do not create a second row", async () => {
    const before = h.store.listAgents().length;
    const dup = await h.api("POST", "/api/agents", { name: "val-bot" });
    expect(dup.status).toBe(409);
    expect(h.store.listAgents().length).toBe(before);
    const pdup = await h.api("POST", "/api/projects", { name: "val-project" });
    expect(pdup.status).toBe(409);
  });

  it("PATCH and rotate-token 404 an unknown agent", async () => {
    expect((await h.api("PATCH", "/api/agents/ag_missing", { name: "x" })).status).toBe(404);
    expect((await h.api("POST", "/api/agents/ag_missing/rotate-token", {})).status).toBe(404);
  });

  it("rotate-token returns a new token and invalidates the old one", async () => {
    const created = await h.api("POST", "/api/agents", { name: "rotating" });
    const old = created.json.token as string;
    const r = await h.api("POST", `/api/agents/${created.json.id}/rotate-token`, {});
    expect(r.status).toBe(200);
    expect(r.json.token).not.toBe(old);
    expect(h.store.getAgentByToken(old)).toBeNull();
    expect(h.store.getAgentByToken(r.json.token)?.id).toBe(created.json.id);
  });
});

describe("integration leases", () => {
  it("404s an unknown integration", async () => {
    const r = await h.api("PUT", "/api/integration-leases/nope", { ttlSeconds: 60 });
    expect(r.status).toBe(404);
    expect(r.json.error).toBe("unknown_integration");
  });

  it("rejects non-positive, fractional and non-numeric TTLs without changing the default", async () => {
    h.store.setIntegrationLease("github", 600);
    for (const ttlSeconds of [-5, 1.5, "abc", "", {}]) {
      const r = await h.api("PUT", "/api/integration-leases/github", { ttlSeconds });
      expect({ ttlSeconds, status: r.status, error: r.json.error }).toEqual({
        ttlSeconds,
        status: 400,
        error: "ttl_seconds_positive_integer_required",
      });
    }
    expect(h.store.getIntegrationLease("github")).toBe(600);
  });

  it("sets, lists, and clears via 0, '0', null, and DELETE", async () => {
    for (const clear of [0, "0", null]) {
      expect((await h.api("PUT", "/api/integration-leases/github", { ttlSeconds: 3600 })).json).toEqual({
        integrationId: "github",
        ttlSeconds: 3600,
      });
      const list = await h.api("GET", "/api/integration-leases");
      expect(list.json.find((l: { integrationId: string }) => l.integrationId === "github")?.ttlSeconds).toBe(3600);
      const r = await h.api("PUT", "/api/integration-leases/github", { ttlSeconds: clear });
      expect(r.json).toEqual({ integrationId: "github", ttlSeconds: null });
      expect(h.store.getIntegrationLease("github")).toBeNull();
    }
    h.store.setIntegrationLease("github", 60);
    const del = await h.api("DELETE", "/api/integration-leases/github");
    expect(del.json).toEqual({ integrationId: "github", ttlSeconds: null });
    expect(h.store.getIntegrationLease("github")).toBeNull();
  });
});

describe("legacy credentials", () => {
  it("requires a data object", async () => {
    for (const body of [{}, { data: "ghp_x" }, { data: null }]) {
      const r = await h.api("PUT", "/api/credentials/github", body);
      expect(r.status).toBe(400);
      expect(r.json.error).toBe("data_required");
    }
    expect(h.store.getCredential("github")).toBeNull();
  });

  it("runs the integration's own validator", async () => {
    const r = await h.api("PUT", "/api/credentials/datadog", { data: { apiKey: "k", site: "not-a-site" } });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("invalid_data");
    expect(h.store.getCredential("datadog")).toBeNull();
  });

  it("stores under the integration id when no name is given, and DELETE removes it", async () => {
    const r = await h.api("PUT", "/api/credentials/github", { data: { pat: "ghp_legacy" } });
    expect(r.status).toBe(200);
    expect(r.json.name).toBe("github");
    expect(r.json).not.toHaveProperty("data");
    expect((await h.api("DELETE", "/api/credentials/github")).status).toBe(204);
    expect(h.store.getCredential("github")).toBeNull();
  });
});

describe("POST /api/connections validation", () => {
  const count = () => h.store.listConnections().length;

  it.each([
    [{ kind: "ssh", vendor: "github", name: "n" }, "unsupported_kind"],
    [{ kind: "app", vendor: "github", name: "   " }, "name_required"],
    [{ kind: "app", vendor: 42, name: "n" }, "unknown_vendor"],
    [{ kind: "app", vendor: "gitlab", name: "n", data: { accessToken: "x" } }, "oauth_connection"],
    [{ kind: "app", vendor: "github", name: "n", data: { pat: "x" }, ownerAgentId: "ag_nope" }, "unknown_agent"],
    [{ kind: "app", vendor: "github", name: "n", data: { pat: "x" }, ownerAgentId: 7 }, "unknown_agent"],
    [{ kind: "app", vendor: "github", name: "n", data: ["x"] }, "invalid_data"],
    [{ kind: "app", vendor: "github", name: "n", data: { pat: "x", extra: "y" } }, "invalid_data"],
    [{ kind: "app", vendor: "github", name: "n", data: { pat: 5 } }, "invalid_data"],
    [{ kind: "app", vendor: "github", name: "n", data: { pat: "" } }, "invalid_data"],
    [{ kind: "app", vendor: "datadog", name: "n", data: { apiKey: "k", site: "nowhere" } }, "invalid_data"],
    [{ kind: "llm", vendor: "github", name: "n", data: { apiKey: "x" } }, "unknown_vendor"],
    [{ kind: "llm", vendor: "openai", name: "n", data: "sk" }, "invalid_data"],
    [{ kind: "llm", vendor: "openai", name: "n", data: { apiKey: 1 } }, "invalid_data"],
    [{ kind: "llm", vendor: "openai", name: "n", data: {} }, "invalid_data"],
    [{ kind: "llm", vendor: "gemini", name: "n", data: { other: "x" } }, "invalid_data"],
    [{ kind: "llm", vendor: "anthropic", name: "n", data: { authMode: "cookie", apiKey: "x" } }, "invalid_data"],
    [{ kind: "llm", vendor: "anthropic", name: "n", data: { authMode: "auth_token" } }, "invalid_data"],
    [{ kind: "llm", vendor: "anthropic", name: "n", data: { authMode: "api_key" } }, "invalid_data"],
    [{ kind: "llm", vendor: "anthropic", name: "n", data: {} }, "invalid_data"],
  ])("refuses %j with %s and persists nothing", async (body, error) => {
    const before = count();
    const r = await h.api("POST", "/api/connections", body);
    expect(r.status).toBe(400);
    expect(r.json.error).toBe(error);
    expect(count()).toBe(before);
  });

  it("names the offending field in the validation message", async () => {
    const r = await h.api("POST", "/api/connections", {
      kind: "app",
      vendor: "github",
      name: "n",
      data: { pat: "x", stowaway: "y" },
    });
    expect(r.json.message).toBe('unknown field "stowaway"');
    const r2 = await h.api("POST", "/api/connections", { kind: "app", vendor: "github", name: "n", data: { pat: 5 } });
    expect(r2.json.message).toBe("data.pat must be a string");
  });

  it("instance origin: unsupported integration, reserved builtin host, and a second claim are refused", async () => {
    const unsupported = await h.api("POST", "/api/connections", {
      kind: "app",
      vendor: "github",
      name: "gh-selfhost",
      data: { pat: "x" },
      instanceOrigin: "https://git.acme.example",
    });
    expect(unsupported.status).toBe(400);
    expect(unsupported.json.error).toBe("instance_origin_unsupported");

    const jfrog = (origin: string, name: string) =>
      h.api("POST", "/api/connections", {
        kind: "app",
        vendor: "jfrog-artifactory",
        name,
        data: { token: "eyJ", host: new URL(origin).host },
        instanceOrigin: origin,
      });
    // api.github.com belongs to a builtin: claiming it would redirect GitHub
    // traffic onto this credential.
    const reserved = await jfrog("https://api.github.com", "hijack");
    expect(reserved.status).toBe(400);
    expect(reserved.json.error).toBe("instance_origin_reserved_host");

    const ok = await jfrog("https://artifacts.acme.example", "jf-1");
    expect(ok.status).toBe(201);
    expect(ok.json.instanceOrigin).toBe("https://artifacts.acme.example");
    const clash = await jfrog("https://ARTIFACTS.acme.example/", "jf-2");
    expect(clash.status).toBe(400);
    expect(clash.json.error).toBe("instance_origin_conflict");
    expect(clash.json.message).toContain(ok.json.id);
  });
});

describe("PUT /api/connections/:id validation", () => {
  it("404s an unknown connection", async () => {
    expect((await h.api("PUT", "/api/connections/conn_missing", { name: "x" })).status).toBe(404);
  });

  it("rejects a blank name, a non-boolean isDefault, and an owner change", async () => {
    const c = await appConn("put-target");
    for (const [body, error] of [
      [{ name: "  " }, "invalid_name"],
      [{ name: 3 }, "invalid_name"],
      [{ isDefault: "yes" }, "invalid_is_default"],
      [{ ownerAgentId: agentId }, "owner_immutable"],
    ] as const) {
      const r = await h.api("PUT", `/api/connections/${c.id}`, body);
      expect({ body, status: r.status, error: r.json.error }).toEqual({ body, status: 400, error });
    }
    expect(h.store.getConnection(c.id)?.name).toBe("put-target");
    // Re-stating the current (null) owner is not a change.
    expect((await h.api("PUT", `/api/connections/${c.id}`, { ownerAgentId: null })).status).toBe(200);
  });

  it("empty data keeps the stored secret; invalid data is refused", async () => {
    const c = await appConn("keep-secret");
    const keep = await h.api("PUT", `/api/connections/${c.id}`, { name: "renamed", data: {} });
    expect(keep.status).toBe(200);
    expect(h.store.getConnection(c.id)?.data).toEqual({ apiToken: "hz-keep-secret" });
    const bad = await h.api("PUT", `/api/connections/${c.id}`, { data: { apiToken: "" } });
    expect(bad.status).toBe(400);
    expect(h.store.getConnection(c.id)?.data).toEqual({ apiToken: "hz-keep-secret" });
    const llm = await llmConn("llm-put");
    const badLlm = await h.api("PUT", `/api/connections/${llm.id}`, { data: { nothing: "" } });
    expect(badLlm.status).toBe(400);
  });

  it("instanceOrigin is refused on LLM connections", async () => {
    const llm = await llmConn("llm-origin");
    const r = await h.api("PUT", `/api/connections/${llm.id}`, { instanceOrigin: "https://x.example" });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("instance_origin_unsupported");
  });

  it("re-claiming its own origin is allowed; clearing it with null releases the claim", async () => {
    const r = await h.api("POST", "/api/connections", {
      kind: "app",
      vendor: "jfrog-artifactory",
      name: "jf-reclaim",
      data: { token: "eyJ", host: "reclaim.acme.example" },
      instanceOrigin: "https://reclaim.acme.example",
    });
    const id = r.json.id;
    const same = await h.api("PUT", `/api/connections/${id}`, { instanceOrigin: "https://reclaim.acme.example" });
    expect(same.status).toBe(200);
    const cleared = await h.api("PUT", `/api/connections/${id}`, { instanceOrigin: null });
    expect(cleared.json.instanceOrigin).toBeNull();
    expect(h.store.getConnectionByInstanceOrigin("https://reclaim.acme.example")).toBeNull();
  });

  it("a connection whose integration is no longer registered cannot take new data or an origin", async () => {
    const orphan = h.store.createConnection({ kind: "app", vendor: "retired-vendor", name: "orphan", data: { k: "v" } });
    const data = await h.api("PUT", `/api/connections/${orphan.id}`, { data: { k: "new" } });
    expect(data.status).toBe(400);
    expect(data.json.message).toBe('unknown integration "retired-vendor"');
    const origin = await h.api("PUT", `/api/connections/${orphan.id}`, { instanceOrigin: "https://x.example" });
    expect(origin.status).toBe(400);
    expect(origin.json.error).toBe("unknown_vendor");
    // Still listed (flagged orphaned) so it can be deleted.
    const list = await h.api("GET", "/api/connections");
    expect(list.json.apps.find((a: { id: string }) => a.id === orphan.id)?.orphaned).toBe(true);
    expect((await h.api("DELETE", `/api/connections/${orphan.id}`)).status).toBe(204);
  });
});

describe("connection activate / deactivate", () => {
  it("404s unknown connections and rejects a non-string reason", async () => {
    expect((await h.api("POST", "/api/connections/conn_missing/activate", {})).status).toBe(404);
    expect((await h.api("POST", "/api/connections/conn_missing/deactivate", {})).status).toBe(404);
    const c = await appConn("bench-me");
    const r = await h.api("POST", `/api/connections/${c.id}/deactivate`, { reason: 42 });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("invalid_reason");
    expect(h.store.getConnection(c.id)?.inactiveAt ?? null).toBeNull();
  });

  it("deactivate benches with a reason; activate restores and drops the inactive fields", async () => {
    const c = await appConn("bench-cycle");
    const off = await h.api("POST", `/api/connections/${c.id}/deactivate`, { reason: "rotating key" });
    expect(off.status).toBe(200);
    expect(off.json.inactiveReason).toContain("rotating key");
    expect(off.json.inactiveAt).toBeTruthy();
    const on = await h.api("POST", `/api/connections/${c.id}/activate`, {});
    expect(on.status).toBe(200);
    expect(on.json).not.toHaveProperty("inactiveAt");
  });
});

describe("connection grants", () => {
  it("404s unknown and LLM connections on every grant route", async () => {
    const llm = await llmConn("llm-grants");
    for (const id of ["conn_missing", llm.id]) {
      expect((await h.api("GET", `/api/connections/${id}/grants`)).status).toBe(404);
      expect((await h.api("POST", `/api/connections/${id}/grants`, { scope: "agent", subjectId: agentId })).status).toBe(404);
      expect((await h.api("DELETE", `/api/connections/${id}/grants/agent/${agentId}`)).status).toBe(404);
    }
  });

  it("validates scope and subject before granting anything", async () => {
    const c = await appConn("grant-validate");
    for (const [body, status, error] of [
      [{ scope: "tenant", subjectId: agentId }, 400, "invalid_scope"],
      [{ scope: "agent", subjectId: "  " }, 400, "invalid_subject"],
      [{ scope: "agent", subjectId: 9 }, 400, "invalid_subject"],
      [{ scope: "agent", subjectId: "ag_nope" }, 404, "unknown_agent"],
      [{ scope: "project", subjectId: "pr_nope" }, 404, "unknown_project"],
    ] as const) {
      const r = await h.api("POST", `/api/connections/${c.id}/grants`, body);
      expect({ body, status: r.status, error: r.json.error }).toEqual({ body, status, error });
    }
    expect(h.store.listGrantsForConnection(c.id)).toEqual([]);
    const badRevoke = await h.api("DELETE", `/api/connections/${c.id}/grants/tenant/${agentId}`);
    expect(badRevoke.status).toBe(400);
  });

  it("a project grant synthesizes an allow rule once, and revoke removes the grant", async () => {
    const c = await appConn("grant-project");
    const first = await h.api("POST", `/api/connections/${c.id}/grants`, { scope: "project", subjectId: projectId });
    expect(first.status).toBe(201);
    expect(first.json.ruleCreated).toBe(true);
    const again = await h.api("POST", `/api/connections/${c.id}/grants`, { scope: "project", subjectId: projectId });
    expect(again.json.ruleCreated).toBe(false);
    expect(again.json.ruleId).toBe(first.json.ruleId);
    expect((await h.api("GET", `/api/connections/${c.id}/grants`)).json).toHaveLength(1);
    expect((await h.api("DELETE", `/api/connections/${c.id}/grants/project/${projectId}`)).status).toBe(204);
    expect(h.store.listGrantsForConnection(c.id)).toEqual([]);
  });
});

describe("per-agent LLM routing", () => {
  it("404s an unknown agent", async () => {
    expect((await h.api("GET", "/api/agents/ag_missing/llm")).status).toBe(404);
    expect((await h.api("PUT", "/api/agents/ag_missing/llm", { enabled: true })).status).toBe(404);
  });

  it("refuses malformed configs without saving them", async () => {
    const llm = await llmConn("route-a");
    const app = await appConn("route-not-llm");
    const ok = { enabled: true, strategy: "fallback", connectionIds: [llm.id] };
    for (const [patch, error] of [
      [{ enabled: "yes" }, "invalid_enabled"],
      [{ strategy: "random" }, "invalid_strategy"],
      [{ vendorStrategies: ["openai"] }, "invalid_vendor_strategies"],
      [{ vendorStrategies: "openai=fallback" }, "invalid_vendor_strategies"],
      [{ vendorStrategies: { "": "fallback" } }, "invalid_vendor_strategies"],
      [{ vendorStrategies: { openai: "random" } }, "invalid_vendor_strategies"],
      [{ connectionIds: llm.id }, "invalid_connection_ids"],
      [{ connectionIds: [llm.id, 3] }, "invalid_connection_ids"],
      [{ connectionIds: [llm.id, llm.id] }, "invalid_connection_ids"],
      [{ connectionIds: [app.id] }, "unknown_connection"],
      [{ connectionIds: ["conn_missing"] }, "unknown_connection"],
    ] as const) {
      const r = await h.api("PUT", `/api/agents/${agentId}/llm`, { ...ok, ...patch });
      expect({ patch, status: r.status, error: r.json.error }).toEqual({ patch, status: 400, error });
    }
    expect(h.store.getAgentLlmConfig(agentId)).toBeNull();
  });

  it("an empty vendorStrategies object is stored as no overrides", async () => {
    const llm = await llmConn("route-b");
    const r = await h.api("PUT", `/api/agents/${agentId}/llm`, {
      enabled: true,
      strategy: "round-robin",
      vendorStrategies: {},
      connectionIds: [llm.id],
    });
    expect(r.status).toBe(200);
    const got = await h.api("GET", `/api/agents/${agentId}/llm`);
    expect(got.json.strategy).toBe("round-robin");
    expect(got.json.vendorStrategies ?? {}).toEqual({});
    expect(got.json.connectionIds).toEqual([llm.id]);
    expect(typeof got.json.mode).toBe("string");
  });
});

describe("per-agent app account selection and connections", () => {
  it("404s an unknown agent on every per-agent route", async () => {
    for (const [method, path, body] of [
      ["GET", "/api/agents/ag_missing/apps", undefined],
      ["PUT", "/api/agents/ag_missing/apps/hetzner", { connectionId: null }],
      ["GET", "/api/agents/ag_missing/connections", undefined],
      ["GET", "/api/agents/ag_missing/notify", undefined],
      ["PUT", "/api/agents/ag_missing/notify", { webhookUrl: "https://hook.example" }],
      ["DELETE", "/api/agents/ag_missing/notify", undefined],
    ] as const) {
      const r = await h.api(method, path, body);
      expect({ method, path, status: r.status }).toEqual({ method, path, status: 404 });
    }
  });

  it("validates the integration and connection id; null clears the choice", async () => {
    const unknown = await h.api("PUT", `/api/agents/${agentId}/apps/nope`, { connectionId: "x" });
    expect(unknown.status).toBe(400);
    expect(unknown.json.error).toBe("unknown_integration");
    const nonString = await h.api("PUT", `/api/agents/${agentId}/apps/hetzner`, { connectionId: 12 });
    expect(nonString.status).toBe(400);
    expect(nonString.json.error).toBe("invalid_connection_id");
    // An agent-bound connection of ANOTHER agent is not available to this one.
    const other = h.store.createAgent("other-owner").agent.id;
    const foreign = await appConn("foreign", { ownerAgentId: other });
    const refused = await h.api("PUT", `/api/agents/${agentId}/apps/hetzner`, { connectionId: foreign.id });
    expect(refused.status).toBe(400);
    expect(refused.json.error).toBe("unknown_connection");

    const mine = await appConn("mine", { ownerAgentId: agentId });
    // Default-deny: even the agent's own connection needs a grant first.
    const ungranted = await h.api("PUT", `/api/agents/${agentId}/apps/hetzner`, { connectionId: mine.id });
    expect(ungranted.status).toBe(400);
    h.store.grantConnection(mine.id, "agent", agentId);
    const set = await h.api("PUT", `/api/agents/${agentId}/apps/hetzner`, { connectionId: mine.id });
    expect(set.status).toBe(200);
    const view = await h.api("GET", `/api/agents/${agentId}/connections`);
    expect(view.status).toBe(200);
    const clear = await h.api("PUT", `/api/agents/${agentId}/apps/hetzner`, { connectionId: "" });
    expect(clear.json).toEqual({ agentId, integrationId: "hetzner", connectionId: null, updatedAt: null });
    expect(h.store.listAgentAppConfigs(agentId)).toEqual([]);
  });
});

describe("owner notify webhook", () => {
  it("requires a non-empty string, stores it trimmed, and DELETE clears it", async () => {
    for (const webhookUrl of [undefined, "", "   ", 5]) {
      const r = await h.api("PUT", `/api/agents/${agentId}/notify`, { webhookUrl });
      expect(r.status).toBe(400);
      expect(r.json.error).toBe("invalid_webhook_url");
    }
    expect(h.store.getAgentNotify(agentId)).toBeNull();
    const set = await h.api("PUT", `/api/agents/${agentId}/notify`, { webhookUrl: "  https://hook.example/x  " });
    expect(set.json.webhookUrl).toBe("https://hook.example/x");
    expect((await h.api("GET", `/api/agents/${agentId}/notify`)).json.webhookUrl).toBe("https://hook.example/x");
    expect((await h.api("DELETE", `/api/agents/${agentId}/notify`)).status).toBe(204);
    expect((await h.api("GET", `/api/agents/${agentId}/notify`)).json.webhookUrl).toBeNull();
  });

  it("owner-notifications validates limit and status, and filters by status", async () => {
    h.store.enqueueOwnerNotification({ agentId, integrationId: "github", connectToken: "tok" });
    for (const qs of ["limit=0", "limit=abc", "limit=1.5", "status=sent"]) {
      const r = await h.api("GET", `/api/owner-notifications?${qs}`);
      expect({ qs, status: r.status }).toEqual({ qs, status: 400 });
    }
    const pending = await h.api("GET", "/api/owner-notifications?status=pending&limit=5");
    expect(pending.status).toBe(200);
    expect(pending.json.length).toBeGreaterThanOrEqual(1);
    // Only the hash of the connect token is kept.
    expect(JSON.stringify(pending.json)).not.toContain('"tok"');
    expect((await h.api("GET", "/api/owner-notifications?status=delivered")).json).toEqual([]);
  });
});

describe("usage", () => {
  it("rejects unparseable time bounds and a bad limit", async () => {
    for (const qs of ["since=yesterday", "until=soon", "limit=0", "limit=x"]) {
      const r = await h.api("GET", `/api/usage?${qs}`);
      expect({ qs, status: r.status }).toEqual({ qs, status: 400 });
    }
  });

  it("defaults to a 7-day window and normalizes explicit bounds to ISO", async () => {
    const def = await h.api("GET", "/api/usage");
    expect(def.status).toBe(200);
    const sinceMs = Date.parse(def.json.since);
    expect(Date.now() - sinceMs).toBeGreaterThan(7 * 24 * 3600 * 1000 - 60_000);
    expect(def.json.until).toBeNull();
    expect(def.json.turnEstimate).toEqual({ estimated: true, gapMs: 60_000 });
    const r = await h.api("GET", "/api/usage?since=2026-01-01&until=2026-01-02&limit=3");
    expect(r.json.since).toBe("2026-01-01T00:00:00.000Z");
    expect(r.json.until).toBe("2026-01-02T00:00:00.000Z");
  });
});

describe("admin OAuth start validation", () => {
  it.each([
    [{ connectionId: 5 }, 400, "connectionId must be a string"],
    [{ connectionId: "conn_missing" }, 404, "unknown_connection"],
    [{ connectionName: "  " }, 400, "connectionName must be a non-empty string"],
    [{ connectionName: "x", ownerAgentId: "ag_nope" }, 400, "unknown ownerAgentId"],
    [{ connectionName: "x", ownerAgentId: 1 }, 400, "unknown ownerAgentId"],
  ])("refuses %j", async (extra, status, error) => {
    const r = await h.api("POST", "/api/integrations/gitlab/oauth/start", {
      clientId: "c",
      clientSecret: "s",
      redirectBase: "https://gate.example",
      ...extra,
    });
    expect(r.status).toBe(status);
    expect(r.json.error).toBe(error);
  });

  it("refuses re-authorizing a connection that belongs to another integration", async () => {
    const hz = await appConn("not-gitlab");
    const r = await h.api("POST", "/api/integrations/gitlab/oauth/start", {
      clientId: "c",
      clientSecret: "s",
      redirectBase: "https://gate.example",
      connectionId: hz.id,
    });
    expect(r.status).toBe(404);
  });
});

describe("rules validation", () => {
  const base = () => ({ scope: "agent", subjectId: agentId, integrationId: "github", effect: "allow" });

  it.each([
    [{ action: "notify" }, 'action must be "require_approval"'],
    [{ connectionScope: "sometimes", connectionId: "conn_x" }, 'connectionScope must be "only" or "except"'],
    [{ connectionScope: "only" }, "connectionScope requires connectionId"],
    [{ connectionId: "conn_x" }, "connectionId requires connectionScope"],
  ])("refuses %j", async (extra, error) => {
    const before = h.store.listRules().length;
    const r = await h.api("POST", "/api/rules", { ...base(), ...extra });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe(error);
    expect(h.store.listRules().length).toBe(before);
  });

  it("refuses unmatchable methods with invalid_methods", async () => {
    for (const methods of [["GTE"], "GET", [1]]) {
      const r = await h.api("POST", "/api/rules", { ...base(), methods });
      expect(r.status).toBe(400);
      expect(r.json.error).toBe("invalid_methods");
    }
  });

  it("stores canonical methods and a lease only on plain allow rules", async () => {
    const leased = await h.api("POST", "/api/rules", { ...base(), methods: [" get ", "post", "GET"], ttlSeconds: 90.7 });
    expect(leased.status).toBe(201);
    expect(leased.json.methods).toEqual(["GET", "POST"]);
    expect(leased.json.leaseTtlSeconds).toBe(90);
    expect(Date.parse(leased.json.expiresAt)).toBeGreaterThan(Date.now());
    expect(leased.json.pathGlob).toBe("/**");

    const gated = await h.api("POST", "/api/rules", { ...base(), effect: "deny", action: "require_approval", ttlSeconds: 60 });
    expect(gated.status).toBe(201);
    expect(gated.json.action).toBe("require_approval");
    expect(gated.json.expiresAt).toBeNull();
    expect(gated.json.leaseTtlSeconds).toBeNull();

    const deny = await h.api("POST", "/api/rules", { ...base(), effect: "deny", ttlSeconds: 60 });
    expect(deny.json.expiresAt).toBeNull();
  });
});

describe("approvals admin API", () => {
  function hold(agent = agentId) {
    const rule = h.store.createRule({
      scope: "agent",
      subjectId: agent,
      integrationId: "github",
      methods: ["*"],
      pathGlob: "/**",
      effect: "deny",
      action: "require_approval",
    });
    return h.store.createApproval({ agentId: agent, integrationId: "github", ruleId: rule.id, method: "DELETE", path: "/repos/x" });
  }

  it("lists newest first, filters by agent, and never returns the decision token", async () => {
    const other = h.store.createAgent("approvals-other").agent.id;
    const mine = hold();
    const theirs = hold(other);
    const all = await h.api("GET", "/api/approvals");
    const ids = all.json.map((a: { id: string }) => a.id);
    expect(ids).toEqual(expect.arrayContaining([mine.id, theirs.id]));
    expect(JSON.stringify(all.json)).not.toContain(mine.token);
    const filtered = await h.api("GET", `/api/approvals?agentId=${other}`);
    expect(filtered.json.map((a: { id: string }) => a.id)).toEqual([theirs.id]);
  });

  it("the list sweeps a pending row past its expiry to expired", async () => {
    const ap = hold();
    (h.store as unknown as { db: { prepare(s: string): { run(...a: unknown[]): void } } }).db
      .prepare("UPDATE approvals SET expires_at = ? WHERE id = ?")
      .run(new Date(Date.now() - 1000).toISOString(), ap.id);
    const r = await h.api("GET", "/api/approvals");
    expect(r.json.find((a: { id: string }) => a.id === ap.id).status).toBe("expired");
    // An expired approval cannot be decided.
    const late = await h.api("POST", `/api/approvals/${ap.id}/approve`, {});
    expect(late.status).toBe(409);
    expect(h.store.getApproval(ap.id)?.status).toBe("expired");
  });

  it("approve/reject 404 an unknown id and 409 an already-decided one", async () => {
    expect((await h.api("POST", "/api/approvals/apr_missing/approve", {})).json.error).toBe("unknown_approval");
    expect((await h.api("POST", "/api/approvals/apr_missing/reject", {})).status).toBe(404);
    const ap = hold();
    const ok = await h.api("POST", `/api/approvals/${ap.id}/reject`, {});
    expect(ok.status).toBe(200);
    expect(ok.json.status).toBe("rejected");
    const flip = await h.api("POST", `/api/approvals/${ap.id}/approve`, {});
    expect(flip.status).toBe(409);
    expect(flip.json.error).toBe("approval_not_pending");
    expect(h.store.getApproval(ap.id)?.status).toBe("rejected");
  });
});

describe("onboarding links admin mint", () => {
  it("normalizes optional fields and exposes validity in the list", async () => {
    const r = await h.api("POST", "/api/onboarding-links", {
      agentId,
      integrationId: "hetzner",
      scopes: ["a", 2],
      connectionName: "  Named  ",
      ttlDays: 2,
    });
    expect(r.status).toBe(201);
    expect(r.json.url).toBe(`https://gate.example/connect/hetzner/${r.json.token}`);
    expect(Date.parse(r.json.expiresAt) - Date.now()).toBeGreaterThan(2 * 86400_000 - 60_000);
    const link = h.store.getOnboardingLink(r.json.token)!;
    expect(link.connectionName).toBe("Named");
    expect(link.scopes).toEqual(["a", "2"]);

    // A blank name and an omitted ttl fall back to the defaults (7 days).
    const d = await h.api("POST", "/api/onboarding-links", { agentId, integrationId: "hetzner", connectionName: "  " });
    expect(h.store.getOnboardingLink(d.json.token)!.connectionName).toBeNull();
    expect(Date.parse(d.json.expiresAt) - Date.now()).toBeGreaterThan(7 * 86400_000 - 60_000);

    // The admin list never carries the plaintext bearer token, only its hash,
    // and revoking by that hash works.
    const list = await h.api("GET", `/api/onboarding-links?agentId=${agentId}`);
    expect(JSON.stringify(list.json)).not.toContain(r.json.token);
    const row = list.json.find((l: { token: string }) => l.token === hashToken(r.json.token));
    expect(row).toMatchObject({ valid: true, connectionName: "Named", integrationId: "hetzner" });
    expect((await h.api("DELETE", `/api/onboarding-links/${row.token}`)).status).toBe(204);
    expect(h.store.getOnboardingLink(r.json.token)).toBeNull();
  });
});

describe("cluster routes with an injected runtime", () => {
  let c: AdminHarness;
  let removed: string[];
  let refreshed = 0;
  let initError: Error | null = null;

  beforeAll(async () => {
    removed = [];
    const fake = {
      status: () => ({ enabled: true, nodeId: "node-self", peers: [{ nodeId: "node-self", self: true }] }),
      refresh: () => {
        refreshed++;
      },
      addPeer: async () => {
        throw new ClusterError(409, "peer_exists", "already a peer");
      },
      leave: async () => {
        throw new Error("network down");
      },
      state: {
        init: () => {
          if (initError) throw initError;
        },
        peekNodeId: () => "node-self",
        removePeer: (id: string) => {
          if (id === "node-explode") throw new Error("db locked");
          if (id !== "node-peer") return false;
          removed.push(id);
          return true;
        },
        mintJoinToken: () => ({ token: "ogj_x", expiresAt: "2099-01-01T00:00:00.000Z" }),
        advertiseUrl: () => "https://node-self.example:9443",
      },
    };
    c = await startAdmin({ cluster: fake as never });
  });

  afterAll(async () => {
    await c.close();
  });

  it("init on a live gateway starts replication immediately", async () => {
    const r = await c.api("POST", "/api/cluster/init", { advertiseUrl: "https://node-self.example:9443" });
    expect(r.status).toBe(201);
    expect(refreshed).toBe(1);
  });

  it("maps a ClusterError to its status and code, anything else to a 500 cluster_error", async () => {
    const add = await c.api("POST", "/api/cluster/peers", { url: "https://p.example" });
    expect(add.status).toBe(409);
    expect(add.json).toEqual({ error: "peer_exists", message: "already a peer" });
    initError = new ClusterError(400, "bad_url");
    const init = await c.api("POST", "/api/cluster/init", {});
    expect(init.status).toBe(400);
    // message === code is not repeated.
    expect(init.json).toEqual({ error: "bad_url" });
    initError = null;
    const leave = await c.api("POST", "/api/cluster/leave", {});
    expect(leave.status).toBe(500);
    expect(leave.json).toEqual({ error: "cluster_error", message: "network down" });
  });

  it("peer removal: self is refused, unknown is 404, a real peer is removed, a failure is a 500", async () => {
    expect((await c.api("DELETE", "/api/cluster/peers/node-self")).json.error).toBe("cannot_remove_self");
    expect((await c.api("DELETE", "/api/cluster/peers/node-unknown")).status).toBe(404);
    expect((await c.api("DELETE", "/api/cluster/peers/node-peer")).status).toBe(204);
    expect(removed).toEqual(["node-peer"]);
    const boom = await c.api("DELETE", "/api/cluster/peers/node-explode");
    expect(boom.status).toBe(500);
    expect(boom.json.error).toBe("cluster_error");
  });

  it("join tokens accept numeric and duration TTLs and report the advertise URL", async () => {
    for (const ttl of [600, "15m"]) {
      const r = await c.api("POST", "/api/cluster/join-tokens", { ttl });
      expect(r.status).toBe(201);
      expect(r.json.peerUrl).toBe("https://node-self.example:9443");
    }
    const bad = await c.api("POST", "/api/cluster/join-tokens", { ttl: true });
    expect(bad.status).toBe(400);
    expect(bad.json.error).toBe("invalid_ttl");
  });
});

describe("integrations list", () => {
  it("surfaces a credential whose integration is not registered as orphaned so it can be removed", async () => {
    const full = await buildRegistry();
    const registry = new Registry();
    for (const i of full.list()) if (i.id !== "hetzner") registry.register(i);
    const o = await startAdmin({ registry });
    try {
      o.store.setCredential("hetzner", "old hetzner", { apiToken: "x" });
      const r = await o.api("GET", "/api/integrations");
      const row = r.json.find((i: { id: string }) => i.id === "hetzner");
      expect(row).toMatchObject({ orphaned: true, connected: true, category: "Disconnected", credentialName: "old hetzner" });
      expect((await o.api("DELETE", "/api/credentials/hetzner")).status).toBe(204);
      const after = await o.api("GET", "/api/integrations");
      expect(after.json.find((i: { id: string }) => i.id === "hetzner")).toBeUndefined();
    } finally {
      await o.close();
    }
  });
});
