import { describe, it, expect, beforeEach } from "vitest";
import { Store, newAgentToken, hashToken, segmentTurns, TURN_GAP_MS } from "../src/store/db.js";

let store: Store;

beforeEach(() => {
  store = new Store(":memory:");
});

describe("agents", () => {
  it("creates an agent and finds it by token", () => {
    const { agent, token } = store.createAgent("builder");
    expect(token).toMatch(/^og_[0-9a-f]{48}$/);
    expect(agent.defaultPolicy).toBe("deny-unmatched");
    const found = store.getAgentByToken(token);
    expect(found?.id).toBe(agent.id);
    expect(store.getAgentByToken("og_wrong")).toBeNull();
  });

  it("stores only the token hash", () => {
    const { agent, token } = store.createAgent("a2");
    expect(agent.tokenHash).toBe(hashToken(token));
    expect(agent.tokenHash).not.toContain(token);
  });

  it("rotates tokens", () => {
    const { agent, token } = store.createAgent("a3");
    const next = store.rotateAgentToken(agent.id)!;
    expect(next).not.toBe(token);
    expect(store.getAgentByToken(token)).toBeNull();
    expect(store.getAgentByToken(next)?.id).toBe(agent.id);
  });

  it("updates project assignment and default policy", () => {
    const project = store.createProject("research");
    const { agent } = store.createAgent("a4");
    const updated = store.updateAgent(agent.id, {
      projectId: project.id,
      defaultPolicy: "allow-all",
    })!;
    expect(updated.projectId).toBe(project.id);
    expect(updated.defaultPolicy).toBe("allow-all");
  });

  it("deleting an agent removes its rules", () => {
    const { agent } = store.createAgent("a5");
    store.createRule({
      scope: "agent",
      subjectId: agent.id,
      integrationId: "github",
      methods: ["GET"],
      pathGlob: "/**",
      effect: "allow",
    });
    store.deleteAgent(agent.id);
    expect(store.listRules({ scope: "agent", subjectId: agent.id })).toHaveLength(0);
  });
});

describe("credentials", () => {
  it("upserts one credential per integration", () => {
    store.setCredential("github", "ziv-pat", { pat: "tok1" });
    store.setCredential("github", "ziv-pat-2", { pat: "tok2" });
    const all = store.listCredentials();
    expect(all).toHaveLength(1);
    expect(all[0].data.pat).toBe("tok2");
  });
});

describe("rulesForAgent", () => {
  it("combines agent rules with project rules", () => {
    const project = store.createProject("p");
    const { agent } = store.createAgent("a", { projectId: project.id });
    store.createRule({
      scope: "agent",
      subjectId: agent.id,
      integrationId: "github",
      methods: ["GET"],
      pathGlob: "/**",
      effect: "allow",
    });
    store.createRule({
      scope: "project",
      subjectId: project.id,
      integrationId: "gmail",
      methods: ["*"],
      pathGlob: "/**",
      effect: "deny",
    });
    const rules = store.rulesForAgent(store.getAgent(agent.id)!);
    expect(rules.map((r) => r.integrationId).sort()).toEqual(["github", "gmail"]);
  });

  it("round-trips connection scoping through createRule and listRules", () => {
    const { agent } = store.createAgent("conn-scoped");
    const created = store.createRule({
      scope: "agent",
      subjectId: agent.id,
      integrationId: "github",
      methods: ["*"],
      pathGlob: "/repos/onegate-bot/onegate/**",
      effect: "deny",
      connectionId: "conn_kop",
      connectionScope: "except",
    });
    expect(created.connectionId).toBe("conn_kop");
    expect(created.connectionScope).toBe("except");
    const [loaded] = store.listRules({ scope: "agent", subjectId: agent.id });
    expect(loaded.connectionId).toBe("conn_kop");
    expect(loaded.connectionScope).toBe("except");
  });

  it("leaves connection fields null/undefined on an ordinary rule", () => {
    const { agent } = store.createAgent("plain-rule");
    const created = store.createRule({
      scope: "agent",
      subjectId: agent.id,
      integrationId: "github",
      methods: ["GET"],
      pathGlob: "/**",
      effect: "allow",
    });
    expect(created.connectionId).toBeNull();
    expect(created.connectionScope).toBeUndefined();
    const [loaded] = store.listRules({ scope: "agent", subjectId: agent.id });
    expect(loaded.connectionId).toBeNull();
    expect(loaded.connectionScope).toBeUndefined();
  });
});

describe("audit", () => {
  it("records and lists entries, newest first", () => {
    store.audit({ host: "x.com", decision: "passthrough" });
    store.audit({ host: "api.github.com", method: "GET", path: "/user", decision: "allow", status: 200 });
    const entries = store.listAudit();
    expect(entries).toHaveLength(2);
    expect(entries[0].host).toBe("api.github.com");
    expect(entries[0].status).toBe(200);
  });
});

describe("connections", () => {
  it("allows many connections per llm vendor", () => {
    store.createConnection({ kind: "llm", vendor: "anthropic", name: "prod", data: { apiKey: "k1" } });
    store.createConnection({ kind: "llm", vendor: "anthropic", name: "backup", data: { apiKey: "k2" } });
    store.createConnection({ kind: "llm", vendor: "openai", name: "oai", data: { apiKey: "k3" } });
    expect(store.listConnections({ kind: "llm", vendor: "anthropic" })).toHaveLength(2);
    expect(store.listConnections({ kind: "llm" })).toHaveLength(3);
    expect(store.listConnections()).toHaveLength(3);
  });

  it("ids are conn_ prefixed and data round-trips", () => {
    const c = store.createConnection({
      kind: "llm",
      vendor: "openai",
      name: "imported",
      data: { accessToken: "at_1", accountId: "acc_1" },
    });
    expect(c.id).toMatch(/^conn_[0-9a-f]{16}$/);
    expect(store.getConnection(c.id)?.data).toEqual({ accessToken: "at_1", accountId: "acc_1" });
  });

  it("the first connection of a vendor becomes the default automatically", () => {
    const a = store.createConnection({ kind: "llm", vendor: "anthropic", name: "a", data: {} });
    const b = store.createConnection({ kind: "llm", vendor: "anthropic", name: "b", data: {} });
    expect(store.getConnection(a.id)?.isDefault).toBe(true);
    expect(store.getConnection(b.id)?.isDefault).toBe(false);
    expect(store.getDefaultConnection("llm", "anthropic")?.id).toBe(a.id);
  });

  it("creating with isDefault demotes the previous default (exactly one per vendor)", () => {
    const a = store.createConnection({ kind: "llm", vendor: "gemini", name: "a", data: {} });
    const b = store.createConnection({ kind: "llm", vendor: "gemini", name: "b", data: {}, isDefault: true });
    expect(store.getConnection(a.id)?.isDefault).toBe(false);
    expect(store.getConnection(b.id)?.isDefault).toBe(true);
    const defaults = store.listConnections({ vendor: "gemini" }).filter((c) => c.isDefault);
    expect(defaults).toHaveLength(1);
  });

  it("defaults are tracked per vendor independently", () => {
    const a = store.createConnection({ kind: "llm", vendor: "anthropic", name: "a", data: {} });
    const o = store.createConnection({ kind: "llm", vendor: "openai", name: "o", data: {} });
    expect(store.getDefaultConnection("llm", "anthropic")?.id).toBe(a.id);
    expect(store.getDefaultConnection("llm", "openai")?.id).toBe(o.id);
  });

  it("updateConnection moves the default and patches name/data", () => {
    const a = store.createConnection({ kind: "llm", vendor: "anthropic", name: "a", data: { apiKey: "k1" } });
    const b = store.createConnection({ kind: "llm", vendor: "anthropic", name: "b", data: { apiKey: "k2" } });
    const updated = store.updateConnection(b.id, { name: "b2", isDefault: true })!;
    expect(updated.name).toBe("b2");
    expect(updated.isDefault).toBe(true);
    expect(updated.data).toEqual({ apiKey: "k2" });
    expect(store.getConnection(a.id)?.isDefault).toBe(false);
    expect(store.updateConnection("conn_missing", { name: "x" })).toBeNull();
  });

  it("ignores isDefault false on the current default (invariant holds)", () => {
    const a = store.createConnection({ kind: "llm", vendor: "anthropic", name: "a", data: {} });
    store.updateConnection(a.id, { isDefault: false });
    expect(store.getConnection(a.id)?.isDefault).toBe(true);
  });

  it("deleting the default promotes the oldest remaining connection", () => {
    const a = store.createConnection({ kind: "llm", vendor: "anthropic", name: "a", data: {} });
    const b = store.createConnection({ kind: "llm", vendor: "anthropic", name: "b", data: {} });
    const c = store.createConnection({ kind: "llm", vendor: "anthropic", name: "c", data: {} });
    store.deleteConnection(a.id);
    expect(store.getConnection(a.id)).toBeNull();
    expect(store.getDefaultConnection("llm", "anthropic")?.id).toBe(b.id);
    store.deleteConnection(b.id);
    expect(store.getDefaultConnection("llm", "anthropic")?.id).toBe(c.id);
    store.deleteConnection(c.id);
    expect(store.getDefaultConnection("llm", "anthropic")).toBeNull();
  });

  it("leaves the app credentials table completely untouched", () => {
    store.setCredential("github", "pat", { pat: "tok1" });
    store.createConnection({ kind: "llm", vendor: "anthropic", name: "a", data: { apiKey: "k" } });
    expect(store.getCredential("github")?.data.pat).toBe("tok1");
    expect(store.listCredentials()).toHaveLength(1);
    expect(store.getCredential("anthropic")).toBeNull();
  });
});

describe("agent llm config", () => {
  it("is absent until set, then upserts", () => {
    const { agent } = store.createAgent("llm-agent");
    expect(store.getAgentLlmConfig(agent.id)).toBeNull();
    const cfg = store.setAgentLlmConfig(agent.id, {
      enabled: true,
      strategy: "fallback",
      connectionIds: ["conn_a", "conn_b"],
    });
    expect(cfg.enabled).toBe(true);
    expect(cfg.strategy).toBe("fallback");
    expect(cfg.connectionIds).toEqual(["conn_a", "conn_b"]);
    const cfg2 = store.setAgentLlmConfig(agent.id, {
      enabled: false,
      strategy: "round-robin",
      connectionIds: ["conn_b"],
    });
    expect(cfg2.enabled).toBe(false);
    expect(cfg2.strategy).toBe("round-robin");
    expect(cfg2.connectionIds).toEqual(["conn_b"]);
  });

  it("round-trips vendorStrategies, and omits it when unset", () => {
    const { agent } = store.createAgent("llm-vendor-agent");
    // No vendorStrategies -> undefined on read.
    const bare = store.setAgentLlmConfig(agent.id, {
      enabled: true,
      strategy: "fallback",
      connectionIds: ["conn_a"],
    });
    expect(bare.vendorStrategies).toBeUndefined();
    expect(store.getAgentLlmConfig(agent.id)!.vendorStrategies).toBeUndefined();
    // With a per-vendor override -> persisted and read back.
    const withVs = store.setAgentLlmConfig(agent.id, {
      enabled: true,
      strategy: "fallback",
      vendorStrategies: { anthropic: "round-robin", openai: "fallback" },
      connectionIds: ["conn_a", "conn_b"],
    });
    expect(withVs.vendorStrategies).toEqual({
      anthropic: "round-robin",
      openai: "fallback",
    });
    expect(store.getAgentLlmConfig(agent.id)!.vendorStrategies).toEqual({
      anthropic: "round-robin",
      openai: "fallback",
    });
    // Clearing the map (undefined) drops it again.
    const cleared = store.setAgentLlmConfig(agent.id, {
      enabled: true,
      strategy: "fallback",
      connectionIds: ["conn_a"],
    });
    expect(cleared.vendorStrategies).toBeUndefined();
  });

  it("migrates an old agent_llm_config lacking vendor_strategies", () => {
    // Simulate a pre-LR2 database: table without the vendor_strategies column.
    const legacy = new Store(":memory:");
    const raw = (legacy as unknown as { db: import("node:sqlite").DatabaseSync }).db;
    raw.exec("DROP TABLE agent_llm_config");
    raw.exec(
      `CREATE TABLE agent_llm_config (
         agent_id TEXT PRIMARY KEY,
         enabled INTEGER NOT NULL DEFAULT 0,
         strategy TEXT NOT NULL DEFAULT 'fallback' CHECK (strategy IN ('fallback','round-robin')),
         connection_ids TEXT NOT NULL DEFAULT '[]',
         updated_at TEXT NOT NULL
       )`,
    );
    raw
      .prepare(
        "INSERT INTO agent_llm_config (agent_id, enabled, strategy, connection_ids, updated_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run("ag_legacy", 1, "round-robin", JSON.stringify(["conn_x"]), new Date().toISOString());
    // Re-run migration (idempotent ALTER adds the nullable column).
    (legacy as unknown as { migrate: () => void }).migrate();
    const cfg = legacy.getAgentLlmConfig("ag_legacy")!;
    expect(cfg.strategy).toBe("round-robin");
    expect(cfg.connectionIds).toEqual(["conn_x"]);
    expect(cfg.vendorStrategies).toBeUndefined();
  });

  it("deleteAgentLlmConfig also clears strategy state", () => {
    const { agent } = store.createAgent("llm-agent-2");
    store.setAgentLlmConfig(agent.id, { enabled: true, strategy: "fallback", connectionIds: [] });
    store.setLlmStrategyState(agent.id, "anthropic", {
      activeIndex: 1,
      rrCursor: 0,
      callsSinceFallback: 3,
      cooldowns: {},
    });
    store.deleteAgentLlmConfig(agent.id);
    expect(store.getAgentLlmConfig(agent.id)).toBeNull();
    expect(store.getLlmStrategyState(agent.id, "anthropic").activeIndex).toBe(0);
  });

  it("deleting the agent removes its llm config and state", () => {
    const { agent } = store.createAgent("llm-agent-3");
    store.setAgentLlmConfig(agent.id, { enabled: true, strategy: "fallback", connectionIds: [] });
    store.setLlmStrategyState(agent.id, "openai", {
      activeIndex: 0,
      rrCursor: 2,
      callsSinceFallback: 0,
      cooldowns: { conn_x: 4 },
    });
    store.deleteAgent(agent.id);
    expect(store.getAgentLlmConfig(agent.id)).toBeNull();
    expect(store.getLlmStrategyState(agent.id, "openai").rrCursor).toBe(-1);
  });
});

describe("llm strategy state", () => {
  it("returns fresh counters when nothing is persisted", () => {
    const s = store.getLlmStrategyState("ag_x", "anthropic");
    expect(s.activeIndex).toBe(0);
    expect(s.rrCursor).toBe(-1);
    expect(s.callsSinceFallback).toBe(0);
    expect(s.cooldowns).toEqual({});
  });

  it("persists and upserts per (agent, vendor)", () => {
    store.setLlmStrategyState("ag_x", "anthropic", {
      activeIndex: 2,
      rrCursor: 1,
      callsSinceFallback: 7,
      cooldowns: { conn_a: 10 },
    });
    store.setLlmStrategyState("ag_x", "openai", {
      activeIndex: 0,
      rrCursor: 0,
      callsSinceFallback: 0,
      cooldowns: {},
    });
    const a = store.getLlmStrategyState("ag_x", "anthropic");
    expect(a.activeIndex).toBe(2);
    expect(a.callsSinceFallback).toBe(7);
    expect(a.cooldowns).toEqual({ conn_a: 10 });
    expect(store.getLlmStrategyState("ag_x", "openai").activeIndex).toBe(0);
    store.setLlmStrategyState("ag_x", "anthropic", {
      activeIndex: 0,
      rrCursor: 1,
      callsSinceFallback: 0,
      cooldowns: {},
    });
    expect(store.getLlmStrategyState("ag_x", "anthropic").activeIndex).toBe(0);
  });
});

describe("llm usage", () => {
  it("records selection events and lists newest first", () => {
    store.recordLlmUsage({ connectionId: "conn_a", connectionName: "prod", vendor: "anthropic", strategy: "fallback", status: 200 });
    store.recordLlmUsage({ connectionId: "conn_a", errors: 1, failover: false, status: 429 });
    store.recordLlmUsage({ connectionId: "conn_b", failover: true, status: 200 });
    const events = store.listLlmUsage();
    expect(events).toHaveLength(3);
    expect(events[0].connectionId).toBe("conn_b");
    expect(events[0].failover).toBe(true);
    expect(events[1].errors).toBe(1);
    expect(events[1].status).toBe(429);
    expect(events[2].connectionName).toBe("prod");
    expect(events[2].strategy).toBe("fallback");
    expect(events[2].selected).toBe(true);
    expect(events[2].inputTokens).toBeNull();
  });

  it("filters by connection and agent", () => {
    store.recordLlmUsage({ connectionId: "conn_a", agentId: "ag_1" });
    store.recordLlmUsage({ connectionId: "conn_b", agentId: "ag_2" });
    expect(store.listLlmUsage({ connectionId: "conn_a" })).toHaveLength(1);
    expect(store.listLlmUsage({ agentId: "ag_2" })[0].connectionId).toBe("conn_b");
  });

  it("rolls up per-connection request/error/token totals", () => {
    store.recordLlmUsage({ connectionId: "conn_a", inputTokens: 100, outputTokens: 20 });
    store.recordLlmUsage({ connectionId: "conn_a", errors: 1, status: 500 });
    store.recordLlmUsage({ connectionId: "conn_b", inputTokens: 5, outputTokens: 1 });
    const totals = store.llmUsageTotals();
    expect(totals).toEqual([
      { connectionId: "conn_a", requests: 2, errors: 1, inputTokens: 100, outputTokens: 20 },
      { connectionId: "conn_b", requests: 1, errors: 0, inputTokens: 5, outputTokens: 1 },
    ]);
  });

  it("reports a last-used timestamp per connection and per vendor", () => {
    store.recordLlmUsage({ connectionId: "conn_a", vendor: "anthropic", inputTokens: 10 });
    store.recordLlmUsage({ connectionId: "conn_b", vendor: "gemini", inputTokens: 5 });
    const byConn = store.llmUsageByConnection();
    for (const row of byConn) {
      expect(typeof row.lastUsed).toBe("string");
      expect(Number.isNaN(Date.parse(row.lastUsed))).toBe(false);
    }
    const byVendor = store.llmUsageByVendor();
    for (const row of byVendor) {
      expect(typeof row.lastUsed).toBe("string");
      expect(Number.isNaN(Date.parse(row.lastUsed))).toBe(false);
    }
  });

  it("rolls up per model and per agent+model", () => {
    store.recordLlmUsage({ connectionId: "conn_a", agentId: "ag_1", vendor: "anthropic", model: "claude-opus-4-8", inputTokens: 100, outputTokens: 20 });
    store.recordLlmUsage({ connectionId: "conn_a", agentId: "ag_1", vendor: "anthropic", model: "claude-opus-4-8", inputTokens: 50, outputTokens: 10 });
    store.recordLlmUsage({ connectionId: "conn_b", agentId: "ag_2", vendor: "gemini", model: "gemini-3-flash-preview", inputTokens: 5, outputTokens: 1 });

    const byModel = store.llmUsageByModel();
    const opus = byModel.find((r) => r.model === "claude-opus-4-8");
    expect(opus).toMatchObject({ vendor: "anthropic", requests: 2, inputTokens: 150, outputTokens: 30 });
    const flash = byModel.find((r) => r.model === "gemini-3-flash-preview");
    expect(flash).toMatchObject({ vendor: "gemini", requests: 1, inputTokens: 5, outputTokens: 1 });

    const byAgentModel = store.llmUsageByAgentModel();
    const a1 = byAgentModel.find((r) => r.agentId === "ag_1" && r.model === "claude-opus-4-8");
    expect(a1).toMatchObject({ vendor: "anthropic", requests: 2, inputTokens: 150, outputTokens: 30 });
  });

  it("estimates turns from request gaps (approximate, gap-based)", () => {
    // Three rapid requests recorded in the same instant belong to one turn.
    for (let i = 0; i < 3; i++) {
      store.recordLlmUsage({ connectionId: "conn_t", agentId: "ag_t", vendor: "anthropic", model: "claude-opus-4-8" });
    }
    const byBot = store.estimatedTurnsByAgentModel();
    const row = byBot.find((r) => r.agentId === "ag_t" && r.model === "claude-opus-4-8");
    expect(row?.estimatedTurns).toBe(1);
    const byModel = store.estimatedTurnsByModel();
    expect(byModel.find((r) => r.model === "claude-opus-4-8")?.estimatedTurns).toBeGreaterThanOrEqual(1);
  });

  it("exposes the llm_turns_estimated view for raw analytics", () => {
    store.recordLlmUsage({ connectionId: "conn_v", agentId: "ag_v", vendor: "gemini", model: "gemini-3-flash-preview" });
    // The view name carries "estimated" so raw DB analytics see the label; it
    // must execute (window function) against node:sqlite.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rows = (store as any).db
      .prepare(
        "SELECT agent_id, vendor, model, SUM(is_turn_start) AS estimated_turns FROM llm_turns_estimated GROUP BY agent_id, vendor, model",
      )
      .all();
    const row = rows.find((r: { agent_id: string }) => r.agent_id === "ag_v");
    expect(Number(row.estimated_turns)).toBe(1);
  });
});

describe("segmentTurns (estimated turn segmentation)", () => {
  const base = Date.parse("2026-07-12T10:00:00.000Z");
  const at = (ms: number, over: Record<string, unknown> = {}) => ({
    agentId: "ag_1",
    vendor: "anthropic",
    model: "claude-opus-4-8",
    ts: new Date(base + ms).toISOString(),
    ...over,
  });

  it("groups requests within the gap into one turn", () => {
    const m = segmentTurns([at(0), at(2000), at(5000)]);
    expect([...m.values()].reduce((s, v) => s + v.turns, 0)).toBe(1);
  });

  it("starts a new turn when the gap exceeds the threshold", () => {
    const m = segmentTurns([at(0), at(1000), at(TURN_GAP_MS + 2000), at(TURN_GAP_MS + 3000)]);
    expect([...m.values()].reduce((s, v) => s + v.turns, 0)).toBe(2);
  });

  it("counts each agent's turns separately", () => {
    const m = segmentTurns([at(0), at(1000, { agentId: "ag_2" }), at(2000)]);
    // ag_1 opens a turn, ag_2 opens a turn, then ag_1 again is a fresh turn
    // (previous row was a different agent), so 3 turns total.
    expect([...m.values()].reduce((s, v) => s + v.turns, 0)).toBe(3);
  });

  it("attributes a turn to the model of its opening request", () => {
    const m = segmentTurns([at(0, { model: "claude-opus-4-8" }), at(2000, { model: "claude-haiku-4-5" })]);
    expect(m.get("ag_1|anthropic|claude-opus-4-8")?.turns).toBe(1);
    expect(m.has("ag_1|anthropic|claude-haiku-4-5")).toBe(false);
  });
});

describe("app connections (default-deny grants)", () => {
  it("llm connections ignore ownerAgentId (always tenant-wide)", () => {
    const { agent } = store.createAgent("a");
    const c = store.createConnection({
      kind: "llm",
      vendor: "anthropic",
      name: "x",
      data: { apiKey: "k" },
      ownerAgentId: agent.id,
    });
    expect(c.ownerAgentId).toBeNull();
  });

  it("a freshly created app connection is granted to nobody (default-deny)", () => {
    const { agent } = store.createAgent("a");
    const conn = store.createConnection({ kind: "app", vendor: "github", name: "shared", data: { pat: "s" } });
    expect(store.countGrantsForConnection(conn.id)).toBe(0);
    expect(store.listAppConnectionsForAgent(agent.id, "github")).toHaveLength(0);
    expect(store.isConnectionGrantedToAgent(conn.id, agent.id)).toBe(false);
  });

  it("agent grant makes the connection visible to that agent only", () => {
    const { agent: a } = store.createAgent("a");
    const { agent: b } = store.createAgent("b");
    const conn = store.createConnection({ kind: "app", vendor: "github", name: "c", data: {} });
    store.grantConnection(conn.id, "agent", a.id);
    expect(store.listAppConnectionsForAgent(a.id, "github").map((c) => c.id)).toEqual([conn.id]);
    expect(store.listAppConnectionsForAgent(b.id, "github")).toHaveLength(0);
    expect(store.isConnectionGrantedToAgent(conn.id, a.id)).toBe(true);
    expect(store.isConnectionGrantedToAgent(conn.id, b.id)).toBe(false);
  });

  it("project grant makes the connection visible to every agent in that project", () => {
    const proj = store.createProject("team");
    const { agent: a } = store.createAgent("a", { projectId: proj.id });
    const { agent: b } = store.createAgent("b", { projectId: proj.id });
    const { agent: outsider } = store.createAgent("c");
    const conn = store.createConnection({ kind: "app", vendor: "github", name: "c", data: {} });
    store.grantConnection(conn.id, "project", proj.id);
    expect(store.listAppConnectionsForAgent(a.id, "github").map((c) => c.id)).toEqual([conn.id]);
    expect(store.listAppConnectionsForAgent(b.id, "github").map((c) => c.id)).toEqual([conn.id]);
    expect(store.listAppConnectionsForAgent(outsider.id, "github")).toHaveLength(0);
    expect(store.isConnectionGrantedToAgent(conn.id, a.id)).toBe(true);
    expect(store.isConnectionGrantedToAgent(conn.id, outsider.id)).toBe(false);
  });

  it("grantConnection is idempotent; revoke removes; both sides reflect it", () => {
    const { agent } = store.createAgent("a");
    const conn = store.createConnection({ kind: "app", vendor: "github", name: "c", data: {} });
    store.grantConnection(conn.id, "agent", agent.id);
    store.grantConnection(conn.id, "agent", agent.id);
    expect(store.countGrantsForConnection(conn.id)).toBe(1);
    expect(store.listGrantsForConnection(conn.id)).toEqual([
      { scope: "agent", subjectId: agent.id, subjectName: "a", createdAt: expect.any(String) },
    ]);
    store.revokeConnection(conn.id, "agent", agent.id);
    expect(store.countGrantsForConnection(conn.id)).toBe(0);
    expect(store.listAppConnectionsForAgent(agent.id, "github")).toHaveLength(0);
    // revoking a non-existent grant is a no-op
    store.revokeConnection(conn.id, "agent", agent.id);
  });

  it("listGrantsForConnection resolves project subject names", () => {
    const proj = store.createProject("team");
    const conn = store.createConnection({ kind: "app", vendor: "github", name: "c", data: {} });
    store.grantConnection(conn.id, "project", proj.id);
    expect(store.listGrantsForConnection(conn.id)).toEqual([
      { scope: "project", subjectId: proj.id, subjectName: "team", createdAt: expect.any(String) },
    ]);
  });

  it("deleting a connection cascades its grants", () => {
    const { agent } = store.createAgent("a");
    const conn = store.createConnection({ kind: "app", vendor: "github", name: "c", data: {} });
    store.grantConnection(conn.id, "agent", agent.id);
    store.deleteConnection(conn.id);
    expect(store.listGrantsForConnection(conn.id)).toHaveLength(0);
    expect(store.listAppConnectionsForAgent(agent.id, "github")).toHaveLength(0);
  });

  it("deleting an agent cleans grants naming it", () => {
    const { agent } = store.createAgent("a");
    const conn = store.createConnection({ kind: "app", vendor: "github", name: "c", data: {} });
    store.grantConnection(conn.id, "agent", agent.id);
    store.deleteAgent(agent.id);
    expect(store.listGrantsForConnection(conn.id)).toHaveLength(0);
  });

  it("deleting a project cleans grants naming it", () => {
    const proj = store.createProject("team");
    const conn = store.createConnection({ kind: "app", vendor: "github", name: "c", data: {} });
    store.grantConnection(conn.id, "project", proj.id);
    store.deleteProject(proj.id);
    expect(store.listGrantsForConnection(conn.id)).toHaveLength(0);
  });

  it("resolveAppConnection: ungranted agent is denied even when a named conn exists", () => {
    const { agent } = store.createAgent("a");
    store.createConnection({ kind: "app", vendor: "github", name: "c", data: {} });
    expect(store.resolveAppConnection(agent.id, "github")).toEqual({ error: "connection_not_granted" });
  });

  it("resolveAppConnection: header naming an existing-but-ungranted conn -> connection_not_granted", () => {
    const { agent } = store.createAgent("a");
    const conn = store.createConnection({ kind: "app", vendor: "github", name: "theirs", data: {} });
    expect(store.resolveAppConnection(agent.id, "github", "theirs")).toEqual({ error: "connection_not_granted" });
    expect(store.resolveAppConnection(agent.id, "github", conn.id)).toEqual({ error: "connection_not_granted" });
  });

  it("resolveAppConnection: header naming nothing -> unknown_connection", () => {
    const { agent } = store.createAgent("a");
    store.createConnection({ kind: "app", vendor: "github", name: "theirs", data: {} });
    expect(store.resolveAppConnection(agent.id, "github", "nope")).toEqual({ error: "unknown_connection" });
  });

  it("resolveAppConnection: granted single candidate is used", () => {
    const { agent } = store.createAgent("a");
    const conn = store.createConnection({ kind: "app", vendor: "github", name: "mine", data: {} });
    store.grantConnection(conn.id, "agent", agent.id);
    expect(store.resolveAppConnection(agent.id, "github")).toEqual({ connection: expect.objectContaining({ id: conn.id }) });
    expect(store.resolveAppConnection(agent.id, "github", "mine")).toEqual({ connection: expect.objectContaining({ id: conn.id }) });
    expect(store.resolveAppConnection(agent.id, "github", conn.id)).toEqual({ connection: expect.objectContaining({ id: conn.id }) });
  });

  it("resolveAppConnection: saved choice used only when still granted, else ignored", () => {
    const { agent } = store.createAgent("a");
    const a = store.createConnection({ kind: "app", vendor: "github", name: "a", data: {} });
    const b = store.createConnection({ kind: "app", vendor: "github", name: "b", data: {} });
    store.grantConnection(a.id, "agent", agent.id);
    store.grantConnection(b.id, "agent", agent.id);
    store.setAgentAppConfig(agent.id, "github", b.id);
    expect(store.resolveAppConnection(agent.id, "github")).toEqual({ connection: expect.objectContaining({ id: b.id }) });
    // revoke the saved choice -> it is ignored, falls to remaining default/sole
    store.revokeConnection(b.id, "agent", agent.id);
    expect(store.resolveAppConnection(agent.id, "github")).toEqual({ connection: expect.objectContaining({ id: a.id }) });
  });

  it("resolveAppConnection: candidate default wins among multiple granted", () => {
    const { agent } = store.createAgent("a");
    const a = store.createConnection({ kind: "app", vendor: "github", name: "a", data: {} });
    const b = store.createConnection({ kind: "app", vendor: "github", name: "b", data: {}, isDefault: true });
    store.grantConnection(a.id, "agent", agent.id);
    store.grantConnection(b.id, "agent", agent.id);
    expect(store.resolveAppConnection(agent.id, "github")).toEqual({ connection: expect.objectContaining({ id: b.id }) });
  });

  it("resolveAppConnection: zero named app conns for the integration -> legacy fall-through (null)", () => {
    const { agent } = store.createAgent("a");
    // no app connections at all for slack
    expect(store.resolveAppConnection(agent.id, "slack")).toBeNull();
    expect(store.resolveAppConnection(agent.id, "slack", "anything")).toEqual({ error: "unknown_connection" });
  });

  it("deleting an app connection scrubs it from agent_app_config", () => {
    const { agent } = store.createAgent("a");
    const owned = store.createConnection({ kind: "app", vendor: "github", name: "mine", data: {} });
    store.setAgentAppConfig(agent.id, "github", owned.id);
    const affected = store.removeConnectionFromAppConfigs(owned.id);
    expect(affected).toEqual([agent.id]);
    expect(store.getAgentAppConfig(agent.id, "github")).toBeNull();
  });

  it("app credentials legacy table is untouched by app connections", () => {
    store.setCredential("github", "pat", { pat: "tok1" });
    store.createConnection({ kind: "app", vendor: "github", name: "conn", data: { pat: "tok2" } });
    expect(store.getCredential("github")?.data.pat).toBe("tok1");
    expect(store.listCredentials()).toHaveLength(1);
  });
});

describe("token format", () => {
  it("newAgentToken is prefixed and unique", () => {
    expect(newAgentToken()).not.toBe(newAgentToken());
  });
});
