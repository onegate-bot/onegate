/**
 * U1: the grant/rule double gate.
 *
 * Reaching a third-party integration used to require TWO independent things:
 * a connection grant AND an allow rule. Operators consistently created the
 * grant, got an unexplained 403, and had no way to see why. These tests pin the
 * fix (grant-time rule ensuring, Store.ensureAllowRuleForGrant) AND the
 * invariants it must never break.
 *
 * Deliberately covers BOTH surfaces: the store method, and the admin API
 * endpoint that the UI and the `onegate connections grant` CLI both post to.
 */

import { describe, it, expect, beforeEach, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/store/db.js";
import { evaluate } from "../src/policy.js";
import { initCa } from "../src/ca.js";
import { buildRegistry } from "../src/integrations/index.js";
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";
import type { Agent, Rule } from "../src/types.js";

/** The call an agent would make against the granted integration. */
const REQ = { integrationId: "github", method: "GET", path: "/user" };

describe("store: granting a connection ensures the matching allow rule", () => {
  let store: Store;

  beforeEach(() => {
    store = new Store(":memory:");
  });

  function githubConn(): string {
    return store.createConnection({
      kind: "app",
      vendor: "github",
      name: "gh",
      data: { pat: "ghp_x" },
    }).id;
  }

  /** Policy verdict for an agent using only its own agent-scoped rules. */
  function verdict(agent: Agent) {
    return evaluate(agent, store.listRules({ scope: "agent", subjectId: agent.id }), REQ);
  }

  it("THE DEFECT: a grant alone now reaches the integration (was default-deny)", () => {
    const { agent } = store.createAgent("a");
    const conn = githubConn();
    store.grantConnection(conn, "agent", agent.id);

    // Before the fix this was the whole bug: grant present, still denied.
    expect(verdict(agent).effect).toBe("deny");

    const ensured = store.ensureAllowRuleForGrant(conn, "agent", agent.id)!;
    expect(ensured.created).toBe(true);
    expect(ensured.rule.effect).toBe("allow");
    expect(ensured.rule.integrationId).toBe("github");
    expect(ensured.rule.scope).toBe("agent");
    expect(ensured.rule.subjectId).toBe(agent.id);
    expect(verdict(agent).effect).toBe("allow");
  });

  it("the auto-created rule is attributable as createdBy=grant", () => {
    const { agent } = store.createAgent("a");
    const conn = githubConn();
    const ensured = store.ensureAllowRuleForGrant(conn, "agent", agent.id)!;
    expect(ensured.rule.createdBy).toBe("grant");
    // And it reads back that way from storage, not just from the return value.
    expect(store.listRules({ scope: "agent", subjectId: agent.id })[0].createdBy).toBe("grant");
  });

  it("a hand-written rule stays attributed to the operator", () => {
    const { agent } = store.createAgent("a");
    const r = store.createRule({
      scope: "agent",
      subjectId: agent.id,
      integrationId: "slack",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
    expect(r.createdBy).toBe("operator");
  });

  it("is idempotent: a second grant creates nothing and returns the same rule", () => {
    const { agent } = store.createAgent("a");
    const conn = githubConn();
    const first = store.ensureAllowRuleForGrant(conn, "agent", agent.id)!;
    const second = store.ensureAllowRuleForGrant(conn, "agent", agent.id)!;
    expect(second.created).toBe(false);
    expect(second.rule.id).toBe(first.rule.id);
    expect(store.listRules({ scope: "agent", subjectId: agent.id })).toHaveLength(1);
  });

  it("INVARIANT: an explicit DENY is never overridden, and still wins", () => {
    const { agent } = store.createAgent("a");
    const conn = githubConn();
    const deny = store.createRule({
      scope: "agent",
      subjectId: agent.id,
      integrationId: "github",
      methods: ["*"],
      pathGlob: "/**",
      effect: "deny",
    });

    const ensured = store.ensureAllowRuleForGrant(conn, "agent", agent.id)!;
    // Nothing synthesized on top of the deny.
    expect(ensured.created).toBe(false);
    expect(ensured.rule.id).toBe(deny.id);
    const rules = store.listRules({ scope: "agent", subjectId: agent.id });
    expect(rules).toHaveLength(1);
    expect(rules[0].effect).toBe("deny");
    // The deny is intact AND decisive.
    expect(verdict(agent)).toMatchObject({ effect: "deny", ruleId: deny.id });
  });

  it("INVARIANT: a narrower existing allow is left alone, never widened", () => {
    const { agent } = store.createAgent("a");
    const conn = githubConn();
    const narrow = store.createRule({
      scope: "agent",
      subjectId: agent.id,
      integrationId: "github",
      methods: ["GET"],
      pathGlob: "/repos/**",
      effect: "allow",
    });

    const ensured = store.ensureAllowRuleForGrant(conn, "agent", agent.id)!;
    expect(ensured.created).toBe(false);
    expect(ensured.rule.id).toBe(narrow.id);

    const rules = store.listRules({ scope: "agent", subjectId: agent.id });
    expect(rules).toHaveLength(1);
    expect(rules[0].methods).toEqual(["GET"]);
    expect(rules[0].pathGlob).toBe("/repos/**");
    // Still narrow in practice: the out-of-scope path is denied.
    expect(evaluate(agent, rules, REQ).effect).toBe("deny");
    expect(
      evaluate(agent, rules, { integrationId: "github", method: "GET", path: "/repos/a/b" }).effect,
    ).toBe("allow");
  });

  it("INVARIANT: default-deny is unchanged for an integration with no grant", () => {
    const { agent } = store.createAgent("a");
    const conn = githubConn();
    store.ensureAllowRuleForGrant(conn, "agent", agent.id);
    // github is now reachable, slack was never granted and must stay denied.
    expect(verdict(agent).effect).toBe("allow");
    expect(
      evaluate(agent, store.listRules({ scope: "agent", subjectId: agent.id }), {
        integrationId: "slack",
        method: "GET",
        path: "/api/x",
      }).effect,
    ).toBe("deny");
  });

  it("INVARIANT: an untouched agent with no grants at all is still denied everything", () => {
    const { agent } = store.createAgent("bare");
    expect(verdict(agent)).toMatchObject({ effect: "deny", ruleId: null });
  });

  it("a project grant produces a project-scoped rule that covers member agents", () => {
    const proj = store.createProject("team");
    const { agent } = store.createAgent("member", { projectId: proj.id });
    const conn = githubConn();
    const ensured = store.ensureAllowRuleForGrant(conn, "project", proj.id)!;
    expect(ensured.created).toBe(true);
    expect(ensured.rule.scope).toBe("project");
    expect(ensured.rule.subjectId).toBe(proj.id);
    // The agent has no agent-scoped rule of its own; the project rule carries it,
    // exactly as the proxy composes them.
    expect(store.listRules({ scope: "agent", subjectId: agent.id })).toHaveLength(0);
    expect(evaluate(agent, store.listRules({ scope: "project", subjectId: proj.id }), REQ).effect).toBe(
      "allow",
    );
  });

  it("a wildcard rule already covers the integration, so nothing is created", () => {
    const { agent } = store.createAgent("a");
    const conn = githubConn();
    const star = store.createRule({
      scope: "agent",
      subjectId: agent.id,
      integrationId: "*",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
    const ensured = store.ensureAllowRuleForGrant(conn, "agent", agent.id)!;
    expect(ensured.created).toBe(false);
    expect(ensured.rule.id).toBe(star.id);
    expect(store.listRules({ scope: "agent", subjectId: agent.id })).toHaveLength(1);
  });

  it("LLM connections get no policy rule (routing has its own path)", () => {
    const { agent } = store.createAgent("a");
    const llm = store.createConnection({
      kind: "llm",
      vendor: "anthropic",
      name: "claude",
      data: { apiKey: "sk-x" },
    }).id;
    expect(store.ensureAllowRuleForGrant(llm, "agent", agent.id)).toBeNull();
    expect(store.listRules({ scope: "agent", subjectId: agent.id })).toHaveLength(0);
  });

  it("an unknown connection or unknown subject is a no-op null", () => {
    const { agent } = store.createAgent("a");
    const conn = githubConn();
    expect(store.ensureAllowRuleForGrant("conn_missing", "agent", agent.id)).toBeNull();
    expect(store.ensureAllowRuleForGrant(conn, "agent", "ag_missing")).toBeNull();
    expect(store.ensureAllowRuleForGrant(conn, "project", "proj_missing")).toBeNull();
    expect(store.listRules({ scope: "agent", subjectId: agent.id })).toHaveLength(0);
  });

  it("carries the integration's access lease onto the created rule", () => {
    const { agent } = store.createAgent("a");
    store.setIntegrationLease("github", 8 * 3600);
    const conn = githubConn();
    const ensured = store.ensureAllowRuleForGrant(conn, "agent", agent.id)!;
    expect(ensured.rule.leaseTtlSeconds).toBe(8 * 3600);
    expect(ensured.rule.expiresAt).toBeTruthy();
  });
});

describe("admin API: POST /api/connections/:id/grants ensures the allow rule", () => {
  let dir: string;
  let store: Store;
  let server: http.Server;
  let port: number;
  let adminToken: string;
  let agentId: string;
  let connId: string;

  function api(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ status: number; json: any }> {
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
            resolve({ status: res.statusCode ?? 0, json });
          });
        },
      );
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "og-grant-rule-"));
    store = new Store(":memory:");
    const ca = initCa(dir);
    const registry = await buildRegistry();
    adminToken = ensureAdminToken(store)!;
    const app = createAdminApp({ store, registry, ca, version: "test" });
    server = http.createServer(app);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as any).port;
    agentId = store.createAgent("grant-agent").agent.id;
    connId = store.createConnection({
      kind: "app",
      vendor: "github",
      name: "gh",
      data: { pat: "ghp_y" },
    }).id;
  });

  afterAll(() => {
    server?.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("reports the rule it created, and that rule is real", async () => {
    const g = await api("POST", `/api/connections/${connId}/grants`, {
      scope: "agent",
      subjectId: agentId,
    });
    expect(g.status).toBe(201);
    expect(g.json.ruleCreated).toBe(true);
    expect(g.json.ruleId).toMatch(/^rl_/);

    const rules = store.listRules({ scope: "agent", subjectId: agentId });
    expect(rules).toHaveLength(1);
    expect(rules[0]).toMatchObject({
      id: g.json.ruleId,
      integrationId: "github",
      effect: "allow",
      createdBy: "grant",
    });
  });

  it("a repeat grant creates no second rule", async () => {
    const again = await api("POST", `/api/connections/${connId}/grants`, {
      scope: "agent",
      subjectId: agentId,
    });
    expect(again.status).toBe(201);
    expect(again.json.ruleCreated).toBe(false);
    expect(store.listRules({ scope: "agent", subjectId: agentId })).toHaveLength(1);
  });

  it("does not synthesize an allow over an operator's explicit deny", async () => {
    const denied = store.createAgent("denied-agent").agent.id;
    const deny = store.createRule({
      scope: "agent",
      subjectId: denied,
      integrationId: "github",
      methods: ["*"],
      pathGlob: "/**",
      effect: "deny",
    });
    const g = await api("POST", `/api/connections/${connId}/grants`, {
      scope: "agent",
      subjectId: denied,
    });
    expect(g.status).toBe(201);
    expect(g.json.ruleCreated).toBe(false);
    const rules = store.listRules({ scope: "agent", subjectId: denied });
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe(deny.id);
    expect(rules[0].effect).toBe("deny");
  });

  it("exposes createdBy on GET /api/rules so an operator can attribute it", async () => {
    const all = (await api("GET", "/api/rules")).json as Rule[];
    const auto = all.find((r) => r.subjectId === agentId);
    expect(auto?.createdBy).toBe("grant");
  });
});
