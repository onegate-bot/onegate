import { describe, it, expect } from "vitest";
import { evaluate, globToRegExp, ruleConnectionMatch, ruleMatches } from "../src/policy.js";
import type { Agent, Rule } from "../src/types.js";

function agent(defaultPolicy: Agent["defaultPolicy"] = "deny-unmatched"): Agent {
  return {
    id: "ag_1",
    name: "test",
    tokenHash: "x",
    projectId: null,
    defaultPolicy,
    createdAt: "",
  };
}

function rule(partial: Partial<Rule>): Rule {
  return {
    id: "rl_1",
    scope: "agent",
    subjectId: "ag_1",
    integrationId: "github",
    methods: ["*"],
    pathGlob: "/**",
    effect: "allow",
    createdAt: "",
    ...partial,
  };
}

describe("globToRegExp", () => {
  it("* stays within one path segment, ** crosses segments", () => {
    expect(globToRegExp("/repos/*/pulls").test("/repos/abc/pulls")).toBe(true);
    expect(globToRegExp("/repos/*/pulls").test("/repos/a/b/pulls")).toBe(false);
    expect(globToRegExp("/repos/**").test("/repos/a/b/pulls")).toBe(true);
    expect(globToRegExp("/**").test("/anything/at/all")).toBe(true);
  });

  it("escapes regex metacharacters", () => {
    expect(globToRegExp("/a.b/c").test("/a.b/c")).toBe(true);
    expect(globToRegExp("/a.b/c").test("/aXb/c")).toBe(false);
  });

  it("trailing /** also matches the bare prefix", () => {
    const g = globToRegExp("/repos/x/y/**");
    expect(g.test("/repos/x/y")).toBe(true);
    expect(g.test("/repos/x/y/")).toBe(true);
    expect(g.test("/repos/x/y/z")).toBe(true);
    // Must not over-match sibling prefixes that merely share the same start.
    expect(g.test("/repos/x/yy")).toBe(false);
    expect(g.test("/repos/x/ything")).toBe(false);
  });
});

describe("ruleMatches", () => {
  it("filters by integration, method and path; ignores query string", () => {
    const r = rule({ integrationId: "github", methods: ["GET"], pathGlob: "/user" });
    expect(ruleMatches(r, { integrationId: "github", method: "GET", path: "/user?per_page=5" })).toBe(true);
    expect(ruleMatches(r, { integrationId: "gmail", method: "GET", path: "/user" })).toBe(false);
    expect(ruleMatches(r, { integrationId: "github", method: "POST", path: "/user" })).toBe(false);
  });

  it('integrationId "*" matches any integration', () => {
    const r = rule({ integrationId: "*" });
    expect(ruleMatches(r, { integrationId: "gmail", method: "GET", path: "/x" })).toBe(true);
  });
});

describe("evaluate", () => {
  const req = { integrationId: "github", method: "DELETE", path: "/repos/z/r" };

  it("deny beats allow", () => {
    const rules = [
      rule({ id: "rl_allow", effect: "allow" }),
      rule({ id: "rl_deny", effect: "deny", methods: ["DELETE"] }),
    ];
    const v = evaluate(agent("allow-all"), rules, req);
    expect(v).toEqual({ effect: "deny", ruleId: "rl_deny" });
  });

  it("explicit allow beats deny-unmatched default", () => {
    const v = evaluate(agent("deny-unmatched"), [rule({ id: "rl_a" })], req);
    expect(v).toEqual({ effect: "allow", ruleId: "rl_a" });
  });

  it("falls back to the agent default when nothing matches", () => {
    expect(evaluate(agent("deny-unmatched"), [], req).effect).toBe("deny");
    expect(evaluate(agent("allow-all"), [], req).effect).toBe("allow");
  });

  it("does not emit needsConnection when no connection-scoped rule matches", () => {
    const v = evaluate(agent("allow-all"), [rule({ id: "rl_a" })], req);
    expect(v.needsConnection).toBeUndefined();
    expect(v).toEqual({ effect: "allow", ruleId: "rl_a" });
  });
});

describe("ruleConnectionMatch (flag on)", () => {
  const base = { integrationId: "github", method: "GET", path: "/repos/x/y" };

  it('a non-connection-scoped rule always "applies"', () => {
    const r = rule({});
    expect(ruleConnectionMatch(r, base, true)).toBe("applies");
    expect(ruleConnectionMatch(r, { ...base, connectionId: "conn_1" }, true)).toBe("applies");
  });

  it('"pending" while the connection is unresolved (undefined)', () => {
    const r = rule({ connectionScope: "except", connectionId: "conn_kop" });
    expect(ruleConnectionMatch(r, base, true)).toBe("pending");
  });

  it('scope "except" applies for any connection other than the target', () => {
    const r = rule({ connectionScope: "except", connectionId: "conn_kop" });
    expect(ruleConnectionMatch(r, { ...base, connectionId: "conn_other" }, true)).toBe("applies");
    expect(ruleConnectionMatch(r, { ...base, connectionId: null }, true)).toBe("applies");
    expect(ruleConnectionMatch(r, { ...base, connectionId: "conn_kop" }, true)).toBe("excluded");
  });

  it('scope "only" applies for the target connection alone', () => {
    const r = rule({ connectionScope: "only", connectionId: "conn_kop" });
    expect(ruleConnectionMatch(r, { ...base, connectionId: "conn_kop" }, true)).toBe("applies");
    expect(ruleConnectionMatch(r, { ...base, connectionId: "conn_other" }, true)).toBe("excluded");
    expect(ruleConnectionMatch(r, { ...base, connectionId: null }, true)).toBe("excluded");
  });
});

describe("ruleConnectionMatch (flag off)", () => {
  const base = { integrationId: "github", method: "GET", path: "/repos/x/y" };

  it("a connection-scoped rule is inert (excluded) regardless of connection", () => {
    const r = rule({ connectionScope: "except", connectionId: "conn_kop" });
    expect(ruleConnectionMatch(r, base, false)).toBe("excluded");
    expect(ruleConnectionMatch(r, { ...base, connectionId: "conn_other" }, false)).toBe("excluded");
    expect(ruleConnectionMatch(r, { ...base, connectionId: "conn_kop" }, false)).toBe("excluded");
  });

  it("an ordinary (non-scoped) rule is unaffected by the flag", () => {
    const r = rule({});
    expect(ruleConnectionMatch(r, base, false)).toBe("applies");
  });
});

describe("evaluate — connection-scoped rules (two phase, flag on)", () => {
  const req = { integrationId: "github", method: "GET", path: "/repos/onegate-bot/onegate/pulls" };
  const on = { connectionScoping: true };

  // Ziv's model: a broad allow plus a DENY-except pinned to the koptereli
  // connection. Phase 1 (connection unresolved) must not deny; phase 2 (resolved)
  // denies every connection except koptereli.
  const rules = [
    rule({ id: "rl_allow", effect: "allow", pathGlob: "/**" }),
    rule({
      id: "rl_pin",
      effect: "deny",
      pathGlob: "/repos/onegate-bot/onegate/**",
      connectionScope: "except",
      connectionId: "conn_kop",
    }),
  ];

  it("phase 1 (unresolved) allows and flags needsConnection", () => {
    const v = evaluate(agent("deny-unmatched"), rules, req, Date.now(), on);
    expect(v.effect).toBe("allow");
    expect(v.ruleId).toBe("rl_allow");
    expect(v.needsConnection).toBe(true);
  });

  it("phase 2 denies when a non-target connection is used", () => {
    const v = evaluate(agent("deny-unmatched"), rules, { ...req, connectionId: "conn_default" }, Date.now(), on);
    expect(v.effect).toBe("deny");
    expect(v.ruleId).toBe("rl_pin");
  });

  it("phase 2 allows when the koptereli connection is used", () => {
    const v = evaluate(agent("deny-unmatched"), rules, { ...req, connectionId: "conn_kop" }, Date.now(), on);
    expect(v.effect).toBe("allow");
    expect(v.ruleId).toBe("rl_allow");
  });

  it("the pin does not touch other paths on the same integration", () => {
    const other = { integrationId: "github", method: "GET", path: "/repos/zivisaiah/nanoclaw" };
    expect(evaluate(agent("deny-unmatched"), rules, other, Date.now(), on).needsConnection).toBeUndefined();
    expect(
      evaluate(agent("deny-unmatched"), rules, { ...other, connectionId: "conn_default" }, Date.now(), on).effect,
    ).toBe("allow");
  });
});

describe("evaluate — connection-scoped rules are inert when the flag is off", () => {
  const req = { integrationId: "github", method: "GET", path: "/repos/onegate-bot/onegate/pulls" };
  const off = { connectionScoping: false };

  const rules = [
    rule({ id: "rl_allow", effect: "allow", pathGlob: "/**" }),
    rule({
      id: "rl_pin",
      effect: "deny",
      pathGlob: "/repos/onegate-bot/onegate/**",
      connectionScope: "except",
      connectionId: "conn_kop",
    }),
  ];

  it("never flags needsConnection and never denies, on any connection", () => {
    // Unresolved: no phase-2 signal, plain allow.
    const v0 = evaluate(agent("deny-unmatched"), rules, req, Date.now(), off);
    expect(v0.needsConnection).toBeUndefined();
    expect(v0).toEqual({ effect: "allow", ruleId: "rl_allow" });
    // Even a non-target connection is allowed (the pin is inert).
    const v1 = evaluate(agent("deny-unmatched"), rules, { ...req, connectionId: "conn_default" }, Date.now(), off);
    expect(v1).toEqual({ effect: "allow", ruleId: "rl_allow" });
  });
});
