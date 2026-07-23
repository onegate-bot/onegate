import { describe, it, expect } from "vitest";
import { evaluate, globToRegExp, ruleMatches } from "../src/policy.js";
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
});
