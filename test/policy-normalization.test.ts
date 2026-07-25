import { describe, it, expect } from "vitest";
import { evaluate, normalizeRequestPath, ruleMatches } from "../src/policy.js";
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

// The pinned/denied path we want to protect: onegate-bot/onegate repo subtree.
const DENY_GLOB = "/repos/onegate-bot/onegate/**";
const CANONICAL = "/repos/onegate-bot/onegate/pulls";

describe("normalizeRequestPath", () => {
  it("leaves an already-canonical path unchanged", () => {
    expect(normalizeRequestPath("/repos/onegate-bot/onegate/pulls")).toBe(
      "/repos/onegate-bot/onegate/pulls",
    );
  });

  it("percent-decodes the path (%2F -> /) so encoded slashes canonicalize", () => {
    expect(normalizeRequestPath("/repos%2Fonegate-bot%2Fonegate%2Fpulls")).toBe(CANONICAL);
    expect(normalizeRequestPath("%2Frepos%2Fonegate-bot%2Fonegate%2Fpulls")).toBe(CANONICAL);
  });

  it("collapses duplicate slashes (//)", () => {
    expect(normalizeRequestPath("//repos/onegate-bot//onegate/pulls")).toBe(CANONICAL);
    expect(normalizeRequestPath("/repos///onegate-bot/onegate/pulls")).toBe(CANONICAL);
  });

  it("collapses . and .. dot-segments (a .. never escapes root)", () => {
    expect(normalizeRequestPath("/repos/x/../onegate-bot/onegate/pulls")).toBe(CANONICAL);
    expect(normalizeRequestPath("/repos/./onegate-bot/onegate/pulls")).toBe(CANONICAL);
    expect(normalizeRequestPath("/../../repos/onegate-bot/onegate/pulls")).toBe(CANONICAL);
  });

  it("preserves the query string verbatim, normalizing only the path", () => {
    expect(normalizeRequestPath("/repos//onegate-bot/onegate/pulls?state=open&per_page=5")).toBe(
      `${CANONICAL}?state=open&per_page=5`,
    );
    // %2F inside the query is NOT decoded (only the path portion is normalized).
    expect(normalizeRequestPath("/repos/onegate-bot/onegate/pulls?q=a%2Fb")).toBe(
      `${CANONICAL}?q=a%2Fb`,
    );
  });

  it("decodes exactly once (no semantic change from a single legitimate decode)", () => {
    // Double-encoded %252F decodes to %2F, NOT to "/".
    expect(normalizeRequestPath("/repos/onegate-bot/onegate/a%252Fb")).toBe(
      "/repos/onegate-bot/onegate/a%2Fb",
    );
  });

  it("treats malformed percent-encoding as a literal (never throws)", () => {
    expect(() => normalizeRequestPath("/repos/%zz/onegate")).not.toThrow();
    expect(normalizeRequestPath("/repos/%zz/onegate")).toBe("/repos/%zz/onegate");
    expect(normalizeRequestPath("/repos/onegate%")).toBe("/repos/onegate%");
    expect(normalizeRequestPath("/repos/onegate%2")).toBe("/repos/onegate%2");
  });

  it("is idempotent", () => {
    const once = normalizeRequestPath("//repos/x/../onegate-bot%2Fonegate/pulls");
    expect(once).toBe(CANONICAL);
    expect(normalizeRequestPath(once)).toBe(CANONICAL);
  });
});

describe("ruleMatches with canonicalization (deny-glob evasion is closed)", () => {
  const deny = rule({
    integrationId: "github",
    methods: ["*"],
    pathGlob: DENY_GLOB,
    effect: "deny",
  });

  const evasions = [
    CANONICAL, // plain canonical
    "/repos%2Fonegate-bot%2Fonegate%2Fpulls", // %2F encoded
    "%2Frepos%2Fonegate-bot%2Fonegate%2Fpulls", // fully encoded
    "//repos/onegate-bot//onegate/pulls", // duplicate slashes
    "/repos/x/../onegate-bot/onegate/pulls", // dot-segment
    "/repos/./onegate-bot/onegate/pulls?ref=main", // dot-segment + query
  ];

  for (const p of evasions) {
    it(`matches the deny glob for equivalent path ${p}`, () => {
      expect(ruleMatches(deny, { integrationId: "github", method: "GET", path: p })).toBe(true);
    });
  }

  it("does not over-match an unrelated repo", () => {
    expect(
      ruleMatches(deny, {
        integrationId: "github",
        method: "GET",
        path: "/repos/zivisaiah/nanoclaw/pulls",
      }),
    ).toBe(false);
  });
});

describe("evaluate: encoded/dot-segment/double-slash variants of a pinned path are all denied", () => {
  const rules = [
    rule({ integrationId: "github", methods: ["*"], pathGlob: "/**", effect: "allow" }),
    rule({
      id: "rl_deny",
      integrationId: "github",
      methods: ["*"],
      pathGlob: DENY_GLOB,
      effect: "deny",
    }),
  ];

  const denied = [
    CANONICAL,
    "/repos%2Fonegate-bot%2Fonegate%2Fpulls",
    "//repos/onegate-bot//onegate/pulls",
    "/repos/x/../onegate-bot/onegate/pulls",
  ];

  for (const p of denied) {
    it(`denies ${p}`, () => {
      const v = evaluate(agent(), rules, { integrationId: "github", method: "GET", path: p });
      expect(v.effect).toBe("deny");
      expect(v.ruleId).toBe("rl_deny");
    });
  }

  it("still allows a normal, non-pinned path (unchanged behavior)", () => {
    const v = evaluate(agent(), rules, {
      integrationId: "github",
      method: "GET",
      path: "/repos/zivisaiah/nanoclaw/pulls?state=open",
    });
    expect(v.effect).toBe("allow");
  });
});
