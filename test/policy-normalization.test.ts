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

  it("is stable on a path that is already fully canonical", () => {
    const once = normalizeRequestPath("//repos/x/../onegate-bot%2Fonegate/pulls");
    expect(once).toBe(CANONICAL);
    expect(normalizeRequestPath(once)).toBe(CANONICAL);
  });

  // Regression guard: normalizeRequestPath is NOT idempotent in general, because
  // decodeOnce peels exactly ONE percent-decode layer per call. Nothing may
  // assume otherwise -- in particular ruleMatches must never re-normalize, or a
  // double-encoded traversal resolves for policy but not for the forwarded
  // request. This documents the non-idempotence so it cannot silently regress
  // into a "safe to call twice" assumption.
  it("is NOT idempotent on a double-encoded traversal (one decode layer per call)", () => {
    const raw = "/repos/onegate-bot/onegate/%252e%252e/x";
    const once = normalizeRequestPath(raw);
    const twice = normalizeRequestPath(once);
    // First pass peels %25 -> %, leaving the dot-segments still encoded, so the
    // traversal does NOT resolve. This is the path forwarded upstream.
    expect(once).toBe("/repos/onegate-bot/onegate/%2e%2e/x");
    // A second pass decodes a layer the proxy never applied, escaping the repo.
    expect(twice).toBe("/repos/onegate-bot/x");
    expect(twice).not.toBe(once);
  });
});

describe("ruleMatches treats req.path as already canonical (no double-decode)", () => {
  const deny = rule({
    integrationId: "github",
    methods: ["*"],
    pathGlob: DENY_GLOB,
    effect: "deny",
  });

  // The proxy normalizes ONCE at the edge and forwards THAT path upstream. The
  // policy engine must match the very same string, otherwise the pin is evaded.
  const doubleEncoded = [
    "/repos/onegate-bot/onegate/%252e%252e/x",
    "/repos/onegate-bot/onegate/%252e%252e/%252e%252e/etc",
    "/repos/onegate-bot/onegate/%252E%252E/x",
  ];

  for (const raw of doubleEncoded) {
    it(`still denies the forwarded form of ${raw}`, () => {
      const forwarded = normalizeRequestPath(raw);
      // The upstream request stays inside the pinned repo subtree...
      expect(forwarded.startsWith("/repos/onegate-bot/onegate/")).toBe(true);
      // ...so the deny rule pinned to that subtree must fire on it.
      expect(
        ruleMatches(deny, { integrationId: "github", method: "GET", path: forwarded }),
      ).toBe(true);
    });
  }

  it("does not re-decode a single-encoded literal segment", () => {
    // %252Fb is a literal "%2Fb" segment after one decode. Re-normalizing would
    // turn it into a path separator and change which rule matches.
    const forwarded = normalizeRequestPath("/repos/onegate-bot/onegate/a%252Fb");
    expect(forwarded).toBe("/repos/onegate-bot/onegate/a%2Fb");
    expect(
      ruleMatches(deny, { integrationId: "github", method: "GET", path: forwarded }),
    ).toBe(true);
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
      // Model the real pipeline: the proxy canonicalizes once at the edge, then
      // policy matches that exact (forwarded) path.
      const forwarded = normalizeRequestPath(p);
      expect(ruleMatches(deny, { integrationId: "github", method: "GET", path: forwarded })).toBe(
        true,
      );
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
    // Re-casing: GitHub resolves owner/repo case-insensitively and serves the
    // pinned repo, so the deny must fire on these too (normalization preserves
    // case by design; the deny glob is what folds it).
    "/repos/OneGate-Bot/onegate/pulls",
    "/repos/onegate-bot/OneGate/pulls",
    "/repos/ONEGATE-BOT/ONEGATE/pulls",
    // Re-casing combined with the encoding evasions above.
    "/repos%2FOneGate-Bot%2FOnegate%2Fpulls",
    "/repos/x/../OneGate-Bot/onegate/pulls",
  ];

  for (const p of denied) {
    it(`denies ${p}`, () => {
      const v = evaluate(agent(), rules, {
        integrationId: "github",
        method: "GET",
        path: normalizeRequestPath(p),
      });
      expect(v.effect).toBe("deny");
      expect(v.ruleId).toBe("rl_deny");
    });
  }

  it("still allows a normal, non-pinned path (unchanged behavior)", () => {
    const v = evaluate(agent(), rules, {
      integrationId: "github",
      method: "GET",
      path: normalizeRequestPath("/repos/zivisaiah/nanoclaw/pulls?state=open"),
    });
    expect(v.effect).toBe("allow");
  });

  // End-to-end regression for the double-encoding deny bypass. Before the fix,
  // evaluate() re-normalized and saw "/repos/onegate-bot/x" (outside the pin) so
  // it ALLOWED, while the proxy forwarded a path still inside the pinned repo.
  it("denies a double-encoded traversal whose forwarded path stays in the pinned repo", () => {
    const rawTarget = "/repos/onegate-bot/onegate/%252e%252e/x";
    const forwarded = normalizeRequestPath(rawTarget);

    // What the vendor actually receives is inside the pinned subtree.
    expect(forwarded).toBe("/repos/onegate-bot/onegate/%2e%2e/x");

    const v = evaluate(agent(), rules, {
      integrationId: "github",
      method: "GET",
      path: forwarded,
    });
    expect(v.effect).toBe("deny");
    expect(v.ruleId).toBe("rl_deny");
  });

  it("denies a multi-segment double-encoded traversal", () => {
    const forwarded = normalizeRequestPath(
      "/repos/onegate-bot/onegate/%252e%252e/%252e%252e/etc",
    );
    const v = evaluate(agent(), rules, {
      integrationId: "github",
      method: "GET",
      path: forwarded,
    });
    expect(v.effect).toBe("deny");
    expect(v.ruleId).toBe("rl_deny");
  });
});
