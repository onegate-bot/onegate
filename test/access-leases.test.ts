import { describe, it, expect, beforeEach } from "vitest";
import { Store, DEFAULT_INTEGRATION_LEASES } from "../src/store/db.js";
import { evaluate, ruleLapsed } from "../src/policy.js";
import type { Agent, Rule } from "../src/types.js";

// ---- policy: lapse semantics ----

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
    integrationId: "hetzner",
    methods: ["*"],
    pathGlob: "/**",
    effect: "allow",
    createdAt: "",
    ...partial,
  };
}

const req = { integrationId: "hetzner", method: "GET", path: "/v1/servers" };
const HOUR = 3600 * 1000;

describe("ruleLapsed", () => {
  it("is false with no expiry, false before, true after", () => {
    const now = 1_000_000;
    expect(ruleLapsed(rule({ expiresAt: null }), now)).toBe(false);
    expect(ruleLapsed(rule({ expiresAt: new Date(now + HOUR).toISOString() }), now)).toBe(false);
    expect(ruleLapsed(rule({ expiresAt: new Date(now - HOUR).toISOString() }), now)).toBe(true);
  });
});

describe("evaluate with access leases", () => {
  const now = Date.parse("2026-07-18T12:00:00.000Z");

  it("a live leased allow rule allows", () => {
    const r = rule({ expiresAt: new Date(now + HOUR).toISOString(), leaseTtlSeconds: 3600 });
    const res = evaluate(agent(), [r], req, now);
    expect(res.effect).toBe("allow");
    expect(res.ruleId).toBe(r.id);
    expect(res.lapsed).toBeFalsy();
  });

  it("a lapsed leased allow rule denies with lapse flags for renewal", () => {
    const r = rule({
      id: "rl_lapsed",
      expiresAt: new Date(now - HOUR).toISOString(),
      leaseTtlSeconds: 3600,
    });
    const res = evaluate(agent(), [r], req, now);
    expect(res.effect).toBe("deny");
    expect(res.lapsed).toBe(true);
    expect(res.lapsedRuleId).toBe("rl_lapsed");
    expect(res.lapsedExpiresAt).toBe(r.expiresAt);
  });

  it("an explicit deny always wins, even over a live lease", () => {
    const allow = rule({ id: "rl_a", expiresAt: new Date(now + HOUR).toISOString() });
    const deny = rule({ id: "rl_d", effect: "deny" });
    expect(evaluate(agent(), [allow, deny], req, now).effect).toBe("deny");
    expect(evaluate(agent(), [allow, deny], req, now).ruleId).toBe("rl_d");
  });

  it("a still-live allow rule wins over a lapsed one", () => {
    const lapsed = rule({ id: "rl_old", expiresAt: new Date(now - HOUR).toISOString() });
    const live = rule({ id: "rl_new", expiresAt: new Date(now + HOUR).toISOString() });
    const res = evaluate(agent(), [lapsed, live], req, now);
    expect(res.effect).toBe("allow");
    expect(res.ruleId).toBe("rl_new");
  });

  it("an allow-all agent is unaffected by a lapsed lease", () => {
    const r = rule({ expiresAt: new Date(now - HOUR).toISOString() });
    const res = evaluate(agent("allow-all"), [r], req, now);
    expect(res.effect).toBe("allow");
    expect(res.lapsed).toBeFalsy();
  });
});

// ---- store: integration leases + rule leases ----

describe("integration leases (time-box catalog)", () => {
  let store: Store;
  beforeEach(() => {
    store = new Store(":memory:");
  });

  it("seeds the default time-boxed integrations (Hetzner 8h)", () => {
    for (const [id, ttl] of DEFAULT_INTEGRATION_LEASES) {
      expect(store.getIntegrationLease(id)).toBe(ttl);
    }
    expect(store.getIntegrationLease("hetzner")).toBe(8 * 3600);
  });

  it("existing non-Hetzner integrations are regular (no lease)", () => {
    expect(store.getIntegrationLease("github")).toBeNull();
    expect(store.getIntegrationLease("google")).toBeNull();
  });

  it("set / list / clear a default time-box", () => {
    store.setIntegrationLease("github", 1800);
    expect(store.getIntegrationLease("github")).toBe(1800);
    const list = store.listIntegrationLeases();
    expect(list.find((l) => l.integrationId === "github")?.ttlSeconds).toBe(1800);
    store.clearIntegrationLease("github");
    expect(store.getIntegrationLease("github")).toBeNull();
  });

  it("setIntegrationLease upserts (updates the TTL)", () => {
    store.setIntegrationLease("github", 100);
    store.setIntegrationLease("github", 200);
    expect(store.getIntegrationLease("github")).toBe(200);
  });
});

describe("effectiveLeaseTtlSeconds (override resolution)", () => {
  let store: Store;
  beforeEach(() => {
    store = new Store(":memory:");
  });

  it("owner override wins over the integration default", () => {
    // hetzner default is 8h; owner sets 2h
    expect(store.effectiveLeaseTtlSeconds("hetzner", 7200)).toBe(7200);
  });

  it("owner override of 0 means always-on (no lease)", () => {
    expect(store.effectiveLeaseTtlSeconds("hetzner", 0)).toBeNull();
  });

  it("no override falls back to the integration default", () => {
    expect(store.effectiveLeaseTtlSeconds("hetzner", null)).toBe(8 * 3600);
  });

  it("no override + regular integration means no lease", () => {
    expect(store.effectiveLeaseTtlSeconds("github", null)).toBeNull();
  });
});

describe("rule lease stamping + renewal", () => {
  let store: Store;
  beforeEach(() => {
    store = new Store(":memory:");
  });

  it("createRule records an expiry + lease TTL", () => {
    const expiresAt = new Date(Date.now() + 8 * 3600 * 1000).toISOString();
    const r = store.createRule({
      scope: "agent",
      subjectId: "ag_x",
      integrationId: "hetzner",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
      expiresAt,
      leaseTtlSeconds: 8 * 3600,
    });
    const got = store.getRule(r.id)!;
    expect(got.expiresAt).toBe(expiresAt);
    expect(got.leaseTtlSeconds).toBe(8 * 3600);
  });

  it("renewRule re-stamps expiry to now + TTL without re-entering credentials", () => {
    const r = store.createRule({
      scope: "agent",
      subjectId: "ag_x",
      integrationId: "hetzner",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
      expiresAt: new Date(Date.now() - 3600 * 1000).toISOString(), // already lapsed
      leaseTtlSeconds: 8 * 3600,
    });
    const before = Date.now();
    const renewed = store.renewRule(r.id)!;
    const newExpiry = Date.parse(renewed.expiresAt!);
    expect(newExpiry).toBeGreaterThan(before + 7 * 3600 * 1000);
    expect(ruleLapsed(renewed, Date.now())).toBe(false);
  });

  it("renewRule on an always-on rule (no TTL) is a no-op, not an error", () => {
    const r = store.createRule({
      scope: "agent",
      subjectId: "ag_x",
      integrationId: "github",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
    const renewed = store.renewRule(r.id)!;
    expect(renewed.expiresAt ?? null).toBeNull();
  });

  it("renewRule returns null for an unknown rule", () => {
    expect(store.renewRule("rl_nope")).toBeNull();
  });
});

describe("renewal links + per-lapse dedup", () => {
  let store: Store;
  beforeEach(() => {
    store = new Store(":memory:");
  });

  it("a renewal link carries the rule id and is reused while live", () => {
    const { agent } = store.createAgent("bot");
    const r = store.createRule({
      scope: "agent",
      subjectId: agent.id,
      integrationId: "hetzner",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
      leaseTtlSeconds: 8 * 3600,
    });
    const link = store.createOnboardingLink({
      agentId: agent.id,
      integrationId: "hetzner",
      ruleId: r.id,
    });
    expect(link.ruleId).toBe(r.id);
    expect(store.activeRenewalLinkFor(r.id)?.token).toBe(link.token);
  });

  it("owner notifications dedup per lapse via dedupKey", () => {
    const { agent } = store.createAgent("bot");
    const dedupKey = "lease:rl_1:2026-07-18T12:00:00.000Z";
    store.enqueueOwnerNotification({
      agentId: agent.id,
      integrationId: "hetzner",
      connectToken: "abc",
      dedupKey,
    });
    expect(store.findOwnerNotificationByDedupKey(dedupKey)).not.toBeNull();
    expect(store.findOwnerNotificationByDedupKey("lease:rl_1:other")).toBeNull();
  });
});
