/**
 * U5 phase one: `require_approval` as a rule action.
 *
 * The invariants under test, in order of how much damage breaking them does:
 *
 *  1. DENY still short-circuits and wins outright. require_approval sits below
 *     it and can never soften an explicit block.
 *  2. require_approval outranks a plain allow, so a narrow gate layered on a
 *     broad grant actually bites instead of being silently inert.
 *  3. The feature can never fail open. A require_approval rule is persisted
 *     with effect "deny", so every consumer that has not learned about actions
 *     (the LLM mode badge, discovery, the admin UI) reads it as a block.
 *  4. Approval tokens are unguessable hex and single-use, and a pending
 *     approval expires.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluate } from "../src/policy.js";
import { Store } from "../src/store/db.js";
import { vendorAllowed } from "../src/llm/mode.js";
import type { Agent, Rule } from "../src/types.js";

function agent(defaultPolicy: Agent["defaultPolicy"] = "deny-unmatched"): Agent {
  return { id: "ag_1", name: "test", tokenHash: "x", projectId: null, defaultPolicy, createdAt: "" };
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

function newStore(): Store {
  return new Store(join(mkdtempSync(join(tmpdir(), "og-approval-")), "onegate.db"));
}

describe("policy: require_approval precedence", () => {
  it("holds a matching request instead of allowing it", () => {
    const v = evaluate(agent("allow-all"), [
      rule({ id: "rl_gate", effect: "deny", action: "require_approval" }),
    ], { integrationId: "github", method: "DELETE", path: "/repos/x/y" });
    expect(v.effect).toBe("deny");
    expect(v.requiresApproval).toBe(true);
    expect(v.ruleId).toBe("rl_gate");
  });

  it("an explicit deny still beats require_approval, whatever the rule order", () => {
    const gate = rule({ id: "rl_gate", effect: "deny", action: "require_approval" });
    const block = rule({ id: "rl_block", effect: "deny", pathGlob: "/repos/**" });

    for (const rules of [
      [gate, block],
      [block, gate],
    ]) {
      const v = evaluate(agent("allow-all"), rules, { integrationId: "github", method: "DELETE", path: "/repos/x/y" });
      expect(v.effect).toBe("deny");
      // The deny wins outright: no approval is offered, so there is nothing for
      // an owner to click that would unblock a request they have blocked.
      expect(v.requiresApproval).toBeUndefined();
      expect(v.ruleId).toBe("rl_block");
    }
  });

  it("require_approval outranks a broad allow, whatever the rule order", () => {
    const broad = rule({ id: "rl_allow", effect: "allow", pathGlob: "/**" });
    const gate = rule({
      id: "rl_gate",
      effect: "deny",
      action: "require_approval",
      pathGlob: "/repos/*/delete",
    });

    for (const rules of [
      [broad, gate],
      [gate, broad],
    ]) {
      const v = evaluate(agent(), rules, { integrationId: "github", method: "POST", path: "/repos/x/delete" });
      expect(v.requiresApproval).toBe(true);
      expect(v.ruleId).toBe("rl_gate");
    }
  });

  it("leaves traffic the gate does not match untouched", () => {
    const rules = [
      rule({ id: "rl_allow", effect: "allow", pathGlob: "/**" }),
      rule({ id: "rl_gate", effect: "deny", action: "require_approval", pathGlob: "/repos/*/delete" }),
    ];
    const v = evaluate(agent(), rules, { integrationId: "github", method: "GET", path: "/repos/x/pulls" });
    expect(v.effect).toBe("allow");
    expect(v.requiresApproval).toBeUndefined();
  });

  it("never manufactures access: the reported effect is always deny", () => {
    // Even under allow-all, and even matched alone, the verdict is a refusal.
    const v = evaluate(agent("allow-all"), [
      rule({ id: "rl_gate", effect: "deny", action: "require_approval" }),
    ], { integrationId: "github", method: "POST", path: "/x" });
    expect(v.effect).not.toBe("allow");
  });
});

describe("require_approval cannot fail open", () => {
  it("is stored as a deny, so a consumer that ignores actions still blocks", () => {
    const store = newStore();
    const { agent: a } = store.createAgent("bot");
    const r = store.createRule({
      scope: "agent",
      subjectId: a.id,
      integrationId: "github",
      methods: ["*"],
      pathGlob: "/**",
      // Even asked for as an allow, the action forces the stored effect to deny.
      effect: "allow",
      action: "require_approval",
    });
    expect(r.effect).toBe("deny");
    expect(r.action).toBe("require_approval");

    // The LLM mode badge reads `effect` and has never heard of actions. It must
    // see a block, not a grant.
    expect(vendorAllowed("github", [{ integrationId: "github", effect: r.effect }], true)).toBe(false);
  });

  it("degrades to a plain deny when the action is dropped", () => {
    // Simulates an older engine, or a row whose action column is unreadable:
    // strip the action and the same rule is simply a deny. It never becomes an
    // allow, and it never disappears.
    const gate = rule({ id: "rl_gate", effect: "deny", action: "require_approval" });
    const stripped = { ...gate, action: null };
    const v = evaluate(agent("allow-all"), [stripped], { integrationId: "github", method: "POST", path: "/x" });
    expect(v.effect).toBe("deny");
    expect(v.requiresApproval).toBeUndefined();
  });

  it("drops an unrecognised stored action rather than trusting it", () => {
    const store = newStore();
    const { agent: a } = store.createAgent("bot");
    const r = store.createRule({
      scope: "agent",
      subjectId: a.id,
      integrationId: "github",
      methods: ["*"],
      pathGlob: "/**",
      effect: "deny",
    });
    expect(store.getRule(r.id)?.action).toBeNull();
  });
});

describe("approvals store", () => {
  it("mints an unguessable hex token and persists only its hash", () => {
    const store = newStore();
    const { agent: a } = store.createAgent("bot");
    const approval = store.createApproval({
      agentId: a.id,
      integrationId: "github",
      ruleId: "rl_gate",
      method: "POST",
      path: "/repos/x/delete",
    });
    // Hex, because chat clients mangle the underscores in base64url.
    expect(approval.token).toMatch(/^[0-9a-f]{48}$/);
    expect(approval.tokenHash).not.toBe(approval.token);
    // The plaintext is never recoverable from storage.
    expect(store.getApproval(approval.id)?.token).toBe("");
    expect(store.getApprovalByToken(approval.token)?.id).toBe(approval.id);
    expect(store.getApprovalByToken("deadbeef")).toBeNull();
  });

  it("is single-use: a decided approval cannot be decided again", () => {
    const store = newStore();
    const { agent: a } = store.createAgent("bot");
    const approval = store.createApproval({
      agentId: a.id,
      integrationId: "github",
      ruleId: "rl_gate",
      method: "POST",
      path: "/x",
    });
    expect(store.decideApproval(approval.id, "approved", Date.now())?.status).toBe("approved");
    // Replaying the same link, or flipping the decision afterwards, is refused.
    expect(store.decideApproval(approval.id, "rejected", Date.now())).toBeNull();
    expect(store.getApproval(approval.id)?.status).toBe("approved");
  });

  it("expires a pending approval and refuses to decide it afterwards", () => {
    const store = newStore();
    const { agent: a } = store.createAgent("bot");
    const approval = store.createApproval({
      agentId: a.id,
      integrationId: "github",
      ruleId: "rl_gate",
      method: "POST",
      path: "/x",
      ttlSeconds: 60,
    });
    const later = Date.parse(approval.expiresAt) + 1000;
    expect(store.decideApproval(approval.id, "approved", later)).toBeNull();
    expect(store.getApproval(approval.id)?.status).toBe("expired");
  });

  it("sweeps expired approvals idempotently and leaves decided ones alone", () => {
    const store = newStore();
    const { agent: a } = store.createAgent("bot");
    const stale = store.createApproval({
      agentId: a.id,
      integrationId: "github",
      ruleId: "rl_gate",
      method: "POST",
      path: "/stale",
      ttlSeconds: 60,
    });
    const decided = store.createApproval({
      agentId: a.id,
      integrationId: "github",
      ruleId: "rl_gate",
      method: "POST",
      path: "/decided",
    });
    store.decideApproval(decided.id, "rejected", Date.now());

    const later = Date.parse(stale.expiresAt) + 1000;
    expect(store.expireApprovals(later)).toBe(1);
    expect(store.expireApprovals(later)).toBe(0);
    expect(store.getApproval(stale.id)?.status).toBe("expired");
    expect(store.getApproval(decided.id)?.status).toBe("rejected");
  });

  it("reuses one live approval across retries of the same request", () => {
    const store = newStore();
    const { agent: a } = store.createAgent("bot");
    const first = store.createApproval({
      agentId: a.id,
      integrationId: "github",
      ruleId: "rl_gate",
      method: "POST",
      path: "/x",
    });
    const now = Date.now();
    // A retried request must not spam the owner with a fresh link each time.
    expect(store.activeApprovalFor(a.id, "github", "POST", "/x", now)?.id).toBe(first.id);
    // A different request is a different decision.
    expect(store.activeApprovalFor(a.id, "github", "DELETE", "/x", now)).toBeNull();
    // Once decided, it is no longer live, so the next attempt starts fresh.
    store.decideApproval(first.id, "approved", now);
    expect(store.activeApprovalFor(a.id, "github", "POST", "/x", now)).toBeNull();
  });

  it("scopes the list to one agent", () => {
    const store = newStore();
    const { agent: a } = store.createAgent("a");
    const { agent: b } = store.createAgent("b");
    for (const ag of [a, b]) {
      store.createApproval({
        agentId: ag.id,
        integrationId: "github",
        ruleId: "rl_gate",
        method: "POST",
        path: "/x",
      });
    }
    expect(store.listApprovals().length).toBe(2);
    expect(store.listApprovals(a.id).map((x) => x.agentId)).toEqual([a.id]);
  });
});
