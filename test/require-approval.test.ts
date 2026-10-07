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
 *  5. An approved approval lets the identical request through exactly once:
 *     redemption is atomic and bound to agent, integration, rule, method, path
 *     and body hash. (The proxy round trip is in require-approval-proxy.test.ts.)
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
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
    // Once decided it is no longer PENDING, so it is not reused as a pending
    // hold. An approved row is spent through redeemApproval instead.
    store.decideApproval(first.id, "approved", now);
    expect(store.activeApprovalFor(a.id, "github", "POST", "/x", now)).toBeNull();
  });

  it("reuses a pending approval only for the same body", () => {
    const store = newStore();
    const { agent: a } = store.createAgent("bot");
    const first = store.createApproval({
      agentId: a.id,
      integrationId: "github",
      ruleId: "rl_gate",
      method: "POST",
      path: "/x",
      bodyHash: "aa",
    });
    const now = Date.now();
    expect(store.activeApprovalFor(a.id, "github", "POST", "/x", now, "aa")?.id).toBe(first.id);
    expect(store.activeApprovalFor(a.id, "github", "POST", "/x", now, "bb")).toBeNull();
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

describe("approval redemption", () => {
  const req = (agentId: string, over: Partial<Parameters<Store["redeemApproval"]>[0]> = {}) => ({
    agentId,
    integrationId: "github",
    ruleId: "rl_gate",
    method: "POST",
    path: "/repos/x/issues",
    bodyHash: "h1",
    ...over,
  });

  function approved(store: Store, agentId: string, ttlSeconds?: number) {
    const ap = store.createApproval({ ...req(agentId), ttlSeconds });
    store.decideApproval(ap.id, "approved", Date.now());
    return ap;
  }

  it("lets the identical request through exactly once", () => {
    const store = newStore();
    const { agent: a } = store.createAgent("bot");
    const ap = approved(store, a.id);
    const redeemed = store.redeemApproval(req(a.id));
    expect(redeemed?.id).toBe(ap.id);
    expect(redeemed?.usedAt).not.toBeNull();
    expect(store.redeemApproval(req(a.id))).toBeNull();
  });

  it("is bound to agent, integration, rule, method, path and body", () => {
    const store = newStore();
    const { agent: a } = store.createAgent("bot");
    const { agent: b } = store.createAgent("other");
    approved(store, a.id);
    for (const over of [
      { agentId: b.id },
      { integrationId: "gitlab" },
      { ruleId: "rl_other" },
      { method: "PUT" },
      { path: "/repos/y/issues" },
      { path: "/repos/x/issues?force=1" },
      { bodyHash: "h2" },
    ]) {
      expect(store.redeemApproval(req(a.id, over))).toBeNull();
    }
    // Lowercase method still matches: methods are stored uppercase.
    expect(store.redeemApproval(req(a.id, { method: "post" }))).not.toBeNull();
  });

  it("never redeems a pending, rejected or expired approval", () => {
    const store = newStore();
    const { agent: a } = store.createAgent("bot");
    store.createApproval(req(a.id));
    expect(store.redeemApproval(req(a.id))).toBeNull();

    const rejected = store.createApproval(req(a.id));
    store.decideApproval(rejected.id, "rejected", Date.now());
    expect(store.redeemApproval(req(a.id))).toBeNull();

    const late = approved(store, a.id, 60);
    expect(store.redeemApproval(req(a.id), Date.parse(late.expiresAt) + 1000)).toBeNull();
    expect(store.getApproval(late.id)?.usedAt).toBeNull();
  });

  it("loses cleanly when another writer claims the row between lookup and claim", () => {
    // Two gateway processes on one database. Store `first` is interrupted after
    // it found the candidate but before its guarded UPDATE runs, and `second`
    // redeems in that gap. The guard must leave `first` with zero changes.
    const file = join(mkdtempSync(join(tmpdir(), "og-approval-race-")), "onegate.db");
    const first = new Store(file);
    const second = new Store(file);
    const { agent: a } = first.createAgent("bot");
    const ap = approved(first, a.id);

    const raw = (first as unknown as { db: DatabaseSync }).db;
    const prepare = raw.prepare.bind(raw);
    let interleaved = false;
    raw.prepare = ((sql: string) => {
      if (sql.startsWith("UPDATE approvals SET used_at") && !interleaved) {
        interleaved = true;
        expect(second.redeemApproval(req(a.id))?.id).toBe(ap.id);
      }
      return prepare(sql);
    }) as typeof raw.prepare;

    expect(first.redeemApproval(req(a.id))).toBeNull();
    expect(interleaved).toBe(true);
    first.close();
    second.close();
  });

  it("migrates a legacy approvals table and never redeems its rows", () => {
    const file = join(mkdtempSync(join(tmpdir(), "og-approval-legacy-")), "onegate.db");
    const legacy = new DatabaseSync(file);
    legacy.exec(`CREATE TABLE approvals (
      id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, integration_id TEXT NOT NULL,
      rule_id TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','expired')),
      created_at TEXT NOT NULL, expires_at TEXT NOT NULL, decided_at TEXT)`);
    const future = new Date(Date.now() + 3600_000).toISOString();
    legacy
      .prepare("INSERT INTO approvals VALUES ('apr_old', 'ag_1', 'github', 'rl_gate', 'POST', '/x', 'h', 'approved', ?, ?, ?)")
      .run(new Date().toISOString(), future, new Date().toISOString());
    legacy.close();

    const store = new Store(file);
    const old = store.getApproval("apr_old")!;
    expect(old.bodyHash).toBeNull();
    expect(old.usedAt).toBeNull();
    // No recorded body hash: fails closed, whatever the retry sends.
    expect(
      store.redeemApproval({ agentId: "ag_1", integrationId: "github", ruleId: "rl_gate", method: "POST", path: "/x", bodyHash: "" }),
    ).toBeNull();
    store.close();
  });
});
