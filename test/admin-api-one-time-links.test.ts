/**
 * Public one-time-token pages: /approve/:token (held requests) and
 * /renew/:token (lease renewal).
 *
 * These routes sit OUTSIDE the admin Bearer gate, so the token in the URL is
 * the only credential. Each must refuse a forged, replayed, expired, or
 * wrong-kind token with the 410 invalid-link page and leave state untouched,
 * and must escape every value it echoes back.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { hashToken } from "../src/store/db.js";
import { startAdmin, type AdminHarness } from "./admin-harness.js";

let h: AdminHarness;
let agentId: string;

beforeAll(async () => {
  h = await startAdmin({ publicBaseUrl: "https://gate.example" });
  agentId = h.store.createAgent("approver-bot").agent.id;
});

afterAll(async () => {
  await h.close();
});

/** Raw handle for back-dating rows (the Store exposes no setter for expiry). */
function db(): { prepare(sql: string): { run(...a: unknown[]): unknown } } {
  return (h.store as unknown as { db: never }).db;
}

function gateRule(subject = agentId) {
  return h.store.createRule({
    scope: "agent",
    subjectId: subject,
    integrationId: "github",
    methods: ["POST"],
    pathGlob: "/**",
    effect: "deny",
    action: "require_approval",
  });
}

function holdRequest(opts: { agent?: string; integrationId?: string; path?: string; method?: string } = {}) {
  const rule = gateRule(opts.agent ?? agentId);
  return h.store.createApproval({
    agentId: opts.agent ?? agentId,
    integrationId: opts.integrationId ?? "github",
    ruleId: rule.id,
    method: opts.method ?? "post",
    path: opts.path ?? "/repos/acme/app/issues",
  });
}

const INVALID = /This link is no longer valid/;

describe("GET /approve/:token", () => {
  it("renders the decision page for a live pending approval, escaping the held request", async () => {
    const ap = holdRequest({ path: '/repos/<script>alert("x")</script>' });
    const r = await h.get(`/approve/${ap.token}`);
    expect(r.status).toBe(200);
    expect(r.headers["content-type"]).toMatch(/text\/html/);
    expect(r.text).toContain("Allow approver-bot to run this GitHub request?");
    // The method was upper-cased at mint time.
    expect(r.text).toContain("<code>POST /repos/&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;</code>");
    expect(r.text).not.toContain("<script>alert");
    // The form posts back to the public base, carrying the same token.
    expect(r.text).toContain(`action="https://gate.example/approve/${ap.token}"`);
    expect(r.text).toMatch(/name="decision" value="approve"/);
    expect(r.text).toMatch(/name="decision" value="reject"/);
    // Rendering is read-only.
    expect(h.store.getApproval(ap.id)?.status).toBe("pending");
  });

  it("refuses a forged token", async () => {
    holdRequest();
    const r = await h.get(`/approve/${"ab".repeat(24)}`);
    expect(r.status).toBe(410);
    expect(r.text).toMatch(INVALID);
  });

  it("refuses an approval that was already decided", async () => {
    const ap = holdRequest();
    h.store.decideApproval(ap.id, "rejected");
    const r = await h.get(`/approve/${ap.token}`);
    expect(r.status).toBe(410);
  });

  it("refuses a still-pending approval that is past its expiry", async () => {
    const ap = holdRequest();
    db().prepare("UPDATE approvals SET expires_at = ? WHERE id = ?").run(new Date(Date.now() - 1000).toISOString(), ap.id);
    const r = await h.get(`/approve/${ap.token}`);
    expect(r.status).toBe(410);
  });

  it("falls back to neutral wording when the agent and integration are gone", async () => {
    const ghost = h.store.createAgent("ghost-bot").agent.id;
    const ap = holdRequest({ agent: ghost, integrationId: "retired-<vendor>" });
    h.store.deleteAgent(ghost);
    const r = await h.get(`/approve/${ap.token}`);
    // The approval row outlives its agent; the page must not crash or echo
    // the unregistered integration id unescaped.
    expect(r.status).toBe(200);
    expect(r.text).toContain("Allow Your bot to run this retired-&lt;vendor&gt; request?");
  });
});

describe("POST /approve/:token", () => {
  it("approve flips the row once; a replay of the same link is refused and changes nothing", async () => {
    const ap = holdRequest();
    const first = await h.postForm(`/approve/${ap.token}`, { decision: "approve" });
    expect(first.status).toBe(200);
    expect(first.text).toContain("Approved");
    expect(first.text).toContain("approver-bot can retry that GitHub request once");
    const decided = h.store.getApproval(ap.id)!;
    expect(decided.status).toBe("approved");
    expect(decided.decidedAt).toBeTruthy();

    // Replay with the opposite decision: must not flip an already-decided row.
    const replay = await h.postForm(`/approve/${ap.token}`, { decision: "reject" });
    expect(replay.status).toBe(410);
    expect(replay.text).toMatch(INVALID);
    expect(h.store.getApproval(ap.id)?.status).toBe("approved");
    expect(h.store.getApproval(ap.id)?.decidedAt).toBe(decided.decidedAt);
  });

  it("reject records a rejection", async () => {
    const ap = holdRequest();
    const r = await h.postForm(`/approve/${ap.token}`, { decision: "reject" });
    expect(r.status).toBe(200);
    expect(r.text).toContain("Rejected");
    expect(r.text).toContain("approver-bot will not run that GitHub request");
    expect(h.store.getApproval(ap.id)?.status).toBe("rejected");
  });

  it("anything other than an explicit 'approve' is a rejection, never consent", async () => {
    for (const fields of [{}, { decision: "APPROVE" }, { decision: "yes" }, { decision: ["approve", "approve"] }]) {
      const ap = holdRequest();
      const r = await h.postForm(`/approve/${ap.token}`, fields as Record<string, string | string[]>);
      expect(r.status).toBe(200);
      expect(h.store.getApproval(ap.id)?.status).toBe("rejected");
    }
  });

  it("refuses a forged token without touching any approval", async () => {
    const ap = holdRequest();
    const r = await h.postForm(`/approve/${"cd".repeat(24)}`, { decision: "approve" });
    expect(r.status).toBe(410);
    expect(h.store.getApproval(ap.id)?.status).toBe("pending");
  });

  it("refuses an expired approval and records it as expired", async () => {
    const ap = holdRequest();
    db().prepare("UPDATE approvals SET expires_at = ? WHERE id = ?").run(new Date(Date.now() - 1000).toISOString(), ap.id);
    const r = await h.postForm(`/approve/${ap.token}`, { decision: "approve" });
    expect(r.status).toBe(410);
    expect(h.store.getApproval(ap.id)?.status).toBe("expired");
  });

  it("the DB never holds a usable token: the stored hash itself is not accepted", async () => {
    const ap = holdRequest();
    const r = await h.postForm(`/approve/${ap.tokenHash}`, { decision: "approve" });
    expect(r.status).toBe(410);
    expect(h.store.getApproval(ap.id)?.status).toBe("pending");
  });
});

describe("/renew/:token", () => {
  function leasedRule(ttl: number | null) {
    return h.store.createRule({
      scope: "agent",
      subjectId: agentId,
      integrationId: "hetzner",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
      leaseTtlSeconds: ttl,
    });
  }
  function renewalLink(ruleId: string | null) {
    return h.store.createOnboardingLink({ agentId, integrationId: "hetzner", ruleId });
  }

  it("GET refuses a forged token, and an onboarding link that is not a renewal link", async () => {
    expect((await h.get(`/renew/${"ef".repeat(24)}`)).status).toBe(410);
    const connectLink = renewalLink(null);
    const r = await h.get(`/renew/${connectLink.token}`);
    expect(r.status).toBe(410);
    expect(r.text).toMatch(INVALID);
    // POST is refused the same way and does not consume the connect link.
    expect((await h.postForm(`/renew/${connectLink.token}`)).status).toBe(410);
    expect(h.store.getOnboardingLink(connectLink.token)?.usedAt).toBeNull();
  });

  it("GET refuses a renewal link whose rule was deleted", async () => {
    const rule = leasedRule(3600);
    const link = renewalLink(rule.id);
    h.store.deleteRule(rule.id);
    expect((await h.get(`/renew/${link.token}`)).status).toBe(410);
  });

  it("GET states the renewal period in the most natural unit", async () => {
    for (const [ttl, phrase] of [
      [1800, "for another 30m"],
      [90, "for another 90s"],
      [7200, "for another 2h"],
    ] as const) {
      const link = renewalLink(leasedRule(ttl).id);
      const r = await h.get(`/renew/${link.token}`);
      expect(r.status).toBe(200);
      expect(r.text).toContain(`Re-allow ${phrase}`);
      expect(r.text).toContain(`action="https://gate.example/renew/${link.token}"`);
    }
  });

  it("GET for a rule without a lease offers a plain re-allow", async () => {
    const link = renewalLink(leasedRule(null).id);
    const r = await h.get(`/renew/${link.token}`);
    expect(r.status).toBe(200);
    expect(r.text).not.toContain("for another");
  });

  it("POST renews once; a replay is refused and does not stack another period", async () => {
    const rule = leasedRule(3600);
    const link = renewalLink(rule.id);
    const first = await h.postForm(`/renew/${link.token}`);
    expect(first.status).toBe(200);
    expect(first.text).toContain("approver-bot is re-allowed");
    expect(first.text).toContain("for the next 1h");
    const renewedAt = h.store.getRule(rule.id)!.expiresAt!;
    expect(Date.parse(renewedAt)).toBeGreaterThan(Date.now() + 3500_000);

    const replay = await h.postForm(`/renew/${link.token}`);
    expect(replay.status).toBe(410);
    expect(h.store.getRule(rule.id)!.expiresAt).toBe(renewedAt);
  });

  it("POST refuses an expired renewal link", async () => {
    const rule = leasedRule(3600);
    const link = renewalLink(rule.id);
    db()
      .prepare("UPDATE onboarding_links SET expires_at = ? WHERE token_hash = ?")
      .run(new Date(Date.now() - 1000).toISOString(), hashToken(link.token));
    expect((await h.postForm(`/renew/${link.token}`)).status).toBe(410);
    expect(Date.parse(h.store.getRule(rule.id)!.expiresAt!)).toBeLessThan(Date.now());
  });

  it("POST for a rule deleted after the link was minted consumes the link and reports it invalid", async () => {
    const rule = leasedRule(3600);
    const link = renewalLink(rule.id);
    h.store.deleteRule(rule.id);
    const r = await h.postForm(`/renew/${link.token}`);
    expect(r.status).toBe(410);
    // Claimed before the lookup: the dead link cannot be retried.
    expect(h.store.getOnboardingLink(link.token)?.usedAt).toBeTruthy();
  });
});
