import { describe, it, expect, beforeEach } from "vitest";
import { Store } from "../src/store/db.js";

let store: Store;

beforeEach(() => {
  store = new Store(":memory:");
});

describe("onboarding links", () => {
  it("creates a link with an unguessable token and a 7 day default TTL", () => {
    const before = Date.now();
    const link = store.createOnboardingLink({ agentId: "ag_1", integrationId: "google" });
    expect(link.token).toMatch(/^[A-Za-z0-9_-]{32}$/);
    expect(link.agentId).toBe("ag_1");
    expect(link.integrationId).toBe("google");
    expect(link.usedAt).toBeNull();
    const ttlMs = new Date(link.expiresAt).getTime() - new Date(link.createdAt).getTime();
    expect(ttlMs).toBeGreaterThan(6.9 * 24 * 60 * 60 * 1000);
    expect(ttlMs).toBeLessThan(7.1 * 24 * 60 * 60 * 1000);
    expect(new Date(link.expiresAt).getTime()).toBeGreaterThan(before);
  });

  it("honours a custom ttlDays, scopes and connectionName", () => {
    const link = store.createOnboardingLink({
      agentId: "ag_2",
      integrationId: "slack",
      scopes: ["chat:write", "channels:read"],
      connectionName: "Slack for Ezer",
      ttlDays: 2,
    });
    expect(link.scopes).toEqual(["chat:write", "channels:read"]);
    expect(link.connectionName).toBe("Slack for Ezer");
    const ttlMs = new Date(link.expiresAt).getTime() - new Date(link.createdAt).getTime();
    expect(ttlMs).toBeGreaterThan(1.9 * 24 * 60 * 60 * 1000);
    expect(ttlMs).toBeLessThan(2.1 * 24 * 60 * 60 * 1000);
  });

  it("normalizes empty scopes to null", () => {
    const link = store.createOnboardingLink({ agentId: "ag_3", integrationId: "google", scopes: [] });
    expect(link.scopes).toBeNull();
  });

  it("generates distinct tokens", () => {
    const a = store.createOnboardingLink({ agentId: "ag", integrationId: "google" });
    const b = store.createOnboardingLink({ agentId: "ag", integrationId: "google" });
    expect(a.token).not.toBe(b.token);
  });

  it("gets a link by token and round-trips fields", () => {
    const link = store.createOnboardingLink({
      agentId: "ag_4",
      integrationId: "jira",
      scopes: ["read:jira-work"],
      connectionName: "Jira",
    });
    const got = store.getOnboardingLink(link.token);
    expect(got).toEqual(link);
    expect(store.getOnboardingLink("nope")).toBeNull();
  });

  it("treats a fresh unused link as valid", () => {
    const link = store.createOnboardingLink({ agentId: "ag_5", integrationId: "google" });
    expect(store.isOnboardingLinkValid(store.getOnboardingLink(link.token))).toBe(true);
  });

  it("treats a used link as invalid", () => {
    const link = store.createOnboardingLink({ agentId: "ag_6", integrationId: "google" });
    store.markOnboardingLinkUsed(link.token);
    const got = store.getOnboardingLink(link.token);
    expect(got?.usedAt).not.toBeNull();
    expect(store.isOnboardingLinkValid(got)).toBe(false);
  });

  it("treats an expired link as invalid", () => {
    const link = store.createOnboardingLink({ agentId: "ag_7", integrationId: "google", ttlDays: 7 });
    // Backdate expiry directly to simulate the clock moving past it.
    (store as unknown as { db: { prepare(sql: string): { run(...a: unknown[]): void } } }).db
      .prepare("UPDATE onboarding_links SET expires_at = ? WHERE token = ?")
      .run(new Date(Date.now() - 1000).toISOString(), link.token);
    expect(store.isOnboardingLinkValid(store.getOnboardingLink(link.token))).toBe(false);
  });

  it("treats a null link as invalid", () => {
    expect(store.isOnboardingLinkValid(null)).toBe(false);
  });

  it("lists links for an agent, newest first, and all links", () => {
    const a = store.createOnboardingLink({ agentId: "ag_A", integrationId: "google" });
    const b = store.createOnboardingLink({ agentId: "ag_A", integrationId: "slack" });
    store.createOnboardingLink({ agentId: "ag_B", integrationId: "google" });
    const forA = store.listOnboardingLinks("ag_A");
    expect(forA.map((l) => l.token)).toContain(a.token);
    expect(forA.map((l) => l.token)).toContain(b.token);
    expect(forA.every((l) => l.agentId === "ag_A")).toBe(true);
    expect(store.listOnboardingLinks().length).toBe(3);
  });

  it("deletes a link", () => {
    const link = store.createOnboardingLink({ agentId: "ag_8", integrationId: "google" });
    store.deleteOnboardingLink(link.token);
    expect(store.getOnboardingLink(link.token)).toBeNull();
  });

  describe("activeOnboardingLinkFor", () => {
    it("returns null when no link exists", () => {
      expect(store.activeOnboardingLinkFor("ag_x", "google")).toBeNull();
    });

    it("returns the newest valid link for the agent+integration", () => {
      const older = store.createOnboardingLink({ agentId: "ag_a", integrationId: "google" });
      const newer = store.createOnboardingLink({ agentId: "ag_a", integrationId: "google" });
      const got = store.activeOnboardingLinkFor("ag_a", "google");
      expect(got?.token).toBe(newer.token);
      expect(got?.token).not.toBe(older.token);
    });

    it("scopes to the exact agent and integration", () => {
      const mine = store.createOnboardingLink({ agentId: "ag_a", integrationId: "google" });
      store.createOnboardingLink({ agentId: "ag_b", integrationId: "google" });
      store.createOnboardingLink({ agentId: "ag_a", integrationId: "slack" });
      expect(store.activeOnboardingLinkFor("ag_a", "google")?.token).toBe(mine.token);
    });

    it("skips used and expired links", () => {
      const used = store.createOnboardingLink({ agentId: "ag_c", integrationId: "google" });
      store.markOnboardingLinkUsed(used.token);
      expect(store.activeOnboardingLinkFor("ag_c", "google")).toBeNull();

      const expired = store.createOnboardingLink({ agentId: "ag_d", integrationId: "google" });
      (store as unknown as { db: { prepare(sql: string): { run(...a: unknown[]): void } } }).db
        .prepare("UPDATE onboarding_links SET expires_at = ? WHERE token = ?")
        .run(new Date(Date.now() - 1000).toISOString(), expired.token);
      expect(store.activeOnboardingLinkFor("ag_d", "google")).toBeNull();
    });

    it("falls through a used newest link to an older still-valid one", () => {
      const older = store.createOnboardingLink({ agentId: "ag_e", integrationId: "google" });
      const newer = store.createOnboardingLink({ agentId: "ag_e", integrationId: "google" });
      store.markOnboardingLinkUsed(newer.token);
      expect(store.activeOnboardingLinkFor("ag_e", "google")?.token).toBe(older.token);
    });
  });
});
