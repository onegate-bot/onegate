/**
 * Store tests for SS1: per-agent notify webhook and owner_notifications table.
 *
 * Verifies:
 *  - setAgentNotify / getAgentNotify / clearAgentNotify round-trip
 *  - The webhook URL is stored encrypted (enc.v1) at rest
 *  - enqueueOwnerNotification / findRecentOwnerNotification / markOwnerNotification / listOwnerNotifications
 */

import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Store } from "../src/store/db.js";

const requireBuiltin = createRequire(import.meta.url);
const { DatabaseSync } = requireBuiltin("node:sqlite") as typeof import("node:sqlite");

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

let store: Store;

// Use in-memory DB for most tests (fast and isolated).
beforeEach(() => {
  store = new Store(":memory:");
});

// ---- agent_notify: webhook config ----

describe("setAgentNotify / getAgentNotify / clearAgentNotify", () => {
  it("returns null when no webhook is set", () => {
    expect(store.getAgentNotify("ag_missing")).toBeNull();
  });

  it("stores and retrieves a webhook URL", () => {
    const { agent } = store.createAgent("test-bot");
    store.setAgentNotify(agent.id, "https://hooks.example.com/tok_secret");
    expect(store.getAgentNotify(agent.id)).toBe("https://hooks.example.com/tok_secret");
  });

  it("overwrites an existing webhook on second set", () => {
    const { agent } = store.createAgent("test-bot");
    store.setAgentNotify(agent.id, "https://hooks.example.com/tok_old");
    store.setAgentNotify(agent.id, "https://hooks.example.com/tok_new");
    expect(store.getAgentNotify(agent.id)).toBe("https://hooks.example.com/tok_new");
  });

  it("clearAgentNotify removes the webhook", () => {
    const { agent } = store.createAgent("test-bot");
    store.setAgentNotify(agent.id, "https://hooks.example.com/tok");
    store.clearAgentNotify(agent.id);
    expect(store.getAgentNotify(agent.id)).toBeNull();
  });

  it("clearAgentNotify is a no-op when nothing is set", () => {
    expect(() => store.clearAgentNotify("ag_ghost")).not.toThrow();
  });
});

// ---- agent_notify: encryption at rest ----

describe("agent_notify webhook is encrypted at rest (enc.v1)", () => {
  let dir: string;
  let dbPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "og-notify-enc-"));
    dbPath = join(dir, "onegate.db");
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function rawWebhookUrl(agentId: string): string {
    const db = new DatabaseSync(dbPath, { readOnly: true });
    const row = db
      .prepare("SELECT webhook_url FROM agent_notify WHERE agent_id = ?")
      .get(agentId) as { webhook_url: string } | undefined;
    db.close();
    if (!row) throw new Error("no row");
    return row.webhook_url;
  }

  it("stores the webhook URL encrypted and decrypts it on read", () => {
    const s = new Store(dbPath);
    const { agent } = s.createAgent("enc-bot");
    s.setAgentNotify(agent.id, "https://hooks.example.com/my_secret_token");
    s.close();

    const raw = rawWebhookUrl(agent.id);
    // Must be sealed (enc.v1 prefix).
    expect(raw.startsWith("enc.v1:")).toBe(true);
    // Must not contain the plaintext secret.
    expect(raw).not.toContain("my_secret_token");

    // A fresh Store over the same DB must decrypt correctly.
    const s2 = new Store(dbPath);
    expect(s2.getAgentNotify(agent.id)).toBe("https://hooks.example.com/my_secret_token");
    s2.close();
  });
});

// ---- owner_notifications: enqueue / dedup / mark / list ----

describe("enqueueOwnerNotification", () => {
  it("creates a row with status pending and attempts 0", () => {
    const row = store.enqueueOwnerNotification({
      agentId: "ag_1",
      integrationId: "github",
      connectToken: "tok_abc",
    });
    expect(row.id).toBeGreaterThan(0);
    expect(row.agentId).toBe("ag_1");
    expect(row.integrationId).toBe("github");
    // The connect token is a bearer capability, stored as its SHA-256 hash.
    expect(row.connectToken).toBe(sha256("tok_abc"));
    expect(row.status).toBe("pending");
    expect(row.attempts).toBe(0);
    expect(row.deliveredAt).toBeNull();
    expect(row.lastAttemptAt).toBeNull();
    expect(row.error).toBeNull();
  });

  it("accepts a null connectToken", () => {
    const row = store.enqueueOwnerNotification({
      agentId: "ag_1",
      integrationId: "slack",
      connectToken: null,
    });
    expect(row.connectToken).toBeNull();
  });
});

describe("findRecentOwnerNotification (dedup)", () => {
  it("returns null when no notifications exist within the window", () => {
    const since = new Date(Date.now() - 60_000).toISOString();
    expect(store.findRecentOwnerNotification("ag_1", "github", since)).toBeNull();
  });

  it("returns the most recent row when one exists within the window", () => {
    store.enqueueOwnerNotification({ agentId: "ag_1", integrationId: "github", connectToken: null });
    const since = new Date(Date.now() - 60_000).toISOString();
    const found = store.findRecentOwnerNotification("ag_1", "github", since);
    expect(found).not.toBeNull();
    expect(found?.agentId).toBe("ag_1");
    expect(found?.integrationId).toBe("github");
  });

  it("returns null when the only row is older than the window", () => {
    const row = store.enqueueOwnerNotification({ agentId: "ag_1", integrationId: "github", connectToken: null });
    // Backdate the row to 2 hours ago using an internal DB handle.
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
    (store as unknown as { db: { prepare(s: string): { run(...a: unknown[]): void } } }).db
      .prepare("UPDATE owner_notifications SET created_at = ? WHERE id = ?")
      .run(twoHoursAgo, row.id);

    // Window is 1 hour: should not find the 2-hours-ago row.
    const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    expect(store.findRecentOwnerNotification("ag_1", "github", since)).toBeNull();
  });

  it("is scoped to (agentId, integrationId): different pair returns null", () => {
    store.enqueueOwnerNotification({ agentId: "ag_1", integrationId: "github", connectToken: null });
    const since = new Date(Date.now() - 60_000).toISOString();
    // Different agent — should not match.
    expect(store.findRecentOwnerNotification("ag_OTHER", "github", since)).toBeNull();
    // Different integration — should not match.
    expect(store.findRecentOwnerNotification("ag_1", "slack", since)).toBeNull();
  });
});

describe("markOwnerNotification", () => {
  it("marks a row delivered with deliveredAt and increments attempts", () => {
    const row = store.enqueueOwnerNotification({ agentId: "ag_1", integrationId: "github", connectToken: null });
    const now = new Date().toISOString();
    store.markOwnerNotification(row.id, { status: "delivered", deliveredAt: now, incrementAttempt: true });

    const since = new Date(Date.now() - 60_000).toISOString();
    const updated = store.findRecentOwnerNotification("ag_1", "github", since);
    expect(updated?.status).toBe("delivered");
    expect(updated?.deliveredAt).toBe(now);
    expect(updated?.attempts).toBe(1);
    expect(updated?.error).toBeNull();
  });

  it("marks a row failed with an error message", () => {
    const row = store.enqueueOwnerNotification({ agentId: "ag_2", integrationId: "slack", connectToken: null });
    store.markOwnerNotification(row.id, { status: "failed", error: "HTTP 500", incrementAttempt: true });

    const since = new Date(Date.now() - 60_000).toISOString();
    const updated = store.findRecentOwnerNotification("ag_2", "slack", since);
    expect(updated?.status).toBe("failed");
    expect(updated?.error).toBe("HTTP 500");
    expect(updated?.attempts).toBe(1);
  });

  it("does not increment attempts when incrementAttempt is false", () => {
    const row = store.enqueueOwnerNotification({ agentId: "ag_3", integrationId: "jira", connectToken: null });
    store.markOwnerNotification(row.id, { status: "pending", incrementAttempt: false });

    const since = new Date(Date.now() - 60_000).toISOString();
    const updated = store.findRecentOwnerNotification("ag_3", "jira", since);
    expect(updated?.attempts).toBe(0);
  });
});

describe("listOwnerNotifications", () => {
  it("returns rows most-recent first", () => {
    store.enqueueOwnerNotification({ agentId: "ag_1", integrationId: "github", connectToken: null });
    store.enqueueOwnerNotification({ agentId: "ag_1", integrationId: "slack", connectToken: null });
    const rows = store.listOwnerNotifications();
    expect(rows.length).toBeGreaterThanOrEqual(2);
    // Most recent should have the higher id.
    expect(rows[0].id).toBeGreaterThan(rows[1].id);
  });

  it("filters by status", () => {
    const r1 = store.enqueueOwnerNotification({ agentId: "ag_1", integrationId: "github", connectToken: null });
    const r2 = store.enqueueOwnerNotification({ agentId: "ag_1", integrationId: "slack", connectToken: null });
    store.markOwnerNotification(r1.id, { status: "delivered", deliveredAt: new Date().toISOString(), incrementAttempt: true });
    store.markOwnerNotification(r2.id, { status: "failed", error: "timeout", incrementAttempt: true });

    const delivered = store.listOwnerNotifications({ status: "delivered" });
    expect(delivered.every((r) => r.status === "delivered")).toBe(true);

    const failed = store.listOwnerNotifications({ status: "failed" });
    expect(failed.every((r) => r.status === "failed")).toBe(true);
  });
});
