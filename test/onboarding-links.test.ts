import { describe, it, expect, beforeEach } from "vitest";
import { createHash } from "node:crypto";
import { Store } from "../src/store/db.js";

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

/** Reads the raw stored onboarding_links row (bypasses hashing) for assertions. */
function rawLinkRows(store: Store): Array<Record<string, unknown>> {
  return (
    store as unknown as { db: { prepare(sql: string): { all(): Array<Record<string, unknown>> } } }
  ).db
    .prepare("SELECT * FROM onboarding_links")
    .all();
}

interface RawDb {
  exec(sql: string): void;
  prepare(sql: string): {
    run(...a: unknown[]): void;
    all(): Array<Record<string, unknown>>;
    get(...a: unknown[]): Record<string, unknown> | undefined;
  };
}

/** The Store's private node:sqlite handle, for shaping legacy fixtures. */
function rawDb(store: Store): RawDb {
  return (store as unknown as { db: RawDb }).db;
}

function tableExists(store: Store, name: string): boolean {
  return (
    rawDb(store)
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
      .get(name) !== undefined
  );
}

function columns(store: Store, table: string): Set<string> {
  return new Set(
    rawDb(store)
      .prepare(`PRAGMA table_info(${table})`)
      .all()
      .map((r) => String(r.name)),
  );
}

/**
 * Replaces onboarding_links with the pre-hash legacy shape: a cleartext `token`
 * PRIMARY KEY and no token_hash. integration_id is deliberately nullable here
 * (the rebuilt table declares it NOT NULL) so a test can force a constraint
 * failure part way through the copy loop.
 */
function makeLegacyTable(store: Store): string {
  const raw = rawDb(store);
  raw.exec("DROP TABLE IF EXISTS onboarding_links");
  raw.exec(`CREATE TABLE onboarding_links (
    token TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    integration_id TEXT,
    scopes TEXT,
    connection_name TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    rule_id TEXT
  )`);
  return "a".repeat(48);
}

function insertLegacyRow(store: Store, token: string, agentId: string): void {
  rawDb(store)
    .prepare(
      "INSERT INTO onboarding_links (token, agent_id, integration_id, scopes, connection_name, created_at, expires_at, used_at, rule_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .run(
      token,
      agentId,
      "google",
      null,
      null,
      new Date().toISOString(),
      new Date(Date.now() + 86_400_000).toISOString(),
      null,
      null,
    );
}

let store: Store;

beforeEach(() => {
  store = new Store(":memory:");
});

describe("onboarding links", () => {
  it("creates a link with an unguessable token and a 7 day default TTL", () => {
    const before = Date.now();
    const link = store.createOnboardingLink({ agentId: "ag_1", integrationId: "google" });
    expect(link.token).toMatch(/^[a-f0-9]{48}$/);
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
      .prepare("UPDATE onboarding_links SET expires_at = ? WHERE token_hash = ?")
      .run(new Date(Date.now() - 1000).toISOString(), link.tokenHash);
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
    // List reads surface the stored hash as `token` (plaintext is unrecoverable).
    expect(forA.map((l) => l.token)).toContain(a.tokenHash);
    expect(forA.map((l) => l.token)).toContain(b.tokenHash);
    expect(forA.every((l) => l.agentId === "ag_A")).toBe(true);
    expect(store.listOnboardingLinks().length).toBe(3);
  });

  it("deletes a link", () => {
    const link = store.createOnboardingLink({ agentId: "ag_8", integrationId: "google" });
    store.deleteOnboardingLink(link.token);
    expect(store.getOnboardingLink(link.token)).toBeNull();
  });

  describe("link reuse is disabled (only the hash is stored)", () => {
    // The plaintext token cannot be recovered from a stored hash, so a live
    // link cannot be turned back into a redeemable URL. The active* helpers
    // therefore return null and callers mint a fresh link; owner-notification
    // dedup still prevents duplicate notifications.
    it("activeOnboardingLinkFor always returns null even with a live link", () => {
      store.createOnboardingLink({ agentId: "ag_a", integrationId: "google" });
      expect(store.activeOnboardingLinkFor("ag_a", "google")).toBeNull();
    });

    it("activeRenewalLinkFor always returns null", () => {
      store.createOnboardingLink({ agentId: "ag_a", integrationId: "google", ruleId: "rl_1" });
      expect(store.activeRenewalLinkFor("rl_1")).toBeNull();
    });
  });

  describe("connect-capability tokens are hashed at rest", () => {
    it("stores only the SHA-256 hash, never the raw token", () => {
      const link = store.createOnboardingLink({ agentId: "ag_h", integrationId: "google" });
      const rows = rawLinkRows(store);
      expect(rows.length).toBe(1);
      const row = rows[0];
      // The raw token must not appear in ANY stored column.
      for (const v of Object.values(row)) {
        expect(String(v ?? "")).not.toContain(link.token);
      }
      // The stored hash is the SHA-256 of the raw token.
      expect(row.token_hash).toBe(sha256(link.token));
      expect(link.tokenHash).toBe(sha256(link.token));
    });

    it("redeems, marks-used and deletes by the raw token (hash match)", () => {
      const link = store.createOnboardingLink({ agentId: "ag_i", integrationId: "jira" });
      // Lookup by raw token still works.
      const got = store.getOnboardingLink(link.token);
      expect(got).not.toBeNull();
      expect(got!.agentId).toBe("ag_i");
      // The re-attached token on redemption is the presented plaintext, so
      // downstream URL rebuilds stay redeemable.
      expect(got!.token).toBe(link.token);
      // Mark-used by raw token flips validity.
      store.markOnboardingLinkUsed(link.token);
      expect(store.isOnboardingLinkValid(store.getOnboardingLink(link.token))).toBe(false);
      // Delete by raw token removes it.
      store.deleteOnboardingLink(link.token);
      expect(store.getOnboardingLink(link.token)).toBeNull();
    });

    it("also revokes when given the stored hash (admin list surfaces the hash)", () => {
      const link = store.createOnboardingLink({ agentId: "ag_j", integrationId: "google" });
      // The admin list exposes the hash as `token`; revoking by it must work.
      const listed = store.listOnboardingLinks("ag_j")[0];
      expect(listed.token).toBe(link.tokenHash);
      store.deleteOnboardingLink(listed.token);
      expect(store.getOnboardingLink(link.token)).toBeNull();
    });

    it("migrates a pre-existing plaintext row so lookup by its token still works", () => {
      // Simulate a legacy DB: a plaintext `token` PRIMARY KEY column with a
      // cleartext token, no token_hash column.
      const raw = (
        store as unknown as { db: { exec(sql: string): void; prepare(sql: string): { run(...a: unknown[]): void } } }
      ).db;
      const legacyToken = "a".repeat(48);
      raw.exec("DROP TABLE onboarding_links");
      raw.exec(`CREATE TABLE onboarding_links (
        token TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        integration_id TEXT NOT NULL,
        scopes TEXT,
        connection_name TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        rule_id TEXT
      )`);
      raw
        .prepare(
          "INSERT INTO onboarding_links (token, agent_id, integration_id, scopes, connection_name, created_at, expires_at, used_at, rule_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          legacyToken,
          "ag_legacy",
          "google",
          null,
          null,
          new Date().toISOString(),
          new Date(Date.now() + 86_400_000).toISOString(),
          null,
          null,
        );
      // Re-open the DB path through a fresh Store to run the migration. Since
      // the test store is :memory:, run the migration by reconstructing over
      // the same handle via the private method.
      (store as unknown as { hashCapabilityTokensAtRest(): void }).hashCapabilityTokensAtRest();
      // The plaintext column is gone, replaced by the hash.
      const rows = rawLinkRows(store);
      expect(rows.length).toBe(1);
      expect(rows[0].token).toBeUndefined();
      expect(rows[0].token_hash).toBe(sha256(legacyToken));
      // The old link (URL already delivered) still redeems by its plaintext.
      const got = store.getOnboardingLink(legacyToken);
      expect(got).not.toBeNull();
      expect(got!.agentId).toBe("ag_legacy");
    });

    it("rolls the whole rebuild back when it fails part way, losing no rows and leaving no plaintext legacy table", () => {
      const raw = rawDb(store);
      const tokens = [makeLegacyTable(store), "b".repeat(48), "c".repeat(48)];
      insertLegacyRow(store, tokens[0], "ag_one");
      insertLegacyRow(store, tokens[1], "ag_two");
      insertLegacyRow(store, tokens[2], "ag_three");

      // Simulate the process dying mid-rebuild: let the copy loop insert the
      // first row, then make the very next insert blow up. Everything the
      // migration did before that point (the RENAME, the CREATE, the rows
      // already copied) is uncommitted work that must not survive.
      const realPrepare = raw.prepare.bind(raw);
      let inserts = 0;
      raw.prepare = (sql: string) => {
        const stmt = realPrepare(sql);
        if (!sql.startsWith("INSERT OR IGNORE INTO onboarding_links")) return stmt;
        const realRun = stmt.run.bind(stmt);
        return {
          ...stmt,
          run: (...args: unknown[]) => {
            if (++inserts > 1) throw new Error("simulated crash mid-migration");
            return realRun(...args);
          },
        };
      };
      try {
        expect(() =>
          (store as unknown as { hashCapabilityTokensAtRest(): void }).hashCapabilityTokensAtRest(),
        ).toThrow(/simulated crash/);
      } finally {
        raw.prepare = realPrepare;
      }

      // All-or-nothing: the rebuild is fully undone. The legacy table is still
      // the live one, holding every original row, and no half-built table with
      // a subset of the data survives.
      const legacyRows = raw
        .prepare("SELECT token, agent_id FROM onboarding_links")
        .all() as Array<Record<string, unknown>>;
      expect(legacyRows.length).toBe(3);
      expect(legacyRows.map((r) => r.token).sort()).toEqual([...tokens].sort());
      expect(tableExists(store, "onboarding_links_legacy")).toBe(false);
      // Still legacy-shaped, so the guard fires again on the next open.
      expect(columns(store, "onboarding_links").has("token")).toBe(true);
      expect(columns(store, "onboarding_links").has("token_hash")).toBe(false);
    });

    it("finishes a half-migrated database left with an orphaned plaintext legacy table", () => {
      const raw = rawDb(store);
      const legacyToken = "d".repeat(48);
      // Reproduce exactly what a crash between the RENAME and the DROP left
      // behind under the old non-transactional migration: a new token_hash
      // table (here already holding one copied row) plus a surviving
      // onboarding_links_legacy still holding cleartext tokens.
      makeLegacyTable(store);
      insertLegacyRow(store, legacyToken, "ag_orphan");
      raw.exec("ALTER TABLE onboarding_links RENAME TO onboarding_links_legacy");
      raw.exec(`CREATE TABLE onboarding_links (
        token_hash TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        integration_id TEXT NOT NULL,
        scopes TEXT,
        connection_name TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        rule_id TEXT
      )`);

      // The old guard (`token` present && no `token_hash`) is false here, so
      // this only completes if the guard also keys off the legacy table.
      (store as unknown as { hashCapabilityTokensAtRest(): void }).hashCapabilityTokensAtRest();

      // The stranded row is carried over as a hash and the plaintext table is gone.
      expect(tableExists(store, "onboarding_links_legacy")).toBe(false);
      const rows = rawLinkRows(store);
      expect(rows.length).toBe(1);
      expect(rows[0].token).toBeUndefined();
      expect(rows[0].token_hash).toBe(sha256(legacyToken));
      const got = store.getOnboardingLink(legacyToken);
      expect(got).not.toBeNull();
      expect(got!.agentId).toBe("ag_orphan");
    });

    it("is a no-op on an already migrated database", () => {
      const link = store.createOnboardingLink({ agentId: "ag_done", integrationId: "google" });
      (store as unknown as { hashCapabilityTokensAtRest(): void }).hashCapabilityTokensAtRest();
      const rows = rawLinkRows(store);
      expect(rows.length).toBe(1);
      expect(rows[0].token_hash).toBe(sha256(link.token));
      expect(tableExists(store, "onboarding_links_legacy")).toBe(false);
      expect(store.getOnboardingLink(link.token)).not.toBeNull();
    });
  });
});
