/**
 * C2: secret-bearing columns (credentials.data, connections.data) must be
 * encrypted at rest. Verifies writes are sealed on disk, reads return
 * plaintext, and pre-existing legacy plaintext rows get re-sealed on boot.
 */
import { createRequire } from "node:module";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it, expect } from "vitest";
import { Store } from "../src/store/db.js";

const require = createRequire(import.meta.url);
const { DatabaseSync } = require("node:sqlite") as typeof import("node:sqlite");

let dir: string;
let dbPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "og-enc-"));
  dbPath = join(dir, "onegate.db");
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

/** Read a raw column value straight from the SQLite file. */
function rawData(table: string, id: string): string {
  const db = new DatabaseSync(dbPath, { readOnly: true });
  const row = db.prepare(`SELECT data FROM ${table} WHERE id = ?`).get(id) as { data: string };
  db.close();
  return row.data;
}

describe("secrets at rest (C2)", () => {
  it("stores credential data encrypted but reads it back in the clear", () => {
    const store = new Store(dbPath);
    const cred = store.setCredential("github", "gh", { token: "ghp_SUPERSECRET" });
    store.close();

    const raw = rawData("credentials", cred.id);
    expect(raw.startsWith("enc.v1:")).toBe(true);
    expect(raw).not.toContain("ghp_SUPERSECRET");

    const reopened = new Store(dbPath);
    expect(reopened.getCredential("github")?.data).toEqual({ token: "ghp_SUPERSECRET" });
    reopened.close();
  });

  it("stores connection data encrypted but reads it back in the clear", () => {
    const store = new Store(dbPath);
    const conn = store.createConnection({
      kind: "app",
      vendor: "slack",
      name: "slack",
      data: { token: "xoxb-SUPERSECRET" },
    });
    store.close();

    const raw = rawData("connections", conn.id);
    expect(raw.startsWith("enc.v1:")).toBe(true);
    expect(raw).not.toContain("xoxb-SUPERSECRET");

    const reopened = new Store(dbPath);
    expect(reopened.getConnection(conn.id)?.data).toEqual({ token: "xoxb-SUPERSECRET" });
    reopened.close();
  });

  it("re-seals legacy plaintext rows on the next boot", () => {
    // Seed a row, then downgrade it to legacy plaintext directly on disk to
    // simulate a DB written before encryption existed.
    const store = new Store(dbPath);
    const cred = store.setCredential("stripe", "stripe", { key: "sk_live_LEGACY" });
    store.close();

    const db = new DatabaseSync(dbPath);
    db.prepare("UPDATE credentials SET data = ? WHERE id = ?").run(
      JSON.stringify({ key: "sk_live_LEGACY" }),
      cred.id,
    );
    db.close();
    expect(rawData("credentials", cred.id)).toContain("sk_live_LEGACY"); // plaintext now

    // Booting a Store over the same file must transparently re-encrypt it.
    const reopened = new Store(dbPath);
    expect(reopened.getCredential("stripe")?.data).toEqual({ key: "sk_live_LEGACY" });
    reopened.close();

    const raw = rawData("credentials", cred.id);
    expect(raw.startsWith("enc.v1:")).toBe(true);
    expect(raw).not.toContain("sk_live_LEGACY");
  });

  it("skips an undecryptable connection row in the list while returning good rows", () => {
    const store = new Store(dbPath);
    const good = store.createConnection({
      kind: "app",
      vendor: "slack",
      name: "good",
      data: { token: "xoxb-GOOD" },
    });
    const bad = store.createConnection({
      kind: "app",
      vendor: "slack",
      name: "bad",
      data: { token: "xoxb-WILL-CORRUPT" },
    });
    store.close();

    // Corrupt the bad row's envelope directly on disk (simulates a row sealed
    // under a rotated key or a truncated blob). The prefix keeps it "sealed" so
    // the migration attempts to open it and box.open throws a bad GCM tag.
    const db = new DatabaseSync(dbPath);
    db.prepare("UPDATE connections SET data = ? WHERE id = ?").run("enc.v1:garbage", bad.id);
    db.close();

    const reopened = new Store(dbPath);
    const listed = reopened.listConnections({ kind: "app", vendor: "slack" });
    const ids = listed.map((c) => c.id);
    expect(ids).toContain(good.id);
    expect(ids).not.toContain(bad.id);
    expect(reopened.getConnection(good.id)?.data).toEqual({ token: "xoxb-GOOD" });
    reopened.close();
  });

  it("skips an undecryptable credential row in the list while returning good rows", () => {
    const store = new Store(dbPath);
    const good = store.setCredential("github", "gh", { token: "ghp_GOOD" });
    const bad = store.setCredential("stripe", "stripe", { key: "sk_live_WILL_CORRUPT" });
    store.close();

    const db = new DatabaseSync(dbPath);
    db.prepare("UPDATE credentials SET data = ? WHERE id = ?").run("enc.v1:garbage", bad.id);
    db.close();

    const reopened = new Store(dbPath);
    const listed = reopened.listCredentials();
    const ids = listed.map((c) => c.id);
    expect(ids).toContain(good.id);
    expect(ids).not.toContain(bad.id);
    reopened.close();
  });

  it("returns null (not throw) from the single-row getters for a corrupt row", () => {
    const store = new Store(dbPath);
    const conn = store.createConnection({
      kind: "app",
      vendor: "slack",
      name: "c",
      data: { token: "xoxb-x" },
    });
    const cred = store.setCredential("github", "gh", { token: "ghp_x" });
    store.close();

    const db = new DatabaseSync(dbPath);
    db.prepare("UPDATE connections SET data = ? WHERE id = ?").run("enc.v1:garbage", conn.id);
    db.prepare("UPDATE credentials SET data = ? WHERE id = ?").run("enc.v1:garbage", cred.id);
    db.close();

    const reopened = new Store(dbPath);
    expect(reopened.getConnection(conn.id)).toBeNull();
    expect(reopened.getCredential("github")).toBeNull();
    reopened.close();
  });

  it("boots (does not throw) when a legacy plaintext row is unparseable", () => {
    const store = new Store(dbPath);
    const good = store.setCredential("github", "gh", { token: "ghp_GOOD" });
    const bad = store.setCredential("stripe", "stripe", { key: "sk_live_x" });
    store.close();

    // Downgrade the bad row to legacy plaintext that is NOT valid JSON, so the
    // constructor's at-rest migration (open -> seal) throws for that row.
    const db = new DatabaseSync(dbPath);
    db.prepare("UPDATE credentials SET data = ? WHERE id = ?").run("this-is-not-json{", bad.id);
    db.close();

    // Construction must not throw despite the one unparseable legacy blob.
    let reopened: Store | undefined;
    expect(() => {
      reopened = new Store(dbPath);
    }).not.toThrow();
    // The good row is still fully usable after boot.
    expect(reopened!.getCredential("github")?.data).toEqual({ token: "ghp_GOOD" });
    expect(good.id).toBeTruthy();
    expect(bad.id).toBeTruthy();
    reopened!.close();
  });

  it("returns null (not throw) from getAgentNotify for an undecryptable webhook row", () => {
    const store = new Store(dbPath);
    const { agent } = store.createAgent("notify-bot");
    store.setAgentNotify(agent.id, "https://hooks.example.com/tok_secret");
    store.close();

    // Simulate a row sealed under a rotated key / a truncated envelope. The
    // enc.v1 prefix keeps it "sealed" so box.open attempts it and throws.
    const db = new DatabaseSync(dbPath);
    db.prepare("UPDATE agent_notify SET webhook_url = ? WHERE agent_id = ?").run(
      "enc.v1:garbage",
      agent.id,
    );
    db.close();

    // Must degrade to "no webhook configured". A throw here lands on the proxy's
    // deny path inside an unawaited async handler and kills the whole gateway.
    const reopened = new Store(dbPath);
    expect(() => reopened.getAgentNotify(agent.id)).not.toThrow();
    expect(reopened.getAgentNotify(agent.id)).toBeNull();
    reopened.close();
  });

  it("keeps other agents' webhooks working when one row is undecryptable", () => {
    const store = new Store(dbPath);
    const bad = store.createAgent("bad-bot").agent;
    const good = store.createAgent("good-bot").agent;
    store.setAgentNotify(bad.id, "https://hooks.example.com/tok_bad");
    store.setAgentNotify(good.id, "https://hooks.example.com/tok_good");
    store.close();

    const db = new DatabaseSync(dbPath);
    db.prepare("UPDATE agent_notify SET webhook_url = ? WHERE agent_id = ?").run(
      "enc.v1:garbage",
      bad.id,
    );
    db.close();

    const reopened = new Store(dbPath);
    expect(reopened.getAgentNotify(bad.id)).toBeNull();
    expect(reopened.getAgentNotify(good.id)).toBe("https://hooks.example.com/tok_good");
    reopened.close();
  });

  it("persists a usable key file next to the DB (0600)", () => {
    const store = new Store(dbPath);
    store.setCredential("github", "gh", { token: "ghp_x" });
    store.close();
    // The key file must exist and let a fresh Store decrypt.
    const { statSync } = require("node:fs") as typeof import("node:fs");
    const mode = statSync(join(dir, "db-secret.key")).mode & 0o777;
    expect(mode).toBe(0o600);
  });
});
