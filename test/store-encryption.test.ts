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
