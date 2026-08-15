/**
 * The concurrent first-boot race on the master key file.
 *
 * The proxy server and the CLI are separate processes that each build a Store
 * against the same data dir. On an empty data dir both can fall through
 * loadSecretKey's existsSync check and reach the create path. The key file must
 * therefore be created exclusively (O_EXCL) so only one generated key can ever
 * reach disk, and the loser must adopt the winner's key -- otherwise rows
 * sealed under the losing key fail AES-GCM auth forever.
 *
 * `node:fs` is mocked here (rather than in secret-box.test.ts) because the only
 * faithful way to reproduce the race is to make the key file appear *between*
 * the existsSync check and the write, and vi.mock is what intercepts the static
 * ESM named imports that secret-box.ts uses.
 */
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// Hoisted so the mock factory below can read it after vi.mock lifts it.
const hooks = vi.hoisted(() => ({ onExistsCheck: null as null | ((path: string) => void) }));

vi.mock("node:fs", async () => {
  const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
  return {
    ...actual,
    existsSync: (path: Parameters<typeof actual.existsSync>[0]) => {
      const result = actual.existsSync(path);
      // Let a test slip the competing writer in at exactly this instant.
      hooks.onExistsCheck?.(String(path));
      return result;
    },
  };
});

const { loadSecretKey } = await import("../src/store/secret-box.js");

describe("loadSecretKey create race", () => {
  let dir: string;
  let dbPath: string;
  let keyPath: string;
  let savedEnvKey: string | undefined;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "onegate-keyrace-"));
    dbPath = join(dir, "onegate.db");
    keyPath = join(dir, "db-secret.key");
    savedEnvKey = process.env.ONEGATE_DB_KEY;
    delete process.env.ONEGATE_DB_KEY;
    hooks.onExistsCheck = null;
  });

  afterEach(() => {
    hooks.onExistsCheck = null;
    if (savedEnvKey === undefined) delete process.env.ONEGATE_DB_KEY;
    else process.env.ONEGATE_DB_KEY = savedEnvKey;
    rmSync(dir, { recursive: true, force: true });
  });

  it("adopts the winner's key when another process creates the file mid-window", () => {
    const winner = randomBytes(32);
    let raced = false;
    // The competing process wins the race right after our existsSync says the
    // file is absent, so our own write hits an already-present file.
    hooks.onExistsCheck = (path) => {
      if (raced || path !== keyPath) return;
      raced = true;
      writeFileSync(keyPath, winner.toString("base64"), { mode: 0o600 });
    };

    const loser = loadSecretKey(dbPath);

    expect(raced).toBe(true);
    // Must converge on the winner's key, not the locally generated one.
    expect(loser).toEqual(winner);
    // And the winner's file must survive untouched.
    expect(Buffer.from(readFileSync(keyPath, "utf8").trim(), "base64")).toEqual(winner);
  });

  it("still creates the key normally when no one races it", () => {
    const key = loadSecretKey(dbPath);
    expect(key.length).toBe(32);
    // A second load sees the file and returns the very same key.
    expect(loadSecretKey(dbPath)).toEqual(key);
  });
});
