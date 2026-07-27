import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { SecretBox, loadSecretKey } from "../src/store/secret-box.js";

const key = () => randomBytes(32);

describe("SecretBox", () => {
  it("seals and opens a roundtrip", () => {
    const box = new SecretBox(key());
    const value = { apiKey: "sk-ant-api03-secret", refresh: "rt_12345" };
    const sealed = box.seal(value);
    expect(box.isSealed(sealed)).toBe(true);
    expect(sealed).not.toContain("sk-ant-api03-secret");
    expect(box.open(sealed)).toEqual(value);
  });

  it("treats non-marked strings as legacy plaintext JSON", () => {
    const box = new SecretBox(key());
    const legacy = JSON.stringify({ token: "plain" });
    expect(box.isSealed(legacy)).toBe(false);
    expect(box.open(legacy)).toEqual({ token: "plain" });
  });

  it("produces a fresh IV each seal (ciphertexts differ)", () => {
    const box = new SecretBox(key());
    const v = { a: 1 };
    expect(box.seal(v)).not.toBe(box.seal(v));
  });

  it("rejects a tampered ciphertext (GCM auth)", () => {
    const box = new SecretBox(key());
    const sealed = box.seal({ x: "y" });
    const marker = sealed.slice(0, sealed.indexOf(":") + 1);
    const raw = Buffer.from(sealed.slice(marker.length), "base64");
    // Flip a byte in the ciphertext region (past the 12-byte IV + 16-byte tag).
    raw[raw.length - 1] ^= 0xff;
    const flipped = marker + raw.toString("base64");
    expect(() => box.open(flipped)).toThrow();
  });

  it("cannot open with a different key", () => {
    const sealed = new SecretBox(key()).seal({ x: "y" });
    expect(() => new SecretBox(key()).open(sealed)).toThrow();
  });

  it("rejects a wrong-length key", () => {
    expect(() => new SecretBox(randomBytes(16))).toThrow();
  });
});

describe("loadSecretKey key file creation", () => {
  let dir: string;
  let dbPath: string;
  let keyPath: string;
  let savedEnvKey: string | undefined;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "onegate-keyfile-"));
    dbPath = join(dir, "onegate.db");
    keyPath = join(dir, "db-secret.key");
    // The env key short-circuits the file path entirely; make sure it is unset.
    savedEnvKey = process.env.ONEGATE_DB_KEY;
    delete process.env.ONEGATE_DB_KEY;
  });

  afterEach(() => {
    if (savedEnvKey === undefined) delete process.env.ONEGATE_DB_KEY;
    else process.env.ONEGATE_DB_KEY = savedEnvKey;
    rmSync(dir, { recursive: true, force: true });
  });

  it("generates and persists a 32-byte key on first boot (0600)", () => {
    expect(existsSync(keyPath)).toBe(false);
    const key = loadSecretKey(dbPath);
    expect(key.length).toBe(32);
    expect(existsSync(keyPath)).toBe(true);
    expect(statSync(keyPath).mode & 0o777).toBe(0o600);
    expect(Buffer.from(readFileSync(keyPath, "utf8").trim(), "base64")).toEqual(key);
  });

  it("reads a pre-existing key file instead of overwriting it", () => {
    const existing = randomBytes(32);
    writeFileSync(keyPath, existing.toString("base64"), { mode: 0o600 });
    expect(loadSecretKey(dbPath)).toEqual(existing);
    // The file on disk is untouched.
    expect(Buffer.from(readFileSync(keyPath, "utf8").trim(), "base64")).toEqual(existing);
  });

  it("is stable across repeated calls (no silent regeneration)", () => {
    const first = loadSecretKey(dbPath);
    const second = loadSecretKey(dbPath);
    const third = loadSecretKey(dbPath);
    expect(second).toEqual(first);
    expect(third).toEqual(first);
  });

  it("throws on a corrupt key file rather than regenerating one", () => {
    writeFileSync(keyPath, "too-short", { mode: 0o600 });
    expect(() => loadSecretKey(dbPath)).toThrow(/corrupt/);
  });
});
