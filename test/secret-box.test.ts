import { randomBytes } from "node:crypto";
import { describe, it, expect } from "vitest";
import { SecretBox } from "../src/store/secret-box.js";

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
