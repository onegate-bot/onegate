/**
 * Unit tests for the secret-masking helpers. The masking rules must never
 * reveal more than the first 12 plus the last 4 characters of a secret, and
 * short secrets must not be over-revealed.
 */

import { describe, it, expect } from "vitest";
import { maskSecret, previewPrimarySecret, llmPreferredSecretKeys } from "../src/util/mask.js";

describe("maskSecret", () => {
  it("returns null for empty or whitespace-only input", () => {
    expect(maskSecret("")).toBeNull();
    expect(maskSecret("   ")).toBeNull();
    // Non-string guards (defensive: callers should pass strings).
    expect(maskSecret(undefined as unknown as string)).toBeNull();
    expect(maskSecret(null as unknown as string)).toBeNull();
  });

  it("shows only the last 4 for short secrets (16 chars or fewer)", () => {
    expect(maskSecret("abcd")).toBe("...abcd");
    expect(maskSecret("a")).toBe("...a");
    // Exactly 8 chars: still only last 4, head never revealed.
    expect(maskSecret("12345678")).toBe("...5678");
    expect(maskSecret("12345678")).not.toContain("1234");
    // 9 and 12 chars (over the old 8-char threshold but still short) must
    // NOT expose the full secret: head and tail would overlap.
    expect(maskSecret("123456789")).toBe("...6789");
    expect(maskSecret("123456789")).not.toContain("12345");
    expect(maskSecret("123456789012")).toBe("...9012");
    // Exactly 16 chars: still last-4 only (no hidden middle otherwise).
    expect(maskSecret("1234567890123456")).toBe("...3456");
    expect(maskSecret("1234567890123456")).not.toContain("12345");
  });

  it("shows first up to 12 plus last 4 only when a middle stays hidden", () => {
    // 17 chars: just over the threshold, one char hidden.
    expect(maskSecret("12345678901234567")).toBe("123456789012...4567");
    // A realistic anthropic key.
    expect(maskSecret("sk-ant-api03-aaaaaaaaaaaaaaaaaaaa4GwA")).toBe("sk-ant-api03...4GwA");
  });

  it("never reveals more than first 12 plus last 4 of a long secret", () => {
    const secret = "sk-ant-api03-MIDDLE_SHOULD_NEVER_APPEAR-TAIL";
    const preview = maskSecret(secret)!;
    expect(preview).toBe("sk-ant-api03...TAIL");
    expect(preview).not.toContain("MIDDLE_SHOULD_NEVER_APPEAR");
    // The visible portion is bounded.
    const [head, tail] = preview.split("...");
    expect(head.length).toBeLessThanOrEqual(12);
    expect(tail.length).toBeLessThanOrEqual(4);
  });

  it("trims surrounding whitespace before masking", () => {
    expect(maskSecret("  sk-ant-api03-aaaaaaaaaaaa4GwA  ")).toBe("sk-ant-api03...4GwA");
  });
});

describe("previewPrimarySecret", () => {
  it("returns null when data is missing or empty", () => {
    expect(previewPrimarySecret(undefined)).toBeNull();
    expect(previewPrimarySecret(null)).toBeNull();
    expect(previewPrimarySecret({})).toBeNull();
    expect(previewPrimarySecret({ apiKey: "" })).toBeNull();
    expect(previewPrimarySecret({ apiKey: "   " })).toBeNull();
  });

  it("prefers preferredKeys in order", () => {
    const data = { apiKey: "sk-ant-apikey-1234567890", authToken: "oat_authtoken_abcdefgh" };
    // anthropic prefers authToken first.
    expect(
      previewPrimarySecret(data, { preferredKeys: llmPreferredSecretKeys("anthropic") }),
    ).toBe(maskSecret("oat_authtoken_abcdefgh"));
    // openai prefers apiKey first.
    expect(
      previewPrimarySecret(data, { preferredKeys: llmPreferredSecretKeys("openai") }),
    ).toBe(maskSecret("sk-ant-apikey-1234567890"));
  });

  it("falls back to the first secret-typed field, then any non-empty value", () => {
    // No preferred key present, but a secret key is.
    expect(
      previewPrimarySecret({ pat: "ghp_LongPatToken1234567890" }, { secretKeys: ["pat"] }),
    ).toBe("ghp_LongPatT...7890");
    // Neither preferred nor secret keys match: first non-empty value wins.
    expect(previewPrimarySecret({ something: "value-1234567890" })).toBe(maskSecret("value-1234567890"));
  });

  it("skips empty preferred and secret keys", () => {
    const data = { authToken: "", apiKey: "sk-ant-api03-realkey-4GwA" };
    expect(
      previewPrimarySecret(data, { preferredKeys: ["authToken", "apiKey"] }),
    ).toBe("sk-ant-api03...4GwA");
  });
});

describe("llmPreferredSecretKeys", () => {
  it("orders vendor secret keys correctly", () => {
    expect(llmPreferredSecretKeys("anthropic")).toEqual(["authToken", "apiKey"]);
    expect(llmPreferredSecretKeys("openai")).toEqual(["apiKey", "accessToken"]);
    expect(llmPreferredSecretKeys("gemini")).toEqual(["apiKey"]);
    expect(llmPreferredSecretKeys("unknown")).toContain("apiKey");
  });
});
