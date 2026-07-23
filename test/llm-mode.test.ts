/**
 * Unit tests for the pure LLM-mode derivation (managed/passthrough/blocked).
 */

import { describe, it, expect } from "vitest";
import { deriveLlmMode, vendorAllowed } from "../src/llm/mode.js";

describe("vendorAllowed", () => {
  it("deny rule wins over allow rule", () => {
    const rules = [
      { integrationId: "anthropic", effect: "allow" as const },
      { integrationId: "anthropic", effect: "deny" as const },
    ];
    expect(vendorAllowed("anthropic", rules, true)).toBe(false);
  });

  it("allow rule permits even under default-deny", () => {
    const rules = [{ integrationId: "anthropic", effect: "allow" as const }];
    expect(vendorAllowed("anthropic", rules, false)).toBe(true);
  });

  it("falls back to default policy when no rule matches", () => {
    expect(vendorAllowed("anthropic", [], true)).toBe(true);
    expect(vendorAllowed("anthropic", [], false)).toBe(false);
  });
});

describe("deriveLlmMode", () => {
  it("managed: enabled with conns and an allow rule", () => {
    expect(
      deriveLlmMode({
        enabled: true,
        connectionVendors: ["anthropic"],
        rules: [{ integrationId: "anthropic", effect: "allow" }],
        defaultAllow: false,
      }),
    ).toBe("managed");
  });

  it("managed: enabled with conns under default-allow and no rule", () => {
    expect(
      deriveLlmMode({
        enabled: true,
        connectionVendors: ["anthropic"],
        rules: [],
        defaultAllow: true,
      }),
    ).toBe("managed");
  });

  it("blocked: disabled with connections attached (the Ezer bug)", () => {
    expect(
      deriveLlmMode({
        enabled: false,
        connectionVendors: ["anthropic"],
        rules: [{ integrationId: "anthropic", effect: "allow" }],
        defaultAllow: true,
      }),
    ).toBe("blocked");
  });

  it("blocked: enabled with conns but a deny rule on the vendor", () => {
    expect(
      deriveLlmMode({
        enabled: true,
        connectionVendors: ["anthropic"],
        rules: [{ integrationId: "anthropic", effect: "deny" }],
        defaultAllow: true,
      }),
    ).toBe("blocked");
  });

  it("blocked: enabled with conns but default-deny and no allow rule", () => {
    expect(
      deriveLlmMode({
        enabled: true,
        connectionVendors: ["gemini"],
        rules: [],
        defaultAllow: false,
      }),
    ).toBe("blocked");
  });

  it("passthrough: disabled with no connections", () => {
    expect(
      deriveLlmMode({
        enabled: false,
        connectionVendors: [],
        rules: [],
        defaultAllow: false,
      }),
    ).toBe("passthrough");
  });

  it("passthrough: enabled but no connections (empty route forwards)", () => {
    expect(
      deriveLlmMode({
        enabled: true,
        connectionVendors: [],
        rules: [],
        defaultAllow: false,
      }),
    ).toBe("passthrough");
  });

  it("partial vendors: one denied one allowed stays managed", () => {
    expect(
      deriveLlmMode({
        enabled: true,
        connectionVendors: ["anthropic", "gemini"],
        rules: [
          { integrationId: "anthropic", effect: "deny" },
          { integrationId: "gemini", effect: "allow" },
        ],
        defaultAllow: false,
      }),
    ).toBe("managed");
  });

  it("all vendors denied is blocked even with multiple conns", () => {
    expect(
      deriveLlmMode({
        enabled: true,
        connectionVendors: ["anthropic", "gemini"],
        rules: [
          { integrationId: "anthropic", effect: "deny" },
          { integrationId: "gemini", effect: "deny" },
        ],
        defaultAllow: true,
      }),
    ).toBe("blocked");
  });
});
