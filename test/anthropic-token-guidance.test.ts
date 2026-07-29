/**
 * Anthropic connect guidance and credential-mismatch validation (upstream
 * onecli issue #459).
 *
 * Two DIFFERENT Anthropic subscription tokens both carry the `sk-ant-oat`
 * prefix: the long-lived one from `claude setup-token` (safe to store) and the
 * short-lived one the Claude Code client caches and ROTATES (pasting it yields
 * a delayed 401). They are not separable locally, so these tests pin the
 * WARNING COPY that stands in for the impossible check, plus the one check
 * that IS reliable (api-key-vs-subscription-token, distinct prefixes).
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  anthropic,
  anthropicSecretMismatch,
  ANTHROPIC_TOKEN_GUIDANCE,
} from "../src/integrations/anthropic.js";
import { composeLlmHelpPrompt } from "../src/integrations/llm-help.js";
import { connectFlowKind } from "../src/integrations/types.js";

describe("anthropic token-type guidance", () => {
  it("names both subscription token types and the delayed-401 failure mode", () => {
    const text = ANTHROPIC_TOKEN_GUIDANCE.whichToken;
    expect(text).toContain("claude setup-token");
    expect(text).toContain("keychain");
    expect(text).toContain("401");
    // The point of the warning is that the prefix does NOT disambiguate.
    expect(text).toContain("sk-ant-oat");
  });

  it("warns that a subscription token 429s for any non-Claude-Code client", () => {
    const text = ANTHROPIC_TOKEN_GUIDANCE.clientIdentity;
    expect(text).toContain("429");
    expect(text).toContain("Claude Code");
    // Must steer to the alternative, not just describe the symptom.
    expect(text).toContain("sk-ant-api03");
  });

  it("exposes a connect guide carrying both warnings", () => {
    const guide = anthropic.connectGuide;
    expect(guide).toBeDefined();
    expect(guide!.consoleUrl).toBe("https://console.anthropic.com/settings/keys");
    const steps = guide!.steps.join("\n");
    expect(steps).toContain("claude setup-token");
    expect(guide!.steps).toContain(ANTHROPIC_TOKEN_GUIDANCE.whichToken);
    expect(guide!.steps).toContain(ANTHROPIC_TOKEN_GUIDANCE.clientIdentity);
  });

  it("declares an api_key connect method with a steering hint", () => {
    expect(anthropic.connect?.method).toBe("api_key");
    expect(anthropic.connect?.hint).toContain("sk-ant-api03");
  });

  it("carries the guidance into the LLM help prompt", () => {
    const prompt = composeLlmHelpPrompt(anthropic);
    expect(prompt).toContain("keychain");
    expect(prompt).toContain("429");
  });

  it("keeps house comms style: no em-dashes or semicolons in user-facing copy", () => {
    const copy = [
      ANTHROPIC_TOKEN_GUIDANCE.whichToken,
      ANTHROPIC_TOKEN_GUIDANCE.clientIdentity,
      anthropic.connect?.hint ?? "",
      ...(anthropic.connectGuide?.steps ?? []),
    ].join("\n");
    expect(copy).not.toContain("—");
    expect(copy).not.toContain(";");
  });
});

describe("the surface that actually renders the guidance", () => {
  // Anthropic carries an `llm` block, so connectFlowKind excludes it from the
  // PUBLIC self-service wizard. The place a user really pastes an Anthropic
  // credential is the admin UI LLM connection modal, so that is what must
  // carry the warnings. This test pins that fact so a future change that makes
  // anthropic publicly connectable does not silently drop the copy.
  it("is the admin LLM connection modal, not the public connect wizard", () => {
    expect(connectFlowKind(anthropic)).toBeNull();
  });

  it("shows both warnings in the admin LLM connection modal", () => {
    const appJs = readFileSync(
      fileURLToPath(new URL("../src/admin/ui/app.js", import.meta.url)),
      "utf8",
    );
    const modal = appJs.slice(appJs.indexOf('anthropicMode === "auth_token"'));
    expect(modal).not.toBe("");
    // Which of the two same-prefix subscription tokens to paste.
    expect(modal).toContain("claude setup-token");
    expect(modal).toContain("keychain");
    expect(modal).toContain("401");
    // The misleading 429.
    expect(modal).toContain("429");
    expect(modal).toContain("client-identity refusal");
    // And the steer to an API key for anything that is not Claude Code.
    expect(modal).toContain("sk-ant-api03");
  });
});

describe("anthropicSecretMismatch", () => {
  it("rejects an API key pasted into the subscription-token field", () => {
    const err = anthropicSecretMismatch("auth_token", "sk-ant-api03-AAAABBBBCCCC");
    expect(err).toBeTruthy();
    expect(err).toContain("API key");
  });

  it("rejects a subscription token pasted into the API-key field", () => {
    const err = anthropicSecretMismatch("api_key", "sk-ant-oat01-AAAABBBBCCCC");
    expect(err).toBeTruthy();
    expect(err).toContain("subscription auth token");
  });

  it("accepts each credential in its correct field", () => {
    expect(anthropicSecretMismatch("api_key", "sk-ant-api03-AAAABBBBCCCC")).toBeNull();
    expect(anthropicSecretMismatch("auth_token", "sk-ant-oat01-AAAABBBBCCCC")).toBeNull();
  });

  it("does NOT try to separate the two subscription token types", () => {
    // Both the setup-token value and the rotating keychain value look like
    // this. Rejecting either would be a false rejection of a valid token, so
    // both must pass and the copy carries the warning instead.
    const setupToken = `sk-ant-oat01-${"A".repeat(80)}`;
    const keychainToken = "sk-ant-oat01-short";
    expect(anthropicSecretMismatch("auth_token", setupToken)).toBeNull();
    expect(anthropicSecretMismatch("auth_token", keychainToken)).toBeNull();
  });

  it("passes unrecognised prefixes rather than risking a false rejection", () => {
    // Anthropic may mint new prefixes at any time. Unknown must never block.
    expect(anthropicSecretMismatch("api_key", "sk-ant-future99-XYZ")).toBeNull();
    expect(anthropicSecretMismatch("auth_token", "sk-ant-future99-XYZ")).toBeNull();
  });

  it("ignores empty input and tolerates surrounding whitespace", () => {
    expect(anthropicSecretMismatch("api_key", "")).toBeNull();
    expect(anthropicSecretMismatch("auth_token", "   ")).toBeNull();
    expect(anthropicSecretMismatch("auth_token", "  sk-ant-api03-AAA  ")).toBeTruthy();
  });
});
