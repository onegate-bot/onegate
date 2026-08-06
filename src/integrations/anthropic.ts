/**
 * Anthropic integration. An Anthropic connection authenticates in one of two
 * modes:
 *
 *  - API key (default): the stored key is injected as the `x-api-key` header,
 *    which is how the Anthropic API authenticates plain API keys.
 *  - Subscription auth token: a long-lived OAuth token (from `claude setup-token`)
 *    is injected as `Authorization: Bearer <token>` together with the
 *    `oauth-2025-04-20` value in the `anthropic-beta` header. This is how
 *    Anthropic authenticates Claude subscription / OAuth tokens. Any incoming
 *    `x-api-key` header is removed so the bearer credential is the only one.
 *
 * The mode is taken from an explicit `authMode` discriminator when present
 * ("api_key" | "auth_token"); otherwise it is inferred from which secret field
 * is set (`authToken` => bearer, `apiKey` => x-api-key). Other headers the
 * client sets (anthropic-version, anthropic-beta) are forwarded unchanged
 * except for the beta value the bearer mode must ensure.
 */

import type { Integration, InjectionContext } from "./types.js";

/** The OAuth beta flag Anthropic requires for subscription/OAuth bearer tokens. */
const OAUTH_BETA = "oauth-2025-04-20";

/** Prefix carried by a plain Anthropic API key (console.anthropic.com). */
export const ANTHROPIC_API_KEY_PREFIX = "sk-ant-api";
/**
 * Prefix carried by an Anthropic subscription/OAuth token. NOTE: BOTH
 * subscription token types share it (see ANTHROPIC_TOKEN_GUIDANCE), so it
 * distinguishes subscription-from-API-key and nothing finer.
 */
export const ANTHROPIC_AUTH_TOKEN_PREFIX = "sk-ant-oat";

/**
 * The two Anthropic credential mistakes that cost users the most time, stated
 * once here so the connect wizard, the LLM help prompt and the validator all
 * tell the same story.
 *
 * 1. TWO SUBSCRIPTION TOKENS, ONE PREFIX. `claude setup-token` mints a
 *    long-lived token, and the Claude Code client separately caches a
 *    short-lived token in the local keychain that it ROTATES. Both start with
 *    `sk-ant-oat`, so neither this form nor the user can tell them apart by
 *    looking. Pasting the keychain one "works" and then 401s hours later when
 *    the owning client rotates it. Only the `claude setup-token` value is
 *    safe to store here.
 * 2. SUBSCRIPTION TOKENS ARE CLIENT-BOUND. Anthropic accepts a subscription
 *    token only for the Claude Code client. Any other client sending one gets
 *    a 429 that reads like a rate limit or a capacity problem but is really a
 *    client-identity refusal, so raising limits or waiting never helps. A
 *    non-Claude-Code agent needs an API key instead.
 */
export const ANTHROPIC_TOKEN_GUIDANCE = {
  /** Which of the two same-prefix subscription tokens to paste. */
  whichToken:
    "Two different Anthropic subscription tokens both start with sk-ant-oat, so the form cannot tell them apart. Paste the long-lived token printed by `claude setup-token`. Do NOT copy the short-lived token that the Claude Code client caches in your local keychain: that one is rotated by its owning client, so the connection looks fine now and starts returning 401 hours later.",
  /** Why a subscription token 429s for anything that is not Claude Code. */
  clientIdentity:
    "A subscription token of either kind is only accepted for the Claude Code client. Any other client sending one gets a 429 that looks like a rate limit or a capacity problem but is actually a client-identity refusal, so waiting or raising limits will not fix it. If the agent is not Claude Code, connect an Anthropic API key (sk-ant-api03) instead of a subscription token.",
} as const;

/**
 * Rejects a credential pasted into the wrong Anthropic field, and nothing else.
 *
 * This checks ONLY the api-key-vs-subscription-token prefix mix-up, because
 * that is the one signal that is locally reliable. The two subscription token
 * types are NOT separable here (both are `sk-ant-oat`), so no check is
 * attempted for them and the wizard copy carries that warning instead. An
 * unrecognised prefix passes: Anthropic can add prefixes at any time and a
 * false rejection of a valid credential is worse than the warning.
 *
 * Returns an error string, or null when there is nothing to complain about.
 */
export function anthropicSecretMismatch(
  mode: "api_key" | "auth_token",
  secret: string,
): string | null {
  const value = secret.trim();
  if (!value) return null;
  if (mode === "auth_token" && value.startsWith(ANTHROPIC_API_KEY_PREFIX)) {
    return 'That looks like an Anthropic API key (sk-ant-api...), not a subscription auth token. Choose the "API key" credential mode, or paste the token printed by `claude setup-token`.';
  }
  if (mode === "api_key" && value.startsWith(ANTHROPIC_AUTH_TOKEN_PREFIX)) {
    return 'That looks like an Anthropic subscription auth token (sk-ant-oat...), not an API key. Choose the "Subscription auth token" credential mode, or paste an API key from https://console.anthropic.com/settings/keys.';
  }
  return null;
}

/**
 * Ensures `anthropic-beta` carries `value`. Appends to the client's existing
 * comma-separated header when the value is missing rather than clobbering it,
 * and sets it when the client sent none.
 */
function ensureBeta(ctx: InjectionContext, value: string): void {
  const existing = ctx.headers["anthropic-beta"];
  const current = Array.isArray(existing) ? existing.join(", ") : existing ?? "";
  const parts = current
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!parts.includes(value)) parts.push(value);
  ctx.headers["anthropic-beta"] = parts.join(", ");
}

/**
 * Injects the connection's secret using the resolved auth mode. Shared by the
 * LLM `inject` and (for api-key connections) the passthrough `inject`.
 */
function injectAnthropic(ctx: InjectionContext): void {
  const data = ctx.credential.data;
  const authMode = data.authMode;
  const useBearer =
    authMode === "auth_token" || (authMode !== "api_key" && Boolean(data.authToken));

  if (useBearer) {
    const authToken = data.authToken;
    if (!authToken) throw new Error('Anthropic auth-token connection has no "authToken" field');
    ctx.headers["authorization"] = `Bearer ${authToken}`;
    delete ctx.headers["x-api-key"];
    ensureBeta(ctx, OAUTH_BETA);
    return;
  }

  const apiKey = data.apiKey;
  if (!apiKey)
    throw new Error('Anthropic connection has no "apiKey" or "authToken" field');
  ctx.headers["x-api-key"] = apiKey;
}

export const anthropic: Integration = {
  id: "anthropic",
  title: "Anthropic",
  hosts: ["api.anthropic.com"],
  category: "AI",
  credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
  connect: {
    method: "api_key",
    hint: "An Anthropic API key (sk-ant-api03) or a Claude subscription auth token from `claude setup-token`. Pick an API key unless the agent is Claude Code itself.",
  },
  connectGuide: {
    consoleUrl: "https://console.anthropic.com/settings/keys",
    steps: [
      "Decide which credential you need. An API key works for every client and is the right default. A subscription auth token only works for the Claude Code client.",
      "API key: open https://console.anthropic.com/settings/keys (Anthropic Console, then Settings, then API keys), click Create key, pick the workspace whose spend limits should apply, and copy the value (it starts with sk-ant-api03).",
      "Subscription auth token: run `claude setup-token` in the Claude Code CLI while logged into your Claude subscription, and copy the long-lived token it prints.",
      ANTHROPIC_TOKEN_GUIDANCE.whichToken,
      ANTHROPIC_TOKEN_GUIDANCE.clientIdentity,
      "Paste the credential into the field below and click Connect Anthropic.",
    ],
  },
  llmHelp: {
    credentialType:
      "Either an Anthropic API key (starts with sk-ant-api03) OR a Claude subscription auth token (starts with sk-ant-oat). For an API key, OneGate injects it as the x-api-key header. For a subscription auth token, OneGate injects it as Authorization: Bearer plus the anthropic-beta: oauth-2025-04-20 header, which is how Anthropic authenticates Claude subscription / OAuth tokens.",
    whereToCreate:
      "API key: https://console.anthropic.com/settings/keys (Anthropic Console, then Settings, then API keys, then Create key). Subscription auth token: run `claude setup-token` in the Claude Code CLI while logged into your Claude subscription, which prints a long-lived OAuth token to paste here.",
    scopes: [
      "Anthropic API keys are not scoped per endpoint. Keys can be workspace-scoped, pick the workspace whose spend limits should apply to the agent.",
      "Subscription auth tokens carry your Claude plan's access and billing, no per-endpoint scoping.",
    ],
    notes:
      'Paste an API key into the "API key" field, or a subscription auth token into the "Subscription auth token" field. The client keeps setting its own anthropic-version header, OneGate only sets the credential (and, for subscription tokens, ensures the oauth-2025-04-20 anthropic-beta flag). ' +
      ANTHROPIC_TOKEN_GUIDANCE.whichToken +
      " " +
      ANTHROPIC_TOKEN_GUIDANCE.clientIdentity +
      " Honest caveat: subscription auth tokens are intended for Claude Code use, and load-balancing several subscriptions through a proxy is a gray area with Anthropic, use at your own discretion.",
  },
  // LLM calls are POSTs with a body. Buffering it (bounded) lets the proxy
  // replay the request once when the strategy engine fails over mid-request.
  needsBody: true,
  llm: {
    vendor: "anthropic",
    inject(ctx: InjectionContext): void {
      injectAnthropic(ctx);
    },
  },
  // The passthrough (app-credential) path stays api-key only.
  inject(ctx: InjectionContext): void {
    const apiKey = ctx.credential.data.apiKey;
    if (!apiKey) throw new Error('Anthropic credential has no "apiKey" field');
    ctx.headers["x-api-key"] = apiKey;
  },
};
