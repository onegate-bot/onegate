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
  llmHelp: {
    credentialType:
      "Either an Anthropic API key (starts with sk-ant-) OR a Claude subscription auth token. For an API key, OneGate injects it as the x-api-key header. For a subscription auth token, OneGate injects it as Authorization: Bearer plus the anthropic-beta: oauth-2025-04-20 header, which is how Anthropic authenticates Claude subscription / OAuth tokens.",
    whereToCreate:
      "API key: https://console.anthropic.com/settings/keys (Anthropic Console, then Settings, then API keys, then Create key). Subscription auth token: run `claude setup-token` in the Claude Code CLI while logged into your Claude subscription, which prints a long-lived OAuth token to paste here.",
    scopes: [
      "Anthropic API keys are not scoped per endpoint. Keys can be workspace-scoped, pick the workspace whose spend limits should apply to the agent.",
      "Subscription auth tokens carry your Claude plan's access and billing, no per-endpoint scoping.",
    ],
    notes:
      'Paste an API key into the "API key" field, or a subscription auth token into the "Subscription auth token" field. The client keeps setting its own anthropic-version header, OneGate only sets the credential (and, for subscription tokens, ensures the oauth-2025-04-20 anthropic-beta flag). Honest caveat: subscription auth tokens are intended for Claude Code use, and load-balancing several subscriptions through a proxy is a gray area with Anthropic, use at your own discretion.',
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
