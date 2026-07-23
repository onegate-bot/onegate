/**
 * OpenRouter integration. OpenRouter is an OpenAI-compatible aggregator that
 * routes to many model providers behind one API key. The stored key is sent as
 * a Bearer token, exactly like OpenAI.
 */

import type { Integration, InjectionContext } from "./types.js";

export const openrouter: Integration = {
  id: "openrouter",
  title: "OpenRouter",
  hosts: ["openrouter.ai"],
  category: "AI",
  credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
  llmHelp: {
    credentialType:
      "An OpenRouter API key (starts with sk-or-). OneGate sends it as a Bearer token in the Authorization header.",
    whereToCreate: "https://openrouter.ai/keys (sign in, then create a new key).",
    scopes: [
      "Optionally cap the key with a credit limit on the OpenRouter dashboard. The same key reaches every model OpenRouter exposes, so scope by credit rather than by model.",
    ],
    notes:
      "Paste the key into the \"API key\" field. The API is OpenAI-compatible at https://openrouter.ai/api/v1, so point the client's base URL there and use OpenRouter model ids (e.g. anthropic/claude-3.5-sonnet). The client may also send HTTP-Referer and X-Title headers for attribution, OneGate forwards them unchanged.",
  },
  // LLM calls are POSTs with a body. Buffering it (bounded) lets the proxy
  // replay the request once when the strategy engine fails over mid-request.
  needsBody: true,
  llm: {
    vendor: "openrouter",
    inject(ctx: InjectionContext): void {
      const apiKey = ctx.credential.data.apiKey;
      if (!apiKey) throw new Error('OpenRouter LLM connection has no "apiKey" field');
      ctx.headers.authorization = `Bearer ${apiKey}`;
    },
  },
  inject(ctx: InjectionContext): void {
    const apiKey = ctx.credential.data.apiKey;
    if (!apiKey) throw new Error('OpenRouter credential has no "apiKey" field');
    ctx.headers.authorization = `Bearer ${apiKey}`;
  },
};
