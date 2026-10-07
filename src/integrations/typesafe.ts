/**
 * TypeSafe integration (Jev models). Jev is a "System One" model: a request
 * carries a `state` plus a map of typed questions (noul / choice / score) and
 * the response carries typed answers with probabilities instead of generated
 * text. It is still billed per token and reports `usage.input_tokens` /
 * `usage.output_tokens`, so it routes and accounts like any other LLM vendor.
 * The stored key is sent as a Bearer token.
 */

import type { Integration, InjectionContext } from "./types.js";

export const typesafe: Integration = {
  id: "typesafe",
  title: "TypeSafe (Jev)",
  hosts: ["api.typesafe.ai"],
  category: "AI",
  credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
  llmHelp: {
    credentialType:
      "A TypeSafe API key. OneGate sends it as a Bearer token in the Authorization header.",
    whereToCreate: "https://console.typesafe.ai/keys (sign in, then create a new key).",
    scopes: [
      "Keys are account-wide: one key reaches POST /v1/systemone and GET /v1/models for every Jev model the account can use, so scope access with OneGate rules rather than at the vendor.",
    ],
    notes:
      "Paste the key into the \"API key\" field. The API lives at https://api.typesafe.ai (SDK env vars TYPESAFE_API_KEY and TYPESAFE_BASE_URL). Evaluations are POST /v1/systemone with { state, model, questions }, where model is jev-latest, jev-preview or a pinned version such as jev-1.13.0. There is no streaming. 429 (rate limit) and 529 (overloaded) are retryable.",
  },
  // Evaluations are POSTs with a body. Buffering it (bounded) lets the proxy
  // replay the request once when the strategy engine fails over mid-request.
  needsBody: true,
  llm: {
    vendor: "typesafe",
    inject(ctx: InjectionContext): void {
      const apiKey = ctx.credential.data.apiKey;
      if (!apiKey) throw new Error('TypeSafe LLM connection has no "apiKey" field');
      ctx.headers.authorization = `Bearer ${apiKey}`;
    },
  },
  inject(ctx: InjectionContext): void {
    const apiKey = ctx.credential.data.apiKey;
    if (!apiKey) throw new Error('TypeSafe credential has no "apiKey" field');
    ctx.headers.authorization = `Bearer ${apiKey}`;
  },
};
