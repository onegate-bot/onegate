/** OpenAI integration. The stored API key is sent as a Bearer token. */

import type { Integration, InjectionContext } from "./types.js";

export const openai: Integration = {
  id: "openai",
  title: "OpenAI",
  hosts: ["api.openai.com"],
  category: "AI",
  credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
  llmHelp: {
    credentialType:
      "An OpenAI API key (starts with sk-). OneGate sends it as a Bearer token in the Authorization header.",
    whereToCreate:
      "https://platform.openai.com/api-keys (sign in, then create a new secret key, ideally scoped to a project).",
    scopes: [
      "Project-scoped keys are recommended. Grant the key access to the models and endpoints the agent uses, write access to chat completions and responses is the common case.",
    ],
    notes:
      'Paste the key into the "API key" field. If the account uses organizations, the client can still send its own OpenAI-Organization header, OneGate forwards it unchanged.',
  },
  // LLM calls are POSTs with a body. Buffering it (bounded) lets the proxy
  // replay the request once when the strategy engine fails over mid-request.
  needsBody: true,
  llm: {
    vendor: "openai",
    /**
     * OpenAI LLM connections come in two shapes:
     * a plain { apiKey }, or an imported Codex-CLI auth.json giving
     * { accessToken, accountId? }. An apiKey wins when both are present.
     */
    inject(ctx: InjectionContext): void {
      const { apiKey, accessToken, accountId } = ctx.credential.data;
      if (apiKey) {
        ctx.headers.authorization = `Bearer ${apiKey}`;
        return;
      }
      if (!accessToken) {
        throw new Error('OpenAI LLM connection has neither "apiKey" nor "accessToken"');
      }
      ctx.headers.authorization = `Bearer ${accessToken}`;
      if (accountId) ctx.headers["chatgpt-account-id"] = accountId;
    },
  },
  inject(ctx: InjectionContext): void {
    const apiKey = ctx.credential.data.apiKey;
    if (!apiKey) throw new Error('OpenAI credential has no "apiKey" field');
    ctx.headers.authorization = `Bearer ${apiKey}`;
  },
};
