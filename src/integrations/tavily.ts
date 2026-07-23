/**
 * Tavily integration. The API key is sent as a Bearer token, which Tavily
 * accepts on all endpoints. Tavily also accepts the key as an "api_key"
 * field inside the JSON request body, a header gateway cannot inject that,
 * so clients must use header auth (see llmHelp notes).
 */

import type { Integration, InjectionContext } from "./types.js";

export const tavily: Integration = {
  id: "tavily",
  title: "Tavily",
  hosts: ["api.tavily.com"],
  category: "Search",
  credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
  llmHelp: {
    credentialType:
      "A Tavily API key (starts with tvly-). OneGate sends it as a Bearer token in the Authorization header.",
    whereToCreate:
      "https://app.tavily.com (sign in and copy the API key from the dashboard).",
    scopes: ["Tavily keys are not scoped, usage is metered per plan."],
    notes:
      "Limitation: Tavily also accepts the key as an api_key field inside the JSON request body, and OneGate cannot rewrite request bodies. Configure the client to authenticate via the Authorization header instead (Tavily supports Bearer auth on all endpoints). Send any placeholder Bearer token and OneGate replaces it.",
  },
  inject(ctx: InjectionContext): void {
    const apiKey = ctx.credential.data.apiKey;
    if (!apiKey) throw new Error('Tavily credential has no "apiKey" field');
    ctx.headers.authorization = `Bearer ${apiKey}`;
  },
};
