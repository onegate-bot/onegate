/**
 * Linear integration. A personal API key goes directly into the
 * Authorization header (Linear API keys are sent bare, without a Bearer
 * prefix). The API is GraphQL only, so per-path policy cannot separate
 * reads from writes, scope the key itself instead.
 */

import type { Integration, InjectionContext } from "./types.js";

export const linear: Integration = {
  id: "linear",
  title: "Linear",
  hosts: ["api.linear.app"],
  category: "Productivity",
  credentialFields: [{ key: "apiKey", label: "Personal API key", secret: true }],
  llmHelp: {
    credentialType:
      "A Linear personal API key (starts with lin_api_). OneGate puts it directly in the Authorization header, Linear API keys are sent bare without a Bearer prefix.",
    whereToCreate:
      "https://linear.app/settings/account/security (Linear settings, then Security and access, then Personal API keys, then New API key).",
    scopes: [
      "Personal API keys can be scoped at creation: read or write, and limited to specific teams. Grant write only if the agent creates or updates issues.",
    ],
    notes:
      "The Linear API is GraphQL at https://api.linear.app/graphql, every call is POST /graphql. Policy path globs therefore cannot distinguish reads from writes, scope the key itself instead.",
  },
  inject(ctx: InjectionContext): void {
    const apiKey = ctx.credential.data.apiKey;
    if (!apiKey) throw new Error('Linear credential has no "apiKey" field');
    ctx.headers.authorization = apiKey;
  },
};
