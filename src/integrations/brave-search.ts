/**
 * Brave Search integration. The subscription token is injected as the
 * X-Subscription-Token header, which is how the Brave Search API
 * authenticates.
 */

import type { Integration, InjectionContext } from "./types.js";

export const braveSearch: Integration = {
  id: "brave-search",
  title: "Brave Search",
  hosts: ["api.search.brave.com"],
  category: "Search",
  credentialFields: [{ key: "token", label: "Subscription token", secret: true }],
  llmHelp: {
    credentialType:
      "A Brave Search API subscription token. OneGate injects it as the X-Subscription-Token header.",
    whereToCreate:
      "https://api-dashboard.search.brave.com (sign up for the Brave Search API, pick a plan, a free tier exists, then copy the token from the API Keys page).",
    scopes: [
      "Tokens are tied to a subscription plan rather than scopes. The Data for Search plan covers web search at /res/v1/web/search.",
    ],
    notes: 'Paste the token into the "Subscription token" field.',
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.token;
    if (!token) throw new Error('Brave Search credential has no "token" field');
    ctx.headers["x-subscription-token"] = token;
  },
};
