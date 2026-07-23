/**
 * Vercel access token, injected as Bearer on api.vercel.com.
 */

import type { Integration, InjectionContext } from "./types.js";

export const vercel: Integration = {
  id: "vercel",
  title: "Vercel",
  hosts: ["api.vercel.com"],
  category: "Infrastructure",
  credentialFields: [{ key: "apiToken", label: "Access token", secret: true }],
  llmHelp: {
    credentialType: 'A Vercel access token (starts with "vcp_"). OneGate sends it as a Bearer token.',
    whereToCreate:
      "https://vercel.com/account/tokens (Account Settings, then Tokens, then Create). Pick the narrowest scope (a single team) and an expiration.",
    notes:
      "Team resources need the ?teamId=... query parameter on API calls, the token itself does not pin a team unless created team-scoped.",
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.apiToken;
    if (!token) throw new Error('Vercel credential has no "apiToken" field');
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
