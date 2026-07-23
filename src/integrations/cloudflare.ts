/**
 * Cloudflare API token, injected as Bearer on api.cloudflare.com. API
 * tokens are scoped at creation time (per zone, per permission group), so
 * the vendor-side credential is the primary least-privilege control.
 */

import type { Integration, InjectionContext } from "./types.js";

export const cloudflare: Integration = {
  id: "cloudflare",
  title: "Cloudflare",
  hosts: ["api.cloudflare.com"],
  category: "Infrastructure",
  credentialFields: [{ key: "apiToken", label: "API token", secret: true }],
  llmHelp: {
    credentialType:
      "A Cloudflare API token (not the legacy Global API Key). OneGate sends it as a Bearer token.",
    whereToCreate:
      "https://dash.cloudflare.com/profile/api-tokens (Cloudflare dashboard, My Profile, then API Tokens, then Create Token).",
    scopes: [
      "Pick a template or build a custom token: grant only the permission groups the agent needs (e.g. Zone DNS Edit for DNS automation, Workers Scripts Edit for deploying Workers) and restrict it to specific zones or accounts.",
    ],
    notes: 'Paste the token into the "API token" field. Verify it with GET /client/v4/user/tokens/verify.',
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.apiToken;
    if (!token) throw new Error('Cloudflare credential has no "apiToken" field');
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
