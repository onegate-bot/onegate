/**
 * Make (make.com) API token, injected as `Authorization: Token <token>`.
 *
 * Make is region-sharded: there is no single API host. An account lives in a
 * zone and its API base is `https://<zone>.make.com/api/v2/...` (eu1, eu2,
 * us1, us2, ...). We claim the `.make.com` suffix so any current or future
 * zone resolves without a hardcoded list. Make's scheme is the literal word
 * `Token`, not `Bearer`.
 */

import type { Integration, InjectionContext } from "./types.js";

export const make: Integration = {
  id: "make",
  title: "Make",
  hosts: [".make.com"],
  category: "Automation",
  credentialFields: [{ key: "apiToken", label: "API token", secret: true }],
  llmHelp: {
    credentialType:
      'A Make API token (a UUID like "12345678-12ef-abcd-1234-1234567890ab"). OneGate sends it as "Authorization: Token <token>" (the literal word Token, not Bearer).',
    whereToCreate:
      "In Make: click your profile avatar, then Profile, then the API / Authentication tab, then Add token. Grant only the scopes the agent needs.",
    scopes: [
      "Make tokens are scope-limited at creation. Pick the narrowest scopes (for example scenarios:read) unless the agent must write.",
    ],
    notes:
      "Make is region-sharded: call your own zone's host, https://<zone>.make.com/api/v2/... where <zone> is the subdomain shown in your browser when logged into Make (eu1, eu2, us1, us2, ...). There is no single api.make.com host.",
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.apiToken;
    if (!token) throw new Error('Make credential has no "apiToken" field');
    ctx.headers.authorization = `Token ${token}`;
  },
};
