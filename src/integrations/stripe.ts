/** Stripe integration. The stored secret key is sent as a Bearer token. */

import type { Integration, InjectionContext } from "./types.js";

export const stripe: Integration = {
  id: "stripe",
  title: "Stripe",
  hosts: ["api.stripe.com", "files.stripe.com"],
  category: "Payments",
  credentialFields: [{ key: "secretKey", label: "Secret key", secret: true }],
  llmHelp: {
    credentialType:
      "A Stripe secret API key (sk_live_ or sk_test_), or preferably a restricted key (rk_). OneGate sends it as a Bearer token.",
    whereToCreate:
      "https://dashboard.stripe.com/apikeys (Developers, then API keys). Use Create restricted key to limit what the agent can touch.",
    scopes: [
      "Restricted keys grant read or write per resource (charges, customers, payment intents and so on). Grant only what the agent needs, and use a test mode key while developing.",
    ],
    notes:
      'Paste the key into the "Secret key" field. Test versus live mode is determined by the key itself, not the URL.',
  },
  inject(ctx: InjectionContext): void {
    const secretKey = ctx.credential.data.secretKey;
    if (!secretKey) throw new Error('Stripe credential has no "secretKey" field');
    ctx.headers.authorization = `Bearer ${secretKey}`;
  },
};
