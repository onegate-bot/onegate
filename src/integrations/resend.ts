/**
 * Resend API key, injected as Bearer on api.resend.com.
 */

import type { Integration, InjectionContext } from "./types.js";

export const resend: Integration = {
  id: "resend",
  title: "Resend",
  hosts: ["api.resend.com"],
  category: "Email",
  credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
  llmHelp: {
    credentialType: 'A Resend API key (starts with "re_"). OneGate sends it as a Bearer token.',
    whereToCreate:
      "https://resend.com/api-keys (Resend dashboard, API Keys, then Create API Key).",
    scopes: [
      'Choose "Sending access" restricted to a single domain unless the agent also manages domains, audiences, or templates.',
    ],
    notes: "POST /emails is the send endpoint. A sending-only key cannot read or list anything.",
  },
  inject(ctx: InjectionContext): void {
    const key = ctx.credential.data.apiKey;
    if (!key) throw new Error('Resend credential has no "apiKey" field');
    ctx.headers.authorization = `Bearer ${key}`;
  },
};
