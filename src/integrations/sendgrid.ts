/** SendGrid integration. The stored API key is sent as a Bearer token. */

import type { Integration, InjectionContext } from "./types.js";

export const sendgrid: Integration = {
  id: "sendgrid",
  title: "SendGrid",
  hosts: ["api.sendgrid.com"],
  category: "Email",
  credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
  llmHelp: {
    credentialType:
      "A SendGrid API key (starts with SG.). OneGate sends it as a Bearer token.",
    whereToCreate:
      "https://app.sendgrid.com/settings/api_keys (Settings, then API Keys, then Create API Key). The key is shown once at creation.",
    scopes: [
      'Choose Restricted Access and grant only what the agent needs, "Mail Send" alone is the common case for sending email.',
    ],
    notes: 'Paste the key into the "API key" field.',
  },
  inject(ctx: InjectionContext): void {
    const apiKey = ctx.credential.data.apiKey;
    if (!apiKey) throw new Error('SendGrid credential has no "apiKey" field');
    ctx.headers.authorization = `Bearer ${apiKey}`;
  },
};
