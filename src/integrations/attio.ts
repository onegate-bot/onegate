/** Attio API key (workspace access token), injected as Bearer on api.attio.com. */

import type { Integration, InjectionContext } from "./types.js";

export const attio: Integration = {
  id: "attio",
  title: "Attio",
  hosts: ["api.attio.com"],
  category: "CRM",
  credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
  connect: {
    method: "api_key",
    hint: "A workspace API key from Attio's developer settings, scoped to what the agent needs.",
  },
  llmHelp: {
    credentialType: "An Attio workspace API key (access token). OneGate sends it as a Bearer token.",
    whereToCreate:
      "Attio, then Workspace settings, then Developers, then create an integration and generate an API key.",
    scopes: [
      "Attio keys carry per-area scopes (records, object configuration, list entries, notes, tasks, ...) each set to read or read-write. Grant read-only where the agent only looks things up.",
    ],
    notes: "The REST API lives under https://api.attio.com/v2/. GET /v2/self shows which workspace the key belongs to.",
  },
  inject(ctx: InjectionContext): void {
    const apiKey = ctx.credential.data.apiKey;
    if (!apiKey) throw new Error('Attio credential has no "apiKey" field');
    ctx.headers.authorization = `Bearer ${apiKey}`;
  },
};
