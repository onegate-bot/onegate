/**
 * Airtable personal access token, injected as Bearer on the Web API
 * (api.airtable.com) and the attachment upload host (content.airtable.com).
 */

import type { Integration, InjectionContext } from "./types.js";

export const airtable: Integration = {
  id: "airtable",
  title: "Airtable",
  hosts: ["api.airtable.com", "content.airtable.com"],
  category: "Productivity",
  credentialFields: [{ key: "token", label: "Personal access token", secret: true }],
  connect: {
    method: "api_key",
    hint: "A personal access token (pat...) scoped to the bases the agent needs.",
  },
  llmHelp: {
    credentialType: "An Airtable personal access token (starts with pat). OneGate sends it as a Bearer token.",
    whereToCreate: "https://airtable.com/create/tokens (Builder hub, then Personal access tokens, then Create token).",
    scopes: [
      "Pick scopes such as data.records:read, data.records:write and schema.bases:read, and add only the bases (or workspace) the agent should reach.",
    ],
    notes:
      "Records live under /v0/<baseId>/<tableIdOrName> on api.airtable.com. Attachment uploads go to content.airtable.com, the same token works there.",
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.token;
    if (!token) throw new Error('Airtable credential has no "token" field');
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
