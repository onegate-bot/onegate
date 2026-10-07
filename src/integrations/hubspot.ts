/**
 * HubSpot via a private app (legacy app) access token, injected as Bearer on
 * api.hubapi.com. Private app tokens do not expire and carry exactly the
 * scopes ticked on the app, so they are the least-privilege option for an
 * agent working in one HubSpot account. A public OAuth app flow is a
 * follow-up.
 */

import type { Integration, InjectionContext } from "./types.js";

export const hubspot: Integration = {
  id: "hubspot",
  title: "HubSpot",
  hosts: ["api.hubapi.com"],
  category: "CRM",
  credentialFields: [{ key: "token", label: "Private app access token", secret: true }],
  connect: {
    method: "api_key",
    hint: "The access token of a HubSpot private app (pat-na1-... or pat-eu1-...), with only the CRM scopes the agent needs.",
  },
  llmHelp: {
    credentialType:
      "A HubSpot private app access token (starts with pat-). OneGate sends it as a Bearer token on api.hubapi.com.",
    whereToCreate:
      "HubSpot, then Settings, then Integrations, then Private Apps (shown as Legacy Apps in newer accounts), then Create a private app. Copy the access token from the Auth tab.",
    scopes: [
      "Tick read scopes such as crm.objects.contacts.read, crm.objects.companies.read and crm.objects.deals.read, plus the matching .write scopes only if the agent creates or updates records. Add tickets for the tickets API.",
    ],
    notes: "CRM objects live under /crm/v3/objects/<type> (contacts, companies, deals, tickets). Search uses POST /crm/v3/objects/<type>/search.",
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.token;
    if (!token) throw new Error('HubSpot credential has no "token" field');
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
