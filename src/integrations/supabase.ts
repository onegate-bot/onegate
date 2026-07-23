/**
 * Supabase Management API via a bring-your-own OAuth app. The authorize URL
 * takes no scope parameter, access is fixed by the scopes configured on the
 * OAuth app itself in the Supabase dashboard. Client credentials ride in an
 * HTTP Basic header on token requests, tokens refresh through the shared
 * engine. Injected as Bearer on api.supabase.com.
 */

import type { Integration, InjectionContext } from "./types.js";
import { oauthBearerToken } from "./oauth.js";

export const supabase: Integration = {
  id: "supabase",
  title: "Supabase",
  hosts: ["api.supabase.com"],
  category: "Developer",
  credentialFields: [
    { key: "clientId", label: "Client ID", secret: false },
    { key: "clientSecret", label: "Client secret", secret: true },
    { key: "accessToken", label: "Access token (set by the connect flow)", secret: true },
    { key: "refreshToken", label: "Refresh token (set by the connect flow)", secret: true, optional: true },
  ],
  connect: {
    method: "oauth",
    hint: "Register an OAuth app from your Supabase org settings. The app's own scopes govern access, you do not pick them here.",
  },
  oauth: {
    authUrl: "https://api.supabase.com/v1/oauth/authorize",
    tokenUrl: "https://api.supabase.com/v1/oauth/token",
    defaultScopes: [],
    omitScopeParam: true,
    tokenAuth: "basic",
    permissions: [
      { scope: "projects:read", name: "Projects", description: "Inspect projects along with their settings and networking", access: "read" },
      { scope: "database:read", name: "Database", description: "Read pooler, SSL, and other database configuration", access: "read" },
      { scope: "database:write", name: "Database write", description: "Execute SQL plus administer backups and webhooks", access: "write" },
      { scope: "auth:read", name: "Auth", description: "Inspect authentication config and SSO providers", access: "read" },
      { scope: "organizations:read", name: "Organizations", description: "Inspect org details and their member lists", access: "read" },
      { scope: "storage:read", name: "Storage", description: "Enumerate and inspect storage buckets", access: "read" },
      { scope: "edge_functions:read", name: "Edge Functions", description: "Enumerate and inspect edge functions", access: "read" },
      { scope: "secrets:read", name: "Secrets", description: "Inspect project secrets and API keys", access: "read" },
    ],
  },
  llmHelp: {
    credentialType:
      'A Supabase OAuth app\'s client ID and secret (secret starts with "sba_"). OneGate runs the consent flow, stores the tokens and refreshes them automatically.',
    whereToCreate:
      "Supabase dashboard, organization settings, OAuth Apps, then Create app. Register the redirect URI shown in the OneGate connect dialog.",
    scopes: [
      "Scopes are configured ON the OAuth app in the Supabase dashboard, not requested per authorization. The permission list shown in the connect dialog is informational, tick the matching scopes when creating the app.",
    ],
    notes:
      "This covers the Management API (api.supabase.com/v1/...): projects, database config, edge functions, secrets. Project data APIs (<ref>.supabase.co) use project keys, not this credential.",
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const token = await oauthBearerToken(supabase, ctx.credential, ctx.store);
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
