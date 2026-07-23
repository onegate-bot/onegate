/**
 * Confluence Cloud via a bring-your-own Atlassian OAuth 2.0 (3LO) app.
 * OAuth-authenticated Confluence calls go through api.atlassian.com
 * (/ex/confluence/<cloudId>/...), never the *.atlassian.net site host, so
 * this integration claims api.atlassian.com alongside jira (the proxy picks
 * whichever of the overlapping integrations has a connected credential).
 * Atlassian's token endpoint wants JSON bodies and rotates refresh tokens,
 * the shared engine handles both. The offline_access scope is required or
 * Atlassian returns no refresh token at all.
 */

import type { Integration, InjectionContext } from "./types.js";
import { oauthBearerToken } from "./oauth.js";

export const confluence: Integration = {
  id: "confluence",
  title: "Confluence",
  hosts: ["api.atlassian.com"],
  category: "Productivity",
  credentialFields: [
    { key: "clientId", label: "Client ID", secret: false },
    { key: "clientSecret", label: "Client secret", secret: true },
    { key: "accessToken", label: "Access token (set by the connect flow)", secret: true },
    { key: "refreshToken", label: "Refresh token (set by the connect flow)", secret: true, optional: true },
  ],
  connect: {
    method: "oauth",
    hint: "Use an OAuth 2.0 (3LO) app from the Atlassian developer console.",
  },
  oauth: {
    authUrl: "https://auth.atlassian.com/authorize",
    tokenUrl: "https://auth.atlassian.com/oauth/token",
    defaultScopes: [
      "read:me",
      "offline_access",
      "read:confluence-content.all",
      "write:confluence-content",
      "read:confluence-space.summary",
      "read:page:confluence",
      "read:space:confluence",
      "write:page:confluence",
      "read:content:confluence",
    ],
    permissions: [
      { scope: "read:confluence-content.all", name: "Content read", description: "Open blog posts, pages, and their comments", access: "read" },
      { scope: "write:confluence-content", name: "Content write", description: "Author and revise blog posts, pages, and comments", access: "write" },
      { scope: "read:confluence-space.summary", name: "Space read", description: "Inspect space metadata and summaries", access: "read" },
      { scope: "read:page:confluence", name: "Page read (v2)", description: "Retrieve page bodies through the v2 REST endpoints", access: "read" },
      { scope: "write:page:confluence", name: "Page write (v2)", description: "Author and revise pages through the v2 REST endpoints", access: "write" },
      { scope: "read:me", name: "Identity", description: "Your Atlassian display name and avatar", access: "read" },
    ],
    extraAuthParams: { audience: "api.atlassian.com", prompt: "consent" },
    tokenFormat: "json",
  },
  llmHelp: {
    credentialType:
      "An Atlassian OAuth 2.0 (3LO) app's client ID and secret. OneGate runs the consent flow, stores the tokens and refreshes them automatically (Atlassian rotates refresh tokens, OneGate persists the replacements).",
    whereToCreate:
      "Atlassian developer console (https://developer.atlassian.com/console/myapps), create an OAuth 2.0 integration, add the Confluence API with the scopes I select in the connect dialog, and register the redirect URI shown there under Authorization.",
    scopes: [
      "offline_access is always required, without it Atlassian returns no refresh token and the connection dies when the first access token expires.",
    ],
    notes:
      "OAuth Confluence calls go through api.atlassian.com: first GET /oauth/token/accessible-resources to find the cloudId, then /ex/confluence/<cloudId>/wiki/api/v2/... for the actual API. The *.atlassian.net site hosts only accept Basic auth (the jira integration covers those).",
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const token = await oauthBearerToken(confluence, ctx.credential, ctx.store);
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
