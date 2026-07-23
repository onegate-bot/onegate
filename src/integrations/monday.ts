/**
 * monday.com via a bring-your-own OAuth app. The authorize URL takes no
 * scope parameter (scopes are fixed on the app in the Developer Center)
 * and the issued token is long lived with no refresh grant. Injected as
 * Bearer on api.monday.com (GraphQL).
 */

import type { Integration, InjectionContext } from "./types.js";
import { oauthBearerToken } from "./oauth.js";

export const monday: Integration = {
  id: "monday",
  title: "monday.com",
  hosts: ["api.monday.com"],
  category: "Productivity",
  credentialFields: [
    { key: "clientId", label: "Client ID", secret: false },
    { key: "clientSecret", label: "Client secret", secret: true },
    { key: "accessToken", label: "Access token (set by the connect flow)", secret: true },
  ],
  connect: {
    method: "oauth",
    hint: "Register an app from the monday.com Developer Center. Its access comes from the app's own scopes, not picked here.",
  },
  oauth: {
    authUrl: "https://auth.monday.com/oauth2/authorize",
    tokenUrl: "https://auth.monday.com/oauth2/token",
    defaultScopes: [],
    omitScopeParam: true,
    permissions: [
      { scope: "me:read", name: "Profile", description: "Your display name, avatar, and email", access: "read" },
      { scope: "boards:read", name: "Boards (read)", description: "Inspect boards together with their items and columns", access: "read" },
      { scope: "boards:write", name: "Boards (write)", description: "Add and edit boards, their items, and columns", access: "write" },
      { scope: "docs:read", name: "Docs (read)", description: "Open documents", access: "read" },
      { scope: "docs:write", name: "Docs (write)", description: "Author and revise documents", access: "write" },
      { scope: "updates:read", name: "Updates (read)", description: "Read updates and comments", access: "read" },
      { scope: "updates:write", name: "Updates (write)", description: "Add updates and comments", access: "write" },
      { scope: "workspaces:read", name: "Workspaces", description: "Inspect workspaces", access: "read" },
      { scope: "users:read", name: "Users", description: "Inspect user profiles", access: "read" },
      { scope: "webhooks:write", name: "Webhooks", description: "Administer webhook setup", access: "write" },
    ],
  },
  llmHelp: {
    credentialType:
      "A monday.com app's client ID and secret. OneGate runs the consent flow and stores the long-lived access token (monday tokens do not expire or refresh).",
    whereToCreate:
      "monday.com Developer Center (avatar menu, then Developers). Create an app, add the OAuth scopes the agent needs on the app's OAuth page, and register the redirect URI shown in the OneGate connect dialog.",
    scopes: [
      "Scopes are configured ON the app in the Developer Center, the authorize URL carries none. The permission list in the connect dialog is informational.",
    ],
    notes:
      "The API is GraphQL only: POST /v2 on api.monday.com. Path policy cannot split read from write, bound access with the app's scopes instead.",
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const token = await oauthBearerToken(monday, ctx.credential, ctx.store);
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
