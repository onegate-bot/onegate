/**
 * Todoist via a bring-your-own OAuth app. Non-standard corners: scopes are
 * comma separated in the auth URL and the code exchange takes no
 * redirect_uri. Tokens are long lived (no refresh grant), injected as
 * Bearer.
 */

import type { Integration, InjectionContext } from "./types.js";
import { oauthBearerToken } from "./oauth.js";

export const todoist: Integration = {
  id: "todoist",
  title: "Todoist",
  hosts: ["api.todoist.com"],
  category: "Productivity",
  credentialFields: [
    { key: "clientId", label: "Client ID", secret: false },
    { key: "clientSecret", label: "Client secret", secret: true },
    { key: "accessToken", label: "Access token (set by the connect flow)", secret: true },
  ],
  connect: {
    method: "oauth",
    hint: "Use an app from the Todoist App Management console.",
  },
  oauth: {
    authUrl: "https://app.todoist.com/oauth/authorize",
    tokenUrl: "https://api.todoist.com/oauth/access_token",
    defaultScopes: ["data:read_write", "data:delete"],
    scopeSeparator: ",",
    sendRedirectUriInExchange: false,
    permissions: [
      { scope: "data:read", name: "View only", description: "View labels, projects, and tasks", access: "read" },
      { scope: "data:read_write", name: "Edit tasks", description: "View, add, and update labels, projects, and tasks", access: "write" },
      { scope: "data:delete", name: "Remove", description: "Irreversibly remove projects and tasks", access: "write" },
    ],
  },
  llmHelp: {
    credentialType:
      "A Todoist app's client ID and secret. OneGate runs the consent flow and stores the long-lived access token (Todoist tokens do not expire or refresh).",
    whereToCreate:
      "Todoist App Management console (https://app.todoist.com/app/settings/integrations/developer or developer.todoist.com). Create an app and set the OAuth redirect URL to the one shown in the OneGate connect dialog.",
    scopes: ["Pick data:read instead of data:read_write for read-only agents."],
    notes:
      "The current unified API lives under /api/v1/ on api.todoist.com (the older /rest/v2/ paths still work).",
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const token = await oauthBearerToken(todoist, ctx.credential, ctx.store);
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
