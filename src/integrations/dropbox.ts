/**
 * Dropbox via a bring-your-own OAuth app. token_access_type=offline makes
 * Dropbox return a refresh token, the access tokens themselves are short
 * lived and minted by the shared engine. Both the RPC host
 * (api.dropboxapi.com) and the content host (content.dropboxapi.com,
 * uploads/downloads) take the same Bearer token.
 */

import type { Integration, InjectionContext } from "./types.js";
import { oauthBearerToken } from "./oauth.js";

export const dropbox: Integration = {
  id: "dropbox",
  title: "Dropbox",
  hosts: ["api.dropboxapi.com", "content.dropboxapi.com"],
  category: "Storage",
  credentialFields: [
    { key: "clientId", label: "App key", secret: false },
    { key: "clientSecret", label: "App secret", secret: true },
    { key: "accessToken", label: "Access token (set by the connect flow)", secret: true },
    { key: "refreshToken", label: "Refresh token (set by the connect flow)", secret: true, optional: true },
  ],
  connect: {
    method: "oauth",
    hint: "Use an app from the Dropbox App Console (dropbox.com/developers/apps).",
  },
  oauth: {
    authUrl: "https://www.dropbox.com/oauth2/authorize",
    tokenUrl: "https://api.dropboxapi.com/oauth2/token",
    defaultScopes: ["account_info.read", "files.metadata.read", "files.content.read"],
    permissions: [
      { scope: "account_info.read", name: "Account details", description: "See the account holder's display name, email address, and avatar", access: "read" },
      { scope: "files.metadata.read", name: "Browse files", description: "Enumerate folders and files together with their sizes", access: "read" },
      { scope: "files.metadata.write", name: "Reorganize files", description: "Relocate, rename, or remove folders and files", access: "write" },
      { scope: "files.content.read", name: "Fetch contents", description: "Open and pull down the contents of files", access: "read" },
      { scope: "files.content.write", name: "Store contents", description: "Add new files or overwrite existing file contents", access: "write" },
      { scope: "sharing.read", name: "View sharing", description: "Inspect shared links and shared folders", access: "read" },
      { scope: "sharing.write", name: "Adjust sharing", description: "Generate shared links and make folders shareable", access: "write" },
    ],
    extraAuthParams: { token_access_type: "offline" },
  },
  llmHelp: {
    credentialType:
      "A Dropbox app's App key and App secret. OneGate runs the consent flow with token_access_type=offline, stores the refresh token and mints short-lived access tokens automatically.",
    whereToCreate:
      "Dropbox App Console (https://www.dropbox.com/developers/apps). Create a Scoped access app, enable the permissions I select in the connect dialog on the Permissions tab, and add the redirect URI shown in the OneGate dialog on the Settings tab.",
    scopes: [
      "Each scope I tick in the connect dialog must ALSO be enabled on the app's Permissions tab in the App Console, Dropbox rejects scopes the app does not declare.",
    ],
    notes:
      "One credential covers both api.dropboxapi.com (RPC endpoints) and content.dropboxapi.com (upload and download endpoints).",
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const token = await oauthBearerToken(dropbox, ctx.credential, ctx.store);
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
