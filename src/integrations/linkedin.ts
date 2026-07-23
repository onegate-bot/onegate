/**
 * LinkedIn via a bring-your-own OAuth app. Standard authorization-code
 * flow. Most LinkedIn apps get no refresh token (programmatic refresh is
 * limited to approved partners), so the stored access token simply expires
 * after about 60 days and the user reconnects. When a refresh token IS
 * present the shared engine uses it. Injected as Bearer on
 * api.linkedin.com.
 */

import type { Integration, InjectionContext } from "./types.js";
import { oauthBearerToken } from "./oauth.js";

export const linkedin: Integration = {
  id: "linkedin",
  title: "LinkedIn",
  hosts: ["api.linkedin.com"],
  category: "Social",
  credentialFields: [
    { key: "clientId", label: "Client ID", secret: false },
    { key: "clientSecret", label: "Client secret", secret: true },
    { key: "accessToken", label: "Access token (set by the connect flow)", secret: true },
    { key: "refreshToken", label: "Refresh token (set by the connect flow)", secret: true, optional: true },
  ],
  connect: {
    method: "oauth",
    hint: "Use an app from the LinkedIn Developer Portal.",
  },
  oauth: {
    authUrl: "https://www.linkedin.com/oauth/v2/authorization",
    tokenUrl: "https://www.linkedin.com/oauth/v2/accessToken",
    defaultScopes: ["openid", "profile", "email", "w_member_social"],
    permissions: [
      { scope: "openid", name: "Identity", description: "Confirm who you are on LinkedIn", access: "read" },
      { scope: "profile", name: "Profile", description: "Your display name, headline, and photo", access: "read" },
      { scope: "email", name: "Email", description: "The email address on your account", access: "read" },
      { scope: "w_member_social", name: "Posts & reactions", description: "Publish, edit, and remove posts, comments, and reactions", access: "write" },
    ],
  },
  llmHelp: {
    credentialType:
      "A LinkedIn app's client ID and secret. OneGate runs the consent flow and stores the access token. Most apps get no refresh token, the token lasts about 60 days and then the user reconnects.",
    whereToCreate:
      "LinkedIn Developer Portal (https://developer.linkedin.com, My Apps). Create an app, add the 'Sign In with LinkedIn using OpenID Connect' and 'Share on LinkedIn' products for the default scopes, and register the redirect URI shown in the OneGate connect dialog.",
    scopes: [
      "Each scope must be granted by a product added to the app (e.g. w_member_social comes from Share on LinkedIn). Requesting a scope no product grants fails the consent screen.",
    ],
    notes:
      "Use /v2/userinfo for identity and /rest/posts (with the LinkedIn-Version header) for posting.",
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const token = await oauthBearerToken(linkedin, ctx.credential, ctx.store);
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
