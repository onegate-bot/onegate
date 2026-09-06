/**
 * GitLab via a bring-your-own OAuth application. API requests get a Bearer
 * access token, git smart HTTP gets Basic oauth2:<token>. GitLab access
 * tokens are short lived and the refresh token rotates on every use; the
 * shared engine handles both.
 *
 * SELF-MANAGED INSTANCES: this integration declares `supportsInstanceOrigin`,
 * so a connection may name the owner's own GitLab domain (e.g.
 * https://gitlab.acme.example). That origin then resolves to this integration
 * and injection is pinned to the connection that claimed it, which is what
 * self-managed deployments need: injection here is host-agnostic (it keys off
 * the request path, not the host), so the same rules apply on any instance.
 *
 * NOT covered yet: the OAuth consent endpoints below are gitlab.com absolute
 * URLs, and the shared engine resolves them from this descriptor rather than
 * from the connection. A self-managed connection therefore has to be created
 * with tokens already in hand (or via the per-integration ONEGATE_GITLAB_AUTH
 * and ONEGATE_GITLAB_TOKEN env overrides). Running consent against the owner's
 * own instance is deliberately deferred, see the PR body.
 */

import type { Integration, InjectionContext } from "./types.js";
import { oauthBearerToken } from "./oauth.js";

export const gitlab: Integration = {
  id: "gitlab",
  title: "GitLab",
  hosts: ["gitlab.com"],
  category: "Developer",
  supportsInstanceOrigin: true,
  credentialFields: [
    { key: "clientId", label: "Application ID", secret: false },
    { key: "clientSecret", label: "Secret", secret: true },
    { key: "accessToken", label: "Access token (set by the connect flow)", secret: true },
    { key: "refreshToken", label: "Refresh token (set by the connect flow)", secret: true, optional: true },
  ],
  connect: {
    method: "oauth",
    hint: "Use an OAuth application from GitLab User Settings, then Applications.",
  },
  oauth: {
    authUrl: "https://gitlab.com/oauth/authorize",
    tokenUrl: "https://gitlab.com/oauth/token",
    defaultScopes: ["api", "read_user", "read_repository", "write_repository", "read_registry"],
    permissions: [
      { scope: "api", name: "Complete API", description: "Every API endpoint, spanning repos and CI/CD pipelines", access: "write" },
      { scope: "read_user", name: "User profile", description: "Display name, avatar, and email address", access: "read" },
      { scope: "read_repository", name: "Repository read", description: "Fetch and clone the contents of repositories", access: "read" },
      { scope: "write_repository", name: "Repository write", description: "Commit, branch, and modify repository contents", access: "write" },
      { scope: "read_registry", name: "Image registry", description: "Download images held in the container registry", access: "read" },
    ],
  },
  llmHelp: {
    credentialType:
      "A GitLab OAuth application (Application ID starting with a long hex string, Secret starting with gloas-). OneGate runs the consent flow, stores the tokens and refreshes them automatically.",
    whereToCreate:
      "GitLab, User Settings, then Applications (https://gitlab.com/-/user_settings/applications). Create an application with the redirect URI shown in the OneGate connect dialog and the scopes I select there.",
    notes:
      "OneGate injects the access token as a Bearer token for API calls (/api/v4/...) and as Basic oauth2:<token> for git over HTTPS. Self-managed GitLab is supported: set the connection's instance origin to your own https domain (e.g. https://gitlab.acme.example) and requests to that host use this connection's credential. The consent flow itself still runs against gitlab.com, so a self-managed connection needs its tokens supplied directly.",
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const token = await oauthBearerToken(gitlab, ctx.credential, ctx.store);
    if (ctx.path.startsWith("/api/")) {
      ctx.headers.authorization = `Bearer ${token}`;
    } else {
      ctx.headers.authorization = "Basic " + Buffer.from(`oauth2:${token}`).toString("base64");
    }
  },
};
