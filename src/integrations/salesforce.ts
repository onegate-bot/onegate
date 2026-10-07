/**
 * Salesforce via a bring-your-own External Client App (or Connected App),
 * standard authorization-code flow against login.salesforce.com. Every org
 * answers on its own My Domain host (acme.my.salesforce.com), which the token
 * response reports as instance_url. The connect flow persists it as
 * instanceUrl and inject binds the token to that exact host.
 *
 * Why the binding matters: the host claim is the `.my.salesforce.com`
 * suffix, and anyone can sign up for a free Developer Edition org and pick a
 * My Domain under it. Without the binding a policy allowing the suffix would
 * let a request to someone else's org carry this org's token.
 *
 * Salesforce token responses carry no expires_in (the lifetime follows the
 * org's session timeout, minimum 15 minutes), so the descriptor assumes ten
 * minutes and the engine refreshes ahead of any org's expiry.
 */

import type { Credential } from "../types.js";
import type { Integration, InjectionContext } from "./types.js";
import { oauthBearerToken } from "./oauth.js";

/** My Domain hosts: production, sandbox (*.sandbox.my...) and partitioned (develop., scratch., ...). */
const INSTANCE_HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)*\.my\.salesforce\.com$/;

/**
 * The org host a Salesforce credential is bound to, from its stored
 * instanceUrl, or null when the value is missing or is anything but a bare
 * https My Domain origin.
 */
export function salesforceInstanceHost(raw: string | undefined | null): string | null {
  if (!raw) return null;
  let u: URL;
  try {
    u = new URL(String(raw).trim());
  } catch {
    return null;
  }
  if (u.protocol !== "https:" || u.username || u.password || u.port || u.search || u.hash) return null;
  if (u.pathname !== "/" && u.pathname !== "") return null;
  const host = u.hostname.toLowerCase();
  return INSTANCE_HOST.test(host) ? host : null;
}

export const salesforce: Integration = {
  id: "salesforce",
  title: "Salesforce",
  hosts: [".my.salesforce.com"],
  category: "CRM",
  credentialFields: [
    { key: "clientId", label: "Consumer key", secret: false },
    { key: "clientSecret", label: "Consumer secret", secret: true },
    { key: "accessToken", label: "Access token (set by the connect flow)", secret: true },
    { key: "refreshToken", label: "Refresh token (set by the connect flow)", secret: true, optional: true },
    { key: "instanceUrl", label: "Instance URL (set by the connect flow)", secret: false },
  ],
  connect: {
    method: "oauth",
    hint: "Use the consumer key and secret of an External Client App (or Connected App) with OAuth enabled. Production and Developer Edition orgs only.",
  },
  oauth: {
    authUrl: "https://login.salesforce.com/services/oauth2/authorize",
    tokenUrl: "https://login.salesforce.com/services/oauth2/token",
    defaultScopes: ["api", "refresh_token"],
    permissions: [
      { scope: "api", name: "CRM data", description: "Read and write records, queries and metadata, limited to what the connecting user may do", access: "write" },
      { scope: "refresh_token", name: "Offline access", description: "Keep the connection working without re-authorizing", access: "read" },
    ],
    persistTokenFields: { instance_url: "instanceUrl" },
    defaultExpiresIn: 600,
  },
  connectGuide: {
    consoleUrl: "https://login.salesforce.com/lightning/setup/ManageExternalClientApplication/home",
    steps: [
      "In Salesforce Setup, open External Client App Manager and click New External Client App (or use App Manager, New Connected App, on orgs that still allow it).",
      "Enable OAuth. Add the redirect URI shown at the top of this page as the callback URL.",
      "Select the OAuth scopes \"Manage user data via APIs (api)\" and \"Perform requests at any time (refresh_token, offline_access)\".",
      "Untick \"Require Proof Key for Code Exchange (PKCE)\": OneGate's OAuth engine does not send a PKCE challenge yet. Keep \"Require secret for Web Server Flow\" ticked.",
      "Save, then open the app's consumer details and copy the Consumer Key and Consumer Secret into the fields below.",
    ],
  },
  llmHelp: {
    credentialType:
      "A Salesforce External Client App's consumer key and secret. OneGate runs the web-server OAuth flow against login.salesforce.com, stores the refresh token and the org's instance URL, and injects short-lived access tokens as Bearer only on that instance host.",
    whereToCreate:
      "Salesforce Setup, External Client App Manager, New External Client App (or App Manager, New Connected App). Enable OAuth, set the callback URL to the redirect URI shown in the OneGate connect dialog, and add the api and refresh_token scopes.",
    scopes: [
      "api gives REST and SOQL access bounded by the connecting user's profile and permission sets, refresh_token lets OneGate renew access. Connect with a dedicated integration user whose permissions match the agent's job.",
      "Untick Require PKCE on the app (OneGate does not send a PKCE challenge yet).",
    ],
    notes:
      "Discovery reports the org's instanceUrl. The REST API lives under <instanceUrl>/services/data/vXX.X/ (e.g. /services/data/v62.0/query?q=...). Sandboxes (test.salesforce.com login) are not supported yet.",
  },
  accountSummary(cred: Credential): Record<string, string | null> {
    const host = salesforceInstanceHost(cred.data.instanceUrl);
    const instanceUrl = host ? `https://${host}` : null;
    return { instanceUrl, apiBaseUrl: instanceUrl ? `${instanceUrl}/services/data` : null };
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const host = salesforceInstanceHost(ctx.credential.data.instanceUrl);
    if (!host) {
      throw new Error(
        'Salesforce credential has no valid "instanceUrl" (https://<domain>.my.salesforce.com), reconnect it',
      );
    }
    if (ctx.host.toLowerCase() !== host) {
      throw new Error(`Salesforce credential is bound to ${host}, refusing to authenticate ${ctx.host}`);
    }
    const token = await oauthBearerToken(salesforce, ctx.credential, ctx.store);
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
