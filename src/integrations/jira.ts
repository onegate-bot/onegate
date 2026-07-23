/**
 * Jira / Atlassian Cloud integration. The account email and an Atlassian
 * API token are sent as HTTP Basic auth (email:token), which Jira and
 * Confluence Cloud REST APIs accept on every *.atlassian.net site.
 */

import type { Credential } from "../types.js";
import type { Integration, InjectionContext } from "./types.js";

/**
 * Normalizes a pasted Jira site URL to a bare https origin with no trailing
 * slash, e.g. "eli.atlassian.net" or "https://eli.atlassian.net/" become
 * "https://eli.atlassian.net". Returns null when nothing usable was given.
 */
export function normalizeSiteUrl(raw: string | undefined | null): string | null {
  const trimmed = (raw ?? "").trim();
  if (!trimmed) return null;
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const u = new URL(withScheme);
    if (!u.hostname) return null;
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

export const jira: Integration = {
  id: "jira",
  title: "Jira / Atlassian Cloud",
  hosts: [".atlassian.net", "api.atlassian.com"],
  category: "Productivity",
  credentialFields: [
    { key: "email", label: "Account email", secret: false },
    { key: "apiToken", label: "API token", secret: true },
    {
      key: "siteUrl",
      label: "Site URL",
      secret: false,
      optional: true,
    },
  ],
  llmHelp: {
    credentialType:
      "An Atlassian API token paired with the account email. OneGate sends them as HTTP Basic auth (email:token, base64 encoded), which Jira and Confluence Cloud accept.",
    whereToCreate:
      "https://id.atlassian.com/manage-profile/security/api-tokens (Atlassian account settings, then Security, then Create API token).",
    scopes: [
      "Classic API tokens carry the full permissions of the user account. Newer scoped API tokens can be restricted, grant Jira work item read and write scopes for typical agent use.",
    ],
    notes:
      'Fill "Account email" with the Atlassian account email and "API token" with the token. Set "Site URL" to your site, e.g. https://your-team.atlassian.net, so the agent can discover which site it reaches (one token covers every *.atlassian.net site the account belongs to). One credential covers Jira and Confluence on that site plus api.atlassian.com.',
  },
  /**
   * Non-secret account facts for the discovery endpoint. A single Atlassian
   * API token is host-agnostic, so OneGate cannot infer the site from the
   * credential alone, the operator records it as siteUrl. The agent needs the
   * site URL to build REST paths, which is exactly what #5438 reason 1 asked
   * for.
   */
  accountSummary(cred: Credential): Record<string, string | null> {
    const email = cred.data.email ? String(cred.data.email) : null;
    const siteUrl = normalizeSiteUrl(cred.data.siteUrl);
    return {
      email,
      siteUrl,
      apiBaseUrl: siteUrl ? `${siteUrl}/rest/api/3` : null,
    };
  },
  inject(ctx: InjectionContext): void {
    const { email, apiToken } = ctx.credential.data;
    if (!email || !apiToken) {
      throw new Error('Jira credential needs both "email" and "apiToken" fields');
    }
    const basic = Buffer.from(`${email}:${apiToken}`).toString("base64");
    ctx.headers.authorization = `Basic ${basic}`;
  },
};
