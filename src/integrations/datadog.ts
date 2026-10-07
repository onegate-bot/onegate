/**
 * Datadog API and application keys, injected as the DD-API-KEY and
 * DD-APPLICATION-KEY headers. Keys belong to one Datadog site (region), and
 * every site has its own API host, so the integration claims each site's
 * api.<site> host exactly. Intake hosts (logs, traces, RUM) are not claimed:
 * a Datadog agent or SDK running next to the AI agent keeps its own key and
 * passes through untouched.
 *
 * The required "site" field (the DD_SITE value, e.g. us5.datadoghq.com) is
 * reported to the agent through discovery and binds the keys to that site's
 * API host, so the keys never reach another region's host.
 */

import type { Credential } from "../types.js";
import type { Integration, InjectionContext } from "./types.js";

/** Every Datadog site, as the DD_SITE value. The API host is "api." + site. */
export const DATADOG_SITES = [
  "datadoghq.com",
  "us3.datadoghq.com",
  "us5.datadoghq.com",
  "datadoghq.eu",
  "ap1.datadoghq.com",
  "ap2.datadoghq.com",
  "uk1.datadoghq.com",
  "ddog-gov.com",
  "us2.ddog-gov.com",
] as const;

/** Datadog's short region names (as shown in the UI and docs) -> DD_SITE. */
const REGION_ALIASES: Record<string, string> = {
  us1: "datadoghq.com",
  us3: "us3.datadoghq.com",
  us5: "us5.datadoghq.com",
  eu: "datadoghq.eu",
  eu1: "datadoghq.eu",
  ap1: "ap1.datadoghq.com",
  ap2: "ap2.datadoghq.com",
  uk1: "uk1.datadoghq.com",
  "us1-fed": "ddog-gov.com",
  "us2-fed": "us2.ddog-gov.com",
};

/**
 * Normalizes a pasted site to a known DD_SITE value. Accepts the site
 * ("us5.datadoghq.com"), a site or API URL ("https://api.us5.datadoghq.com",
 * "https://app.datadoghq.eu"), a short region name ("us5", "EU") or nothing
 * (null, rejected by validateCredential and inject). Returns undefined for anything
 * that is not a Datadog site.
 */
export function normalizeDatadogSite(raw: string | undefined | null): string | null | undefined {
  let s = (raw ?? "").trim().toLowerCase();
  if (!s) return null;
  if (REGION_ALIASES[s]) return REGION_ALIASES[s];
  s = s.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  s = s.replace(/^(api|app)\./, "");
  return (DATADOG_SITES as readonly string[]).includes(s) ? s : undefined;
}

export const datadog: Integration = {
  id: "datadog",
  title: "Datadog",
  hosts: DATADOG_SITES.map((site) => `api.${site}`),
  category: "Developer",
  credentialFields: [
    { key: "apiKey", label: "API key", secret: true },
    { key: "appKey", label: "Application key", secret: true, optional: true },
    { key: "site", label: "Site (e.g. datadoghq.com, us5.datadoghq.com, datadoghq.eu, or us5, eu)", secret: false },
  ],
  connect: {
    method: "api_key",
    hint: "An API key plus an application key from the same organization, and your Datadog site. The keys are only sent to that site's API host.",
  },
  llmHelp: {
    credentialType:
      "A Datadog API key (organization-level) and an application key (user or service account level). OneGate sends them as the DD-API-KEY and DD-APPLICATION-KEY headers.",
    whereToCreate:
      "Datadog, then Organization Settings, then API Keys for the API key and Application Keys for the application key (or a service account's application key, preferred for agents).",
    scopes: [
      "Application keys can be scoped (e.g. monitors_read, metrics_read, logs_read_data, dashboards_read). Grant read scopes for observability agents and add write scopes only for automation that edits monitors or dashboards.",
      "Most read endpoints need both keys. Metric and event submission need only the API key.",
    ],
    notes:
      'Fill "Site" with your DD_SITE value: datadoghq.com (US1), us3.datadoghq.com, us5.datadoghq.com, datadoghq.eu (EU1), ap1.datadoghq.com, ap2.datadoghq.com, uk1.datadoghq.com, ddog-gov.com or us2.ddog-gov.com (short names like us5 or eu work too). The API base URL is https://api.<site>/api/.',
  },
  /** Requires a known site when the credential is saved, not at first use. */
  validateCredential(data: Record<string, string>): string | null {
    const site = normalizeDatadogSite(data.site);
    if (site === null) {
      return "data.site is required (your DD_SITE, e.g. datadoghq.com, us5.datadoghq.com, datadoghq.eu or us5, eu)";
    }
    if (site === undefined) {
      return `data.site "${data.site}" is not a Datadog site (use e.g. datadoghq.com, us5.datadoghq.com, datadoghq.eu or us5, eu)`;
    }
    return null;
  },
  /** The site tells the agent which regional API host its keys live on. */
  accountSummary(cred: Credential): Record<string, string | null> {
    const site = normalizeDatadogSite(cred.data.site) ?? null;
    return { site, apiBaseUrl: site ? `https://api.${site}` : null };
  },
  inject(ctx: InjectionContext): void {
    const { apiKey, appKey } = ctx.credential.data;
    if (!apiKey) throw new Error('Datadog credential has no "apiKey" field');
    const site = normalizeDatadogSite(ctx.credential.data.site);
    if (site === undefined) {
      throw new Error(`Datadog credential has an unknown site "${ctx.credential.data.site}"`);
    }
    // Keys belong to one site: never spray them across every regional host.
    if (!site) throw new Error('Datadog credential has no "site" field, set your DD_SITE');
    if (ctx.host.toLowerCase() !== `api.${site}`) {
      throw new Error(`Datadog credential is bound to api.${site}, refusing to authenticate ${ctx.host}`);
    }
    ctx.headers["dd-api-key"] = apiKey;
    if (appKey) ctx.headers["dd-application-key"] = appKey;
    else delete ctx.headers["dd-application-key"];
  },
};
