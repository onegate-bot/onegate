/**
 * PostHog Cloud personal API key, injected as Bearer on the private API
 * hosts (US, EU and the legacy app. host). Event ingestion hosts
 * (us.i.posthog.com, eu.i.posthog.com) take the public project key in the
 * request body, nothing to inject there, so they are not claimed and SDK
 * capture traffic passes through untouched.
 */

import type { Credential } from "../types.js";
import type { Integration, InjectionContext } from "./types.js";

/** Hosts serving each region. app.posthog.com is the legacy US host. */
const REGION_HOSTS: Record<"us" | "eu", string[]> = {
  us: ["us.posthog.com", "app.posthog.com"],
  eu: ["eu.posthog.com"],
};

function posthogRegion(raw: string | undefined): "us" | "eu" | null {
  const region = String(raw ?? "").trim().toLowerCase();
  return region === "us" || region === "eu" ? region : null;
}

export const posthog: Integration = {
  id: "posthog",
  title: "PostHog",
  hosts: ["us.posthog.com", "eu.posthog.com", "app.posthog.com"],
  category: "Developer",
  credentialFields: [
    { key: "apiKey", label: "Personal API key", secret: true },
    { key: "region", label: "Region (us or eu)", secret: false, optional: true },
  ],
  connect: {
    method: "api_key",
    hint: "A personal API key (phx_...). Project keys (phc_) are public ingestion keys and cannot read data.",
  },
  llmHelp: {
    credentialType:
      "A PostHog personal API key (starts with phx_). OneGate sends it as a Bearer token on the PostHog Cloud API hosts.",
    whereToCreate:
      "PostHog, then Settings, then User, then Personal API keys (https://us.posthog.com/settings/user-api-keys, or eu.posthog.com for EU Cloud).",
    scopes: [
      "Personal API keys are scoped per resource (query:read, insight:read, feature_flag:write, ...) and can be limited to specific projects or organizations. Grant only what the agent needs.",
    ],
    notes:
      'Fill "Region" with us or eu so the agent knows which host to call (https://us.posthog.com or https://eu.posthog.com), OneGate then refuses the other region. Endpoints live under /api/projects/<project_id>/. Event capture uses the public project key and is not routed through OneGate.',
  },
  /** A typo like "europe" would silently leave the key unbound, reject it at save time. */
  validateCredential(data: Record<string, string>): string | null {
    const raw = (data.region ?? "").trim();
    return raw && !posthogRegion(raw) ? `data.region "${data.region}" must be us or eu` : null;
  },
  /** The region tells the agent which API host its key lives on. */
  accountSummary(cred: Credential): Record<string, string | null> {
    const region = posthogRegion(cred.data.region);
    if (!region) return { region: null, apiBaseUrl: null };
    return { region, apiBaseUrl: `https://${region}.posthog.com` };
  },
  inject(ctx: InjectionContext): void {
    const apiKey = ctx.credential.data.apiKey;
    if (!apiKey) throw new Error('PostHog credential has no "apiKey" field');
    // A key lives in one region. When the operator recorded it, refuse the
    // other region's hosts so the key never travels there.
    const region = posthogRegion(ctx.credential.data.region);
    if (region && !REGION_HOSTS[region].includes(ctx.host.toLowerCase())) {
      throw new Error(`PostHog credential is bound to the ${region} region, refusing to authenticate ${ctx.host}`);
    }
    ctx.headers.authorization = `Bearer ${apiKey}`;
  },
};
