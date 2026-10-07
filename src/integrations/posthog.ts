/**
 * PostHog Cloud personal API key, injected as Bearer on the private API
 * hosts (US, EU and the legacy app. host). Event ingestion hosts
 * (us.i.posthog.com, eu.i.posthog.com) take the public project key in the
 * request body, nothing to inject there, so they are not claimed and SDK
 * capture traffic passes through untouched.
 */

import type { Credential } from "../types.js";
import type { Integration, InjectionContext } from "./types.js";

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
      'Fill "Region" with us or eu so the agent knows which host to call (https://us.posthog.com or https://eu.posthog.com). Endpoints live under /api/projects/<project_id>/. Event capture uses the public project key and is not routed through OneGate.',
  },
  /** The region tells the agent which API host its key lives on. */
  accountSummary(cred: Credential): Record<string, string | null> {
    const region = String(cred.data.region ?? "").trim().toLowerCase();
    if (region !== "us" && region !== "eu") return { region: null, apiBaseUrl: null };
    return { region, apiBaseUrl: `https://${region}.posthog.com` };
  },
  inject(ctx: InjectionContext): void {
    const apiKey = ctx.credential.data.apiKey;
    if (!apiKey) throw new Error('PostHog credential has no "apiKey" field');
    ctx.headers.authorization = `Bearer ${apiKey}`;
  },
};
