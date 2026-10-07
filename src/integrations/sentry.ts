/**
 * Sentry (sentry.io SaaS) auth token, injected as Bearer. Covers the
 * main API host plus the US and EU data-residency hosts. Event ingestion
 * (*.ingest.sentry.io, authenticated by the public DSN) is deliberately NOT
 * claimed, so an agent's own error reporting keeps passing through untouched.
 */

import type { Integration, InjectionContext } from "./types.js";

export const sentry: Integration = {
  id: "sentry",
  title: "Sentry",
  hosts: ["sentry.io", "us.sentry.io", "de.sentry.io"],
  category: "Developer",
  credentialFields: [{ key: "token", label: "Auth token", secret: true }],
  connect: {
    method: "api_key",
    hint: "An organization auth token or a personal (user) auth token. It works on sentry.io and the regional us./de. hosts.",
  },
  llmHelp: {
    credentialType:
      "A Sentry auth token: an organization token (starts with sntrys_) or a personal user auth token (starts with sntryu_). OneGate sends it as a Bearer token.",
    whereToCreate:
      "Organization tokens: Sentry Settings, then Developer Settings, then Organization Tokens. Personal tokens: User settings, then Personal Tokens (https://sentry.io/settings/account/api/auth-tokens/).",
    scopes: [
      "Personal tokens take explicit scopes: grant org:read, project:read and event:read for read-only triage, add event:write to resolve or assign issues and project:releases for release automation.",
      "Organization tokens carry a fixed release/source-map scope set, use a personal token when the agent must read issues.",
    ],
    notes:
      "The REST API lives under /api/0/. Data-residency organizations answer on their region host (us.sentry.io or de.sentry.io), the same token works there. Self-hosted Sentry is not covered, write a community integration with your instance host.",
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.token;
    if (!token) throw new Error('Sentry credential has no "token" field');
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
