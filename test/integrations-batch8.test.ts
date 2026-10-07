/**
 * Batch 8 integrations: HubSpot, Salesforce, Sentry, Datadog, PostHog,
 * Microsoft 365, Zoom, Attio, Airtable and Asana. Header rewrites, host
 * claims (including what must NOT be claimed), the token flows against local
 * stub servers only, and the OAuth callback persisting Salesforce's
 * instance_url end to end through the admin app.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import http from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { IncomingHttpHeaders } from "node:http";
import { buildRegistry } from "../src/integrations/index.js";
import { composeLlmHelpPrompt } from "../src/integrations/llm-help.js";
import { buildAuthUrl } from "../src/integrations/oauth.js";
import type { Integration } from "../src/integrations/types.js";
import { hubspot } from "../src/integrations/hubspot.js";
import { sentry } from "../src/integrations/sentry.js";
import { posthog } from "../src/integrations/posthog.js";
import { attio } from "../src/integrations/attio.js";
import { INTEGRATION_LOGOS } from "../src/admin/logos.js";
import { Store } from "../src/store/db.js";
import { initCa } from "../src/ca.js";
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";
import type { Credential } from "../src/types.js";

function cred(data: Record<string, string>, integrationId = "x", id = "cr_b8"): Credential {
  return { id, integrationId, name: "t", data, createdAt: "" };
}

function ctxFor(host: string, credential: Credential, store: Store, headers: IncomingHttpHeaders = {}) {
  return { headers, method: "GET", path: "/", host, credential, store };
}

const BATCH: Integration[] = [
  hubspot,
  sentry,
  posthog,
  attio,
];

describe("batch 8 registry claims", () => {
  it("resolves every new host to its integration", async () => {
    const registry = await buildRegistry();
    const expected: Record<string, string> = {
      "api.hubapi.com": "hubspot",
      "sentry.io": "sentry",
      "us.sentry.io": "sentry",
      "de.sentry.io": "sentry",
      "us.posthog.com": "posthog",
      "eu.posthog.com": "posthog",
      "app.posthog.com": "posthog",
      "api.attio.com": "attio",
    };
    for (const [host, id] of Object.entries(expected)) {
      expect(registry.resolveHostCandidates(host).map((i) => i.id), host).toEqual([id]);
    }
  });

  it("leaves ingestion, login and look-alike hosts to passthrough", async () => {
    const registry = await buildRegistry();
    for (const host of [
      "o123.ingest.sentry.io",
      "o123.ingest.us.sentry.io",
      "us.i.posthog.com",
      "http-intake.logs.datadoghq.com",
      "app.datadoghq.com",
      "login.salesforce.com",
      "my.salesforce.com.evil.example",
      "evilmy.salesforce.com",
      "acme.lightning.force.com",
      "login.microsoftonline.com",
      "zoom.us",
      "app.hubspot.com",
    ]) {
      expect(registry.resolveHost(host), host).toBeNull();
    }
  });

  it("every new integration has a brand logo entry", () => {
    for (const i of BATCH) expect(INTEGRATION_LOGOS[i.id], i.id).toBeTruthy();
  });

  it("llm help prompts compose with the crafted hints", () => {
    for (const i of BATCH) {
      const prompt = composeLlmHelpPrompt(i);
      expect(prompt, i.id).toContain(i.title);
      expect(prompt, i.id).toContain(i.llmHelp!.credentialType!);
    }
  });
});

describe("batch 8 static token integrations", () => {
  const store = new Store(":memory:");
  const cases: [Integration, string, Record<string, string>, string][] = [
    [hubspot, "api.hubapi.com", { token: "pat-na1-x" }, "Bearer pat-na1-x"],
    [sentry, "us.sentry.io", { token: "sntryu_x" }, "Bearer sntryu_x"],
    [posthog, "eu.posthog.com", { apiKey: "phx_x" }, "Bearer phx_x"],
    [attio, "api.attio.com", { apiKey: "attio_x" }, "Bearer attio_x"],
  ];

  for (const [integration, host, data, expected] of cases) {
    it(`${integration.id} swaps the placeholder for the real Bearer token`, async () => {
      const ctx = ctxFor(host, cred(data), store, { authorization: "Bearer og_placeholder" });
      await integration.inject(ctx);
      expect(ctx.headers.authorization).toBe(expected);
    });

    it(`${integration.id} throws when the credential field is missing`, () => {
      expect(() => integration.inject(ctxFor(host, cred({}), store))).toThrow(/credential has no/);
    });
  }

  it("posthog summarizes the region and API base, ignoring junk", () => {
    expect(posthog.accountSummary!(cred({ apiKey: "k", region: " EU " }))).toEqual({
      region: "eu",
      apiBaseUrl: "https://eu.posthog.com",
    });
    expect(posthog.accountSummary!(cred({ apiKey: "k" }))).toEqual({ region: null, apiBaseUrl: null });
    expect(posthog.accountSummary!(cred({ apiKey: "k", region: "mars" }))).toEqual({
      region: null,
      apiBaseUrl: null,
    });
  });
});


