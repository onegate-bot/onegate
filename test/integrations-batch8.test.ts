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
import { salesforce, salesforceInstanceHost } from "../src/integrations/salesforce.js";
import { sentry } from "../src/integrations/sentry.js";
import { datadog, normalizeDatadogSite, DATADOG_SITES } from "../src/integrations/datadog.js";
import { posthog } from "../src/integrations/posthog.js";
import { microsoft, MICROSOFT_APPS } from "../src/integrations/microsoft.js";
import { zoom } from "../src/integrations/zoom.js";
import { attio } from "../src/integrations/attio.js";
import { airtable } from "../src/integrations/airtable.js";
import { asana } from "../src/integrations/asana.js";
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
  salesforce,
  sentry,
  datadog,
  posthog,
  microsoft,
  zoom,
  attio,
  airtable,
  asana,
];

describe("batch 8 registry claims", () => {
  it("resolves every new host to its integration", async () => {
    const registry = await buildRegistry();
    const expected: Record<string, string> = {
      "api.hubapi.com": "hubspot",
      "acme.my.salesforce.com": "salesforce",
      "acme--dev.sandbox.my.salesforce.com": "salesforce",
      "sentry.io": "sentry",
      "us.sentry.io": "sentry",
      "de.sentry.io": "sentry",
      "api.datadoghq.com": "datadog",
      "api.us3.datadoghq.com": "datadog",
      "api.us5.datadoghq.com": "datadog",
      "api.datadoghq.eu": "datadog",
      "api.ap1.datadoghq.com": "datadog",
      "api.ddog-gov.com": "datadog",
      "us.posthog.com": "posthog",
      "eu.posthog.com": "posthog",
      "app.posthog.com": "posthog",
      "graph.microsoft.com": "microsoft",
      "api.zoom.us": "zoom",
      "api.attio.com": "attio",
      "api.airtable.com": "airtable",
      "content.airtable.com": "airtable",
      "app.asana.com": "asana",
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
    [posthog, "eu.posthog.com", { apiKey: "phx_x", region: "eu" }, "Bearer phx_x"],
    [attio, "api.attio.com", { apiKey: "attio_x" }, "Bearer attio_x"],
    [airtable, "content.airtable.com", { token: "patX.y" }, "Bearer patX.y"],
    [asana, "app.asana.com", { token: "2/123/456:abc" }, "Bearer 2/123/456:abc"],
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

  it("posthog binds the key to its recorded region", async () => {
    const eu = cred({ apiKey: "phx_x", region: "eu" });
    const ok = ctxFor("EU.posthog.com", eu, store);
    await posthog.inject(ok);
    expect(ok.headers.authorization).toBe("Bearer phx_x");
    for (const host of ["us.posthog.com", "app.posthog.com"]) {
      const ctx = ctxFor(host, eu, store);
      expect(() => posthog.inject(ctx)).toThrow(/bound to the eu region/);
      expect(ctx.headers.authorization).toBeUndefined();
    }
    const us = cred({ apiKey: "phx_x", region: "us" });
    for (const host of ["us.posthog.com", "app.posthog.com"]) posthog.inject(ctxFor(host, us, store));
    expect(() => posthog.inject(ctxFor("eu.posthog.com", us, store))).toThrow(/bound to the us region/);
  });

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

describe("datadog integration", () => {
  const store = new Store(":memory:");

  it("injects DD-API-KEY and DD-APPLICATION-KEY over agent placeholders", () => {
    const ctx = ctxFor("api.datadoghq.com", cred({ apiKey: "ddapi", appKey: "ddapp", site: "datadoghq.com" }), store, {
      "dd-api-key": "placeholder",
      "dd-application-key": "placeholder",
    });
    datadog.inject(ctx);
    expect(ctx.headers["dd-api-key"]).toBe("ddapi");
    expect(ctx.headers["dd-application-key"]).toBe("ddapp");
  });

  it("drops an agent-sent application key placeholder when none is stored", () => {
    const ctx = ctxFor("api.datadoghq.com", cred({ apiKey: "ddapi", site: "datadoghq.com" }), store, {
      "dd-application-key": "placeholder",
    });
    datadog.inject(ctx);
    expect(ctx.headers["dd-api-key"]).toBe("ddapi");
    expect(ctx.headers["dd-application-key"]).toBeUndefined();
  });

  it("binds the keys to the configured site's API host", () => {
    const c = cred({ apiKey: "ddapi", appKey: "ddapp", site: "us5.datadoghq.com" });
    const ok = ctxFor("api.us5.datadoghq.com", c, store);
    datadog.inject(ok);
    expect(ok.headers["dd-api-key"]).toBe("ddapi");
    const other = ctxFor("api.datadoghq.eu", c, store);
    expect(() => datadog.inject(other)).toThrow(/bound to api\.us5\.datadoghq\.com/);
    expect(other.headers["dd-api-key"]).toBeUndefined();
  });

  it("rejects an unknown site and a missing API key", () => {
    expect(() =>
      datadog.inject(ctxFor("api.datadoghq.com", cred({ apiKey: "k", site: "evil.example" }), store)),
    ).toThrow(/unknown site/);
    expect(() => datadog.inject(ctxFor("api.datadoghq.com", cred({ appKey: "x" }), store))).toThrow(/apiKey/);
  });

  it("accepts short region names and rejects unknown sites at connect time", () => {
    expect(normalizeDatadogSite("us5")).toBe("us5.datadoghq.com");
    expect(normalizeDatadogSite(" EU ")).toBe("datadoghq.eu");
    expect(normalizeDatadogSite("US1-FED")).toBe("ddog-gov.com");
    expect(datadog.validateCredential!({ apiKey: "k", site: "US5" })).toBeNull();
    expect(datadog.validateCredential!({ apiKey: "k" })).toMatch(/site is required/);
    expect(datadog.validateCredential!({ apiKey: "k", site: "  " })).toMatch(/site is required/);
    // Saved without a site some other way, inject still refuses to spray the keys.
    expect(() => datadog.inject(ctxFor("api.datadoghq.com", cred({ apiKey: "k" }), store))).toThrow(/no "site"/);
    expect(datadog.validateCredential!({ apiKey: "k", site: "us9" })).toMatch(/not a Datadog site/);
    const ctx = ctxFor("api.us5.datadoghq.com", cred({ apiKey: "k", site: "us5" }), store);
    datadog.inject(ctx);
    expect(ctx.headers["dd-api-key"]).toBe("k");
  });

  it("normalizes pasted sites and URLs", () => {
    expect(normalizeDatadogSite("")).toBeNull();
    expect(normalizeDatadogSite(undefined)).toBeNull();
    expect(normalizeDatadogSite("US3.datadoghq.com")).toBe("us3.datadoghq.com");
    expect(normalizeDatadogSite("https://app.datadoghq.eu/dashboard")).toBe("datadoghq.eu");
    expect(normalizeDatadogSite("https://api.ap1.datadoghq.com")).toBe("ap1.datadoghq.com");
    expect(normalizeDatadogSite("datadoghq.com.evil.example")).toBeUndefined();
  });

  it("claims exactly one API host per site", () => {
    expect(datadog.hosts).toEqual(DATADOG_SITES.map((s) => `api.${s}`));
  });

  it("summarizes the site for discovery", () => {
    expect(datadog.accountSummary!(cred({ apiKey: "k", site: "datadoghq.eu" }))).toEqual({
      site: "datadoghq.eu",
      apiBaseUrl: "https://api.datadoghq.eu",
    });
    expect(datadog.accountSummary!(cred({ apiKey: "k", site: "nope" }))).toEqual({ site: null, apiBaseUrl: null });
  });
});

describe("token flows against a local stub (zoom, salesforce, microsoft)", () => {
  let server: http.Server;
  let store: Store;
  let zoomGrants = 0;
  let sfRefreshes = 0;
  let sfInstance = "https://acme.my.salesforce.com";
  let msRefreshes = 0;
  let lastZoom: { auth: string; params: URLSearchParams } | null = null;
  let onZoomMint: () => void = () => {};
  let lastMs: URLSearchParams | null = null;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const params = new URLSearchParams(body);
        const json = (status: number, payload: unknown) => {
          res.writeHead(status, { "content-type": "application/json" });
          res.end(JSON.stringify(payload));
        };
        if (req.url === "/zoom/token") {
          zoomGrants++;
          onZoomMint();
          lastZoom = { auth: req.headers.authorization ?? "", params };
          if (lastZoom.auth !== "Basic " + Buffer.from("zcid:zsecret").toString("base64")) {
            json(401, { reason: "Invalid client_id or client_secret", error: "invalid_client" });
            return;
          }
          json(200, { access_token: `zoom_at_${zoomGrants}`, token_type: "bearer", expires_in: 3599 });
          return;
        }
        if (req.url === "/sf/token") {
          sfRefreshes++;
          // Salesforce omits expires_in on purpose.
          json(200, {
            access_token: `sf_at_${sfRefreshes}`,
            instance_url: sfInstance,
            token_type: "Bearer",
          });
          return;
        }
        if (req.url === "/ms/token") {
          msRefreshes++;
          lastMs = params;
          json(200, {
            access_token: `ms_at_${msRefreshes}`,
            refresh_token: `ms_rt_${msRefreshes}`,
            expires_in: 3600,
            token_type: "Bearer",
          });
          return;
        }
        res.writeHead(404).end();
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    process.env.ONEGATE_OAUTH_TOKEN_URL_ZOOM = `http://127.0.0.1:${port}/zoom/token`;
    process.env.ONEGATE_OAUTH_TOKEN_URL_SALESFORCE = `http://127.0.0.1:${port}/sf/token`;
    process.env.ONEGATE_OAUTH_TOKEN_URL_MICROSOFT = `http://127.0.0.1:${port}/ms/token`;
  });

  afterAll(() => {
    server.close();
    delete process.env.ONEGATE_OAUTH_TOKEN_URL_ZOOM;
    delete process.env.ONEGATE_OAUTH_TOKEN_URL_SALESFORCE;
    delete process.env.ONEGATE_OAUTH_TOKEN_URL_MICROSOFT;
  });

  beforeEach(() => {
    store = new Store(":memory:");
    zoomGrants = 0;
    sfRefreshes = 0;
    sfInstance = "https://acme.my.salesforce.com";
    msRefreshes = 0;
    lastZoom = null;
    onZoomMint = () => {};
    lastMs = null;
  });

  it("zoom mints an account_credentials token with Basic auth, injects Bearer and caches", async () => {
    const c = store.setCredential("zoom", "t", { accountId: "acct_1", clientId: "zcid", clientSecret: "zsecret" });
    const ctx1 = ctxFor("api.zoom.us", c, store, { authorization: "Bearer og_placeholder" });
    await zoom.inject(ctx1);
    const ctx2 = ctxFor("api.zoom.us", c, store);
    await zoom.inject(ctx2);
    expect(ctx1.headers.authorization).toBe("Bearer zoom_at_1");
    expect(ctx2.headers.authorization).toBe("Bearer zoom_at_1");
    expect(zoomGrants).toBe(1);
    expect(lastZoom!.params.get("grant_type")).toBe("account_credentials");
    expect(lastZoom!.params.get("account_id")).toBe("acct_1");
    // Client credentials ride in the Basic header, never the body.
    expect(lastZoom!.params.has("client_secret")).toBe(false);
  });

  it("zoom does not cache a token minted for a connection deleted mid-request", async () => {
    const conn = store.createConnection({
      kind: "app",
      vendor: "zoom",
      name: "zoom-work",
      data: { accountId: "acct_1", clientId: "zcid", clientSecret: "zsecret" },
    });
    onZoomMint = () => store.deleteConnection(conn.id);
    const c = { id: conn.id, integrationId: "zoom", name: conn.name, data: { ...conn.data }, createdAt: "" };
    await zoom.inject(ctxFor("api.zoom.us", c, store));
    expect(store.getSecretSetting(`oauth_access_token:zoom:${conn.id}`)).toBeNull();
    expect(store.getCredential("zoom")).toBeNull();
  });

  it("zoom does not cache a token minted for an account edited mid-request", async () => {
    const c = store.setCredential("zoom", "t", { accountId: "acct_1", clientId: "zcid", clientSecret: "zsecret" });
    onZoomMint = () => store.setCredential("zoom", "t", { accountId: "acct_2", clientId: "zcid", clientSecret: "zsecret" });
    await zoom.inject(ctxFor("api.zoom.us", c, store));
    expect(store.getSecretSetting(`oauth_access_token:zoom:${c.id}`)).toBeNull();
    expect(store.getCredential("zoom")!.data.accountId).toBe("acct_2");
  });

  it("zoom re-mints after the account ID is edited instead of reusing the old account's token", async () => {
    store.setCredential("zoom", "t", { accountId: "acct_1", clientId: "zcid", clientSecret: "zsecret" });
    await zoom.inject(ctxFor("api.zoom.us", store.getCredential("zoom")!, store));
    store.setCredential("zoom", "t", { accountId: "acct_2", clientId: "zcid", clientSecret: "zsecret" });
    const ctx = ctxFor("api.zoom.us", store.getCredential("zoom")!, store);
    await zoom.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer zoom_at_2");
    expect(lastZoom!.params.get("account_id")).toBe("acct_2");
  });

  it("zoom surfaces vendor rejections and requires an account id", async () => {
    const bad = cred({ accountId: "acct_1", clientId: "zcid", clientSecret: "wrong" }, "zoom");
    await expect(zoom.inject(ctxFor("api.zoom.us", bad, store))).rejects.toThrow(
      /account_credentials grant failed \(401\)/,
    );
    const noAcct = cred({ clientId: "zcid", clientSecret: "zsecret" }, "zoom");
    await expect(zoom.inject(ctxFor("api.zoom.us", noAcct, store))).rejects.toThrow(/accountId/);
    expect(zoom.accountSummary!(cred({ accountId: "acct_1" }))).toEqual({ accountId: "acct_1" });
    expect(zoom.accountSummary!(cred({}))).toEqual({ accountId: null });
  });

  it("salesforce refreshes, injects Bearer on its own instance and assumes a short lifetime", async () => {
    const c = store.setCredential("salesforce", "Salesforce OAuth", {
      clientId: "sfid",
      clientSecret: "sfsec",
      refreshToken: "sf_rt",
      instanceUrl: "https://acme.my.salesforce.com",
    });
    const ctx = ctxFor("acme.my.salesforce.com", c, store, { authorization: "Bearer og_placeholder" });
    await salesforce.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer sf_at_1");
    const cached = store.getSecretSetting<{ token: string; exp: number }>(
      `oauth_access_token:salesforce:${c.id}`,
    )!;
    // No expires_in in the response: the descriptor's 600 s default applies, not 3600.
    expect(cached.exp - Date.now()).toBeLessThanOrEqual(600_000);
    expect(cached.exp - Date.now()).toBeGreaterThan(590_000);
    await salesforce.inject(ctxFor("acme.my.salesforce.com", c, store));
    expect(sfRefreshes).toBe(1);
  });

  it("salesforce re-persists a changed instance_url on refresh and rebinds to the new host", async () => {
    sfInstance = "https://acme-renamed.my.salesforce.com";
    const c = store.setCredential("salesforce", "Salesforce OAuth", {
      clientId: "sfid",
      clientSecret: "sfsec",
      refreshToken: "sf_rt",
      instanceUrl: "https://acme.my.salesforce.com",
    });
    await salesforce.inject(ctxFor("acme.my.salesforce.com", c, store));
    const reloaded = store.getCredential("salesforce")!;
    expect(reloaded.data.instanceUrl).toBe("https://acme-renamed.my.salesforce.com");
    expect(reloaded.data.refreshToken).toBe("sf_rt");
    const moved = ctxFor("acme-renamed.my.salesforce.com", reloaded, store);
    await salesforce.inject(moved);
    expect(moved.headers.authorization).toBe("Bearer sf_at_1");
    await expect(salesforce.inject(ctxFor("acme.my.salesforce.com", reloaded, store))).rejects.toThrow(
      /bound to acme-renamed\.my\.salesforce\.com/,
    );
  });

  it("salesforce persists a changed instance_url onto a named connection", async () => {
    sfInstance = "https://acme-renamed.my.salesforce.com";
    const conn = store.createConnection({
      kind: "app",
      vendor: "salesforce",
      name: "sf-work",
      data: { clientId: "sfid", clientSecret: "sfsec", refreshToken: "sf_rt", instanceUrl: "https://acme.my.salesforce.com" },
    });
    const c = cred({ ...conn.data }, "salesforce", conn.id);
    await salesforce.inject(ctxFor("acme.my.salesforce.com", c, store));
    expect(store.getConnection(conn.id)!.data.instanceUrl).toBe("https://acme-renamed.my.salesforce.com");
    expect(store.getCredential("salesforce")).toBeNull();
  });

  it("salesforce refuses any other org, even under the claimed suffix, before minting a token", async () => {
    const c = cred(
      { clientId: "sfid", clientSecret: "sfsec", refreshToken: "sf_rt", instanceUrl: "https://acme.my.salesforce.com" },
      "salesforce",
    );
    const ctx = ctxFor("attacker.my.salesforce.com", c, store);
    await expect(salesforce.inject(ctx)).rejects.toThrow(/bound to acme\.my\.salesforce\.com/);
    expect(ctx.headers.authorization).toBeUndefined();
    expect(sfRefreshes).toBe(0);
  });

  it("salesforce refuses a credential without a valid instance URL", async () => {
    for (const instanceUrl of ["", "https://evil.example", "http://acme.my.salesforce.com"]) {
      const c = cred({ accessToken: "at", instanceUrl }, "salesforce");
      await expect(salesforce.inject(ctxFor("acme.my.salesforce.com", c, store))).rejects.toThrow(
        /no valid "instanceUrl"/,
      );
    }
  });

  it("salesforce validates instance URLs strictly", () => {
    expect(salesforceInstanceHost("https://acme.my.salesforce.com")).toBe("acme.my.salesforce.com");
    expect(salesforceInstanceHost("https://ACME.my.salesforce.com/")).toBe("acme.my.salesforce.com");
    expect(salesforceInstanceHost("https://acme--dev.sandbox.my.salesforce.com")).toBe(
      "acme--dev.sandbox.my.salesforce.com",
    );
    for (const bad of [
      undefined,
      "",
      "not a url",
      "acme.my.salesforce.com",
      "http://acme.my.salesforce.com",
      "https://acme.my.salesforce.com:8443",
      "https://user:pw@acme.my.salesforce.com",
      "https://acme.my.salesforce.com/services",
      "https://acme.my.salesforce.com/?x=1",
      "https://acme.my.salesforce.com/#x",
      "https://my.salesforce.com",
      "https://acme.my.salesforce.com.evil.example",
      "https://acme.salesforce.com",
    ]) {
      expect(salesforceInstanceHost(bad), String(bad)).toBeNull();
    }
  });

  it("salesforce summarizes the instance URL for discovery", () => {
    expect(salesforce.accountSummary!(cred({ instanceUrl: "https://acme.my.salesforce.com" }))).toEqual({
      instanceUrl: "https://acme.my.salesforce.com",
      apiBaseUrl: "https://acme.my.salesforce.com/services/data",
    });
    expect(salesforce.accountSummary!(cred({}))).toEqual({ instanceUrl: null, apiBaseUrl: null });
  });

  it("microsoft refreshes against the token endpoint and persists the rotated refresh token", async () => {
    const c = store.setCredential("microsoft", "Microsoft 365 OAuth", {
      clientId: "mscid",
      clientSecret: "mssec",
      refreshToken: "ms_rt_0",
    });
    const ctx = ctxFor("graph.microsoft.com", c, store, { authorization: "Bearer og_placeholder" });
    await microsoft.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer ms_at_1");
    expect(lastMs!.get("grant_type")).toBe("refresh_token");
    expect(lastMs!.get("refresh_token")).toBe("ms_rt_0");
    expect(lastMs!.get("client_id")).toBe("mscid");
    expect(store.getCredential("microsoft")!.data.refreshToken).toBe("ms_rt_1");
    await microsoft.inject(ctxFor("graph.microsoft.com", c, store));
    expect(msRefreshes).toBe(1);
  });

  it("microsoft builds a common-tenant consent URL and every scope pack asks for offline access", () => {
    const u = new URL(
      buildAuthUrl("microsoft", microsoft.oauth!, {
        clientId: "mscid",
        redirectUri: "https://gw.example/oauth/microsoft/callback",
        scopes: microsoft.oauth!.defaultScopes,
        state: "st",
      }),
    );
    expect(u.origin + u.pathname).toBe("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
    const scopes = u.searchParams.get("scope")!.split(" ");
    expect(scopes).toEqual(expect.arrayContaining(["offline_access", "User.Read", "Mail.ReadWrite", "Calendars.ReadWrite", "Files.ReadWrite"]));
    expect(new Set(scopes).size).toBe(scopes.length);
    expect(scopes).not.toContain("Notes.ReadWrite");
    for (const pack of MICROSOFT_APPS) expect(pack.scopes, pack.id).toContain("offline_access");
  });
});

describe("OAuth callback persists Salesforce's instance_url (admin app, stub token endpoint)", () => {
  let dir: string;
  let store: Store;
  let server: http.Server;
  let tokenServer: http.Server;
  let port: number;
  let adminToken: string;
  let tokenBody: Record<string, unknown>;

  function request(
    method: string,
    path: string,
    body?: unknown,
    auth = true,
  ): Promise<{ status: number; text: string }> {
    return new Promise((resolve, reject) => {
      const payload = body === undefined ? null : JSON.stringify(body);
      const req = http.request(
        {
          host: "127.0.0.1",
          port,
          method,
          path,
          agent: false,
          headers: {
            ...(payload ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } : {}),
            ...(auth ? { authorization: `Bearer ${adminToken}` } : {}),
          },
        },
        (res) => {
          let text = "";
          res.on("data", (c) => (text += c));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, text }));
        },
      );
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  async function connect(extra: Record<string, unknown> = {}): Promise<{ status: number; text: string }> {
    const start = await request("POST", "/api/integrations/salesforce/oauth/start", {
      clientId: "sfid",
      clientSecret: "sfsec",
      redirectBase: `http://127.0.0.1:${port}`,
      ...extra,
    });
    expect(start.status).toBe(200);
    const url = new URL(JSON.parse(start.text).url);
    expect(url.searchParams.get("scope")).toBe("api refresh_token");
    const state = url.searchParams.get("state");
    return request("GET", `/oauth/salesforce/callback?state=${state}&code=c1`, undefined, false);
  }

  beforeAll(async () => {
    tokenServer = http.createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(tokenBody));
      });
    });
    await new Promise<void>((r) => tokenServer.listen(0, "127.0.0.1", r));
    const tport = (tokenServer.address() as { port: number }).port;
    process.env.ONEGATE_OAUTH_TOKEN_URL_SALESFORCE = `http://127.0.0.1:${tport}/token`;
    process.env.ONEGATE_OAUTH_AUTH_URL_SALESFORCE = `http://127.0.0.1:${tport}/authorize`;

    dir = mkdtempSync(join(tmpdir(), "onegate-b8-"));
    store = new Store(":memory:");
    const ca = initCa(dir);
    const registry = await buildRegistry();
    adminToken = ensureAdminToken(store)!;
    server = http.createServer(createAdminApp({ store, registry, ca, version: "test" }));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as { port: number }).port;
  });

  afterAll(() => {
    server.close();
    tokenServer.close();
    delete process.env.ONEGATE_OAUTH_TOKEN_URL_SALESFORCE;
    delete process.env.ONEGATE_OAUTH_AUTH_URL_SALESFORCE;
    rmSync(dir, { recursive: true, force: true });
  });

  it("stores instanceUrl and a short assumed expiry from a response without expires_in", async () => {
    tokenBody = {
      access_token: "sf_at",
      refresh_token: "sf_rt",
      instance_url: "https://acme.my.salesforce.com",
      id: "https://login.salesforce.com/id/00D/005",
      token_type: "Bearer",
      scope: "api refresh_token",
    };
    const before = Math.floor(Date.now() / 1000);
    const cb = await connect();
    expect(cb.status).toBe(200);
    const data = store.getCredential("salesforce")!.data;
    expect(data.instanceUrl).toBe("https://acme.my.salesforce.com");
    expect(data.accessToken).toBe("sf_at");
    expect(data.refreshToken).toBe("sf_rt");
    // Unmapped extras are not stored.
    expect(data.id).toBeUndefined();
    const exp = Number(data.expiresAt);
    expect(exp).toBeGreaterThanOrEqual(before + 600);
    expect(exp).toBeLessThanOrEqual(before + 602);
  });

  it("rejects an unknown Datadog site with a clear 400 when saving", async () => {
    const legacy = await request("PUT", "/api/credentials/datadog", { data: { apiKey: "k", site: "us9" } });
    expect(legacy.status).toBe(400);
    expect(JSON.parse(legacy.text)).toMatchObject({ error: "invalid_data" });
    expect(legacy.text).toContain("not a Datadog site");
    expect(store.getCredential("datadog")).toBeNull();
    const conn = await request("POST", "/api/connections", {
      kind: "app",
      vendor: "datadog",
      name: "dd",
      data: { apiKey: "k", site: "us9" },
    });
    expect(conn.status).toBe(400);
    expect(conn.text).toContain("not a Datadog site");
    const good = await request("PUT", "/api/credentials/datadog", { data: { apiKey: "k", site: "us5" } });
    expect(good.status).toBe(200);
    const goodConn = await request("POST", "/api/connections", {
      kind: "app",
      vendor: "datadog",
      name: "dd",
      data: { apiKey: "k", site: "eu" },
    });
    expect(goodConn.status).toBe(201);
  });

  it("rejects non-string legacy credential values with 400 invalid_data, not a 500", async () => {
    const r = await request("PUT", "/api/credentials/datadog", { data: { apiKey: "k", site: 42 } });
    expect(r.status).toBe(400);
    expect(JSON.parse(r.text)).toEqual({ error: "invalid_data", message: "data.site must be a string" });
  });

  it("PUT /api/connections/:id runs the Datadog hook only when data is sent", async () => {
    // Stored directly with a bad site, bypassing the API, to prove a rename
    // (no data) never runs the hook.
    const conn = store.createConnection({
      kind: "app",
      vendor: "datadog",
      name: "dd-legacy-bad",
      data: { apiKey: "k", site: "us9" },
    });
    const rename = await request("PUT", `/api/connections/${conn.id}`, { name: "dd-renamed" });
    expect(rename.status).toBe(200);
    const bad = await request("PUT", `/api/connections/${conn.id}`, { data: { apiKey: "k", site: "us9" } });
    expect(bad.status).toBe(400);
    expect(JSON.parse(bad.text).error).toBe("invalid_data");
    expect(bad.text).toContain("not a Datadog site");
  });

  it("rejects an unknown PostHog region on both save routes", async () => {
    const legacy = await request("PUT", "/api/credentials/posthog", { data: { apiKey: "phx_x", region: "europe" } });
    expect(legacy.status).toBe(400);
    expect(legacy.text).toContain("must be us or eu");
    const conn = await request("POST", "/api/connections", {
      kind: "app",
      vendor: "posthog",
      name: "ph",
      data: { apiKey: "phx_x", region: "europe" },
    });
    expect(conn.status).toBe(400);
    expect(conn.text).toContain("must be us or eu");
    const ok = await request("PUT", "/api/credentials/posthog", { data: { apiKey: "phx_x", region: "EU" } });
    expect(ok.status).toBe(200);
    expect(posthog.validateCredential!({ apiKey: "phx_x" })).toBe("data.region is required (us or eu)");
    expect(posthog.validateCredential!({ apiKey: "phx_x", region: " " })).toBe("data.region is required (us or eu)");
    const missing = await request("PUT", "/api/credentials/posthog", { data: { apiKey: "phx_x" } });
    expect(missing.status).toBe(400);
    expect(missing.text).toContain("region is required");
    // Stored without a region some other way, inject refuses instead of sending the key anywhere.
    expect(() =>
      posthog.inject({ headers: {}, method: "GET", path: "/", host: "us.posthog.com", credential: cred({ apiKey: "phx_x" }), store }),
    ).toThrow(/no valid "region"/);
  });

  it("re-authorizing a connection to another org drops the old org's cached token", async () => {
    tokenBody = { access_token: "sf_at_A", refresh_token: "sf_rt_A", instance_url: "https://org-a.my.salesforce.com" };
    expect((await connect({ connectionName: "sf-reauth" })).status).toBe(200);
    const conn = store.listConnections().find((c) => c.name === "sf-reauth")!;
    const key = `oauth_access_token:salesforce:${conn.id}`;
    // A token minted earlier for org A is still cached.
    store.setSecretSetting(key, { token: "cached_org_a", exp: Date.now() + 3_600_000 });

    tokenBody = { access_token: "sf_at_B", refresh_token: "sf_rt_B", instance_url: "https://org-b.my.salesforce.com" };
    expect((await connect({ connectionId: conn.id })).status).toBe(200);
    expect(store.getSecretSetting(key)).toBeNull();

    const fresh = store.getConnection(conn.id)!;
    const c = { id: fresh.id, integrationId: "salesforce", name: fresh.name, data: fresh.data, createdAt: "" };
    const ctx = ctxFor("org-b.my.salesforce.com", c, store);
    await salesforce.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer sf_at_B");
  });

  it("editing a connection's data drops its cached token, the next inject mints fresh", async () => {
    tokenBody = { access_token: "sf_at_A", refresh_token: "sf_rt_A", instance_url: "https://org-a.my.salesforce.com" };
    expect((await connect({ connectionName: "sf-edit" })).status).toBe(200);
    const conn = store.listConnections().find((c) => c.name === "sf-edit")!;
    const key = `oauth_access_token:salesforce:${conn.id}`;
    store.setSecretSetting(key, { token: "cached_org_a", exp: Date.now() + 3_600_000 });

    const edit = await request("PUT", `/api/connections/${conn.id}`, {
      data: { clientId: "sfid", clientSecret: "sfsec", refreshToken: "sf_rt_A", instanceUrl: "https://org-b.my.salesforce.com" },
    });
    expect(edit.status).toBe(200);
    expect(store.getSecretSetting(key)).toBeNull();

    tokenBody = { access_token: "sf_at_fresh", instance_url: "https://org-b.my.salesforce.com" };
    const fresh = store.getConnection(conn.id)!;
    const ctx = ctxFor("org-b.my.salesforce.com", { id: fresh.id, integrationId: "salesforce", name: fresh.name, data: fresh.data, createdAt: "" }, store);
    await salesforce.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer sf_at_fresh");
    // The refresh's own write path keeps the token it just minted.
    expect(store.getSecretSetting<{ token: string }>(key)!.token).toBe("sf_at_fresh");
  });

  it("editing the legacy credential through PUT /api/credentials drops its cached token", async () => {
    store.setCredential("zoom", "t", { accountId: "acct_1", clientId: "zcid", clientSecret: "zsecret" });
    const id = store.getCredential("zoom")!.id;
    store.setSecretSetting(`oauth_access_token:zoom:${id}`, { token: "old", exp: Date.now() + 3_600_000 });
    const r = await request("PUT", "/api/credentials/zoom", {
      data: { accountId: "acct_2", clientId: "zcid", clientSecret: "zsecret" },
    });
    expect(r.status).toBe(200);
    expect(store.getSecretSetting(`oauth_access_token:zoom:${id}`)).toBeNull();
  });

  it("re-connecting the legacy credential drops its cached token", async () => {
    tokenBody = { access_token: "sf_at_1", refresh_token: "sf_rt_1", instance_url: "https://acme.my.salesforce.com" };
    expect((await connect()).status).toBe(200);
    const id = store.getCredential("salesforce")!.id;
    store.setSecretSetting(`oauth_access_token:salesforce:${id}`, { token: "stale", exp: Date.now() + 3_600_000 });
    tokenBody = { access_token: "sf_at_2", refresh_token: "sf_rt_2", instance_url: "https://acme.my.salesforce.com" };
    expect((await connect()).status).toBe(200);
    expect(store.getCredential("salesforce")!.id).toBe(id);
    expect(store.getSecretSetting(`oauth_access_token:salesforce:${id}`)).toBeNull();
  });

  it("ignores a non-string instance_url instead of storing junk", async () => {
    tokenBody = { access_token: "sf_at2", refresh_token: "sf_rt2", instance_url: 42 };
    const cb = await connect();
    expect(cb.status).toBe(200);
    const data = store.getCredential("salesforce")!.data;
    expect(data.accessToken).toBe("sf_at2");
    expect(data.instanceUrl).toBeUndefined();
  });
});
