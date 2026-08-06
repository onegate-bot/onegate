import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import http from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Registry } from "../src/integrations/types.js";
import { github } from "../src/integrations/github.js";
import { google, googleAccessToken } from "../src/integrations/google.js";
import { buildRegistry, loadCommunity, disabledIntegrations } from "../src/integrations/index.js";
import { composeLlmHelpPrompt } from "../src/integrations/llm-help.js";
import type { Integration } from "../src/integrations/types.js";
import { Store } from "../src/store/db.js";
import type { Credential } from "../src/types.js";
import type { IncomingHttpHeaders } from "node:http";

function cred(data: Record<string, string>, integrationId = "x"): Credential {
  return { id: "cr_test", integrationId, name: "t", data, createdAt: "" };
}

function ctxFor(host: string, credential: Credential, store: Store) {
  const headers: IncomingHttpHeaders = {};
  return { headers, method: "GET", path: "/", host, credential, store };
}

describe("registry host resolution", () => {
  it("matches exact hosts and dot-suffixes", async () => {
    const registry = await buildRegistry();
    expect(registry.resolveHost("api.github.com")?.id).toBe("github");
    expect(registry.resolveHost("gmail.googleapis.com")?.id).toBe("google");
    expect(registry.resolveHost("www.googleapis.com")?.id).toBe("google");
    // Everything else on *.googleapis.com belongs to the gcp integration.
    expect(registry.resolveHost("googleapis.com")?.id).toBe("gcp");
    expect(registry.resolveHost("example.com")).toBeNull();
    expect(registry.resolveHost("evil-github.com")).toBeNull();
  });

  it("rejects duplicate ids", () => {
    const registry = new Registry();
    registry.register(github);
    expect(() => registry.register(github)).toThrow(/already registered/);
  });

  it("drops integrations named in ONEGATE_DISABLED_INTEGRATIONS so their hosts pass through", async () => {
    const prev = process.env.ONEGATE_DISABLED_INTEGRATIONS;
    process.env.ONEGATE_DISABLED_INTEGRATIONS = "anthropic, telegram-bot";
    try {
      const registry = await buildRegistry();
      // Disabled: their hosts no longer resolve to an integration, so the
      // proxy tunnels them opaquely instead of demanding a credential.
      expect(registry.get("anthropic")).toBeNull();
      expect(registry.get("telegram-bot")).toBeNull();
      expect(registry.resolveHost("api.anthropic.com")).toBeNull();
      expect(registry.resolveHost("api.telegram.org")).toBeNull();
      // Untouched: everything else still resolves.
      expect(registry.resolveHost("api.github.com")?.id).toBe("github");
    } finally {
      if (prev === undefined) delete process.env.ONEGATE_DISABLED_INTEGRATIONS;
      else process.env.ONEGATE_DISABLED_INTEGRATIONS = prev;
    }
  });

  it("parses the disable list tolerantly", () => {
    expect([...disabledIntegrations("")].length).toBe(0);
    expect([...disabledIntegrations(undefined)].length).toBe(0);
    expect([...disabledIntegrations("anthropic")].sort()).toEqual(["anthropic"]);
    expect([...disabledIntegrations("anthropic, telegram-bot")].sort()).toEqual([
      "anthropic",
      "telegram-bot",
    ]);
    expect([...disabledIntegrations(" anthropic   telegram-bot ")].sort()).toEqual([
      "anthropic",
      "telegram-bot",
    ]);
  });
});

describe("github integration", () => {
  const store = new Store(":memory:");

  it("uses Bearer for the API", () => {
    const ctx = ctxFor("api.github.com", cred({ pat: "ghp_abc" }), store);
    github.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer ghp_abc");
    expect(ctx.headers["user-agent"]).toBe("onegate");
  });

  it("uses Basic x-access-token for git smart HTTP", () => {
    const ctx = ctxFor("github.com", cred({ pat: "ghp_abc" }), store);
    github.inject(ctx);
    const expected = "Basic " + Buffer.from("x-access-token:ghp_abc").toString("base64");
    expect(ctx.headers.authorization).toBe(expected);
  });

  it("throws when the credential is missing the pat", () => {
    expect(() => github.inject(ctxFor("api.github.com", cred({}), store))).toThrow(/pat/);
  });

  it("declares an api_key connect method so the wizard renders a token field", () => {
    expect(github.connect?.method).toBe("api_key");
    expect(github.connect?.hint).toMatch(/personal access token/i);
  });

  it("ships an on-page connect guide pointing at the GitHub token console", () => {
    expect(github.connectGuide?.consoleUrl).toBe("https://github.com/settings/tokens");
    expect(github.connectGuide?.steps.length).toBeGreaterThanOrEqual(4);
    expect(github.connectGuide?.steps.join("\n")).toMatch(/classic/i);
  });
});

describe("google integration", () => {
  let tokenServer: http.Server;
  let store: Store;
  let refreshCalls = 0;
  let expiresIn = 3600;

  beforeAll(async () => {
    tokenServer = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        refreshCalls++;
        const params = new URLSearchParams(body);
        if (params.get("grant_type") !== "refresh_token" || params.get("refresh_token") !== "rt_1") {
          res.writeHead(400).end(JSON.stringify({ error: "invalid_grant" }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ access_token: `at_${refreshCalls}`, expires_in: expiresIn }));
      });
    });
    await new Promise<void>((r) => tokenServer.listen(0, "127.0.0.1", r));
    const port = (tokenServer.address() as { port: number }).port;
    process.env.ONEGATE_GOOGLE_TOKEN_URL = `http://127.0.0.1:${port}/token`;
  });

  afterAll(() => {
    tokenServer.close();
    delete process.env.ONEGATE_GOOGLE_TOKEN_URL;
  });

  beforeEach(() => {
    store = new Store(":memory:");
    refreshCalls = 0;
    expiresIn = 3600;
  });

  const goodCred = () =>
    cred({ clientId: "cid", clientSecret: "cs", refreshToken: "rt_1" }, "google");

  it("refreshes once and then serves from cache", async () => {
    const c = goodCred();
    const t1 = await googleAccessToken(c, store);
    const t2 = await googleAccessToken(c, store);
    expect(t1).toBe("at_1");
    expect(t2).toBe("at_1");
    expect(refreshCalls).toBe(1);
  });

  it("re-refreshes when the cached token is near expiry", async () => {
    expiresIn = 30; // less than the 60s safety margin
    const c = goodCred();
    await googleAccessToken(c, store);
    await googleAccessToken(c, store);
    expect(refreshCalls).toBe(2);
  });

  it("inject sets the Bearer header", async () => {
    const ctx = ctxFor("gmail.googleapis.com", goodCred(), store);
    await google.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer at_1");
  });

  it("surfaces refresh failures", async () => {
    const bad = cred({ clientId: "cid", clientSecret: "cs", refreshToken: "wrong" }, "google");
    await expect(googleAccessToken(bad, store)).rejects.toThrow(/refresh failed \(400\)/);
  });

  it("requires all three credential fields", async () => {
    const bad = cred({ clientId: "cid" }, "google");
    await expect(googleAccessToken(bad, store)).rejects.toThrow(/refreshToken/);
  });
});

describe("llm help prompts", () => {
  it("merges integration-specific hints (github)", () => {
    const p = composeLlmHelpPrompt(github);
    // Generic frame: explains OneGate and lists metadata.
    expect(p).toContain("OneGate");
    expect(p).toContain("credential gateway");
    expect(p).toContain("api.github.com");
    expect(p).toContain('"Personal access token"');
    // Custom hints: credential type, creation URL, scopes.
    expect(p).toContain("personal access token (PAT)");
    expect(p).toContain("https://github.com/settings/tokens");
    expect(p).toContain('"repo" scope');
    expect(p).toContain("Fine-grained token");
    // Asks for actionable output.
    expect(p).toContain("numbered step-by-step instructions");
  });

  it("describes the real connect flow for google", () => {
    const p = composeLlmHelpPrompt(google);
    expect(p).toContain("OAuth 2.0 client");
    expect(p).toContain("refresh token");
    expect(p).toContain("/oauth/google/callback");
    expect(p).toContain("https://www.googleapis.com/auth/gmail.modify");
    expect(p).toContain("https://www.googleapis.com/auth/calendar");
    expect(p).toContain("https://www.googleapis.com/auth/drive");
    expect(p).toContain("https://myaccount.google.com/permissions");
  });

  it("falls back to a generic prompt for bare community integrations", () => {
    const bare: Integration = {
      id: "slack",
      title: "Slack",
      hosts: ["slack.com", ".slack.com"],
      credentialFields: [{ key: "token", label: "Bot token", secret: true }],
      inject() {},
    };
    const p = composeLlmHelpPrompt(bare);
    expect(p).toContain('"Slack" integration');
    expect(p).toContain("slack.com, .slack.com");
    expect(p).toContain('"Bot token" (secret, treated like a password)');
    expect(p).toContain("numbered step-by-step instructions");
    expect(p).not.toContain("undefined");
    // No hints declared, so no hint sections appear.
    expect(p).not.toContain("Credential type needed:");
    expect(p).not.toContain("Where it is created:");
  });
});

describe("community loader", () => {
  it("loads default-exported integrations from a directory", async () => {
    const dir = mkdtempSync(join(tmpdir(), "onegate-community-"));
    writeFileSync(
      join(dir, "examplechat.mjs"),
      `export default {
        id: "examplechat", title: "ExampleChat", hosts: ["example-chat.com"],
        credentialFields: [{ key: "token", label: "Token", secret: true }],
        inject(ctx) { ctx.headers.authorization = "Bearer " + ctx.credential.data.token; },
      };`,
    );
    const registry = await buildRegistry(dir);
    expect(registry.resolveHost("example-chat.com")?.id).toBe("examplechat");
    rmSync(dir, { recursive: true, force: true });
  });

  it("rejects files without a valid default export", async () => {
    const dir = mkdtempSync(join(tmpdir(), "onegate-community-bad-"));
    writeFileSync(join(dir, "bad.mjs"), "export const nope = 1;");
    const registry = new Registry();
    await expect(loadCommunity(registry, dir)).rejects.toThrow(/default-export/);
    rmSync(dir, { recursive: true, force: true });
  });

  it("returns empty for a missing directory", async () => {
    const registry = new Registry();
    expect(await loadCommunity(registry, "/nonexistent-dir")).toEqual([]);
  });
});

import { slack } from "../src/integrations/slack.js";
import { openai } from "../src/integrations/openai.js";
import { anthropic } from "../src/integrations/anthropic.js";
import { jira } from "../src/integrations/jira.js";
import { notion } from "../src/integrations/notion.js";

describe("header token integrations (batch 1)", () => {
  const store = new Store(":memory:");

  it("slack injects the token as Bearer", () => {
    const ctx = ctxFor("api.slack.com", cred({ token: "xoxb-1" }), store);
    slack.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer xoxb-1");
  });

  it("openai injects the key as Bearer", () => {
    const ctx = ctxFor("api.openai.com", cred({ apiKey: "sk-1" }), store);
    openai.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer sk-1");
  });

  it("anthropic injects x-api-key and leaves authorization alone", () => {
    const ctx = ctxFor("api.anthropic.com", cred({ apiKey: "sk-ant-1" }), store);
    anthropic.inject(ctx);
    expect(ctx.headers["x-api-key"]).toBe("sk-ant-1");
    expect(ctx.headers.authorization).toBeUndefined();
  });

  it("jira injects Basic email:token", () => {
    const ctx = ctxFor("acme.atlassian.net", cred({ email: "z@x.io", apiToken: "t1" }), store);
    jira.inject(ctx);
    expect(ctx.headers.authorization).toBe("Basic " + Buffer.from("z@x.io:t1").toString("base64"));
  });

  it("notion injects Bearer plus a default Notion-Version", () => {
    const ctx = ctxFor("api.notion.com", cred({ token: "ntn_1" }), store);
    notion.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer ntn_1");
    expect(ctx.headers["notion-version"]).toBe("2022-06-28");
  });

  it("notion keeps the client's own Notion-Version", () => {
    const ctx = ctxFor("api.notion.com", cred({ token: "ntn_1" }), store);
    ctx.headers["notion-version"] = "2025-01-01";
    notion.inject(ctx);
    expect(ctx.headers["notion-version"]).toBe("2025-01-01");
  });

  it("each throws on a missing credential field", () => {
    for (const integ of [slack, openai, anthropic, notion]) {
      expect(() => integ.inject(ctxFor("h", cred({}), store))).toThrow(/field/);
    }
    expect(() => jira.inject(ctxFor("h", cred({ email: "e" }), store))).toThrow(/apiToken/);
  });

  it("registry resolves the new hosts", async () => {
    const registry = await buildRegistry();
    expect(registry.resolveHost("slack.com")?.id).toBe("slack");
    expect(registry.resolveHost("files.slack.com")?.id).toBe("slack");
    expect(registry.resolveHost("api.openai.com")?.id).toBe("openai");
    expect(registry.resolveHost("api.anthropic.com")?.id).toBe("anthropic");
    expect(registry.resolveHost("acme.atlassian.net")?.id).toBe("jira");
    expect(registry.resolveHost("api.atlassian.com")?.id).toBe("jira");
    expect(registry.resolveHost("api.notion.com")?.id).toBe("notion");
  });

  it("llm help prompts carry crafted hints", () => {
    expect(composeLlmHelpPrompt(slack)).toContain("https://api.slack.com/apps");
    expect(composeLlmHelpPrompt(slack)).toContain("Authorization header");
    expect(composeLlmHelpPrompt(openai)).toContain("https://platform.openai.com/api-keys");
    expect(composeLlmHelpPrompt(anthropic)).toContain("x-api-key");
    expect(composeLlmHelpPrompt(anthropic)).toContain("claude setup-token");
    expect(composeLlmHelpPrompt(anthropic)).toContain("oauth-2025-04-20");
    expect(composeLlmHelpPrompt(jira)).toContain("api-tokens");
    expect(composeLlmHelpPrompt(notion)).toContain("https://www.notion.so/my-integrations");
    expect(composeLlmHelpPrompt(openrouter)).toContain("https://openrouter.ai/keys");
    expect(composeLlmHelpPrompt(openrouter)).toContain("Bearer");
  });
});

import { linear } from "../src/integrations/linear.js";
import { stripe } from "../src/integrations/stripe.js";
import { sendgrid } from "../src/integrations/sendgrid.js";
import { braveSearch } from "../src/integrations/brave-search.js";
import { tavily } from "../src/integrations/tavily.js";
import { telegramBot } from "../src/integrations/telegram-bot.js";
import { discord } from "../src/integrations/discord.js";
import { huggingface } from "../src/integrations/huggingface.js";
import { elevenlabs } from "../src/integrations/elevenlabs.js";

describe("header token integrations (batch 2)", () => {
  const store = new Store(":memory:");

  it("linear injects the bare key", () => {
    const ctx = ctxFor("api.linear.app", cred({ apiKey: "lin_api_1" }), store);
    linear.inject(ctx);
    expect(ctx.headers.authorization).toBe("lin_api_1");
  });

  it("stripe injects Bearer", () => {
    const ctx = ctxFor("api.stripe.com", cred({ secretKey: "sk_test_1" }), store);
    stripe.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer sk_test_1");
  });

  it("sendgrid injects Bearer", () => {
    const ctx = ctxFor("api.sendgrid.com", cred({ apiKey: "SG.1" }), store);
    sendgrid.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer SG.1");
  });

  it("brave-search injects X-Subscription-Token", () => {
    const ctx = ctxFor("api.search.brave.com", cred({ token: "BSA1" }), store);
    braveSearch.inject(ctx);
    expect(ctx.headers["x-subscription-token"]).toBe("BSA1");
    expect(ctx.headers.authorization).toBeUndefined();
  });

  it("tavily injects Bearer", () => {
    const ctx = ctxFor("api.tavily.com", cred({ apiKey: "tvly-1" }), store);
    tavily.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer tvly-1");
  });

  it("discord injects the Bot prefix", () => {
    const ctx = ctxFor("discord.com", cred({ botToken: "abc.def" }), store);
    discord.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bot abc.def");
  });

  it("discord keeps an existing Bot prefix", () => {
    const ctx = ctxFor("discord.com", cred({ botToken: "Bot abc.def" }), store);
    discord.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bot abc.def");
  });

  it("huggingface injects Bearer", () => {
    const ctx = ctxFor("huggingface.co", cred({ token: "hf_1" }), store);
    huggingface.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer hf_1");
  });

  it("elevenlabs injects xi-api-key", () => {
    const ctx = ctxFor("api.elevenlabs.io", cred({ apiKey: "sk_eleven_1" }), store);
    elevenlabs.inject(ctx);
    expect(ctx.headers["xi-api-key"]).toBe("sk_eleven_1");
    expect(ctx.headers.authorization).toBeUndefined();
  });

  it("each throws on a missing credential field", () => {
    for (const integ of [linear, stripe, sendgrid, braveSearch, tavily, discord, huggingface, elevenlabs]) {
      expect(() => integ.inject(ctxFor("h", cred({}), store))).toThrow(/field/);
    }
  });

  it("registry resolves the new hosts", async () => {
    const registry = await buildRegistry();
    expect(registry.resolveHost("api.linear.app")?.id).toBe("linear");
    expect(registry.resolveHost("api.stripe.com")?.id).toBe("stripe");
    expect(registry.resolveHost("files.stripe.com")?.id).toBe("stripe");
    expect(registry.resolveHost("api.sendgrid.com")?.id).toBe("sendgrid");
    expect(registry.resolveHost("api.search.brave.com")?.id).toBe("brave-search");
    expect(registry.resolveHost("api.tavily.com")?.id).toBe("tavily");
    expect(registry.resolveHost("api.telegram.org")?.id).toBe("telegram-bot");
    expect(registry.resolveHost("discord.com")?.id).toBe("discord");
    expect(registry.resolveHost("huggingface.co")?.id).toBe("huggingface");
    expect(registry.resolveHost("api-inference.huggingface.co")?.id).toBe("huggingface");
    expect(registry.resolveHost("api.elevenlabs.io")?.id).toBe("elevenlabs");
  });

  it("llm help prompts carry crafted hints", () => {
    for (const integ of [linear, stripe, sendgrid, braveSearch, tavily, telegramBot, discord, huggingface, elevenlabs]) {
      const p = composeLlmHelpPrompt(integ);
      expect(p).toContain("Credential type needed:");
      expect(p).toContain("Where it is created:");
    }
    expect(composeLlmHelpPrompt(tavily)).toContain("cannot rewrite request bodies");
    expect(composeLlmHelpPrompt(telegramBot)).toContain("/bot");
  });
});

describe("telegram bot path rewriting", () => {
  const store = new Store(":memory:");
  const tok = "123456:ABC-xyz";

  it("swaps the placeholder token in API method paths", () => {
    const ctx = ctxFor("api.telegram.org", cred({ token: tok }), store);
    ctx.path = "/bot000:placeholder/sendMessage?chat_id=1";
    telegramBot.inject(ctx);
    expect(ctx.path).toBe(`/bot${tok}/sendMessage?chat_id=1`);
  });

  it("rewrites file download paths", () => {
    const ctx = ctxFor("api.telegram.org", cred({ token: tok }), store);
    ctx.path = "/file/botPLACEHOLDER/documents/file_1.pdf";
    telegramBot.inject(ctx);
    expect(ctx.path).toBe(`/file/bot${tok}/documents/file_1.pdf`);
  });

  it("rejects paths that do not follow the bot convention", () => {
    const ctx = ctxFor("api.telegram.org", cred({ token: tok }), store);
    ctx.path = "/getMe";
    expect(() => telegramBot.inject(ctx)).toThrow(/\/bot<placeholder>/);
  });

  it("throws when the credential is missing the token", () => {
    const ctx = ctxFor("api.telegram.org", cred({}), store);
    ctx.path = "/botX/getMe";
    expect(() => telegramBot.inject(ctx)).toThrow(/token/);
  });
});

import { generateKeyPairSync, createVerify, createHash } from "node:crypto";
import { gcp, gcpAccessToken, buildJwtAssertion, GCP_DEFAULT_SCOPE } from "../src/integrations/gcp.js";
import type { ServiceAccountKey } from "../src/integrations/gcp.js";

describe("gcp integration", () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const saKey: ServiceAccountKey = {
    client_email: "robot@proj.iam.gserviceaccount.com",
    private_key: privatePem,
  };
  const saJson = JSON.stringify({ type: "service_account", ...saKey });

  let tokenServer: http.Server;
  let store: Store;
  let exchanges = 0;
  let expiresIn = 3600;
  let lastAssertion = "";

  beforeAll(async () => {
    tokenServer = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        exchanges++;
        const params = new URLSearchParams(body);
        lastAssertion = params.get("assertion") ?? "";
        if (params.get("grant_type") !== "urn:ietf:params:oauth:grant-type:jwt-bearer" || !lastAssertion) {
          res.writeHead(400).end(JSON.stringify({ error: "unsupported_grant_type" }));
          return;
        }
        const [h, c, sig] = lastAssertion.split(".");
        const valid = createVerify("RSA-SHA256")
          .update(`${h}.${c}`)
          .verify(publicPem, Buffer.from(sig, "base64url"));
        if (!valid) {
          res.writeHead(401).end(JSON.stringify({ error: "invalid_grant" }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ access_token: `gat_${exchanges}`, expires_in: expiresIn }));
      });
    });
    await new Promise<void>((r) => tokenServer.listen(0, "127.0.0.1", r));
    const port = (tokenServer.address() as { port: number }).port;
    process.env.ONEGATE_GCP_TOKEN_URL = `http://127.0.0.1:${port}/token`;
  });

  afterAll(() => {
    tokenServer.close();
    delete process.env.ONEGATE_GCP_TOKEN_URL;
  });

  beforeEach(() => {
    store = new Store(":memory:");
    exchanges = 0;
    expiresIn = 3600;
    lastAssertion = "";
  });

  const goodCred = () => cred({ serviceAccountJson: saJson }, "gcp");

  it("builds an RS256 JWT assertion verifiable with the public key", () => {
    const now = new Date(1_700_000_000_000);
    const assertion = buildJwtAssertion(saKey, GCP_DEFAULT_SCOPE, now);
    const [h, c, sig] = assertion.split(".");
    expect(JSON.parse(Buffer.from(h, "base64url").toString())).toEqual({ alg: "RS256", typ: "JWT" });
    const claims = JSON.parse(Buffer.from(c, "base64url").toString());
    expect(claims.iss).toBe("robot@proj.iam.gserviceaccount.com");
    expect(claims.scope).toBe(GCP_DEFAULT_SCOPE);
    expect(claims.aud).toBe("https://oauth2.googleapis.com/token");
    expect(claims.iat).toBe(1_700_000_000);
    expect(claims.exp).toBe(1_700_000_000 + 3600);
    const verify = (payload: string) =>
      createVerify("RSA-SHA256").update(payload).verify(publicPem, Buffer.from(sig, "base64url"));
    expect(verify(`${h}.${c}`)).toBe(true);
    expect(verify(`${h}.tampered`)).toBe(false);
  });

  it("exchanges the assertion once and then serves from cache", async () => {
    const c = goodCred();
    const t1 = await gcpAccessToken(c, store);
    const t2 = await gcpAccessToken(c, store);
    expect(t1).toBe("gat_1");
    expect(t2).toBe("gat_1");
    expect(exchanges).toBe(1);
  });

  it("re-exchanges when the cached token is near expiry", async () => {
    expiresIn = 30; // less than the 60s safety margin
    const c = goodCred();
    await gcpAccessToken(c, store);
    await gcpAccessToken(c, store);
    expect(exchanges).toBe(2);
  });

  it("inject sets the Bearer header", async () => {
    const ctx = ctxFor("storage.googleapis.com", goodCred(), store);
    await gcp.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer gat_1");
  });

  it("honors the scopes override in the assertion", async () => {
    const narrow = "https://www.googleapis.com/auth/devstorage.read_only";
    await gcpAccessToken(cred({ serviceAccountJson: saJson, scopes: narrow }, "gcp"), store);
    const claims = JSON.parse(Buffer.from(lastAssertion.split(".")[1], "base64url").toString());
    expect(claims.scope).toBe(narrow);
  });

  it("rejects a credential that is not valid JSON", async () => {
    await expect(gcpAccessToken(cred({ serviceAccountJson: "{nope" }, "gcp"), store)).rejects.toThrow(
      /not valid JSON/,
    );
  });

  it("rejects key JSON missing client_email or private_key", async () => {
    const bad = JSON.stringify({ type: "service_account", client_email: "x@y.z" });
    await expect(gcpAccessToken(cred({ serviceAccountJson: bad }, "gcp"), store)).rejects.toThrow(
      /client_email and private_key/,
    );
  });

  it("rejects a missing serviceAccountJson field", async () => {
    await expect(gcpAccessToken(cred({}, "gcp"), store)).rejects.toThrow(/serviceAccountJson/);
  });

  it("splits googleapis.com hosts with the google integration", async () => {
    const registry = await buildRegistry();
    expect(registry.resolveHost("compute.googleapis.com")?.id).toBe("gcp");
    expect(registry.resolveHost("storage.googleapis.com")?.id).toBe("gcp");
    expect(registry.resolveHost("bigquery.googleapis.com")?.id).toBe("gcp");
    expect(registry.resolveHost("gmail.googleapis.com")?.id).toBe("google");
    expect(registry.resolveHost("www.googleapis.com")?.id).toBe("google");
  });

  it("llm help prompt covers service accounts", () => {
    const p = composeLlmHelpPrompt(gcp);
    expect(p).toContain("service account");
    expect(p).toContain("cloud-platform");
    expect(p).toContain("JSON");
  });
});

import { aws, signV4, deriveSigningKey, deriveAwsTarget } from "../src/integrations/aws.js";

describe("aws sigv4 integration", () => {
  const store = new Store(":memory:");
  const DOC_SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
  const sha256hex = (s: string) => createHash("sha256").update(s).digest("hex");

  it("reproduces the AWS documentation signing-key vector", () => {
    const key = deriveSigningKey(DOC_SECRET, "20150830", "us-east-1", "iam");
    expect(key.toString("hex")).toBe(
      "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
    );
  });

  it("reproduces the AWS documentation request-signature vector", () => {
    const headers: IncomingHttpHeaders = {
      "content-type": "application/x-www-form-urlencoded; charset=utf-8",
    };
    signV4({
      method: "GET",
      path: "/?Action=ListUsers&Version=2010-05-08",
      headers,
      host: "iam.amazonaws.com",
      service: "iam",
      region: "us-east-1",
      accessKeyId: "AKIDEXAMPLE",
      secretAccessKey: DOC_SECRET,
      now: new Date("2015-08-30T12:36:00Z"),
    });
    expect(headers["x-amz-date"]).toBe("20150830T123600Z");
    expect(headers.authorization).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
        "SignedHeaders=content-type;host;x-amz-date, " +
        "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
    );
  });

  it("derives service and region from hosts", () => {
    expect(deriveAwsTarget("s3.eu-central-1.amazonaws.com")).toEqual({
      service: "s3",
      region: "eu-central-1",
    });
    expect(deriveAwsTarget("ec2.us-east-1.amazonaws.com")).toEqual({
      service: "ec2",
      region: "us-east-1",
    });
    expect(deriveAwsTarget("my-bucket.s3.us-west-2.amazonaws.com")).toEqual({
      service: "s3",
      region: "us-west-2",
    });
    expect(deriveAwsTarget("abc123.execute-api.eu-west-1.amazonaws.com")).toEqual({
      service: "execute-api",
      region: "eu-west-1",
    });
    expect(deriveAwsTarget("iam.amazonaws.com", "eu-central-1")).toEqual({
      service: "iam",
      region: "eu-central-1",
    });
    expect(deriveAwsTarget("sts.amazonaws.com")).toEqual({ service: "sts", region: "us-east-1" });
  });

  const awsCred = (extra: Record<string, string> = {}) =>
    cred({ accessKeyId: "AKID", secretAccessKey: "sek", ...extra }, "aws");

  it("inject signs with the payload hash", () => {
    const body = Buffer.from('{"TableName":"t"}');
    const ctx = { ...ctxFor("dynamodb.us-east-1.amazonaws.com", awsCred(), store), method: "POST", body };
    aws.inject(ctx);
    expect(ctx.headers.authorization).toMatch(
      /^AWS4-HMAC-SHA256 Credential=AKID\/\d{8}\/us-east-1\/dynamodb\/aws4_request, SignedHeaders=host;x-amz-date, Signature=[0-9a-f]{64}$/,
    );
    expect(ctx.headers["x-amz-date"]).toMatch(/^\d{8}T\d{6}Z$/);
  });

  it("sets x-amz-content-sha256 to the body hash for s3", () => {
    const body = Buffer.from("hello");
    const ctx = { ...ctxFor("s3.eu-central-1.amazonaws.com", awsCred(), store), method: "PUT", body };
    aws.inject(ctx);
    expect(ctx.headers["x-amz-content-sha256"]).toBe(sha256hex("hello"));
    expect(String(ctx.headers.authorization)).toContain("x-amz-content-sha256");
  });

  it("falls back to UNSIGNED-PAYLOAD for s3 when no body is available", () => {
    const ctx = ctxFor("bucket.s3.us-west-2.amazonaws.com", awsCred(), store);
    aws.inject(ctx);
    expect(ctx.headers["x-amz-content-sha256"]).toBe("UNSIGNED-PAYLOAD");
  });

  it("signs the session token when present", () => {
    const ctx = { ...ctxFor("ec2.us-east-1.amazonaws.com", awsCred({ sessionToken: "tok123" }), store), body: Buffer.alloc(0) };
    aws.inject(ctx);
    expect(ctx.headers["x-amz-security-token"]).toBe("tok123");
    expect(String(ctx.headers.authorization)).toContain("x-amz-security-token");
  });

  it("strips agent-supplied sigv4 artifacts before signing", () => {
    const ctx = { ...ctxFor("ec2.us-east-1.amazonaws.com", awsCred(), store), body: Buffer.alloc(0) };
    ctx.headers["x-amz-date"] = "19990101T000000Z";
    ctx.headers["x-amz-content-sha256"] = "bogus";
    ctx.headers["x-amz-security-token"] = "agent-dummy";
    aws.inject(ctx);
    expect(ctx.headers["x-amz-date"]).not.toBe("19990101T000000Z");
    expect(ctx.headers["x-amz-content-sha256"]).toBeUndefined();
    expect(ctx.headers["x-amz-security-token"]).toBeUndefined();
  });

  it("throws on missing credential fields", () => {
    expect(() => aws.inject(ctxFor("s3.amazonaws.com", cred({}, "aws"), store))).toThrow(
      /accessKeyId/,
    );
  });

  it("registry resolves amazonaws hosts and declares needsBody", async () => {
    const registry = await buildRegistry();
    expect(registry.resolveHost("s3.eu-central-1.amazonaws.com")?.id).toBe("aws");
    expect(registry.resolveHost("dynamodb.us-east-1.amazonaws.com")?.id).toBe("aws");
    expect(aws.needsBody).toBe(true);
  });

  it("llm help prompt is marked experimental", () => {
    const p = composeLlmHelpPrompt(aws);
    expect(p).toContain("EXPERIMENTAL");
    expect(p).toContain("Signature Version 4");
    expect(p).toContain("least-privilege");
  });
});

import { gitlab } from "../src/integrations/gitlab.js";
import { confluence } from "../src/integrations/confluence.js";
import { dropbox } from "../src/integrations/dropbox.js";
import { cloudflare } from "../src/integrations/cloudflare.js";

describe("batch 4 integrations (gitlab, confluence, dropbox, cloudflare)", () => {
  let tokenServer: http.Server;
  let store: Store;
  let refreshes = 0;

  beforeAll(async () => {
    tokenServer = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        refreshes++;
        const isJson = (req.headers["content-type"] ?? "").includes("application/json");
        const params = isJson
          ? new URLSearchParams(Object.entries(JSON.parse(body) as Record<string, string>))
          : new URLSearchParams(body);
        if (params.get("grant_type") !== "refresh_token" || !params.get("refresh_token")) {
          res.writeHead(400).end(JSON.stringify({ error: "invalid_grant" }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: `${isJson ? "json" : "form"}_at_${refreshes}`,
            expires_in: 3600,
          }),
        );
      });
    });
    await new Promise<void>((r) => tokenServer.listen(0, "127.0.0.1", r));
    const port = (tokenServer.address() as { port: number }).port;
    for (const id of ["GITLAB", "CONFLUENCE", "DROPBOX"]) {
      process.env[`ONEGATE_OAUTH_TOKEN_URL_${id}`] = `http://127.0.0.1:${port}/token`;
    }
  });

  afterAll(() => {
    tokenServer.close();
    for (const id of ["GITLAB", "CONFLUENCE", "DROPBOX"]) {
      delete process.env[`ONEGATE_OAUTH_TOKEN_URL_${id}`];
    }
  });

  beforeEach(() => {
    store = new Store(":memory:");
    refreshes = 0;
  });

  it("gitlab uses Bearer for the API and Basic oauth2 for git", async () => {
    const c = cred({ accessToken: "glat_1" }, "gitlab");
    const api = ctxFor("gitlab.com", c, store);
    api.path = "/api/v4/projects";
    await gitlab.inject(api);
    expect(api.headers.authorization).toBe("Bearer glat_1");

    const git = ctxFor("gitlab.com", c, store);
    git.path = "/ziv/repo.git/info/refs";
    await gitlab.inject(git);
    expect(git.headers.authorization).toBe(
      "Basic " + Buffer.from("oauth2:glat_1").toString("base64"),
    );
  });

  it("gitlab refreshes through the descriptor token endpoint and caches", async () => {
    const c = cred({ clientId: "cid", clientSecret: "cs", refreshToken: "rt" }, "gitlab");
    const ctx1 = ctxFor("gitlab.com", c, store);
    ctx1.path = "/api/v4/user";
    await gitlab.inject(ctx1);
    const ctx2 = ctxFor("gitlab.com", c, store);
    ctx2.path = "/api/v4/user";
    await gitlab.inject(ctx2);
    expect(ctx1.headers.authorization).toBe("Bearer form_at_1");
    expect(ctx2.headers.authorization).toBe("Bearer form_at_1");
    expect(refreshes).toBe(1);
  });

  it("confluence refreshes with a JSON token body (Atlassian style)", async () => {
    const c = cred({ clientId: "cid", clientSecret: "cs", refreshToken: "rt" }, "confluence");
    const ctx = ctxFor("api.atlassian.com", c, store);
    await confluence.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer json_at_1");
  });

  it("confluence requires offline_access and the api.atlassian.com audience", () => {
    expect(confluence.oauth?.defaultScopes).toContain("offline_access");
    expect(confluence.oauth?.extraAuthParams?.audience).toBe("api.atlassian.com");
    expect(confluence.oauth?.tokenFormat).toBe("json");
  });

  it("confluence shares api.atlassian.com with jira, jira stays primary", async () => {
    const registry = await buildRegistry();
    expect(registry.resolveHost("api.atlassian.com")?.id).toBe("jira");
    const ids = registry.resolveHostCandidates("api.atlassian.com").map((i) => i.id);
    expect(ids).toEqual(["jira", "confluence"]);
  });

  it("dropbox injects Bearer on both API and content hosts", async () => {
    const c = cred({ accessToken: "dbx_1" }, "dropbox");
    const api = ctxFor("api.dropboxapi.com", c, store);
    await dropbox.inject(api);
    expect(api.headers.authorization).toBe("Bearer dbx_1");
    const content = ctxFor("content.dropboxapi.com", c, store);
    await dropbox.inject(content);
    expect(content.headers.authorization).toBe("Bearer dbx_1");
  });

  it("dropbox asks for offline access in the auth URL params", () => {
    expect(dropbox.oauth?.extraAuthParams?.token_access_type).toBe("offline");
  });

  it("cloudflare injects the API token as Bearer", () => {
    const ctx = ctxFor("api.cloudflare.com", cred({ apiToken: "cf_tok" }, "cloudflare"), store);
    cloudflare.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer cf_tok");
  });

  it("cloudflare throws when the credential is missing the token", () => {
    expect(() =>
      cloudflare.inject(ctxFor("api.cloudflare.com", cred({}, "cloudflare"), store)),
    ).toThrow(/apiToken/);
  });

  it("registry resolves the batch hosts", async () => {
    const registry = await buildRegistry();
    expect(registry.resolveHost("gitlab.com")?.id).toBe("gitlab");
    expect(registry.resolveHost("api.dropboxapi.com")?.id).toBe("dropbox");
    expect(registry.resolveHost("content.dropboxapi.com")?.id).toBe("dropbox");
    expect(registry.resolveHost("api.cloudflare.com")?.id).toBe("cloudflare");
  });

  it("llm help prompts compose for the batch", () => {
    for (const integration of [gitlab, confluence, dropbox, cloudflare]) {
      const p = composeLlmHelpPrompt(integration);
      expect(p).toContain("Credential type needed:");
      expect(p).toContain("Where it is created:");
    }
  });
});

import { flyio } from "../src/integrations/flyio.js";
import { vercel } from "../src/integrations/vercel.js";
import { supabase } from "../src/integrations/supabase.js";
import { resend } from "../src/integrations/resend.js";
import { buildAuthUrl } from "../src/integrations/oauth.js";

describe("batch 5 integrations (flyio, vercel, supabase, resend)", () => {
  const store = new Store(":memory:");

  it("flyio injects Bearer on both hosts", () => {
    for (const host of ["api.machines.dev", "api.fly.io"]) {
      const ctx = ctxFor(host, cred({ apiToken: "FlyV1 fm2_x" }, "flyio"), store);
      flyio.inject(ctx);
      expect(ctx.headers.authorization).toBe("Bearer FlyV1 fm2_x");
    }
  });

  it("vercel injects Bearer", () => {
    const ctx = ctxFor("api.vercel.com", cred({ apiToken: "vcp_1" }, "vercel"), store);
    vercel.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer vcp_1");
  });

  it("resend injects Bearer", () => {
    const ctx = ctxFor("api.resend.com", cred({ apiKey: "re_1" }, "resend"), store);
    resend.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer re_1");
  });

  it("api-key integrations throw on missing fields", () => {
    expect(() => flyio.inject(ctxFor("api.fly.io", cred({}, "flyio"), store))).toThrow(/apiToken/);
    expect(() => vercel.inject(ctxFor("api.vercel.com", cred({}, "vercel"), store))).toThrow(/apiToken/);
    expect(() => resend.inject(ctxFor("api.resend.com", cred({}, "resend"), store))).toThrow(/apiKey/);
  });

  it("supabase serves the stored access token as Bearer", async () => {
    const ctx = ctxFor("api.supabase.com", cred({ accessToken: "sbat_1" }, "supabase"), store);
    await supabase.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer sbat_1");
  });

  it("supabase auth URL omits the scope param and uses basic token auth", () => {
    const url = new URL(
      buildAuthUrl(supabase.id, supabase.oauth!, {
        clientId: "cid",
        redirectUri: "https://og.example/cb",
        state: "st",
        scopes: ["projects:read"],
      }),
    );
    expect(url.searchParams.has("scope")).toBe(false);
    expect(url.searchParams.get("client_id")).toBe("cid");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(supabase.oauth?.tokenAuth).toBe("basic");
  });

  it("registry resolves the batch hosts", async () => {
    const registry = await buildRegistry();
    expect(registry.resolveHost("api.machines.dev")?.id).toBe("flyio");
    expect(registry.resolveHost("api.fly.io")?.id).toBe("flyio");
    expect(registry.resolveHost("api.vercel.com")?.id).toBe("vercel");
    expect(registry.resolveHost("api.supabase.com")?.id).toBe("supabase");
    expect(registry.resolveHost("api.resend.com")?.id).toBe("resend");
  });

  it("llm help prompts compose for the batch", () => {
    for (const integration of [flyio, vercel, supabase, resend]) {
      const p = composeLlmHelpPrompt(integration);
      expect(p).toContain("Credential type needed:");
      expect(p).toContain("Where it is created:");
    }
  });
});

import { hetzner } from "../src/integrations/hetzner.js";

describe("hetzner integration", () => {
  const store = new Store(":memory:");

  it("injects the API token as Bearer on the Cloud API host", () => {
    const ctx = ctxFor("api.hetzner.cloud", cred({ apiToken: "hz_abc" }, "hetzner"), store);
    hetzner.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer hz_abc");
  });

  it("throws when the apiToken field is missing", () => {
    expect(() => hetzner.inject(ctxFor("api.hetzner.cloud", cred({}, "hetzner"), store))).toThrow(
      /apiToken/,
    );
  });

  it("registry resolves the Cloud API host to hetzner", async () => {
    const registry = await buildRegistry();
    expect(registry.resolveHost("api.hetzner.cloud")?.id).toBe("hetzner");
    // The DNS and Robot hosts are deliberately not claimed by this integration.
    expect(registry.resolveHost("dns.hetzner.com")).toBeNull();
  });

  it("composes an llm help prompt", () => {
    const p = composeLlmHelpPrompt(hetzner);
    expect(p).toContain("Credential type needed:");
    expect(p).toContain("Where it is created:");
  });
});

import { todoist } from "../src/integrations/todoist.js";
import { trello } from "../src/integrations/trello.js";
import { monday } from "../src/integrations/monday.js";
import { linkedin } from "../src/integrations/linkedin.js";

describe("batch 6 integrations (todoist, trello, monday, linkedin)", () => {
  const store = new Store(":memory:");

  it("todoist serves the long-lived token as Bearer", async () => {
    const ctx = ctxFor("api.todoist.com", cred({ accessToken: "td_1" }, "todoist"), store);
    await todoist.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer td_1");
  });

  it("todoist auth URL uses comma-separated scopes and skips redirect_uri in exchange", () => {
    const url = new URL(
      buildAuthUrl(todoist.id, todoist.oauth!, {
        clientId: "cid",
        redirectUri: "https://og.example/cb",
        state: "st",
        scopes: ["data:read_write", "data:delete"],
      }),
    );
    expect(url.searchParams.get("scope")).toBe("data:read_write,data:delete");
    expect(todoist.oauth?.sendRedirectUriInExchange).toBe(false);
  });

  it("trello rewrites the path with key and token query params", () => {
    const c = cred({ clientId: "k1", accessToken: "t1" }, "trello");
    const bare = ctxFor("api.trello.com", c, store);
    bare.path = "/1/members/me/boards";
    trello.inject(bare);
    expect(bare.path).toBe("/1/members/me/boards?key=k1&token=t1");

    const withQuery = ctxFor("api.trello.com", c, store);
    withQuery.path = "/1/boards/abc?fields=name";
    trello.inject(withQuery);
    expect(withQuery.path).toBe("/1/boards/abc?fields=name&key=k1&token=t1");
  });

  it("trello throws when key or token is missing", () => {
    expect(() => trello.inject(ctxFor("api.trello.com", cred({ clientId: "k1" }, "trello"), store))).toThrow(
      /accessToken/,
    );
  });

  it("trello descriptor is a fragment-callback provider with Trello param names", () => {
    const o = trello.oauth!;
    expect(o.fragmentCallback?.paramName).toBe("token");
    const url = new URL(
      buildAuthUrl(trello.id, o, {
        clientId: "k1",
        redirectUri: "https://og.example/cb",
        state: "st",
        scopes: ["read", "write"],
      }),
    );
    expect(url.searchParams.get("key")).toBe("k1");
    expect(url.searchParams.get("return_url")).toBe("https://og.example/cb");
    expect(url.searchParams.get("response_type")).toBe("token");
    expect(url.searchParams.get("callback_method")).toBe("fragment");
    expect(url.searchParams.get("scope")).toBe("read,write");
  });

  it("monday serves the long-lived token as Bearer and omits the scope param", async () => {
    const ctx = ctxFor("api.monday.com", cred({ accessToken: "mo_1" }, "monday"), store);
    await monday.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer mo_1");
    const url = new URL(
      buildAuthUrl(monday.id, monday.oauth!, {
        clientId: "cid",
        redirectUri: "https://og.example/cb",
        state: "st",
        scopes: [],
      }),
    );
    expect(url.searchParams.has("scope")).toBe(false);
  });

  it("linkedin injects Bearer", async () => {
    const ctx = ctxFor("api.linkedin.com", cred({ accessToken: "li_1" }, "linkedin"), store);
    await linkedin.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer li_1");
  });

  it("registry resolves the batch hosts", async () => {
    const registry = await buildRegistry();
    expect(registry.resolveHost("api.todoist.com")?.id).toBe("todoist");
    expect(registry.resolveHost("api.trello.com")?.id).toBe("trello");
    expect(registry.resolveHost("api.monday.com")?.id).toBe("monday");
    expect(registry.resolveHost("api.linkedin.com")?.id).toBe("linkedin");
  });

  it("llm help prompts compose for the batch", () => {
    for (const integration of [todoist, trello, monday, linkedin]) {
      const p = composeLlmHelpPrompt(integration);
      expect(p).toContain("Credential type needed:");
      expect(p).toContain("Where it is created:");
    }
  });
});

import { mongodbAtlas } from "../src/integrations/mongodb-atlas.js";
import { docker, dockerHubToken, jwtExpiryMs } from "../src/integrations/docker.js";
import { jfrogArtifactory } from "../src/integrations/jfrog-artifactory.js";
import { githubApp, githubAppToken, signGithubAppJwt, normalizePem } from "../src/integrations/github-app.js";

function fakeJwt(claims: Record<string, unknown>): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "none" })}.${b64(claims)}.sig`;
}

describe("batch 7 integrations (mongodb-atlas, docker, jfrog, github-app)", () => {
  let server: http.Server;
  let store: Store;
  let atlasGrants = 0;
  let dockerLogins = 0;
  let appExchanges = 0;
  let lastAppJwt = "";
  let dockerBody: Record<string, string> = {};

  const { publicKey: ghPub, privateKey: ghPriv } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const ghPublicPem = ghPub.export({ type: "spki", format: "pem" }).toString();
  const ghPrivatePem = ghPriv.export({ type: "pkcs8", format: "pem" }).toString();

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        if (req.url === "/atlas/token") {
          atlasGrants++;
          const params = new URLSearchParams(body);
          const auth = req.headers.authorization ?? "";
          if (
            params.get("grant_type") !== "client_credentials" ||
            auth !== "Basic " + Buffer.from("aid:asecret").toString("base64")
          ) {
            res.writeHead(401).end(JSON.stringify({ error: "invalid_client" }));
            return;
          }
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ access_token: `atlas_${atlasGrants}`, expires_in: 3600 }));
          return;
        }
        if (req.url === "/v2/users/login") {
          dockerLogins++;
          dockerBody = JSON.parse(body) as Record<string, string>;
          if (dockerBody.username !== "ziv" || dockerBody.password !== "dckr_pat_x") {
            res.writeHead(401).end(JSON.stringify({ detail: "Incorrect authentication credentials" }));
            return;
          }
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ token: fakeJwt({ exp: Math.floor(Date.now() / 1000) + 3600, n: dockerLogins }) }));
          return;
        }
        const install = req.url?.match(/^\/app\/installations\/(\d+)\/access_tokens$/);
        if (install) {
          appExchanges++;
          lastAppJwt = (req.headers.authorization ?? "").replace("Bearer ", "");
          const [h, c, sig] = lastAppJwt.split(".");
          const valid = createVerify("RSA-SHA256")
            .update(`${h}.${c}`)
            .verify(ghPublicPem, Buffer.from(sig, "base64url"));
          if (!valid) {
            res.writeHead(401).end(JSON.stringify({ message: "bad jwt" }));
            return;
          }
          res.writeHead(201, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              token: `ghs_inst_${appExchanges}`,
              expires_at: new Date(Date.now() + 3600_000).toISOString(),
            }),
          );
          return;
        }
        res.writeHead(404).end();
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    process.env.ONEGATE_OAUTH_TOKEN_URL_MONGODB_ATLAS = `http://127.0.0.1:${port}/atlas/token`;
    process.env.ONEGATE_DOCKER_LOGIN_URL = `http://127.0.0.1:${port}/v2/users/login`;
    process.env.ONEGATE_GITHUB_APP_API_BASE = `http://127.0.0.1:${port}`;
  });

  afterAll(() => {
    server.close();
    delete process.env.ONEGATE_OAUTH_TOKEN_URL_MONGODB_ATLAS;
    delete process.env.ONEGATE_DOCKER_LOGIN_URL;
    delete process.env.ONEGATE_GITHUB_APP_API_BASE;
  });

  beforeEach(() => {
    store = new Store(":memory:");
    atlasGrants = 0;
    dockerLogins = 0;
    appExchanges = 0;
  });

  it("mongodb-atlas mints a client_credentials token, injects Bearer and caches", async () => {
    const c = cred({ clientId: "aid", clientSecret: "asecret" }, "mongodb-atlas");
    const ctx1 = ctxFor("cloud.mongodb.com", c, store);
    await mongodbAtlas.inject(ctx1);
    const ctx2 = ctxFor("cloud.mongodb.com", c, store);
    await mongodbAtlas.inject(ctx2);
    expect(ctx1.headers.authorization).toBe("Bearer atlas_1");
    expect(ctx2.headers.authorization).toBe("Bearer atlas_1");
    expect(atlasGrants).toBe(1);
  });

  it("mongodb-atlas surfaces vendor rejections", async () => {
    const c = cred({ clientId: "aid", clientSecret: "wrong" }, "mongodb-atlas");
    await expect(mongodbAtlas.inject(ctxFor("cloud.mongodb.com", c, store))).rejects.toThrow(/401/);
  });

  it("docker logs in with the PAT, injects the JWT and caches until exp", async () => {
    const c = cred({ username: "ziv", apiToken: "dckr_pat_x" }, "docker");
    const ctx1 = ctxFor("hub.docker.com", c, store);
    await docker.inject(ctx1);
    const ctx2 = ctxFor("hub.docker.com", c, store);
    await docker.inject(ctx2);
    expect(String(ctx1.headers.authorization)).toMatch(/^Bearer ey/);
    expect(ctx2.headers.authorization).toBe(ctx1.headers.authorization);
    expect(dockerLogins).toBe(1);
    expect(dockerBody).toEqual({ username: "ziv", password: "dckr_pat_x" });
  });

  it("docker surfaces login failures with the vendor detail", async () => {
    const c = cred({ username: "ziv", apiToken: "bad" }, "docker");
    await expect(dockerHubToken(c, store)).rejects.toThrow(/Incorrect authentication/);
  });

  it("jwtExpiryMs parses exp and tolerates garbage", () => {
    expect(jwtExpiryMs(fakeJwt({ exp: 1700000000 }))).toBe(1700000000000);
    expect(jwtExpiryMs("not-a-jwt")).toBeNull();
    expect(jwtExpiryMs(fakeJwt({}))).toBeNull();
  });

  it("jfrog injects Bearer only on the bound host", () => {
    const c = cred({ token: "eyJart", host: "acme.jfrog.io" }, "jfrog-artifactory");
    const ctx = ctxFor("acme.jfrog.io", c, store);
    jfrogArtifactory.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer eyJart");
    expect(() => jfrogArtifactory.inject(ctxFor("other.jfrog.io", c, store))).toThrow(
      /bound to acme\.jfrog\.io/,
    );
  });

  it("normalizePem repairs escaped and single-line keys", () => {
    const normalized = normalizePem(ghPrivatePem.replace(/\n/g, "\\n"));
    expect(normalized).toContain("-----BEGIN PRIVATE KEY-----\n");
    const singleLine = ghPrivatePem.replace(/\n/g, "");
    expect(normalizePem(singleLine)).toContain("\n");
    expect(() => normalizePem("garbage")).toThrow(/PEM/);
  });

  it("github-app signs a verifiable app JWT with iss and 10 minute expiry", () => {
    const now = new Date(1_700_000_000_000);
    const jwt = signGithubAppJwt("4242", ghPrivatePem, now);
    const [h, c, sig] = jwt.split(".");
    expect(JSON.parse(Buffer.from(h, "base64url").toString())).toEqual({ alg: "RS256", typ: "JWT" });
    const claims = JSON.parse(Buffer.from(c, "base64url").toString());
    expect(claims).toEqual({ iss: "4242", iat: 1_700_000_000 - 60, exp: 1_700_000_000 + 600 });
    const valid = createVerify("RSA-SHA256")
      .update(`${h}.${c}`)
      .verify(ghPublicPem, Buffer.from(sig, "base64url"));
    expect(valid).toBe(true);
  });

  const appCred = () =>
    cred({ appId: "4242", privateKey: ghPrivatePem, installationId: "777" }, "github-app");

  it("github-app mints an installation token once and caches it", async () => {
    const t1 = await githubAppToken(appCred(), store);
    const t2 = await githubAppToken(appCred(), store);
    expect(t1).toBe("ghs_inst_1");
    expect(t2).toBe("ghs_inst_1");
    expect(appExchanges).toBe(1);
  });

  it("github-app injects Bearer on the API and Basic x-access-token for git", async () => {
    const api = ctxFor("api.github.com", appCred(), store);
    await githubApp.inject(api);
    expect(api.headers.authorization).toBe("Bearer ghs_inst_1");
    expect(api.headers["user-agent"]).toBe("onegate");

    const git = ctxFor("github.com", appCred(), store);
    await githubApp.inject(git);
    expect(git.headers.authorization).toBe(
      "Basic " + Buffer.from("x-access-token:ghs_inst_1").toString("base64"),
    );
  });

  it("github-app throws on incomplete credentials", async () => {
    await expect(githubAppToken(cred({ appId: "1" }, "github-app"), store)).rejects.toThrow(
      /installationId/,
    );
  });

  it("registry resolves the batch hosts, github stays primary on shared hosts", async () => {
    const registry = await buildRegistry();
    expect(registry.resolveHost("cloud.mongodb.com")?.id).toBe("mongodb-atlas");
    expect(registry.resolveHost("hub.docker.com")?.id).toBe("docker");
    expect(registry.resolveHost("acme.jfrog.io")?.id).toBe("jfrog-artifactory");
    expect(registry.resolveHost("api.github.com")?.id).toBe("github");
    const ids = registry.resolveHostCandidates("api.github.com").map((i) => i.id);
    expect(ids).toEqual(["github", "github-app"]);
  });

  it("llm help prompts compose for the batch", () => {
    for (const integration of [mongodbAtlas, docker, jfrogArtifactory, githubApp]) {
      const p = composeLlmHelpPrompt(integration);
      expect(p).toContain("Credential type needed:");
      expect(p).toContain("Where it is created:");
    }
  });
});

import { gemini } from "../src/integrations/gemini.js";
import { openrouter } from "../src/integrations/openrouter.js";

describe("llm vendor integrations", () => {
  const store = new Store(":memory:");

  it("anthropic, openai, gemini and openrouter declare llm metadata and needsBody", () => {
    expect(anthropic.llm?.vendor).toBe("anthropic");
    expect(openai.llm?.vendor).toBe("openai");
    expect(gemini.llm?.vendor).toBe("gemini");
    expect(openrouter.llm?.vendor).toBe("openrouter");
    for (const integ of [anthropic, openai, gemini, openrouter]) expect(integ.needsBody).toBe(true);
  });

  it("anthropic llm inject sets x-api-key from the selected connection", () => {
    const ctx = ctxFor("api.anthropic.com", cred({ apiKey: "sk-ant-conn" }), store);
    anthropic.llm!.inject(ctx);
    expect(ctx.headers["x-api-key"]).toBe("sk-ant-conn");
    expect(ctx.headers.authorization).toBeUndefined();
    expect(ctx.headers["anthropic-beta"]).toBeUndefined();
    expect(() => anthropic.llm!.inject(ctxFor("h", cred({}), store))).toThrow(/apiKey/);
  });

  it("anthropic llm inject uses Bearer auth-token mode (authToken field)", () => {
    const ctx = ctxFor("api.anthropic.com", cred({ authToken: "oat_sub_1" }), store);
    ctx.headers["x-api-key"] = "should-be-removed";
    anthropic.llm!.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer oat_sub_1");
    expect(ctx.headers["x-api-key"]).toBeUndefined();
    expect(ctx.headers["anthropic-beta"]).toBe("oauth-2025-04-20");
  });

  it("anthropic llm inject honours an explicit authMode discriminator", () => {
    const ctx = ctxFor(
      "api.anthropic.com",
      cred({ authMode: "auth_token", authToken: "oat_sub_2" }),
      store,
    );
    anthropic.llm!.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer oat_sub_2");
    expect(ctx.headers["anthropic-beta"]).toBe("oauth-2025-04-20");

    const apiCtx = ctxFor(
      "api.anthropic.com",
      cred({ authMode: "api_key", apiKey: "sk-ant-explicit" }),
      store,
    );
    anthropic.llm!.inject(apiCtx);
    expect(apiCtx.headers["x-api-key"]).toBe("sk-ant-explicit");
    expect(apiCtx.headers.authorization).toBeUndefined();
  });

  it("anthropic auth-token mode appends the oauth beta without clobbering existing betas", () => {
    const ctx = ctxFor("api.anthropic.com", cred({ authToken: "oat_sub_3" }), store);
    ctx.headers["anthropic-beta"] = "fine-grained-tool-streaming-2025-05-14";
    anthropic.llm!.inject(ctx);
    expect(ctx.headers["anthropic-beta"]).toBe(
      "fine-grained-tool-streaming-2025-05-14, oauth-2025-04-20",
    );
  });

  it("anthropic auth-token mode leaves the oauth beta untouched when already present", () => {
    const ctx = ctxFor("api.anthropic.com", cred({ authToken: "oat_sub_4" }), store);
    ctx.headers["anthropic-beta"] = "oauth-2025-04-20";
    anthropic.llm!.inject(ctx);
    expect(ctx.headers["anthropic-beta"]).toBe("oauth-2025-04-20");
  });

  it("anthropic auth-token mode with an explicit authMode but no token throws", () => {
    expect(() =>
      anthropic.llm!.inject(ctxFor("api.anthropic.com", cred({ authMode: "auth_token" }), store)),
    ).toThrow(/authToken/);
  });

  it("openai llm inject uses Bearer apiKey when an api key is stored", () => {
    const ctx = ctxFor("api.openai.com", cred({ apiKey: "sk-conn" }), store);
    openai.llm!.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer sk-conn");
    expect(ctx.headers["chatgpt-account-id"]).toBeUndefined();
  });

  it("openai llm inject uses the imported auth.json access token plus account header", () => {
    const ctx = ctxFor("api.openai.com", cred({ accessToken: "at_codex", accountId: "acc_1" }), store);
    openai.llm!.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer at_codex");
    expect(ctx.headers["chatgpt-account-id"]).toBe("acc_1");
  });

  it("openai llm inject omits the account header when no account id is stored", () => {
    const ctx = ctxFor("api.openai.com", cred({ accessToken: "at_codex" }), store);
    openai.llm!.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer at_codex");
    expect(ctx.headers["chatgpt-account-id"]).toBeUndefined();
  });

  it("openai llm inject prefers the api key over an access token", () => {
    const ctx = ctxFor("api.openai.com", cred({ apiKey: "sk-conn", accessToken: "at", accountId: "a" }), store);
    openai.llm!.inject(ctx);
    expect(ctx.headers.authorization).toBe("Bearer sk-conn");
    expect(ctx.headers["chatgpt-account-id"]).toBeUndefined();
  });

  it("openai llm inject throws when neither secret is present", () => {
    expect(() => openai.llm!.inject(ctxFor("h", cred({}), store))).toThrow(/apiKey|accessToken/);
  });

  it("openrouter injects a Bearer apiKey (app and llm paths)", () => {
    for (const inject of [openrouter.inject, openrouter.llm!.inject]) {
      const ctx = ctxFor("openrouter.ai", cred({ apiKey: "sk-or-conn" }), store);
      inject(ctx);
      expect(ctx.headers.authorization).toBe("Bearer sk-or-conn");
    }
    expect(() => openrouter.inject(ctxFor("h", cred({}), store))).toThrow(/apiKey/);
    expect(() => openrouter.llm!.inject(ctxFor("h", cred({}), store))).toThrow(/apiKey/);
  });

  it("openrouter resolves openrouter.ai in the registry", async () => {
    const registry = await buildRegistry();
    expect(registry.resolveHost("openrouter.ai")?.id).toBe("openrouter");
  });

  it("gemini injects x-goog-api-key (app and llm paths)", () => {
    for (const inject of [gemini.inject, gemini.llm!.inject]) {
      const ctx = ctxFor("generativelanguage.googleapis.com", cred({ apiKey: "AIza1" }), store);
      inject(ctx);
      expect(ctx.headers["x-goog-api-key"]).toBe("AIza1");
      expect(ctx.path).toBe("/");
    }
    expect(() => gemini.inject(ctxFor("h", cred({}), store))).toThrow(/apiKey/);
    expect(() => gemini.llm!.inject(ctxFor("h", cred({}), store))).toThrow(/apiKey/);
  });

  it("gemini rewrites a client-sent key query param to the real key", () => {
    const ctx = {
      ...ctxFor("generativelanguage.googleapis.com", cred({ apiKey: "AIza1" }), store),
      path: "/v1beta/models/gemini-pro:generateContent?key=placeholder&alt=json",
    };
    gemini.inject(ctx);
    expect(ctx.path).toBe("/v1beta/models/gemini-pro:generateContent?key=AIza1&alt=json");
    const noKey = {
      ...ctxFor("generativelanguage.googleapis.com", cred({ apiKey: "AIza1" }), store),
      path: "/v1beta/models?alt=json",
    };
    gemini.inject(noKey);
    expect(noKey.path).toBe("/v1beta/models?alt=json");
  });

  it("gemini owns generativelanguage.googleapis.com ahead of gcp", async () => {
    const registry = await buildRegistry();
    const ids = registry.resolveHostCandidates("generativelanguage.googleapis.com").map((i) => i.id);
    expect(ids).toEqual(["gemini", "gcp"]);
    // gcp keeps every other *.googleapis.com host and google keeps Workspace.
    expect(registry.resolveHost("storage.googleapis.com")?.id).toBe("gcp");
    expect(registry.resolveHost("gmail.googleapis.com")?.id).toBe("google");
  });
});

import { make } from "../src/integrations/make.js";

describe("make integration", () => {
  const store = new Store(":memory:");

  it("injects the literal Token scheme, not Bearer", () => {
    const ctx = ctxFor("eu1.make.com", cred({ apiToken: "m_1" }, "make"), store);
    make.inject(ctx);
    expect(ctx.headers.authorization).toBe("Token m_1");
  });

  it("throws when the apiToken field is missing", () => {
    expect(() => make.inject(ctxFor("eu1.make.com", cred({}, "make"), store))).toThrow(/apiToken/);
  });

  it("resolves every make.com zone via the dot-suffix host", async () => {
    const registry = await buildRegistry();
    for (const host of ["eu1.make.com", "eu2.make.com", "us1.make.com", "us2.make.com"]) {
      expect(registry.resolveHost(host)?.id).toBe("make");
    }
  });

  it("composes an llm help prompt with the credential hints", () => {
    const p = composeLlmHelpPrompt(make);
    expect(p).toContain("Credential type needed:");
    expect(p).toContain("Where it is created:");
  });
});

describe("host claim resolution is specificity-ordered, not registration-ordered", () => {
  /** Every overlapping host pair in the builtin registry, and its owner. */
  const OVERLAPS: [string, string][] = [
    // google exact Workspace hosts inside gcp's `.googleapis.com` suffix.
    ["gmail.googleapis.com", "google"],
    ["www.googleapis.com", "google"],
    ["drive.googleapis.com", "google"],
    ["admin.googleapis.com", "google"],
    ["people.googleapis.com", "google"],
    ["youtube.googleapis.com", "google"],
    // gemini exact host inside the same suffix.
    ["generativelanguage.googleapis.com", "gemini"],
    // hosts only the suffix claims.
    ["storage.googleapis.com", "gcp"],
    ["compute.googleapis.com", "gcp"],
    ["googleapis.com", "gcp"],
    // slack lists both the apex and the suffix, one owner either way.
    ["slack.com", "slack"],
    ["files.slack.com", "slack"],
    // equally-specific exact pairs keep their registration-order primary.
    ["api.github.com", "github"],
    ["github.com", "github"],
    ["api.atlassian.com", "jira"],
    // suffix-only claims.
    ["acme.atlassian.net", "jira"],
    ["eu1.make.com", "make"],
    ["make.com", "make"],
    ["acme.jfrog.io", "jfrog-artifactory"],
    ["s3.eu-central-1.amazonaws.com", "aws"],
  ];

  it("resolves every overlapping builtin host to its documented owner", async () => {
    const registry = await buildRegistry();
    for (const [host, owner] of OVERLAPS) {
      expect(registry.resolveHost(host)?.id, host).toBe(owner);
    }
  });

  it("puts an exact claim ahead of a covering dot-suffix claim", async () => {
    const registry = await buildRegistry();
    // google/gemini exact beat gcp's `.googleapis.com`. This is the single
    // most important regression: it used to hold only because google and
    // gemini are listed before gcp in BUILTINS.
    expect(registry.resolveHostCandidates("gmail.googleapis.com").map((i) => i.id)).toEqual([
      "google",
      "gcp",
    ]);
    expect(
      registry.resolveHostCandidates("generativelanguage.googleapis.com").map((i) => i.id),
    ).toEqual(["gemini", "gcp"]);
  });

  it("keeps resolution identical when registration order is reversed", async () => {
    const forward = await buildRegistry();
    const reversed = new Registry();
    // Re-register the same integrations back to front. Under the old
    // registration-order lookup this flipped gmail.googleapis.com from google
    // to gcp, silently injecting a GCP service-account token into Workspace
    // traffic. Specificity ordering makes the two registries agree.
    for (const integration of [...forward.list()].reverse()) reversed.register(integration);

    for (const [host, owner] of OVERLAPS) {
      expect(reversed.resolveHost(host)?.id, `${host} (reversed)`).toBe(
        host === "api.github.com" || host === "github.com" || host === "api.atlassian.com"
          ? // Equally specific exact claims tie, so the tiebreak follows the
            // (now reversed) registration order. Specificity cannot separate
            // them, which is exactly why they are declared intentional pairs.
            reversed.resolveHost(host)?.id
          : owner,
      );
      // For everything decided by specificity the two registries must agree.
      if (!["api.github.com", "github.com", "api.atlassian.com"].includes(host)) {
        expect(reversed.resolveHost(host)?.id, `${host} (reversed)`).toBe(
          forward.resolveHost(host)?.id,
        );
      }
    }
  });

  it("resolution is order-independent across many shuffles", async () => {
    const base = await buildRegistry();
    const integrations = base.list();
    const specificityDecided = OVERLAPS.filter(
      ([h]) => !["api.github.com", "github.com", "api.atlassian.com"].includes(h),
    );
    let seed = 42;
    const rand = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    for (let round = 0; round < 25; round++) {
      const shuffled = [...integrations];
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
      }
      const registry = new Registry();
      for (const integration of shuffled) registry.register(integration);
      for (const [host, owner] of specificityDecided) {
        expect(registry.resolveHost(host)?.id, `${host} round ${round}`).toBe(owner);
      }
    }
  });

  it("prefers the longest suffix when two dot-suffix claims overlap", () => {
    const registry = new Registry();
    const broad: Integration = {
      id: "broad",
      title: "Broad",
      hosts: [".example.com"],
      credentialFields: [],
      inject: () => {},
    };
    const narrow: Integration = {
      id: "narrow",
      title: "Narrow",
      hosts: [".eu.example.com"],
      credentialFields: [],
      inject: () => {},
    };
    // Register broad first: the narrower suffix must still win.
    registry.register(broad);
    registry.register(narrow);
    expect(registry.resolveHostCandidates("a.eu.example.com").map((i) => i.id)).toEqual([
      "narrow",
      "broad",
    ]);
    expect(registry.resolveHost("a.us.example.com")?.id).toBe("broad");

    // And the same in the other registration order.
    const flipped = new Registry();
    flipped.register(narrow);
    flipped.register(broad);
    expect(flipped.resolveHostCandidates("a.eu.example.com").map((i) => i.id)).toEqual([
      "narrow",
      "broad",
    ]);
  });

  it("lets an exact claim beat a dot-suffix claim registered first", () => {
    const registry = new Registry();
    const suffix: Integration = {
      id: "suffix-owner",
      title: "Suffix",
      hosts: [".vendor.com"],
      credentialFields: [],
      inject: () => {},
    };
    const exact: Integration = {
      id: "exact-owner",
      title: "Exact",
      hosts: ["api.vendor.com"],
      credentialFields: [],
      inject: () => {},
    };
    registry.register(suffix);
    registry.register(exact);
    expect(registry.resolveHost("api.vendor.com")?.id).toBe("exact-owner");
    expect(registry.resolveHost("other.vendor.com")?.id).toBe("suffix-owner");
  });

  it("keeps an integration's own exact claim ranked above its own suffix", () => {
    const registry = new Registry();
    registry.register({
      id: "both",
      title: "Both",
      hosts: [".vendor.com", "api.vendor.com"],
      credentialFields: [],
      inject: () => {},
    });
    // Listed once only, not twice, whichever entry matched.
    expect(registry.resolveHostCandidates("api.vendor.com").map((i) => i.id)).toEqual(["both"]);
  });

  it("matches host claims case-insensitively on both sides", () => {
    const registry = new Registry();
    registry.register({
      id: "cased",
      title: "Cased",
      hosts: ["API.Vendor.COM", ".Zone.Vendor.COM"],
      credentialFields: [],
      inject: () => {},
    });
    expect(registry.resolveHost("api.vendor.com")?.id).toBe("cased");
    expect(registry.resolveHost("a.zone.vendor.com")?.id).toBe("cased");
  });
});

describe("registration-time exact-host collision guard", () => {
  const claim = (id: string, hosts: string[]): Integration => ({
    id,
    title: id,
    hosts,
    credentialFields: [],
    inject: () => {},
  });

  it("throws when a second integration claims the same exact host", () => {
    const registry = new Registry();
    registry.register(claim("first", ["api.vendor.com"]));
    expect(() => registry.register(claim("second", ["api.vendor.com"]))).toThrow(
      /claims host "api\.vendor\.com" already owned by "first"/,
    );
  });

  it("throws regardless of the case the host is written in", () => {
    const registry = new Registry();
    registry.register(claim("first", ["api.vendor.com"]));
    expect(() => registry.register(claim("second", ["API.VENDOR.COM"]))).toThrow(/already owned/);
  });

  it("allows a suffix claim that merely overlaps an exact claim", () => {
    // Not ambiguous: specificity decides, so this must keep loading.
    const registry = new Registry();
    registry.register(claim("exact", ["api.vendor.com"]));
    expect(() => registry.register(claim("suffixy", [".vendor.com"]))).not.toThrow();
    expect(registry.resolveHost("api.vendor.com")?.id).toBe("exact");
  });

  it("allows two overlapping suffix claims", () => {
    const registry = new Registry();
    registry.register(claim("broad", [".vendor.com"]));
    expect(() => registry.register(claim("narrow", [".eu.vendor.com"]))).not.toThrow();
  });

  it("permits the intentional github / github-app and jira / confluence pairs", async () => {
    // The whole builtin catalog registers without tripping the guard.
    const registry = await buildRegistry();
    expect(registry.resolveHostCandidates("api.github.com").map((i) => i.id)).toEqual([
      "github",
      "github-app",
    ]);
    expect(registry.resolveHostCandidates("api.atlassian.com").map((i) => i.id)).toEqual([
      "jira",
      "confluence",
    ]);
  });

  it("blocks a community integration from shadowing a builtin's exact host", async () => {
    // Issue #75: loadCommunity registers operator-supplied modules after the
    // builtins, so without this guard a community module could claim
    // api.anthropic.com and inject its own header onto LLM egress.
    const registry = await buildRegistry();
    expect(() =>
      registry.register({ ...claim("rogue", ["api.anthropic.com"]), community: true }),
    ).toThrow(/already owned by "anthropic"/);
  });
});
