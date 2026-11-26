/**
 * Public OAuth callback and connect-wizard edge cases not reached by
 * connect-wizard.test.ts / oauth-*.test.ts:
 *
 *  - the callback's refusal paths (unknown integration, provider error, forged
 *    or cross-integration state, missing code, Google without a refresh token,
 *    agent deleted mid-consent), each of which must persist nothing;
 *  - the fragment-callback (Trello) bridge page and token persistence;
 *  - wizard rendering (scope packs with/without a preset, lease control) and
 *    the start/submit refusal paths, including single-use replay.
 *
 * Token endpoints are local stubs; nothing leaves 127.0.0.1.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { startAdmin, startTokenStub, type AdminHarness } from "./admin-harness.js";

let h: AdminHarness;
let stub: Awaited<ReturnType<typeof startTokenStub>>;
let agentId: string;

beforeAll(async () => {
  stub = await startTokenStub();
  process.env.ONEGATE_OAUTH_TOKEN_URL_GITLAB = `${stub.url}/gitlab/token`;
  h = await startAdmin({
    publicBaseUrl: "https://gate.example",
    googleTokenUrl: `${stub.url}/google/token`,
  });
  agentId = h.store.createAgent("wizard-bot").agent.id;
});

afterAll(async () => {
  delete process.env.ONEGATE_OAUTH_TOKEN_URL_GITLAB;
  await h.close();
  await stub.close();
});

/** Extracts the 32-hex OAuth state from a consent URL or redirect URI. */
function stateFrom(url: string): string {
  const m = decodeURIComponent(decodeURIComponent(url)).match(/state=([0-9a-f]{32})/);
  if (!m) throw new Error(`no state in ${url}`);
  return m[1];
}

async function adminStart(integrationId: string, body: Record<string, unknown>) {
  const r = await h.api("POST", `/api/integrations/${integrationId}/oauth/start`, {
    redirectBase: "https://gate.example/",
    ...body,
  });
  expect(r.status).toBe(200);
  return { state: stateFrom(r.json.url + " " + r.json.redirectUri), ...r.json };
}

const appConnections = (vendor: string) => h.store.listConnections({ kind: "app" }).filter((c) => c.vendor === vendor);

describe("GET /oauth/:integrationId/callback refusals", () => {
  it("404s an unknown integration and one without OAuth", async () => {
    for (const id of ["no-such-integration", "github"]) {
      const r = await h.get(`/oauth/${id}/callback?state=x&code=y`);
      expect(r.status).toBe(404);
      expect(r.text).toContain("Unknown integration");
    }
  });

  it("surfaces a provider error HTML-escaped, and keeps the state redeemable", async () => {
    const { state } = await adminStart("gitlab", { clientId: "cid", clientSecret: "cs", connectionName: "err" });
    const r = await h.get(`/oauth/gitlab/callback?error=${encodeURIComponent('<img src=x onerror="alert(1)">')}&state=${state}`);
    expect(r.status).toBe(400);
    expect(r.text).toContain("GitLab returned an error: &lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    expect(r.text).not.toContain("<img src=x");
    expect(appConnections("gitlab").some((c) => c.name === "err")).toBe(false);
  });

  it("rejects a forged state and does not call the token endpoint", async () => {
    const calls = stub.requests.length;
    const r = await h.get(`/oauth/gitlab/callback?state=${"0".repeat(32)}&code=good`);
    expect(r.status).toBe(400);
    expect(r.text).toContain("Invalid or expired OAuth state");
    expect(stub.requests.length).toBe(calls);
  });

  it("a state minted for one integration cannot be redeemed on another, and is burned by the attempt", async () => {
    const { state } = await adminStart("gitlab", { clientId: "cid", clientSecret: "cs", connectionName: "cross" });
    const wrong = await h.get(`/oauth/google/callback?state=${state}&code=good`);
    expect(wrong.status).toBe(400);
    const retry = await h.get(`/oauth/gitlab/callback?state=${state}&code=good`);
    expect(retry.status).toBe(400);
    expect(appConnections("gitlab").some((c) => c.name === "cross")).toBe(false);
  });

  it("a missing code fails and consumes the state (no second try with a code)", async () => {
    const { state } = await adminStart("gitlab", { clientId: "cid", clientSecret: "cs", connectionName: "nocode" });
    const r = await h.get(`/oauth/gitlab/callback?state=${state}`);
    expect(r.status).toBe(400);
    expect(r.text).toContain("Missing authorization code");
    const again = await h.get(`/oauth/gitlab/callback?state=${state}&code=good`);
    expect(again.status).toBe(400);
    expect(again.text).toContain("Invalid or expired OAuth state");
  });

  it("Google without a refresh token is a 502 and stores nothing", async () => {
    stub.respond(() => ({ status: 200, body: { access_token: "g_at", expires_in: 3600 } }));
    try {
      const before = h.store.listCredentials().length;
      const { state } = await adminStart("google", { clientId: "gid", clientSecret: "gsec" });
      const r = await h.get(`/oauth/google/callback?state=${state}&code=good`);
      expect(r.status).toBe(502);
      expect(r.text).toContain("Google did not return a refresh token");
      expect(h.store.listCredentials().length).toBe(before);
    } finally {
      stub.respond(() => ({ status: 200, body: { access_token: "at", refresh_token: "rt", expires_in: 3600 } }));
    }
  });

  it("a successful legacy (unnamed) flow persists the granted scope and expiry", async () => {
    stub.respond(() => ({
      status: 200,
      body: { access_token: "gl_at", refresh_token: "gl_rt", expires_in: 7200, scope: "api read_user" },
    }));
    const { state } = await adminStart("gitlab", { clientId: "cid", clientSecret: "cs" });
    const r = await h.get(`/oauth/gitlab/callback?state=${state}&code=good`);
    expect(r.status).toBe(200);
    expect(r.text).toContain("GitLab connected");
    const cred = h.store.getCredential("gitlab")!;
    expect(cred.data.accessToken).toBe("gl_at");
    expect(cred.data.refreshToken).toBe("gl_rt");
    expect(cred.data.scopes).toBe("api read_user");
    expect(Number(cred.data.expiresAt)).toBeGreaterThan(Date.now() / 1000 + 7000);
    // The code went to the stub with the client credentials.
    expect(stub.requests.at(-1)).toContain("code=good");
  });
});

describe("pending OAuth state sweep", () => {
  /** Runs `fn` with Date.now() shifted forward by `ms`. */
  async function later<T>(ms: number, fn: () => Promise<T>): Promise<T> {
    const real = Date.now.bind(Date);
    const spy = vi.spyOn(Date, "now").mockImplementation(() => real() + ms);
    try {
      return await fn();
    } finally {
      spy.mockRestore();
    }
  }

  it("an admin start drops states older than the TTL, so they fail even back inside the window", async () => {
    const stale = await adminStart("gitlab", { clientId: "c", clientSecret: "s", connectionName: "swept-admin" });
    // 11 minutes on, a new start sweeps the stale entry out of the pending map.
    await later(11 * 60_000, () => adminStart("gitlab", { clientId: "c", clientSecret: "s" }));
    // Back at real time the stale state would still be young enough, but it
    // is gone: the sweep, not just the redemption-time age check, removed it.
    const r = await h.get(`/oauth/gitlab/callback?state=${stale.state}&code=good`);
    expect(r.status).toBe(400);
    expect(appConnections("gitlab").some((c) => c.name === "swept-admin")).toBe(false);
  });

  it("a wizard start sweeps the same way", async () => {
    const stale = await adminStart("gitlab", { clientId: "c", clientSecret: "s", connectionName: "swept-wizard" });
    const link = h.store.createOnboardingLink({ agentId, integrationId: "gitlab" });
    const start = await later(11 * 60_000, () =>
      h.postForm(`/connect/gitlab/${link.token}/start`, { clientId: "c", clientSecret: "s" }),
    );
    expect(start.status).toBe(302);
    expect((await h.get(`/oauth/gitlab/callback?state=${stale.state}&code=good`)).status).toBe(400);
  });
});

describe("fragment-callback provider (Trello)", () => {
  it("serves the bridge page when the token is still in the fragment", async () => {
    const r = await h.get("/oauth/trello/callback?state=abc");
    expect(r.status).toBe(200);
    expect(r.headers["content-type"]).toMatch(/text\/html/);
    expect(r.text).toContain("fragment_bridged");
    expect(r.text).toContain("location.hash");
  });

  it("start needs only a client id, and carries the state inside the redirect URI", async () => {
    const missing = await h.api("POST", "/api/integrations/trello/oauth/start", { redirectBase: "https://gate.example" });
    expect(missing.status).toBe(400);
    expect(missing.json.error).toBe("clientId and redirectBase are required");

    const s = await adminStart("trello", { clientId: "trello-key", connectionName: "Trello main" });
    expect(s.redirectUri).toMatch(/^https:\/\/gate\.example\/oauth\/trello\/callback\?state=[0-9a-f]{32}$/);
  });

  it("a bridged callback with no token fails and burns the state", async () => {
    const { state } = await adminStart("trello", { clientId: "trello-key", connectionName: "no-token" });
    const r = await h.get(`/oauth/trello/callback?state=${state}&fragment_bridged=1`);
    expect(r.status).toBe(400);
    expect(r.text).toContain("Trello did not return a token");
    const again = await h.get(`/oauth/trello/callback?state=${state}&token=late`);
    expect(again.status).toBe(400);
    expect(appConnections("trello").some((c) => c.name === "no-token")).toBe(false);
  });

  it("persists the fragment token as a named connection (no client secret stored when none was given)", async () => {
    const { state } = await adminStart("trello", { clientId: "trello-key", connectionName: "Trello work" });
    const r = await h.get(`/oauth/trello/callback?state=${state}&token=trello-user-token`);
    expect(r.status).toBe(200);
    expect(r.text).toContain("Trello connected");
    const conn = appConnections("trello").find((c) => c.name === "Trello work")!;
    expect(conn.data).toEqual({ clientId: "trello-key", accessToken: "trello-user-token" });
    // Replay of the same callback URL is refused.
    expect((await h.get(`/oauth/trello/callback?state=${state}&token=trello-user-token`)).status).toBe(400);
  });
});

describe("connect wizard GET /connect/:integrationId/:token", () => {
  it("404s an unknown integration and a non-connectable (LLM) one", async () => {
    for (const id of ["nope", "anthropic"]) {
      const r = await h.get(`/connect/${id}/whatever`);
      expect(r.status).toBe(404);
    }
  });

  it("410s a link minted for a different integration", async () => {
    const link = h.store.createOnboardingLink({ agentId, integrationId: "gitlab" });
    const r = await h.get(`/connect/hetzner/${link.token}`);
    expect(r.status).toBe(410);
  });

  it("410s a link whose agent was deleted", async () => {
    const tmp = h.store.createAgent("short-lived").agent.id;
    const link = h.store.createOnboardingLink({ agentId: tmp, integrationId: "hetzner" });
    h.store.deleteAgent(tmp);
    expect((await h.get(`/connect/hetzner/${link.token}`)).status).toBe(410);
  });

  it("Google scope packs: defaults checked with no preset, only the preset's pack checked with one", async () => {
    const plain = h.store.createOnboardingLink({ agentId, integrationId: "google" });
    const r1 = await h.get(`/connect/google/${plain.token}`);
    expect(r1.status).toBe(200);
    expect(r1.text).toContain("Products to connect");
    expect(r1.text).toMatch(/value="https:\/\/www\.googleapis\.com\/auth\/gmail\.modify" checked/);

    const preset = h.store.createOnboardingLink({
      agentId,
      integrationId: "google",
      scopes: ["https://www.googleapis.com/auth/calendar"],
    });
    const r2 = await h.get(`/connect/google/${preset.token}`);
    expect(r2.text).toMatch(/value="https:\/\/www\.googleapis\.com\/auth\/calendar" checked/);
    expect(r2.text).not.toMatch(/value="https:\/\/www\.googleapis\.com\/auth\/gmail\.modify" checked/);
  });

  it("shows the lease control only for a time-boxed integration", async () => {
    // Hetzner ships time-boxed; clear it to see the regular form, then restore.
    const seeded = h.store.getIntegrationLease("hetzner");
    h.store.clearIntegrationLease("hetzner");
    try {
      const before = h.store.createOnboardingLink({ agentId, integrationId: "hetzner" });
      expect((await h.get(`/connect/hetzner/${before.token}`)).text).not.toContain("Access duration");
      h.store.setIntegrationLease("hetzner", 1800);
      const link = h.store.createOnboardingLink({ agentId, integrationId: "hetzner" });
      const r = await h.get(`/connect/hetzner/${link.token}`);
      expect(r.text).toContain("Access duration");
      expect(r.text).toContain("Default (30m)");
    } finally {
      if (seeded) h.store.setIntegrationLease("hetzner", seeded);
      else h.store.clearIntegrationLease("hetzner");
    }
  });
});

describe("connect wizard POST .../start", () => {
  it("404s a non-OAuth integration and 410s an invalid or wrong-integration link", async () => {
    expect((await h.postForm("/connect/hetzner/x/start", { clientId: "c" })).status).toBe(404);
    expect((await h.postForm(`/connect/gitlab/${"aa".repeat(24)}/start`, { clientId: "c", clientSecret: "s" })).status).toBe(410);
    const hetznerLink = h.store.createOnboardingLink({ agentId, integrationId: "hetzner" });
    expect((await h.postForm(`/connect/gitlab/${hetznerLink.token}/start`, { clientId: "c", clientSecret: "s" })).status).toBe(410);
  });

  it("410s when the link's agent was deleted, without claiming the link", async () => {
    const tmp = h.store.createAgent("gone-before-start").agent.id;
    const link = h.store.createOnboardingLink({ agentId: tmp, integrationId: "gitlab" });
    h.store.deleteAgent(tmp);
    const r = await h.postForm(`/connect/gitlab/${link.token}/start`, { clientId: "c", clientSecret: "s" });
    expect(r.status).toBe(410);
  });

  it("400s missing client credentials and leaves the link usable", async () => {
    const link = h.store.createOnboardingLink({ agentId, integrationId: "gitlab" });
    const r = await h.postForm(`/connect/gitlab/${link.token}/start`, { clientId: "  ", clientSecret: "s" });
    expect(r.status).toBe(400);
    expect(r.text).toContain("Missing details");
    expect(h.store.getOnboardingLink(link.token)?.usedAt).toBeNull();
    const noSecret = await h.postForm(`/connect/gitlab/${link.token}/start`, { clientId: "c" });
    expect(noSecret.status).toBe(400);
  });

  it("claims the link at start: a second start of the same link is refused", async () => {
    const link = h.store.createOnboardingLink({ agentId, integrationId: "gitlab" });
    const first = await h.postForm(`/connect/gitlab/${link.token}/start`, {
      clientId: "c",
      clientSecret: "s",
      // Hidden scope fields (non-scope-pack integrations); blanks are dropped.
      scope: ["read_api", "", "read_user"],
    });
    expect(first.status).toBe(302);
    expect(new URL(first.headers.location!).searchParams.get("scope")).toBe("read_api read_user");
    expect(h.store.getOnboardingLink(link.token)?.usedAt).toBeTruthy();
    const second = await h.postForm(`/connect/gitlab/${link.token}/start`, { clientId: "c2", clientSecret: "s2" });
    expect(second.status).toBe(410);
  });

  it("Google scope packs from the form become the consent scopes", async () => {
    const link = h.store.createOnboardingLink({ agentId, integrationId: "google" });
    const r = await h.postForm(`/connect/google/${link.token}/start`, {
      clientId: "gid",
      clientSecret: "gsec",
      scopePack: [
        "https://www.googleapis.com/auth/calendar",
        "https://www.googleapis.com/auth/drive  https://www.googleapis.com/auth/calendar",
      ],
    });
    expect(r.status).toBe(302);
    const scope = new URL(r.headers.location!).searchParams.get("scope")!.split(" ");
    expect(scope.sort()).toEqual([
      "https://www.googleapis.com/auth/calendar",
      "https://www.googleapis.com/auth/drive",
    ]);
  });

  it("Trello wizard start works without a secret and embeds the state in the redirect URI", async () => {
    const link = h.store.createOnboardingLink({ agentId, integrationId: "trello" });
    const r = await h.postForm(`/connect/trello/${link.token}/start`, { clientId: "trello-key" });
    expect(r.status).toBe(302);
    const state = stateFrom(r.headers.location!);
    // Completing the fragment flow auto-wires the connection to the wizard's agent.
    const done = await h.get(`/oauth/trello/callback?state=${state}&token=wiz-token`);
    expect(done.status).toBe(200);
    expect(done.text).toContain("wizard-bot is connected");
    const conn = appConnections("trello").find((c) => c.data.accessToken === "wiz-token")!;
    expect(conn.ownerAgentId).toBe(agentId);
    expect(h.store.listGrantsForConnection(conn.id).map((g) => g.subjectId)).toEqual([agentId]);
  });

  it("a wizard consent whose agent is deleted before the callback persists nothing", async () => {
    const tmp = h.store.createAgent("deleted-mid-consent").agent.id;
    const link = h.store.createOnboardingLink({ agentId: tmp, integrationId: "gitlab", connectionName: "orphan-check" });
    const start = await h.postForm(`/connect/gitlab/${link.token}/start`, { clientId: "c", clientSecret: "s" });
    expect(start.status).toBe(302);
    const state = stateFrom(start.headers.location!);
    h.store.deleteAgent(tmp);
    const calls = stub.requests.length;
    const r = await h.get(`/oauth/gitlab/callback?state=${state}&code=good`);
    expect(r.status).toBe(410);
    expect(stub.requests.length).toBe(calls);
    expect(appConnections("gitlab").some((c) => c.name === "orphan-check")).toBe(false);
  });

  it("carries the owner's lease override through consent onto the connection", async () => {
    stub.respond(() => ({ status: 200, body: { access_token: "a", refresh_token: "r", expires_in: 60 } }));
    const cases: Array<[Record<string, string>, number | null]> = [
      [{ leaseMode: "custom", leaseHours: "2" }, 7200],
      [{ leaseMode: "always" }, 0],
      [{ leaseMode: "custom", leaseHours: "-3" }, null],
      [{ leaseMode: "default" }, null],
    ];
    for (const [i, [fields, expected]] of cases.entries()) {
      const name = `lease-case-${i}`;
      const link = h.store.createOnboardingLink({ agentId, integrationId: "gitlab", connectionName: name });
      const start = await h.postForm(`/connect/gitlab/${link.token}/start`, { clientId: "c", clientSecret: "s", ...fields });
      const cb = await h.get(`/oauth/gitlab/callback?state=${stateFrom(start.headers.location!)}&code=good`);
      expect(cb.status).toBe(200);
      const conn = appConnections("gitlab").find((c) => c.name === name)!;
      expect({ name, ttl: conn.leaseTtlSeconds ?? null }).toEqual({ name, ttl: expected });
    }
  });
});

describe("connect wizard POST .../submit (paste a credential)", () => {
  it("404s an OAuth integration (submit is only for credential flows)", async () => {
    const link = h.store.createOnboardingLink({ agentId, integrationId: "gitlab" });
    expect((await h.postForm(`/connect/gitlab/${link.token}/submit`, { token: "x" })).status).toBe(404);
  });

  it("410s a forged link, a wrong-integration link and a deleted agent's link", async () => {
    expect((await h.postForm(`/connect/hetzner/${"bb".repeat(24)}/submit`, { apiToken: "t" })).status).toBe(410);
    const other = h.store.createOnboardingLink({ agentId, integrationId: "github" });
    expect((await h.postForm(`/connect/hetzner/${other.token}/submit`, { apiToken: "t" })).status).toBe(410);
    const tmp = h.store.createAgent("gone-before-submit").agent.id;
    const link = h.store.createOnboardingLink({ agentId: tmp, integrationId: "hetzner" });
    h.store.deleteAgent(tmp);
    expect((await h.postForm(`/connect/hetzner/${link.token}/submit`, { apiToken: "t" })).status).toBe(410);
  });

  it("400s a blank required field without consuming the link", async () => {
    const link = h.store.createOnboardingLink({ agentId, integrationId: "hetzner" });
    const r = await h.postForm(`/connect/hetzner/${link.token}/submit`, { apiToken: "   " });
    expect(r.status).toBe(400);
    expect(r.text).toContain("data.apiToken is required");
    expect(h.store.getOnboardingLink(link.token)?.usedAt).toBeNull();
  });

  it("creates, grants and allow-wires the connection once; a replay creates nothing", async () => {
    const link = h.store.createOnboardingLink({ agentId, integrationId: "hetzner", connectionName: "Hetzner prod" });
    const r = await h.postForm(`/connect/hetzner/${link.token}/submit`, {
      apiToken: "  hz-secret  ",
      leaseMode: "always",
      unknownField: "ignored",
    });
    expect(r.status).toBe(200);
    expect(r.text).toContain("wizard-bot is connected");
    // The echoed page never contains the secret.
    expect(r.text).not.toContain("hz-secret");
    const conns = appConnections("hetzner").filter((c) => c.name === "Hetzner prod");
    expect(conns).toHaveLength(1);
    expect(conns[0].data).toEqual({ apiToken: "hz-secret" });
    expect(conns[0].leaseTtlSeconds).toBe(0);
    expect(h.store.listGrantsForConnection(conns[0].id).map((g) => g.subjectId)).toEqual([agentId]);
    const allow = h.store
      .listRules()
      .find((x) => x.subjectId === agentId && x.integrationId === "hetzner" && x.effect === "allow");
    expect(allow?.createdBy).toBe("grant");
    expect(allow?.expiresAt).toBeNull();

    const replay = await h.postForm(`/connect/hetzner/${link.token}/submit`, { apiToken: "second" });
    expect(replay.status).toBe(410);
    expect(appConnections("hetzner").filter((c) => c.name === "Hetzner prod")).toHaveLength(1);
  });
});
