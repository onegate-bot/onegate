import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import http from "node:http";
import {
  buildAuthUrl,
  exchangeCode,
  pickTokenFields,
  oauthBearerToken,
  clientCredentialsToken,
} from "../src/integrations/oauth.js";
import type { OAuthDescriptor } from "../src/integrations/types.js";
import { Store } from "../src/store/db.js";
import type { Credential } from "../src/types.js";

function cred(data: Record<string, string>, integrationId = "testx"): Credential {
  return { id: "cr_oauth", integrationId, name: "t", data, createdAt: "" };
}

const base: OAuthDescriptor = {
  authUrl: "https://auth.example.com/authorize",
  tokenUrl: "https://auth.example.com/token",
  defaultScopes: ["read", "write"],
};

describe("buildAuthUrl", () => {
  const params = {
    clientId: "cid",
    redirectUri: "https://gw.example/oauth/testx/callback",
    scopes: ["read", "write"],
    state: "st1",
  };

  it("builds a standard authorization-code URL", () => {
    const u = new URL(buildAuthUrl("testx", base, params));
    expect(u.origin + u.pathname).toBe("https://auth.example.com/authorize");
    expect(u.searchParams.get("client_id")).toBe("cid");
    expect(u.searchParams.get("redirect_uri")).toBe(params.redirectUri);
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("scope")).toBe("read write");
    expect(u.searchParams.get("state")).toBe("st1");
  });

  it("honors extra params and custom scope separators (Todoist style)", () => {
    const u = new URL(
      buildAuthUrl(
        "testx",
        { ...base, scopeSeparator: ",", extraAuthParams: { access_type: "offline" } },
        params,
      ),
    );
    expect(u.searchParams.get("scope")).toBe("read,write");
    expect(u.searchParams.get("access_type")).toBe("offline");
  });

  it("can omit the scope param entirely (Monday style)", () => {
    const u = new URL(buildAuthUrl("testx", { ...base, omitScopeParam: true }, params));
    expect(u.searchParams.has("scope")).toBe(false);
  });

  it("supports fragment providers with renamed params (Trello style)", () => {
    const u = new URL(
      buildAuthUrl(
        "testx",
        {
          ...base,
          clientIdParam: "key",
          redirectUriParam: "return_url",
          responseType: "token",
          scopeSeparator: ",",
          extraAuthParams: { callback_method: "fragment", expiration: "never" },
          fragmentCallback: { paramName: "token" },
        },
        params,
      ),
    );
    expect(u.searchParams.get("key")).toBe("cid");
    expect(u.searchParams.get("return_url")).toBe(params.redirectUri);
    expect(u.searchParams.get("response_type")).toBe("token");
    expect(u.searchParams.get("callback_method")).toBe("fragment");
  });
});

describe("pickTokenFields", () => {
  it("maps string extras and skips reserved keys, empties and non-strings", () => {
    const oauth: OAuthDescriptor = {
      ...base,
      persistTokenFields: {
        instance_url: "instanceUrl",
        a: "accessToken",
        r: "refreshToken",
        e: "expiresAt",
        s: "scopes",
        id: "clientId",
        n: "num",
        z: "empty",
      },
    };
    expect(
      pickTokenFields(oauth, {
        instance_url: "https://x.example",
        a: "1",
        r: "2",
        e: "3",
        s: "4",
        id: "5",
        n: 7,
        z: "",
      }),
    ).toEqual({ instanceUrl: "https://x.example" });
    expect(pickTokenFields(base, { instance_url: "x" })).toEqual({});
  });
});

describe("token endpoint flows", () => {
  let server: http.Server;
  let url: string;
  let lastReq: { headers: http.IncomingHttpHeaders; body: string; contentType?: string };
  let respond: (
    req: typeof lastReq,
  ) => { status: number; body: unknown } | Promise<{ status: number; body: unknown }>;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        lastReq = { headers: req.headers, body, contentType: req.headers["content-type"] };
        void (async () => {
          try {
            const out = await respond(lastReq);
            res.writeHead(out.status, { "content-type": "application/json" });
            res.end(JSON.stringify(out.body));
          } catch (err) {
            res.writeHead(500, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: String(err) }));
          }
        })();
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    url = `http://127.0.0.1:${port}/token`;
  });

  afterAll(() => server.close());

  beforeEach(() => {
    respond = () => ({ status: 200, body: { access_token: "at", expires_in: 3600 } });
  });

  const descriptor = (extra: Partial<OAuthDescriptor> = {}): OAuthDescriptor => ({
    ...base,
    tokenUrl: url,
    ...extra,
  });

  const exchangeParams = {
    code: "c1",
    clientId: "cid",
    clientSecret: "cs",
    redirectUri: "https://gw.example/oauth/testx/callback",
  };

  it("exchanges a code with form encoding and body client auth", async () => {
    const tokens = await exchangeCode("testx", descriptor(), exchangeParams);
    expect(tokens.access_token).toBe("at");
    const form = new URLSearchParams(lastReq.body);
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("code")).toBe("c1");
    expect(form.get("client_id")).toBe("cid");
    expect(form.get("client_secret")).toBe("cs");
    expect(form.get("redirect_uri")).toBe(exchangeParams.redirectUri);
    expect(lastReq.contentType).toContain("application/x-www-form-urlencoded");
  });

  it("supports JSON token requests (Atlassian style)", async () => {
    await exchangeCode("testx", descriptor({ tokenFormat: "json" }), exchangeParams);
    expect(lastReq.contentType).toContain("application/json");
    expect(JSON.parse(lastReq.body).code).toBe("c1");
  });

  it("supports HTTP Basic client auth (Supabase style)", async () => {
    await exchangeCode("testx", descriptor({ tokenAuth: "basic" }), exchangeParams);
    const expected = "Basic " + Buffer.from("cid:cs").toString("base64");
    expect(lastReq.headers.authorization).toBe(expected);
    expect(new URLSearchParams(lastReq.body).has("client_secret")).toBe(false);
  });

  it("can omit redirect_uri in the exchange (Todoist style)", async () => {
    await exchangeCode("testx", descriptor({ sendRedirectUriInExchange: false }), exchangeParams);
    expect(new URLSearchParams(lastReq.body).has("redirect_uri")).toBe(false);
  });

  it("surfaces provider errors with status and body", async () => {
    respond = () => ({ status: 400, body: { error: "invalid_grant" } });
    await expect(exchangeCode("testx", descriptor(), exchangeParams)).rejects.toThrow(
      /Token exchange failed \(400\)/,
    );
  });

  it("rejects 200 responses without an access token", async () => {
    respond = () => ({ status: 200, body: { error_description: "nope" } });
    await expect(exchangeCode("testx", descriptor(), exchangeParams)).rejects.toThrow(/nope/);
  });

  describe("oauthBearerToken", () => {
    let store: Store;
    beforeEach(() => {
      store = new Store(":memory:");
    });

    const integ = (extra: Partial<OAuthDescriptor> = {}) => ({
      id: "testx",
      oauth: descriptor(extra),
    });

    it("returns long-lived tokens without a refresh token as is", async () => {
      const t = await oauthBearerToken(integ(), cred({ accessToken: "long_lived" }), store);
      expect(t).toBe("long_lived");
    });

    it("throws when there is nothing to work with", async () => {
      await expect(oauthBearerToken(integ(), cred({}), store)).rejects.toThrow(/accessToken/);
    });

    it("uses a stored access token that is still fresh", async () => {
      respond = () => {
        throw new Error("should not refresh");
      };
      const fresh = String(Math.floor(Date.now() / 1000) + 3600);
      const t = await oauthBearerToken(
        integ(),
        cred({
          clientId: "cid",
          clientSecret: "cs",
          accessToken: "still_good",
          refreshToken: "rt",
          expiresAt: fresh,
        }),
        store,
      );
      expect(t).toBe("still_good");
    });

    it("refreshes expired tokens and serves the next call from cache", async () => {
      let calls = 0;
      respond = (req) => {
        calls++;
        const form = new URLSearchParams(req.body);
        expect(form.get("grant_type")).toBe("refresh_token");
        expect(form.get("refresh_token")).toBe("rt");
        return { status: 200, body: { access_token: `at_${calls}`, expires_in: 3600 } };
      };
      const stale = String(Math.floor(Date.now() / 1000) - 10);
      const c = store.setCredential("testx", "t", {
        clientId: "cid",
        clientSecret: "cs",
        accessToken: "old",
        refreshToken: "rt",
        expiresAt: stale,
      });
      expect(await oauthBearerToken(integ(), c, store)).toBe("at_1");
      expect(await oauthBearerToken(integ(), c, store)).toBe("at_1");
      expect(calls).toBe(1);
    });

    it("persists rotated refresh tokens (GitLab style)", async () => {
      respond = () => ({
        status: 200,
        body: { access_token: "at_new", refresh_token: "rt_rotated", expires_in: 7200 },
      });
      const c = store.setCredential("testx", "t", { clientId: "cid", clientSecret: "cs", refreshToken: "rt" });
      await oauthBearerToken(integ(), c, store);
      const saved = store.getCredential("testx");
      expect(saved?.data.refreshToken).toBe("rt_rotated");
      expect(store.getSecretSetting<{ token: string }>(`oauth_access_token:testx:${c.id}`)!.token).toBe("at_new");
    });

    it("assumes the descriptor's default lifetime when expires_in is absent (Salesforce style)", async () => {
      respond = () => ({ status: 200, body: { access_token: "no_exp" } });
      const c = store.setCredential("testx", "t", { clientId: "cid", clientSecret: "cs", refreshToken: "rt" });
      expect(await oauthBearerToken(integ({ defaultExpiresIn: 600 }), c, store)).toBe("no_exp");
      const cached = store.getSecretSetting<{ exp: number }>(`oauth_access_token:testx:${c.id}`)!;
      expect(cached.exp - Date.now()).toBeLessThanOrEqual(600_000);
      expect(cached.exp - Date.now()).toBeGreaterThan(590_000);
    });

    it("falls back to an hour when neither expires_in nor a default is given", async () => {
      respond = () => ({ status: 200, body: { access_token: "no_exp" } });
      const c = store.setCredential("testx", "t", { clientId: "cid", clientSecret: "cs", refreshToken: "rt" });
      await oauthBearerToken(integ(), c, store);
      const cached = store.getSecretSetting<{ exp: number }>(`oauth_access_token:testx:${c.id}`)!;
      expect(cached.exp - Date.now()).toBeGreaterThan(3_590_000);
    });

    it("re-applies persistTokenFields on refresh but never overwrites reserved keys", async () => {
      respond = () => ({
        status: 200,
        body: { access_token: "at_x", instance_url: "https://new.example", evil: "pwned" },
      });
      const c = store.setCredential("testx", "t", {
        clientId: "cid",
        clientSecret: "cs",
        refreshToken: "rt",
        instanceUrl: "https://old.example",
      });
      await oauthBearerToken(
        integ({ persistTokenFields: { instance_url: "instanceUrl", evil: "clientSecret" } }),
        c,
        store,
      );
      const saved = store.getCredential("testx")!.data;
      expect(saved.instanceUrl).toBe("https://new.example");
      expect(saved.clientSecret).toBe("cs");
    });

    it("does not cache the token of a legacy credential deleted mid-refresh", async () => {
      const c = store.setCredential("testx", "t", { clientId: "cid", clientSecret: "cs", refreshToken: "rt" });
      respond = () => {
        store.deleteCredential("testx");
        return { status: 200, body: { access_token: "at_deleted", refresh_token: "rt2", expires_in: 3600 } };
      };
      await oauthBearerToken(integ(), c, store);
      expect(store.getCredential("testx")).toBeNull();
      expect(store.getSecretSetting(`oauth_access_token:testx:${c.id}`)).toBeNull();
    });

    it("deleteCredential purges the credential's cached access token", async () => {
      const c = store.setCredential("testx", "t", { clientId: "cid", clientSecret: "cs", refreshToken: "rt" });
      respond = () => ({ status: 200, body: { access_token: "at_live", expires_in: 3600 } });
      await oauthBearerToken(integ(), c, store);
      expect(store.getSecretSetting(`oauth_access_token:testx:${c.id}`)).not.toBeNull();
      store.deleteCredential("testx");
      expect(store.getSecretSetting(`oauth_access_token:testx:${c.id}`)).toBeNull();
      store.deleteCredential("testx"); // no row: a no-op
    });

    it("never resurrects a deleted legacy credential from a refresh", async () => {
      respond = () => ({ status: 200, body: { access_token: "at_x", refresh_token: "rt_rotated" } });
      const c = cred({ clientId: "cid", clientSecret: "cs", refreshToken: "rt" });
      await oauthBearerToken(integ(), c, store);
      expect(store.getCredential("testx")).toBeNull();
    });

    it("applies only the refresh delta onto the row as it is now (concurrent edit kept)", async () => {
      const c = store.setCredential("testx", "t", {
        clientId: "cid",
        clientSecret: "cs",
        refreshToken: "rt",
        instanceUrl: "https://old.example",
      });
      respond = () => {
        // An admin edit lands while the token request is in flight.
        store.setCredential("testx", "t", { ...c.data, clientSecret: "cs_rotated_by_admin" });
        return { status: 200, body: { access_token: "at_x", refresh_token: "rt2", instance_url: "https://new.example" } };
      };
      await oauthBearerToken(integ({ persistTokenFields: { instance_url: "instanceUrl" } }), c, store);
      expect(store.getCredential("testx")!.data).toEqual({
        clientId: "cid",
        clientSecret: "cs_rotated_by_admin",
        refreshToken: "rt2",
        instanceUrl: "https://new.example",
      });
    });

    it("never resurrects a connection deleted mid-refresh, and does not cache its token", async () => {
      const conn = store.createConnection({
        kind: "app",
        vendor: "testx",
        name: "work",
        data: { clientId: "cid", clientSecret: "cs", refreshToken: "rt" },
      });
      respond = () => {
        store.deleteConnection(conn.id);
        return { status: 200, body: { access_token: "at_revoked", refresh_token: "rt_rotated", expires_in: 3600 } };
      };
      const c: Credential = { id: conn.id, integrationId: "testx", name: conn.name, data: { ...conn.data }, createdAt: "" };
      await oauthBearerToken(integ(), c, store);
      expect(store.getConnection(conn.id)).toBeNull();
      expect(store.getCredential("testx")).toBeNull();
      expect(store.getSecretSetting(`oauth_access_token:testx:${conn.id}`)).toBeNull();
    });

    it("persists the delta onto a live connection", async () => {
      const conn = store.createConnection({
        kind: "app",
        vendor: "testx",
        name: "work",
        data: { clientId: "cid", clientSecret: "cs", refreshToken: "rt" },
      });
      respond = () => ({ status: 200, body: { access_token: "at_c", refresh_token: "rt_c2", expires_in: 3600 } });
      const c: Credential = { id: conn.id, integrationId: "testx", name: conn.name, data: { ...conn.data }, createdAt: "" };
      expect(await oauthBearerToken(integ(), c, store)).toBe("at_c");
      expect(store.getConnection(conn.id)!.data.refreshToken).toBe("rt_c2");
      // Writing the rotated refresh token must not purge the token just minted.
      expect(store.getSecretSetting<{ token: string }>(`oauth_access_token:testx:${conn.id}`)!.token).toBe("at_c");
      expect(store.getCredential("testx")).toBeNull();
    });

    it("does not rewrite the credential when nothing changed", async () => {
      respond = () => ({ status: 200, body: { access_token: "at_x", instance_url: "https://same.example" } });
      const c = cred({ clientId: "cid", clientSecret: "cs", refreshToken: "rt", instanceUrl: "https://same.example" });
      await oauthBearerToken(integ({ persistTokenFields: { instance_url: "instanceUrl" } }), c, store);
      expect(store.getCredential("testx")).toBeNull();
    });

    it("surfaces refresh failures", async () => {
      respond = () => ({ status: 401, body: { error: "invalid_client" } });
      const c = cred({ clientId: "cid", clientSecret: "cs", refreshToken: "rt" });
      await expect(oauthBearerToken(integ(), c, store)).rejects.toThrow(/token refresh failed/);
    });

    it("coalesces concurrent refreshes into a single exchange (rotating provider)", async () => {
      // A rotating provider consumes the presented refresh token, so a second
      // concurrent exchange would present an already-used token and be
      // rejected. The single flight must collapse both callers onto one POST.
      let calls = 0;
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      respond = async (req) => {
        calls++;
        expect(new URLSearchParams(req.body).get("refresh_token")).toBe("rt");
        // Hold the first exchange open so the second caller arrives mid-flight.
        await gate;
        return {
          status: 200,
          body: {
            access_token: `at_${calls}`,
            refresh_token: `rt_rotated_${calls}`,
            expires_in: 3600,
          },
        };
      };
      const c = store.setCredential("testx", "t", { clientId: "cid", clientSecret: "cs", refreshToken: "rt" });

      const first = oauthBearerToken(integ(), c, store);
      const second = oauthBearerToken(integ(), c, store);
      // Give the second caller a tick to reach the refresh path before the
      // first one is allowed to finish.
      await new Promise((r) => setTimeout(r, 20));
      release();
      const [a, b] = await Promise.all([first, second]);

      expect(calls).toBe(1);
      expect(a).toBe("at_1");
      expect(b).toBe(a);
      // The winner's rotated token must survive, not be clobbered by a loser.
      expect(store.getCredential("testx")?.data.refreshToken).toBe("rt_rotated_1");
    });

    it("clears the in-flight entry after a failure so later refreshes retry", async () => {
      respond = () => ({ status: 401, body: { error: "invalid_client" } });
      const c = cred({ clientId: "cid", clientSecret: "cs", refreshToken: "rt" });
      await expect(oauthBearerToken(integ(), c, store)).rejects.toThrow(/token refresh failed/);
      // A poisoned map would replay the rejected promise instead of retrying.
      respond = () => ({ status: 200, body: { access_token: "at_after", expires_in: 3600 } });
      expect(await oauthBearerToken(integ(), c, store)).toBe("at_after");
    });
  });

  describe("clientCredentialsToken", () => {
    it("mints with Basic auth and caches", async () => {
      let calls = 0;
      respond = (req) => {
        calls++;
        expect(req.headers.authorization).toBe(
          "Basic " + Buffer.from("svc_id:svc_secret").toString("base64"),
        );
        expect(new URLSearchParams(req.body).get("grant_type")).toBe("client_credentials");
        return { status: 200, body: { access_token: "cc_at", expires_in: 3600 } };
      };
      const store = new Store(":memory:");
      const c = store.setCredential("testx", "t", { clientId: "svc_id", clientSecret: "svc_secret" });
      expect(await clientCredentialsToken("testx", url, c, store)).toBe("cc_at");
      expect(await clientCredentialsToken("testx", url, c, store)).toBe("cc_at");
      expect(calls).toBe(1);
    });

    it("sends a caller-supplied grant body (Zoom account_credentials style)", async () => {
      respond = (req) => {
        const form = new URLSearchParams(req.body);
        expect(form.get("grant_type")).toBe("account_credentials");
        expect(form.get("account_id")).toBe("acct");
        return { status: 200, body: { access_token: "acct_at", expires_in: 3600 } };
      };
      const store = new Store(":memory:");
      const c = cred({ clientId: "svc_id", clientSecret: "svc_secret" });
      expect(
        await clientCredentialsToken("testx", url, c, store, {
          grant_type: "account_credentials",
          account_id: "acct",
        }),
      ).toBe("acct_at");
    });

    it("labels errors client_credentials when the body has no grant_type", async () => {
      respond = () => ({ status: 401, body: { error: "invalid_client" } });
      const store = new Store(":memory:");
      const c = cred({ clientId: "svc_id", clientSecret: "svc_secret" });
      await expect(
        clientCredentialsToken("testx", url, c, store, { audience: "x" }),
      ).rejects.toThrow(/testx client_credentials grant failed \(401\)/);
    });

    it("requires both client id and secret", async () => {
      const store = new Store(":memory:");
      await expect(
        clientCredentialsToken("testx", url, cred({ clientId: "only" }), store),
      ).rejects.toThrow(/clientSecret/);
    });
  });
});
