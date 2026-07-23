import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import http from "node:http";
import {
  buildAuthUrl,
  exchangeCode,
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

describe("token endpoint flows", () => {
  let server: http.Server;
  let url: string;
  let lastReq: { headers: http.IncomingHttpHeaders; body: string; contentType?: string };
  let respond: (req: typeof lastReq) => { status: number; body: unknown };

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        lastReq = { headers: req.headers, body, contentType: req.headers["content-type"] };
        const out = respond(lastReq);
        res.writeHead(out.status, { "content-type": "application/json" });
        res.end(JSON.stringify(out.body));
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
      const c = cred({
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
      const c = cred({ clientId: "cid", clientSecret: "cs", refreshToken: "rt" });
      await oauthBearerToken(integ(), c, store);
      const saved = store.getCredential("testx");
      expect(saved?.data.refreshToken).toBe("rt_rotated");
    });

    it("surfaces refresh failures", async () => {
      respond = () => ({ status: 401, body: { error: "invalid_client" } });
      const c = cred({ clientId: "cid", clientSecret: "cs", refreshToken: "rt" });
      await expect(oauthBearerToken(integ(), c, store)).rejects.toThrow(/token refresh failed/);
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
      const c = cred({ clientId: "svc_id", clientSecret: "svc_secret" });
      expect(await clientCredentialsToken("testx", url, c, store)).toBe("cc_at");
      expect(await clientCredentialsToken("testx", url, c, store)).toBe("cc_at");
      expect(calls).toBe(1);
    });

    it("requires both client id and secret", async () => {
      const store = new Store(":memory:");
      await expect(
        clientCredentialsToken("testx", url, cred({ clientId: "only" }), store),
      ).rejects.toThrow(/clientSecret/);
    });
  });
});
