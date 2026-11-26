/**
 * Regression tests for admin API input hardening:
 *
 *  - repeated query keys on the public OAuth callback no longer crash it;
 *  - a final error handler answers generically (never a stack trace or a
 *    server path) on both /api and public pages, keeping body-parser 4xx codes;
 *  - POST /api/rules validates scope, effect, pathGlob and ttlSeconds;
 *  - agent defaultPolicy is allow-all | deny-unmatched;
 *  - integration lease ttlSeconds is a JSON integer in (0, 10 years];
 *  - an absurd wizard leaseHours falls back to the integration default.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import http from "node:http";
import { Store } from "../src/store/db.js";
import { buildRegistry } from "../src/integrations/index.js";
import { createAdminApp, ensureAdminToken, MAX_TTL_SECONDS } from "../src/admin/api.js";

let store: Store;
let server: http.Server;
let port: number;
let token: string;
let agentId: string;

interface Res {
  status: number;
  text: string;
  json: any;
}

function request(method: string, path: string, opts: { body?: string; type?: string; auth?: boolean } = {}): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path,
        agent: false,
        headers: {
          ...(opts.body !== undefined
            ? { "content-type": opts.type ?? "application/json", "content-length": Buffer.byteLength(opts.body) }
            : {}),
          ...(opts.auth === false ? {} : { authorization: `Bearer ${token}` }),
        },
      },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          let json: any = null;
          try {
            json = JSON.parse(text);
          } catch {
            /* html */
          }
          resolve({ status: res.statusCode ?? 0, text, json });
        });
      },
    );
    req.on("error", reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

const api = (method: string, path: string, body?: unknown) =>
  request(method, path, body === undefined ? {} : { body: JSON.stringify(body) });

/** No stack frame, no absolute path, no exception class name in a response. */
function expectNoLeak(r: Res): void {
  expect(r.text).not.toMatch(/\bat [\w.<>]+ \(/);
  expect(r.text).not.toContain(process.cwd());
  expect(r.text).not.toMatch(/TypeError|RangeError|SqliteError|CHECK constraint/);
}

beforeAll(async () => {
  store = new Store(":memory:");
  token = ensureAdminToken(store)!;
  const app = createAdminApp({
    store,
    registry: await buildRegistry(),
    ca: { rootPem: "pem" } as never,
    version: "test",
    publicBaseUrl: "https://gate.example",
  });
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as { port: number }).port;
  agentId = store.createAgent("hardening-bot").agent.id;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  store.close();
});

describe("public OAuth callback query handling", () => {
  it("a repeated error param is answered with the first value, not a crash", async () => {
    const r = await request("GET", "/oauth/gitlab/callback?error=access_denied&error=%3Cb%3E", { auth: false });
    expect(r.status).toBe(400);
    expect(r.text).toContain("GitLab returned an error: access_denied");
    expectNoLeak(r);
  });

  it("repeated state / code params cannot smuggle an array into the state lookup", async () => {
    const r = await request("GET", "/oauth/gitlab/callback?state=a&state=b&code=x&code=y", { auth: false });
    expect(r.status).toBe(400);
    expect(r.text).toContain("Invalid or expired OAuth state");
    const bracket = await request("GET", "/oauth/gitlab/callback?error[k]=v&state[x]=1", { auth: false });
    expect(bracket.status).toBe(400);
    expectNoLeak(bracket);
  });
});

describe("final error handler", () => {
  it("an unexpected failure on an /api route is a generic JSON 500, logged server-side", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const orig = store.listProjects.bind(store);
    store.listProjects = () => {
      throw new Error("disk I/O error at /secret/path/onegate.db");
    };
    try {
      const r = await api("GET", "/api/projects");
      expect(r.status).toBe(500);
      expect(r.json).toEqual({ error: "internal_error" });
      expect(r.text).not.toContain("/secret/path");
      expect(err).toHaveBeenCalledWith(expect.stringContaining("disk I/O error"));
    } finally {
      store.listProjects = orig;
      err.mockRestore();
    }
  });

  it("an unexpected failure on a public page is a generic HTML 500", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const orig = store.getApprovalByToken.bind(store);
    store.getApprovalByToken = () => {
      throw new TypeError("boom in /secret/path");
    };
    try {
      const r = await request("GET", "/approve/abc", { auth: false });
      expect(r.status).toBe(500);
      expect(r.text).toContain("Something went wrong");
      expect(r.text).not.toContain("/secret/path");
      expectNoLeak(r);
    } finally {
      store.getApprovalByToken = orig;
      err.mockRestore();
    }
  });

  it("malformed JSON keeps its 400, with a generic code and no parser trace", async () => {
    const r = await request("POST", "/api/agents", { body: '{"name": ' });
    expect(r.status).toBe(400);
    expect(r.json).toEqual({ error: "invalid_json" });
    expectNoLeak(r);
  });

  it("an oversized public form keeps its 413 as a plain page", async () => {
    const r = await request("POST", "/connect/hetzner/x/submit", {
      body: `apiToken=${"a".repeat(600 * 1024)}`,
      type: "application/x-www-form-urlencoded",
      auth: false,
    });
    expect(r.status).toBe(413);
    expect(r.text).toContain("Bad request");
    expectNoLeak(r);
  });
});

describe("POST /api/rules validation", () => {
  const base = () => ({ scope: "agent", subjectId: agentId, integrationId: "github", effect: "allow" });

  it.each([
    [{ scope: "tenant" }, "invalid_scope"],
    [{ effect: "maybe" }, "invalid_effect"],
    [{ effect: "ALLOW" }, "invalid_effect"],
    [{ pathGlob: 5 }, "invalid_path_glob"],
    [{ pathGlob: "repos/**" }, "invalid_path_glob"],
    [{ pathGlob: ["/a"] }, "invalid_path_glob"],
    [{ ttlSeconds: 1e20 }, "invalid_ttl_seconds"],
    [{ ttlSeconds: MAX_TTL_SECONDS + 1 }, "invalid_ttl_seconds"],
    [{ ttlSeconds: -1 }, "invalid_ttl_seconds"],
    [{ ttlSeconds: true }, "invalid_ttl_seconds"],
    [{ ttlSeconds: "soon" }, "invalid_ttl_seconds"],
    [{ ttlSeconds: "" }, "invalid_ttl_seconds"],
  ])("refuses %j with %s and stores nothing", async (patch, error) => {
    const before = store.listRules().length;
    const r = await api("POST", "/api/rules", { ...base(), ...patch });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe(error);
    expectNoLeak(r);
    expect(store.listRules().length).toBe(before);
  });

  it("still accepts the defaults, a wildcard glob and the maximum lease", async () => {
    const plain = await api("POST", "/api/rules", base());
    expect(plain.status).toBe(201);
    expect(plain.json.pathGlob).toBe("/**");
    const star = await api("POST", "/api/rules", { ...base(), pathGlob: "**" });
    expect(star.status).toBe(201);
    const max = await api("POST", "/api/rules", { ...base(), ttlSeconds: MAX_TTL_SECONDS });
    expect(max.status).toBe(201);
    expect(max.json.leaseTtlSeconds).toBe(MAX_TTL_SECONDS);
    const none = await api("POST", "/api/rules", { ...base(), ttlSeconds: 0 });
    expect(none.json.expiresAt).toBeNull();
  });
});

describe("agent defaultPolicy", () => {
  it("rejects an unknown policy on create and update", async () => {
    const before = store.listAgents().length;
    const c = await api("POST", "/api/agents", { name: "policy-bad", defaultPolicy: "bogus" });
    expect(c.status).toBe(400);
    expect(c.json.error).toBe("invalid_default_policy");
    expect(store.listAgents().length).toBe(before);
    const u = await api("PATCH", `/api/agents/${agentId}`, { defaultPolicy: "allow" });
    expect(u.status).toBe(400);
    expect(store.getAgent(agentId)?.defaultPolicy).toBe("deny-unmatched");
  });

  it("accepts both valid policies and an omitted one", async () => {
    const c = await api("POST", "/api/agents", { name: "policy-ok", defaultPolicy: "allow-all" });
    expect(c.status).toBe(201);
    expect(c.json.defaultPolicy).toBe("allow-all");
    const u = await api("PATCH", `/api/agents/${c.json.id}`, { defaultPolicy: "deny-unmatched" });
    expect(u.json.defaultPolicy).toBe("deny-unmatched");
    const n = await api("PATCH", `/api/agents/${c.json.id}`, { name: "policy-ok-2" });
    expect(n.json.defaultPolicy).toBe("deny-unmatched");
  });
});

describe("integration lease ttlSeconds", () => {
  it.each([true, "3600", 1e300, MAX_TTL_SECONDS + 1, 1.5, -60, {}])("refuses %j", async (ttlSeconds) => {
    store.setIntegrationLease("github", 600);
    const r = await api("PUT", "/api/integration-leases/github", { ttlSeconds });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("ttl_seconds_positive_integer_required");
    expect(store.getIntegrationLease("github")).toBe(600);
  });

  it("accepts the maximum and still clears with 0, '0' and null", async () => {
    expect((await api("PUT", "/api/integration-leases/github", { ttlSeconds: MAX_TTL_SECONDS })).status).toBe(200);
    expect(store.getIntegrationLease("github")).toBe(MAX_TTL_SECONDS);
    for (const clear of [0, "0", null]) {
      store.setIntegrationLease("github", 60);
      const r = await api("PUT", "/api/integration-leases/github", { ttlSeconds: clear });
      expect(r.json).toEqual({ integrationId: "github", ttlSeconds: null });
    }
  });
});

describe("wizard lease override cap", () => {
  it("an absurd custom leaseHours falls back to the integration default instead of failing", async () => {
    const link = store.createOnboardingLink({ agentId, integrationId: "hetzner", connectionName: "huge-lease" });
    const r = await request("POST", `/connect/hetzner/${link.token}/submit`, {
      body: new URLSearchParams({ apiToken: "hz", leaseMode: "custom", leaseHours: "1e12" }).toString(),
      type: "application/x-www-form-urlencoded",
      auth: false,
    });
    expect(r.status).toBe(200);
    const conn = store.listConnections({ kind: "app" }).find((c) => c.name === "huge-lease")!;
    expect(conn.leaseTtlSeconds ?? null).toBeNull();
  });
});
