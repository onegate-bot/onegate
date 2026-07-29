/**
 * Owner-supplied instance origin for self-hosted integrations.
 *
 * Four layers are covered here, in the order a request meets them:
 *   1. normalizeInstanceOrigin  - syntax and SSRF guards on the supplied origin
 *   2. Registry                 - the origin's host resolves to the integration
 *   3. Store                    - persistence, uniqueness, back-compat
 *   4. Admin API                - support/reserved-host/conflict validation
 *
 * The SSRF block is deliberately exhaustive rather than representative: this
 * feature widens the set of hosts OneGate will terminate TLS for and inject a
 * secret into, so every range we claim to block gets an explicit assertion.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/store/db.js";
import { initCa } from "../src/ca.js";
import { buildRegistry } from "../src/integrations/index.js";
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";
import { normalizeInstanceOrigin, isBlockedAddress } from "../src/util/instance-origin.js";

/** Unwraps a success, failing loudly if validation rejected the input. */
function ok(raw: string): { origin: string; host: string } {
  const r = normalizeInstanceOrigin(raw);
  if ("error" in r) throw new Error(`expected ${raw} to be accepted, got ${r.error.code}`);
  return r;
}

/** Unwraps a rejection, failing loudly if validation accepted the input. */
function err(raw: unknown): string {
  const r = normalizeInstanceOrigin(raw);
  if (!("error" in r)) throw new Error(`expected rejection, got ${JSON.stringify(r)}`);
  return r.error.code;
}

describe("normalizeInstanceOrigin: accepted shapes", () => {
  it("accepts a plain https origin and canonicalizes it", () => {
    expect(ok("https://gitlab.acme.example")).toEqual({
      origin: "https://gitlab.acme.example",
      host: "gitlab.acme.example",
    });
  });

  it("strips a bare trailing slash and lowercases the host", () => {
    // A pasted URL almost always carries the trailing slash, and casing in a
    // hostname is not significant. Both must land on one canonical string or
    // the uniqueness index can be bypassed by re-typing the same host.
    expect(ok("https://GitLab.ACME.Example/").origin).toBe("https://gitlab.acme.example");
  });

  it("accepts a deep subdomain", () => {
    expect(ok("https://git.eu-west.infra.acme.example").host).toBe("git.eu-west.infra.acme.example");
  });
});

describe("normalizeInstanceOrigin: syntax rejections", () => {
  it("rejects a non-string or empty value", () => {
    expect(err("")).toBe("invalid_instance_origin");
    expect(err("   ")).toBe("invalid_instance_origin");
    expect(err(42)).toBe("invalid_instance_origin");
    expect(err(null)).toBe("invalid_instance_origin");
    expect(err({})).toBe("invalid_instance_origin");
  });

  it("rejects an unparseable value", () => {
    expect(err("not a url")).toBe("invalid_instance_origin");
    expect(err("https://")).toBe("invalid_instance_origin");
  });

  it("rejects any scheme other than https", () => {
    // http would carry the injected secret in clear text over the network.
    expect(err("http://gitlab.acme.example")).toBe("instance_origin_not_https");
    expect(err("ftp://gitlab.acme.example")).toBe("instance_origin_not_https");
    expect(err("file:///etc/passwd")).toBe("instance_origin_not_https");
    expect(err("gopher://gitlab.acme.example")).toBe("instance_origin_not_https");
  });

  it("rejects userinfo", () => {
    // Credentials embedded in the origin would be stored unencrypted and are a
    // classic way to make a URL read as one host while resolving to another.
    expect(err("https://user@gitlab.acme.example")).toBe("instance_origin_has_userinfo");
    expect(err("https://user:pass@gitlab.acme.example")).toBe("instance_origin_has_userinfo");
    expect(err("https://api.github.com@gitlab.acme.example")).toBe("instance_origin_has_userinfo");
  });

  it("rejects a path, query or fragment", () => {
    expect(err("https://gitlab.acme.example/gitlab")).toBe("instance_origin_has_path");
    expect(err("https://gitlab.acme.example/a/b")).toBe("instance_origin_has_path");
    expect(err("https://gitlab.acme.example?x=1")).toBe("instance_origin_has_query");
    expect(err("https://gitlab.acme.example#frag")).toBe("instance_origin_has_fragment");
  });

  it("rejects any explicit non-default port", () => {
    // PORT POLICY: the proxy MITM-terminates port 443 only; every other port is
    // passed through untouched. Storing a ported origin would create a claim
    // that silently never receives its credential.
    expect(err("https://gitlab.acme.example:8443")).toBe("instance_origin_port_unsupported");
    expect(err("https://gitlab.acme.example:80")).toBe("instance_origin_port_unsupported");
    expect(err("https://gitlab.acme.example:8080")).toBe("instance_origin_port_unsupported");
  });

  it("accepts an explicit :443 because it is the port we intercept", () => {
    // WHATWG URL strips the scheme-default port, so ":443" is indistinguishable
    // from no port at all. It normalizes to the bare origin, which is correct:
    // 443 is exactly the port the MITM path handles.
    expect(ok("https://gitlab.acme.example:443").origin).toBe("https://gitlab.acme.example");
  });
});

describe("normalizeInstanceOrigin: SSRF guards", () => {
  it("rejects loopback by name", () => {
    expect(err("https://localhost")).toBe("instance_origin_blocked_host");
    expect(err("https://LOCALHOST")).toBe("instance_origin_blocked_host");
    expect(err("https://ip6-localhost")).toBe("instance_origin_blocked_host");
    expect(err("https://ip6-loopback")).toBe("instance_origin_blocked_host");
    expect(err("https://anything.localhost")).toBe("instance_origin_blocked_host");
  });

  it("rejects .local and single-label intranet names", () => {
    expect(err("https://gitlab.local")).toBe("instance_origin_blocked_host");
    // A dotless name only resolves through a local search domain, so it can
    // never be a legitimate public self-managed deployment.
    expect(err("https://intranet")).toBe("instance_origin_blocked_host");
    expect(err("https://gitlab")).toBe("instance_origin_blocked_host");
  });

  it("rejects loopback IPv4 literals: 127.0.0.0/8", () => {
    expect(err("https://127.0.0.1")).toBe("instance_origin_blocked_host");
    expect(err("https://127.1.2.3")).toBe("instance_origin_blocked_host");
  });

  it("rejects 0.0.0.0 and the 0.0.0.0/8 range", () => {
    expect(err("https://0.0.0.0")).toBe("instance_origin_blocked_host");
    expect(err("https://0.1.2.3")).toBe("instance_origin_blocked_host");
  });

  it("rejects link-local 169.254.0.0/16 including the cloud metadata address", () => {
    // 169.254.169.254 is the single highest-value SSRF target on every major
    // cloud: it serves instance role credentials to anything that can reach it.
    expect(err("https://169.254.169.254")).toBe("instance_origin_blocked_host");
    expect(err("https://169.254.0.1")).toBe("instance_origin_blocked_host");
  });

  it("rejects RFC1918 private ranges 10/8, 172.16/12 and 192.168/16", () => {
    expect(err("https://10.0.0.1")).toBe("instance_origin_blocked_host");
    expect(err("https://10.255.255.255")).toBe("instance_origin_blocked_host");
    expect(err("https://172.16.0.1")).toBe("instance_origin_blocked_host");
    expect(err("https://172.31.255.254")).toBe("instance_origin_blocked_host");
    expect(err("https://192.168.0.1")).toBe("instance_origin_blocked_host");
    expect(err("https://192.168.1.100")).toBe("instance_origin_blocked_host");
  });

  it("rejects IPv6 loopback, unspecified, unique-local fc00::/7 and link-local", () => {
    expect(err("https://[::1]")).toBe("instance_origin_blocked_host");
    expect(err("https://[::]")).toBe("instance_origin_blocked_host");
    expect(err("https://[fc00::1]")).toBe("instance_origin_blocked_host");
    expect(err("https://[fd12:3456:789a::1]")).toBe("instance_origin_blocked_host");
    expect(err("https://[fe80::1]")).toBe("instance_origin_blocked_host");
  });

  it("rejects every IP literal, including public ones", () => {
    // IP LITERAL POLICY: bare literals are rejected outright. A literal cannot
    // generally be covered by a publicly trusted certificate, the private-range
    // blocklist is only meaningful against literals, and a real self-managed
    // enterprise deployment is addressed by a hostname.
    expect(err("https://8.8.8.8")).toBe("instance_origin_blocked_host");
    expect(err("https://1.1.1.1")).toBe("instance_origin_blocked_host");
    expect(err("https://[2606:4700:4700::1111]")).toBe("instance_origin_blocked_host");
  });

  it("rejects decimal, octal and hex encodings of a loopback literal", () => {
    // 2130706433 == 0x7f000001 == 127.0.0.1. A naive dotted-quad-only check
    // lets all three of these straight through to the metadata service.
    expect(err("https://2130706433")).toBe("instance_origin_blocked_host");
    expect(err("https://0177.0.0.1")).toBe("instance_origin_blocked_host");
    expect(err("https://0x7f000001")).toBe("instance_origin_blocked_host");
    expect(err("https://2852039166")).toBe("instance_origin_blocked_host");
  });
});

describe("isBlockedAddress", () => {
  it("blocks every private and special-use range", () => {
    for (const addr of [
      "127.0.0.1",
      "0.0.0.0",
      "10.1.2.3",
      "172.16.5.5",
      "172.31.0.1",
      "192.168.1.1",
      "169.254.169.254",
      "100.64.0.1",
      "::1",
      "::",
      "fc00::1",
      "fd00::abcd",
      "fe80::1",
      "::ffff:127.0.0.1",
      "::ffff:10.0.0.1",
    ]) {
      expect(isBlockedAddress(addr), `${addr} must be blocked`).toBe(true);
    }
  });

  it("allows ordinary public addresses", () => {
    for (const addr of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "11.0.0.1", "2606:4700::1111"]) {
      expect(isBlockedAddress(addr), `${addr} must be allowed`).toBe(false);
    }
  });

  it("does not confuse 172.32/172.15 with the 172.16/12 private block", () => {
    // The 172 private block is 172.16.0.0 - 172.31.255.255 only. Treating all
    // of 172/8 as private would wrongly block real public hosts.
    expect(isBlockedAddress("172.15.255.255")).toBe(false);
    expect(isBlockedAddress("172.32.0.0")).toBe(false);
  });
});

describe("registry host resolution with instance origins", () => {
  it("resolves an instance origin host to the claiming integration", async () => {
    const registry = await buildRegistry();
    expect(registry.resolveHost("gitlab.acme.example")).toBeNull();

    registry.setInstanceOriginLookup((host) =>
      host === "gitlab.acme.example"
        ? { host, integrationId: "gitlab", connectionId: "conn_x" }
        : null,
    );
    expect(registry.resolveHost("gitlab.acme.example")?.id).toBe("gitlab");
    // Unclaimed hosts still pass through untouched.
    expect(registry.resolveHost("other.acme.example")).toBeNull();
  });

  it("never lets an instance origin claim override a builtin host", async () => {
    // The credential-redirection case: a stale or hostile row claiming
    // api.github.com must not divert real GitHub traffic.
    const registry = await buildRegistry();
    registry.setInstanceOriginLookup(() => ({
      host: "api.github.com",
      integrationId: "gitlab",
      connectionId: "conn_evil",
    }));
    expect(registry.resolveHost("api.github.com")?.id).toBe("github");
  });

  it("ignores a claim whose integration does not declare support", async () => {
    // Defence in depth: if supportsInstanceOrigin is removed from an
    // integration, existing rows go inert rather than keeping their claim.
    const registry = await buildRegistry();
    registry.setInstanceOriginLookup((host) => ({
      host,
      integrationId: "slack",
      connectionId: "conn_y",
    }));
    expect(registry.resolveHost("slack.acme.example")).toBeNull();
  });

  it("resolveStaticHostCandidates ignores instance origins entirely", async () => {
    const registry = await buildRegistry();
    registry.setInstanceOriginLookup((host) => ({
      host,
      integrationId: "gitlab",
      connectionId: "conn_z",
    }));
    expect(registry.resolveStaticHostCandidates("gitlab.acme.example")).toEqual([]);
    expect(registry.resolveStaticHostCandidates("gitlab.com").map((i) => i.id)).toEqual(["gitlab"]);
  });
});

describe("store: instance origin persistence", () => {
  let store: Store;

  beforeAll(() => {
    store = new Store(":memory:");
  });

  afterAll(() => store.close());

  it("defaults to null so existing connections are unchanged", () => {
    const c = store.createConnection({
      kind: "app",
      vendor: "gitlab",
      name: "saas",
      data: { clientId: "a", clientSecret: "b", accessToken: "t" },
    });
    expect(c.instanceOrigin ?? null).toBeNull();
    expect(store.getConnection(c.id)?.instanceOrigin ?? null).toBeNull();
  });

  it("round-trips a claim and looks it up by origin and by host", () => {
    const c = store.createConnection({
      kind: "app",
      vendor: "gitlab",
      name: "self-hosted",
      data: { clientId: "a", clientSecret: "b", accessToken: "t" },
      instanceOrigin: "https://gitlab.acme.example",
    });
    expect(c.instanceOrigin).toBe("https://gitlab.acme.example");
    expect(store.getConnectionByInstanceOrigin("https://gitlab.acme.example")?.id).toBe(c.id);
    expect(store.instanceOriginClaimFor("gitlab.acme.example")).toEqual({
      host: "gitlab.acme.example",
      integrationId: "gitlab",
      connectionId: c.id,
    });
  });

  it("returns null for a host nobody claims", () => {
    expect(store.instanceOriginClaimFor("nobody.example")).toBeNull();
    expect(store.getConnectionByInstanceOrigin("https://nobody.example")).toBeNull();
  });

  it("refuses a second connection claiming the same origin", () => {
    expect(() =>
      store.createConnection({
        kind: "app",
        vendor: "gitlab",
        name: "dup",
        data: { clientId: "a", clientSecret: "b", accessToken: "t" },
        instanceOrigin: "https://gitlab.acme.example",
      }),
    ).toThrow(/already claimed/);
  });

  it("lets updateConnection clear and re-claim an origin", () => {
    const c = store.createConnection({
      kind: "app",
      vendor: "gitlab",
      name: "movable",
      data: { clientId: "a", clientSecret: "b", accessToken: "t" },
      instanceOrigin: "https://git.one.example",
    });
    // Omitted = untouched.
    expect(store.updateConnection(c.id, { name: "renamed" })?.instanceOrigin).toBe(
      "https://git.one.example",
    );
    // Null = cleared, which frees the origin for another connection.
    expect(store.updateConnection(c.id, { instanceOrigin: null })?.instanceOrigin ?? null).toBeNull();
    expect(store.getConnectionByInstanceOrigin("https://git.one.example")).toBeNull();
    // And it can be claimed again.
    expect(
      store.updateConnection(c.id, { instanceOrigin: "https://git.two.example" })?.instanceOrigin,
    ).toBe("https://git.two.example");
  });

  it("refuses an update that collides with another connection's claim", () => {
    const c = store.createConnection({
      kind: "app",
      vendor: "gitlab",
      name: "collider",
      data: { clientId: "a", clientSecret: "b", accessToken: "t" },
    });
    expect(() =>
      store.updateConnection(c.id, { instanceOrigin: "https://gitlab.acme.example" }),
    ).toThrow(/already claimed/);
  });
});

describe("admin API: instance origin validation", () => {
  let dir: string;
  let store: Store;
  let server: http.Server;
  let port: number;
  let adminToken: string;

  function api(method: string, path: string, body?: unknown): Promise<{ status: number; json: any }> {
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
            ...(payload
              ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) }
              : {}),
            authorization: `Bearer ${adminToken}`,
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
              /* non-JSON body */
            }
            resolve({ status: res.statusCode ?? 0, json });
          });
        },
      );
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  // POST /api/connections refuses any integration carrying an `oauth`
  // descriptor (error "oauth_connection"), because those need the browser
  // consent round-trip. GitLab is one, so the POST-path cases below drive the
  // other wired integration, jfrog-artifactory, which is api_key. GitLab is
  // still covered, via PUT, in its own test further down.
  const jfrogData = { token: "eyJtest", host: "artifactory.acme.example" };

  /** Creates an app connection and returns its id, failing loudly otherwise. */
  async function createJfrog(name: string, instanceOrigin?: string): Promise<string> {
    const r = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "jfrog-artifactory",
      name,
      data: jfrogData,
      ...(instanceOrigin === undefined ? {} : { instanceOrigin }),
    });
    if (r.status !== 201) {
      throw new Error(`create ${name} failed: ${r.status} ${JSON.stringify(r.json)}`);
    }
    return r.json.id;
  }

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "onegate-instance-origin-"));
    store = new Store(":memory:");
    const ca = initCa(dir);
    const registry = await buildRegistry();
    adminToken = ensureAdminToken(store)!;
    const app = createAdminApp({ store, registry, ca, version: "test" });
    server = http.createServer(app);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as { port: number }).port;
  });

  afterAll(() => {
    server.close();
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("creates a connection with a valid instance origin and exposes it", async () => {
    const r = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "jfrog-artifactory",
      name: "acme self-hosted",
      data: jfrogData,
      instanceOrigin: "https://artifactory.acme.example/",
    });
    expect(r.status).toBe(201);
    expect(r.json.instanceOrigin).toBe("https://artifactory.acme.example");
  });

  it("omitting instanceOrigin yields a null claim, unchanged from before", async () => {
    const r = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "jfrog-artifactory",
      name: "jfrog cloud",
      data: { token: "eyJtest", host: "acme.jfrog.io" },
    });
    expect(r.status).toBe(201);
    expect(r.json.instanceOrigin).toBeNull();
  });

  it("rejects an instance origin on an integration that does not support one", async () => {
    const r = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "github",
      name: "gh",
      data: { pat: "ghp_aaaaaaaaaaaaaaaaaaaa" },
      instanceOrigin: "https://github.acme.example",
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("instance_origin_unsupported");
  });

  it("rejects an origin naming a builtin integration's host", async () => {
    // The hijack case, refused at write time as well as at resolution time.
    const r = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "jfrog-artifactory",
      name: "hijack",
      data: jfrogData,
      instanceOrigin: "https://api.github.com",
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("instance_origin_reserved_host");
  });

  it("rejects an origin claiming the integration's own SaaS host", async () => {
    // jfrog claims the ".jfrog.io" dot-suffix, so any subdomain is reserved.
    const r = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "jfrog-artifactory",
      name: "self-hijack",
      data: jfrogData,
      instanceOrigin: "https://acme.jfrog.io",
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("instance_origin_reserved_host");
  });

  it("rejects a second connection claiming an origin already taken", async () => {
    const r = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "jfrog-artifactory",
      name: "dupe",
      data: jfrogData,
      instanceOrigin: "https://artifactory.acme.example",
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("instance_origin_conflict");
  });

  it("surfaces SSRF rejections as 400 with the specific code", async () => {
    for (const [origin, code] of [
      ["http://artifactory.acme.example", "instance_origin_not_https"],
      ["https://169.254.169.254", "instance_origin_blocked_host"],
      ["https://10.0.0.1", "instance_origin_blocked_host"],
      ["https://localhost", "instance_origin_blocked_host"],
      ["https://artifactory.acme.example:8443", "instance_origin_port_unsupported"],
      ["https://artifactory.acme.example/path", "instance_origin_has_path"],
    ] as const) {
      const r = await api("POST", "/api/connections", {
        kind: "app",
        vendor: "jfrog-artifactory",
        name: `bad-${origin}`,
        data: jfrogData,
        instanceOrigin: origin,
      });
      expect(r.status, origin).toBe(400);
      expect(r.json.error, origin).toBe(code);
    }
  });

  it("updates an origin, and lets a connection keep its own origin on update", async () => {
    const id = await createJfrog("updatable", "https://art.update.example");

    // Re-sending its OWN origin must not trip the conflict check.
    const same = await api("PUT", `/api/connections/${id}`, {
      instanceOrigin: "https://art.update.example",
    });
    expect(same.status).toBe(200);
    expect(same.json.instanceOrigin).toBe("https://art.update.example");

    const moved = await api("PUT", `/api/connections/${id}`, {
      instanceOrigin: "https://art.moved.example",
    });
    expect(moved.status).toBe(200);
    expect(moved.json.instanceOrigin).toBe("https://art.moved.example");

    const cleared = await api("PUT", `/api/connections/${id}`, { instanceOrigin: null });
    expect(cleared.status).toBe(200);
    expect(cleared.json.instanceOrigin).toBeNull();
  });

  it("rejects an instance origin on an integration that does not declare support", async () => {
    const gh = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "github",
      name: "gh-put",
      data: { pat: "ghp_bbbbbbbbbbbbbbbbbbbb" },
    });
    expect(gh.status).toBe(201);
    const r = await api("PUT", `/api/connections/${gh.json.id}`, {
      instanceOrigin: "https://github.acme.example",
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("instance_origin_unsupported");
  });

  it("still refuses a direct POST for an OAuth integration, so GitLab sets its origin via PUT", async () => {
    // Documents the deferral: OAuth connections are minted by the consent
    // round-trip, and `oauth/start` does not accept an instanceOrigin yet.
    const refused = await api("POST", "/api/connections", {
      kind: "app",
      vendor: "gitlab",
      name: "gitlab direct",
      data: { clientId: "a", clientSecret: "b", accessToken: "t" },
      instanceOrigin: "https://gitlab.acme.example",
    });
    expect(refused.status).toBe(400);
    expect(refused.json.error).toBe("oauth_connection");

    // The path that does work: create the connection the way the OAuth callback
    // does, then claim the origin over the admin API.
    const conn = store.createConnection({
      kind: "app",
      vendor: "gitlab",
      name: "gitlab self-managed",
      data: { clientId: "a", clientSecret: "b", accessToken: "t" },
    });
    const r = await api("PUT", `/api/connections/${conn.id}`, {
      instanceOrigin: "https://gitlab.acme.example/",
    });
    expect(r.status).toBe(200);
    expect(r.json.instanceOrigin).toBe("https://gitlab.acme.example");

    // And the reserved-host guard applies on this path too.
    const hijack = await api("PUT", `/api/connections/${conn.id}`, {
      instanceOrigin: "https://gitlab.com",
    });
    expect(hijack.status).toBe(400);
    expect(hijack.json.error).toBe("instance_origin_reserved_host");
  });

  it("rejects an instance origin on an llm connection", async () => {
    const llm = await api("POST", "/api/connections", {
      kind: "llm",
      vendor: "anthropic",
      name: "claude",
      data: { apiKey: "sk-ant-test" },
    });
    expect(llm.status).toBe(201);
    const r = await api("PUT", `/api/connections/${llm.json.id}`, {
      instanceOrigin: "https://anthropic.acme.example",
    });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("instance_origin_unsupported");
  });
});
