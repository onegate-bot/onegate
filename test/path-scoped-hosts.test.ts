/**
 * Path-scoped host claims: two auth modes on one hostname.
 *
 * A bare host claim owns a hostname outright. A PATH-SCOPED claim
 * ({ host, path }) owns only a subtree of it, and is MORE SPECIFIC, so it wins
 * for matching requests while the bare claim keeps serving everything else.
 * Two path-scoped claims on one host resolve longest-prefix-first.
 *
 * Split in two:
 *  - registry unit tests, including the adversarial path shapes,
 *  - a real end-to-end proxy test proving the per-path credential actually
 *    reaches the vendor: two integrations share one hostname with DIFFERENT
 *    auth modes and each request gets the right one.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { initCa } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { Registry, pathScopeMatches } from "../src/integrations/types.js";
import { buildRegistry } from "../src/integrations/index.js";
import { GatewayProxy } from "../src/proxy/server.js";
import { normalizeRequestPath } from "../src/policy.js";
import type { Integration } from "../src/integrations/types.js";

const SHARED_HOST = "api.shared-vendor.com";

/** Minimal integration whose inject stamps an identifying header. */
function stub(id: string, hosts: Integration["hosts"]): Integration {
  return {
    id,
    title: id,
    hosts,
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    inject(ctx) {
      ctx.headers.authorization = `Bearer ${ctx.credential.data.apiKey}`;
    },
  };
}

/** Ids resolved for host+path, most specific first. */
function idsFor(registry: Registry, host: string, path: string): string[] {
  return registry.resolveHostPathCandidates(host, path).map((i) => i.id);
}

describe("pathScopeMatches (segment-boundary prefix match)", () => {
  it("matches the prefix itself and any deeper segment", () => {
    expect(pathScopeMatches("/youtube/v3", "/youtube/v3")).toBe(true);
    expect(pathScopeMatches("/youtube/v3", "/youtube/v3/")).toBe(true);
    expect(pathScopeMatches("/youtube/v3", "/youtube/v3/search")).toBe(true);
    expect(pathScopeMatches("/youtube/v3", "/youtube/v3/videos/list")).toBe(true);
  });

  it("does NOT match a longer sibling segment", () => {
    // The whole point: /youtube/v3 must never capture /youtube/v31.
    expect(pathScopeMatches("/youtube/v3", "/youtube/v31")).toBe(false);
    expect(pathScopeMatches("/youtube/v3", "/youtube/v31/search")).toBe(false);
    expect(pathScopeMatches("/youtube/v3", "/youtube/v3x")).toBe(false);
    expect(pathScopeMatches("/youtube/v3", "/youtube/v3-beta")).toBe(false);
  });

  it("does not match unrelated or shorter paths", () => {
    expect(pathScopeMatches("/youtube/v3", "/")).toBe(false);
    expect(pathScopeMatches("/youtube/v3", "/youtube")).toBe(false);
    expect(pathScopeMatches("/youtube/v3", "/drive/v3/files")).toBe(false);
  });

  it("ignores the query string when matching", () => {
    expect(pathScopeMatches("/youtube/v3", "/youtube/v3/search?q=cats")).toBe(true);
    // A query cannot smuggle the prefix in.
    expect(pathScopeMatches("/youtube/v3", "/drive/v3/files?x=/youtube/v3")).toBe(false);
  });

  it("treats a trailing slash on the PREFIX as the same scope", () => {
    expect(pathScopeMatches("/youtube/v3/", "/youtube/v3/search")).toBe(true);
    expect(pathScopeMatches("/youtube/v3/", "/youtube/v31")).toBe(false);
  });

  it("a root prefix matches everything", () => {
    expect(pathScopeMatches("/", "/anything/at/all")).toBe(true);
  });
});

describe("registry: path-scoped host claims", () => {
  it("a path-scoped claim wins over a bare claim on the same host", () => {
    const registry = new Registry();
    registry.register(stub("bare", [SHARED_HOST])); // registered FIRST
    registry.register(stub("scoped", [{ host: SHARED_HOST, path: "/scoped/v1" }]));

    // Inside the scope the more specific claim wins despite registering later.
    expect(idsFor(registry, SHARED_HOST, "/scoped/v1/thing")).toEqual(["scoped", "bare"]);
    // The bare claim still serves every other path, and alone.
    expect(idsFor(registry, SHARED_HOST, "/other/thing")).toEqual(["bare"]);
  });

  it("resolves two path-scoped claims longest-prefix-first", () => {
    const registry = new Registry();
    registry.register(stub("shallow", [{ host: SHARED_HOST, path: "/a" }]));
    registry.register(stub("deep", [{ host: SHARED_HOST, path: "/a/b/c" }]));

    expect(idsFor(registry, SHARED_HOST, "/a/b/c/d")).toEqual(["deep", "shallow"]);
    expect(idsFor(registry, SHARED_HOST, "/a/b")).toEqual(["shallow"]);
    // Registration order is irrelevant to specificity: same result reversed.
    const rev = new Registry();
    rev.register(stub("deep", [{ host: SHARED_HOST, path: "/a/b/c" }]));
    rev.register(stub("shallow", [{ host: SHARED_HOST, path: "/a" }]));
    expect(idsFor(rev, SHARED_HOST, "/a/b/c/d")).toEqual(["deep", "shallow"]);
  });

  it("keeps registration order as the tie-break among equally specific claims", () => {
    const registry = new Registry();
    registry.register(stub("first", [SHARED_HOST]));
    registry.register(stub("second", [SHARED_HOST]));
    expect(idsFor(registry, SHARED_HOST, "/x")).toEqual(["first", "second"]);

    const scoped = new Registry();
    scoped.register(stub("a", [{ host: SHARED_HOST, path: "/p" }]));
    scoped.register(stub("b", [{ host: SHARED_HOST, path: "/p" }]));
    expect(idsFor(scoped, SHARED_HOST, "/p/x")).toEqual(["a", "b"]);
  });

  it("path scoping works on dot-suffix host claims too", () => {
    const registry = new Registry();
    registry.register(stub("bare", [".shared-vendor.com"]));
    registry.register(stub("scoped", [{ host: ".shared-vendor.com", path: "/scoped" }]));
    expect(idsFor(registry, "sub.shared-vendor.com", "/scoped/x")).toEqual(["scoped", "bare"]);
    expect(idsFor(registry, "sub.shared-vendor.com", "/nope")).toEqual(["bare"]);
    // Host still has to match at all.
    expect(idsFor(registry, "other.com", "/scoped/x")).toEqual([]);
  });

  it("adversarial paths cannot escape or forge a scope", () => {
    const registry = new Registry();
    registry.register(stub("bare", [SHARED_HOST]));
    registry.register(stub("scoped", [{ host: SHARED_HOST, path: "/scoped/v1" }]));

    // Every case is normalized exactly the way the proxy normalizes it, using
    // the SAME helper, so these assert real request behaviour and not a
    // hand-rolled second normaliser.
    const resolve = (raw: string) => idsFor(registry, SHARED_HOST, normalizeRequestPath(raw));

    // Traversal out of the scope must NOT stay in the scope.
    expect(resolve("/scoped/v1/../../other")).toEqual(["bare"]);
    expect(resolve("/scoped/v1/../other")).toEqual(["bare"]);
    // Percent-encoded traversal, same outcome.
    expect(resolve("/scoped/v1/%2e%2e/%2e%2e/other")).toEqual(["bare"]);
    expect(resolve("/scoped/v1/%2E%2E/other")).toEqual(["bare"]);
    // Traversal INTO the scope from elsewhere resolves to the scope, which is
    // correct: after normalization the request really is inside it.
    expect(resolve("/other/../scoped/v1/thing")).toEqual(["scoped", "bare"]);
    // Double slashes must not create a phantom empty segment that dodges the
    // boundary check.
    expect(resolve("//scoped//v1//thing")).toEqual(["scoped", "bare"]);
    expect(resolve("/scoped//v1")).toEqual(["scoped", "bare"]);
    // An encoded slash IS decoded by the shared normalizer, so this really is
    // the in-scope path and resolves that way. That is the safe direction:
    // scoping, policy matching and audit all see the SAME canonical path, so an
    // encoded separator can never scope a request to one integration while
    // policy reads it as another.
    expect(resolve("/scoped%2fv1/thing")).toEqual(["scoped", "bare"]);
    expect(resolve("/scoped%2Fv1/thing")).toEqual(["scoped", "bare"]);
    // But encoding cannot manufacture a scope that is not there.
    expect(resolve("/other%2fscoped%2fv1")).toEqual(["bare"]);
    // Longer sibling segment, through the real normalizer.
    expect(resolve("/scoped/v31/thing")).toEqual(["bare"]);
    expect(resolve("/scoped/v1x/thing")).toEqual(["bare"]);
    // Query strings never participate in matching.
    expect(resolve("/other?next=/scoped/v1")).toEqual(["bare"]);
    expect(resolve("/scoped/v1?x=1")).toEqual(["scoped", "bare"]);
    // Bare root.
    expect(resolve("/")).toEqual(["bare"]);
  });
});

describe("registry: existing bare-claim behaviour is unchanged", () => {
  it("resolveHostPathCandidates equals resolveHostCandidates when no scopes match", async () => {
    const registry = await buildRegistry();
    for (const host of [
      "api.github.com",
      "api.atlassian.com",
      "generativelanguage.googleapis.com",
      "googleapis.com",
      "gmail.googleapis.com",
    ]) {
      const bare = registry.resolveHostCandidates(host).map((i) => i.id);
      const scoped = idsFor(registry, host, "/some/ordinary/path");
      expect(scoped, host).toEqual(bare);
    }
  });

  it("google keeps every non-YouTube path on www.googleapis.com", async () => {
    const registry = await buildRegistry();
    expect(idsFor(registry, "www.googleapis.com", "/drive/v3/files")[0]).toBe("google");
    expect(idsFor(registry, "www.googleapis.com", "/oauth2/v3/userinfo")[0]).toBe("google");
    // youtube is not even a candidate outside its scope.
    expect(idsFor(registry, "www.googleapis.com", "/drive/v3/files")).not.toContain("youtube");
  });

  it("youtube owns /youtube/v3 on the shared host, and only that", async () => {
    const registry = await buildRegistry();
    expect(idsFor(registry, "www.googleapis.com", "/youtube/v3/search")[0]).toBe("youtube");
    expect(idsFor(registry, "www.googleapis.com", "/youtube/v3")[0]).toBe("youtube");
    // The sibling-segment trap.
    expect(idsFor(registry, "www.googleapis.com", "/youtube/v31/search")[0]).toBe("google");
    // google stays available as the fallback candidate inside the scope, so an
    // operator who has only connected Workspace is no worse off than today.
    expect(idsFor(registry, "www.googleapis.com", "/youtube/v3/search")).toContain("google");
  });
});

/* -------------------------------------------------------------------------- */
/* End-to-end: one host, two auth modes, correct credential per path.          */
/* -------------------------------------------------------------------------- */

let dir: string;
let store: Store;
let proxy: GatewayProxy;
let proxyPort: number;
let stubServer: https.Server;
let stubPort: number;
let caPem: string;
let agentToken: string;
let lastSeen: { auth?: string; path?: string } = {};

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-pathscope-"));
  const ca = initCa(dir);
  caPem = ca.rootPem;
  store = new Store(":memory:");

  const leaf = ca.leafFor(SHARED_HOST);
  stubServer = https.createServer({ key: leaf.key, cert: leaf.cert }, (req, res) => {
    lastSeen = { auth: req.headers.authorization as string | undefined, path: req.url };
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  });
  await new Promise<void>((r) => stubServer.listen(0, "127.0.0.1", r));
  stubPort = (stubServer.address() as { port: number }).port;

  // Two integrations on ONE hostname with two DIFFERENT auth modes: the bare
  // claim uses a bearer token, the path-scoped one an API key in the query.
  const registry = new Registry();
  registry.register({
    id: "oauthy",
    title: "OAuthy",
    hosts: [SHARED_HOST],
    credentialFields: [{ key: "token", label: "Token", secret: true }],
    inject(ctx) {
      ctx.headers.authorization = `Bearer ${ctx.credential.data.token}`;
    },
  });
  registry.register({
    id: "keyed",
    title: "Keyed",
    hosts: [{ host: SHARED_HOST, path: "/keyed/v1" }],
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    inject(ctx) {
      const [p, q = ""] = ctx.path.split("?");
      const params = new URLSearchParams(q);
      params.set("key", ctx.credential.data.apiKey);
      ctx.path = `${p}?${params.toString()}`;
    },
  });

  store.setCredential("oauthy", "oauthy-cred", { token: "OAUTH-TOKEN" });
  store.setCredential("keyed", "keyed-cred", { apiKey: "API-KEY" });

  const a = store.createAgent("path-agent", { defaultPolicy: "deny-unmatched" });
  agentToken = a.token;
  for (const integrationId of ["oauthy", "keyed"]) {
    store.createRule({
      scope: "agent",
      subjectId: a.agent.id,
      integrationId,
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
  }

  proxy = new GatewayProxy({
    ca,
    store,
    registry,
    upstreamTls: { ca: caPem },
    upstreamLookup: () => ({ host: "127.0.0.1", port: stubPort }),
  });
  proxyPort = await proxy.listen(0, "127.0.0.1");
});

afterAll(async () => {
  await proxy.close();
  stubServer.closeAllConnections();
  stubServer.close();
  rmSync(dir, { recursive: true, force: true });
});

function viaProxy(path: string): Promise<{ status: number; connectStatus: number }> {
  return new Promise((resolve, reject) => {
    const connectReq = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "CONNECT",
      path: `${SHARED_HOST}:443`,
      headers: {
        "proxy-authorization": "Basic " + Buffer.from(`agent:${agentToken}`).toString("base64"),
      },
      agent: false,
    });
    connectReq.on("connect", (connectRes, socket) => {
      if (connectRes.statusCode !== 200) {
        socket.destroy();
        resolve({ status: 0, connectStatus: connectRes.statusCode ?? 0 });
        return;
      }
      const tlsSocket = tls.connect({ socket, servername: SHARED_HOST, ca: caPem }, () => {
        const req = https.request(
          { createConnection: () => tlsSocket, host: SHARED_HOST, method: "GET", path },
          (res) => {
            res.on("data", () => {});
            res.on("end", () => {
              resolve({ status: res.statusCode ?? 0, connectStatus: 200 });
              tlsSocket.end();
            });
          },
        );
        req.on("error", reject);
        req.end();
      });
      tlsSocket.on("error", reject);
    });
    connectReq.on("error", reject);
    connectReq.end();
  });
}

describe("proxy: one host serves two auth modes by path", () => {
  it("injects the path-scoped integration's credential inside the scope", async () => {
    const r = await viaProxy("/keyed/v1/items");
    expect(r.status).toBe(200);
    // The API key went into the query, and NO bearer token leaked.
    expect(lastSeen.path).toBe("/keyed/v1/items?key=API-KEY");
    expect(lastSeen.auth).toBeUndefined();
  });

  it("injects the bare integration's credential everywhere else", async () => {
    const r = await viaProxy("/other/items");
    expect(r.status).toBe(200);
    expect(lastSeen.auth).toBe("Bearer OAUTH-TOKEN");
    expect(lastSeen.path).toBe("/other/items");
    // The API key must never appear on an out-of-scope request.
    expect(lastSeen.path).not.toContain("API-KEY");
  });

  it("a longer sibling segment does NOT get the scoped credential", async () => {
    const r = await viaProxy("/keyed/v11/items");
    expect(r.status).toBe(200);
    expect(lastSeen.auth).toBe("Bearer OAUTH-TOKEN");
    expect(lastSeen.path).not.toContain("API-KEY");
  });

  it("traversal out of the scope does NOT get the scoped credential", async () => {
    const r = await viaProxy("/keyed/v1/../../other/items");
    expect(r.status).toBe(200);
    expect(lastSeen.auth).toBe("Bearer OAUTH-TOKEN");
    expect(lastSeen.path).not.toContain("API-KEY");
  });
});
