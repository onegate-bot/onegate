/**
 * Rule HTTP-method normalization and validation at the write boundary.
 *
 * `ruleMatches` in policy.ts compares against `req.method.toUpperCase()`, so a
 * rule whose stored methods are not canonical uppercase verbs can never match.
 * A DENY rule in that state is silently inert (it looks configured but grants
 * nothing) and an ALLOW rule silently never fires. These tests pin the write
 * boundary so an unmatchable value can no longer be persisted.
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
import { ruleMatches } from "../src/policy.js";
import { normalizeMethods, InvalidMethodError } from "../src/util/methods.js";

let dir: string;
let store: Store;
let server: http.Server;
let port: number;
let adminToken: string;
let agentId: string;

function api(
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; json: any; text: string }> {
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
          resolve({ status: res.statusCode ?? 0, json, text });
        });
      },
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-rulemethods-"));
  store = new Store(":memory:");
  const ca = initCa(dir);
  const registry = await buildRegistry();
  adminToken = ensureAdminToken(store)!;
  const app = createAdminApp({ store, registry, ca, version: "test" });
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as { port: number }).port;
  const agent = await api("POST", "/api/agents", { name: "methods-subject" });
  agentId = agent.json.id;
});

afterAll(() => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

function addRule(body: Record<string, unknown>) {
  return api("POST", "/api/rules", {
    scope: "agent",
    subjectId: agentId,
    integrationId: "github",
    effect: "deny",
    pathGlob: "/**",
    ...body,
  });
}

describe("normalizeMethods (shared write-boundary helper)", () => {
  it("uppercases, trims, and drops empty entries", () => {
    expect(normalizeMethods([" post ", "put", "", "  "])).toEqual(["POST", "PUT"]);
  });

  it("defaults an absent or empty list to the wildcard", () => {
    expect(normalizeMethods(undefined)).toEqual(["*"]);
    expect(normalizeMethods([])).toEqual(["*"]);
    expect(normalizeMethods(["   "])).toEqual(["*"]);
  });

  it("preserves the wildcard", () => {
    expect(normalizeMethods(["*"])).toEqual(["*"]);
  });

  it("de-duplicates verbs that collapse after normalization", () => {
    expect(normalizeMethods(["get", "GET", " Get "])).toEqual(["GET"]);
  });

  it("rejects an unknown verb with a clear error", () => {
    expect(() => normalizeMethods(["BOGUS"])).toThrow(InvalidMethodError);
    // A plausible typo is exactly the case that used to persist silently.
    expect(() => normalizeMethods(["GTE"])).toThrow(/unsupported HTTP method "GTE"/);
  });

  it("rejects a non-string entry instead of crashing", () => {
    expect(() => normalizeMethods([123 as unknown as string])).toThrow(InvalidMethodError);
  });

  it("rejects a non-array methods value", () => {
    expect(() => normalizeMethods("GET" as unknown as string[])).toThrow(InvalidMethodError);
  });
});

describe("POST /api/rules method normalization", () => {
  it("stores lowercase methods uppercased, and the rule matches a real request", async () => {
    const r = await addRule({ methods: ["post", "put"] });
    expect(r.status).toBe(201);
    expect(r.json.methods).toEqual(["POST", "PUT"]);

    // The whole point: the persisted rule must actually match a live request.
    const stored = store.getRule(r.json.id)!;
    expect(stored.methods).toEqual(["POST", "PUT"]);
    expect(ruleMatches(stored, { integrationId: "github", method: "POST", path: "/repos/x/y" } as never)).toBe(true);
  });

  it("trims surrounding whitespace so a padded verb still matches", async () => {
    const r = await addRule({ methods: [" post "] });
    expect(r.status).toBe(201);
    expect(r.json.methods).toEqual(["POST"]);
    const stored = store.getRule(r.json.id)!;
    expect(ruleMatches(stored, { integrationId: "github", method: "POST", path: "/x" } as never)).toBe(true);
  });

  it("rejects an unknown verb with a 400 instead of storing an inert rule", async () => {
    const r = await addRule({ methods: ["BOGUS"] });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("invalid_methods");
    expect(r.json.message).toMatch(/BOGUS/);
  });

  it("rejects a non-string method entry with a 400 rather than a 500", async () => {
    const r = await addRule({ methods: [123] });
    expect(r.status).toBe(400);
    expect(r.json.error).toBe("invalid_methods");
  });

  it("still accepts the wildcard and defaults an empty list to it", async () => {
    expect((await addRule({ methods: ["*"] })).json.methods).toEqual(["*"]);
    expect((await addRule({ methods: [] })).json.methods).toEqual(["*"]);
    expect((await addRule({})).json.methods).toEqual(["*"]);
  });

  it("accepts every standard verb in mixed case", async () => {
    const r = await addRule({ methods: ["get", "Head", "post", "PUT", "patch", "delete", "options", "trace", "connect"] });
    expect(r.status).toBe(201);
    expect(r.json.methods).toEqual(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"]);
  });
});

describe("Store.createRule defense in depth", () => {
  it("normalizes at the store layer even when a caller bypasses the admin API", () => {
    const r = store.createRule({
      scope: "agent",
      subjectId: agentId,
      integrationId: "github",
      methods: [" delete "],
      pathGlob: "/**",
      effect: "deny",
    });
    expect(r.methods).toEqual(["DELETE"]);
  });

  it("throws on an unknown verb rather than persisting an unmatchable rule", () => {
    expect(() =>
      store.createRule({
        scope: "agent",
        subjectId: agentId,
        integrationId: "github",
        methods: ["NOPE"],
        pathGlob: "/**",
        effect: "deny",
      }),
    ).toThrow(InvalidMethodError);
  });
});
