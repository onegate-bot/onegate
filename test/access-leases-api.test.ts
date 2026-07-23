import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/store/db.js";
import { initCa } from "../src/ca.js";
import { buildRegistry } from "../src/integrations/index.js";
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";

let dir: string;
let store: Store;
let server: http.Server;
let port: number;
let adminToken: string;

function api(
  method: string,
  path: string,
  body?: unknown,
  token: string | null = adminToken,
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
          ...(payload
            ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) }
            : {}),
          ...(token ? { authorization: `Bearer ${token}` } : {}),
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
            /* non-JSON */
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
  dir = mkdtempSync(join(tmpdir(), "onegate-lease-"));
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
  rmSync(dir, { recursive: true, force: true });
});

describe("integration-lease catalog API", () => {
  it("Hetzner is seeded time-boxed (8h) and surfaced on /api/integrations", async () => {
    const leases = await api("GET", "/api/integration-leases");
    expect(leases.status).toBe(200);
    const hz = leases.json.find((l: any) => l.integrationId === "hetzner");
    expect(hz?.ttlSeconds).toBe(8 * 3600);

    const integrations = await api("GET", "/api/integrations");
    const hzInt = integrations.json.find((i: any) => i.id === "hetzner");
    expect(hzInt.leaseDefaultSeconds).toBe(8 * 3600);
    const gh = integrations.json.find((i: any) => i.id === "github");
    expect(gh.leaseDefaultSeconds ?? null).toBeNull();
  });

  it("PUT sets, PUT 0 / DELETE clears a default time-box", async () => {
    const set = await api("PUT", "/api/integration-leases/github", { ttlSeconds: 1800 });
    expect(set.status).toBe(200);
    expect(set.json.ttlSeconds).toBe(1800);
    expect(store.getIntegrationLease("github")).toBe(1800);

    const clearZero = await api("PUT", "/api/integration-leases/github", { ttlSeconds: 0 });
    expect(clearZero.json.ttlSeconds).toBeNull();
    expect(store.getIntegrationLease("github")).toBeNull();

    await api("PUT", "/api/integration-leases/github", { ttlSeconds: 1800 });
    const del = await api("DELETE", "/api/integration-leases/github");
    expect(del.status).toBe(200);
    expect(store.getIntegrationLease("github")).toBeNull();
  });

  it("rejects an unknown integration and a bad TTL", async () => {
    expect((await api("PUT", "/api/integration-leases/nope", { ttlSeconds: 100 })).status).toBe(404);
    expect((await api("PUT", "/api/integration-leases/github", { ttlSeconds: -5 })).status).toBe(400);
    expect((await api("PUT", "/api/integration-leases/github", { ttlSeconds: 1.5 })).status).toBe(400);
  });
});

describe("rules with a lease + renewal", () => {
  let agentId: string;

  it("POST /api/rules with ttlSeconds stamps an expiry", async () => {
    const a = await api("POST", "/api/agents", { name: "leasebot" });
    agentId = a.json.id;
    const r = await api("POST", "/api/rules", {
      scope: "agent",
      subjectId: agentId,
      integrationId: "hetzner",
      effect: "allow",
      methods: ["*"],
      pathGlob: "/**",
      ttlSeconds: 8 * 3600,
    });
    expect(r.status).toBe(201);
    expect(r.json.leaseTtlSeconds).toBe(8 * 3600);
    expect(r.json.expiresAt).toBeTruthy();
    expect(Date.parse(r.json.expiresAt)).toBeGreaterThan(Date.now());
  });

  it("POST /api/rules/:id/renew re-stamps expiry; 404 for unknown", async () => {
    const rule = store.createRule({
      scope: "agent",
      subjectId: agentId,
      integrationId: "hetzner",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
      expiresAt: new Date(Date.now() - 3600 * 1000).toISOString(),
      leaseTtlSeconds: 8 * 3600,
    });
    const renew = await api("POST", `/api/rules/${rule.id}/renew`, {});
    expect(renew.status).toBe(200);
    expect(Date.parse(renew.json.expiresAt)).toBeGreaterThan(Date.now());

    expect((await api("POST", "/api/rules/rl_missing/renew", {})).status).toBe(404);
  });
});

describe("renewal page (/renew/:token)", () => {
  it("renders a one-tap re-allow page and re-stamps the rule on POST", async () => {
    const a = store.createAgent("renewbot");
    const rule = store.createRule({
      scope: "agent",
      subjectId: a.agent.id,
      integrationId: "hetzner",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
      expiresAt: new Date(Date.now() - 3600 * 1000).toISOString(),
      leaseTtlSeconds: 8 * 3600,
    });
    const link = store.createOnboardingLink({
      agentId: a.agent.id,
      integrationId: "hetzner",
      ruleId: rule.id,
    });

    // GET renders (public, no admin token)
    const page = await api("GET", `/renew/${link.token}`, undefined, null);
    expect(page.status).toBe(200);
    expect(page.text.toLowerCase()).toContain("re-allow");

    // POST re-stamps and marks the link used
    const submit = await new Promise<{ status: number }>((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port,
          method: "POST",
          path: `/renew/${link.token}`,
          agent: false,
          headers: { "content-type": "application/x-www-form-urlencoded", "content-length": 0 },
        },
        (res) => {
          res.on("data", () => {});
          res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
        },
      );
      req.on("error", reject);
      req.end();
    });
    expect(submit.status).toBe(200);
    const after = store.getRule(rule.id)!;
    expect(Date.parse(after.expiresAt!)).toBeGreaterThan(Date.now());
    expect(store.getOnboardingLink(link.token)?.usedAt).toBeTruthy();
  });
});
