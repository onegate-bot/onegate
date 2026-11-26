/**
 * Admin API authentication gate.
 *
 * Every /api route except /api/health must refuse a request that does not carry
 * `Authorization: Bearer <admin token>`. Rather than hand-maintain a route list
 * (which silently rots when a route is added), the route table is extracted from
 * the source of src/admin/api.ts, so a new route is covered by this suite the
 * moment it is registered.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { resetAdminToken } from "../src/admin/api.js";
import { startAdmin, type AdminHarness } from "./admin-harness.js";

let h: AdminHarness;

beforeAll(async () => {
  h = await startAdmin({ publicBaseUrl: "https://gate.example" });
});

afterAll(async () => {
  await h.close();
});

/** Every `app.<verb>("/api/...")` registration in the admin source. */
function apiRoutes(): Array<{ method: string; path: string }> {
  const src = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "..", "src", "admin", "api.ts"),
    "utf8",
  );
  const out: Array<{ method: string; path: string }> = [];
  const re = /app\.(get|post|put|patch|delete)\(\s*[`"](\/api[^`"]*)[`"]/g;
  for (const m of src.matchAll(re)) {
    const method = m[1].toUpperCase();
    // The approvals routes are registered in a loop over `${verb}`.
    const variants = m[2].includes("${verb}")
      ? ["approve", "reject"].map((v) => m[2].replace("${verb}", v))
      : [m[2]];
    for (const v of variants) {
      out.push({ method, path: v.replace(/:([A-Za-z]+)/g, (_s, name: string) => `probe_${name}`) });
    }
  }
  return out;
}

describe("public routes", () => {
  it("GET /api/health needs no token and reports the running version", async () => {
    const r = await h.api("GET", "/api/health", undefined, null);
    expect(r.status).toBe(200);
    expect(r.json).toEqual({ ok: true, version: "test-version" });
    // A bad token on the public route is ignored, not rejected.
    const bad = await h.api("GET", "/api/health", undefined, "oga_wrong");
    expect(bad.status).toBe(200);
  });

  it("GET /ca.pem serves the root CA as a PEM download without a token", async () => {
    const r = await h.get("/ca.pem");
    expect(r.status).toBe(200);
    expect(r.headers["content-type"]).toMatch(/^application\/x-pem-file/);
    expect(r.text).toContain("-----BEGIN CERTIFICATE-----");
  });
});

describe("Bearer auth on every non-public /api route", () => {
  const routes = apiRoutes();

  it("discovers the full route table from the source", () => {
    // Sanity floor so a broken regex cannot make the gate test vacuous.
    expect(routes.length).toBeGreaterThanOrEqual(50);
    expect(routes).toContainEqual({ method: "POST", path: "/api/approvals/probe_id/approve" });
    expect(routes).toContainEqual({ method: "GET", path: "/api/health" });
  });

  it("refuses every gated route with no Authorization header", async () => {
    for (const { method, path } of routes) {
      if (path === "/api/health") continue;
      const r = await h.rawAuth(method, path, undefined);
      expect({ method, path, status: r.status, body: r.json }).toEqual({
        method,
        path,
        status: 401,
        body: { error: "invalid_admin_token" },
      });
    }
  });

  it("refuses every gated route with a wrong token", async () => {
    for (const { method, path } of routes) {
      if (path === "/api/health") continue;
      const r = await h.rawAuth(method, path, "Bearer oga_not_the_admin_token");
      expect({ method, path, status: r.status }).toEqual({ method, path, status: 401 });
    }
  });

  it("refuses malformed Authorization headers that still contain the real token", async () => {
    const variants = [
      h.token, // no scheme
      `Basic ${h.token}`,
      `bearer ${h.token}`, // scheme is matched case-sensitively
      `Bearer  ${h.token}`, // extra space changes the hashed value
      `Bearer ${h.token}x`,
      `Bearer ${h.token.slice(0, -1)}`,
      "Bearer ",
    ];
    for (const auth of variants) {
      const r = await h.rawAuth("GET", "/api/agents", auth);
      expect({ auth, status: r.status }).toEqual({ auth, status: 401 });
    }
  });

  it("an unauthenticated mutation has no side effect", async () => {
    const before = h.store.listAgents().length;
    const r = await h.api("POST", "/api/agents", { name: "sneaky" }, null);
    expect(r.status).toBe(401);
    expect(h.store.listAgents().length).toBe(before);
  });

  it("the gate also covers case and trailing-slash variants of a route", async () => {
    for (const path of ["/API/agents", "/api/Agents", "/api/agents/"]) {
      const r = await h.rawAuth("GET", path, undefined);
      expect({ path, status: r.status }).toEqual({ path, status: 401 });
    }
  });

  it("accepts the right token, and resetting it immediately revokes the old one", async () => {
    expect((await h.api("GET", "/api/agents")).status).toBe(200);
    const old = h.token;
    const fresh = resetAdminToken(h.store);
    expect(fresh).toMatch(/^oga_[0-9a-f]{48}$/);
    expect((await h.api("GET", "/api/agents", undefined, old)).status).toBe(401);
    expect((await h.api("GET", "/api/agents", undefined, fresh)).status).toBe(200);
    h.token = fresh;
  });
});
