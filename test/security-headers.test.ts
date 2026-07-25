/**
 * Security headers: the admin app must set anti-clickjacking and
 * content-type-protection headers on EVERY response (public wizard/renew pages,
 * the health/API endpoints, and the static admin SPA), preventing framing of the
 * one-tap /renew lease re-allow, the connect wizard, and the authenticated admin
 * console.
 *
 * Driven against the real admin app, mirroring connect-wizard.test.ts.
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

let dir: string;
let store: Store;
let server: http.Server;
let port: number;
let adminToken: string;

/** GET returning the response headers alongside status + body. */
function get(
  path: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; text: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "GET", path, agent: false, headers },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text, headers: res.headers }),
        );
      },
    );
    req.on("error", reject);
    req.end();
  });
}

function expectSecurityHeaders(h: http.IncomingHttpHeaders) {
  expect(h["x-frame-options"]).toBe("DENY");
  expect(h["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(h["x-content-type-options"]).toBe("nosniff");
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-sec-headers-"));
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

describe("security headers", () => {
  it("sets anti-clickjacking + nosniff headers on a public connect page (invalid token 410)", async () => {
    const r = await get("/connect/github/deadbeeftoken");
    expect(r.status).toBe(410); // friendly HTML page, framable without the fix
    expectSecurityHeaders(r.headers);
  });

  it("sets anti-clickjacking + nosniff headers on the public /renew page (invalid token)", async () => {
    const r = await get("/renew/deadbeeftoken");
    // Renders an HTML page (valid or invalid); the headers must be present either way.
    expectSecurityHeaders(r.headers);
  });

  it("sets the headers on the health endpoint", async () => {
    const r = await get("/api/health");
    expect(r.status).toBe(200);
    expectSecurityHeaders(r.headers);
  });

  it("sets the headers on an authenticated API response", async () => {
    const r = await get("/api/connections", {
      authorization: `Bearer ${adminToken}`,
    });
    expect(r.status).toBe(200);
    expectSecurityHeaders(r.headers);
  });
});
