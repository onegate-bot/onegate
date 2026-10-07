/**
 * The public base URL for owner-facing links (approve, connect, renew).
 *
 * Those links carry one-time tokens, so they must point at this gateway:
 * ONEGATE_PUBLIC_URL when set (validated), else the admin listener itself.
 * There is no hosted default.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import { initCa } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { buildRegistry } from "../src/integrations/index.js";
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";
import { parsePublicUrl, publicBaseUrlFromEnv, resolvePublicBaseUrl } from "../src/util/public-url.js";

describe("resolvePublicBaseUrl", () => {
  it("uses ONEGATE_PUBLIC_URL when set", () => {
    expect(resolvePublicBaseUrl({ publicUrl: "https://gate.example.com", bind: "10.0.0.5", adminPort: 9000 })).toEqual({
      url: "https://gate.example.com",
      fallback: false,
    });
  });

  it("strips trailing slashes and keeps a reverse-proxy path prefix", () => {
    expect(parsePublicUrl("https://gate.example.com/")).toBe("https://gate.example.com");
    expect(parsePublicUrl("  http://gate.example.com:8443/onegate//  ")).toBe("http://gate.example.com:8443/onegate");
  });

  it("throws on a malformed value", () => {
    for (const bad of ["gate.example.com", "not a url", "ftp://gate.example.com", "javascript:alert(1)"]) {
      expect(() => resolvePublicBaseUrl({ publicUrl: bad })).toThrow(/ONEGATE_PUBLIC_URL/);
    }
    expect(() => parsePublicUrl("https://gate.example.com/?x=1")).toThrow(/query or fragment/);
    expect(() => parsePublicUrl("https://gate.example.com/#frag")).toThrow(/query or fragment/);
  });

  it("falls back to the admin listener on a concrete bind address", () => {
    expect(resolvePublicBaseUrl({ bind: "192.168.1.20", adminPort: 9090 })).toEqual({
      url: "http://192.168.1.20:9090",
      fallback: true,
    });
    expect(resolvePublicBaseUrl({ bind: "::1", adminPort: 8080 }).url).toBe("http://[::1]:8080");
    expect(resolvePublicBaseUrl({ bind: "[::1]", adminPort: 8080 }).url).toBe("http://[::1]:8080");
  });

  it("falls back to localhost without a bind address or on a wildcard one", () => {
    for (const bind of [undefined, "", "0.0.0.0", "::", "[::]"]) {
      expect(resolvePublicBaseUrl({ bind, adminPort: 8080 })).toEqual({ url: "http://localhost:8080", fallback: true });
    }
    // A blank ONEGATE_PUBLIC_URL counts as unset.
    expect(resolvePublicBaseUrl({ publicUrl: "  " }).url).toBe("http://localhost:8080");
  });

  it("reads the same values from the environment", () => {
    expect(publicBaseUrlFromEnv({ ONEGATE_PUBLIC_URL: "https://gate.example.com/" }).url).toBe(
      "https://gate.example.com",
    );
    expect(publicBaseUrlFromEnv({ ONEGATE_BIND: "10.1.2.3", ONEGATE_ADMIN_PORT: "9999" })).toEqual({
      url: "http://10.1.2.3:9999",
      fallback: true,
    });
    expect(publicBaseUrlFromEnv({ ONEGATE_ADMIN_PORT: "nope" }).url).toBe("http://localhost:8080");
  });
});

describe("admin links use the resolved base", () => {
  let dir: string;
  const servers: http.Server[] = [];

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "onegate-public-url-"));
  });

  afterAll(() => {
    for (const s of servers) s.close();
    rmSync(dir, { recursive: true, force: true });
  });

  async function mintConnectLink(publicBaseUrl?: string): Promise<string> {
    const store = new Store(":memory:");
    const ca = initCa(join(dir, String(servers.length)));
    const registry = await buildRegistry();
    const adminToken = ensureAdminToken(store)!;
    const agentId = store.createAgent("linker").agent.id;
    const server = http.createServer(createAdminApp({ store, registry, ca, version: "test", publicBaseUrl }));
    servers.push(server);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    const r = await fetch(`http://127.0.0.1:${port}/api/onboarding-links`, {
      method: "POST",
      headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
      body: JSON.stringify({ agentId, integrationId: "gitlab" }),
    });
    expect(r.status).toBe(201);
    return ((await r.json()) as { url: string }).url;
  }

  it("emits connect links on the configured base", async () => {
    const url = await mintConnectLink("https://gate.example.com/og");
    expect(url).toMatch(/^https:\/\/gate\.example\.com\/og\/connect\/gitlab\/[0-9a-f]+$/);
  });

  it("falls back to the admin listener, never a hosted domain", async () => {
    const saved = { url: process.env.ONEGATE_PUBLIC_URL, bind: process.env.ONEGATE_BIND, port: process.env.ONEGATE_ADMIN_PORT };
    delete process.env.ONEGATE_PUBLIC_URL;
    delete process.env.ONEGATE_BIND;
    delete process.env.ONEGATE_ADMIN_PORT;
    try {
      const url = await mintConnectLink();
      expect(url).toMatch(/^http:\/\/localhost:8080\/connect\/gitlab\//);
      expect(url).not.toContain("onegate.bot");
    } finally {
      for (const [k, v] of [
        ["ONEGATE_PUBLIC_URL", saved.url],
        ["ONEGATE_BIND", saved.bind],
        ["ONEGATE_ADMIN_PORT", saved.port],
      ] as const) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });
});
