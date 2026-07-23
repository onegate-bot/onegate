/**
 * Unit tests for the M0 admin client: token/host resolution and error mapping.
 * A tiny stub server stands in for the admin API so no full app is needed.
 */

import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import { AdminClient, ApiError, resolveHost, resolveToken } from "../src/cli/client.js";

function stub(handler: http.RequestListener): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as { port: number }).port;
      resolve({ url: `http://127.0.0.1:${port}`, close: () => server.close() });
    });
  });
}

afterEach(() => {
  delete process.env.ONEGATE_ADMIN_TOKEN;
  delete process.env.ONEGATE_ADMIN_URL;
});

describe("resolveToken", () => {
  it("prefers the explicit token", () => {
    process.env.ONEGATE_ADMIN_TOKEN = "oga_env";
    expect(resolveToken("oga_flag")).toBe("oga_flag");
  });
  it("falls back to the env var", () => {
    process.env.ONEGATE_ADMIN_TOKEN = "oga_env";
    expect(resolveToken(undefined)).toBe("oga_env");
  });
  it("throws a clear error when neither is set", () => {
    expect(() => resolveToken(undefined)).toThrow(/admin token/);
  });
});

describe("resolveHost", () => {
  it("defaults to localhost:8080", () => {
    expect(resolveHost(undefined)).toBe("http://localhost:8080");
  });
  it("honors the env var", () => {
    process.env.ONEGATE_ADMIN_URL = "http://example:9000";
    expect(resolveHost(undefined)).toBe("http://example:9000");
  });
});

describe("AdminClient error mapping", () => {
  it("maps 401 to a token-rejected message", async () => {
    const s = await stub((_req, res) => {
      res.statusCode = 401;
      res.end(JSON.stringify({ error: "invalid_admin_token" }));
    });
    const client = new AdminClient({ host: s.url, token: "oga_x" });
    await expect(client.get("/api/agents")).rejects.toThrow(/admin token rejected \(401\)/);
    s.close();
  });

  it("surfaces error+message on a 400", async () => {
    const s = await stub((_req, res) => {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "unknown_vendor", message: "vendor must be one of: anthropic" }));
    });
    const client = new AdminClient({ host: s.url, token: "oga_x" });
    try {
      await client.post("/api/connections", {});
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      expect((e as ApiError).status).toBe(400);
      expect((e as Error).message).toContain("unknown_vendor");
      expect((e as Error).message).toContain("anthropic");
    }
    s.close();
  });

  it("returns the parsed body on success", async () => {
    const s = await stub((_req, res) => {
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ ok: true, items: [1, 2] }));
    });
    const client = new AdminClient({ host: s.url, token: "oga_x" });
    const body = (await client.get("/api/x")) as { ok: boolean; items: number[] };
    expect(body.ok).toBe(true);
    expect(body.items).toEqual([1, 2]);
    s.close();
  });

  it("gives a clear error when the host is unreachable", async () => {
    // Port 1 is privileged and not listening: connection refused.
    const client = new AdminClient({ host: "http://127.0.0.1:1", token: "oga_x" });
    await expect(client.get("/api/x")).rejects.toThrow(/cannot reach admin API/);
  });
});
