/**
 * Unit tests for the M0 admin client: token/host resolution and error mapping.
 * A tiny stub server stands in for the admin API so no full app is needed.
 */

import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import { AdminClient, ApiError, resolveHost, resolveToken, tokenMatchesStore } from "../src/cli/client.js";
import { Store } from "../src/store/db.js";
import { ensureAdminToken } from "../src/admin/api.js";
import { isJsonMode, setJsonMode } from "../src/cli/output.js";

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

describe("AdminClient non-JSON and edge responses", () => {
  async function errorFor(status: number, body: string): Promise<ApiError> {
    const s = await stub((_req, res) => {
      res.statusCode = status;
      res.end(body);
    });
    try {
      await new AdminClient({ host: s.url, token: "oga_x" }).get("/api/x");
      throw new Error("should have thrown");
    } catch (e) {
      return e as ApiError;
    } finally {
      s.close();
    }
  }

  it("maps 403 to a fixed message regardless of the body", async () => {
    const e = await errorFor(403, JSON.stringify({ error: "nope", message: "secret detail" }));
    expect(e.status).toBe(403);
    expect(e.message).toBe("forbidden (403).");
  });

  it("uses a trimmed 200-char snippet of a non-JSON error body", async () => {
    const e = await errorFor(502, `  <html>${"x".repeat(500)}</html>  `);
    expect(e.status).toBe(502);
    expect(e.body).toBeUndefined();
    expect(e.message).toBe(`API error 502: <html>${"x".repeat(194)}`);
  });

  it("falls back to the bare status for an empty error body", async () => {
    expect((await errorFor(500, "")).message).toBe("API error 500");
  });

  it("shows a message-only JSON error, and the raw JSON when it has neither field", async () => {
    expect((await errorFor(409, JSON.stringify({ message: "already decided" }))).message).toBe(
      "API error 409: already decided",
    );
    expect((await errorFor(418, JSON.stringify({ detail: "teapot" }))).message).toBe('API error 418: {"detail":"teapot"}');
  });

  it("a 2xx with a non-JSON or empty body resolves to undefined", async () => {
    for (const body of ["plain text", ""]) {
      const s = await stub((_req, res) => {
        res.statusCode = body ? 200 : 204;
        res.end(body);
      });
      const client = new AdminClient({ host: s.url, token: "oga_x" });
      expect(await client.del("/api/x")).toBeUndefined();
      s.close();
    }
  });

  it("sends the bearer token and a JSON body with the right headers", async () => {
    let seen: { auth?: string; type?: string; len?: string; body: string; method?: string } = { body: "" };
    const s = await stub((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        seen = {
          auth: req.headers.authorization,
          type: req.headers["content-type"],
          len: req.headers["content-length"],
          body,
          method: req.method,
        };
        res.end("{}");
      });
    });
    await new AdminClient({ host: s.url, token: "oga_secret" }).patch("/api/agents/a", { name: "n" });
    s.close();
    expect(seen).toEqual({
      auth: "Bearer oga_secret",
      type: "application/json",
      len: String(Buffer.byteLength('{"name":"n"}')),
      body: '{"name":"n"}',
      method: "PATCH",
    });
  });
});

describe("tokenMatchesStore", () => {
  it("matches only the exact admin token, and never when none is stored", () => {
    const store = new Store(":memory:");
    expect(tokenMatchesStore(store, "oga_anything")).toBe(false);
    const token = ensureAdminToken(store)!;
    expect(tokenMatchesStore(store, token)).toBe(true);
    expect(tokenMatchesStore(store, `${token}x`)).toBe(false);
    expect(tokenMatchesStore(store, "")).toBe(false);
    store.close();
  });
});

describe("json mode flag", () => {
  it("reflects setJsonMode", () => {
    setJsonMode(true);
    expect(isJsonMode()).toBe(true);
    setJsonMode(false);
    expect(isJsonMode()).toBe(false);
  });
});
