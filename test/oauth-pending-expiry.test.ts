/**
 * Pending OAuth states must stop being redeemable once they age out.
 *
 * Single-use was already enforced (the callback deletes the entry it reads),
 * but AGE was only applied lazily by the /oauth/start sweep. With no new
 * /oauth/start, a pending entry - which carries the operator's clientId,
 * clientSecret and redirectUri - stayed redeemable indefinitely.
 *
 * These tests drive the real admin app end to end against a stub token
 * endpoint (GitLab descriptor, overridden via ONEGATE_OAUTH_*_URL_GITLAB) and
 * move the clock with fake timers, so nothing here depends on wall time.
 */

import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from "vitest";
import http from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/store/db.js";
import { initCa } from "../src/ca.js";
import { buildRegistry } from "../src/integrations/index.js";
import { createAdminApp, ensureAdminToken, OAUTH_PENDING_TTL_MS } from "../src/admin/api.js";

let dir: string;
let store: Store;
let server: http.Server;
let port: number;
let adminToken: string;

let tokenServer: http.Server;
/** Counts token-endpoint hits, so we can prove a rejected callback never redeems. */
let tokenHits = 0;

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
          resolve({ status: res.statusCode ?? 0, json, text });
        });
      },
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/** The callback route is unauthenticated; hit it without a token. */
function callback(path: string): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "GET", path, agent: false },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

/** Starts a flow and returns its pending state value. */
async function startFlow(name: string): Promise<string> {
  const start = await api("POST", "/api/integrations/gitlab/oauth/start", {
    clientId: "cid",
    clientSecret: "csecret",
    redirectBase: `http://127.0.0.1:${port}`,
    connectionName: name,
    ownerAgentId: null,
  });
  expect(start.status).toBe(200);
  const state = new URL(start.json.url).searchParams.get("state");
  expect(state).toBeTruthy();
  return state!;
}

beforeAll(async () => {
  tokenServer = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      tokenHits++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: "gl_at_1",
          refresh_token: "gl_rt_1",
          expires_in: 3600,
          scope: "api",
        }),
      );
    });
  });
  await new Promise<void>((r) => tokenServer.listen(0, "127.0.0.1", r));
  const tport = (tokenServer.address() as { port: number }).port;
  process.env.ONEGATE_OAUTH_TOKEN_URL_GITLAB = `http://127.0.0.1:${tport}/token`;
  process.env.ONEGATE_OAUTH_AUTH_URL_GITLAB = `http://127.0.0.1:${tport}/authorize`;

  dir = mkdtempSync(join(tmpdir(), "onegate-oauth-expiry-"));
  store = new Store(":memory:");
  const ca = initCa(dir);
  const registry = await buildRegistry();
  adminToken = ensureAdminToken(store)!;
  const app = createAdminApp({ store, registry, ca, version: "test" });
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as { port: number }).port;
});

afterEach(() => {
  vi.useRealTimers();
});

afterAll(() => {
  server.close();
  tokenServer.close();
  delete process.env.ONEGATE_OAUTH_TOKEN_URL_GITLAB;
  delete process.env.ONEGATE_OAUTH_AUTH_URL_GITLAB;
  rmSync(dir, { recursive: true, force: true });
});

describe("pending OAuth state expiry is enforced at redemption", () => {
  it("rejects a callback whose state is older than the TTL", async () => {
    const state = await startFlow("GitLab stale");
    const before = tokenHits;

    // Age the state past the window without any /oauth/start running, so the
    // lazy sweep never gets a chance to remove it.
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + OAUTH_PENDING_TTL_MS + 1_000);

    const res = await callback(`/oauth/gitlab/callback?state=${state}&code=auth_code_1`);
    expect(res.status).toBe(400);
    expect(res.text).toContain("Invalid or expired OAuth state");
    // The code was never exchanged, so the stale clientId/clientSecret never left the box.
    expect(tokenHits).toBe(before);
    expect(store.listConnections().find((c) => c.name === "GitLab stale")).toBeUndefined();
  });

  it("removes the expired entry, so replaying the same state still fails once time is normal", async () => {
    const state = await startFlow("GitLab replay");

    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + OAUTH_PENDING_TTL_MS + 1_000);
    const first = await callback(`/oauth/gitlab/callback?state=${state}&code=auth_code_1`);
    expect(first.status).toBe(400);
    vi.useRealTimers();

    // If the rejection had left the entry behind it would be redeemable again
    // the moment the clock is back inside the window.
    const before = tokenHits;
    const replay = await callback(`/oauth/gitlab/callback?state=${state}&code=auth_code_1`);
    expect(replay.status).toBe(400);
    expect(replay.text).toContain("Invalid or expired OAuth state");
    expect(tokenHits).toBe(before);
    expect(store.listConnections().find((c) => c.name === "GitLab replay")).toBeUndefined();
  });

  it("still accepts a callback within the TTL", async () => {
    const state = await startFlow("GitLab fresh");

    // Just inside the window: aged, but not expired.
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + OAUTH_PENDING_TTL_MS - 5_000);

    const res = await callback(`/oauth/gitlab/callback?state=${state}&code=auth_code_1`);
    expect(res.status).toBe(200);
    expect(res.text).toContain("connected");

    const conn = store.listConnections().find((c) => c.name === "GitLab fresh");
    expect(conn).toBeTruthy();
    expect(conn!.data.accessToken).toBe("gl_at_1");
  });

  it("shares one TTL constant between the start-route sweep and the callback check", async () => {
    // A single source of truth: the sweep and the redemption check must not be
    // able to drift apart. Both read OAUTH_PENDING_TTL_MS, and the literal
    // appears exactly once in the module.
    const src = await import("node:fs").then((fs) =>
      fs.readFileSync(new URL("../src/admin/api.ts", import.meta.url), "utf8"),
    );
    expect(OAUTH_PENDING_TTL_MS).toBe(600_000);
    // The window is declared once and nowhere else, so no call site can drift.
    expect(src.match(/600_000/g) ?? []).toHaveLength(1);
    expect(src).toContain("export const OAUTH_PENDING_TTL_MS = 600_000;");
    // Every sweep reads the constant instead of its own literal.
    expect(src).not.toMatch(/v\.createdAt > \d/);
    expect(src.match(/v\.createdAt > OAUTH_PENDING_TTL_MS/g) ?? []).toHaveLength(2);
    // ...and so does the redemption-time check in the callback.
    expect(src).toMatch(/pending\.createdAt > OAUTH_PENDING_TTL_MS/);
  });
});
