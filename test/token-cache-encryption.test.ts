/**
 * Cached UPSTREAM access tokens must be sealed at rest.
 *
 * Integrations that do not hold a static secret mint a short-lived upstream
 * token (OAuth bearer, GCP access token, Docker Hub JWT, GitHub App
 * installation token) and cache it in the settings table. Those are the
 * actual credentials the proxy injects, so a plaintext cache row would hand a
 * leaked DB file live upstream access, defeating the at-rest encryption
 * applied to credentials and connections.
 *
 * Covers: sealed on write, round-trips on read, a legacy plaintext row is
 * still readable, and an undecryptable row degrades to a cache miss instead of
 * throwing into the request path.
 */
import { createRequire } from "node:module";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { Store } from "../src/store/db.js";
import { oauthBearerToken } from "../src/integrations/oauth.js";
import { dockerHubToken } from "../src/integrations/docker.js";
import type { OAuthDescriptor } from "../src/integrations/types.js";
import type { Credential } from "../src/types.js";

const require = createRequire(import.meta.url);
const { DatabaseSync } = require("node:sqlite") as typeof import("node:sqlite");

let dir: string;
let dbPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "og-tokcache-"));
  dbPath = join(dir, "onegate.db");
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

/** Reads a settings value straight out of the SQLite file, bypassing the Store. */
function rawSetting(key: string): string | null {
  const db = new DatabaseSync(dbPath, { readOnly: true });
  const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as
    | { value: string }
    | undefined;
  db.close();
  return row ? row.value : null;
}

/** Writes a settings value straight into the SQLite file, bypassing the Store. */
function writeRawSetting(key: string, value: string): void {
  const db = new DatabaseSync(dbPath);
  db.prepare(
    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
  ).run(key, value);
  db.close();
}

describe("Store secret settings", () => {
  it("seals on write and round-trips on read", () => {
    const store = new Store(dbPath);
    store.setSecretSetting("oauth_access_token:testx:cr_1", {
      token: "ya29.SUPERSECRET",
      exp: Date.now() + 3_600_000,
    });
    store.close();

    const raw = rawSetting("oauth_access_token:testx:cr_1")!;
    expect(raw.startsWith("enc.v1:")).toBe(true);
    expect(raw).not.toContain("ya29.SUPERSECRET");

    const reopened = new Store(dbPath);
    expect(reopened.getSecretSetting<{ token: string }>("oauth_access_token:testx:cr_1")?.token).toBe(
      "ya29.SUPERSECRET",
    );
    reopened.close();
  });

  it("reads a pre-existing legacy plaintext row without throwing", () => {
    const store = new Store(dbPath);
    // A row written by an older build: plain JSON, no envelope.
    writeRawSetting("docker_hub_jwt:cr_legacy", JSON.stringify({ token: "legacy_jwt", exp: 1 }));
    expect(store.getSecretSetting<{ token: string }>("docker_hub_jwt:cr_legacy")).toEqual({
      token: "legacy_jwt",
      exp: 1,
    });
    store.close();
  });

  it("degrades an undecryptable row to a cache miss instead of throwing", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const store = new Store(dbPath);
    // Sealed under a different key (or truncated): the GCM tag will not verify.
    writeRawSetting("gcp_access_token:cr_x:abc", "enc.v1:" + Buffer.from("garbage").toString("base64"));
    expect(store.getSecretSetting("gcp_access_token:cr_x:abc")).toBeNull();
    expect(warn).toHaveBeenCalled();
    // Never logs the stored value.
    expect(warn.mock.calls.flat().join(" ")).not.toContain("enc.v1:");
    store.close();
  });

  it("returns null for a missing key", () => {
    const store = new Store(dbPath);
    expect(store.getSecretSetting("github_app_token:nope")).toBeNull();
    store.close();
  });

  it("leaves the plain setSetting/getSetting API untouched", () => {
    const store = new Store(dbPath);
    store.setSetting("admin_token", "not-a-secret-blob");
    expect(store.getSetting("admin_token")).toBe("not-a-secret-blob");
    store.close();
    expect(rawSetting("admin_token")).toBe("not-a-secret-blob");
  });
});

describe("integration token caches are sealed", () => {
  let server: http.Server;
  let port: number;
  let respond: () => { status: number; body: unknown };

  beforeEach(async () => {
    server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const r = respond();
        res.writeHead(r.status, { "content-type": "application/json" });
        res.end(JSON.stringify(r.body));
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as { port: number }).port;
  });
  afterEach(async () => {
    await new Promise<void>((r) => server.close(() => r()));
    delete process.env.ONEGATE_OAUTH_TOKEN_URL_TESTX;
    delete process.env.ONEGATE_DOCKER_LOGIN_URL;
  });

  const descriptor: OAuthDescriptor = {
    authUrl: "https://auth.example.com/authorize",
    tokenUrl: "https://auth.example.com/token",
    defaultScopes: ["read"],
  };
  const cred = (data: Record<string, string>, id = "cr_tc"): Credential => ({
    id,
    integrationId: "testx",
    name: "t",
    data,
    createdAt: "",
  });

  it("oauthBearerToken never writes the refreshed token in cleartext", async () => {
    process.env.ONEGATE_OAUTH_TOKEN_URL_TESTX = `http://127.0.0.1:${port}/token`;
    respond = () => ({ status: 200, body: { access_token: "at_PLAINTEXT", expires_in: 3600 } });

    const store = new Store(dbPath);
    const c = cred({ clientId: "cid", clientSecret: "cs", refreshToken: "rt" });
    expect(await oauthBearerToken({ id: "testx", oauth: descriptor }, c, store)).toBe("at_PLAINTEXT");
    // Second call is served from the sealed cache (the server would answer the
    // same token anyway, so assert the row shape rather than the call count).
    expect(await oauthBearerToken({ id: "testx", oauth: descriptor }, c, store)).toBe("at_PLAINTEXT");
    store.close();

    const raw = rawSetting("oauth_access_token:testx:cr_tc")!;
    expect(raw.startsWith("enc.v1:")).toBe(true);
    expect(raw).not.toContain("at_PLAINTEXT");
  });

  it("oauthBearerToken re-mints when the cached row is undecryptable", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    process.env.ONEGATE_OAUTH_TOKEN_URL_TESTX = `http://127.0.0.1:${port}/token`;
    let calls = 0;
    respond = () => {
      calls++;
      return { status: 200, body: { access_token: `at_${calls}`, expires_in: 3600 } };
    };

    const store = new Store(dbPath);
    const c = cred({ clientId: "cid", clientSecret: "cs", refreshToken: "rt" });
    expect(await oauthBearerToken({ id: "testx", oauth: descriptor }, c, store)).toBe("at_1");

    // Corrupt the sealed cache row (simulates a rotated ONEGATE_DB_KEY).
    store.setSetting(
      "oauth_access_token:testx:cr_tc",
      "enc.v1:" + Buffer.from("not-a-valid-envelope").toString("base64"),
    );
    // The request path must not throw: it re-mints and re-seals.
    expect(await oauthBearerToken({ id: "testx", oauth: descriptor }, c, store)).toBe("at_2");
    store.close();

    expect(rawSetting("oauth_access_token:testx:cr_tc")!.startsWith("enc.v1:")).toBe(true);
  });

  it("oauthBearerToken still honors a legacy plaintext cache row", async () => {
    process.env.ONEGATE_OAUTH_TOKEN_URL_TESTX = `http://127.0.0.1:${port}/token`;
    // If the legacy row were ignored the call would refresh and return this.
    respond = () => ({ status: 200, body: { access_token: "refreshed_not_expected", expires_in: 3600 } });
    const store = new Store(dbPath);
    writeRawSetting(
      "oauth_access_token:testx:cr_tc",
      JSON.stringify({ token: "legacy_at", exp: Date.now() + 3_600_000 }),
    );
    const c = cred({ clientId: "cid", clientSecret: "cs", refreshToken: "rt" });
    expect(await oauthBearerToken({ id: "testx", oauth: descriptor }, c, store)).toBe("legacy_at");
    store.close();
  });

  it("dockerHubToken never writes the Hub JWT in cleartext", async () => {
    process.env.ONEGATE_DOCKER_LOGIN_URL = `http://127.0.0.1:${port}/v2/users/login`;
    respond = () => ({ status: 200, body: { token: "dockerjwt_PLAINTEXT" } });

    const store = new Store(dbPath);
    const c: Credential = {
      id: "cr_dock",
      integrationId: "docker",
      name: "d",
      data: { username: "u", apiToken: "dckr_pat_x" },
      createdAt: "",
    };
    expect(await dockerHubToken(c, store)).toBe("dockerjwt_PLAINTEXT");
    expect(await dockerHubToken(c, store)).toBe("dockerjwt_PLAINTEXT");
    store.close();

    const raw = rawSetting("docker_hub_jwt:cr_dock")!;
    expect(raw.startsWith("enc.v1:")).toBe(true);
    expect(raw).not.toContain("dockerjwt_PLAINTEXT");
  });
});
