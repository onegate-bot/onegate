/**
 * Coverage-focused end-to-end tests for the `integrations` and `credentials`
 * CLI command modules (src/cli/commands/integrations.ts). Uses the same harness
 * as cli-admin.test.ts: a real admin server on an ephemeral port over a temp-dir
 * store, with main() driven through ONEGATE_ADMIN_URL / ONEGATE_ADMIN_TOKEN.
 *
 * cli-admin.test.ts already covers the happy paths (list, connect, credentials
 * set/rm). This file targets what it does not: the access-lease sub-commands,
 * the duration parser, the flag-parsing rejections and every unknown-command /
 * usage-error exit path.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import http from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/store/db.js";
import { initCa } from "../src/ca.js";
import { buildRegistry } from "../src/integrations/index.js";
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";
import { setJsonMode } from "../src/cli/output.js";
import { main } from "../src/cli.js";

let dir: string;
let store: Store;
let server: http.Server;
let port: number;
let adminToken: string;
let logs: string[];
let errs: string[];
let exitCode: number | null;

let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;
let outSpy: ReturnType<typeof vi.spyOn>;
let exitSpy: ReturnType<typeof vi.spyOn>;

async function run(...argv: string[]): Promise<{ out: string; err: string; exit: number | null }> {
  logs = [];
  errs = [];
  exitCode = null;
  setJsonMode(false);
  try {
    await main(argv);
  } catch (e) {
    if ((e as Error).message !== "__exit__") throw e;
  }
  return { out: logs.join("\n"), err: errs.join("\n"), exit: exitCode };
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-cliint-"));
  process.env.ONEGATE_DATA = dir;
  initCa(dir);
  store = new Store(join(dir, "onegate.db"));
  adminToken = ensureAdminToken(store)!;
  const registry = await buildRegistry();
  const app = createAdminApp({ store, registry, ca: { rootPem: "x" } as never, version: "test" });
  server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as { port: number }).port;

  process.env.ONEGATE_ADMIN_URL = `http://127.0.0.1:${port}`;
  process.env.ONEGATE_ADMIN_TOKEN = adminToken;

  logSpy = vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => {
    logs.push(a.join(" "));
  });
  errSpy = vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => {
    errs.push(a.join(" "));
  });
  outSpy = vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
    logs.push(String(chunk));
    return true;
  }) as never);
  exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
    exitCode = code ?? 0;
    throw new Error("__exit__");
  }) as never);
});

afterAll(async () => {
  logSpy.mockRestore();
  errSpy.mockRestore();
  outSpy.mockRestore();
  exitSpy.mockRestore();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  store.close();
  delete process.env.ONEGATE_DATA;
  delete process.env.ONEGATE_ADMIN_URL;
  delete process.env.ONEGATE_ADMIN_TOKEN;
  rmSync(dir, { recursive: true, force: true });
});

describe("cli integrations: list", () => {
  it("renders the human table with the lease/llm columns", async () => {
    const { out, exit } = await run("integrations", "list");
    expect(exit).toBeNull();
    // Header row from the table renderer.
    expect(out).toContain("ID");
    expect(out).toContain("CATEGORY");
    expect(out).toContain("CONNECTED");
    expect(out).toContain("LLM");
    expect(out).toContain("TIMEBOX");
    expect(out).toContain("github");
    // github is not an LLM vendor and is not time-boxed, so both fall back to "-".
    const githubRow = out.split("\n").find((l) => l.startsWith("github "));
    expect(githubRow).toBeTruthy();
    expect(githubRow).toContain("-");
    // hetzner ships time-boxed at 8h by default, so fmtLease renders whole hours.
    const hetznerRow = out.split("\n").find((l) => l.startsWith("hetzner "));
    expect(hetznerRow).toContain("8h");
  });

  it("shows the vendor for an LLM integration", async () => {
    const { out } = await run("--json", "integrations", "list");
    const items = JSON.parse(out) as Array<{ id: string; llm: { vendor: string } | null }>;
    const anthropic = items.find((i) => i.id === "anthropic");
    expect(anthropic?.llm?.vendor).toBe("anthropic");
    const human = await run("integrations", "list");
    expect(human.out.split("\n").find((l) => l.startsWith("anthropic "))).toContain("anthropic");
  });

  it("the ls alias behaves like list", async () => {
    const { out } = await run("--json", "integrations", "ls");
    const items = JSON.parse(out) as Array<{ id: string }>;
    expect(items.some((i) => i.id === "github")).toBe(true);
  });
});

describe("cli integrations: connect", () => {
  it("prints the authorize URL and the registered redirect URI", async () => {
    const { out, exit } = await run(
      "integrations",
      "connect",
      "google",
      "--client-id",
      "cid-123",
      "--client-secret",
      "csec-456",
      "--redirect-base",
      "https://gw.example.com",
    );
    expect(exit).toBeNull();
    expect(out).toContain("Open this URL in a browser to authorize");
    expect(out).toContain("https://accounts.google.com");
    expect(out).toContain("client_id=cid-123");
    expect(out).toContain("Redirect URI registered: https://gw.example.com");
  });

  it("--scopes is split, trimmed and empty entries dropped", async () => {
    const { out } = await run(
      "--json",
      "integrations",
      "connect",
      "google",
      "--client-id",
      "cid-scoped",
      "--client-secret",
      "csec",
      "--redirect-base",
      "https://gw.example.com",
      "--scopes",
      " https://www.googleapis.com/auth/gmail.readonly , , openid ",
    );
    const res = JSON.parse(out) as { url: string };
    const scope = new URL(res.url).searchParams.get("scope") ?? "";
    expect(scope).toContain("gmail.readonly");
    expect(scope).toContain("openid");
    // The blank entry between the commas must not survive as an empty scope.
    expect(scope.split(" ").filter((s) => s === "")).toHaveLength(0);
  });

  it("omitting --client-secret still posts (defaulted to empty) and lets the API decide", async () => {
    // The CLI only requires id + --client-id + --redirect-base; the secret is
    // defaulted to "". Google is a confidential client, so the server rejects
    // it, which proves the request was sent rather than blocked client-side.
    const { err, exit } = await run(
      "integrations",
      "connect",
      "google",
      "--client-id",
      "cid-public",
      "--redirect-base",
      "https://gw.example.com",
    );
    expect(exit).toBe(1);
    expect(err).toContain("clientSecret");
  });

  it("fails without a positional integration id", async () => {
    const { err, exit } = await run(
      "integrations",
      "connect",
      "--client-id",
      "cid",
      "--redirect-base",
      "https://gw.example.com",
    );
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate integrations connect <id>");
  });

  it("fails without --client-id", async () => {
    const { err, exit } = await run(
      "integrations",
      "connect",
      "google",
      "--redirect-base",
      "https://gw.example.com",
    );
    expect(exit).toBe(1);
    expect(err).toContain("--client-id");
  });

  it("fails without --redirect-base", async () => {
    const { err, exit } = await run("integrations", "connect", "google", "--client-id", "cid");
    expect(exit).toBe(1);
    expect(err).toContain("--redirect-base");
  });

  it("surfaces the API error for a non-OAuth integration", async () => {
    const { err, exit } = await run(
      "integrations",
      "connect",
      "github",
      "--client-id",
      "cid",
      "--redirect-base",
      "https://gw.example.com",
    );
    expect(exit).toBe(1);
    expect(err).toBeTruthy();
  });
});

describe("cli integrations: lease", () => {
  it("lease list shows the seeded hetzner default", async () => {
    const { out, exit } = await run("integrations", "lease", "list");
    expect(exit).toBeNull();
    expect(out).toContain("INTEGRATION");
    expect(out).toContain("DEFAULT TIMEBOX");
    expect(out).toContain("hetzner");
    expect(out).toContain("8h");
  });

  it("a bare `lease` with no verb defaults to list", async () => {
    const { out } = await run("--json", "integrations", "lease");
    const rows = JSON.parse(out) as Array<{ integrationId: string; ttlSeconds: number }>;
    expect(rows.some((r) => r.integrationId === "hetzner" && r.ttlSeconds === 28800)).toBe(true);
  });

  it("the ls alias behaves like lease list", async () => {
    const { out } = await run("--json", "integrations", "lease", "ls");
    const rows = JSON.parse(out) as Array<{ integrationId: string }>;
    expect(rows.some((r) => r.integrationId === "hetzner")).toBe(true);
  });

  it("lease set accepts hour shorthand", async () => {
    const { out, exit } = await run("integrations", "lease", "set", "github", "2h");
    expect(exit).toBeNull();
    expect(out).toBe("github is time-boxed, default 2h.");
    expect(store.getIntegrationLease("github")).toBe(7200);
  });

  it("lease set accepts minute shorthand and renders sub-hour TTLs in seconds", async () => {
    const { out } = await run("integrations", "lease", "set", "github", "30m");
    // 1800 is not a whole number of hours, so fmtLease falls back to seconds.
    expect(out).toBe("github is time-boxed, default 1800s.");
    expect(store.getIntegrationLease("github")).toBe(1800);
  });

  it("lease set accepts bare seconds and an explicit s suffix", async () => {
    await run("integrations", "lease", "set", "github", "3600");
    expect(store.getIntegrationLease("github")).toBe(3600);
    await run("integrations", "lease", "set", "github", "45s");
    expect(store.getIntegrationLease("github")).toBe(45);
  });

  it("lease set tolerates whitespace and an uppercase unit", async () => {
    const { out } = await run("integrations", "lease", "set", "github", " 3 H ");
    expect(out).toBe("github is time-boxed, default 3h.");
    expect(store.getIntegrationLease("github")).toBe(10800);
  });

  it("lease set rejects a malformed duration before calling the API", async () => {
    const { err, exit } = await run("integrations", "lease", "set", "github", "8 hours");
    expect(exit).toBe(1);
    expect(err).toContain('invalid duration "8 hours"');
    expect(err).toContain('use seconds, or "8h" / "30m"');
    // The prior value must be untouched since the parser threw first.
    expect(store.getIntegrationLease("github")).toBe(10800);
  });

  it("lease set rejects a negative duration", async () => {
    const { err, exit } = await run("integrations", "lease", "set", "github", "-5");
    expect(exit).toBe(1);
    expect(err).toContain("invalid duration");
  });

  it("lease set without a duration fails with usage", async () => {
    const { err, exit } = await run("integrations", "lease", "set", "github");
    expect(exit).toBe(1);
    expect(err).toBe("onegate: usage: onegate integrations lease set <id> <duration>");
  });

  it("lease set without an id fails with usage", async () => {
    const { err, exit } = await run("integrations", "lease", "set");
    expect(exit).toBe(1);
    expect(err).toBe("onegate: usage: onegate integrations lease set <id> <duration>");
  });

  it("lease set surfaces a 404 for an unknown integration", async () => {
    const { err, exit } = await run("integrations", "lease", "set", "not-a-real-integration", "1h");
    expect(exit).toBe(1);
    expect(err).toContain("unknown_integration");
  });

  it("lease clear turns the integration back into a regular one", async () => {
    const { out, exit } = await run("integrations", "lease", "clear", "github");
    expect(exit).toBeNull();
    expect(out).toBe("github is now a regular (non-time-boxed) integration.");
    expect(store.getIntegrationLease("github")).toBeNull();
  });

  it("the rm alias clears a lease and emits the same shape in json mode", async () => {
    await run("integrations", "lease", "set", "github", "1h");
    const { out } = await run("--json", "integrations", "lease", "rm", "github");
    expect(JSON.parse(out)).toEqual({ integrationId: "github", ttlSeconds: null });
    expect(store.getIntegrationLease("github")).toBeNull();
  });

  it("lease clear without an id fails with usage", async () => {
    const { err, exit } = await run("integrations", "lease", "clear");
    expect(exit).toBe(1);
    expect(err).toBe("onegate: usage: onegate integrations lease clear <id>");
  });

  it("an unknown lease verb is rejected", async () => {
    const { err, exit } = await run("integrations", "lease", "bogus");
    expect(exit).toBe(1);
    expect(err).toContain('unknown integrations lease command "bogus"');
    expect(err).toContain("Try: list, set, clear");
  });

  it("lease list reports the empty case when nothing is time-boxed", async () => {
    // hetzner is the only seeded default; drop it to reach the empty branch,
    // then restore it so later tests (and other files) see the shipped state.
    const before = store.getIntegrationLease("hetzner");
    store.clearIntegrationLease("hetzner");
    try {
      const { out } = await run("integrations", "lease", "list");
      expect(out).toBe("no time-boxed integrations.");
    } finally {
      if (before) store.setIntegrationLease("hetzner", before);
    }
  });
});

describe("cli integrations: unknown sub-command", () => {
  it("rejects an unknown sub-command", async () => {
    const { err, exit } = await run("integrations", "bogus");
    expect(exit).toBe(1);
    expect(err).toContain('unknown integrations command "bogus"');
    expect(err).toContain("Try: list, connect, lease");
  });

  it("rejects a missing sub-command", async () => {
    const { err, exit } = await run("integrations");
    expect(exit).toBe(1);
    expect(err).toContain("unknown integrations command");
  });
});

describe("cli credentials: set", () => {
  it("stores multiple --data pairs and never echoes the secret", async () => {
    const { out, exit } = await run(
      "credentials",
      "set",
      "github",
      "--name",
      "gh-multi",
      "--data",
      "pat=ghp_supersecretvalue1",
      "--data",
      "org=acme",
    );
    expect(exit).toBeNull();
    expect(out).toBe('Credential set for github ("gh-multi").');
    expect(out).not.toContain("ghp_supersecretvalue1");
    const cred = store.getCredential("github")!;
    expect(cred.name).toBe("gh-multi");
    expect(cred.data).toMatchObject({ pat: "ghp_supersecretvalue1", org: "acme" });
  });

  it("defaults the name to the integration id when --name is omitted", async () => {
    const { out } = await run("credentials", "set", "github", "--data", "pat=ghp_named");
    expect(out).toBe('Credential set for github ("github").');
    expect(store.getCredential("github")!.name).toBe("github");
  });

  it("keeps everything after the first = in the value", async () => {
    await run("credentials", "set", "github", "--data", "pat=a=b=c");
    expect(store.getCredential("github")!.data.pat).toBe("a=b=c");
  });

  it("json mode emits only the id/integrationId/name, never the data", async () => {
    const { out } = await run(
      "--json",
      "credentials",
      "set",
      "github",
      "--name",
      "gh-json",
      "--data",
      "pat=ghp_jsonmodesecret2",
    );
    const res = JSON.parse(out) as Record<string, unknown>;
    expect(Object.keys(res).sort()).toEqual(["id", "integrationId", "name"]);
    expect(res.integrationId).toBe("github");
    expect(res.name).toBe("gh-json");
    expect(out).not.toContain("ghp_jsonmodesecret2");
  });

  it("the add alias behaves like set", async () => {
    const { out } = await run("credentials", "add", "github", "--data", "pat=ghp_aliased");
    expect(out).toContain("Credential set for github");
  });

  it("fails without a positional integration id", async () => {
    const { err, exit } = await run("credentials", "set", "--data", "pat=x");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate credentials set <integrationId>");
  });

  it("fails when no --data pair is given", async () => {
    const { err, exit } = await run("credentials", "set", "github", "--name", "gh");
    expect(exit).toBe(1);
    expect(err).toBe("onegate: at least one --data k=v is required");
  });

  it("rejects a --data value with no =", async () => {
    const { err, exit } = await run("credentials", "set", "github", "--data", "justakey");
    expect(exit).toBe(1);
    expect(err).toBe('onegate: --data must be key=value, got "justakey"');
  });

  it("rejects a --data value with an empty key", async () => {
    const { err, exit } = await run("credentials", "set", "github", "--data", "=novalue");
    expect(exit).toBe(1);
    expect(err).toBe('onegate: --data must be key=value, got "=novalue"');
  });

  it("surfaces a 404 for an unknown integration", async () => {
    const { err, exit } = await run(
      "credentials",
      "set",
      "not-a-real-integration",
      "--data",
      "pat=x",
    );
    expect(exit).toBe(1);
    expect(err).toContain("unknown_integration");
  });
});

describe("cli credentials: rm", () => {
  it("removes the stored credential", async () => {
    await run("credentials", "set", "github", "--data", "pat=ghp_tobedeleted");
    const { out, exit } = await run("credentials", "rm", "github");
    expect(exit).toBeNull();
    expect(out).toBe("Removed credential for github.");
    expect(store.getCredential("github")).toBeNull();
  });

  it("the remove and delete aliases work and are idempotent", async () => {
    const remove = await run("credentials", "remove", "github");
    expect(remove.out).toBe("Removed credential for github.");
    const del = await run("--json", "credentials", "delete", "github");
    expect(JSON.parse(del.out)).toEqual({ removed: "github" });
  });

  it("fails without an integration id", async () => {
    const { err, exit } = await run("credentials", "rm");
    expect(exit).toBe(1);
    expect(err).toBe("onegate: usage: onegate credentials rm <integrationId>");
  });

  it("rejects an unknown credentials sub-command", async () => {
    const { err, exit } = await run("credentials", "bogus");
    expect(exit).toBe(1);
    expect(err).toContain('unknown credentials command "bogus"');
    expect(err).toContain("Try: set, rm");
  });

  it("rejects a missing credentials sub-command", async () => {
    const { err, exit } = await run("credentials");
    expect(exit).toBe(1);
    expect(err).toContain("unknown credentials command");
  });
});
