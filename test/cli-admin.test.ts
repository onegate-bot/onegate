/**
 * End-to-end tests for the admin-API-backed CLI commands (M0-M5). A real
 * admin server is booted on an ephemeral port backed by a file store under
 * ONEGATE_DATA, and main() is driven with ONEGATE_ADMIN_URL / ONEGATE_ADMIN_TOKEN
 * set. This exercises the node:http client, every command module, the auth
 * failure path, and the M1 direct-store fallback for a disabled vendor.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
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
  dir = mkdtempSync(join(tmpdir(), "onegate-cliadmin-"));
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
  delete process.env.ONEGATE_DISABLED_INTEGRATIONS;
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  delete process.env.ONEGATE_DISABLED_INTEGRATIONS;
});

describe("cli admin: agents", () => {
  let agentId: string;

  it("agents add returns a one-time token", async () => {
    const { out } = await run("agents", "add", "worker", "--policy", "allow-all");
    expect(out).toMatch(/Token \(shown ONCE\): og_/);
    expect(out).toContain("default: allow-all");
  });

  it("agents list shows the agent (json mode)", async () => {
    const { out } = await run("--json", "agents", "list");
    const parsed = JSON.parse(out) as Array<{ id: string; name: string }>;
    const a = parsed.find((x) => x.name === "worker");
    expect(a).toBeTruthy();
    agentId = a!.id;
  });

  it("agents rename changes the name", async () => {
    const { out } = await run("agents", "rename", agentId, "worker2");
    expect(out).toContain('renamed to "worker2"');
  });

  it("agents rotate-token mints a new token", async () => {
    const { out } = await run("agents", "rotate-token", agentId);
    expect(out).toMatch(/New token for .* og_/);
  });
});

describe("cli admin: connections + per-agent llm", () => {
  let connId: string;
  let agentId: string;

  beforeAll(async () => {
    const r = await run("--json", "agents", "add", "llmworker");
    agentId = (JSON.parse(r.out) as { id: string }).id;
  });

  it("connections add via API (enabled vendor anthropic)", async () => {
    const { out } = await run(
      "--json",
      "connections",
      "add",
      "--vendor",
      "anthropic",
      "--name",
      "anth-1",
      "--api-key",
      "sk-ant-secret",
      "--default",
    );
    const conn = JSON.parse(out) as { id: string; vendor: string; hasSecret: boolean };
    expect(conn.vendor).toBe("anthropic");
    expect(conn.hasSecret).toBe(true);
    // The secret must never appear in output.
    expect(out).not.toContain("sk-ant-secret");
    connId = conn.id;
  });

  it("connections list shows the connection without the secret", async () => {
    const { out } = await run("connections", "list");
    expect(out).toContain("anth-1");
    expect(out).not.toContain("sk-ant-secret");
  });

  it("agents llm set wires the connection", async () => {
    const { out } = await run(
      "agents",
      "llm",
      "set",
      agentId,
      "--strategy",
      "fallback",
      "--connections",
      connId,
    );
    expect(out).toContain("enabled=true");
    expect(out).toContain("strategy=fallback");
  });

  it("agents llm get reflects the config", async () => {
    const { out } = await run("--json", "agents", "llm", "get", agentId);
    const cfg = JSON.parse(out) as { enabled: boolean; connectionIds: string[] };
    expect(cfg.enabled).toBe(true);
    expect(cfg.connectionIds).toContain(connId);
  });

  it("agents llm clear disables routing", async () => {
    const { out } = await run("--json", "agents", "llm", "clear", agentId);
    const cfg = JSON.parse(out) as { enabled: boolean; connectionIds: string[] };
    expect(cfg.enabled).toBe(false);
    expect(cfg.connectionIds).toEqual([]);
  });

  it("connections rm removes it", async () => {
    const { out } = await run("connections", "rm", connId);
    expect(out).toContain("Removed connection");
  });
});

describe("cli admin: app connections + per-agent app accounts", () => {
  let sharedId: string;
  let mineId: string;
  let agentId: string;

  beforeAll(async () => {
    const r = await run("--json", "agents", "add", "appworker");
    agentId = (JSON.parse(r.out) as { id: string }).id;
  });

  it("connections add --kind app creates a tenant-wide connection", async () => {
    const { out } = await run(
      "--json",
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "github",
      "--name",
      "gh-shared",
      "--data",
      "pat=ghp_sharedsecretvalue1",
      "--default",
    );
    const conn = JSON.parse(out) as {
      id: string;
      kind: string;
      vendor: string;
      ownerAgentId: string | null;
      isDefault: boolean;
    };
    expect(conn.kind).toBe("app");
    expect(conn.vendor).toBe("github");
    expect(conn.ownerAgentId).toBeNull();
    expect(conn.isDefault).toBe(true);
    expect(out).not.toContain("ghp_sharedsecretvalue1");
    sharedId = conn.id;
  });

  it("connections add --kind app --agent creates an agent-bound connection", async () => {
    const { out } = await run(
      "--json",
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "github",
      "--name",
      "gh-mine",
      "--data",
      "pat=ghp_agentboundsecret9",
      "--agent",
      agentId,
    );
    const conn = JSON.parse(out) as { id: string; ownerAgentId: string | null };
    expect(conn.ownerAgentId).toBe(agentId);
    expect(out).not.toContain("ghp_agentboundsecret9");
    mineId = conn.id;
  });

  it("connections add --kind app requires --data", async () => {
    const { err, exit } = await run(
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "github",
      "--name",
      "gh-nodata",
    );
    expect(exit).toBe(1);
    expect(err).toContain("--data");
  });

  it("connections list shows app connections with scope, no secret", async () => {
    const { out } = await run("connections", "list");
    expect(out).toContain("App connections:");
    expect(out).toContain("gh-shared");
    expect(out).toContain("tenant-wide");
    expect(out).toContain("gh-mine");
    expect(out).not.toContain("ghp_sharedsecretvalue1");
    expect(out).not.toContain("ghp_agentboundsecret9");
  });

  it("agents apps set saves the choice", async () => {
    // Default-deny: the choice is only valid for a granted connection. Grant
    // both app connections to this agent first.
    store.grantConnection(sharedId, "agent", agentId);
    store.grantConnection(mineId, "agent", agentId);
    const { out } = await run("agents", "apps", "set", agentId, "github", "--connection", mineId);
    expect(out).toContain(mineId);
    expect(out).toContain("github");
  });

  it("agents apps get reflects the saved choice and lists available connections", async () => {
    const { out } = await run("--json", "agents", "apps", "get", agentId);
    const view = JSON.parse(out) as {
      configs: Array<{ integrationId: string; connectionId: string }>;
      available: Array<{ id: string }>;
    };
    expect(view.configs).toEqual([
      expect.objectContaining({ integrationId: "github", connectionId: mineId }),
    ]);
    const ids = view.available.map((c) => c.id);
    expect(ids).toContain(sharedId);
    expect(ids).toContain(mineId);
    expect(out).not.toContain("ghp_sharedsecretvalue1");
    expect(out).not.toContain("ghp_agentboundsecret9");
  });

  it("agents apps clear removes the choice", async () => {
    const { out } = await run("--json", "agents", "apps", "clear", agentId, "github");
    const res = JSON.parse(out) as { connectionId: string | null };
    expect(res.connectionId).toBeNull();
  });
});

describe("cli admin: connection grants (default-deny authorization)", () => {
  let connId: string;
  let agentId: string;
  let projectId: string;

  beforeAll(async () => {
    const a = await run("--json", "agents", "add", "grantworker");
    agentId = (JSON.parse(a.out) as { id: string }).id;
    const p = await run("--json", "projects", "add", "grant-project");
    projectId = (JSON.parse(p.out) as { id: string }).id;
    const c = await run(
      "--json",
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "github",
      "--name",
      "gh-granted",
      "--data",
      "pat=ghp_grantsecretvalue7",
    );
    connId = (JSON.parse(c.out) as { id: string }).id;
  });

  it("a fresh app connection starts with no grants (default-deny)", async () => {
    const { out } = await run("--json", "connections", "grants", "--id", connId);
    expect(JSON.parse(out)).toEqual([]);
    const { out: human } = await run("connections", "grants", "--id", connId);
    expect(human).toContain("default-deny");
  });

  it("connections grants without --id fails", async () => {
    const { err, exit } = await run("connections", "grants");
    expect(exit).toBe(1);
    expect(err).toContain("--id");
  });

  it("connections grant --agent grants to an agent", async () => {
    const { out } = await run(
      "--json",
      "connections",
      "grant",
      "--id",
      connId,
      "--agent",
      agentId,
    );
    const res = JSON.parse(out) as { scope: string; subjectId: string; granted: boolean };
    expect(res).toMatchObject({ scope: "agent", subjectId: agentId, granted: true });
  });

  it("connections grant --project grants to a project", async () => {
    const { out } = await run(
      "--json",
      "connections",
      "grant",
      "--id",
      connId,
      "--project",
      projectId,
    );
    const res = JSON.parse(out) as { scope: string; subjectId: string; granted: boolean };
    expect(res).toMatchObject({ scope: "project", subjectId: projectId, granted: true });
  });

  it("connections grants lists both grants, leaks no secret", async () => {
    const { out } = await run("--json", "connections", "grants", "--id", connId);
    const grants = JSON.parse(out) as Array<{ scope: string; subjectId: string }>;
    expect(grants).toContainEqual(expect.objectContaining({ scope: "agent", subjectId: agentId }));
    expect(grants).toContainEqual(
      expect.objectContaining({ scope: "project", subjectId: projectId }),
    );
    const { out: human } = await run("connections", "grants", "--id", connId);
    expect(human).toContain("grantworker");
    expect(human).toContain("grant-project");
    expect(human).not.toContain("ghp_grantsecretvalue7");
  });

  it("connections grant requires exactly one of --agent or --project", async () => {
    const neither = await run("connections", "grant", "--id", connId);
    expect(neither.exit).toBe(1);
    expect(neither.err).toContain("exactly one of --agent");
    const both = await run(
      "connections",
      "grant",
      "--id",
      connId,
      "--agent",
      agentId,
      "--project",
      projectId,
    );
    expect(both.exit).toBe(1);
    expect(both.err).toContain("exactly one of --agent");
  });

  it("connections revoke removes a grant", async () => {
    const { out } = await run(
      "--json",
      "connections",
      "revoke",
      "--id",
      connId,
      "--agent",
      agentId,
    );
    const res = JSON.parse(out) as { scope: string; subjectId: string; revoked: boolean };
    expect(res).toMatchObject({ scope: "agent", subjectId: agentId, revoked: true });
    const remaining = await run("--json", "connections", "grants", "--id", connId);
    const grants = JSON.parse(remaining.out) as Array<{ scope: string; subjectId: string }>;
    expect(grants).not.toContainEqual(
      expect.objectContaining({ scope: "agent", subjectId: agentId }),
    );
    expect(grants).toContainEqual(
      expect.objectContaining({ scope: "project", subjectId: projectId }),
    );
  });
});

describe("cli admin: M1 direct-store fallback for a disabled vendor", () => {
  it("refuses without --allow-disabled-vendor", async () => {
    process.env.ONEGATE_DISABLED_INTEGRATIONS = "anthropic";
    const { err, exit } = await run(
      "connections",
      "add",
      "--vendor",
      "anthropic",
      "--name",
      "anth-disabled",
      "--auth-token",
      "tok-secret",
    );
    expect(exit).toBe(1);
    expect(err).toContain("ONEGATE_DISABLED_INTEGRATIONS");
    expect(err).toContain("--allow-disabled-vendor");
  });

  it("writes directly to the store with --allow-disabled-vendor", async () => {
    process.env.ONEGATE_DISABLED_INTEGRATIONS = "anthropic";
    const { out, err } = await run(
      "--json",
      "connections",
      "add",
      "--vendor",
      "anthropic",
      "--name",
      "anth-seeded",
      "--auth-token",
      "tok-secret",
      "--allow-disabled-vendor",
    );
    expect(err).toContain("bypassing the API vendor gate");
    const conn = JSON.parse(out) as { id: string; vendor: string; hasSecret: boolean };
    expect(conn.vendor).toBe("anthropic");
    expect(conn.hasSecret).toBe(true);
    expect(out).not.toContain("tok-secret");

    // The row really landed in the store with the right auth mode + secret.
    const seeded = store.getConnection(conn.id)!;
    expect(seeded.name).toBe("anth-seeded");
    expect(seeded.data.authToken).toBe("tok-secret");
    expect(seeded.data.authMode).toBe("auth_token");
  });
});

describe("cli admin: rules", () => {
  let ruleId: string;
  let agentId: string;

  beforeAll(async () => {
    const r = await run("--json", "agents", "add", "ruleworker");
    agentId = (JSON.parse(r.out) as { id: string }).id;
  });

  it("rules add creates an allow rule", async () => {
    const { out } = await run(
      "--json",
      "rules",
      "add",
      "--scope",
      "agent",
      "--subject",
      agentId,
      "--integration",
      "github",
      "--effect",
      "allow",
      "--methods",
      "GET,POST",
    );
    const rule = JSON.parse(out) as { id: string; effect: string; methods: string[] };
    expect(rule.effect).toBe("allow");
    expect(rule.methods).toEqual(["GET", "POST"]);
    ruleId = rule.id;
  });

  it("rules list shows it", async () => {
    const { out } = await run("rules", "list");
    expect(out).toContain(ruleId);
  });

  it("rules rm removes it", async () => {
    const { out } = await run("rules", "rm", ruleId);
    expect(out).toContain("Removed rule");
  });
});

describe("cli admin: integrations + credentials", () => {
  it("integrations list includes github", async () => {
    const { out } = await run("--json", "integrations", "list");
    const items = JSON.parse(out) as Array<{ id: string }>;
    expect(items.some((i) => i.id === "github")).toBe(true);
  });

  it("credentials set then rm", async () => {
    const set = await run("credentials", "set", "github", "--name", "gh", "--data", "pat=ghp_secret");
    expect(set.out).toContain("Credential set for github");
    expect(set.out).not.toContain("ghp_secret");
    const rm = await run("credentials", "rm", "github");
    expect(rm.out).toContain("Removed credential for github");
  });

  it("integrations connect prints an OAuth URL (browser-only)", async () => {
    const { out } = await run(
      "integrations",
      "connect",
      "google",
      "--client-id",
      "cid",
      "--client-secret",
      "csec",
      "--redirect-base",
      "https://gw.example.com",
    );
    expect(out).toContain("https://");
    expect(out).toContain("Open this URL");
  });
});

describe("cli admin: audit + usage", () => {
  it("audit returns rows (possibly empty) without error", async () => {
    const { out, exit } = await run("--json", "audit", "--limit", "5");
    expect(exit).toBeNull();
    expect(Array.isArray(JSON.parse(out))).toBe(true);
  });

  it("usage returns rollups", async () => {
    const { out, exit } = await run("--json", "usage");
    expect(exit).toBeNull();
    const res = JSON.parse(out) as { connections: unknown[]; vendors: unknown[] };
    expect(Array.isArray(res.connections)).toBe(true);
    expect(Array.isArray(res.vendors)).toBe(true);
  });
});

describe("cli admin: projects", () => {
  let projId: string;

  it("projects add", async () => {
    const { out } = await run("--json", "projects", "add", "proj-a");
    const p = JSON.parse(out) as { id: string; name: string };
    expect(p.name).toBe("proj-a");
    projId = p.id;
  });

  it("projects list shows it", async () => {
    const { out } = await run("projects", "list");
    expect(out).toContain("proj-a");
  });

  it("projects rm removes it", async () => {
    const { out } = await run("projects", "rm", projId);
    expect(out).toContain("Removed project");
  });
});

describe("cli admin: auth failure", () => {
  it("a bad token yields a clean 401 message and exit 1", async () => {
    const { err, exit } = await run("--token", "oga_wrong", "agents", "list");
    expect(exit).toBe(1);
    expect(err).toContain("401");
  });

  it("a missing token fails clearly", async () => {
    const saved = process.env.ONEGATE_ADMIN_TOKEN;
    delete process.env.ONEGATE_ADMIN_TOKEN;
    const { err, exit } = await run("agents", "list");
    expect(exit).toBe(1);
    expect(err).toContain("admin token");
    process.env.ONEGATE_ADMIN_TOKEN = saved;
  });
});
