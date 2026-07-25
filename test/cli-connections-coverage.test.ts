/**
 * Coverage-focused tests for src/cli/commands/connections.ts — the paths
 * cli-admin.test.ts does not reach: the secret-collection flag matrix
 * (--auth-json, --secret-stdin, --auth-token-stdin), every usage/validation
 * error, set-default, the human-readable renderers for empty and populated
 * listings, and the whole `agents notify` family.
 *
 * Same harness as cli-admin.test.ts: a real admin server on an ephemeral port
 * over a temp-dir Store, driving main() with ONEGATE_ADMIN_URL /
 * ONEGATE_ADMIN_TOKEN set and console captured by spies.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
import http from "node:http";
import { Readable } from "node:stream";
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

/**
 * Runs a command with process.stdin replaced by a readable carrying `input`,
 * so the --secret-stdin path can be exercised without a real pipe.
 */
async function runWithStdin(
  input: string,
  ...argv: string[]
): Promise<{ out: string; err: string; exit: number | null }> {
  const original = Object.getOwnPropertyDescriptor(process, "stdin")!;
  Object.defineProperty(process, "stdin", {
    value: Readable.from([Buffer.from(input, "utf8")]),
    configurable: true,
  });
  try {
    return await run(...argv);
  } finally {
    Object.defineProperty(process, "stdin", original);
  }
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-clicoverage-"));
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

describe("cli connections: empty-state human output", () => {
  it("list on a fresh store reports no connections of either kind", async () => {
    const { out, exit } = await run("connections", "list");
    expect(exit).toBeNull();
    expect(out).toContain("no LLM connections.");
    expect(out).toContain("no app connections.");
  });
});

describe("cli connections: secret collection flags", () => {
  it("--auth-json imports string fields and never echoes them", async () => {
    const { out } = await run(
      "--json",
      "connections",
      "add",
      "--vendor",
      "openai",
      "--name",
      "oai-authjson",
      "--auth-json",
      JSON.stringify({ accessToken: "test-secret-value", accountId: "acct-1", expires: 123 }),
    );
    const conn = JSON.parse(out) as { id: string; vendor: string; hasSecret: boolean };
    expect(conn.vendor).toBe("openai");
    expect(conn.hasSecret).toBe(true);
    expect(out).not.toContain("test-secret-value");

    // Only the string members are imported; the numeric one is dropped.
    const stored = store.getConnection(conn.id)!;
    expect(stored.data.accessToken).toBe("test-secret-value");
    expect(stored.data.accountId).toBe("acct-1");
    expect(stored.data.expires).toBeUndefined();
  });

  it("--auth-json rejects malformed JSON", async () => {
    const { err, exit } = await run(
      "connections",
      "add",
      "--vendor",
      "openai",
      "--name",
      "oai-badjson",
      "--auth-json",
      "{not json",
    );
    expect(exit).toBe(1);
    expect(err).toContain("--auth-json must be valid JSON");
  });

  it("--secret-stdin reads an api key from stdin", async () => {
    const { out } = await runWithStdin(
      "  test-secret-value\n",
      "--json",
      "connections",
      "add",
      "--vendor",
      "anthropic",
      "--name",
      "anth-stdin",
      "--secret-stdin",
    );
    const conn = JSON.parse(out) as { id: string; hasSecret: boolean };
    expect(conn.hasSecret).toBe(true);
    expect(out).not.toContain("test-secret-value");

    // The value is trimmed and stored as an api key (no auth_token mode).
    const stored = store.getConnection(conn.id)!;
    expect(stored.data.apiKey).toBe("test-secret-value");
    expect(stored.data.authMode).toBeUndefined();
  });

  it("--secret-stdin with --auth-token-stdin stores an auth token", async () => {
    const { out } = await runWithStdin(
      "test-secret-value\n",
      "--json",
      "connections",
      "add",
      "--vendor",
      "anthropic",
      "--name",
      "anth-stdin-token",
      "--secret-stdin",
      "--auth-token-stdin",
    );
    const conn = JSON.parse(out) as { id: string };
    const stored = store.getConnection(conn.id)!;
    expect(stored.data.authToken).toBe("test-secret-value");
    expect(stored.data.authMode).toBe("auth_token");
    expect(out).not.toContain("test-secret-value");
  });

  it("--secret-stdin rejects empty stdin", async () => {
    const { err, exit } = await runWithStdin(
      "   \n",
      "connections",
      "add",
      "--vendor",
      "anthropic",
      "--name",
      "anth-emptystdin",
      "--secret-stdin",
    );
    expect(exit).toBe(1);
    expect(err).toContain("no secret on stdin");
  });

  it("add with no secret flag at all fails with the flag list", async () => {
    const { err, exit } = await run(
      "connections",
      "add",
      "--vendor",
      "anthropic",
      "--name",
      "anth-nosecret",
    );
    expect(exit).toBe(1);
    expect(err).toContain("no secret given");
    expect(err).toContain("--api-key");
    expect(err).toContain("--secret-stdin");
  });
});

describe("cli connections: add validation", () => {
  it("rejects an unknown --kind", async () => {
    const { err, exit } = await run("connections", "add", "--kind", "widget", "--name", "x");
    expect(exit).toBe(1);
    expect(err).toContain('--kind must be "llm" or "app"');
  });

  it("requires --vendor and --name for an llm connection", async () => {
    const noVendor = await run("connections", "add", "--name", "nameonly");
    expect(noVendor.exit).toBe(1);
    expect(noVendor.err).toContain("usage: onegate connections add --vendor");

    const noName = await run("connections", "add", "--vendor", "anthropic");
    expect(noName.exit).toBe(1);
    expect(noName.err).toContain("usage: onegate connections add --vendor");
  });

  it("requires --integration and --name for an app connection", async () => {
    const { err, exit } = await run("connections", "add", "--kind", "app", "--data", "pat=x");
    expect(exit).toBe(1);
    expect(err).toContain("--kind app --integration");
  });

  it("rejects a --data pair that is not key=value", async () => {
    const { err, exit } = await run(
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "github",
      "--name",
      "gh-baddata",
      "--data",
      "novalue",
    );
    expect(exit).toBe(1);
    expect(err).toContain('--data must be key=value, got "novalue"');
  });

  it("accepts --vendor as an alias for --integration on an app connection", async () => {
    const { out } = await run(
      "--json",
      "connections",
      "add",
      "--kind",
      "app",
      "--vendor",
      "github",
      "--name",
      "gh-vendoralias",
      "--data",
      "pat=test-secret-value",
    );
    const conn = JSON.parse(out) as { vendor: string; kind: string };
    expect(conn.kind).toBe("app");
    expect(conn.vendor).toBe("github");
    expect(out).not.toContain("test-secret-value");
  });

  it("splits --data only on the first = so values may contain =", async () => {
    const { out } = await run(
      "--json",
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "github",
      "--name",
      "gh-equals",
      "--data",
      "pat=test-secret-value=trailing",
    );
    const conn = JSON.parse(out) as { id: string };
    expect(store.getConnection(conn.id)!.data.pat).toBe("test-secret-value=trailing");
    expect(out).not.toContain("test-secret-value");
  });
});

describe("cli connections: human-readable add + set-default + rm", () => {
  let llmId: string;
  let appId: string;
  let agentId: string;

  beforeAll(async () => {
    const a = await run("--json", "agents", "add", "humanworker");
    agentId = (JSON.parse(a.out) as { id: string }).id;
  });

  it("llm add prints a human confirmation line without the secret", async () => {
    const { out } = await run(
      "connections",
      "add",
      "--vendor",
      "anthropic",
      "--name",
      "anth-human",
      "--api-key",
      "test-secret-value",
    );
    expect(out).toMatch(
      /Connection "anth-human" created \(conn_.*vendor=anthropic, default=false\)\./,
    );
    expect(out).not.toContain("test-secret-value");
    llmId = /\((conn_[a-z0-9]+)/.exec(out)![1];
  });

  it("app add prints the tenant-wide scope in human mode", async () => {
    const { out } = await run(
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "github",
      "--name",
      "gh-human",
      "--data",
      "pat=test-secret-value",
    );
    expect(out).toContain('App connection "gh-human" created');
    expect(out).toContain("scope=tenant-wide");
    expect(out).not.toContain("test-secret-value");
    appId = /\((conn_[a-z0-9]+)/.exec(out)![1];
  });

  it("app add prints the agent scope when --agent is given", async () => {
    const { out } = await run(
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "github",
      "--name",
      "gh-human-agent",
      "--data",
      "pat=test-secret-value",
      "--agent",
      agentId,
    );
    expect(out).toContain("scope=agent humanworker");
    expect(out).not.toContain("test-secret-value");
  });

  it("list renders both tables with scopes and no secrets", async () => {
    const { out } = await run("connections", "list");
    expect(out).toContain("LLM connections:");
    expect(out).toContain("anth-human");
    expect(out).toContain("App connections:");
    expect(out).toContain("gh-human");
    expect(out).toContain("tenant-wide");
    expect(out).toContain("agent: humanworker");
    expect(out).not.toContain("test-secret-value");
  });

  it("set-default promotes a connection", async () => {
    const { out } = await run("connections", "set-default", llmId);
    expect(out).toContain(`"anth-human" (${llmId}) is now the default for anthropic.`);
    expect(store.getConnection(llmId)!.isDefault).toBe(true);
  });

  it("set-default without an id fails", async () => {
    const { err, exit } = await run("connections", "set-default");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate connections set-default <id>");
  });

  it("set-default on an unknown id surfaces the API error", async () => {
    const { err, exit } = await run("connections", "set-default", "conn_doesnotexist");
    expect(exit).toBe(1);
    expect(err).toContain("404");
  });

  it("rm without an id fails", async () => {
    const { err, exit } = await run("connections", "rm");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate connections rm <id>");
  });

  it("the delete alias removes a connection", async () => {
    const { out } = await run("connections", "delete", appId);
    expect(out).toContain(`Removed connection ${appId}.`);
    expect(store.getConnection(appId)).toBeNull();
  });
});

describe("cli connections: unknown subcommand", () => {
  it("names the offending subcommand and lists the valid ones", async () => {
    const { err, exit } = await run("connections", "frobnicate");
    expect(exit).toBe(1);
    expect(err).toContain('unknown connections command "frobnicate"');
    expect(err).toContain("list, add, set-default, rm, grants, grant, revoke");
  });
});

describe("cli connections: grant/revoke usage errors", () => {
  it("grant without --id prefixes the usage line", async () => {
    const { err, exit } = await run("connections", "grant", "--agent", "ag_x");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate connections grant --id");
    expect(err).toContain("--id <connectionId> is required");
  });

  it("revoke without --id prefixes the usage line", async () => {
    const { err, exit } = await run("connections", "revoke", "--agent", "ag_x");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate connections revoke --id");
    expect(err).toContain("--id <connectionId> is required");
  });

  it("revoke requires exactly one of --agent or --project", async () => {
    const { err, exit } = await run("connections", "revoke", "--id", "conn_x");
    expect(exit).toBe(1);
    expect(err).toContain("exactly one of --agent");
  });
});

describe("cli connections: grant/revoke human confirmations", () => {
  let agentId: string;
  let connId: string;

  beforeAll(async () => {
    const a = await run("--json", "agents", "add", "grantworker");
    agentId = (JSON.parse(a.out) as { id: string }).id;
    const c = await run(
      "--json",
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "github",
      "--name",
      "grant-target",
      "--data",
      "pat=test-secret-value",
    );
    connId = (JSON.parse(c.out) as { id: string }).id;
  });

  it("grant prints the human confirmation", async () => {
    const { out } = await run("connections", "grant", "--id", connId, "--agent", agentId);
    expect(out).toContain(`Granted connection ${connId} to agent ${agentId}.`);
    expect(store.listGrantsForConnection(connId).some((g) => g.subjectId === agentId)).toBe(true);
  });

  it("grants lists the grant in human mode", async () => {
    const { out } = await run("connections", "grants", "--id", connId);
    expect(out).toContain(agentId);
  });

  it("revoke prints the human confirmation", async () => {
    const { out } = await run("connections", "revoke", "--id", connId, "--agent", agentId);
    expect(out).toContain(`Revoked connection ${connId} from agent ${agentId}.`);
    expect(store.listGrantsForConnection(connId).some((g) => g.subjectId === agentId)).toBe(false);
  });
});

describe("cli connections: legacy single-credential rows", () => {
  it("list labels a legacy credentials row as shared (legacy)", async () => {
    // The pre-connections credentials table is still surfaced by the API with
    // a synthetic legacy:true shape, which the list renderer labels distinctly.
    store.setCredential("gitlab", "legacy-gitlab", { token: "test-secret-value" });
    const { out } = await run("connections", "list");
    expect(out).toContain("legacy-gitlab");
    expect(out).toContain("shared (legacy)");
    expect(out).not.toContain("test-secret-value");
  });
});

describe("cli connections: disabled-vendor human output", () => {
  it("prints the confirmation line in human mode after a direct-store seed", async () => {
    process.env.ONEGATE_DISABLED_INTEGRATIONS = "openai";
    const { out, err } = await run(
      "connections",
      "add",
      "--vendor",
      "openai",
      "--name",
      "oai-seeded-human",
      "--api-key",
      "test-secret-value",
      "--allow-disabled-vendor",
    );
    expect(err).toContain("bypassing the API vendor gate");
    expect(out).toContain('Connection "oai-seeded-human" created');
    expect(out).toContain("vendor=openai");
    expect(out).not.toContain("test-secret-value");
  });
});

describe("cli agents llm: flag parsing and usage errors", () => {
  let agentId: string;
  let connA: string;
  let connB: string;

  beforeAll(async () => {
    const a = await run("--json", "agents", "add", "llmflags");
    agentId = (JSON.parse(a.out) as { id: string }).id;
    const ca = await run(
      "--json",
      "connections",
      "add",
      "--vendor",
      "anthropic",
      "--name",
      "llmflags-a",
      "--api-key",
      "test-secret-value",
    );
    connA = (JSON.parse(ca.out) as { id: string }).id;
    const cb = await run(
      "--json",
      "connections",
      "add",
      "--vendor",
      "anthropic",
      "--name",
      "llmflags-b",
      "--api-key",
      "test-secret-value",
    );
    connB = (JSON.parse(cb.out) as { id: string }).id;
  });

  it("get without an agent id fails", async () => {
    const { err, exit } = await run("agents", "llm", "get");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate agents llm get <agentId>");
  });

  it("get renders the human view of an unconfigured agent", async () => {
    const { out } = await run("agents", "llm", "get", agentId);
    expect(out).toContain(`agent:       ${agentId}`);
    expect(out).toContain("enabled:     false");
    expect(out).toContain("strategy:    fallback");
    expect(out).toContain("connections: -");
    expect(out).toContain("updated:     -");
  });

  it("set without an agent id fails", async () => {
    const { err, exit } = await run("agents", "llm", "set");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate agents llm set <agentId>");
  });

  it("set rejects an unknown --strategy", async () => {
    const { err, exit } = await run("agents", "llm", "set", agentId, "--strategy", "random");
    expect(exit).toBe(1);
    expect(err).toContain('--strategy must be "fallback" or "round-robin"');
  });

  it("set accepts round-robin and trims/filters the connection list", async () => {
    const { out } = await run(
      "agents",
      "llm",
      "set",
      agentId,
      "--strategy",
      "round-robin",
      "--connections",
      ` ${connA} , ,${connB}, `,
    );
    expect(out).toContain("strategy=round-robin");
    expect(out).toContain(`connections=[${connA}, ${connB}]`);
    expect(out).toContain("enabled=true");
  });

  it("--disabled wins over the enabled-by-default behaviour", async () => {
    const { out } = await run(
      "--json",
      "agents",
      "llm",
      "set",
      agentId,
      "--connections",
      connA,
      "--disabled",
    );
    const cfg = JSON.parse(out) as { enabled: boolean; strategy: string };
    expect(cfg.enabled).toBe(false);
    // --strategy defaults to fallback when not given.
    expect(cfg.strategy).toBe("fallback");
  });

  it("--enabled turns it back on", async () => {
    const { out } = await run(
      "--json",
      "agents",
      "llm",
      "set",
      agentId,
      "--connections",
      connA,
      "--enabled",
    );
    expect((JSON.parse(out) as { enabled: boolean }).enabled).toBe(true);
  });

  it("set with no --connections sends an empty list", async () => {
    const { out } = await run("--json", "agents", "llm", "set", agentId);
    expect((JSON.parse(out) as { connectionIds: string[] }).connectionIds).toEqual([]);
  });

  it("get renders a configured agent with its connection list", async () => {
    await run("agents", "llm", "set", agentId, "--connections", `${connA},${connB}`);
    const { out } = await run("agents", "llm", "get", agentId);
    expect(out).toContain("enabled:     true");
    expect(out).toContain(`connections: ${connA}, ${connB}`);
    expect(out).not.toMatch(/updated:\s+-$/m);
  });

  it("clear without an agent id fails", async () => {
    const { err, exit } = await run("agents", "llm", "clear");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate agents llm clear <agentId>");
  });

  it("clear prints the human confirmation", async () => {
    const { out } = await run("agents", "llm", "clear", agentId);
    expect(out).toContain(`LLM routing cleared for ${agentId} (disabled, no connections).`);
  });

  it("an unknown llm verb lists the valid ones", async () => {
    const { err, exit } = await run("agents", "llm", "wat", agentId);
    expect(exit).toBe(1);
    expect(err).toContain('unknown "agents llm" command "wat"');
    expect(err).toContain("Try: get, set, clear");
  });
});

describe("cli agents apps: human rendering and usage errors", () => {
  let agentId: string;
  let sharedId: string;
  let mineId: string;

  beforeAll(async () => {
    const a = await run("--json", "agents", "add", "appshuman");
    agentId = (JSON.parse(a.out) as { id: string }).id;
    const s = await run(
      "--json",
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "github",
      "--name",
      "apps-shared",
      "--data",
      "pat=test-secret-value",
    );
    sharedId = (JSON.parse(s.out) as { id: string }).id;
    const m = await run(
      "--json",
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "github",
      "--name",
      "apps-mine",
      "--data",
      "pat=test-secret-value",
      "--agent",
      agentId,
    );
    mineId = (JSON.parse(m.out) as { id: string }).id;
  });

  it("get without an agent id fails", async () => {
    const { err, exit } = await run("agents", "apps", "get");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate agents apps get <agentId>");
  });

  it("get reports 'none' for both sections before anything is chosen or granted", async () => {
    // An app connection is only "available" to an agent once it is granted, so
    // a freshly created agent sees the empty form of both sections.
    const { out } = await run("agents", "apps", "get", agentId);
    expect(out).toContain(`agent: ${agentId}`);
    expect(out).toContain("saved app account choices: none");
    expect(out).toContain("available app connections: none.");
    expect(out).not.toContain("test-secret-value");
  });

  it("get lists granted connections with their scopes once they are granted", async () => {
    store.grantConnection(sharedId, "agent", agentId);
    store.grantConnection(mineId, "agent", agentId);
    const { out } = await run("agents", "apps", "get", agentId);
    expect(out).toContain("saved app account choices: none");
    expect(out).toContain("available app connections (tenant-wide plus this agent's own):");
    expect(out).toContain("apps-shared");
    expect(out).toContain("tenant-wide");
    expect(out).toContain("apps-mine");
    expect(out).toContain("agent: appshuman");
    expect(out).not.toContain("test-secret-value");
  });

  it("get renders the saved choice table once a choice exists", async () => {
    await run("agents", "apps", "set", agentId, "github", "--connection", mineId);
    const { out } = await run("agents", "apps", "get", agentId);
    expect(out).toContain("saved app account choices:");
    expect(out).toContain("INTEGRATION");
    // The connection id resolves to its friendly name via the available list.
    expect(out).toContain("apps-mine");
    expect(out).toContain(mineId);
    expect(out).not.toContain("test-secret-value");
  });

  it("set requires an integration positional and --connection", async () => {
    const noIntegration = await run("agents", "apps", "set", agentId);
    expect(noIntegration.exit).toBe(1);
    expect(noIntegration.err).toContain("usage: onegate agents apps set <agentId> <integrationId> --connection <id>");

    const noConnection = await run("agents", "apps", "set", agentId, "github");
    expect(noConnection.exit).toBe(1);
    expect(noConnection.err).toContain("--connection <id>");
  });

  it("set prints the human confirmation", async () => {
    const { out } = await run("agents", "apps", "set", agentId, "github", "--connection", sharedId);
    expect(out).toContain(`agent ${agentId} will use connection ${sharedId} for github.`);
  });

  it("clear requires an integration id", async () => {
    const { err, exit } = await run("agents", "apps", "clear", agentId);
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate agents apps clear <agentId> <integrationId>");
  });

  it("clear prints the human confirmation", async () => {
    const { out } = await run("agents", "apps", "clear", agentId, "github");
    expect(out).toContain(`Cleared github choice for agent ${agentId} (will use the default connection).`);
  });

  it("an unknown apps verb lists the valid ones", async () => {
    const { err, exit } = await run("agents", "apps", "wat", agentId);
    expect(exit).toBe(1);
    expect(err).toContain('unknown "agents apps" command "wat"');
    expect(err).toContain("Try: get, set, clear");
  });
});

describe("cli agents notify: owner webhook", () => {
  let agentId: string;

  beforeAll(async () => {
    const a = await run("--json", "agents", "add", "notifyworker");
    agentId = (JSON.parse(a.out) as { id: string }).id;
  });

  it("get without an agent id fails", async () => {
    const { err, exit } = await run("agents", "notify", "get");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate agents notify get <agentId>");
  });

  it("get reports '(not set)' before a webhook is configured", async () => {
    const { out } = await run("agents", "notify", "get", agentId);
    expect(out).toContain(`agent:      ${agentId}`);
    expect(out).toContain("webhook:    (not set)");
  });

  it("set without an agent id fails", async () => {
    const { err, exit } = await run("agents", "notify", "set");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate agents notify set <agentId> --url <webhookUrl>");
  });

  it("set without --url fails", async () => {
    const { err, exit } = await run("agents", "notify", "set", agentId);
    expect(exit).toBe(1);
    expect(err).toContain("--url <webhookUrl>");
  });

  it("set stores the webhook and confirms without echoing the URL", async () => {
    const { out } = await run(
      "agents",
      "notify",
      "set",
      agentId,
      "--url",
      "https://hooks.example.com/inject/test-secret-value",
    );
    expect(out).toContain(`Notify webhook for ${agentId} set.`);
    expect(out).not.toContain("test-secret-value");
    expect(store.getAgentNotify(agentId)).toBe(
      "https://hooks.example.com/inject/test-secret-value",
    );
  });

  it("get then shows the stored webhook", async () => {
    const { out } = await run("agents", "notify", "get", agentId);
    expect(out).toContain("webhook:    https://hooks.example.com/inject/test-secret-value");
  });

  it("get in json mode returns the config object", async () => {
    const { out } = await run("--json", "agents", "notify", "get", agentId);
    const cfg = JSON.parse(out) as { agentId: string; webhookUrl: string | null };
    expect(cfg.agentId).toBe(agentId);
    expect(cfg.webhookUrl).toContain("hooks.example.com");
  });

  it("clear without an agent id fails", async () => {
    const { err, exit } = await run("agents", "notify", "clear");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate agents notify clear <agentId>");
  });

  it("clear removes the webhook", async () => {
    const { out } = await run("agents", "notify", "clear", agentId);
    expect(out).toContain(`Notify webhook for ${agentId} cleared.`);
    expect(store.getAgentNotify(agentId)).toBeNull();
    const after = await run("agents", "notify", "get", agentId);
    expect(after.out).toContain("webhook:    (not set)");
  });

  it("an unknown notify verb lists the valid ones", async () => {
    const { err, exit } = await run("agents", "notify", "wat", agentId);
    expect(exit).toBe(1);
    expect(err).toContain('unknown "agents notify" command "wat"');
    expect(err).toContain("Try: get, set, clear");
  });

  it("notify set on an unknown agent surfaces the API 404", async () => {
    const { err, exit } = await run(
      "agents",
      "notify",
      "set",
      "ag_doesnotexist",
      "--url",
      "https://hooks.example.com/nope",
    );
    expect(exit).toBe(1);
    expect(err).toContain("404");
  });
});
