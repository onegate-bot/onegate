/**
 * Dispatcher and argument-parsing tests for the CLI entrypoint (src/cli.ts) and
 * the agents/projects command modules. The end-to-end happy paths already live
 * in cli.test.ts (local commands) and cli-admin.test.ts (admin API commands);
 * this file covers the edges around them: global flag extraction, unknown and
 * missing sub-commands, usage errors, help/exit-code behaviour and the
 * top-level error handler.
 *
 * Like cli-admin.test.ts a real admin server is booted on an ephemeral port
 * over a temp-dir store, so the commands exercise the real node:http client
 * rather than a mock. process.exit is trapped and rethrown as a sentinel so a
 * failing path can never take down the vitest worker.
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
  dir = mkdtempSync(join(tmpdir(), "onegate-clicore-"));
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

describe("cli dispatcher: help and exit codes", () => {
  it("no command prints the full help and does not set a failing exit code", async () => {
    const { out, exit } = await run();
    expect(out).toContain("OneGate — open-source credential gateway for AI agents");
    expect(out).toContain("Local commands");
    expect(out).toContain("Admin API commands");
    expect(out).toContain("Global flags");
    expect(exit).toBeNull();
  });

  it("`help` prints help and exits successfully", async () => {
    const { out, exit } = await run("help");
    expect(out).toContain("Usage:");
    expect(exit).toBeNull();
  });

  it("`--help` prints help and exits successfully", async () => {
    // --help is not a recognised global flag, so it falls through to the
    // dispatcher as the command word and is treated as a help request.
    const { out, exit } = await run("--help");
    expect(out).toContain("Usage:");
    expect(exit).toBeNull();
  });

  it("an unknown command prints help and exits 1", async () => {
    const { out, exit } = await run("definitely-not-a-command");
    expect(out).toContain("Usage:");
    expect(exit).toBe(1);
  });

  it("a known command with no sub-command falls through to help and exits 1", async () => {
    // `admin` only dispatches on the `reset-token` sub-command; anything else
    // is unhandled and lands on the help + exit 1 path.
    const { out, exit } = await run("admin");
    expect(out).toContain("Usage:");
    expect(exit).toBe(1);
  });

  it("`agent` without a recognised sub-command falls through to help and exits 1", async () => {
    const { out, exit } = await run("agent", "bogus");
    expect(out).toContain("Usage:");
    expect(exit).toBe(1);
  });
});

describe("cli dispatcher: global flag extraction", () => {
  // This block runs before any agent is created, so `agents list` here also
  // covers the empty-listing branch of the agents command.
  it("agents list reports plainly when the store has no agents", async () => {
    const { out, exit } = await run("agents", "list");
    expect(exit).toBeNull();
    expect(out).toContain("no agents.");
  });

  it("--host and --token are accepted in separate-argument form", async () => {
    const { out, err, exit } = await run(
      "--host",
      `http://127.0.0.1:${port}`,
      "--token",
      adminToken,
      "agents",
      "list",
    );
    expect(exit).toBeNull();
    expect(err).toBe("");
    expect(out).toContain("no agents.");
  });

  it("--host= and --token= are accepted in inline form", async () => {
    const { out, err, exit } = await run(
      `--host=http://127.0.0.1:${port}`,
      `--token=${adminToken}`,
      "agents",
      "list",
    );
    expect(exit).toBeNull();
    expect(err).toBe("");
    expect(out).toContain("no agents.");
  });

  it("an inline --token= overrides a wrong ONEGATE_ADMIN_TOKEN", async () => {
    const saved = process.env.ONEGATE_ADMIN_TOKEN;
    process.env.ONEGATE_ADMIN_TOKEN = "oga_this_is_wrong";
    const { exit, err } = await run(`--token=${adminToken}`, "agents", "list");
    process.env.ONEGATE_ADMIN_TOKEN = saved;
    expect(exit).toBeNull();
    expect(err).toBe("");
  });

  it("an inline --host= pointing nowhere yields a clean unreachable error", async () => {
    // Port 1 is reserved and never listening, so this exercises the client's
    // connection-error path through the CLI's top-level handler.
    const { err, exit } = await run("--host=http://127.0.0.1:1", "agents", "list");
    expect(exit).toBe(1);
    expect(err).toContain("cannot reach admin API");
  });

  it("global flags are stripped from anywhere in argv, not just the front", async () => {
    const { out, exit } = await run("agents", "list", "--json", `--host=http://127.0.0.1:${port}`);
    expect(exit).toBeNull();
    expect(Array.isArray(JSON.parse(out))).toBe(true);
  });

  it("--json switches every command to machine-readable output", async () => {
    const { out } = await run("--json", "projects", "list");
    expect(() => JSON.parse(out)).not.toThrow();
  });
});

describe("cli dispatcher: top-level error handling", () => {
  it("an ApiError from the admin API is reported without a stack trace", async () => {
    // Renaming a missing agent is a real 404 from the admin API, which the
    // catch in main() turns into a one-line `onegate: ...` message.
    const { err, exit } = await run("agents", "rename", "ag_does_not_exist", "newname");
    expect(exit).toBe(1);
    expect(err).toMatch(/^onegate: API error 404/);
    expect(err).not.toContain("at ");
  });

  it("a plain Error thrown by a command module is reported the same way", async () => {
    // A bad sub-command throws a plain Error rather than an ApiError, which
    // takes the second branch of the catch in main().
    const { err, exit } = await run("agents", "not-a-subcommand");
    expect(exit).toBe(1);
    expect(err).toContain("onegate: unknown agents command");
  });
});

describe("cli local: agent add validation", () => {
  it("agent add without a name fails with usage and exit 1", async () => {
    const { err, exit } = await run("agent", "add");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate agent add <name>");
  });

  it("agent add rejects an invalid --policy", async () => {
    const { err, exit } = await run("agent", "add", "badpolicy", "--policy", "sometimes");
    expect(exit).toBe(1);
    expect(err).toContain("--policy must be allow-all or deny-unmatched");
  });

  it("agent list reports plainly against a store with no agents", async () => {
    // A fresh data dir gives an empty local store, which is the only way to
    // reach the empty branch of the local `agent list` command.
    const fresh = mkdtempSync(join(tmpdir(), "onegate-clicore-freshdb-"));
    const saved = process.env.ONEGATE_DATA;
    process.env.ONEGATE_DATA = fresh;
    const { out, exit } = await run("agent", "list");
    process.env.ONEGATE_DATA = saved;
    rmSync(fresh, { recursive: true, force: true });
    expect(exit).toBeNull();
    expect(out).toContain("no agents.");
  });
});

describe("cli local: init and print-ca guards", () => {
  it("init refuses to overwrite an already-initialized data dir", async () => {
    // beforeAll already ran initCa() against ONEGATE_DATA.
    const { err, exit } = await run("init");
    expect(exit).toBe(1);
    expect(err).toContain("already initialized");
  });

  it("print-ca fails clearly when the data dir is not initialized", async () => {
    const empty = mkdtempSync(join(tmpdir(), "onegate-clicore-empty-"));
    const saved = process.env.ONEGATE_DATA;
    process.env.ONEGATE_DATA = empty;
    const { err, exit } = await run("print-ca");
    process.env.ONEGATE_DATA = saved;
    rmSync(empty, { recursive: true, force: true });
    expect(exit).toBe(1);
    expect(err).toContain("not initialized");
  });

  it("start fails clearly when the data dir is not initialized", async () => {
    const empty = mkdtempSync(join(tmpdir(), "onegate-clicore-nostart-"));
    const saved = process.env.ONEGATE_DATA;
    process.env.ONEGATE_DATA = empty;
    const { err, exit } = await run("start");
    process.env.ONEGATE_DATA = saved;
    rmSync(empty, { recursive: true, force: true });
    expect(exit).toBe(1);
    expect(err).toContain("not initialized");
  });
});

describe("cli local: start boots the gateway and shuts down cleanly", () => {
  // The success path of `start` binds real listeners and installs signal
  // handlers on the process. Port 0 gives the OS an ephemeral port and the
  // bind is pinned to loopback, so the test never touches a fixed port or a
  // non-local interface. The SIGINT/SIGTERM handlers it registers are removed
  // afterwards so they cannot leak into other tests in this worker.
  const savedPorts = {
    proxy: process.env.ONEGATE_PROXY_PORT,
    admin: process.env.ONEGATE_ADMIN_PORT,
    bind: process.env.ONEGATE_BIND,
  };
  let beforeSigint: Array<(...a: unknown[]) => void>;
  let beforeSigterm: Array<(...a: unknown[]) => void>;

  beforeAll(() => {
    beforeSigint = process.listeners("SIGINT") as Array<(...a: unknown[]) => void>;
    beforeSigterm = process.listeners("SIGTERM") as Array<(...a: unknown[]) => void>;
    process.env.ONEGATE_PROXY_PORT = "0";
    process.env.ONEGATE_ADMIN_PORT = "0";
    process.env.ONEGATE_BIND = "127.0.0.1";
  });

  afterAll(() => {
    for (const l of process.listeners("SIGINT") as Array<(...a: unknown[]) => void>) {
      if (!beforeSigint.includes(l)) process.removeListener("SIGINT", l);
    }
    for (const l of process.listeners("SIGTERM") as Array<(...a: unknown[]) => void>) {
      if (!beforeSigterm.includes(l)) process.removeListener("SIGTERM", l);
    }
    if (savedPorts.proxy === undefined) delete process.env.ONEGATE_PROXY_PORT;
    else process.env.ONEGATE_PROXY_PORT = savedPorts.proxy;
    if (savedPorts.admin === undefined) delete process.env.ONEGATE_ADMIN_PORT;
    else process.env.ONEGATE_ADMIN_PORT = savedPorts.admin;
    if (savedPorts.bind === undefined) delete process.env.ONEGATE_BIND;
    else process.env.ONEGATE_BIND = savedPorts.bind;
  });

  it("prints the startup banner, then the SIGINT handler shuts down and exits 0", async () => {
    const started = await run("start");
    expect(started.exit).toBeNull();
    expect(started.out).toContain("OneGate ");
    expect(started.out).toContain("proxy:  http://127.0.0.1:");
    expect(started.out).toContain("admin:  http://127.0.0.1:");
    expect(started.out).toContain(`data:   ${dir}`);
    expect(started.out).toContain("integrations: ");

    // Drive the shutdown handler `start` registered. It calls process.exit(0),
    // which the exit spy converts into the __exit__ sentinel.
    const handlers = process.listeners("SIGINT") as Array<() => Promise<void>>;
    const shutdown = handlers[handlers.length - 1];
    logs = [];
    errs = [];
    exitCode = null;
    await expect(shutdown()).rejects.toThrow("__exit__");
    expect(exitCode).toBe(0);
    expect(logs.join("\n")).toContain("shutting down");

    // A second call is a no-op: the shuttingDown guard returns before exiting.
    exitCode = null;
    await expect(shutdown()).resolves.toBeUndefined();
    expect(exitCode).toBeNull();
  });
});

describe("agents command: sub-command routing and usage errors", () => {
  let agentId: string;

  beforeAll(async () => {
    const r = await run("--json", "agents", "add", "coverage-worker");
    agentId = (JSON.parse(r.out) as { id: string }).id;
  });

  it("`ls` is an alias for `list`", async () => {
    const { out, exit } = await run("--json", "agents", "ls");
    expect(exit).toBeNull();
    const names = (JSON.parse(out) as Array<{ name: string }>).map((a) => a.name);
    expect(names).toContain("coverage-worker");
  });

  it("list renders an aligned table in human mode", async () => {
    const { out } = await run("agents", "list");
    expect(out).toContain("ID");
    expect(out).toContain("NAME");
    expect(out).toContain("POLICY");
    expect(out).toContain("PROJECT");
    expect(out).toContain("coverage-worker");
  });

  it("add without a name fails with usage", async () => {
    const { err, exit } = await run("agents", "add");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate agents add <name>");
  });

  it("add rejects an invalid --policy before calling the API", async () => {
    const { err, exit } = await run("agents", "add", "bad", "--policy", "maybe");
    expect(exit).toBe(1);
    expect(err).toContain("--policy must be allow-all or deny-unmatched");
  });

  it("rename without both arguments fails with usage", async () => {
    const missingBoth = await run("agents", "rename");
    expect(missingBoth.exit).toBe(1);
    expect(missingBoth.err).toContain("usage: onegate agents rename <id> <newName>");
    const missingName = await run("agents", "rename", agentId);
    expect(missingName.exit).toBe(1);
    expect(missingName.err).toContain("usage: onegate agents rename <id> <newName>");
  });

  it("rm without an id fails with usage", async () => {
    const { err, exit } = await run("agents", "rm");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate agents rm <id>");
  });

  it("rotate-token without an id fails with usage", async () => {
    const { err, exit } = await run("agents", "rotate-token");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate agents rotate-token <id>");
  });

  it("`remove` and `delete` are aliases for `rm`", async () => {
    const a = await run("--json", "agents", "add", "alias-remove");
    const removeId = (JSON.parse(a.out) as { id: string }).id;
    const removed = await run("--json", "agents", "remove", removeId);
    expect(JSON.parse(removed.out)).toEqual({ removed: removeId });

    const b = await run("--json", "agents", "add", "alias-delete");
    const deleteId = (JSON.parse(b.out) as { id: string }).id;
    const deleted = await run("agents", "delete", deleteId);
    expect(deleted.out).toContain(`Removed agent ${deleteId}`);
  });

  it("an unknown sub-command names the valid ones", async () => {
    const { err, exit } = await run("agents", "frobnicate");
    expect(exit).toBe(1);
    expect(err).toContain('unknown agents command "frobnicate"');
    expect(err).toContain("list, add, rename, rm, rotate-token, llm");
  });

  it("a missing sub-command is reported as an empty command name", async () => {
    const { err, exit } = await run("agents");
    expect(exit).toBe(1);
    expect(err).toContain('unknown agents command ""');
  });
});

describe("projects command: empty listing and usage errors", () => {
  it("list reports plainly when there are no projects", async () => {
    // This suite owns a dedicated store with no projects seeded, so the
    // empty-list branch is reachable before any project is added.
    const { out, exit } = await run("projects", "list");
    expect(exit).toBeNull();
    expect(out).toContain("no projects.");
  });

  it("add without a name fails with usage", async () => {
    const { err, exit } = await run("projects", "add");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate projects add <name>");
  });

  it("rm without an id fails with usage", async () => {
    const { err, exit } = await run("projects", "rm");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate projects rm <id>");
  });

  it("an unknown sub-command names the valid ones", async () => {
    const { err, exit } = await run("projects", "frobnicate");
    expect(exit).toBe(1);
    expect(err).toContain('unknown projects command "frobnicate"');
    expect(err).toContain("list, add, rm");
  });
});
