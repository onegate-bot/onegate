/**
 * Coverage for the M4 read-only observability commands (`onegate audit`,
 * `onegate usage`). The existing cli-admin suite only drives these in --json
 * mode, which skips the whole human-readable rendering path. Here a real admin
 * server is booted on an ephemeral port over a temp-dir Store (same harness
 * shape as cli-admin.test.ts), the store is seeded with audit + LLM usage rows,
 * and main() is driven without --json so the table renderers run.
 *
 * The tail of each suite calls auditCommand/usageCommand directly against a
 * stub CliContext, which is the only way to reach the defensive fallbacks
 * (`res.models?.length`, `turnEstimate?.gapMs ?? 60_000`) that the real admin
 * API never produces.
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
import { auditCommand, usageCommand } from "../src/cli/commands/observe.js";
import type { CliContext } from "../src/cli/context.js";

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

/** Ids of the two agents seeded below, used by the --agent filter tests. */
let agentAId: string;
let agentBId: string;
let connId: string;

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
 * Drives a command function directly with a canned response body, bypassing the
 * admin server. Returns the captured stdout plus the path the command asked for
 * so flag -> query-string mapping can be asserted.
 */
async function runDirect(
  fn: (ctx: CliContext, args: string[]) => Promise<void>,
  body: unknown,
  args: string[] = [],
): Promise<{ out: string; path: string }> {
  logs = [];
  setJsonMode(false);
  let seen = "";
  const ctx = {
    client: () => ({
      get: async (p: string) => {
        seen = p;
        return body;
      },
    }),
    store: () => {
      throw new Error("store() must not be used by observe commands");
    },
  } as unknown as CliContext;
  await fn(ctx, args);
  return { out: logs.join("\n"), path: seen };
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-cliobserve-"));
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

describe("cli observe: audit (empty)", () => {
  // Runs before any audit rows are seeded, so it hits the !rows.length branch.
  it("prints a friendly line when there are no audit rows", async () => {
    const { out, exit } = await run("audit");
    expect(exit).toBeNull();
    expect(out).toBe("no audit rows.");
  });
});

describe("cli observe: audit (populated)", () => {
  beforeAll(() => {
    agentAId = store.createAgent("observe-a").agent.id;
    agentBId = store.createAgent("observe-b").agent.id;
    connId = store.createConnection({
      kind: "llm",
      vendor: "anthropic",
      name: "observe-conn",
      data: { apiKey: "sk-test" },
    }).id;

    store.audit({
      agentId: agentAId,
      agentName: "observe-a",
      integrationId: "github",
      host: "api.github.com",
      method: "GET",
      path: "/user",
      decision: "allow",
      status: 200,
    });
    // An LLM-routed row: llmConnectionName is resolved from connectionId.
    store.audit({
      agentId: agentAId,
      agentName: "observe-a",
      integrationId: "anthropic",
      host: "api.anthropic.com",
      method: "POST",
      path: "/v1/messages",
      decision: "allow",
      status: 200,
      connectionId: connId,
      connectionName: "stale-name",
      llmVendor: "anthropic",
    });
    // A denied row for the other agent, with null method/path so the table's
    // "-" placeholder for missing cells is exercised.
    store.audit({
      agentId: agentBId,
      agentName: "observe-b",
      host: "evil.example.com",
      decision: "deny",
      status: 403,
    });
  });

  it("renders a table with a header row and one line per audit row", async () => {
    const { out, exit } = await run("audit");
    expect(exit).toBeNull();
    const lines = out.split("\n");
    expect(lines[0]).toMatch(/^TS\s+AGENT\s+HOST\s+METHOD\s+PATH\s+DECISION\s+STATUS\s+CONNECTION$/);
    expect(lines).toHaveLength(4);
    expect(out).toContain("api.github.com");
    expect(out).toContain("evil.example.com");
    expect(out).toContain("deny");
    expect(out).toContain("403");
  });

  it("resolves an LLM row's connection id to the connection's current name", async () => {
    const { out } = await run("audit");
    const row = out.split("\n").find((l) => l.includes("api.anthropic.com"))!;
    expect(row).toContain("observe-conn");
    // The name captured at request time is superseded by the live one.
    expect(row).not.toContain("stale-name");
  });

  it("renders '-' for a row with no method or path", async () => {
    const { out } = await run("audit");
    const row = out.split("\n").find((l) => l.includes("evil.example.com"))!;
    expect(row).toMatch(/evil\.example\.com\s+-\s+-\s+deny/);
  });

  it("--agent filters to that agent's rows only", async () => {
    const { out, exit } = await run("audit", "--agent", agentBId);
    expect(exit).toBeNull();
    expect(out).toContain("evil.example.com");
    expect(out).not.toContain("api.github.com");
    expect(out.split("\n")).toHaveLength(2); // header + 1 row
  });

  it("--limit caps the number of rows returned", async () => {
    const { out, exit } = await run("audit", "--limit", "1");
    expect(exit).toBeNull();
    expect(out.split("\n")).toHaveLength(2); // header + 1 row
  });

  it("--agent and --limit combine into a single query string", async () => {
    const { path } = await runDirect(auditCommand, [], ["--agent", "ag_x", "--limit", "7"]);
    expect(path).toBe("/api/audit?agentId=ag_x&limit=7");
  });

  it("omits the query string entirely when no flags are given", async () => {
    const { path } = await runDirect(auditCommand, []);
    expect(path).toBe("/api/audit");
  });

  it("an unknown flag exits 1 with a parse error", async () => {
    const { exit, err } = await run("audit", "--nope");
    expect(exit).toBe(1);
    expect(err).toMatch(/nope/i);
  });
});

describe("cli observe: usage (empty rollups)", () => {
  // The seeded audit rows above do not create llm_usage entries, so every
  // rollup section is still empty here and prints "(none)".
  it("prints '(none)' under every section when nothing has been recorded", async () => {
    const { out, exit } = await run("usage");
    expect(exit).toBeNull();
    expect(out).toMatch(/^Usage since \d{4}-\d{2}-\d{2}T/);
    expect(out).toContain("By connection:");
    expect(out).toContain("By vendor:");
    expect(out).toContain("By model:");
    expect(out).toContain("By bot + model:");
    expect(out.match(/^ {2}\(none\)$/gm)).toHaveLength(4);
  });

  it("omits the 'until' clause when --until is not given", async () => {
    const { out } = await run("usage");
    expect(out).not.toContain(" until ");
  });

  it("always prints the EST TURNS caveat footer", async () => {
    const { out } = await run("usage");
    expect(out).toContain("EST TURNS = estimated conversational turns");
    expect(out).toContain("(>60s = new turn)");
    expect(out).toContain("Approximate, not exact.");
  });
});

describe("cli observe: usage (populated rollups)", () => {
  beforeAll(() => {
    store.recordLlmUsage({
      connectionId: connId,
      connectionName: "observe-conn",
      agentId: agentAId,
      vendor: "anthropic",
      model: "claude-opus-4-8",
      strategy: "fallback",
      inputTokens: 1200,
      outputTokens: 340,
      status: 200,
    });
    store.recordLlmUsage({
      connectionId: connId,
      connectionName: "observe-conn",
      agentId: agentAId,
      vendor: "anthropic",
      model: "claude-opus-4-8",
      strategy: "fallback",
      errors: 1,
      failover: true,
      inputTokens: 50,
      outputTokens: 0,
      status: 429,
    });
    // No model recorded: the CLI substitutes "(unknown)" in the model column.
    store.recordLlmUsage({
      connectionId: connId,
      connectionName: "observe-conn",
      agentId: agentBId,
      vendor: "anthropic",
      inputTokens: 10,
      outputTokens: 5,
      status: 200,
    });
  });

  it("renders the by-connection table with the connection's current name", async () => {
    const { out, exit } = await run("usage");
    expect(exit).toBeNull();
    const section = out.slice(out.indexOf("By connection:"), out.indexOf("By vendor:"));
    expect(section).toMatch(/CONNECTION\s+VENDOR\s+REQUESTS\s+ERRORS\s+FAILOVERS\s+IN TOK\s+OUT TOK/);
    expect(section).toContain("observe-conn");
    expect(section).not.toContain("(none)");
  });

  it("renders the by-vendor table with summed requests and errors", async () => {
    const { out } = await run("usage");
    const section = out.slice(out.indexOf("By vendor:"), out.indexOf("By model:"));
    expect(section).toMatch(/VENDOR\s+REQUESTS\s+ERRORS\s+FAILOVERS\s+IN TOK\s+OUT TOK/);
    const row = section.split("\n").find((l) => l.startsWith("anthropic"))!;
    // 3 recorded events, 1 of which was an error and a failover.
    expect(row.split(/\s+/)).toEqual(["anthropic", "3", "1", "1", "1260", "345"]);
  });

  it("renders the by-model table and shows '(unknown)' for a null model", async () => {
    const { out } = await run("usage");
    const section = out.slice(out.indexOf("By model:"), out.indexOf("By bot + model:"));
    expect(section).toMatch(/VENDOR\s+MODEL\s+REQUESTS\s+EST TURNS\s+ERRORS\s+IN TOK\s+OUT TOK/);
    expect(section).toContain("claude-opus-4-8");
    expect(section).toContain("(unknown)");
  });

  it("renders the by-bot table resolving agent ids to agent names", async () => {
    const { out } = await run("usage");
    const section = out.slice(out.indexOf("By bot + model:"), out.indexOf("EST TURNS ="));
    expect(section).toMatch(/BOT\s+VENDOR\s+MODEL\s+REQUESTS\s+EST TURNS\s+ERRORS\s+IN TOK\s+OUT TOK/);
    expect(section).toContain("observe-a");
    expect(section).toContain("observe-b");
    expect(section).not.toContain(agentAId);
  });

  it("--since and --until are echoed in the header line", async () => {
    const since = "2020-01-01T00:00:00.000Z";
    const until = "2999-01-01T00:00:00.000Z";
    const { out, exit } = await run("usage", "--since", since, "--until", until);
    expect(exit).toBeNull();
    expect(out.split("\n")[0]).toBe(`Usage since ${since} until ${until}`);
  });

  it("--since in the future yields empty rollups", async () => {
    const { out } = await run("usage", "--since", "2999-01-01T00:00:00.000Z");
    expect(out.match(/^ {2}\(none\)$/gm)).toHaveLength(4);
  });

  it("all three flags combine into a single query string", async () => {
    const { path } = await runDirect(
      usageCommand,
      { since: "s", until: null, connections: [], vendors: [], models: [], bots: [], recent: [] },
      ["--since", "2020-01-01", "--until", "2021-01-01", "--limit", "5"],
    );
    expect(path).toBe("/api/usage?since=2020-01-01&until=2021-01-01&limit=5");
  });

  it("omits the query string entirely when no flags are given", async () => {
    const { path } = await runDirect(usageCommand, {
      since: "s",
      until: null,
      connections: [],
      vendors: [],
      models: [],
      bots: [],
      recent: [],
    });
    expect(path).toBe("/api/usage");
  });

  it("a non-ISO --since surfaces the server's 400 and exits 1", async () => {
    const { exit, err } = await run("usage", "--since", "not-a-date");
    expect(exit).toBe(1);
    expect(err).toContain("invalid_time_range");
  });

  it("an unknown flag exits 1 with a parse error", async () => {
    const { exit, err } = await run("usage", "--nope");
    expect(exit).toBe(1);
    expect(err).toMatch(/nope/i);
  });
});

describe("cli observe: usage defensive fallbacks", () => {
  // The live admin API always sends models, bots and turnEstimate. These
  // stub-context cases cover the `?.` / `??` guards for a response that omits
  // them (an older server, or a hand-rolled gateway).

  it("treats missing models and bots arrays as empty sections", async () => {
    const { out } = await runDirect(usageCommand, {
      since: "2020-01-01T00:00:00.000Z",
      until: null,
      connections: [],
      vendors: [],
      recent: [],
    });
    expect(out.match(/^ {2}\(none\)$/gm)).toHaveLength(4);
  });

  it("falls back to a 60s gap when turnEstimate is absent", async () => {
    const { out } = await runDirect(usageCommand, {
      since: "2020-01-01T00:00:00.000Z",
      until: null,
      connections: [],
      vendors: [],
      models: [],
      bots: [],
      recent: [],
    });
    expect(out).toContain("(>60s = new turn)");
  });

  it("reports the server's configured gap when turnEstimate is present", async () => {
    const { out } = await runDirect(usageCommand, {
      since: "2020-01-01T00:00:00.000Z",
      until: null,
      turnEstimate: { estimated: true, gapMs: 90_000 },
      connections: [],
      vendors: [],
      models: [],
      bots: [],
      recent: [],
    });
    expect(out).toContain("(>90s = new turn)");
  });

  it("defaults estimatedTurns to 0 when a model/bot row omits it", async () => {
    const { out } = await runDirect(usageCommand, {
      since: "2020-01-01T00:00:00.000Z",
      until: null,
      connections: [],
      vendors: [],
      models: [{ vendor: "openai", model: null, requests: 2, errors: 0, failovers: 0, inputTokens: 1, outputTokens: 2 }],
      bots: [
        {
          agentId: "ag_gone",
          agentName: null,
          vendor: "openai",
          model: null,
          requests: 2,
          errors: 0,
          inputTokens: 1,
          outputTokens: 2,
        },
      ],
      recent: [],
    });
    const modelRow = out.split("\n").find((l) => l.startsWith("openai"))!;
    expect(modelRow.split(/\s+/)).toEqual(["openai", "(unknown)", "2", "0", "0", "1", "2"]);
    // A bot row with no resolvable name renders as "(unknown)" too.
    const botRow = out.split("\n").find((l) => l.startsWith("(unknown)"))!;
    expect(botRow.split(/\s+/)).toEqual(["(unknown)", "openai", "(unknown)", "2", "0", "0", "1", "2"]);
  });

  it("still prints all four section headers for a wholly empty response", async () => {
    const { out } = await runDirect(usageCommand, {
      since: "2020-01-01T00:00:00.000Z",
      until: "2020-01-02T00:00:00.000Z",
      connections: [],
      vendors: [],
      models: [],
      bots: [],
      recent: [],
    });
    expect(out.split("\n")[0]).toBe(
      "Usage since 2020-01-01T00:00:00.000Z until 2020-01-02T00:00:00.000Z",
    );
    expect(out).toContain("By connection:");
    expect(out).toContain("By bot + model:");
  });
});

describe("cli observe: json mode", () => {
  it("audit --json emits raw rows and skips the table", async () => {
    logs = [];
    setJsonMode(false);
    await main(["--json", "audit", "--agent", agentBId]);
    const rows = JSON.parse(logs.join("\n")) as Array<{ host: string; decision: string }>;
    expect(rows).toHaveLength(1);
    expect(rows[0].host).toBe("evil.example.com");
    expect(rows[0].decision).toBe("deny");
  });

  it("usage --json emits the raw rollup object and skips the tables", async () => {
    logs = [];
    setJsonMode(false);
    await main(["--json", "usage"]);
    const out = logs.join("\n");
    const res = JSON.parse(out) as { vendors: Array<{ vendor: string; requests: number }> };
    expect(res.vendors.find((v) => v.vendor === "anthropic")?.requests).toBe(3);
    expect(out).not.toContain("By vendor:");
  });
});
