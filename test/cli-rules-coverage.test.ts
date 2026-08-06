/**
 * Branch coverage for the `onegate rules` command surface. Rules decide which
 * agent may reach which integration with which connection, so every flag
 * combination and every rejection path is asserted here: the connection-scoped
 * flags (--connection / --connection-scope), the TTL shorthand parser, the
 * lease/connection rendering in list + add output, and the sub-command aliases.
 *
 * Harness matches test/cli-admin.test.ts: a real admin server on an ephemeral
 * port over a temp-dir Store, driven through main() from src/cli.ts.
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

interface RuleJson {
  id: string;
  scope: string;
  subjectId: string;
  integrationId: string;
  methods: string[];
  pathGlob: string;
  effect: string;
  expiresAt?: string | null;
  leaseTtlSeconds?: number | null;
  connectionId?: string | null;
  connectionScope?: string;
}

let dir: string;
let store: Store;
let server: http.Server;
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

/** Creates a rule and returns the parsed JSON row. */
async function addRule(...argv: string[]): Promise<RuleJson> {
  const { out, err } = await run("--json", "rules", "add", ...argv);
  expect(err).toBe("");
  return JSON.parse(out) as RuleJson;
}

let agentId: string;
let connId: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-clirules-"));
  process.env.ONEGATE_DATA = dir;
  initCa(dir);
  store = new Store(join(dir, "onegate.db"));
  adminToken = ensureAdminToken(store)!;
  const registry = await buildRegistry();
  const app = createAdminApp({ store, registry, ca: { rootPem: "x" } as never, version: "test" });
  server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;

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

  const a = await run("--json", "agents", "add", "rules-cov-worker");
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
    "gh-pin",
    "--data",
    "pat=ghp_x",
  );
  connId = (JSON.parse(c.out) as { id: string }).id;
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

describe("cli rules: add defaults and human output", () => {
  it("defaults methods to * and path to /** when the flags are omitted", async () => {
    const rule = await addRule(
      "--scope",
      "agent",
      "--subject",
      agentId,
      "--integration",
      "github",
      "--effect",
      "allow",
    );
    expect(rule.methods).toEqual(["*"]);
    expect(rule.pathGlob).toBe("/**");
    expect(rule.connectionScope).toBeFalsy();
    expect(rule.leaseTtlSeconds).toBeFalsy();
  });

  it("prints a plain summary line with no connection or lease suffix", async () => {
    const { out, exit } = await run(
      "rules",
      "add",
      "--scope",
      "agent",
      "--subject",
      agentId,
      "--integration",
      "slack",
      "--effect",
      "deny",
      "--methods",
      "POST",
      "--path",
      "/api/chat.postMessage",
    );
    expect(exit).toBeNull();
    expect(out).toMatch(
      new RegExp(`^Rule rl_\\w+: deny agent:${agentId} -> slack POST /api/chat\\.postMessage$`, "m"),
    );
    expect(out).not.toContain("[connection");
    expect(out).not.toContain("[lease");
  });

  it("trims whitespace and drops empty entries from --methods", async () => {
    const rule = await addRule(
      "--scope",
      "agent",
      "--subject",
      agentId,
      "--integration",
      "github",
      "--effect",
      "allow",
      "--methods",
      " GET , ,POST,, PUT ",
    );
    expect(rule.methods).toEqual(["GET", "POST", "PUT"]);
  });

  it("supports project scope as well as agent scope", async () => {
    const proj = await run("--json", "projects", "add", "rules-cov-proj");
    const projId = (JSON.parse(proj.out) as { id: string }).id;
    const rule = await addRule(
      "--scope",
      "project",
      "--subject",
      projId,
      "--integration",
      "*",
      "--effect",
      "deny",
    );
    expect(rule.scope).toBe("project");
    expect(rule.subjectId).toBe(projId);
    expect(rule.integrationId).toBe("*");
  });
});

describe("cli rules: required-flag validation", () => {
  const usage = "usage: onegate rules add --scope agent|project";

  it("rejects a missing --scope", async () => {
    const { err, exit } = await run(
      "rules",
      "add",
      "--subject",
      agentId,
      "--integration",
      "github",
      "--effect",
      "allow",
    );
    expect(exit).toBe(1);
    expect(err).toContain(usage);
  });

  it("rejects a missing --subject", async () => {
    const { err, exit } = await run(
      "rules",
      "add",
      "--scope",
      "agent",
      "--integration",
      "github",
      "--effect",
      "allow",
    );
    expect(exit).toBe(1);
    expect(err).toContain(usage);
  });

  it("rejects a missing --integration", async () => {
    const { err, exit } = await run("rules", "add", "--scope", "agent", "--subject", agentId, "--effect", "allow");
    expect(exit).toBe(1);
    expect(err).toContain(usage);
  });

  it("rejects a missing --effect", async () => {
    const { err, exit } = await run(
      "rules",
      "add",
      "--scope",
      "agent",
      "--subject",
      agentId,
      "--integration",
      "github",
    );
    expect(exit).toBe(1);
    expect(err).toContain(usage);
  });

  it("rejects an unknown flag before it reaches the API", async () => {
    const { err, exit } = await run(
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
      "--conection",
      connId,
    );
    expect(exit).toBe(1);
    expect(err).toMatch(/unknown option/i);
  });
});

describe("cli rules: connection-scoped flags", () => {
  it("creates a connection-scoped rule with scope only", async () => {
    const rule = await addRule(
      "--scope",
      "agent",
      "--subject",
      agentId,
      "--integration",
      "github",
      "--effect",
      "allow",
      "--connection",
      connId,
      "--connection-scope",
      "only",
    );
    expect(rule.connectionId).toBe(connId);
    expect(rule.connectionScope).toBe("only");
  });

  it("creates a connection-scoped rule with scope except and prints the suffix", async () => {
    const { out, exit } = await run(
      "rules",
      "add",
      "--scope",
      "agent",
      "--subject",
      agentId,
      "--integration",
      "github",
      "--effect",
      "deny",
      "--connection",
      connId,
      "--connection-scope",
      "except",
    );
    expect(exit).toBeNull();
    expect(out).toContain(`[connection except ${connId}]`);
  });

  it("rejects an invalid --connection-scope value", async () => {
    const { err, exit } = await run(
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
      "--connection",
      connId,
      "--connection-scope",
      "all",
    );
    expect(exit).toBe(1);
    expect(err).toContain('invalid --connection-scope "all" (use "only" or "except")');
  });

  it("rejects an empty --connection-scope value", async () => {
    const { err, exit } = await run(
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
      "--connection",
      connId,
      "--connection-scope",
      "",
    );
    expect(exit).toBe(1);
    expect(err).toContain("invalid --connection-scope");
  });

  it("rejects --connection-scope without --connection", async () => {
    const { err, exit } = await run(
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
      "--connection-scope",
      "only",
    );
    expect(exit).toBe(1);
    expect(err).toContain("--connection-scope requires --connection <conn-id>");
  });

  it("rejects --connection without --connection-scope", async () => {
    const { err, exit } = await run(
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
      "--connection",
      connId,
    );
    expect(exit).toBe(1);
    expect(err).toContain("--connection requires --connection-scope only|except");
  });
});

describe("cli rules: --ttl parsing", () => {
  async function ttlRule(ttl: string): Promise<RuleJson> {
    return addRule(
      "--scope",
      "agent",
      "--subject",
      agentId,
      "--integration",
      "github",
      "--effect",
      "allow",
      "--ttl",
      ttl,
    );
  }

  it("accepts bare seconds", async () => {
    expect((await ttlRule("90")).leaseTtlSeconds).toBe(90);
  });

  it("accepts an explicit s suffix", async () => {
    expect((await ttlRule("45s")).leaseTtlSeconds).toBe(45);
  });

  it("accepts an m suffix", async () => {
    expect((await ttlRule("30m")).leaseTtlSeconds).toBe(1800);
  });

  it("accepts an h suffix, uppercase and space-separated", async () => {
    expect((await ttlRule("8H")).leaseTtlSeconds).toBe(28800);
    expect((await ttlRule(" 2 h ")).leaseTtlSeconds).toBe(7200);
  });

  it("stamps expiresAt alongside the lease and prints the lease suffix", async () => {
    const { out, exit } = await run(
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
      "--ttl",
      "8h",
    );
    expect(exit).toBeNull();
    expect(out).toMatch(/\[lease 8h until \d{4}-\d{2}-\d{2}T/);
  });

  it("renders a non-hour-aligned lease in seconds", async () => {
    const { out } = await run(
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
      "--ttl",
      "90",
    );
    expect(out).toMatch(/\[lease 90s until /);
  });

  it("a zero ttl records no lease (the API only leases ttl > 0)", async () => {
    const rule = await ttlRule("0");
    expect(rule.leaseTtlSeconds).toBeFalsy();
    expect(rule.expiresAt).toBeFalsy();
  });

  it("a ttl on a deny rule is ignored by the API", async () => {
    const rule = await addRule(
      "--scope",
      "agent",
      "--subject",
      agentId,
      "--integration",
      "github",
      "--effect",
      "deny",
      "--ttl",
      "1h",
    );
    expect(rule.leaseTtlSeconds).toBeFalsy();
  });

  it.each(["abc", "8d", "1.5h", "8 hours", ""])("rejects the malformed ttl %j", async (bad) => {
    const { err, exit } = await run(
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
      "--ttl",
      bad,
    );
    expect(exit).toBe(1);
    expect(err).toContain(`invalid --ttl "${bad}" (use seconds, or "8h" / "30m")`);
  });

  it("rejects a negative ttl (parseArgs refuses the dash-leading value first)", async () => {
    const { err, exit } = await run(
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
      "--ttl",
      "-5",
    );
    expect(exit).toBe(1);
    expect(err).toMatch(/argument is ambiguous/);
  });

  it("rejects a negative ttl passed with = syntax, in the parser", async () => {
    const { err, exit } = await run(
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
      "--ttl=-5",
    );
    expect(exit).toBe(1);
    expect(err).toContain('invalid --ttl "-5"');
  });
});

describe("cli rules: list rendering", () => {
  it("prints a table with CONNECTION and LEASE columns filled in", async () => {
    const { out, exit } = await run("rules", "list");
    expect(exit).toBeNull();
    expect(out).toContain("CONNECTION");
    expect(out).toContain("LEASE");
    // A connection-scoped rule renders "<scope> <connId>"; an unscoped one "-".
    expect(out).toContain(`only ${connId}`);
    expect(out).toContain(`except ${connId}`);
    expect(out).toMatch(/8h until \d{4}-\d{2}-\d{2}T/);
    expect(out).toMatch(/^ID\s+SCOPE\s+SUBJECT/m);
  });

  it("renders an expired lease as (expired) rather than a stale until-date", async () => {
    const expired = store.createRule({
      scope: "agent",
      subjectId: agentId,
      integrationId: "github",
      methods: ["GET"],
      pathGlob: "/expired/**",
      effect: "allow",
      leaseTtlSeconds: 3600,
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    });
    const { out } = await run("rules", "list");
    expect(out).toContain("1h (expired)");
    await run("rules", "rm", expired.id);
  });

  it("renders a lease TTL with no expiry as a bare duration", async () => {
    const noExpiry = store.createRule({
      scope: "agent",
      subjectId: agentId,
      integrationId: "github",
      methods: ["GET"],
      pathGlob: "/no-expiry/**",
      effect: "allow",
      leaseTtlSeconds: 7200,
      expiresAt: null,
    });
    const { out } = await run("rules", "list");
    const row = out.split("\n").find((l) => l.includes(noExpiry.id))!;
    expect(row).toMatch(/2h\s*$/);
    await run("rules", "rm", noExpiry.id);
  });

  it("ls is an alias for list", async () => {
    const { out, exit } = await run("rules", "ls");
    expect(exit).toBeNull();
    expect(out).toContain("INTEGRATION");
  });

  it("says 'no rules.' once every rule is gone", async () => {
    const { out } = await run("--json", "rules", "list");
    for (const r of JSON.parse(out) as RuleJson[]) await run("rules", "rm", r.id);
    const after = await run("rules", "list");
    expect(after.out).toBe("no rules.");
  });
});

describe("cli rules: renew", () => {
  it("re-stamps a lapsed lease and reports the new expiry", async () => {
    // Seeded already-expired so the re-stamp is observable.
    const rule = store.createRule({
      scope: "agent",
      subjectId: agentId,
      integrationId: "github",
      methods: ["GET"],
      pathGlob: "/**",
      effect: "allow",
      leaseTtlSeconds: 3600,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    const { out, exit } = await run("rules", "renew", rule.id);
    expect(exit).toBeNull();
    expect(out).toMatch(new RegExp(`^Renewed rule ${rule.id}: lease 1h until `));
    expect(Date.parse(store.getRule(rule.id)!.expiresAt!)).toBeGreaterThan(Date.now());
    await run("rules", "rm", rule.id);
  });

  it("renewing an unleased rule is a no-op that reports no lease", async () => {
    const rule = await addRule(
      "--scope",
      "agent",
      "--subject",
      agentId,
      "--integration",
      "github",
      "--effect",
      "allow",
    );
    const { out, exit } = await run("rules", "renew", rule.id);
    expect(exit).toBeNull();
    expect(out).toContain(`Renewed rule ${rule.id}: lease -`);
    await run("rules", "rm", rule.id);
  });

  it("requires an id", async () => {
    const { err, exit } = await run("rules", "renew");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate rules renew <id>");
  });

  it("reports a 404 for an unknown rule id", async () => {
    const { err, exit } = await run("rules", "renew", "rl_does_not_exist");
    expect(exit).toBe(1);
    expect(err).toContain("unknown_rule");
  });
});

describe("cli rules: rm and dispatch", () => {
  async function seed(): Promise<string> {
    const r = await addRule(
      "--scope",
      "agent",
      "--subject",
      agentId,
      "--integration",
      "github",
      "--effect",
      "allow",
    );
    return r.id;
  }

  it("rm removes the rule and it disappears from list", async () => {
    const id = await seed();
    const { out, exit } = await run("rules", "rm", id);
    expect(exit).toBeNull();
    expect(out).toBe(`Removed rule ${id}.`);
    const after = await run("--json", "rules", "list");
    expect((JSON.parse(after.out) as RuleJson[]).some((r) => r.id === id)).toBe(false);
  });

  it("remove and delete are aliases for rm", async () => {
    const a = await seed();
    expect((await run("rules", "remove", a)).out).toContain("Removed rule");
    const b = await seed();
    expect((await run("rules", "delete", b)).out).toContain("Removed rule");
  });

  it("rm emits the removed id in json mode", async () => {
    const id = await seed();
    const { out } = await run("--json", "rules", "rm", id);
    expect(JSON.parse(out)).toEqual({ removed: id });
  });

  it("rm requires an id", async () => {
    const { err, exit } = await run("rules", "rm");
    expect(exit).toBe(1);
    expect(err).toContain("usage: onegate rules rm <id>");
  });

  it("rejects an unknown sub-command", async () => {
    const { err, exit } = await run("rules", "nope");
    expect(exit).toBe(1);
    expect(err).toContain('unknown rules command "nope". Try: list, add, renew, rm');
  });

  it("rejects a missing sub-command", async () => {
    const { err, exit } = await run("rules");
    expect(exit).toBe(1);
    expect(err).toContain("unknown rules command");
  });
});

/**
 * The CLI splits `--methods` on commas and forwards the result. Because the
 * policy matcher only ever compares against an uppercase method, a lowercase
 * or misspelled verb produced a rule that could never match: a deny rule
 * stored that way was silently inert. The CLI now normalizes and validates
 * before the call (the server does the same).
 */
describe("rules add --methods normalization", () => {
  it("uppercases and trims lowercase verbs", async () => {
    const rule = await addRule(
      "--scope", "agent", "--subject", agentId, "--integration", "github",
      "--effect", "deny", "--methods", " post , put ",
    );
    expect(rule.methods).toEqual(["POST", "PUT"]);
  });

  it("keeps the wildcard default", async () => {
    const rule = await addRule(
      "--scope", "agent", "--subject", agentId, "--integration", "github", "--effect", "allow",
    );
    expect(rule.methods).toEqual(["*"]);
  });

  it("tolerates a trailing comma", async () => {
    const rule = await addRule(
      "--scope", "agent", "--subject", agentId, "--integration", "github",
      "--effect", "deny", "--methods", "get,",
    );
    expect(rule.methods).toEqual(["GET"]);
  });

  it("rejects an unknown verb with a clear error instead of storing it", async () => {
    const { err, exit } = await run(
      "rules", "add", "--scope", "agent", "--subject", agentId, "--integration", "github",
      "--effect", "deny", "--methods", "GTE",
    );
    expect(exit).toBe(1);
    expect(err).toContain('invalid --methods "GTE"');
    expect(err).toContain("unsupported HTTP method");
  });
});
