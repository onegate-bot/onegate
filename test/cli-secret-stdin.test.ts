/**
 * Secret-input tests: every secret-bearing CLI flag must have a stdin form so
 * the value never lands in argv (visible in `ps`, /proc/<pid>/cmdline and shell
 * history).
 *
 * Covers:
 *   - `credentials set --data-stdin` (key=value lines, and the sole-key form)
 *   - `integrations connect --client-secret-stdin`
 *   - `connections add --kind app --data-stdin`
 *   - the secret never appearing in argv or in --help output
 *   - the legacy argv flags still working (backwards compatibility)
 *   - supplying both forms being rejected with a clear error
 *
 * Same harness as cli-integrations-coverage.test.ts (real admin server on an
 * ephemeral port over a temp-dir store), plus a process.stdin swap so the
 * stdin paths can be driven without a real pipe.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
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
import {
  parseDataPairs,
  readDataPairsFromStdin,
  readRequiredSecretFromStdin,
  readSecretFromStdin,
  rejectDuplicateSecretInput,
} from "../src/cli/secret-input.js";

/** A value that must never surface in argv, help text or command output. */
const SECRET = "sk-live-must-never-hit-argv-9f3a2b";

let dir: string;
let store: Store;
let server: http.Server;
let port: number;
let adminToken: string;
let logs: string[];
let errs: string[];
let exitCode: number | null;
let seenArgv: string[][];

let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;
let outSpy: ReturnType<typeof vi.spyOn>;
let exitSpy: ReturnType<typeof vi.spyOn>;

async function run(...argv: string[]): Promise<{ out: string; err: string; exit: number | null }> {
  logs = [];
  errs = [];
  exitCode = null;
  seenArgv.push(argv);
  setJsonMode(false);
  try {
    await main(argv);
  } catch (e) {
    if ((e as Error).message !== "__exit__") throw e;
  }
  return { out: logs.join("\n"), err: errs.join("\n"), exit: exitCode };
}

/** Runs a command with process.stdin replaced by a readable carrying `input`. */
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
  seenArgv = [];
  dir = mkdtempSync(join(tmpdir(), "onegate-clisecret-"));
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

// ---------------------------------------------------------------- helpers ---

describe("secret-input helpers", () => {
  const withStdin = async <T>(input: string, fn: () => Promise<T>): Promise<T> => {
    const original = Object.getOwnPropertyDescriptor(process, "stdin")!;
    Object.defineProperty(process, "stdin", {
      value: Readable.from([Buffer.from(input, "utf8")]),
      configurable: true,
    });
    try {
      return await fn();
    } finally {
      Object.defineProperty(process, "stdin", original);
    }
  };

  it("readSecretFromStdin trims surrounding whitespace and newlines", async () => {
    const got = await withStdin(`  ${SECRET}\n`, () => readSecretFromStdin());
    expect(got).toBe(SECRET);
  });

  it("readRequiredSecretFromStdin rejects empty stdin with the label", async () => {
    await expect(withStdin("   \n", () => readRequiredSecretFromStdin("client secret"))).rejects.toThrow(
      "no client secret on stdin",
    );
  });

  it("readDataPairsFromStdin parses newline-separated key=value pairs", async () => {
    const got = await withStdin(`apiKey=${SECRET}\nregion=eu1\n`, () => readDataPairsFromStdin());
    expect(got).toEqual({ apiKey: SECRET, region: "eu1" });
  });

  it("readDataPairsFromStdin skips blank lines", async () => {
    const got = await withStdin(`apiKey=${SECRET}\n\n\nregion=eu1\n`, () => readDataPairsFromStdin());
    expect(got).toEqual({ apiKey: SECRET, region: "eu1" });
  });

  it("readDataPairsFromStdin supports the sole-key form (raw secret, no framing)", async () => {
    const got = await withStdin(SECRET, () => readDataPairsFromStdin("apiKey"));
    expect(got).toEqual({ apiKey: SECRET });
  });

  it("readDataPairsFromStdin still parses key=value even when a sole key is offered", async () => {
    const got = await withStdin(`token=${SECRET}`, () => readDataPairsFromStdin("apiKey"));
    expect(got).toEqual({ token: SECRET });
  });

  it("readDataPairsFromStdin rejects a line with no =", async () => {
    await expect(withStdin("apiKey\nregion=eu1", () => readDataPairsFromStdin())).rejects.toThrow(
      "must be key=value",
    );
  });

  it("readDataPairsFromStdin rejects empty stdin", async () => {
    await expect(withStdin("  \n ", () => readDataPairsFromStdin())).rejects.toThrow("no data on stdin");
  });

  it("parseDataPairs keeps everything after the first =", () => {
    expect(parseDataPairs(["apiKey=a=b=c"])).toEqual({ apiKey: "a=b=c" });
  });

  it("rejectDuplicateSecretInput throws only when both forms are given", () => {
    expect(() => rejectDuplicateSecretInput("--data", "--data-stdin", true, true)).toThrow(
      "mutually exclusive",
    );
    expect(() => rejectDuplicateSecretInput("--data", "--data-stdin", true, false)).not.toThrow();
    expect(() => rejectDuplicateSecretInput("--data", "--data-stdin", false, true)).not.toThrow();
    expect(() => rejectDuplicateSecretInput("--data", "--data-stdin", false, false)).not.toThrow();
  });
});

// ------------------------------------------------------ credentials set ---

describe("cli credentials set: --data-stdin", () => {
  it("reads key=value pairs from stdin and stores them", async () => {
    const r = await runWithStdin(
      `apiKey=${SECRET}\nregion=eu1\n`,
      "credentials",
      "set",
      "stripe",
      "--name",
      "stdin-pairs",
      "--data-stdin",
    );
    expect(r.exit).toBeNull();
    expect(r.out).toContain('Credential set for stripe ("stdin-pairs")');
    const cred = store.getCredential("stripe");
    expect(cred?.data).toMatchObject({ apiKey: SECRET, region: "eu1" });
  });

  it("the sole-key form pipes a raw secret with no key=value framing", async () => {
    const r = await runWithStdin(
      SECRET,
      "credentials",
      "set",
      "stripe",
      "--name",
      "stdin-solekey",
      "--data-stdin",
      "apiKey",
    );
    expect(r.exit).toBeNull();
    const cred = store.getCredential("stripe");
    expect(cred?.data.apiKey).toBe(SECRET);
  });

  it("never echoes the secret back in the output", async () => {
    const r = await runWithStdin(
      `apiKey=${SECRET}\n`,
      "credentials",
      "set",
      "stripe",
      "--name",
      "stdin-noecho",
      "--data-stdin",
    );
    expect(r.out).not.toContain(SECRET);
    expect(r.err).not.toContain(SECRET);
  });

  it("the secret never appears in the argv that invoked the command", async () => {
    await runWithStdin(
      `apiKey=${SECRET}\n`,
      "credentials",
      "set",
      "stripe",
      "--name",
      "stdin-argv",
      "--data-stdin",
    );
    const argv = seenArgv[seenArgv.length - 1];
    expect(argv).toContain("--data-stdin");
    expect(argv.join(" ")).not.toContain(SECRET);
  });

  it("rejects empty stdin", async () => {
    const r = await runWithStdin("   \n", "credentials", "set", "stripe", "--name", "x", "--data-stdin");
    expect(r.exit).toBe(1);
    expect(r.err).toContain("no data on stdin");
  });

  it("rejects supplying both --data and --data-stdin", async () => {
    const r = await runWithStdin(
      `apiKey=${SECRET}`,
      "credentials",
      "set",
      "stripe",
      "--name",
      "x",
      "--data",
      "apiKey=other",
      "--data-stdin",
    );
    expect(r.exit).toBe(1);
    expect(r.err).toContain("--data and --data-stdin are mutually exclusive");
  });

  it("the legacy --data flag still works (backwards compatibility)", async () => {
    const r = await run("credentials", "set", "stripe", "--name", "legacy-data", "--data", "apiKey=legacy1");
    expect(r.exit).toBeNull();
    expect(r.out).toContain('Credential set for stripe ("legacy-data")');
    expect(store.getCredential("stripe")?.data.apiKey).toBe("legacy1");
  });

  it("the no-secret error steers the operator to the stdin form", async () => {
    const r = await run("credentials", "set", "stripe", "--name", "x");
    expect(r.exit).toBe(1);
    expect(r.err).toContain("--data-stdin");
  });
});

// --------------------------------------------------- integrations connect ---

describe("cli integrations connect: --client-secret-stdin", () => {
  it("reads the OAuth client secret from stdin and starts the flow", async () => {
    const r = await runWithStdin(
      SECRET,
      "integrations",
      "connect",
      "google",
      "--client-id",
      "cid-123",
      "--client-secret-stdin",
      "--redirect-base",
      "https://example.test",
    );
    expect(r.exit).toBeNull();
    expect(r.out).toContain("Open this URL in a browser to authorize");
    expect(r.out).toContain("cid-123");
  });

  it("never echoes the client secret into the printed authorize URL", async () => {
    const r = await runWithStdin(
      SECRET,
      "integrations",
      "connect",
      "google",
      "--client-id",
      "cid-noecho",
      "--client-secret-stdin",
      "--redirect-base",
      "https://example.test",
    );
    expect(r.out).not.toContain(SECRET);
    expect(r.err).not.toContain(SECRET);
  });

  it("the secret never appears in the argv that invoked the command", async () => {
    await runWithStdin(
      SECRET,
      "integrations",
      "connect",
      "google",
      "--client-id",
      "cid-argv",
      "--client-secret-stdin",
      "--redirect-base",
      "https://example.test",
    );
    const argv = seenArgv[seenArgv.length - 1];
    expect(argv).toContain("--client-secret-stdin");
    expect(argv.join(" ")).not.toContain(SECRET);
  });

  it("rejects empty stdin with a clear message", async () => {
    const r = await runWithStdin(
      "  \n",
      "integrations",
      "connect",
      "google",
      "--client-id",
      "cid-empty",
      "--client-secret-stdin",
      "--redirect-base",
      "https://example.test",
    );
    expect(r.exit).toBe(1);
    expect(r.err).toContain("no client secret on stdin");
  });

  it("rejects supplying both --client-secret and --client-secret-stdin", async () => {
    const r = await runWithStdin(
      SECRET,
      "integrations",
      "connect",
      "google",
      "--client-id",
      "cid-both",
      "--client-secret",
      "argv-secret",
      "--client-secret-stdin",
      "--redirect-base",
      "https://example.test",
    );
    expect(r.exit).toBe(1);
    expect(r.err).toContain("--client-secret and --client-secret-stdin are mutually exclusive");
  });

  it("the legacy --client-secret flag still works (backwards compatibility)", async () => {
    const r = await run(
      "integrations",
      "connect",
      "google",
      "--client-id",
      "cid-legacy",
      "--client-secret",
      "legacy-secret",
      "--redirect-base",
      "https://example.test",
    );
    expect(r.exit).toBeNull();
    expect(r.out).toContain("Open this URL in a browser to authorize");
  });

  it("the usage error advertises the stdin form", async () => {
    const r = await run("integrations", "connect", "google", "--redirect-base", "https://example.test");
    expect(r.exit).toBe(1);
    expect(r.err).toContain("--client-secret-stdin");
  });
});

// ------------------------------------------------- connections add --kind app ---

describe("cli connections add --kind app: --data-stdin", () => {
  it("reads key=value pairs from stdin and creates the app connection", async () => {
    const r = await runWithStdin(
      `secretKey=${SECRET}\n`,
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "stripe",
      "--name",
      "app-stdin",
      "--data-stdin",
    );
    expect(r.exit).toBeNull();
    expect(r.out).toContain('App connection "app-stdin" created');
    expect(r.out).not.toContain(SECRET);
  });

  it("the secret never appears in the argv that invoked the command", async () => {
    await runWithStdin(
      `secretKey=${SECRET}\n`,
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "stripe",
      "--name",
      "app-stdin-argv",
      "--data-stdin",
    );
    const argv = seenArgv[seenArgv.length - 1];
    expect(argv).toContain("--data-stdin");
    expect(argv.join(" ")).not.toContain(SECRET);
  });

  it("rejects supplying both --data and --data-stdin", async () => {
    const r = await runWithStdin(
      `secretKey=${SECRET}`,
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "stripe",
      "--name",
      "app-both",
      "--data",
      "secretKey=other",
      "--data-stdin",
    );
    expect(r.exit).toBe(1);
    expect(r.err).toContain("--data and --data-stdin are mutually exclusive");
  });

  it("the legacy --data flag still works (backwards compatibility)", async () => {
    const r = await run(
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "stripe",
      "--name",
      "app-legacy",
      "--data",
      "secretKey=legacy2",
    );
    expect(r.exit).toBeNull();
    expect(r.out).toContain('App connection "app-legacy" created');
  });

  it("the no-secret error steers the operator to the stdin form", async () => {
    const r = await run(
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "stripe",
      "--name",
      "app-nosecret",
    );
    expect(r.exit).toBe(1);
    expect(r.err).toContain("--data-stdin");
  });
});

// -------------------------------------------------------------- help text ---

describe("cli help: secret guidance", () => {
  it("advertises the stdin flags and warns the argv forms are insecure", async () => {
    const r = await run("--help");
    expect(r.out).toContain("--data-stdin");
    expect(r.out).toContain("--client-secret-stdin");
    expect(r.out).toContain("--secret-stdin");
    expect(r.out).toMatch(/insecure|shell history/i);
  });

  it("help output never contains a secret value", async () => {
    const r = await run("--help");
    expect(r.out).not.toContain(SECRET);
  });
});
