/**
 * `onegate approvals pin set|clear|status`: the owner PIN that guards
 * approve/renew links in relay mode (ONEGATE_AGENT_RELAYS_OWNER_LINKS). The PIN
 * is read from stdin only, so it never lands in argv.
 *
 * Harness matches test/cli-secret-stdin.test.ts: a real admin server on an
 * ephemeral port over a temp-dir Store, driven through main() from src/cli.ts.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import http from "node:http";
import { Readable } from "node:stream";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/store/db.js";
import { initCa } from "../src/ca.js";
import { Registry } from "../src/integrations/types.js";
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";
import { setJsonMode } from "../src/cli/output.js";
import { main } from "../src/cli.js";
import { OWNER_PIN_SETTING, verifyOwnerPin } from "../src/util/owner-links.js";

let dir: string;
let store: Store;
let server: http.Server;
let logs: string[];
let errs: string[];
let exitCode: number | null;
const spies: Array<{ mockRestore(): void }> = [];

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

async function runWithStdin(input: string, ...argv: string[]) {
  const original = Object.getOwnPropertyDescriptor(process, "stdin")!;
  Object.defineProperty(process, "stdin", { value: Readable.from([Buffer.from(input, "utf8")]), configurable: true });
  try {
    return await run(...argv);
  } finally {
    Object.defineProperty(process, "stdin", original);
  }
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-clipin-"));
  process.env.ONEGATE_DATA = dir;
  initCa(dir);
  store = new Store(join(dir, "onegate.db"));
  const adminToken = ensureAdminToken(store)!;
  const app = createAdminApp({
    store,
    registry: new Registry(),
    ca: { rootPem: "x" } as never,
    version: "test",
    agentRelaysOwnerLinks: true,
  });
  server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  process.env.ONEGATE_ADMIN_URL = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  process.env.ONEGATE_ADMIN_TOKEN = adminToken;
  spies.push(
    vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => void logs.push(a.join(" "))),
    vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => void errs.push(a.join(" "))),
    vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
      logs.push(String(chunk));
      return true;
    }) as never),
    vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      exitCode = code ?? 0;
      throw new Error("__exit__");
    }) as never),
  );
});

afterAll(async () => {
  for (const s of spies) s.mockRestore();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  store.close();
  delete process.env.ONEGATE_DATA;
  delete process.env.ONEGATE_ADMIN_URL;
  delete process.env.ONEGATE_ADMIN_TOKEN;
  rmSync(dir, { recursive: true, force: true });
});

describe("onegate approvals pin", () => {
  it("sets the PIN from stdin, stored hashed", async () => {
    const r = await runWithStdin("246810\n", "approvals", "pin", "set");
    expect(r.exit).toBeNull();
    expect(r.out).toContain("Owner PIN: set");
    expect(r.out).toContain("require it");
    const stored = store.getSetting(OWNER_PIN_SETTING)!;
    expect(stored).not.toContain("246810");
    expect(verifyOwnerPin("246810", stored)).toBe(true);
  });

  it("reports status, and clears", async () => {
    const st = await run("--json", "approvals", "pin", "status");
    expect(JSON.parse(st.out)).toEqual({ set: true, required: true });
    const cl = await run("approvals", "pin", "clear");
    expect(cl.out).toContain("Owner PIN: not set");
    expect(store.getSetting(OWNER_PIN_SETTING)).toBeNull();
  });

  it("rejects empty stdin, a bad PIN and an unknown verb", async () => {
    expect((await runWithStdin("", "approvals", "pin", "set")).err).toMatch(/no PIN on stdin/);
    expect((await runWithStdin("12", "approvals", "pin", "set")).err).toMatch(/4 to 64/);
    expect((await run("approvals", "pin", "show")).err).toMatch(/usage/);
  });
});
