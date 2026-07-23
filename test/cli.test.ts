import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.js";

let dir: string;
let logs: string[];
let logSpy: ReturnType<typeof vi.spyOn>;
let outSpy: ReturnType<typeof vi.spyOn>;

async function run(...argv: string[]): Promise<string> {
  logs = [];
  await main(argv);
  return logs.join("\n");
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "onegate-cli-"));
  process.env.ONEGATE_DATA = dir;
  logSpy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    logs.push(args.join(" "));
  });
  outSpy = vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
    logs.push(String(chunk));
    return true;
  }) as never);
});

afterAll(() => {
  logSpy.mockRestore();
  outSpy.mockRestore();
  delete process.env.ONEGATE_DATA;
  rmSync(dir, { recursive: true, force: true });
});

describe("onegate cli", () => {
  it("init creates the CA, db and prints the admin token once", async () => {
    const out = await run("init");
    expect(out).toContain("Admin token:  oga_");
    expect(existsSync(join(dir, "rootCA.pem"))).toBe(true);
    expect(existsSync(join(dir, "onegate.db"))).toBe(true);
  });

  it("agent add prints a one-time token and proxy env line", async () => {
    const out = await run("agent", "add", "scout", "--policy", "allow-all");
    expect(out).toMatch(/Token \(shown ONCE\): og_[0-9a-f]{48}/);
    expect(out).toContain("HTTPS_PROXY=http://agent:og_");
    expect(out).toContain("default: allow-all");
  });

  it("agent list shows registered agents", async () => {
    const out = await run("agent", "list");
    expect(out).toContain("scout");
    expect(out).toContain("policy=allow-all");
  });

  it("print-ca emits the PEM", async () => {
    const out = await run("print-ca");
    expect(out).toContain("BEGIN CERTIFICATE");
  });

  it("admin reset-token mints a fresh token", async () => {
    const out = await run("admin", "reset-token");
    expect(out).toMatch(/New admin token: oga_[0-9a-f]{48}/);
  });

  it("no command prints help", async () => {
    const out = await run();
    expect(out).toContain("Usage:");
  });
});
