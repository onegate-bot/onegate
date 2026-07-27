import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Regression tests for the CA/leaf private keys being created world-readable.
 *
 * The defect was `writeFileSync(path, key)` followed by `chmodSync(path, 0o600)`:
 * the file is created with the process umask (typically 0022 -> 0644) and only
 * tightened afterwards, so there is a window in which any local process can open
 * a handle that remains readable after the chmod.
 *
 * Asserting the *final* on-disk mode cannot catch this -- it is 0600 either way
 * once the chmod lands. Instead we neutralize `chmodSync` so the mode left on
 * disk is exactly what the write syscall created. That makes the assertion
 * deterministic (no timing/race dependency) and it fails on the pre-fix code.
 *
 * We also pin the umask for the duration of the test so the pre-fix behaviour is
 * not masked by an already-restrictive ambient umask (e.g. 0077 in some CI
 * images would yield 0600 by accident and hide the bug).
 */
vi.mock("node:fs", async () => {
  const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
  return { ...actual, chmodSync: vi.fn() };
});

let dir: string;
let previousUmask: number;

beforeAll(() => {
  previousUmask = process.umask(0o022);
  dir = mkdtempSync(join(tmpdir(), "onegate-ca-keymode-"));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
  process.umask(previousUmask);
});

describe("private key file creation mode (chmodSync neutralized)", () => {
  it("creates the root CA key 0600 at write time, not via a follow-up chmod", async () => {
    const { initCa, caPaths } = await import("../src/ca.js");
    initCa(dir, "OneGate KeyMode Test CA");

    const p = caPaths(dir);
    const keyMode = statSync(p.keyPath).mode & 0o777;
    expect(keyMode).toBe(0o600);

    // The public root certificate is deliberately left at default permissions:
    // it is meant to be readable so clients can import it into a trust store.
    const certMode = statSync(p.certPath).mode & 0o777;
    expect(certMode & 0o044).not.toBe(0);
  });

  it("creates leaf private keys 0600 at write time", async () => {
    const { loadCa, caPaths } = await import("../src/ca.js");
    const ca = loadCa(dir);
    ca.leafFor("example.com");

    const p = caPaths(dir);
    const leafKeyMode = statSync(join(p.certsDir, "example.com.key")).mode & 0o777;
    expect(leafKeyMode).toBe(0o600);

    // The leaf certificate itself is public material, same as the root cert.
    const leafCertMode = statSync(join(p.certsDir, "example.com.crt")).mode & 0o777;
    expect(leafCertMode & 0o044).not.toBe(0);
  });
});
