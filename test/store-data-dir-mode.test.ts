import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Regression tests for the data directory being created world-traversable.
 *
 * `secret-box.ts` documents the key layout as "0600, in a 0700 dir" and calls
 * `mkdirSync(dir, { recursive: true, mode: 0o700 })`. But the Store constructor
 * ran first and created the same directory with no mode, so the process umask
 * (typically 0022 -> 0755) won. Recursive `mkdirSync` on an existing directory
 * neither errors nor re-applies the mode, so the 0700 never took effect on a
 * real first boot, and the SQLite database, its -wal/-shm sidecars and the audit
 * trail inside them were left readable by any local user.
 *
 * The umask is pinned for the duration so an already-restrictive ambient umask
 * (0077 in some CI images) cannot make the pre-fix code pass by accident.
 */

let root: string;
let previousUmask: number;

beforeAll(() => {
  previousUmask = process.umask(0o022);
  root = mkdtempSync(join(tmpdir(), "onegate-datadir-mode-"));
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
  process.umask(previousUmask);
});

const modeOf = (p: string) => statSync(p).mode & 0o777;

// File modes are not meaningful on Windows; the rest of the suite is POSIX-only
// anyway (the CA tests make the same assumption).
describe.skipIf(process.platform === "win32")("data directory permissions", () => {
  it("creates a fresh data directory 0700, not at the process umask", async () => {
    const { Store } = await import("../src/store/db.js");
    const dir = join(root, "fresh");

    const store = new Store(join(dir, "onegate.db"));
    store.close();

    expect(modeOf(dir)).toBe(0o700);
  });

  it("tightens a pre-existing 0755 data directory on the upgrade path", async () => {
    const { Store } = await import("../src/store/db.js");
    const dir = join(root, "upgraded");

    // Simulate a data directory left behind at default permissions by an
    // earlier release, where the mkdir mode alone would be a no-op.
    mkdirSync(dir, { recursive: true });
    expect(modeOf(dir)).toBe(0o755);

    const store = new Store(join(dir, "onegate.db"));
    store.close();

    expect(modeOf(dir)).toBe(0o700);
  });

  it("does not touch the filesystem for an in-memory database", async () => {
    const { Store } = await import("../src/store/db.js");
    // `dirname(":memory:")` is "." -- the cwd must never be chmodded to 0700.
    const store = new Store(":memory:");
    store.close();

    expect(modeOf(process.cwd())).not.toBe(0o700);
  });
});

/**
 * Second pass with `chmodSync` neutralized. This isolates the mode applied by
 * the `mkdirSync` syscall itself, so the fresh-boot case cannot be papered over
 * by the follow-up chmod. It fails on the pre-fix code, where the mkdir carried
 * no mode at all.
 */
describe.skipIf(process.platform === "win32")(
  "data directory creation mode (chmodSync neutralized)",
  () => {
    it("creates the directory 0700 at mkdir time, not via a follow-up chmod", async () => {
      vi.resetModules();
      vi.doMock("node:fs", async () => {
        const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
        return { ...actual, chmodSync: vi.fn(), default: { ...actual, chmodSync: vi.fn() } };
      });

      try {
        const { Store } = await import("../src/store/db.js");
        const dir = join(root, "nochmod");

        const store = new Store(join(dir, "onegate.db"));
        store.close();

        expect(modeOf(dir)).toBe(0o700);
      } finally {
        vi.doUnmock("node:fs");
        vi.resetModules();
      }
    });
  },
);
