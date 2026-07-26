/**
 * Unit tests for the admin UI router's render generation guard.
 *
 * The admin UI ships as plain browser JS exercised by the separate ui-smoke
 * job, so app.js itself is not loadable here. The guard logic it depends on
 * lives in its own module (src/admin/ui/render-generation.js) precisely so the
 * race it prevents can be pinned down by a real automated test.
 *
 * The race: every renderer awaits network calls before writing root.innerHTML.
 * If the user navigates while a render is in flight, two renders run
 * concurrently and whichever finishes LAST wins the final write. The slowest
 * renderer (connections) then paints masked secret previews, grant chips and
 * destructive controls (Disconnect, Set default) under an unrelated heading.
 */

import { describe, it, expect, beforeEach } from "vitest";
// @ts-expect-error - plain browser JS module, no type declarations by design.
import {
  beginGeneration,
  currentGeneration,
  isCurrentGeneration,
  resetGeneration,
} from "../src/admin/ui/render-generation.js";

beforeEach(() => {
  resetGeneration();
});

describe("render generation counter", () => {
  it("starts at zero and increments monotonically per navigation", () => {
    expect(currentGeneration()).toBe(0);
    expect(beginGeneration()).toBe(1);
    expect(beginGeneration()).toBe(2);
    expect(beginGeneration()).toBe(3);
    expect(currentGeneration()).toBe(3);
  });

  it("treats only the newest token as current", () => {
    const first = beginGeneration();
    expect(isCurrentGeneration(first)).toBe(true);

    const second = beginGeneration();
    expect(isCurrentGeneration(second)).toBe(true);
    expect(isCurrentGeneration(first)).toBe(false);
  });

  it("never reports a stale token as current again once superseded", () => {
    const stale = beginGeneration();
    beginGeneration();
    beginGeneration();
    expect(isCurrentGeneration(stale)).toBe(false);
  });
});

describe("concurrent render race", () => {
  // Minimal stand-in for app.js: a root whose innerHTML is the last write to
  // win, and renderers that await before writing (as every real one does).
  const makeRoot = () => ({ innerHTML: "" });

  /** A renderer WITHOUT the guard: the shape of the code before the fix. */
  async function renderUnguarded(root: { innerHTML: string }, delayMs: number, html: string) {
    await new Promise((r) => setTimeout(r, delayMs));
    root.innerHTML = html;
  }

  /** A renderer WITH the guard: captures at entry, checks before writing. */
  async function renderGuarded(root: { innerHTML: string }, delayMs: number, html: string) {
    const gen = currentGeneration();
    await new Promise((r) => setTimeout(r, delayMs));
    if (!isCurrentGeneration(gen)) return;
    root.innerHTML = html;
  }

  it("without a guard, the slow stale render overwrites the current view", async () => {
    const root = makeRoot();

    // Navigate to connections (slow), then immediately away to audit (fast).
    beginGeneration();
    const slow = renderUnguarded(root, 40, "CONNECTIONS: Disconnect / Set default");
    beginGeneration();
    const fast = renderUnguarded(root, 5, "AUDIT");
    await Promise.all([slow, fast]);

    // The stale connections markup wins. This is the defect.
    expect(root.innerHTML).toBe("CONNECTIONS: Disconnect / Set default");
  });

  it("with the guard, the stale render abandons its write and the current view stands", async () => {
    const root = makeRoot();

    beginGeneration();
    const slow = renderGuarded(root, 40, "CONNECTIONS: Disconnect / Set default");
    beginGeneration();
    const fast = renderGuarded(root, 5, "AUDIT");
    await Promise.all([slow, fast]);

    expect(root.innerHTML).toBe("AUDIT");
    expect(root.innerHTML).not.toContain("Disconnect");
  });

  it("lets a render that was never superseded write normally", async () => {
    const root = makeRoot();
    beginGeneration();
    await renderGuarded(root, 5, "CONNECTIONS");
    expect(root.innerHTML).toBe("CONNECTIONS");
  });

  it("survives rapid navigation: only the final view is painted", async () => {
    const root = makeRoot();
    const views = ["dashboard", "agents", "connections", "rules", "audit"];

    // Each navigation starts a render; earlier ones are slower on purpose so
    // they would all land after the last one without the guard.
    const pending = views.map((view, i) => {
      beginGeneration();
      return renderGuarded(root, (views.length - i) * 10, view);
    });
    await Promise.all(pending);

    expect(root.innerHTML).toBe("audit");
  });

  it("guards a post-await write into a sub-element too (audit/usage inner load)", async () => {
    // renderAudit and renderUsage keep loading after the initial paint and
    // write into #audit-table / #usage-body. Those writes need the same guard.
    const table = { innerHTML: "" };

    const gen = beginGeneration();
    const stale = (async () => {
      await new Promise((r) => setTimeout(r, 30));
      if (!isCurrentGeneration(gen)) return;
      table.innerHTML = "STALE ROWS";
    })();

    beginGeneration(); // user navigates away
    await stale;

    expect(table.innerHTML).toBe("");
  });
});
