/**
 * Render generation guard for the admin UI router.
 *
 * Every renderer in app.js awaits network calls before writing root.innerHTML.
 * Without a guard, navigating away mid-render lets the slower (stale) render
 * finish last and paint its markup under the newer view's heading. That is how
 * connection rows, masked secret previews and destructive controls (Disconnect,
 * Set default) can end up on a page the user never navigated to.
 *
 * The router bumps the generation on every navigation. A renderer captures the
 * generation it started under and checks it before each DOM write; if the
 * generation has moved on, the render abandons its write.
 *
 * Kept as its own module so the logic is unit-testable: app.js as a whole is
 * browser code exercised by the separate ui-smoke job, not by vitest.
 */

/** Monotonic counter, bumped once per navigation. */
let generation = 0;

/** Start a new navigation. Returns the token renders started now must carry. */
export function beginGeneration() {
  generation += 1;
  return generation;
}

/** The generation currently being rendered. */
export function currentGeneration() {
  return generation;
}

/**
 * True when `token` is still the live generation, i.e. the caller's render has
 * not been superseded by a later navigation and may write to the DOM.
 */
export function isCurrentGeneration(token) {
  return token === generation;
}

/** Test-only: reset the counter so cases do not leak into each other. */
export function resetGeneration() {
  generation = 0;
}
