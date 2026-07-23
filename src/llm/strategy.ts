/**
 * LLM routing strategy engine. Pure functions over persisted counters, the
 * proxy loads the (agent, vendor) state from the store, runs a selection,
 * and persists the returned state. Semantics follow the build spec exactly.
 *
 * The connections list passed in is the agent's enabled connections of the
 * vendor being called, in configured order. Callers guarantee it is
 * non-empty: with no connections there is nothing to route and the proxy
 * falls back to the legacy app-credential path.
 */

import type { LlmStrategy } from "../types.js";

/** The mutable subset of LlmStrategyState the engine operates on. */
export interface StrategyCounters {
  /** Fallback: index of the connection currently in use. */
  activeIndex: number;
  /** Round-robin: index of the most recently selected connection (-1 = none yet). */
  rrCursor: number;
  /** Fallback: calls served on a non-primary connection since the last switch. */
  callsSinceFallback: number;
  /** Round-robin: connectionId -> remaining skip count. */
  cooldowns: Record<string, number>;
}

export interface Selection {
  index: number;
  connectionId: string;
  /** Counters to persist for subsequent requests. */
  state: StrategyCounters;
}

export interface ErrorOutcome {
  /** Counters to persist for subsequent requests. */
  state: StrategyCounters;
  /**
   * Connection index the in-request failover retry should use, or null when
   * there is nothing sensible to retry (single connection, or fallback
   * already sitting on the last connection).
   */
  retryIndex: number | null;
}

/** How many calls a round-robin connection is skipped for after an error. */
export const COOLDOWN_CALLS = 10;

/** How many fallback calls are served off-primary before retrying the primary. */
export const FALLBACK_RETURN_CALLS = 10;

export function initialCounters(): StrategyCounters {
  return { activeIndex: 0, rrCursor: -1, callsSinceFallback: 0, cooldowns: {} };
}

/**
 * Picks the connection for the next request and returns the counters to
 * persist. Fallback serves connections[active_index] and, while off-primary,
 * counts calls so the 10th call flips active_index back to 0 for subsequent
 * requests. Round-robin decrements every cooldown once per call, then
 * advances the cursor to the next connection whose cooldown is spent,
 * ignoring cooldowns entirely when every connection is cooling (never
 * hard-stop).
 */
export function selectConnection(
  strategy: LlmStrategy,
  connectionIds: string[],
  state: StrategyCounters,
): Selection {
  const n = connectionIds.length;
  if (n === 0) throw new Error("selectConnection requires at least one connection");

  if (strategy === "fallback") {
    const index = Math.min(state.activeIndex, n - 1);
    let activeIndex = index;
    let calls = 0;
    if (index > 0) {
      calls = state.callsSinceFallback + 1;
      if (calls >= FALLBACK_RETURN_CALLS) {
        activeIndex = 0;
        calls = 0;
      }
    }
    return {
      index,
      connectionId: connectionIds[index],
      state: { ...state, activeIndex, callsSinceFallback: calls },
    };
  }

  // round-robin
  const cooldowns: Record<string, number> = {};
  for (const [id, left] of Object.entries(state.cooldowns)) {
    const next = left - 1;
    if (next > 0) cooldowns[id] = next;
  }
  const start = ((state.rrCursor + 1) % n + n) % n;
  let index = -1;
  for (let step = 0; step < n; step++) {
    const i = (start + step) % n;
    if ((cooldowns[connectionIds[i]] ?? 0) === 0) {
      index = i;
      break;
    }
  }
  // All connections cooling down: ignore cooldowns and take them in cursor
  // order anyway.
  if (index === -1) index = start;
  return {
    index,
    connectionId: connectionIds[index],
    state: { ...state, rrCursor: index, cooldowns },
  };
}

/**
 * Records an error on the connection at `erroredIndex` and returns the
 * counters to persist plus the index the in-request retry should use.
 * Fallback advances active_index by one (staying at the last connection when
 * exhausted) and resets the return counter. Round-robin puts the errored
 * connection on a 10-call cooldown and retries the next non-cooling
 * connection, ignoring cooldowns when everything is cooling.
 */
export function onSelectionError(
  strategy: LlmStrategy,
  connectionIds: string[],
  state: StrategyCounters,
  erroredIndex: number,
): ErrorOutcome {
  const n = connectionIds.length;
  if (n === 0) throw new Error("onSelectionError requires at least one connection");

  if (strategy === "fallback") {
    const next = Math.min(erroredIndex + 1, n - 1);
    return {
      state: { ...state, activeIndex: next, callsSinceFallback: 0 },
      retryIndex: next === erroredIndex ? null : next,
    };
  }

  // round-robin
  const cooldowns = { ...state.cooldowns, [connectionIds[erroredIndex]]: COOLDOWN_CALLS };
  let retryIndex: number | null = null;
  for (let step = 1; step < n; step++) {
    const i = (erroredIndex + step) % n;
    if ((cooldowns[connectionIds[i]] ?? 0) === 0) {
      retryIndex = i;
      break;
    }
  }
  if (retryIndex === null && n > 1) retryIndex = (erroredIndex + 1) % n;
  return {
    state: { ...state, rrCursor: retryIndex ?? state.rrCursor, cooldowns },
    retryIndex,
  };
}
