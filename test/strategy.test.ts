import { describe, it, expect } from "vitest";
import {
  initialCounters,
  selectConnection,
  onSelectionError,
  COOLDOWN_CALLS,
  FALLBACK_RETURN_CALLS,
  type StrategyCounters,
} from "../src/llm/strategy.js";

const IDS = ["conn_a", "conn_b", "conn_c"];

describe("fallback strategy", () => {
  it("selects the primary while healthy and keeps the counter at zero", () => {
    let state: StrategyCounters = initialCounters();
    for (let i = 0; i < 25; i++) {
      const sel = selectConnection("fallback", IDS, state);
      expect(sel.index).toBe(0);
      expect(sel.connectionId).toBe("conn_a");
      state = sel.state;
      expect(state.callsSinceFallback).toBe(0);
    }
  });

  it("advances on error and retries the new active connection in-request", () => {
    const out = onSelectionError("fallback", IDS, initialCounters(), 0);
    expect(out.state.activeIndex).toBe(1);
    expect(out.state.callsSinceFallback).toBe(0);
    expect(out.retryIndex).toBe(1);
    const next = selectConnection("fallback", IDS, out.state);
    expect(next.index).toBe(1);
  });

  it("stays at the last connection when exhausted, with no in-request retry", () => {
    const atLast: StrategyCounters = { ...initialCounters(), activeIndex: 2 };
    const out = onSelectionError("fallback", IDS, atLast, 2);
    expect(out.state.activeIndex).toBe(2);
    expect(out.retryIndex).toBeNull();
  });

  it("has no retry for a single connection", () => {
    const out = onSelectionError("fallback", ["conn_only"], initialCounters(), 0);
    expect(out.state.activeIndex).toBe(0);
    expect(out.retryIndex).toBeNull();
  });

  it("returns to the primary after 10 calls on a fallback connection", () => {
    let state: StrategyCounters = onSelectionError("fallback", IDS, initialCounters(), 0).state;
    // Calls 1..10 are served by the fallback connection (index 1).
    for (let call = 1; call <= FALLBACK_RETURN_CALLS; call++) {
      const sel = selectConnection("fallback", IDS, state);
      expect(sel.index).toBe(1);
      state = sel.state;
    }
    // The 10th call flipped the persisted index back to the primary.
    expect(state.activeIndex).toBe(0);
    expect(state.callsSinceFallback).toBe(0);
    const sel = selectConnection("fallback", IDS, state);
    expect(sel.index).toBe(0);
  });

  it("re-fails over and restarts the 10-call counter when the primary is still bad", () => {
    let state: StrategyCounters = onSelectionError("fallback", IDS, initialCounters(), 0).state;
    for (let call = 1; call <= FALLBACK_RETURN_CALLS; call++) {
      state = selectConnection("fallback", IDS, state).state;
    }
    // Back at the primary, which errors again: advance to index 1, counter reset.
    const out = onSelectionError("fallback", IDS, state, 0);
    expect(out.state.activeIndex).toBe(1);
    expect(out.state.callsSinceFallback).toBe(0);
    expect(out.retryIndex).toBe(1);
  });

  it("a second error during one request advances further down the order", () => {
    const first = onSelectionError("fallback", IDS, initialCounters(), 0);
    expect(first.retryIndex).toBe(1);
    const second = onSelectionError("fallback", IDS, first.state, 1);
    expect(second.state.activeIndex).toBe(2);
    expect(second.retryIndex).toBe(2);
    const third = onSelectionError("fallback", IDS, second.state, 2);
    expect(third.retryIndex).toBeNull();
  });

  it("clamps a stale active index after connections were removed", () => {
    const stale: StrategyCounters = { ...initialCounters(), activeIndex: 5 };
    const sel = selectConnection("fallback", ["conn_a", "conn_b"], stale);
    expect(sel.index).toBe(1);
  });
});

describe("round-robin strategy", () => {
  it("cycles through connections in order", () => {
    let state: StrategyCounters = initialCounters();
    const picks: number[] = [];
    for (let i = 0; i < 7; i++) {
      const sel = selectConnection("round-robin", IDS, state);
      picks.push(sel.index);
      state = sel.state;
    }
    expect(picks).toEqual([0, 1, 2, 0, 1, 2, 0]);
  });

  it("puts an errored connection on cooldown and retries the next one", () => {
    const sel = selectConnection("round-robin", IDS, initialCounters());
    expect(sel.index).toBe(0);
    const out = onSelectionError("round-robin", IDS, sel.state, 0);
    expect(out.state.cooldowns.conn_a).toBe(COOLDOWN_CALLS);
    expect(out.retryIndex).toBe(1);
    expect(out.state.rrCursor).toBe(1);
  });

  it("skips a cooled connection for about 10 calls", () => {
    let state: StrategyCounters = onSelectionError(
      "round-robin",
      IDS,
      selectConnection("round-robin", IDS, initialCounters()).state,
      0,
    ).state;
    // conn_a is cooling: only b and c are served while the cooldown drains
    // (one decrement per call, so it rejoins on the 10th call).
    const picks: string[] = [];
    for (let i = 0; i < COOLDOWN_CALLS - 1; i++) {
      const sel = selectConnection("round-robin", IDS, state);
      picks.push(sel.connectionId);
      state = sel.state;
    }
    expect(picks).not.toContain("conn_a");
    // Cooldown spent: conn_a rejoins the rotation.
    let sawA = false;
    for (let i = 0; i < IDS.length; i++) {
      const sel = selectConnection("round-robin", IDS, state);
      if (sel.connectionId === "conn_a") sawA = true;
      state = sel.state;
    }
    expect(sawA).toBe(true);
  });

  it("ignores cooldowns when every connection is cooling (never hard-stop)", () => {
    let state: StrategyCounters = initialCounters();
    for (let i = 0; i < IDS.length; i++) {
      const sel = selectConnection("round-robin", IDS, state);
      state = onSelectionError("round-robin", IDS, sel.state, sel.index).state;
    }
    expect(Object.keys(state.cooldowns).sort()).toEqual([...IDS].sort());
    // All cooled: selection still proceeds, one by one in cursor order.
    const first = selectConnection("round-robin", IDS, state);
    const second = selectConnection("round-robin", IDS, first.state);
    expect(first.index).not.toBe(second.index);
  });

  it("the in-request retry skips cooled connections too", () => {
    // conn_b already cooling, conn_a errors: retry must land on conn_c.
    const state: StrategyCounters = { ...initialCounters(), cooldowns: { conn_b: 5 } };
    const sel = selectConnection("round-robin", IDS, state);
    expect(sel.index).toBe(0);
    const out = onSelectionError("round-robin", IDS, sel.state, 0);
    expect(out.retryIndex).toBe(2);
  });

  it("retries the next connection even when everything is cooling", () => {
    const state: StrategyCounters = {
      ...initialCounters(),
      cooldowns: { conn_a: 9, conn_b: 9, conn_c: 9 },
    };
    const out = onSelectionError("round-robin", IDS, state, 1);
    expect(out.retryIndex).toBe(2);
  });

  it("has no retry for a single connection", () => {
    const out = onSelectionError("round-robin", ["conn_only"], initialCounters(), 0);
    expect(out.retryIndex).toBeNull();
    expect(out.state.cooldowns.conn_only).toBe(COOLDOWN_CALLS);
  });

  it("drops fully drained cooldowns from the state", () => {
    let state: StrategyCounters = { ...initialCounters(), cooldowns: { conn_a: 1 } };
    state = selectConnection("round-robin", IDS, state).state;
    expect(state.cooldowns.conn_a).toBeUndefined();
  });
});

describe("engine guards", () => {
  it("rejects empty connection lists", () => {
    expect(() => selectConnection("fallback", [], initialCounters())).toThrow(/at least one/);
    expect(() => onSelectionError("round-robin", [], initialCounters(), 0)).toThrow(/at least one/);
  });
});
