/**
 * Policy engine.
 *
 * A request is checked against the union of the agent's own rules and its
 * project's rules. Explicit DENY beats explicit ALLOW, which beats the
 * agent's default policy (`allow-all` or `deny-unmatched`).
 */

import type { Agent, Effect, Rule } from "./types.js";

export interface PolicyRequest {
  integrationId: string;
  method: string;
  path: string;
  /**
   * The app connection this request resolved to, when known. Three states:
   *   - `undefined`: the connection has not been resolved yet (phase-1 eval,
   *     before the proxy picks a connection). Connection-scoped rules are held
   *     pending and reported via PolicyResult.needsConnection.
   *   - `null`: resolved, but the request uses no named app connection (the
   *     legacy single-credential path).
   *   - a string: the resolved connection id.
   */
  connectionId?: string | null;
}

export interface PolicyResult {
  effect: Effect;
  /** Rule that decided the outcome, null when the default policy applied. */
  ruleId: string | null;
  /**
   * True when the ONLY allow rule that matched had an access lease that has
   * expired. The effect is "deny" (ruleId null, a default-deny), but the proxy
   * uses this to send the owner a one-tap RENEWAL prompt instead of a fresh
   * connect prompt. Set only when no live allow rule and no explicit deny won.
   */
  lapsed?: boolean;
  /** The lapsed allow rule's id, for minting a renewal link + dedup. */
  lapsedRuleId?: string | null;
  /** The lapsed rule's expiry timestamp, part of the renewal dedup key. */
  lapsedExpiresAt?: string | null;
  /**
   * True when at least one connection-scoped rule matched this request's
   * integration/method/path but could not be decided because the connection was
   * not yet resolved (`req.connectionId === undefined`). The proxy uses this as
   * a signal to re-evaluate once the connection is known (phase 2). False/absent
   * means the verdict is final regardless of connection.
   */
  needsConnection?: boolean;
}

const globCache = new Map<string, RegExp>();

/**
 * Converts a path glob to a regex. `**` matches anything including `/`,
 * `*` matches anything except `/`. Matching is anchored.
 *
 * A trailing `/**` is special-cased so that `/x/**` matches both the bare
 * prefix `/x` and any sub-path `/x/...` (regex `^/x(/.*)?$`). This lets a
 * single rule cover a resource and everything beneath it. `**` anywhere else
 * (including a mid-path `/**`) keeps the plain "matches anything" behavior.
 */
export function globToRegExp(glob: string): RegExp {
  let re = globCache.get(glob);
  if (re) return re;
  // Detect a trailing `/**` on an otherwise glob-free prefix segment so we can
  // make the trailing `/...` optional (covers the bare prefix too).
  const trailing = glob.endsWith("/**");
  const base = trailing ? glob.slice(0, -3) : glob;
  const escapedBase = base
    .replace(/[.+^${}()|[\]\\?]/g, "\\$&")
    .replace(/\*\*/g, "\0")
    .replace(/\*/g, "[^/]*")
    .replace(/\0/g, ".*");
  const escaped = trailing ? `${escapedBase}(/.*)?` : escapedBase;
  re = new RegExp(`^${escaped}$`);
  globCache.set(glob, re);
  return re;
}

export function ruleMatches(rule: Rule, req: PolicyRequest): boolean {
  if (rule.integrationId !== "*" && rule.integrationId !== req.integrationId) return false;
  if (!rule.methods.includes("*") && !rule.methods.includes(req.method.toUpperCase())) return false;
  const path = req.path.split("?")[0];
  return globToRegExp(rule.pathGlob).test(path);
}

/**
 * Whether a rule's connection scope lets it participate in this request:
 *   - "applies": the rule participates (either not connection-scoped, or its
 *     connection condition is satisfied).
 *   - "excluded": the rule is connection-scoped and the condition is not met, so
 *     it drops out of the decision.
 *   - "pending": the rule is connection-scoped but the connection is not yet
 *     resolved, so it cannot be decided in this pass.
 */
export type ConnectionMatch = "applies" | "excluded" | "pending";

/**
 * Feature flag: whether connection-scoped rules are enforced at all.
 *
 * OFF by default. When off, a connection-scoped rule is completely INERT (it
 * neither allows nor denies, and never triggers the phase-2 re-eval), so the
 * code and any connection-scoped rules can be deployed with zero behavioural
 * change and switched on deliberately later. Enable by setting env
 * `ONEGATE_CONNECTION_SCOPED_RULES` to `1` or `true` and restarting.
 */
export function connectionScopingEnabled(): boolean {
  const v = process.env.ONEGATE_CONNECTION_SCOPED_RULES;
  return v === "1" || v === "true";
}

export function ruleConnectionMatch(
  rule: Rule,
  req: PolicyRequest,
  enabled: boolean = connectionScopingEnabled(),
): ConnectionMatch {
  if (!rule.connectionScope) return "applies";
  // Flag off: the connection scope is ignored and the rule sits out the
  // decision entirely. (It must NOT fall through as a plain rule, or a
  // DENY-except would become a DENY-all.)
  if (!enabled) return "excluded";
  if (req.connectionId === undefined) return "pending";
  const isTarget = req.connectionId != null && req.connectionId === rule.connectionId;
  const applies = rule.connectionScope === "only" ? isTarget : !isTarget;
  return applies ? "applies" : "excluded";
}

/** An allow rule is lapsed when it carries a lease that has already expired. */
export function ruleLapsed(rule: Rule, nowMs: number): boolean {
  if (!rule.expiresAt) return false;
  const t = Date.parse(rule.expiresAt);
  return !Number.isNaN(t) && t <= nowMs;
}

export function evaluate(
  agent: Agent,
  rules: Rule[],
  req: PolicyRequest,
  nowMs: number = Date.now(),
  opts: { connectionScoping?: boolean } = {},
): PolicyResult {
  const scoping = opts.connectionScoping ?? connectionScopingEnabled();
  let allowed: Rule | null = null;
  let lapsed: Rule | null = null;
  let needsConnection = false;
  for (const rule of rules) {
    if (!ruleMatches(rule, req)) continue;
    const cm = ruleConnectionMatch(rule, req, scoping);
    if (cm === "pending") {
      // A connection-scoped rule matched the path but the connection is not yet
      // known. Flag it so the proxy re-evaluates after resolution, and skip it
      // for now (an unresolved connection-scoped rule neither allows nor denies).
      needsConnection = true;
      continue;
    }
    if (cm === "excluded") continue;
    if (rule.effect === "deny")
      return { effect: "deny", ruleId: rule.id, ...(needsConnection ? { needsConnection: true } : {}) };
    if (ruleLapsed(rule, nowMs)) {
      // Remember the most recently-expiring lapsed rule so the owner is asked
      // to renew, but keep scanning: a still-live allow rule wins over a lapse.
      if (!lapsed || Date.parse(rule.expiresAt as string) > Date.parse(lapsed.expiresAt as string)) {
        lapsed = rule;
      }
      continue;
    }
    if (!allowed) allowed = rule;
  }
  if (allowed)
    return { effect: "allow", ruleId: allowed.id, ...(needsConnection ? { needsConnection: true } : {}) };
  // A lapsed lease only bites when the default would deny anyway: an allow-all
  // agent still passes (its access never depended on the leased rule).
  if (lapsed && agent.defaultPolicy !== "allow-all") {
    return {
      effect: "deny",
      ruleId: null,
      lapsed: true,
      lapsedRuleId: lapsed.id,
      lapsedExpiresAt: lapsed.expiresAt ?? null,
      ...(needsConnection ? { needsConnection: true } : {}),
    };
  }
  return {
    effect: agent.defaultPolicy === "allow-all" ? "allow" : "deny",
    ruleId: null,
    ...(needsConnection ? { needsConnection: true } : {}),
  };
}
