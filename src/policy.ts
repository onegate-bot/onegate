/**
 * Policy engine.
 *
 * A request is checked against the union of the agent's own rules and its
 * project's rules. Precedence, strongest first:
 *
 *   DENY  >  REQUIRE_APPROVAL  >  ALLOW  >  default policy
 *
 * Explicit DENY still short-circuits the scan and wins outright — that is
 * unchanged and deliberately unweakened. REQUIRE_APPROVAL sits BELOW deny and
 * ABOVE allow: it is a restriction layered on a capability, so a narrow gate
 * (`require_approval` on `/repos/*\/delete`) must bite even when a broad allow
 * (`/**`) also matches, otherwise the gate would be silently inert in the most
 * common real configuration. It can never manufacture access on its own: its
 * reported `effect` is always "deny".
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
  /**
   * The destination host (the CONNECT authority, without port), when known.
   * Only host-qualified globs (see parseHostQualifiedGlob) consult it; a
   * host-qualified rule never matches a request that carries no host.
   */
  host?: string;
}

export interface PolicyResult {
  effect: Effect;
  /** Rule that decided the outcome, null when the default policy applied. */
  ruleId: string | null;
  /**
   * True when the deciding rule carried the `require_approval` action: the call
   * is HELD for an owner decision rather than refused outright.
   *
   * `effect` is ALWAYS "deny" when this is set. That is deliberate: every
   * existing caller that branches on `effect` keeps blocking the request, and
   * only a caller that explicitly understands `requiresApproval` (the proxy)
   * turns it into a pending-approval response. A caller that ignores this flag
   * therefore fails CLOSED, never open.
   */
  requiresApproval?: boolean;
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

/**
 * Percent-decodes a string ONCE, treating any malformed escape (a `%` not
 * followed by two hex digits) as a literal. Never throws.
 *
 * `decodeURIComponent` throws on malformed input, so we scan manually and only
 * decode well-formed `%XX` triples. Exactly one decode pass is performed, so a
 * legitimately double-encoded segment (`%252F`) decodes to `%2F`, NOT `/` — the
 * agent's intended single decode is preserved and no extra semantics are
 * introduced.
 */
function decodeOnce(input: string): string {
  let out = "";
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ch === "%" && i + 2 < input.length) {
      const hex = input.slice(i + 1, i + 3);
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        out += String.fromCharCode(parseInt(hex, 16));
        i += 2;
        continue;
      }
    }
    out += ch;
  }
  return out;
}

/**
 * Collapses `.`/`..` dot-segments and repeated slashes in an absolute path.
 * A leading `..` can never escape above root (it is discarded). The result
 * always starts with `/`.
 */
function collapsePath(path: string): string {
  const leadingSlash = path.startsWith("/");
  const segments = path.split("/");
  const out: string[] = [];
  for (const seg of segments) {
    if (seg === "" || seg === ".") continue; // "" collapses repeated slashes
    if (seg === "..") {
      out.pop();
      continue;
    }
    out.push(seg);
  }
  // Preserve a single trailing slash if the input had one and there is content.
  const trailingSlash = path.length > 1 && path.endsWith("/");
  let result = (leadingSlash ? "/" : "") + out.join("/");
  if (trailingSlash && out.length > 0 && !result.endsWith("/")) result += "/";
  if (result === "") result = leadingSlash ? "/" : "";
  return result;
}

/**
 * Canonicalizes a request target so policy matching and upstream forwarding
 * both use one unambiguous path.
 *
 * The path portion (everything before the first `?`) is percent-decoded once
 * (malformation-safe), then its `.`/`..` dot-segments and duplicate slashes are
 * collapsed. The query string is preserved verbatim and re-attached — only the
 * path is normalized. This closes deny-glob evasion via equivalent-but-encoded
 * paths (`%2Frepos%2F...`, `//repos/...`, `/repos/x/../onegate-bot/...`) by
 * ensuring the matched request equals the request forwarded upstream.
 */
export function normalizeRequestPath(target: string): string {
  const qIdx = target.indexOf("?");
  const rawPath = qIdx === -1 ? target : target.slice(0, qIdx);
  const query = qIdx === -1 ? "" : target.slice(qIdx); // includes leading "?"
  const decoded = decodeOnce(rawPath);
  const canonical = collapsePath(decoded);
  return canonical + query;
}

/**
 * Compiled-glob cache. The key MUST carry the case mode as well as the glob
 * text: the same glob compiles to two different regexes (with and without the
 * `i` flag), and keying on the glob alone would serve whichever variant was
 * compiled first to both callers.
 */
const globCache = new Map<string, RegExp>();

/**
 * Converts a path glob to a regex. `**` matches anything including `/`,
 * `*` matches anything except `/`. Matching is anchored.
 *
 * A trailing `/**` is special-cased so that `/x/**` matches both the bare
 * prefix `/x` and any sub-path `/x/...` (regex `^/x(/.*)?$`). This lets a
 * single rule cover a resource and everything beneath it. `**` anywhere else
 * (including a mid-path `/**`) keeps the plain "matches anything" behavior.
 *
 * `caseInsensitive` adds the `i` flag. It is used ONLY for deny rules — see the
 * asymmetry note on ruleMatches.
 */
export function globToRegExp(glob: string, caseInsensitive = false): RegExp {
  const cacheKey = caseInsensitive ? `i:${glob}` : `s:${glob}`;
  let re = globCache.get(cacheKey);
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
  re = new RegExp(`^${escaped}$`, caseInsensitive ? "i" : "");
  globCache.set(cacheKey, re);
  return re;
}

/**
 * Host-qualified globs.
 *
 * A rule's `pathGlob` normally starts with `/` and is matched against the
 * request path only. A pathGlob that does NOT start with `/` and whose first
 * segment (everything before the first `/`) looks like a DNS name with at least
 * two labels is HOST-QUALIFIED:
 *
 *     <hostGlob>[/<pathGlob>]
 *
 *   `http-intake.logs.us5.datadoghq.com/**`  that host, every path
 *   `*.datadoghq.com`                         any ONE label under datadoghq.com
 *   `**.datadoghq.com/**`                     datadoghq.com and every subdomain
 *   `api.example.com/v1/admin/**`             that host, only under /v1/admin
 *
 * Host part, matched label by label against the lowercased host (a single
 * trailing dot on the host is ignored, so `example.com.` cannot dodge a rule):
 *   - case-insensitive, always (DNS names are case-insensitive);
 *   - a label `*` matches exactly one label; `*` inside a label
 *     (`api-*.example.com`) matches any run of characters within that label;
 *   - a label `**` matches ZERO or more labels, so `**.example.com` also matches
 *     the apex `example.com` (mirrors the path rule that `/x/**` matches `/x`);
 *   - it must contain at least one literal label (no wildcard), so a catch-all
 *     like `*.*` or `**.**` is rejected rather than silently matching the world.
 *
 * Path part: an absent path part means `/**`. When present it is an ordinary
 * path glob (with the leading `/` restored) and keeps the exact path semantics,
 * including the deny-case-insensitive / allow-case-sensitive asymmetry.
 *
 * Backward compatibility: a legacy pathGlob without a leading `/` and without a
 * dot in its first segment (e.g. `**`) is NOT host-qualified and keeps its old
 * regex behaviour, so no stored rule changes meaning. New rules can no longer
 * be created that way (see validatePathGlob).
 */
export interface HostQualifiedGlob {
  hostGlob: string;
  pathGlob: string;
}

const HOST_GLOB_LABEL = /^(\*\*|[a-z0-9*-]+)$/;

/**
 * Parses a host-qualified glob, or returns null when `glob` is a plain path glob
 * (starts with `/`) or is not a well-formed host-qualified glob.
 */
export function parseHostQualifiedGlob(glob: string): HostQualifiedGlob | null {
  if (glob.startsWith("/")) return null;
  const slash = glob.indexOf("/");
  const hostGlob = (slash === -1 ? glob : glob.slice(0, slash)).toLowerCase();
  const pathGlob = slash === -1 ? "/**" : glob.slice(slash);
  const labels = hostGlob.split(".");
  if (labels.length < 2) return null;
  if (!labels.every((l) => HOST_GLOB_LABEL.test(l))) return null;
  // `**` must be a whole label (rejects `a**b`), and at least one label must be
  // literal so the host part always pins something.
  if (labels.some((l) => l !== "**" && l.includes("**"))) return null;
  if (!labels.some((l) => !l.includes("*"))) return null;
  return { hostGlob, pathGlob };
}

/** True when `glob` is a valid host-qualified glob. */
export function isHostQualifiedGlob(glob: string): boolean {
  return parseHostQualifiedGlob(glob) !== null;
}

/** Thrown by validatePathGlob for a glob that can never be what was meant. */
export class InvalidPathGlobError extends Error {}

/**
 * Validates a pathGlob at rule-creation time. Accepted: a path glob starting
 * with `/`, or a valid host-qualified glob. Anything else (`**`, `api/v1/**`,
 * `*.*`, `bad_host.com/**`) is rejected: it would either match nothing or not
 * mean what it reads as, and a silently inert deny rule is the failure mode
 * this guards against.
 */
export function validatePathGlob(glob: string): void {
  if (glob.startsWith("/")) return;
  if (isHostQualifiedGlob(glob)) return;
  throw new InvalidPathGlobError(
    `invalid path glob "${glob}": use a path starting with "/" (e.g. "/v1/**"), or a host-qualified glob ` +
      `"<host>[/<path>]" (e.g. "api.example.com/**", "*.example.com", "**.example.com/v1/**"); ` +
      `host labels may be "*" (one label) or "**" (any number of labels) and at least one label must be literal`,
  );
}

/** Lowercases a host and drops a single trailing root dot. */
function canonicalHost(host: string): string {
  const h = host.toLowerCase();
  return h.endsWith(".") ? h.slice(0, -1) : h;
}

const labelCache = new Map<string, RegExp>();
function labelMatches(pattern: string, label: string): boolean {
  if (pattern === "*") return label.length > 0;
  if (!pattern.includes("*")) return pattern === label;
  let re = labelCache.get(pattern);
  if (!re) {
    // Labels are validated to [a-z0-9*-], so `*` should be the only
    // regex-significant character. Escape everything else anyway so a pattern
    // that ever reaches here unvalidated can only match literally.
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^.]*");
    re = new RegExp(`^${escaped}$`);
    labelCache.set(pattern, re);
  }
  return re.test(label);
}

/**
 * Matches a host against the host part of a host-qualified glob (see
 * parseHostQualifiedGlob for the semantics). Always case-insensitive.
 */
export function hostGlobMatches(hostGlob: string, host: string): boolean {
  const pat = hostGlob.toLowerCase().split(".");
  const labels = canonicalHost(host).split(".");
  // Memoised (pattern index, label index) walk; `**` is the only branching
  // label, so this is O(pat * labels) at worst.
  const memo = new Map<number, boolean>();
  const walk = (i: number, j: number): boolean => {
    const key = i * (labels.length + 1) + j;
    const hit = memo.get(key);
    if (hit !== undefined) return hit;
    let ok: boolean;
    if (i === pat.length) ok = j === labels.length;
    else if (pat[i] === "**") ok = walk(i + 1, j) || (j < labels.length && walk(i, j + 1));
    else ok = j < labels.length && labelMatches(pat[i], labels[j]) && walk(i + 1, j + 1);
    memo.set(key, ok);
    return ok;
  };
  return walk(0, 0);
}

/**
 * Passthrough (opaque tunnel) enforcement: returns the first live DENY rule
 * whose host-qualified glob's HOST part matches `host`, or null.
 *
 * A passthrough is a raw byte pipe, so neither the method nor the path is ever
 * visible. The rule's method list and path part are therefore IGNORED here and
 * a matching deny blocks the whole host (fail-closed): a deny on
 * `api.example.com/v1/admin/**` refuses every tunnel to api.example.com. The
 * integration id is ignored too, for the same reason: a passthrough host is by
 * definition not owned by an integration, and the host in the glob names the
 * destination explicitly. A require_approval rule (persisted as effect "deny")
 * cannot be held on an opaque tunnel, so it blocks as well.
 *
 * Connection-scoped rules never apply (a passthrough has no app connection),
 * lapsed rules are skipped, and ALLOW rules are not consulted: passthrough
 * stays default-open, exactly as before.
 */
export function passthroughDenyRule(rules: Rule[], host: string, nowMs: number = Date.now()): Rule | null {
  for (const rule of rules) {
    if (rule.effect !== "deny") continue;
    if (rule.connectionScope) continue;
    if (ruleLapsed(rule, nowMs)) continue;
    const hq = parseHostQualifiedGlob(rule.pathGlob);
    if (!hq) continue;
    if (hostGlobMatches(hq.hostGlob, host)) return rule;
  }
  return null;
}

export function ruleMatches(rule: Rule, req: PolicyRequest): boolean {
  if (rule.integrationId !== "*" && rule.integrationId !== req.integrationId) return false;
  if (!rule.methods.includes("*") && !rule.methods.includes(req.method.toUpperCase())) return false;
  // `req.path` is REQUIRED to be already canonical: callers must pass the exact
  // path the proxy will forward upstream (see normalizeRequestPath, applied once
  // at the proxy edge). Only the query string is stripped here.
  //
  // Do NOT re-normalize. normalizeRequestPath is deliberately NOT idempotent:
  // decodeOnce peels exactly one percent-decode layer per call, so a second pass
  // decodes a further layer that the proxy never applied and never forwards. A
  // double-encoded traversal (`/repos/a/b/%252e%252e/x`) forwards upstream as
  // `/repos/a/b/%2e%2e/x` but would match here as `/repos/a/x`, escaping a deny
  // glob pinned to `/repos/a/b/**` while the vendor still serves the pinned repo.
  // Matching the forwarded path verbatim is what keeps that invariant true.
  const path = req.path.split("?")[0];
  // Case sensitivity is ASYMMETRIC by effect, and deliberately so. Do not
  // "simplify" this into one mode for both.
  //
  // Several vendors resolve significant path segments case-insensitively:
  // GitHub serves /repos/OWNER/REPO under any casing of owner and repo. The
  // proxy forwards the path exactly as matched, so with byte-case-sensitive
  // matching a DENY (or a connection-scoped deny-except pin) written as
  // `/repos/onegate-bot/onegate/**` simply does not fire on
  // `/repos/OneGate-Bot/onegate/...`. That falls through to the agent's broad
  // allow rule, is forwarded upstream, and the vendor serves the very resource
  // the deny was meant to fence off -- audited as an ordinary allow, so the
  // evasion is near-invisible after the fact.
  //
  // Matching DENY case-insensitively closes that. It can only ever REFUSE more
  // requests, so widening it is fail-safe.
  //
  // ALLOW stays case-sensitive. Other vendors have genuinely case-SENSITIVE
  // path segments (S3 object keys, Drive file ids, base64 identifiers), where
  // an allow of `/files/AbC` matching `/files/abc` would grant access to a
  // DIFFERENT object. Widening an allow is fail-OPEN, so it is not done.
  //
  // A host-qualified glob (`<host>[/<path>]`, see parseHostQualifiedGlob)
  // matches only when the request carries a host and that host matches; the
  // path part then follows exactly the same rules as a plain path glob.
  let pathGlob = rule.pathGlob;
  const hq = parseHostQualifiedGlob(pathGlob);
  if (hq) {
    if (req.host === undefined || !hostGlobMatches(hq.hostGlob, req.host)) return false;
    pathGlob = hq.pathGlob;
  }
  return globToRegExp(pathGlob, rule.effect === "deny").test(path);
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
  let approval: Rule | null = null;
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
    if (rule.action === "require_approval") {
      // Held for owner decision. Recorded and the scan CONTINUES, because a
      // later explicit deny must still short-circuit and win outright. Not
      // returned here, so ordering within the rule list never lets an approval
      // gate pre-empt a deny.
      //
      // Such a rule is persisted with effect = "deny" (see RuleAction), so if
      // this branch were ever removed or the action column were lost, the rule
      // degrades to a plain deny below. It cannot degrade to an allow.
      if (!approval) approval = rule;
      continue;
    }
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
  // REQUIRE_APPROVAL outranks ALLOW. No explicit deny matched (that would have
  // returned already), so this is the strongest surviving verdict. `effect` is
  // "deny": the call is refused NOW and only a caller that understands
  // `requiresApproval` may offer the owner a decision.
  if (approval)
    return {
      effect: "deny",
      ruleId: approval.id,
      requiresApproval: true,
      ...(needsConnection ? { needsConnection: true } : {}),
    };
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
