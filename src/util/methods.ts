/**
 * Canonicalization for a rule's HTTP methods.
 *
 * `ruleMatches` (src/policy.ts) compares a rule's methods against
 * `req.method.toUpperCase()`, so anything that is not a canonical uppercase
 * verb can never match. Persisting such a value is worse than an error: a DENY
 * rule stored that way is silently inert (it reads back looking configured but
 * blocks nothing) and an ALLOW rule silently never fires. Both write paths
 * (admin API and CLI) funnel through here so an unmatchable value cannot be
 * stored in the first place.
 */

/** The wildcard accepted alongside the standard verbs. */
export const METHOD_WILDCARD = "*";

/**
 * Verbs the proxy can actually observe on a request. CONNECT is included
 * because OneGate terminates CONNECT for its MITM tunnel.
 */
export const ALLOWED_METHODS = [
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
  "TRACE",
  "CONNECT",
] as const;

const ALLOWED = new Set<string>(ALLOWED_METHODS);

/** Thrown when a caller supplies a method that could never match a request. */
export class InvalidMethodError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidMethodError";
  }
}

/**
 * Normalizes a rule's methods to the canonical form the matcher expects:
 * trimmed, uppercased, de-duplicated, empties dropped. An absent or
 * effectively-empty list defaults to the wildcard, matching the previous
 * default. Throws `InvalidMethodError` for a non-array, a non-string entry, or
 * a verb outside {@link ALLOWED_METHODS} / the wildcard.
 */
export function normalizeMethods(methods: string[] | undefined | null): string[] {
  if (methods == null) return [METHOD_WILDCARD];
  if (!Array.isArray(methods)) {
    throw new InvalidMethodError("methods must be an array of HTTP method names");
  }

  const out: string[] = [];
  for (const raw of methods) {
    if (typeof raw !== "string") {
      throw new InvalidMethodError(
        `methods must be strings, received ${raw === null ? "null" : typeof raw}`,
      );
    }
    const m = raw.trim().toUpperCase();
    // Blank entries are padding (e.g. a trailing comma in `--methods GET,`),
    // not an attempt to express a verb, so they are dropped rather than
    // rejected.
    if (m === "") continue;
    if (m !== METHOD_WILDCARD && !ALLOWED.has(m)) {
      throw new InvalidMethodError(
        `unsupported HTTP method "${raw}" (expected one of ${ALLOWED_METHODS.join(", ")}, or "*")`,
      );
    }
    if (!out.includes(m)) out.push(m);
  }

  return out.length ? out : [METHOD_WILDCARD];
}
