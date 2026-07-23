/**
 * Derives a three-state LLM-mode badge from existing agent data:
 *
 * - "managed": OneGate injects a managed connection key with failover and
 *   usage accounting. (route enabled, connections attached, at least one
 *   connection vendor permitted by the agent's rules/policy)
 * - "passthrough": the agent uses its own key and OneGate forwards without
 *   injecting. (no connections attached, whether or not the route is on)
 * - "blocked": the LLM will not work through OneGate. Either the route is off
 *   while connections are attached (the request falls through to a 502
 *   onegate_no_credential), or the route is on but policy denies every
 *   connection vendor.
 *
 * This is a pure derivation from already-stored data, never a new setting.
 */

export type LlmMode = "managed" | "passthrough" | "blocked";

/** A rule shape sufficient to evaluate vendor allow/deny. */
export interface ModeRule {
  integrationId: string;
  effect: "allow" | "deny";
}

export interface DeriveLlmModeInput {
  /** Whether the per-agent LLM route is enabled. */
  enabled: boolean;
  /** Vendor of each connection attached to the route (llm connections only). */
  connectionVendors: string[];
  /** The agent's effective rules (own plus project). */
  rules: ModeRule[];
  /** True when the agent's default policy permits unmatched traffic. */
  defaultAllow: boolean;
}

/**
 * Whether the given vendor is permitted by the agent's rules and default
 * policy. A deny rule wins, then an allow rule, else the default policy.
 */
export function vendorAllowed(vendor: string, rules: ModeRule[], defaultAllow: boolean): boolean {
  if (rules.some((r) => r.integrationId === vendor && r.effect === "deny")) return false;
  if (rules.some((r) => r.integrationId === vendor && r.effect === "allow")) return true;
  return defaultAllow;
}

export function deriveLlmMode(input: DeriveLlmModeInput): LlmMode {
  const { enabled, connectionVendors, rules, defaultAllow } = input;
  const hasConns = connectionVendors.length > 0;

  if (enabled && hasConns) {
    const vendors = [...new Set(connectionVendors)];
    if (vendors.every((v) => !vendorAllowed(v, rules, defaultAllow))) return "blocked";
    return "managed";
  }

  // Route off but connections attached: misconfigured. The request falls
  // through to a 502 onegate_no_credential (the Ezer bug).
  if (!enabled && hasConns) return "blocked";

  // No connections: route off = agent uses its own key and OneGate forwards,
  // or route on but empty = forwarded.
  return "passthrough";
}
