/**
 * Audit clarity helpers. Every audit row already carries a `decision` that
 * fully determines whether OneGate itself blocked the request or merely
 * forwarded it and the status came back from the upstream service. These pure
 * functions derive a human-facing `source` label and a plain-words `reason`
 * from an existing row, so the distinction can be shown without any schema
 * change and applies retroactively to historical rows.
 *
 * The motivating case: a default-deny agent with no matching allow rule gets a
 * 403 written by OneGate, byte-identical in status to a 403 the upstream API
 * would return. Without a source label the operator cannot tell which side
 * said no.
 */

import type { AuditEntry, Decision } from "./types.js";

/** Decisions where OneGate itself ended the request (never reached upstream). */
const ONEGATE_BLOCKS: ReadonlySet<Decision> = new Set<Decision>([
  "deny",
  "auth_failed",
  "no_credential",
  "unknown_connection",
  "connection_not_granted",
  "body_too_large",
]);

/** True when OneGate (not the upstream service) ended the request. */
export function isOnegateBlock(decision: Decision): boolean {
  return ONEGATE_BLOCKS.has(decision);
}

export type AuditSource = "onegate" | "upstream";

/**
 * Who produced the recorded outcome. `onegate` means OneGate blocked it before
 * it ever reached the upstream; `upstream` means OneGate allowed or passed the
 * request through and the recorded status came back from the API itself.
 */
export function auditSource(decision: Decision): AuditSource {
  return isOnegateBlock(decision) ? "onegate" : "upstream";
}

/**
 * A short, plain-words explanation suitable for showing next to a row. Returns
 * null when no explanation adds value (a clean allow/passthrough success).
 */
export function auditReason(entry: Pick<AuditEntry, "decision" | "ruleId" | "status">): string | null {
  const { decision, ruleId, status } = entry;
  switch (decision) {
    case "deny":
      return ruleId
        ? `Blocked by OneGate: an explicit deny rule matched (rule ${ruleId}).`
        : "Blocked by OneGate: no allow rule matches this agent and integration. Add an allow rule to permit it.";
    case "auth_failed":
      return "Blocked by OneGate: the agent proxy token is missing or invalid.";
    case "no_credential":
      return "Blocked by OneGate: no credential is connected for this integration.";
    case "unknown_connection":
      return "Blocked by OneGate: the x-onegate-connection header names a connection this agent cannot use.";
    case "connection_not_granted":
      return "Blocked by OneGate: the selected connection is not granted to this agent.";
    case "body_too_large":
      return "Blocked by OneGate: the request body exceeded the size OneGate will buffer.";
    case "allow":
      return typeof status === "number" && status >= 400
        ? `Allowed by OneGate. The upstream service returned ${status}, so this status came from the API, not OneGate.`
        : null;
    case "passthrough":
      return typeof status === "number" && status >= 400
        ? `Passed through by OneGate without interception. The upstream service returned ${status}.`
        : null;
    default:
      return null;
  }
}
