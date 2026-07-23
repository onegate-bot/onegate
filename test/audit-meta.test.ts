import { describe, it, expect } from "vitest";
import { auditSource, auditReason, isOnegateBlock } from "../src/audit-meta.js";
import type { Decision } from "../src/types.js";

describe("auditSource", () => {
  const blocks: Decision[] = [
    "deny",
    "auth_failed",
    "no_credential",
    "unknown_connection",
    "connection_not_granted",
    "body_too_large",
  ];
  for (const d of blocks) {
    it(`labels ${d} as onegate`, () => {
      expect(auditSource(d)).toBe("onegate");
      expect(isOnegateBlock(d)).toBe(true);
    });
  }
  for (const d of ["allow", "passthrough"] as Decision[]) {
    it(`labels ${d} as upstream`, () => {
      expect(auditSource(d)).toBe("upstream");
      expect(isOnegateBlock(d)).toBe(false);
    });
  }
});

describe("auditReason", () => {
  it("default-deny (no rule) tells the operator to add an allow rule", () => {
    const r = auditReason({ decision: "deny", ruleId: null, status: 403 });
    expect(r).toContain("Blocked by OneGate");
    expect(r).toContain("no allow rule");
    expect(r).toContain("Add an allow rule");
  });

  it("explicit deny rule names the rule", () => {
    const r = auditReason({ decision: "deny", ruleId: "rl_abc", status: 403 });
    expect(r).toContain("Blocked by OneGate");
    expect(r).toContain("deny rule");
    expect(r).toContain("rl_abc");
  });

  it("auth_failed explains the token", () => {
    expect(auditReason({ decision: "auth_failed", ruleId: null, status: 407 })).toContain(
      "proxy token",
    );
  });

  it("no_credential explains the missing credential", () => {
    expect(auditReason({ decision: "no_credential", ruleId: null, status: 502 })).toContain(
      "no credential",
    );
  });

  it("unknown_connection explains the header", () => {
    expect(auditReason({ decision: "unknown_connection", ruleId: null, status: 400 })).toContain(
      "x-onegate-connection",
    );
  });

  it("connection_not_granted explains the grant", () => {
    expect(
      auditReason({ decision: "connection_not_granted", ruleId: null, status: 403 }),
    ).toContain("not granted");
  });

  it("body_too_large explains the size limit", () => {
    expect(auditReason({ decision: "body_too_large", ruleId: null, status: 413 })).toContain(
      "body",
    );
  });

  it("allow with a 4xx status points the operator at the upstream service", () => {
    const r = auditReason({ decision: "allow", ruleId: "rl_x", status: 403 });
    expect(r).toContain("Allowed by OneGate");
    expect(r).toContain("403");
    expect(r).toContain("from the API");
  });

  it("allow with a success status has no reason", () => {
    expect(auditReason({ decision: "allow", ruleId: "rl_x", status: 200 })).toBeNull();
    expect(auditReason({ decision: "allow", ruleId: null, status: null })).toBeNull();
  });

  it("passthrough with a 4xx status names the upstream service", () => {
    const r = auditReason({ decision: "passthrough", ruleId: null, status: 401 });
    expect(r).toContain("Passed through by OneGate");
    expect(r).toContain("401");
  });

  it("passthrough with a success status has no reason", () => {
    expect(auditReason({ decision: "passthrough", ruleId: null, status: 200 })).toBeNull();
    expect(auditReason({ decision: "passthrough", ruleId: null, status: null })).toBeNull();
  });
});
