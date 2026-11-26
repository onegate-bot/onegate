/**
 * Failure edges of the LLM-routed proxy path: connection-level upstream
 * errors (failover and the final 502), the buffering cap, responses the usage
 * scanner cannot read, and a mid-body upstream failure on the relay.
 *
 * The stub vendor's behaviour is keyed on the injected x-api-key, so each
 * connection's data decides how "its" upstream misbehaves.
 */

import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { startHarness, viaProxy, waitFor, type Harness } from "./proxy-harness.js";
import type { Connection, LlmStrategy } from "../src/types.js";

const LLM_HOST = "api.llm-edge.test";
const VENDOR = "llmedge";

let h: Harness;

beforeAll(async () => {
  h = await startHarness({
    setup(registry) {
      registry.register({
        id: VENDOR,
        title: "LLM Edge Vendor",
        hosts: [LLM_HOST],
        credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
        needsBody: true,
        llm: {
          vendor: VENDOR,
          inject(ctx) {
            ctx.headers["x-api-key"] = ctx.credential.data.apiKey;
          },
        },
        inject(ctx) {
          ctx.headers["x-api-key"] = `app-${ctx.credential.data.apiKey}`;
        },
      });
    },
  });
  h.handler = llmStub;
});

afterAll(async () => {
  await h.close();
});

afterEach(() => {
  h.resetStub();
  h.handler = llmStub;
  delete process.env.ONEGATE_MAX_BUFFERED_BODY;
});

/** Behaviour per injected key. */
function llmStub(req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse): void {
  const key = String(req.headers["x-api-key"] ?? "");
  if (key === "key-drop") {
    // Connection-level failure: hang up without any response.
    req.socket.destroy();
    return;
  }
  if (key === "key-opaque") {
    // An encoding the usage scanner does not attempt to decode.
    res.writeHead(200, { "content-type": "application/json", "content-encoding": "zstd" });
    res.end("opaque-bytes");
    return;
  }
  if (key === "key-midbody") {
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write("data: {}\n\n");
    setTimeout(() => res.socket?.destroy(), 20);
    return;
  }
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: true, key, usage: { input_tokens: 3, output_tokens: 5 } }));
}

/** A routed agent whose LLM config lists the given connection keys in order. */
function routedAgent(
  name: string,
  keys: string[],
  strategy: LlmStrategy = "fallback",
): { token: string; id: string; conns: Connection[] } {
  const a = h.store.createAgent(name, { defaultPolicy: "deny-unmatched" });
  h.store.createRule({
    scope: "agent",
    subjectId: a.agent.id,
    integrationId: VENDOR,
    methods: ["*"],
    pathGlob: "/**",
    effect: "allow",
  });
  const conns = keys.map((k, i) =>
    h.store.createConnection({ kind: "llm", vendor: VENDOR, name: `${name}-${i}`, data: { apiKey: k } }),
  );
  h.store.setAgentLlmConfig(a.agent.id, { enabled: true, strategy, connectionIds: conns.map((c) => c.id) });
  return { token: a.token, id: a.agent.id, conns };
}

function call(token: string, body = JSON.stringify({ model: "edge-1", messages: [] })) {
  return viaProxy(h, {
    host: LLM_HOST,
    token,
    method: "POST",
    path: "/v1/messages",
    body,
    headers: { "content-type": "application/json" },
  });
}

describe("connection-level upstream failures", () => {
  it("fails over to the next connection when the first hangs up, replaying the body", async () => {
    const a = routedAgent("llm-drop-then-ok", ["key-drop", "key-good"]);
    const body = JSON.stringify({ model: "edge-1", messages: [{ role: "user", content: "hi" }] });
    const r = await call(a.token, body);
    expect(r.status).toBe(200);
    expect(r.json.key).toBe("key-good");
    // Both attempts carried the identical buffered body.
    expect(h.seen.map((s) => s.body)).toEqual([body, body]);

    const [dropped] = h.store.listLlmUsage({ connectionId: a.conns[0].id });
    expect(dropped).toMatchObject({ errors: 1, status: null, failover: false });
    const entry = h.store.listAudit({ agentId: a.id, limit: 5 })[0];
    expect(entry).toMatchObject({ decision: "allow", status: 200, connectionId: a.conns[1].id, llmFailover: true });
    expect(h.logs.some((l) => l.includes(`llm upstream error for ${LLM_HOST} via ${a.conns[0].id}`))).toBe(true);
  });

  it("answers 502 onegate_upstream_error when the failover target fails too (retries only once)", async () => {
    const a = routedAgent("llm-drop-drop", ["key-drop", "key-drop", "key-good"]);
    const r = await call(a.token);
    expect(r.status).toBe(502);
    expect(r.json.error).toBe("onegate_upstream_error");
    // Exactly two attempts: the original and one failover; the third key is never tried.
    expect(h.seen).toHaveLength(2);
    expect(h.store.listLlmUsage({ connectionId: a.conns[2].id })).toHaveLength(0);
    const entry = h.store.listAudit({ agentId: a.id, limit: 5 })[0];
    expect(entry).toMatchObject({ decision: "allow", status: 502, connectionId: a.conns[1].id, llmFailover: true });
    const [second] = h.store.listLlmUsage({ connectionId: a.conns[1].id });
    expect(second).toMatchObject({ errors: 1, failover: true, status: null });
  });
});

describe("request body cap on the LLM path", () => {
  it("refuses a body over ONEGATE_MAX_BUFFERED_BODY with 413 and never calls the vendor", async () => {
    const a = routedAgent("llm-big", ["key-good"]);
    process.env.ONEGATE_MAX_BUFFERED_BODY = "64";
    const r = await call(a.token, JSON.stringify({ model: "edge-1", pad: "x".repeat(200) }));
    expect(r.status).toBe(413);
    expect(r.json.error).toBe("onegate_body_too_large");
    expect(r.json.message).toContain("64 byte");
    expect(h.seen).toHaveLength(0);
    expect(h.store.listAudit({ agentId: a.id, limit: 5 })[0]).toMatchObject({
      decision: "body_too_large",
      status: 413,
    });
    expect(h.store.listLlmUsage({ connectionId: a.conns[0].id })).toHaveLength(0);
  });

  it("ignores a non-numeric cap and keeps the default", async () => {
    const a = routedAgent("llm-badcap", ["key-good"]);
    process.env.ONEGATE_MAX_BUFFERED_BODY = "not-a-number";
    const r = await call(a.token, JSON.stringify({ model: "edge-1", pad: "x".repeat(200) }));
    expect(r.status).toBe(200);
  });
});

describe("usage accounting for responses the scanner cannot read", () => {
  it("relays the body untouched and records a usage row with null tokens", async () => {
    const a = routedAgent("llm-opaque", ["key-opaque"]);
    const r = await call(a.token);
    expect(r.status).toBe(200);
    expect(r.headers["content-encoding"]).toBe("zstd");
    expect(r.body).toBe("opaque-bytes");
    const [row] = h.store.listLlmUsage({ connectionId: a.conns[0].id });
    expect(row).toMatchObject({ errors: 0, status: 200, inputTokens: null, outputTokens: null });
  });

  it("records parsed token counts for a readable JSON response (control)", async () => {
    const a = routedAgent("llm-readable", ["key-good"]);
    const r = await call(a.token);
    expect(r.status).toBe(200);
    await waitFor(() => h.store.listLlmUsage({ connectionId: a.conns[0].id }).length === 1);
    const [row] = h.store.listLlmUsage({ connectionId: a.conns[0].id });
    expect(row).toMatchObject({ inputTokens: 3, outputTokens: 5 });
  });
});

describe("mid-body upstream failure on the LLM relay", () => {
  it("aborts the agent's response, logs it, and keeps serving", async () => {
    const a = routedAgent("llm-midbody", ["key-midbody"]);
    const outcome = await call(a.token).then(
      () => "ended",
      () => "error",
    );
    expect(outcome).toBe("error");
    await waitFor(() => h.logs.some((l) => l.includes(`llm upstream response stream error for ${LLM_HOST}`)));
    // The usage row is still written once the upstream stream closes.
    await waitFor(() => h.store.listLlmUsage({ connectionId: a.conns[0].id }).length === 1);

    const b = routedAgent("llm-after-midbody", ["key-good"]);
    const next = await call(b.token);
    expect(next.status).toBe(200);
  });
});

describe("approval holds on the LLM-routed path", () => {
  it("replays the exact held body once the owner approves, and audits the approval", async () => {
    const a = routedAgent("llm-approval", ["key-good"]);
    h.store.createRule({
      scope: "agent",
      subjectId: a.id,
      integrationId: VENDOR,
      methods: ["POST"],
      pathGlob: "/v1/messages",
      effect: "deny",
      action: "require_approval",
    });
    const body = JSON.stringify({ model: "edge-1", messages: [{ role: "user", content: "ship it" }] });
    const held = await call(a.token, body);
    expect(held.status).toBe(403);
    expect(held.json.error).toBe("onegate_approval_pending");
    expect(h.seen).toHaveLength(0);

    expect(h.store.decideApproval(held.json.approval_id, "approved")).not.toBeNull();
    const ok = await call(a.token, body);
    expect(ok.status).toBe(200);
    expect(h.seen.map((s) => s.body)).toEqual([body]);
    const entry = h.store.listAudit({ agentId: a.id, limit: 5 })[0];
    expect(entry).toMatchObject({ decision: "allow", approvalId: held.json.approval_id, connectionId: a.conns[0].id });

    // Spent: the same call is held again.
    const again = await call(a.token, body);
    expect(again.json.error).toBe("onegate_approval_pending");
    expect(h.seen).toHaveLength(1);
  });
});
