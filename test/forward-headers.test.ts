/**
 * RFC 7230 §6.1 conformance for the forwarded request header set.
 *
 * `forwardHeaders` is the single chokepoint both forward paths (the normal
 * integration path and the LLM-routed path) use to build upstream headers, so
 * these assertions cover both.
 */

import { describe, it, expect } from "vitest";
import { forwardHeaders } from "../src/proxy/server.js";

describe("forwardHeaders", () => {
  it("drops the fixed hop-by-hop set and the OneGate-internal headers", () => {
    const out = forwardHeaders({
      "content-type": "application/json",
      connection: "keep-alive",
      "keep-alive": "timeout=5",
      "transfer-encoding": "chunked",
      upgrade: "websocket",
      te: "trailers",
      trailer: "expires",
      "proxy-connection": "keep-alive",
      "proxy-authenticate": "basic",
      "proxy-authorization": "Bearer tok",
      authorization: "Bearer agent-token",
      "x-onegate-connection": "conn_abc",
    });
    expect(out).toEqual({ "content-type": "application/json" });
  });

  it("drops headers the client named in Connection (RFC 7230 §6.1)", () => {
    const out = forwardHeaders({
      connection: "x-foo",
      "x-foo": "hop-scoped",
      "x-keep": "end-to-end",
    });
    expect(out["x-foo"]).toBeUndefined();
    expect(out["x-keep"]).toBe("end-to-end");
  });

  it("handles a multi-token Connection list with arbitrary spacing and case", () => {
    const out = forwardHeaders({
      connection: "keep-alive,  X-Foo ,X-Bar",
      "x-foo": "a",
      "x-bar": "b",
      "x-keep": "c",
    });
    expect(out["x-foo"]).toBeUndefined();
    expect(out["x-bar"]).toBeUndefined();
    expect(out["x-keep"]).toBe("c");
  });

  it("handles Connection arriving as string[]", () => {
    const out = forwardHeaders({
      connection: ["x-foo", "x-bar, keep-alive"] as unknown as string,
      "x-foo": "a",
      "x-bar": "b",
      "x-keep": "c",
    });
    expect(out["x-foo"]).toBeUndefined();
    expect(out["x-bar"]).toBeUndefined();
    expect(out["x-keep"]).toBe("c");
  });

  it("ignores empty tokens in the Connection list", () => {
    const out = forwardHeaders({
      connection: " , ,x-foo, ",
      "x-foo": "a",
      "x-keep": "c",
    });
    expect(out["x-foo"]).toBeUndefined();
    expect(out["x-keep"]).toBe("c");
  });

  it("does not let a client strip structural headers via Connection", () => {
    const out = forwardHeaders({
      connection: "host, content-length",
      host: "api.example-vendor.com",
      "content-length": "12",
    });
    expect(out.host).toBe("api.example-vendor.com");
    expect(out["content-length"]).toBe("12");
  });

  it("still strips authorization when it is named in Connection", () => {
    const out = forwardHeaders({
      connection: "authorization, x-onegate-connection",
      authorization: "Bearer agent-token",
      "x-onegate-connection": "conn_abc",
      "x-keep": "c",
    });
    expect(out.authorization).toBeUndefined();
    expect(out["x-onegate-connection"]).toBeUndefined();
    expect(out["x-keep"]).toBe("c");
  });

  it("passes everything through when there is no Connection header", () => {
    const out = forwardHeaders({ "x-foo": "a", "content-type": "text/plain" });
    expect(out).toEqual({ "x-foo": "a", "content-type": "text/plain" });
  });
});
