/**
 * Regression: a mid-body failure while relaying an upstream response body must
 * NOT crash the proxy process.
 *
 * Both forward paths (the non-LLM one and the LLM `streamBack` one) pipe the
 * upstream response straight to the agent. The `upstream.on("error")` handlers
 * they already had only cover the pre-response phase — once headers are sent
 * and the body is flowing, an upstream RST / premature close / TLS teardown
 * emits 'error' on the RESPONSE stream. With no listener there, Node escalates
 * it to an uncaught exception, and since nothing in src installs a
 * process-level `uncaughtException` handler the whole shared proxy dies,
 * dropping every agent's traffic at once.
 *
 * A full e2e mid-body RST through the TLS MITM is timing-dependent, so this
 * drives `pipeUpstreamResponse` (the helper both production paths now use)
 * against real Node stream objects instead.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { AddressInfo } from "node:net";
import { pipeUpstreamResponse } from "../src/proxy/server.js";

/** Server standing in for the agent-facing side; yields a real ServerResponse. */
let resServer: http.Server;
let resPort: number;

beforeAll(async () => {
  resServer = http.createServer(() => {
    /* per-test handler is installed via once("request") below */
  });
  await new Promise<void>((r) => resServer.listen(0, "127.0.0.1", r));
  resPort = (resServer.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise<void>((r) => resServer.close(() => r()));
});

/**
 * Grabs one real ServerResponse from the helper server, plus a promise that
 * settles when the client side of that exchange finishes (cleanly or not).
 */
function nextResponse(): Promise<{ res: http.ServerResponse; clientDone: Promise<string> }> {
  return new Promise((resolve) => {
    resServer.once("request", (_req, res) => {
      resolve({ res, clientDone });
    });
    const clientDone = new Promise<string>((done) => {
      const req = http.request({ port: resPort, host: "127.0.0.1", path: "/" }, (cRes) => {
        cRes.on("data", () => {});
        cRes.on("end", () => done("end"));
        cRes.on("error", () => done("error"));
      });
      req.on("error", () => done("error"));
      req.end();
    });
  });
}

/** A fake upstream request handle recording whether it was destroyed. */
function fakeUpstream() {
  return { destroyed: false, destroy(this: { destroyed: boolean }) { this.destroyed = true; } };
}

describe("pipeUpstreamResponse", () => {
  it("does not throw an unhandled 'error' when the upstream body fails mid-stream", async () => {
    const { res, clientDone } = await nextResponse();
    const upRes = new http.IncomingMessage(null as never);
    const upstream = fakeUpstream();
    const seen: Error[] = [];

    res.writeHead(200, { "content-type": "text/plain" });
    pipeUpstreamResponse(upRes, res, upstream, (err) => seen.push(err));

    // Body starts flowing, then the upstream dies mid-body.
    upRes.push("partial");
    const boom = new Error("socket hang up");
    // Would be an uncaught exception (and a dead proxy) without the listener.
    expect(() => upRes.emit("error", boom)).not.toThrow();

    expect(seen).toHaveLength(1);
    expect(seen[0].message).toBe("socket hang up");
    // Client is torn down rather than left hanging on a truncated body.
    expect(await clientDone).toBe("error");
    expect(res.destroyed).toBe(true);
  });

  it("attaches an 'error' listener to the upstream response stream", async () => {
    const { res } = await nextResponse();
    const upRes = new http.IncomingMessage(null as never);

    expect(upRes.listenerCount("error")).toBe(0);
    pipeUpstreamResponse(upRes, res, fakeUpstream());
    expect(upRes.listenerCount("error")).toBeGreaterThan(0);

    res.destroy();
  });

  it("destroys the upstream request when the agent-facing response errors", async () => {
    const { res } = await nextResponse();
    const upRes = new http.IncomingMessage(null as never);
    const upstream = fakeUpstream();

    pipeUpstreamResponse(upRes, res, upstream);
    expect(upstream.destroyed).toBe(false);

    // Client disconnected mid-body: don't leak the upstream socket.
    expect(() => res.emit("error", new Error("ECONNRESET"))).not.toThrow();
    expect(upstream.destroyed).toBe(true);
  });

  it("relays a normal body through to the client unchanged", async () => {
    const { res, clientDone } = await nextResponse();
    const upRes = new http.IncomingMessage(null as never);

    res.writeHead(200, { "content-type": "text/plain" });
    pipeUpstreamResponse(upRes, res, fakeUpstream());

    upRes.push("hello ");
    upRes.push("world");
    upRes.push(null);

    expect(await clientDone).toBe("end");
  });
});
