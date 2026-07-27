/**
 * SSRF guard on the opaque CONNECT passthrough path.
 *
 * The passthrough tunnel is a raw byte pipe with no inspection of the inner
 * protocol, so the destination address is the only enforcement point. These
 * tests pin the two halves of that guard: the pure address classifier, and the
 * proxy behaviour (403 + audit for internal destinations, tunnels still open
 * for public ones and for operator-sanctioned upstreamLookup overrides).
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import http from "node:http";
import net from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initCa } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { Registry } from "../src/integrations/types.js";
import { GatewayProxy, isBlockedDestination } from "../src/proxy/server.js";

describe("isBlockedDestination", () => {
  it("blocks IPv4 loopback across the whole /8", () => {
    expect(isBlockedDestination("127.0.0.1")).toBe(true);
    expect(isBlockedDestination("127.1.2.3")).toBe(true);
  });

  it("blocks link-local and cloud metadata (169.254.0.0/16)", () => {
    expect(isBlockedDestination("169.254.169.254")).toBe(true);
    expect(isBlockedDestination("169.254.0.1")).toBe(true);
  });

  it("blocks RFC1918 private ranges", () => {
    expect(isBlockedDestination("10.0.0.1")).toBe(true);
    expect(isBlockedDestination("192.168.1.1")).toBe(true);
    // 172.16/12 is 172.16 through 172.31 inclusive.
    expect(isBlockedDestination("172.16.0.1")).toBe(true);
    expect(isBlockedDestination("172.17.0.1")).toBe(true); // the docker bridge / admin API
    expect(isBlockedDestination("172.31.255.255")).toBe(true);
  });

  it("does not over-block the public neighbours of 172.16/12", () => {
    expect(isBlockedDestination("172.15.0.1")).toBe(false);
    expect(isBlockedDestination("172.32.0.1")).toBe(false);
  });

  it("blocks CGNAT 100.64.0.0/10 but not its public neighbours", () => {
    expect(isBlockedDestination("100.64.0.1")).toBe(true);
    expect(isBlockedDestination("100.127.255.255")).toBe(true);
    expect(isBlockedDestination("100.63.255.255")).toBe(false);
    expect(isBlockedDestination("100.128.0.1")).toBe(false);
  });

  it("blocks the unspecified address", () => {
    expect(isBlockedDestination("0.0.0.0")).toBe(true);
    expect(isBlockedDestination("::")).toBe(true);
  });

  it("blocks IPv6 loopback, link-local and unique-local", () => {
    expect(isBlockedDestination("::1")).toBe(true);
    expect(isBlockedDestination("fe80::1")).toBe(true);
    expect(isBlockedDestination("febf::1")).toBe(true);
    expect(isBlockedDestination("fc00::1")).toBe(true);
    expect(isBlockedDestination("fd12:3456::1")).toBe(true);
  });

  it("blocks IPv4-mapped IPv6 forms of blocked addresses", () => {
    expect(isBlockedDestination("::ffff:127.0.0.1")).toBe(true);
    expect(isBlockedDestination("::ffff:169.254.169.254")).toBe(true);
    expect(isBlockedDestination("::ffff:172.17.0.1")).toBe(true);
    expect(isBlockedDestination("::ffff:10.0.0.1")).toBe(true);
    // An IPv4-mapped PUBLIC address is still fine.
    expect(isBlockedDestination("::ffff:93.184.216.34")).toBe(false);
  });

  it("strips an IPv6 zone index before judging", () => {
    expect(isBlockedDestination("fe80::1%eth0")).toBe(true);
  });

  it("allows public addresses", () => {
    expect(isBlockedDestination("93.184.216.34")).toBe(false);
    expect(isBlockedDestination("8.8.8.8")).toBe(false);
    expect(isBlockedDestination("2606:2800:220:1::1")).toBe(false);
  });

  it("returns false for non-address strings (hostnames are handled separately)", () => {
    expect(isBlockedDestination("example.com")).toBe(false);
    expect(isBlockedDestination("")).toBe(false);
  });
});

describe("CONNECT passthrough destination guard", () => {
  let dir: string;
  let store: Store;
  let proxy: GatewayProxy;
  let port: number;
  let token: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "onegate-ssrf-"));
    store = new Store(":memory:");
    // No upstreamLookup: this proxy dials whatever the guard lets through, so
    // the guard is what these tests actually exercise.
    proxy = new GatewayProxy({ ca: initCa(dir), store, registry: new Registry() });
    port = await proxy.listen(0, "127.0.0.1");
    token = store.createAgent("ssrf-agent", { defaultPolicy: "deny-unmatched" }).token;
  });

  afterAll(async () => {
    await proxy.close();
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  /** Issues a CONNECT and resolves with the status line's status code. */
  function connect(authority: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const req = http.request({
        host: "127.0.0.1",
        port,
        method: "CONNECT",
        path: authority,
        headers: {
          "proxy-authorization": "Basic " + Buffer.from(`agent:${token}`).toString("base64"),
        },
        agent: false,
      });
      // A refused CONNECT is answered with a status line and then the socket is
      // ended, which node surfaces as 'connect' for 2xx and 'response' for the
      // rest depending on timing; handle both plus a clean FIN.
      req.on("connect", (res, socket) => {
        socket.destroy();
        resolve(res.statusCode ?? 0);
      });
      req.on("response", (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.on("error", reject);
      req.end();
    });
  }

  it("refuses a tunnel to the docker bridge / admin API address", async () => {
    // The real deployment binds the OneGate admin API on 172.17.0.1:8080, and
    // the non-443 port means onConnect skips integration matching entirely.
    expect(await connect("172.17.0.1:8080")).toBe(403);
  });

  it("refuses a tunnel to cloud metadata", async () => {
    expect(await connect("169.254.169.254:80")).toBe(403);
  });

  it("refuses a tunnel to loopback", async () => {
    expect(await connect("127.0.0.1:8080")).toBe(403);
  });

  it("refuses a tunnel to other private ranges", async () => {
    expect(await connect("10.0.0.1:22")).toBe(403);
    expect(await connect("192.168.1.1:443")).toBe(403);
  });

  it("refuses a tunnel to localhost by name", async () => {
    expect(await connect("localhost:8080")).toBe(403);
  });

  it("audits a blocked attempt as a OneGate-side deny", async () => {
    await connect("172.17.0.1:8080");
    const entry = store.listAudit({ limit: 50 }).find((e) => e.host === "172.17.0.1");
    expect(entry).toBeDefined();
    expect(entry?.decision).toBe("deny");
    expect(entry?.status).toBe(403);
    expect(entry?.source).toBe("onegate");
  });

});

describe("ONEGATE_ALLOW_INTERNAL_PASSTHROUGH escape hatch", () => {
  /**
   * Proves the non-blocked path still opens a real tunnel. A genuinely public
   * destination cannot be dialled from a test sandbox, so instead we take a
   * destination the guard blocks by default, flip the operator opt-in, and
   * assert the very same request now tunnels end to end. That exercises the
   * allow branch of the guard against a real listener, and pins the escape
   * hatch at the same time.
   */
  it("tunnels to an internal destination only when explicitly opted in", async () => {
    const dir = mkdtempSync(join(tmpdir(), "onegate-ssrf-optin-"));
    const store = new Store(":memory:");

    const upstream = net.createServer((c) => c.on("data", (d) => c.write(d)));
    await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
    const upstreamPort = (upstream.address() as net.AddressInfo).port;

    const proxy = new GatewayProxy({ ca: initCa(dir), store, registry: new Registry() });
    const port = await proxy.listen(0, "127.0.0.1");
    const token = store.createAgent("optin-agent", { defaultPolicy: "deny-unmatched" }).token;

    const connect = (): Promise<number> =>
      new Promise((resolve, reject) => {
        const req = http.request({
          host: "127.0.0.1",
          port,
          method: "CONNECT",
          path: `127.0.0.1:${upstreamPort}`,
          headers: {
            "proxy-authorization": "Basic " + Buffer.from(`agent:${token}`).toString("base64"),
          },
          agent: false,
        });
        req.on("connect", (res, socket) => {
          socket.destroy();
          resolve(res.statusCode ?? 0);
        });
        req.on("response", (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        });
        req.on("error", reject);
        req.end();
      });

    // Default: blocked.
    expect(await connect()).toBe(403);

    const prev = process.env.ONEGATE_ALLOW_INTERNAL_PASSTHROUGH;
    process.env.ONEGATE_ALLOW_INTERNAL_PASSTHROUGH = "1";
    try {
      // Same request, opted in: a real tunnel to a real listener.
      expect(await connect()).toBe(200);
      expect(store.listAudit({ limit: 10 })[0]?.decision).toBe("passthrough");
    } finally {
      if (prev === undefined) delete process.env.ONEGATE_ALLOW_INTERNAL_PASSTHROUGH;
      else process.env.ONEGATE_ALLOW_INTERNAL_PASSTHROUGH = prev;
    }

    await proxy.close();
    upstream.close();
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("CONNECT passthrough with an operator-sanctioned upstreamLookup", () => {
  it("still tunnels to a loopback fixture, because the override is deliberate", async () => {
    const dir = mkdtempSync(join(tmpdir(), "onegate-ssrf-lookup-"));
    const store = new Store(":memory:");

    // A local stub standing in for the redirected upstream.
    const upstream = net.createServer((c) => c.on("data", (d) => c.write(d)));
    await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
    const upstreamPort = (upstream.address() as net.AddressInfo).port;

    const proxy = new GatewayProxy({
      ca: initCa(dir),
      store,
      registry: new Registry(),
      // Redirects every upstream to loopback. The guard must not break this:
      // it is how tests and operators deliberately target a local fixture.
      upstreamLookup: () => ({ host: "127.0.0.1", port: upstreamPort }),
    });
    const port = await proxy.listen(0, "127.0.0.1");
    const token = store.createAgent("lookup-agent", { defaultPolicy: "deny-unmatched" }).token;

    const status = await new Promise<number>((resolve, reject) => {
      const req = http.request({
        host: "127.0.0.1",
        port,
        method: "CONNECT",
        path: "opaque.example.com:443",
        headers: {
          "proxy-authorization": "Basic " + Buffer.from(`agent:${token}`).toString("base64"),
        },
        agent: false,
      });
      req.on("connect", (res, socket) => {
        socket.destroy();
        resolve(res.statusCode ?? 0);
      });
      req.on("response", (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.on("error", reject);
      req.end();
    });

    expect(status).toBe(200);
    expect(store.listAudit({ limit: 10 })[0]?.decision).toBe("passthrough");

    await proxy.close();
    upstream.close();
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
});
