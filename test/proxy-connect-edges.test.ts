/**
 * CONNECT-level edges of the gateway proxy: proxy auth parsing, plain-HTTP
 * refusal, malformed authorities, passthrough failure / DNS pinning, leaf
 * minting failures, and CONNECT `head` bytes on the passthrough path.
 */

import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from "vitest";
import dns from "node:dns";
import net from "node:net";
import tls from "node:tls";
import type { Ca } from "../src/ca.js";
import {
  basicAuth,
  delay,
  rawConnect,
  startHarness,
  viaProxy,
  waitFor,
  type Harness,
} from "./proxy-harness.js";

const VENDOR_HOST = "api.edge-vendor.test";

let h: Harness;
let token: string;
let agentId: string;

beforeAll(async () => {
  h = await startHarness({
    setup(registry, store) {
      registry.register({
        id: "edgevendor",
        title: "Edge Vendor",
        hosts: [VENDOR_HOST],
        credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
        inject(ctx) {
          ctx.headers.authorization = `Bearer ${ctx.credential.data.apiKey}`;
        },
      });
      store.setCredential("edgevendor", "main", { apiKey: "vendor-secret" });
      const a = store.createAgent("edge-agent", { defaultPolicy: "deny-unmatched" });
      token = a.token;
      agentId = a.agent.id;
      store.createRule({
        scope: "agent",
        subjectId: agentId,
        integrationId: "edgevendor",
        methods: ["*"],
        pathGlob: "/**",
        effect: "allow",
      });
    },
  });
});

afterAll(async () => {
  await h.close();
});

afterEach(() => {
  vi.restoreAllMocks();
  h.resetStub();
});

/** The proxy's live options object, so a test can redirect upstreamLookup. */
function proxyOpts(x: Harness): { upstreamLookup?: (host: string, port: number) => { host: string; port: number } } {
  return (x.proxy as unknown as { opts: ReturnType<typeof proxyOpts> }).opts;
}

/** Waits for the proxy to close the connection itself, rather than resetting it from the client. */
function closed(socket: net.Socket): Promise<void> {
  return new Promise((r) => (socket.destroyed ? r() : socket.once("close", () => r())));
}

function auditCount(): number {
  return h.store.listAudit({ limit: 1000 }).length;
}

describe("plain (non-CONNECT) HTTP requests", () => {
  it("are refused with 501: the gateway only mediates HTTPS", async () => {
    const r = await fetch(`http://127.0.0.1:${h.proxyPort}/anything`);
    expect(r.status).toBe(501);
    expect(await r.json()).toEqual({ error: "OneGate only proxies HTTPS (CONNECT)" });
    expect(h.seen).toHaveLength(0);
  });
});

describe("malformed CONNECT authorities", () => {
  it("rejects a host with illegal characters with 400, before auth or audit", async () => {
    const before = auditCount();
    const { statusLine, socket } = await rawConnect(h.proxyPort, "bad_host!:443", {
      "Proxy-Authorization": basicAuth(token),
    });
    await closed(socket);
    expect(statusLine).toBe("HTTP/1.1 400 Bad Request");
    expect(auditCount()).toBe(before);
  });

  it("rejects an empty host with 400", async () => {
    const { statusLine, socket } = await rawConnect(h.proxyPort, ":443", {
      "Proxy-Authorization": basicAuth(token),
    });
    await closed(socket);
    expect(statusLine).toBe("HTTP/1.1 400 Bad Request");
  });

  it("defaults a missing port to 443 and still TLS-terminates the integration host", async () => {
    const r = await viaProxy(h, { host: VENDOR_HOST, token, authority: VENDOR_HOST, path: "/v1/no-port" });
    expect(r.status).toBe(200);
    expect(h.seen[0].headers.authorization).toBe("Bearer vendor-secret");
  });
});

describe("proxy authentication", () => {
  it("accepts the token as a Bearer Proxy-Authorization", async () => {
    const r = await viaProxy(h, { host: VENDOR_HOST, proxyAuth: `Bearer ${token}`, path: "/v1/bearer" });
    expect(r.status).toBe(200);
    expect(h.seen[0].path).toBe("/v1/bearer");
  });

  it("accepts a Basic credential with no user part (the whole value is the token)", async () => {
    const proxyAuth = "Basic " + Buffer.from(token).toString("base64");
    const r = await viaProxy(h, { host: VENDOR_HOST, proxyAuth, path: "/v1/bare" });
    expect(r.status).toBe(200);
  });

  it.each([
    ["an unsupported scheme", () => `Digest ${token}`],
    ["a scheme with no credential", () => "Basic"],
  ])("rejects %s with 407 and audits auth_failed", async (_label, header) => {
    const before = h.store.listAudit({ limit: 1000 }).filter((e) => e.decision === "auth_failed").length;
    const r = await viaProxy(h, { host: VENDOR_HOST, proxyAuth: header(), path: "/v1/x" });
    expect(r.connectStatus).toBe(407);
    const failed = h.store.listAudit({ limit: 1000 }).filter((e) => e.decision === "auth_failed");
    expect(failed.length).toBe(before + 1);
    expect(failed[0].host).toBe(VENDOR_HOST);
    expect(failed[0].agentId).toBeNull();
    expect(h.seen).toHaveLength(0);
  });
});

describe("passthrough (non-integration hosts and non-443 ports)", () => {
  it("tunnels an integration host on a non-443 port opaquely, forwarding pipelined head bytes", async () => {
    // A raw TCP echo-ish upstream: records what arrives and replies "PONG".
    const received: Buffer[] = [];
    const upstream = net.createServer((c) => {
      c.on("error", () => {});
      c.on("data", (d) => {
        received.push(d);
        c.write("PONG");
      });
    });
    await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
    const upstreamPort = (upstream.address() as net.AddressInfo).port;
    const opts = proxyOpts(h);
    const original = opts.upstreamLookup;
    const dialled: Array<[string, number]> = [];
    opts.upstreamLookup = (host, port) => {
      dialled.push([host, port]);
      return { host: "127.0.0.1", port: upstreamPort };
    };
    try {
      const { statusLine, socket, rest } = await rawConnect(
        h.proxyPort,
        `${VENDOR_HOST}:8443`,
        { "Proxy-Authorization": basicAuth(token) },
        "PING-IN-HEAD",
      );
      expect(statusLine).toBe("HTTP/1.1 200 Connection Established");
      let reply = rest.toString();
      if (!reply.includes("PONG")) {
        reply += await new Promise<string>((r) => socket.once("data", (d) => r(d.toString())));
      }
      socket.destroy();
      expect(reply).toContain("PONG");
      expect(Buffer.concat(received).toString()).toBe("PING-IN-HEAD");
      // Not MITM'd: the opaque path dialled the agent's port, not the stub vendor.
      expect(dialled).toEqual([[VENDOR_HOST, 8443]]);
      const entry = h.store.listAudit({ limit: 5 })[0];
      expect(entry.decision).toBe("passthrough");
      expect(entry.agentId).toBe(agentId);
    } finally {
      opts.upstreamLookup = original;
      upstream.close();
    }
  });

  it("answers 502 when the passthrough upstream refuses the connection", async () => {
    const closed = net.createServer();
    await new Promise<void>((r) => closed.listen(0, "127.0.0.1", r));
    const deadPort = (closed.address() as net.AddressInfo).port;
    await new Promise<void>((r) => closed.close(() => r()));

    const opts = proxyOpts(h);
    const original = opts.upstreamLookup;
    opts.upstreamLookup = () => ({ host: "127.0.0.1", port: deadPort });
    try {
      const { statusLine, socket } = await rawConnect(h.proxyPort, "opaque.example.com:443", {
        "Proxy-Authorization": basicAuth(token),
      });
      socket.destroy();
      expect(statusLine).toBe("HTTP/1.1 502 Bad Gateway");
    } finally {
      opts.upstreamLookup = original;
    }
  });
});

describe("passthrough destination resolution (no upstreamLookup)", () => {
  let p: Harness;
  beforeAll(async () => {
    p = await startHarness({ proxy: () => ({ upstreamLookup: undefined }) });
  });
  afterAll(async () => {
    await p.close();
  });

  async function tokenFor(name: string): Promise<{ token: string; id: string }> {
    const a = p.store.createAgent(name, { defaultPolicy: "deny-unmatched" });
    return { token: a.token, id: a.agent.id };
  }

  it("refuses a hostname whose DNS answer is internal (403, audited as a deny)", async () => {
    const lookup = vi
      .spyOn(dns.promises, "lookup")
      .mockResolvedValue({ address: "10.1.2.3", family: 4 } as never);
    const a = await tokenFor("rebind-agent");
    const { statusLine, socket } = await rawConnect(p.proxyPort, "rebind.example.com:443", {
      "Proxy-Authorization": basicAuth(a.token),
    });
    socket.destroy();
    expect(statusLine).toBe("HTTP/1.1 403 Forbidden");
    expect(lookup).toHaveBeenCalledWith("rebind.example.com");
    const entry = p.store.listAudit({ agentId: a.id, limit: 5 })[0];
    expect(entry).toMatchObject({ decision: "deny", status: 403, host: "rebind.example.com" });
    expect(p.logs.some((l) => l.includes("rebind.example.com -> 10.1.2.3"))).toBe(true);
  });

  it("answers 502 (not 403) when the hostname does not resolve", async () => {
    vi.spyOn(dns.promises, "lookup").mockRejectedValue(
      Object.assign(new Error("getaddrinfo ENOTFOUND nowhere.example"), { code: "ENOTFOUND" }),
    );
    const a = await tokenFor("nxdomain-agent");
    const { statusLine, socket } = await rawConnect(p.proxyPort, "nowhere.example:443", {
      "Proxy-Authorization": basicAuth(a.token),
    });
    socket.destroy();
    expect(statusLine).toBe("HTTP/1.1 502 Bad Gateway");
    expect(p.store.listAudit({ agentId: a.id, limit: 5 })).toHaveLength(0);
  });

  it("dials the vetted resolved address, not the hostname (DNS pinning)", async () => {
    const upstream = net.createServer((c) => {
      c.on("error", () => {}); // the proxy RSTs it when the client hangs up
      c.end("HELLO");
    });
    await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
    const upstreamPort = (upstream.address() as net.AddressInfo).port;
    vi.spyOn(dns.promises, "lookup").mockResolvedValue({ address: "203.0.113.7", family: 4 } as never);
    const realConnect = net.connect;
    const dialled: unknown[] = [];
    vi.spyOn(net, "connect").mockImplementation(((port: number, host: string, cb: () => void) => {
      dialled.push([host, port]);
      // Redirect the (public, unroutable in tests) pinned address to a fixture.
      return realConnect(upstreamPort, "127.0.0.1", cb);
    }) as never);
    try {
      const a = await tokenFor("pinned-agent");
      const { statusLine, socket } = await rawConnect(p.proxyPort, "public.example.com:443", {
        "Proxy-Authorization": basicAuth(a.token),
      });
      socket.destroy();
      expect(statusLine).toBe("HTTP/1.1 200 Connection Established");
      expect(dialled).toEqual([["203.0.113.7", 443]]);
      expect(p.store.listAudit({ agentId: a.id, limit: 5 })[0].decision).toBe("passthrough");
    } finally {
      upstream.close();
    }
  });

  it("dials a public IP literal as given, without a DNS lookup", async () => {
    const upstream = net.createServer((c) => {
      c.on("error", () => {}); // the proxy RSTs it when the client hangs up
      c.end("HELLO");
    });
    await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
    const upstreamPort = (upstream.address() as net.AddressInfo).port;
    const lookup = vi.spyOn(dns.promises, "lookup");
    const realConnect = net.connect;
    const dialled: unknown[] = [];
    vi.spyOn(net, "connect").mockImplementation(((port: number, host: string, cb: () => void) => {
      dialled.push([host, port]);
      return realConnect(upstreamPort, "127.0.0.1", cb);
    }) as never);
    try {
      const a = await tokenFor("literal-agent");
      const { statusLine, socket } = await rawConnect(p.proxyPort, "198.51.100.20:8080", {
        "Proxy-Authorization": basicAuth(a.token),
      });
      socket.destroy();
      expect(statusLine).toBe("HTTP/1.1 200 Connection Established");
      expect(dialled).toEqual([["198.51.100.20", 8080]]);
      expect(lookup).not.toHaveBeenCalled();
    } finally {
      upstream.close();
    }
  });
});

describe("leaf minting failures on the TLS-terminating paths", () => {
  let gate: { release: () => void; fail: boolean; calls: number };
  let p: Harness;
  let ptoken: string;

  beforeAll(async () => {
    gate = { release: () => {}, fail: false, calls: 0 };
    p = await startHarness({
      setup(registry, store) {
        registry.register({
          id: "edgevendor",
          title: "Edge Vendor",
          hosts: [VENDOR_HOST],
          credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
          inject(ctx) {
            ctx.headers.authorization = `Bearer ${ctx.credential.data.apiKey}`;
          },
        });
        store.setCredential("edgevendor", "main", { apiKey: "k" });
        const a = store.createAgent("leaf-agent", { defaultPolicy: "allow-all" });
        ptoken = a.token;
      },
      wrapCa(ca: Ca): Ca {
        const wrapped = Object.create(ca) as Ca;
        wrapped.leafForAsync = async (host: string) => {
          gate.calls++;
          if (gate.fail) throw new Error("keygen exploded");
          await new Promise<void>((r) => (gate.release = r));
          return ca.leafForAsync(host);
        };
        return wrapped;
      },
    });
  });
  afterAll(async () => {
    await p.close();
  });

  it.each([
    ["an integration host", VENDOR_HOST],
    ["the discovery host", "onegate.internal"],
  ])("destroys the accepted tunnel when minting the leaf fails (%s)", async (_label, host) => {
    gate.fail = true;
    try {
      const { statusLine, socket, rest } = await rawConnect(p.proxyPort, `${host}:443`, {
        "Proxy-Authorization": basicAuth(ptoken),
      });
      expect(statusLine).toBe("HTTP/1.1 200 Connection Established");
      // The success line is already on the wire, so the only signal left is a
      // closed socket: no TLS, no bytes.
      await new Promise<void>((r) => (socket.destroyed ? r() : socket.once("close", () => r())));
      expect(rest.length).toBe(0);
      expect(p.seen).toHaveLength(0);
    } finally {
      gate.fail = false;
    }
  });

  it("drops the tunnel quietly when the client hangs up while the leaf is minting", async () => {
    const before = gate.calls;
    const { statusLine, socket } = await rawConnect(p.proxyPort, `${VENDOR_HOST}:443`, {
      "Proxy-Authorization": basicAuth(ptoken),
    });
    expect(statusLine).toBe("HTTP/1.1 200 Connection Established");
    await waitFor(() => gate.calls === before + 1);
    // An abrupt RST, so the proxy-side socket is already destroyed by the
    // time the leaf arrives.
    socket.resetAndDestroy();
    await delay(50);
    gate.release();
    await delay(50);
    // The proxy survived and still serves the next tunnel normally.
    const next = viaProxy(p, { host: VENDOR_HOST, token: ptoken, path: "/after-hangup" });
    await waitFor(() => gate.calls === before + 2);
    gate.release();
    const r = await next;
    expect(r.status).toBe(200);
    expect(p.seen.map((s) => s.path)).toEqual(["/after-hangup"]);
  });
});

describe("garbage inside an accepted tunnel", () => {
  async function tunnel(host: string) {
    const { statusLine, socket } = await rawConnect(h.proxyPort, `${host}:443`, {
      "Proxy-Authorization": basicAuth(token),
    });
    expect(statusLine).toBe("HTTP/1.1 200 Connection Established");
    return socket;
  }

  it.each([
    ["an integration host", VENDOR_HOST],
    ["the discovery host", "onegate.internal"],
  ])("drops a client that speaks plaintext instead of TLS (%s)", async (_label, host) => {
    const socket = await tunnel(host);
    socket.on("error", () => {});
    socket.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    await new Promise<void>((r) => (socket.destroyed ? r() : socket.once("close", () => r())));
    expect(h.seen).toHaveLength(0);
  });

  it("drops a client that sends malformed HTTP over valid TLS, and keeps serving", async () => {
    const socket = await tunnel(VENDOR_HOST);
    const tlsSocket = tls.connect({ socket, servername: VENDOR_HOST, ca: h.caPem });
    tlsSocket.on("error", () => {});
    await new Promise<void>((r) => tlsSocket.once("secureConnect", () => r()));
    tlsSocket.write("THIS IS NOT HTTP\r\n\r\n");
    const reply = await new Promise<string>((r) => {
      let buf = "";
      tlsSocket.on("data", (c) => (buf += c));
      tlsSocket.once("close", () => r(buf));
    });
    // The inner parser's clientError handler destroys the socket outright:
    // no response, nothing forwarded.
    expect(reply).toBe("");
    expect(h.seen).toHaveLength(0);
    const next = await viaProxy(h, { host: VENDOR_HOST, token, path: "/v1/after-garbage" });
    expect(next.status).toBe(200);
  });
});
