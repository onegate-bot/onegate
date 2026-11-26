/**
 * Hardening of the MITM request path against inputs that used to crash the
 * whole gateway or bypass a deny glob:
 *
 *  - a percent-decoded space/control character in the path made https.request
 *    throw synchronously inside the async inner handler (unhandled rejection,
 *    process exit). The path is now re-encoded for the wire.
 *  - path confusion (`;`, `\`, encoded `?`) is refused with 400 + audit.
 *  - an out-of-range self-mint `ttlDays` threw RangeError in an event listener.
 *  - a write to a reset CONNECT socket before its error listener was attached.
 *  - a ClientHello pipelined in the same packet as CONNECT broke the handshake.
 *
 * Everything runs against a local HTTPS stub; the raw client speaks the
 * request line verbatim so encodings reach the proxy untouched.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { Duplex } from "node:stream";
import { initCa } from "../src/ca.js";
import { Store, parseOnboardingTtlDays, MAX_ONBOARDING_LINK_TTL_DAYS } from "../src/store/db.js";
import { Registry, type Integration } from "../src/integrations/types.js";
import { GatewayProxy } from "../src/proxy/server.js";
import {
  canonicalizeRequestTarget,
  encodePathForUpstream,
  globToRegExp,
  normalizeRequestPath,
  sanitizeQueryForUpstream,
} from "../src/policy.js";
import { auditReason, isOnegateBlock } from "../src/audit-meta.js";
import { DISCOVERY_HOST } from "../src/discovery.js";

const VENDOR = "api.example-vendor.com";
/** An integration whose inject splices an unescaped space into the path. */
const BROKEN = "api.broken-vendor.com";

let dir: string;
let store: Store;
let proxy: GatewayProxy;
let proxyPort: number;
let caPem: string;
let token: string;
let agentId: string;
let stub: https.Server;
const seen: Array<{ path: string; auth: string | undefined }> = [];

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-path-hardening-"));
  const ca = initCa(dir);
  caPem = ca.rootPem;
  store = new Store(":memory:");
  const leaf = ca.leafFor(VENDOR);
  stub = https.createServer({ key: leaf.key, cert: leaf.cert }, (req, res) => {
    req.resume();
    req.on("end", () => {
      seen.push({ path: req.url ?? "", auth: req.headers.authorization });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ path: req.url }));
    });
  });
  await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
  const stubPort = (stub.address() as net.AddressInfo).port;

  const registry = new Registry();
  const vendor: Integration = {
    id: "vendor",
    title: "Vendor",
    hosts: [VENDOR],
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    inject(ctx) {
      ctx.headers.authorization = `Bearer ${ctx.credential.data.apiKey}`;
    },
  };
  registry.register(vendor);
  registry.register({
    id: "broken",
    title: "Broken",
    hosts: [BROKEN],
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    inject(ctx) {
      ctx.path = `${ctx.path}/with space`;
    },
  });
  store.setCredential("broken", "k", { apiKey: "x" });
  store.setCredential("vendor", "k", { apiKey: "REAL-SECRET" });
  const a = store.createAgent("hardening", { defaultPolicy: "deny-unmatched" });
  token = a.token;
  agentId = a.agent.id;
  store.createRule({
    scope: "agent",
    subjectId: agentId,
    integrationId: "vendor",
    methods: ["*"],
    pathGlob: "/v1/**",
    effect: "allow",
  });
  store.createRule({
    scope: "agent",
    subjectId: agentId,
    integrationId: "broken",
    methods: ["*"],
    pathGlob: "/**",
    effect: "allow",
  });
  store.createRule({
    scope: "agent",
    subjectId: agentId,
    integrationId: "vendor",
    methods: ["*"],
    pathGlob: "/v1/admin/**",
    effect: "deny",
  });

  proxy = new GatewayProxy({
    ca,
    store,
    registry,
    upstreamTls: { ca: caPem },
    upstreamLookup: () => ({ host: "127.0.0.1", port: stubPort }),
  });
  proxyPort = await proxy.listen(0, "127.0.0.1");
});

afterAll(async () => {
  await proxy.close();
  await new Promise<void>((r) => stub.close(() => r()));
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  seen.length = 0;
});

function connectHead(host: string): string {
  return (
    `CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}:443\r\n` +
    `Proxy-Authorization: Basic ${Buffer.from(`agent:${token}`).toString("base64")}\r\n\r\n`
  );
}

/** Parses a raw HTTP/1.1 response (headers + chunked or length body). */
function parseResponse(raw: string): { status: number; body: string } {
  const sep = raw.indexOf("\r\n\r\n");
  const head = raw.slice(0, sep);
  let body = raw.slice(sep + 4);
  if (/transfer-encoding: chunked/i.test(head)) {
    let out = "";
    let rest = body;
    for (;;) {
      const nl = rest.indexOf("\r\n");
      if (nl === -1) break;
      const size = parseInt(rest.slice(0, nl), 16);
      if (!size) break;
      out += rest.slice(nl + 2, nl + 2 + size);
      rest = rest.slice(nl + 2 + size + 2);
    }
    body = out;
  }
  return { status: Number(head.split(" ")[1]), body };
}

/**
 * CONNECTs to `host`, then writes `requestLine` verbatim over TLS and returns
 * the parsed response. The request line is never re-encoded by a client lib.
 */
function rawRequest(
  requestLine: string,
  opts: { host?: string; headers?: string; body?: string } = {},
): Promise<{ status: number; body: string }> {
  const host = opts.host ?? VENDOR;
  return new Promise((resolve, reject) => {
    const s = net.connect(proxyPort, "127.0.0.1", () => s.write(connectHead(host)));
    s.on("error", reject);
    let buf = "";
    const onData = (d: Buffer) => {
      buf += d.toString("latin1");
      if (!buf.includes("\r\n\r\n")) return;
      s.off("data", onData);
      if (!buf.startsWith("HTTP/1.1 200")) {
        reject(new Error(`CONNECT failed: ${buf}`));
        return;
      }
      const t = tls.connect({ socket: s, servername: host, ca: caPem }, () => {
        const body = opts.body ?? "";
        t.write(
          `${requestLine} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n` +
            `${opts.headers ?? ""}Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
        );
      });
      let out = "";
      t.on("data", (c: Buffer) => (out += c.toString("latin1")));
      t.on("end", () => resolve(parseResponse(out)));
      t.on("close", () => resolve(parseResponse(out)));
      t.on("error", reject);
    };
    s.on("data", onData);
  });
}

function lastAudit() {
  return store.listAudit({ limit: 1, agentId })[0];
}

describe("canonicalizeRequestTarget (unit)", () => {
  it("re-encodes everything outside pchar, keeping '/' as separator", () => {
    expect(encodePathForUpstream("/v1/a b")).toBe("/v1/a%20b");
    expect(encodePathForUpstream("/v1/\x00\x01\r\n\x7f")).toBe("/v1/%00%01%0D%0A%7F");
    expect(encodePathForUpstream("/v1/100%/x#y?z")).toBe("/v1/100%25/x%23y%3Fz");
    expect(encodePathForUpstream("/v1/a-b._~!$&'()*+,=:@")).toBe("/v1/a-b._~!$&'()*+,=:@");
    expect(encodePathForUpstream('/v1/"<>{}|^`[]')).toBe("/v1/%22%3C%3E%7B%7D%7C%5E%60%5B%5D");
    // Latin1 code units are bytes (preserves raw UTF-8 bytes exactly); above
    // 0xFF is UTF-8 encoded.
    expect(encodePathForUpstream("/v1/\xc3\xa9")).toBe("/v1/%C3%A9");
    expect(encodePathForUpstream("/v1/☃")).toBe("/v1/%E2%98%83");
  });

  it("the vendor's single decode of the forwarded path equals the policy path", () => {
    for (const raw of ["/v1/a%20b", "/v1/a%2520b", "/v1/x%23y", "/v1/%25", "/v1/%C3%A9", "/v1/%00"]) {
      const t = canonicalizeRequestTarget(raw);
      const forwardedPath = t.forward.split("?")[0];
      const vendorView = Buffer.from(decodeURIComponent(forwardedPath), "utf8").toString("utf8");
      const policyView = Buffer.from(t.path, "latin1").toString("utf8");
      expect(vendorView).toBe(policyView);
    }
  });

  it("keeps the query verbatim and only makes it wire-safe", () => {
    const t = canonicalizeRequestTarget("/v1/a%20b?q=a%2Fb&x=%20y");
    expect(t.path).toBe("/v1/a b?q=a%2Fb&x=%20y");
    expect(t.forward).toBe("/v1/a%20b?q=a%2Fb&x=%20y");
    expect(sanitizeQueryForUpstream("?a=b c\x01é")).toBe("?a=b%20c%01%E9");
  });

  it("keeps %2F, '..' and '//' behaviour exactly as normalizeRequestPath had it", () => {
    // %2F decodes to a real separator (deny-evasion fix), forwarded as '/'.
    expect(canonicalizeRequestTarget("/repos%2Fo%2Fr/pulls")).toMatchObject({
      path: "/repos/o/r/pulls",
      forward: "/repos/o/r/pulls",
      rejectReason: null,
    });
    expect(canonicalizeRequestTarget("//repos/x/../o//r").forward).toBe("/repos/o/r");
    // A literal %2F needs double encoding; it stays literal end to end.
    const dbl = canonicalizeRequestTarget("/projects/group%252Fproj");
    expect(dbl.path).toBe("/projects/group%2Fproj");
    expect(dbl.forward).toBe("/projects/group%252Fproj");
    expect(normalizeRequestPath("/projects/group%252Fproj")).toBe(dbl.path);
  });

  it("rejects ';', '\\', an encoded '?' and non-origin-form targets", () => {
    for (const raw of [
      "/v1/admin;x/users",
      "/v1/admin%3bx/users",
      "/v1/admin%5cusers",
      "/v1/admin\\users",
      "/v1/admin%3F/users",
      "http://evil.example/v1/x",
      "*",
    ]) {
      expect(canonicalizeRequestTarget(raw).rejectReason, raw).toBeTruthy();
    }
    expect(canonicalizeRequestTarget("/v1/x?a=1;b=2").rejectReason).toBeNull();
  });

  it("a deny '/**' glob also matches a decoded newline (dotAll)", () => {
    const deny = globToRegExp("/v1/admin/**", true);
    const allow = globToRegExp("/v1/*/*");
    const p = normalizeRequestPath("/v1/admin/x%0a");
    expect(allow.test(p)).toBe(true);
    expect(deny.test(p)).toBe(true);
  });

  it("invalid_path is an OneGate block with a plain-words reason", () => {
    expect(isOnegateBlock("invalid_path")).toBe(true);
    expect(auditReason({ decision: "invalid_path", ruleId: null, status: 400 })).toContain("Blocked by OneGate");
  });
});

describe("decoded paths never crash the gateway", () => {
  it("forwards GET /v1/a%20b as /v1/a%20b and keeps serving", async () => {
    const r = await rawRequest("GET /v1/a%20b");
    expect(r.status).toBe(200);
    expect(seen.map((s) => s.path)).toEqual(["/v1/a%20b"]);
    expect(seen[0].auth).toBe("Bearer REAL-SECRET");
    const again = await rawRequest("GET /v1/ok");
    expect(again.status).toBe(200);
  });

  it("forwards encoded control characters re-encoded", async () => {
    const r = await rawRequest("GET /v1/x%00%0d%0a%09%7fy");
    expect(r.status).toBe(200);
    expect(seen.map((s) => s.path)).toEqual(["/v1/x%00%0D%0A%09%7Fy"]);
    expect((await rawRequest("GET /v1/ok")).status).toBe(200);
  });

  it("forwards %252f and %23 encoded so the vendor sees what policy saw", async () => {
    expect((await rawRequest("GET /v1/admin%252fusers")).status).toBe(200);
    expect((await rawRequest("GET /v1/admin%23")).status).toBe(200);
    expect(seen.map((s) => s.path)).toEqual(["/v1/admin%252fusers", "/v1/admin%23"]);
  });

  it("still denies the canonical forms of the deny glob", async () => {
    for (const p of ["/v1/admin/users", "/v1/admin%2fusers", "/v1/%2e%2e/v1/admin/x", "/v1//admin/x"]) {
      expect((await rawRequest(`GET ${p}`)).status, p).toBe(403);
    }
    expect(seen).toEqual([]);
  });
});

describe("inner request handler safety net", () => {
  it("a throw inside the async handler fails only that request with 500", async () => {
    // https.request throws ERR_UNESCAPED_CHARACTERS synchronously on the
    // spliced space; before the .catch this was an unhandled rejection.
    const r = await rawRequest("GET /v1/x", { host: BROKEN });
    expect(r.status).toBe(500);
    expect(JSON.parse(r.body).error).toBe("onegate_internal_error");
    expect(seen).toEqual([]);
    expect((await rawRequest("GET /v1/ok")).status).toBe(200);
  });
});

describe("path confusion is rejected with 400 and audited", () => {
  for (const p of [
    "/v1/admin;x/users",
    "/v1/admin%3bx/users",
    "/v1/admin%5cusers",
    "/v1/admin\\users",
    "/v1/admin%3F/users",
    "http://evil.example/v1/admin/x",
  ]) {
    it(`GET ${p} -> 400 invalid_path, never forwarded`, async () => {
      const r = await rawRequest(`GET ${p}`);
      expect(r.status).toBe(400);
      expect(JSON.parse(r.body).error).toBe("onegate_invalid_path");
      expect(seen).toEqual([]);
      const row = lastAudit();
      expect(row.decision).toBe("invalid_path");
      expect(row.status).toBe(400);
      expect(row.path).toBe(p);
      expect(row.source).toBe("onegate");
    });
  }
});

describe("self-mint ttlDays", () => {
  beforeAll(() => {
    expect(MAX_ONBOARDING_LINK_TTL_DAYS).toBe(90);
  });

  const mint = (body: unknown) => {
    const json = typeof body === "string" ? body : JSON.stringify(body);
    return rawRequest("POST /connect-links", {
      host: DISCOVERY_HOST,
      headers: "Content-Type: application/json\r\n",
      body: json,
    });
  };

  for (const ttlDays of [1e9, 0, -1, 1.5, 91, "7", Number.MAX_VALUE]) {
    it(`ttlDays ${String(ttlDays)} -> 400 and the gateway keeps serving`, async () => {
      const r = await mint({ integrationId: "vendor", ttlDays });
      expect(r.status).toBe(400);
      expect(JSON.parse(r.body).error).toBe("invalid_ttl_days");
      expect((await rawRequest("GET /v1/ok")).status).toBe(200);
    });
  }

  it("a valid ttlDays mints a link expiring that many days out", async () => {
    const r = await mint({ integrationId: "vendor", ttlDays: 30 });
    expect(r.status).toBe(201);
    const days = (Date.parse(JSON.parse(r.body).expiresAt) - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(29.9);
    expect(days).toBeLessThan(30.1);
  });

  it("a non-object JSON body is 400, not a crash", async () => {
    for (const body of ["null", "[]", "42"]) {
      const r = await mint(body);
      expect(r.status, body).toBe(400);
    }
  });

  it("parseOnboardingTtlDays bounds", () => {
    expect(parseOnboardingTtlDays(undefined)).toBeUndefined();
    expect(parseOnboardingTtlDays(1)).toBe(1);
    expect(parseOnboardingTtlDays(90)).toBe(90);
    expect(parseOnboardingTtlDays(91)).toBeNull();
    expect(parseOnboardingTtlDays(Number.NaN)).toBeNull();
    expect(() => store.createOnboardingLink({ agentId, integrationId: "vendor", ttlDays: 1e9 })).toThrow(
      /ttlDays must be an integer/,
    );
  });
});

describe("CONNECT socket handling", () => {
  it("a client reset racing the 400 for an invalid host does not crash the proxy", async () => {
    for (let i = 0; i < 5; i++) {
      const s = net.createConnection(proxyPort, "127.0.0.1");
      s.on("error", () => {});
      await new Promise<void>((r) => s.once("connect", () => r()));
      s.write("CONNECT bad_host!:443 HTTP/1.1\r\nHost: x\r\n\r\n");
      s.resetAndDestroy();
    }
    await new Promise((r) => setTimeout(r, 200));
    expect((await rawRequest("GET /v1/ok")).status).toBe(200);
  });

  it("a ClientHello pipelined in the same write as CONNECT completes the handshake", async () => {
    const r = await new Promise<{ status: number; body: string }>((resolve, reject) => {
      const s = net.connect(proxyPort, "127.0.0.1");
      s.on("error", reject);
      let first = true;
      let connected = false;
      let pending = Buffer.alloc(0);
      // A duplex in front of the raw socket: the first TLS write (the
      // ClientHello) is glued onto the CONNECT head in ONE socket write.
      const wire = new Duplex({
        write(chunk: Buffer, _enc, cb) {
          if (first) {
            first = false;
            s.write(Buffer.concat([Buffer.from(connectHead(VENDOR)), chunk]));
          } else {
            s.write(chunk);
          }
          cb();
        },
        read() {},
      });
      s.on("data", (d: Buffer) => {
        if (connected) {
          wire.push(d);
          return;
        }
        pending = Buffer.concat([pending, d]);
        const idx = pending.indexOf("\r\n\r\n");
        if (idx === -1) return;
        const head = pending.subarray(0, idx).toString();
        if (!head.startsWith("HTTP/1.1 200")) return reject(new Error(head));
        connected = true;
        const rest = pending.subarray(idx + 4);
        if (rest.length) wire.push(rest);
      });
      s.on("end", () => wire.push(null));
      s.once("connect", () => {
        const t = tls.connect({ socket: wire, servername: VENDOR, ca: caPem }, () => {
          t.write(`GET /v1/pipelined HTTP/1.1\r\nHost: ${VENDOR}\r\nConnection: close\r\n\r\n`);
        });
        let out = "";
        t.on("data", (c: Buffer) => (out += c.toString()));
        t.on("end", () => resolve(parseResponse(out)));
        t.on("error", reject);
      });
    });
    expect(r.status).toBe(200);
    expect(seen.map((s) => s.path)).toEqual(["/v1/pipelined"]);
  });
});
