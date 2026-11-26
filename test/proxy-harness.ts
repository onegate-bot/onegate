/**
 * Shared, fully local harness for end-to-end proxy tests:
 *
 *   client --CONNECT--> GatewayProxy --TLS--> stub "vendor" https server
 *
 * The stub serves a leaf for whatever SNI it is asked for (minted from the
 * same test CA the client trusts), and `upstreamLookup` routes the gateway's
 * outbound connections to it. The stub's behaviour is swappable per test via
 * `h.handler`; every request it receives is recorded in `h.seen`.
 *
 * Not a test file itself (no `.test.ts` suffix), so vitest does not collect it.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { initCa, type Ca } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { Registry } from "../src/integrations/types.js";
import { GatewayProxy, type ProxyOptions } from "../src/proxy/server.js";

export interface SeenRequest {
  method?: string;
  path?: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export type StubHandler = (
  req: http.IncomingMessage,
  res: http.ServerResponse,
  body: string,
) => void;

export interface Harness {
  dir: string;
  ca: Ca;
  caPem: string;
  store: Store;
  registry: Registry;
  proxy: GatewayProxy;
  proxyPort: number;
  stub: https.Server;
  stubPort: number;
  /** Every request the stub vendor received, in order. */
  seen: SeenRequest[];
  /** Lines the proxy logged. */
  logs: string[];
  /** Current stub behaviour; tests may replace it (reset with `resetStub`). */
  handler: StubHandler;
  resetStub(): void;
  close(): Promise<void>;
}

/** Default stub: 200 JSON echo of the path. */
export const echoHandler: StubHandler = (req, res) => {
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: true, path: req.url }));
};

export async function startHarness(
  opts: {
    setup?: (registry: Registry, store: Store) => void;
    /** Extra / overriding proxy options. `upstreamLookup` defaults to the stub. */
    proxy?: (h: { ca: Ca; stubPort: number }) => Partial<ProxyOptions>;
    /** Wrap the CA handed to the proxy (e.g. to make leaf minting fail). */
    wrapCa?: (ca: Ca) => Ca;
  } = {},
): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), "onegate-proxy-h-"));
  const ca = initCa(dir);
  const caPem = ca.rootPem;
  const store = new Store(":memory:");
  const registry = new Registry();
  const seen: SeenRequest[] = [];
  const logs: string[] = [];

  const h = { handler: echoHandler } as Harness;

  const stub = https.createServer(
    {
      SNICallback: (servername, cb) => {
        const leaf = ca.leafFor(servername);
        cb(null, tls.createSecureContext({ key: leaf.key, cert: leaf.cert }));
      },
    },
    (req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        seen.push({ method: req.method, path: req.url, headers: req.headers, body });
        h.handler(req, res, body);
      });
    },
  );
  await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
  const stubPort = (stub.address() as net.AddressInfo).port;

  opts.setup?.(registry, store);

  const proxy = new GatewayProxy({
    ca: opts.wrapCa ? opts.wrapCa(ca) : ca,
    store,
    registry,
    upstreamTls: { ca: caPem },
    upstreamLookup: () => ({ host: "127.0.0.1", port: stubPort }),
    log: (line) => logs.push(line),
    ...(opts.proxy?.({ ca, stubPort }) ?? {}),
  });
  const proxyPort = await proxy.listen(0, "127.0.0.1");

  Object.assign(h, {
    dir,
    ca,
    caPem,
    store,
    registry,
    proxy,
    proxyPort,
    stub,
    stubPort,
    seen,
    logs,
    resetStub() {
      h.handler = echoHandler;
      seen.length = 0;
    },
    async close() {
      await proxy.close();
      stub.closeAllConnections();
      stub.close();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    },
  });
  return h;
}

export function basicAuth(token: string): string {
  return "Basic " + Buffer.from(`agent:${token}`).toString("base64");
}

export interface ProxyReply {
  connectStatus: number;
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  json: any;
}

function parseJson(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Sends one request through the proxy over a fresh CONNECT tunnel, the way a
 * real agent would. A non-200 CONNECT resolves with `status: 0`.
 */
export function viaProxy(
  h: Pick<Harness, "proxyPort" | "caPem">,
  opts: {
    host: string;
    token?: string | null;
    /** Full Proxy-Authorization header value; overrides `token`. */
    proxyAuth?: string;
    method?: string;
    path?: string;
    body?: string | Buffer;
    headers?: Record<string, string>;
    /** CONNECT authority; defaults to `${host}:443`. */
    authority?: string;
  },
): Promise<ProxyReply> {
  return new Promise((resolve, reject) => {
    const connectHeaders: Record<string, string> = {};
    if (opts.proxyAuth !== undefined) connectHeaders["proxy-authorization"] = opts.proxyAuth;
    else if (opts.token) connectHeaders["proxy-authorization"] = basicAuth(opts.token);
    const connectReq = http.request({
      host: "127.0.0.1",
      port: h.proxyPort,
      method: "CONNECT",
      path: opts.authority ?? `${opts.host}:443`,
      headers: connectHeaders,
      agent: false,
    });
    connectReq.on("connect", (connectRes, socket) => {
      if (connectRes.statusCode !== 200) {
        socket.destroy();
        resolve({ connectStatus: connectRes.statusCode ?? 0, status: 0, headers: {}, body: "", json: null });
        return;
      }
      const tlsSocket = tls.connect({ socket, servername: opts.host, ca: h.caPem }, () => {
        const req = https.request(
          {
            createConnection: () => tlsSocket,
            host: opts.host,
            method: opts.method ?? "GET",
            path: opts.path ?? "/",
            headers: opts.headers,
          },
          (res) => {
            let body = "";
            res.on("data", (c) => (body += c));
            res.on("end", () => {
              tlsSocket.end();
              resolve({
                connectStatus: 200,
                status: res.statusCode ?? 0,
                headers: res.headers,
                body,
                json: parseJson(body),
              });
            });
            res.on("error", reject);
          },
        );
        req.on("error", reject);
        if (opts.body !== undefined) req.write(opts.body);
        req.end();
      });
      tlsSocket.on("error", reject);
    });
    connectReq.on("error", reject);
    connectReq.end();
  });
}

/**
 * Sends a raw CONNECT and resolves with the status line the proxy wrote, plus
 * the still-open socket (callers must destroy it).
 */
export function rawConnect(
  port: number,
  authority: string,
  headers: Record<string, string> = {},
  extra: Buffer | string = "",
): Promise<{ statusLine: string; socket: net.Socket; rest: Buffer }> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(port, "127.0.0.1", () => {
      const lines = [`CONNECT ${authority} HTTP/1.1`, `Host: ${authority}`];
      for (const [k, v] of Object.entries(headers)) lines.push(`${k}: ${v}`);
      // Header block and any pipelined bytes go out in ONE write so the proxy
      // sees the trailing bytes as the CONNECT `head`.
      socket.write(Buffer.concat([Buffer.from(lines.join("\r\n") + "\r\n\r\n"), Buffer.from(extra)]));
    });
    let buf = Buffer.alloc(0);
    const onData = (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
      const idx = buf.indexOf("\r\n\r\n");
      if (idx !== -1) {
        socket.off("data", onData);
        socket.off("end", onEnd);
        const statusLine = buf.subarray(0, buf.indexOf("\r\n")).toString();
        resolve({ statusLine, socket, rest: buf.subarray(idx + 4) });
      }
    };
    const onEnd = () => resolve({ statusLine: buf.toString().split("\r\n")[0] ?? "", socket, rest: Buffer.alloc(0) });
    socket.on("data", onData);
    socket.on("end", onEnd);
    socket.on("error", reject);
  });
}

export const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Polls `cond` until it holds (or the timeout passes). */
export async function waitFor(cond: () => boolean, timeoutMs = 2000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timed out");
    await delay(10);
  }
}
