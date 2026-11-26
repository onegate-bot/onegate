/**
 * Shared harness for the admin API coverage suites: a real admin app on an
 * ephemeral 127.0.0.1 port over an in-memory Store, plus raw HTTP helpers that
 * never go through fetch (so no ambient proxy env can reroute them).
 *
 * Not a test file itself (no `.test.ts` suffix), imported by
 * admin-api-*.test.ts.
 */

import http from "node:http";
import { Store } from "../src/store/db.js";
import { buildRegistry } from "../src/integrations/index.js";
import type { Registry } from "../src/integrations/types.js";
import { createAdminApp, ensureAdminToken, type AdminApiOptions } from "../src/admin/api.js";

export interface Res {
  status: number;
  text: string;
  json: any;
  headers: http.IncomingHttpHeaders;
}

export interface AdminHarness {
  store: Store;
  registry: Registry;
  token: string;
  port: number;
  base: string;
  /** JSON request; `token: null` sends no Authorization header. */
  api(method: string, path: string, body?: unknown, token?: string | null): Promise<Res>;
  /** Request with an arbitrary raw Authorization header value (or none). */
  rawAuth(method: string, path: string, authorization: string | undefined): Promise<Res>;
  /** Unauthenticated GET (public pages). */
  get(path: string): Promise<Res>;
  /** Unauthenticated urlencoded form POST (public pages). */
  postForm(path: string, fields?: Record<string, string | string[]>): Promise<Res>;
  close(): Promise<void>;
}

function send(
  port: number,
  method: string,
  path: string,
  headers: Record<string, string | number>,
  payload: string | null,
): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method, path, agent: false, headers },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          let json: any = null;
          try {
            json = JSON.parse(text);
          } catch {
            /* non-JSON body */
          }
          resolve({ status: res.statusCode ?? 0, text, json, headers: res.headers });
        });
      },
    );
    req.on("error", reject);
    if (payload !== null) req.write(payload);
    req.end();
  });
}

export async function startAdmin(
  extra: Partial<Omit<AdminApiOptions, "store" | "registry" | "ca" | "version">> & {
    registry?: Registry;
  } = {},
): Promise<AdminHarness> {
  const store = new Store(":memory:");
  const token = ensureAdminToken(store)!;
  const registry = extra.registry ?? (await buildRegistry());
  // publicBaseUrl is filled in once the port is known (links must point back
  // at this server), so the app reads it lazily through a mutable object.
  const opts: AdminApiOptions = {
    store,
    registry,
    ca: { rootPem: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n" } as never,
    version: "test-version",
    ...extra,
  };
  const app = createAdminApp(opts);
  const server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  const base = `http://127.0.0.1:${port}`;

  // Reads the token from the harness object so a test that rotates it
  // (resetAdminToken) can update h.token and keep using the default.
  const api: AdminHarness["api"] = (method, path, body, tok = h.token) => {
    const payload = body === undefined ? null : JSON.stringify(body);
    return send(
      port,
      method,
      path,
      {
        ...(payload !== null
          ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) }
          : {}),
        ...(tok ? { authorization: `Bearer ${tok}` } : {}),
      },
      payload,
    );
  };

  const h: AdminHarness = {
    store,
    registry,
    token,
    port,
    base,
    api,
    rawAuth: (method, path, authorization) =>
      send(port, method, path, authorization === undefined ? {} : { authorization }, null),
    get: (path) => send(port, "GET", path, {}, null),
    postForm: (path, fields = {}) => {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(fields)) {
        for (const one of Array.isArray(v) ? v : [v]) params.append(k, one);
      }
      const payload = params.toString();
      return send(
        port,
        "POST",
        path,
        {
          "content-type": "application/x-www-form-urlencoded",
          "content-length": Buffer.byteLength(payload),
        },
        payload,
      );
    },
    close: async () => {
      await new Promise<void>((r) => server.close(() => r()));
      store.close();
    },
  };
  return h;
}

/** Stub OAuth token endpoint whose response each test can swap. */
export async function startTokenStub(): Promise<{
  url: string;
  respond: (fn: () => { status: number; body: unknown }) => void;
  requests: string[];
  close: () => Promise<void>;
}> {
  let responder: () => { status: number; body: unknown } = () => ({
    status: 200,
    body: { access_token: "at_default", refresh_token: "rt_default", expires_in: 3600 },
  });
  const requests: string[] = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      requests.push(raw);
      const out = responder();
      res.writeHead(out.status, { "content-type": "application/json" });
      res.end(JSON.stringify(out.body));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  return {
    url: `http://127.0.0.1:${port}`,
    respond: (fn) => {
      responder = fn;
    },
    requests,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}
