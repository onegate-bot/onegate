/**
 * Thin admin API client for the OneGate CLI.
 *
 * The CLI talks to a LOCAL admin API on the same host as the server. OneGate
 * itself often runs behind a MITM proxy, and global fetch
 * (undici) captures HTTPS_PROXY at bootstrap, which would mis-route a call to
 * localhost through that proxy. To stay correct we use node:http / node:https
 * directly with a dedicated agent that never consults proxy env, exactly the
 * "dedicated agent, never fetch" rule the gateway code already follows.
 */

import http from "node:http";
import https from "node:https";
import { Store, hashToken } from "../store/db.js";

const ADMIN_TOKEN_KEY = "admin_token_hash";

export interface ClientOptions {
  /** Base URL of the admin API, e.g. http://localhost:8080 */
  host: string;
  /** Admin bearer token (oga_...). */
  token: string;
}

export interface ApiResponse {
  status: number;
  /** Parsed JSON body when the response was JSON, otherwise undefined. */
  body: unknown;
  /** Raw text body (always present). */
  raw: string;
}

/** Raised for any non-2xx admin API response, with a clean message. */
export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, body: unknown, raw: string) {
    super(messageFor(status, body, raw));
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

function messageFor(status: number, body: unknown, raw: string): string {
  if (status === 401) return "admin token rejected (401). Check --token or ONEGATE_ADMIN_TOKEN.";
  if (status === 403) return "forbidden (403).";
  const b = body as { error?: string; message?: string } | undefined;
  if (b && typeof b === "object" && (b.error || b.message)) {
    const parts = [b.error, b.message].filter(Boolean);
    return `API error ${status}: ${parts.join(" - ")}`;
  }
  const snippet = raw.trim().slice(0, 200);
  return snippet ? `API error ${status}: ${snippet}` : `API error ${status}`;
}

export class AdminClient {
  private readonly base: URL;
  private readonly token: string;
  private readonly agent: http.Agent | https.Agent;
  private readonly transport: typeof http | typeof https;

  constructor(opts: ClientOptions) {
    this.base = new URL(opts.host);
    this.token = opts.token;
    const secure = this.base.protocol === "https:";
    this.transport = secure ? https : http;
    // A dedicated agent with proxy env ignored. node:http honors proxy env
    // only when NODE_USE_ENV_PROXY is set, but a fresh agent keeps us safe and
    // explicit regardless of the runtime.
    this.agent = secure ? new https.Agent() : new http.Agent();
  }

  /** Performs a request and returns the raw response without throwing on 4xx/5xx. */
  raw(method: string, path: string, body?: unknown): Promise<ApiResponse> {
    const url = new URL(path, this.base);
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const headers: Record<string, string> = {
      authorization: `Bearer ${this.token}`,
      accept: "application/json",
    };
    if (payload) {
      headers["content-type"] = "application/json";
      headers["content-length"] = String(payload.length);
    }
    return new Promise<ApiResponse>((resolve, reject) => {
      const req = this.transport.request(
        url,
        { method, agent: this.agent, headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c as Buffer));
          res.on("end", () => {
            const raw = Buffer.concat(chunks).toString("utf8");
            let parsed: unknown;
            try {
              parsed = raw ? JSON.parse(raw) : undefined;
            } catch {
              parsed = undefined;
            }
            resolve({ status: res.statusCode ?? 0, body: parsed, raw });
          });
        },
      );
      req.on("error", (err) =>
        reject(new Error(`cannot reach admin API at ${this.base.origin}: ${err.message}`)),
      );
      if (payload) req.write(payload);
      req.end();
    });
  }

  /** Performs a request and throws ApiError on any non-2xx response. */
  async request(method: string, path: string, body?: unknown): Promise<unknown> {
    const res = await this.raw(method, path, body);
    if (res.status < 200 || res.status >= 300) {
      throw new ApiError(res.status, res.body, res.raw);
    }
    return res.body;
  }

  get(path: string): Promise<unknown> {
    return this.request("GET", path);
  }
  post(path: string, body?: unknown): Promise<unknown> {
    return this.request("POST", path, body);
  }
  put(path: string, body?: unknown): Promise<unknown> {
    return this.request("PUT", path, body);
  }
  patch(path: string, body?: unknown): Promise<unknown> {
    return this.request("PATCH", path, body);
  }
  del(path: string): Promise<unknown> {
    return this.request("DELETE", path);
  }
}

/**
 * Resolves the admin token from (in order): explicit --token, the
 * ONEGATE_ADMIN_TOKEN env var. There is no way to recover the plaintext token
 * from the store (only its hash is kept), so when neither is given we fail with
 * a clear message rather than guessing.
 */
export function resolveToken(explicit: string | undefined): string {
  const token = explicit ?? process.env.ONEGATE_ADMIN_TOKEN;
  if (!token) {
    throw new Error(
      "no admin token. Pass --token <oga_...> or set ONEGATE_ADMIN_TOKEN.",
    );
  }
  return token;
}

/**
 * Same-host sanity check: confirms the given token hashes to the admin token
 * hash stored locally. Only usable when the CLI runs on the server box with
 * access to the store. Returns true when it matches, false otherwise. Never
 * reveals the token.
 */
export function tokenMatchesStore(store: Store, token: string): boolean {
  const stored = store.getSetting(ADMIN_TOKEN_KEY);
  return Boolean(stored) && stored === hashToken(token);
}

export function resolveHost(explicit: string | undefined): string {
  return explicit ?? process.env.ONEGATE_ADMIN_URL ?? "http://localhost:8080";
}
