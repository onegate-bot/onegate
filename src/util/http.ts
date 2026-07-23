/**
 * Minimal direct HTTP helpers. Deliberately not fetch: fetch's global
 * dispatcher may carry an ambient corporate proxy (NODE_USE_ENV_PROXY),
 * and the gateway must always dial endpoints itself.
 */

import http from "node:http";
import https from "node:https";

export interface HttpResult {
  status: number;
  body: string;
}

function send(
  url: string,
  method: string,
  payload: string | null,
  headers: Record<string, string>,
): Promise<HttpResult> {
  const u = new URL(url);
  const mod = u.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const req = mod.request(
      {
        hostname: u.hostname,
        port: u.port || (u.protocol === "https:" ? 443 : 80),
        path: u.pathname + u.search,
        method,
        agent: false,
        headers: {
          ...headers,
          ...(payload !== null ? { "content-length": Buffer.byteLength(payload) } : {}),
        },
      },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on("error", reject);
    req.end(payload ?? undefined);
  });
}

export function postForm(
  url: string,
  form: URLSearchParams,
  headers: Record<string, string> = {},
): Promise<HttpResult> {
  return send(url, "POST", form.toString(), {
    "content-type": "application/x-www-form-urlencoded",
    ...headers,
  });
}

export function postJson(
  url: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<HttpResult> {
  return send(url, "POST", JSON.stringify(body), {
    "content-type": "application/json",
    ...headers,
  });
}
