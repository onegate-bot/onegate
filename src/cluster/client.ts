/**
 * Cluster client: signed, sealed requests from this node to a peer's cluster
 * listener, and the join request a new node sends with a join token.
 *
 * Uses node:http/https with a dedicated agent rather than global fetch, for the
 * same reason as the CLI admin client: OneGate often runs with proxy env set,
 * and fetch (undici) would route peer traffic through that proxy.
 */

import http from "node:http";
import https from "node:https";
import {
  HEADER_JOIN_ID,
  joinAad,
  joinKeys,
  joinMasterKey,
  joinTokenId,
  newNonce,
  openJson,
  requestAad,
  responseAad,
  sealJson,
  signRequest,
  type ClusterKeys,
} from "./crypto.js";

/** Per-request timeout. A peer that does not answer is treated as down. */
export const PEER_TIMEOUT_MS = 10_000;

/** A non-2xx answer from a peer (or no answer at all: status 0). */
export class ClusterHttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ClusterHttpError";
  }
}

// No keep-alive: a poll every couple of seconds gains nothing from a pooled
// socket, and a socket pooled across a peer restart fails the next pull.
const httpAgent = new http.Agent({ keepAlive: false });
const httpsAgent = new https.Agent({ keepAlive: false });

function send(
  baseUrl: string,
  method: string,
  path: string,
  headers: Record<string, string>,
  body: string,
): Promise<{ status: number; text: string }> {
  const url = new URL(path, baseUrl);
  const secure = url.protocol === "https:";
  const transport = secure ? https : http;
  return new Promise((resolve, reject) => {
    const req = transport.request(
      url,
      {
        method,
        agent: secure ? httpsAgent : httpAgent,
        timeout: PEER_TIMEOUT_MS,
        headers: {
          accept: "application/json",
          ...(body ? { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) } : {}),
          ...headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c as Buffer));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new Error(`timed out after ${PEER_TIMEOUT_MS}ms`)));
    req.on("error", (err) => reject(new ClusterHttpError(0, "unreachable", `cannot reach ${url.origin}: ${err.message}`)));
    if (body) req.write(body);
    req.end();
  });
}

function parse(status: number, text: string): Record<string, unknown> {
  let json: Record<string, unknown> | null = null;
  try {
    json = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    json = null;
  }
  if (status < 200 || status >= 300) {
    const code = typeof json?.error === "string" ? json.error : `http_${status}`;
    const msg = typeof json?.message === "string" ? `${code}: ${json.message}` : code;
    throw new ClusterHttpError(status, code, `peer answered ${status} (${msg})`);
  }
  if (!json || typeof json.sealed !== "string") throw new ClusterHttpError(status, "bad_response", "peer response is not sealed");
  return json;
}

/**
 * One authenticated call to a peer. The request is HMAC-signed, an optional
 * body is sealed, and the response must open under the transport key bound to
 * this request's nonce, otherwise it is rejected as forged or replayed.
 */
export async function clusterCall<T>(input: {
  url: string;
  method: "GET" | "POST";
  path: string;
  keys: ClusterKeys;
  nodeId: string;
  body?: unknown;
}): Promise<T> {
  const nonce = newNonce();
  const body = input.body === undefined ? "" : JSON.stringify({ sealed: sealJson(input.keys.seal, requestAad(nonce), input.body) });
  const headers = signRequest(input.keys, { method: input.method, path: input.path, nodeId: input.nodeId, body, nonce });
  const res = await send(input.url, input.method, input.path, headers, body);
  const json = parse(res.status, res.text);
  try {
    return openJson<T>(input.keys.seal, responseAad(nonce), json.sealed as string);
  } catch {
    throw new ClusterHttpError(res.status, "unauthenticated_response", "peer response failed authentication (different cluster secret, or tampered)");
  }
}

/** What a node receives when its join is accepted. Carries the crown jewels. */
export interface JoinPayload {
  v: 1;
  clusterId: string;
  clusterSecret: string;
  /** The SecretBox key, base64. */
  dbKey: string;
  caCert: string;
  caKey: string;
  serverNodeId: string;
  snapshot: import("./state.js").ClusterSnapshot;
}

/** Redeems a join token at a peer. Only the token's lookup id travels in clear. */
export async function requestJoin(input: {
  url: string;
  token: string;
  nodeId: string;
  advertiseUrl: string;
}): Promise<JoinPayload> {
  const id = joinTokenId(input.token);
  const keys = joinKeys(joinMasterKey(input.token));
  const nonce = newNonce();
  const body = JSON.stringify({
    nonce,
    sealed: sealJson(keys.request, joinAad("request", id, nonce), {
      nodeId: input.nodeId,
      advertiseUrl: input.advertiseUrl,
      ts: Date.now(),
    }),
  });
  const res = await send(input.url, "POST", "/cluster/v1/join", { [HEADER_JOIN_ID]: id }, body);
  const json = parse(res.status, res.text);
  try {
    return openJson<JoinPayload>(keys.response, joinAad("response", id, nonce), json.sealed as string);
  } catch {
    throw new ClusterHttpError(res.status, "unauthenticated_response", "join response failed authentication");
  }
}
