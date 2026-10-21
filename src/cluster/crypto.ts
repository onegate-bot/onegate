/**
 * Cluster transport crypto.
 *
 * Peers talk over a dedicated listener, usually across a WireGuard/Tailscale
 * tailnet, but nothing here relies on that link being private:
 *
 *  - Every request is authenticated with an HMAC over method, path+query, the
 *    sender's node id, a timestamp, a random nonce and the body hash, keyed from
 *    the shared cluster secret. A request outside the replay window, or reusing
 *    a nonce inside it, is rejected.
 *  - Every response (and every request body) is sealed with AES-256-GCM under a
 *    key derived from the same secret. The additional data binds a response to
 *    the request nonce that asked for it, so a recorded response cannot be
 *    replayed, and an on-path attacker can neither read config nor inject
 *    changes. The cluster secret itself never crosses the wire.
 *
 * The one exchange that must carry secrets (the DB key, the CA key, the cluster
 * secret) is the join. It is sealed under a key derived from the single-use
 * join token, which the operator moves out of band, so a passive observer
 * without the token learns nothing. Deriving that key on the serving node needs
 * token-equivalent material, so unlike agent tokens a join token cannot be
 * stored as a bare hash: the node keeps the SHA-256 (lookup) plus the derived
 * key sealed with the DB key, and erases the sealed key the moment the token is
 * used or found expired. A leaked database file alone therefore cannot redeem
 * an outstanding token.
 */

import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

const ALGO = "aes-256-gcm";
const IV_LEN = 12;
const TAG_LEN = 16;

/** Allowed clock difference between a request's timestamp and the receiver. */
export const REPLAY_WINDOW_MS = 60_000;

export const HEADER_NODE = "x-onegate-node";
export const HEADER_TS = "x-onegate-ts";
export const HEADER_NONCE = "x-onegate-nonce";
export const HEADER_SIG = "x-onegate-sig";
export const HEADER_JOIN_ID = "x-onegate-join-id";

/** Keys derived from the cluster secret. */
export interface ClusterKeys {
  mac: Buffer;
  seal: Buffer;
}

function hkdf(ikm: Buffer | string, salt: string, info: string): Buffer {
  return Buffer.from(hkdfSync("sha256", ikm, salt, info, 32));
}

export function deriveClusterKeys(secret: string, clusterId: string): ClusterKeys {
  return {
    mac: hkdf(secret, clusterId, "onegate-cluster-v1 request-mac"),
    seal: hkdf(secret, clusterId, "onegate-cluster-v1 transport-seal"),
  };
}

export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/** AES-256-GCM seal of a JSON value. Output: base64(iv | tag | ciphertext). */
export function sealJson(key: Buffer, aad: string, value: unknown): string {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(value), "utf8")), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString("base64");
}

/** Opens sealJson output. Throws on a wrong key, wrong AAD or any tampering. */
export function openJson<T = unknown>(key: Buffer, aad: string, sealed: string): T {
  const raw = Buffer.from(sealed, "base64");
  if (raw.length < IV_LEN + TAG_LEN) throw new Error("sealed payload too short");
  const decipher = createDecipheriv(ALGO, key, raw.subarray(0, IV_LEN));
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(raw.subarray(IV_LEN, IV_LEN + TAG_LEN));
  const pt = Buffer.concat([decipher.update(raw.subarray(IV_LEN + TAG_LEN)), decipher.final()]);
  return JSON.parse(pt.toString("utf8")) as T;
}

function canonical(method: string, path: string, node: string, ts: string, nonce: string, body: string): string {
  return [method.toUpperCase(), path, node, ts, nonce, sha256Hex(body)].join("\n");
}

export function newNonce(): string {
  return randomBytes(16).toString("hex");
}

/** Headers that authenticate one request. `body` is the exact bytes sent. */
export function signRequest(
  keys: ClusterKeys,
  input: { method: string; path: string; nodeId: string; body?: string; nowMs?: number; nonce?: string },
): Record<string, string> {
  const ts = String(input.nowMs ?? Date.now());
  const nonce = input.nonce ?? newNonce();
  const sig = createHmac("sha256", keys.mac)
    .update(canonical(input.method, input.path, input.nodeId, ts, nonce, input.body ?? ""))
    .digest("hex");
  return { [HEADER_NODE]: input.nodeId, [HEADER_TS]: ts, [HEADER_NONCE]: nonce, [HEADER_SIG]: sig };
}

/**
 * Remembers nonces seen inside the replay window. Only requests that already
 * passed the HMAC are recorded, so its size is bounded by legitimate traffic.
 */
export class NonceCache {
  private seen = new Map<string, number>();

  /** Records the nonce; false if it was already seen (a replay). */
  remember(nonce: string, nowMs: number): boolean {
    for (const [n, exp] of this.seen) {
      if (exp > nowMs) break;
      this.seen.delete(n);
    }
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, nowMs + 2 * REPLAY_WINDOW_MS);
    return true;
  }
}

export type VerifyResult = { ok: true; nodeId: string; nonce: string } | { ok: false; reason: string };

/** Verifies a request signed with signRequest. */
export function verifyRequest(
  keys: ClusterKeys,
  input: {
    method: string;
    path: string;
    headers: Record<string, string | string[] | undefined>;
    body: string;
    nonces: NonceCache;
    nowMs?: number;
  },
): VerifyResult {
  const h = (name: string) => {
    const v = input.headers[name];
    return typeof v === "string" ? v : undefined;
  };
  const node = h(HEADER_NODE);
  const ts = h(HEADER_TS);
  const nonce = h(HEADER_NONCE);
  const sig = h(HEADER_SIG);
  if (!node || !ts || !nonce || !sig) return { ok: false, reason: "missing_signature" };
  const now = input.nowMs ?? Date.now();
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum) || Math.abs(now - tsNum) > REPLAY_WINDOW_MS) {
    return { ok: false, reason: "stale_request" };
  }
  const expected = createHmac("sha256", keys.mac)
    .update(canonical(input.method, input.path, node, ts, nonce, input.body))
    .digest();
  const given = Buffer.from(sig, "hex");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    return { ok: false, reason: "bad_signature" };
  }
  if (!input.nonces.remember(nonce, now)) return { ok: false, reason: "replayed_request" };
  return { ok: true, nodeId: node, nonce };
}

/** AAD for a sealed response to the request carrying `nonce`. */
export function responseAad(nonce: string): string {
  return `onegate-cluster-v1 response ${nonce}`;
}

/** AAD for a sealed request body carrying `nonce`. */
export function requestAad(nonce: string): string {
  return `onegate-cluster-v1 request ${nonce}`;
}

// ---- join tokens ----

const JOIN_PREFIX = "ogj_";

export function newJoinToken(): string {
  return JOIN_PREFIX + randomBytes(32).toString("base64url");
}

export function isJoinTokenShaped(token: string): boolean {
  return /^ogj_[A-Za-z0-9_-]{43}$/.test(token);
}

/** Lookup id for a join token: the only token-derived value sent in the clear. */
export function joinTokenId(token: string): string {
  return sha256Hex(`onegate-cluster-join-id ${token}`);
}

/** The token-derived master key; the request and response keys come from it. */
export function joinMasterKey(token: string): Buffer {
  return hkdf(token, "onegate-cluster-join", "onegate-cluster-v1 join-master");
}

export function joinKeys(master: Buffer): { request: Buffer; response: Buffer } {
  return {
    request: hkdf(master, "onegate-cluster-join", "onegate-cluster-v1 join-request"),
    response: hkdf(master, "onegate-cluster-join", "onegate-cluster-v1 join-response"),
  };
}

export function joinAad(direction: "request" | "response", id: string, nonce: string): string {
  return `onegate-cluster-v1 join-${direction} ${id} ${nonce}`;
}

/** Parses a duration like "15m", "2h", "90s" or a bare number of seconds. */
export function parseDurationSeconds(raw: string): number | null {
  const m = /^(\d+)\s*([smhd]?)$/.exec(raw.trim());
  if (!m) return null;
  const n = Number(m[1]);
  const mult = { "": 1, s: 1, m: 60, h: 3600, d: 86400 }[m[2] as "" | "s" | "m" | "h" | "d"];
  return n * mult;
}
