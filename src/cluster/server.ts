/**
 * The cluster listener: the HTTP surface peers pull from. It runs on its own
 * address/port (ONEGATE_CLUSTER_LISTEN), separate from the agent proxy and the
 * admin API, so it can be bound to a tailnet interface only and firewalled on
 * its own. Off unless configured.
 *
 *   GET  /cluster/v1/hello                  who are you (node id, cluster id, head)
 *   GET  /cluster/v1/changes?since=&limit=  a page of this node's own changes
 *   GET  /cluster/v1/snapshot               every shared row + versions + cursors
 *   POST /cluster/v1/leave                  a peer announces it is leaving
 *   POST /cluster/v1/join                   a new node redeems a join token
 *
 * Every route except join requires a request signed with the cluster secret and
 * answers with a body sealed to that request (src/cluster/crypto.ts). Join is
 * authenticated by the single-use join token and sealed with a key derived from
 * it. Error bodies are plain JSON codes and carry no data.
 */

import http from "node:http";
import type { Store } from "../store/db.js";
import { isValidNodeId } from "../store/cluster-schema.js";
import {
  HEADER_JOIN_ID,
  NonceCache,
  REPLAY_WINDOW_MS,
  joinAad,
  joinKeys,
  openJson,
  requestAad,
  responseAad,
  sealJson,
  verifyRequest,
} from "./crypto.js";
import { ClusterError, ClusterState, validateClusterUrl } from "./state.js";
import type { JoinPayload } from "./client.js";

/** Request bodies on this listener are tiny (join, leave). */
const MAX_BODY_BYTES = 64 * 1024;

export interface ClusterServerOptions {
  store: Store;
  state: ClusterState;
  /** The root CA PEMs to hand a joining node, or null if unavailable. */
  caFiles: () => { cert: string; key: string } | null;
  log?: (line: string) => void;
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new ClusterError(413, "body_too_large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text), "cache-control": "no-store" });
  res.end(text);
}

/** Builds the request handler (exported separately so tests can mount it). */
export function createClusterHandler(opts: ClusterServerOptions): http.RequestListener {
  const { store, state } = opts;
  const nonces = new NonceCache();
  const log = opts.log ?? (() => {});

  async function handleJoin(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const id = req.headers[HEADER_JOIN_ID];
    if (typeof id !== "string" || !/^[0-9a-f]{64}$/.test(id)) throw new ClusterError(401, "invalid_join_token");
    const raw = await readBody(req);
    let body: { nonce?: unknown; sealed?: unknown };
    try {
      body = JSON.parse(raw);
    } catch {
      throw new ClusterError(400, "invalid_body");
    }
    if (typeof body.nonce !== "string" || typeof body.sealed !== "string") throw new ClusterError(400, "invalid_body");
    const keys = joinKeys(state.joinMaster(id));
    let request: { nodeId?: unknown; advertiseUrl?: unknown; ts?: unknown };
    try {
      request = openJson(keys.request, joinAad("request", id, body.nonce), body.sealed);
    } catch {
      // Not proof of the token: do not spend it, so a garbled attempt cannot
      // burn the operator's token.
      throw new ClusterError(401, "invalid_join_token");
    }
    if (typeof request.ts !== "number" || Math.abs(Date.now() - request.ts) > REPLAY_WINDOW_MS) {
      throw new ClusterError(401, "stale_request");
    }
    if (typeof request.nodeId !== "string" || !isValidNodeId(request.nodeId)) throw new ClusterError(400, "invalid_node_id");
    if (request.nodeId === state.peekNodeId()) throw new ClusterError(409, "node_id_in_use", "the joining node has this node's id");
    const advertiseUrl = validateClusterUrl(request.advertiseUrl);
    const ca = opts.caFiles();
    if (!ca) throw new ClusterError(500, "ca_unavailable", "this node cannot read its root CA files");
    if (!state.claimJoinToken(id)) throw new ClusterError(410, "join_token_used");
    store.syncClusterCapture();
    // Captured, so every existing peer learns the new member and starts
    // pulling from it; included in the snapshot below for the joiner itself.
    state.upsertPeer(request.nodeId, advertiseUrl);
    const payload: JoinPayload = {
      v: 1,
      clusterId: state.clusterId()!,
      clusterSecret: state.secret(),
      dbKey: store.clusterInternals().secretKey.toString("base64"),
      caCert: ca.cert,
      caKey: ca.key,
      serverNodeId: state.peekNodeId()!,
      snapshot: state.snapshot(),
    };
    log(`node ${request.nodeId} joined from ${advertiseUrl}`);
    sendJson(res, 200, { sealed: sealJson(keys.response, joinAad("response", id, body.nonce), payload) });
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const method = req.method ?? "GET";
    const path = req.url ?? "/";
    const url = new URL(path, "http://cluster.invalid");
    if (!state.isEnabled()) throw new ClusterError(503, "cluster_not_initialized");
    if (method === "POST" && url.pathname === "/cluster/v1/join") return handleJoin(req, res);

    const raw = method === "POST" ? await readBody(req) : "";
    const v = verifyRequest(state.keys(), { method, path, headers: req.headers, body: raw, nonces });
    if (!v.ok) throw new ClusterError(401, v.reason);
    // A long-running server may have joined/left via another process.
    store.syncClusterCapture();
    const keys = state.keys();
    const reply = (value: unknown) => sendJson(res, 200, { sealed: sealJson(keys.seal, responseAad(v.nonce), value) });

    if (method === "GET" && url.pathname === "/cluster/v1/hello") {
      return reply({ nodeId: state.peekNodeId(), clusterId: state.clusterId(), head: state.head(), now: Date.now() });
    }
    if (method === "GET" && url.pathname === "/cluster/v1/changes") {
      const since = Number(url.searchParams.get("since") ?? "0");
      const limit = Number(url.searchParams.get("limit") ?? "500");
      const page = state.changesSince(since, limit, v.nodeId);
      return reply({ nodeId: state.peekNodeId(), ...page, now: Date.now() });
    }
    if (method === "GET" && url.pathname === "/cluster/v1/snapshot") {
      return reply(state.snapshot());
    }
    if (method === "POST" && url.pathname === "/cluster/v1/leave") {
      let parsed: { sealed?: unknown };
      try {
        parsed = JSON.parse(raw);
      } catch {
        throw new ClusterError(400, "invalid_body");
      }
      if (typeof parsed.sealed !== "string") throw new ClusterError(400, "invalid_body");
      const inner = openJson<{ nodeId?: unknown }>(keys.seal, requestAad(v.nonce), parsed.sealed);
      if (inner.nodeId !== v.nodeId) throw new ClusterError(400, "node_mismatch", "a node may only announce its own departure");
      const removed = state.removePeer(v.nodeId);
      log(`node ${v.nodeId} left the cluster`);
      return reply({ removed });
    }
    throw new ClusterError(404, "not_found");
  }

  return (req, res) => {
    handle(req, res).catch((err) => {
      if (err instanceof ClusterError) {
        sendJson(res, err.status, { error: err.code, ...(err.message !== err.code ? { message: err.message } : {}) });
        return;
      }
      log(`request failed: ${(err as Error).message}`);
      sendJson(res, 500, { error: "internal_error" });
    });
  };
}
