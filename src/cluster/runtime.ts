/**
 * Cluster runtime for a running gateway: the optional cluster listener and the
 * replication loop that pulls every peer's changes.
 *
 * The loop is a self-rescheduling timer (never overlapping runs). Each tick,
 * for every peer that is not backing off, it pulls pages of changes from the
 * peer's cursor until the peer reports no more, applying each page in one
 * transaction. A failing peer backs off exponentially (2s, 4s, ... capped at
 * 60s) and is retried; the other peers are unaffected. Every ten minutes the
 * tick also compacts the changelog.
 *
 * Nothing runs for a node that is not in a cluster: refresh() only starts the
 * timer once the node is a member, and stops it after a leave.
 */

import http from "node:http";
import type { Store } from "../store/db.js";
import { clusterCall, ClusterHttpError } from "./client.js";
import { createClusterHandler } from "./server.js";
import { ClusterError, ClusterState, validateClusterUrl, type ApplyResult, type ClusterChange, type ClusterPeer, type ClusterStatus } from "./state.js";

export const DEFAULT_POLL_INTERVAL_MS = 2_000;
export const MAX_BACKOFF_MS = 60_000;
/** Changelog history kept even after every peer has pulled it. */
export const DEFAULT_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const COMPACT_EVERY_MS = 10 * 60 * 1000;
const PAGE_SIZE = 500;
/** Pages pulled from one peer in one tick before yielding to the others. */
const MAX_PAGES_PER_TICK = 20;

export interface ClusterRuntimeOptions {
  store: Store;
  caFiles?: () => { cert: string; key: string } | null;
  log?: (line: string) => void;
  pollIntervalMs?: number;
  retentionMs?: number;
}

interface PeerLoopState {
  failures: number;
  nextAt: number;
}

/** Resolves ONEGATE_CLUSTER_RETENTION_DAYS (whole or fractional days). */
export function retentionMsFromEnv(raw = process.env.ONEGATE_CLUSTER_RETENTION_DAYS): number {
  const n = Number(raw);
  return raw && Number.isFinite(n) && n > 0 ? n * 86_400_000 : DEFAULT_RETENTION_MS;
}

/**
 * Parses ONEGATE_CLUSTER_LISTEN: "port", "host:port" or "[v6]:port". Returns
 * null when unset (the listener is off by default).
 */
export function parseClusterListen(raw: string | undefined, defaultHost: string): { host: string; port: number } | null {
  if (!raw || !raw.trim()) return null;
  const s = raw.trim();
  const m = /^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/.exec(s);
  const host = m ? (m[1] ?? m[2]) : defaultHost;
  const port = Number(m ? m[3] : s);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`ONEGATE_CLUSTER_LISTEN must be "port" or "host:port", got "${raw}"`);
  }
  return { host, port };
}

export class ClusterRuntime {
  readonly state: ClusterState;
  private readonly store: Store;
  private readonly log: (line: string) => void;
  private readonly pollIntervalMs: number;
  private readonly retentionMs: number;
  private readonly caFiles: () => { cert: string; key: string } | null;
  private server: http.Server | null = null;
  private listenAddress: string | null = null;
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private ticking: Promise<void> | null = null;
  private lastCompactAt = 0;
  private peers = new Map<string, PeerLoopState>();

  constructor(opts: ClusterRuntimeOptions) {
    this.store = opts.store;
    this.state = new ClusterState(opts.store);
    this.log = opts.log ?? (() => {});
    this.pollIntervalMs = opts.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    this.retentionMs = opts.retentionMs ?? DEFAULT_RETENTION_MS;
    this.caFiles = opts.caFiles ?? (() => null);
  }

  /** Starts the cluster listener. Resolves to the bound port. */
  async listen(port: number, host: string): Promise<number> {
    const server = http.createServer(createClusterHandler({ store: this.store, state: this.state, caFiles: this.caFiles, log: this.log }));
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => resolve());
    });
    this.server = server;
    const bound = (server.address() as { port: number }).port;
    this.listenAddress = `${host}:${bound}`;
    return bound;
  }

  /** "host:port" of the cluster listener, or null when it is off. */
  listening(): string | null {
    return this.listenAddress;
  }

  /**
   * Re-reads membership: syncs the capture triggers and starts or stops the
   * replication loop. Call after init/join/leave and once at boot.
   */
  refresh(): void {
    const enabled = this.store.syncClusterCapture();
    if (enabled && !this.running) {
      this.running = true;
      this.schedule(0);
      this.log(`replicating as ${this.state.peekNodeId()} in ${this.state.clusterId()}`);
    } else if (!enabled && this.running) {
      this.stopLoop();
    }
  }

  private schedule(delay: number): void {
    if (!this.running) return;
    this.timer = setTimeout(() => {
      this.ticking = this.tick().finally(() => {
        this.ticking = null;
        this.schedule(this.pollIntervalMs);
      });
    }, delay);
    this.timer.unref();
  }

  private stopLoop(): void {
    this.running = false;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private async tick(): Promise<void> {
    // Another process may have run `cluster leave` (or init) on this DB.
    if (!this.store.syncClusterCapture()) {
      this.stopLoop();
      return;
    }
    await this.pollOnce();
    if (Date.now() - this.lastCompactAt > COMPACT_EVERY_MS) {
      this.lastCompactAt = Date.now();
      try {
        const n = this.state.compact(this.retentionMs);
        if (n) this.log(`compacted ${n} changelog entries`);
      } catch (err) {
        this.log(`compaction failed: ${(err as Error).message}`);
      }
    }
  }

  /** Pulls every due peer once. Public so tests can drive replication deterministically. */
  async pollOnce(): Promise<void> {
    if (!this.state.isEnabled()) return;
    const self = this.state.peekNodeId();
    const now = Date.now();
    const peers = this.state.listPeers().filter((p) => p.nodeId !== self);
    for (const id of [...this.peers.keys()]) {
      if (!peers.some((p) => p.nodeId === id)) this.peers.delete(id);
    }
    await Promise.all(
      peers.map(async (peer) => {
        const ls = this.peers.get(peer.nodeId) ?? { failures: 0, nextAt: 0 };
        this.peers.set(peer.nodeId, ls);
        if (ls.nextAt > now) return;
        try {
          await this.pullPeer(peer);
          ls.failures = 0;
          ls.nextAt = 0;
        } catch (err) {
          ls.failures += 1;
          ls.nextAt = Date.now() + Math.min(MAX_BACKOFF_MS, this.pollIntervalMs * 2 ** ls.failures);
          const msg = (err as Error).message;
          this.state.recordPullError(peer.nodeId, msg);
          if (ls.failures === 1 || ls.failures % 10 === 0) this.log(`pull from ${peer.nodeId} (${peer.url}) failed: ${msg}`);
        }
      }),
    );
  }

  /** Pulls and applies everything a peer has after our cursor for it. */
  async pullPeer(peer: ClusterPeer): Promise<ApplyResult> {
    const total: ApplyResult = { applied: 0, skipped: 0, conflicts: 0 };
    for (let page = 0; page < MAX_PAGES_PER_TICK; page++) {
      const cursor = this.state.cursorFor(peer.nodeId);
      const sentAt = Date.now();
      const res = await clusterCall<{ nodeId: string; changes: ClusterChange[]; head: number; more: boolean; now: number }>({
        url: peer.url,
        method: "GET",
        path: `/cluster/v1/changes?since=${cursor}&limit=${PAGE_SIZE}`,
        keys: this.state.keys(),
        nodeId: this.state.peekNodeId()!,
      });
      if (res.nodeId !== peer.nodeId) {
        throw new ClusterError(502, "wrong_peer", `${peer.url} is node ${res.nodeId}, expected ${peer.nodeId}`);
      }
      const r = this.state.applyChanges(peer.nodeId, res.changes, res.head);
      this.state.recordClockSkew(peer.nodeId, res.now - (sentAt + Date.now()) / 2);
      total.applied += r.applied;
      total.skipped += r.skipped;
      total.conflicts += r.conflicts;
      if (!res.more) break;
    }
    return total;
  }

  /** Asks a URL who it is, and adds it as a peer if it is in our cluster. */
  async addPeer(rawUrl: string): Promise<ClusterPeer> {
    const url = validateClusterUrl(rawUrl);
    let hello: { nodeId: string; clusterId: string };
    try {
      hello = await clusterCall({ url, method: "GET", path: "/cluster/v1/hello", keys: this.state.keys(), nodeId: this.state.peekNodeId()! });
    } catch (err) {
      // 401 from the peer, or a response that does not open under our key:
      // the peer holds a different cluster secret.
      if (err instanceof ClusterHttpError && (err.status === 401 || err.code === "unauthenticated_response")) {
        throw new ClusterError(409, "different_cluster", `${url} rejected this cluster's credentials: it belongs to another cluster`);
      }
      throw new ClusterError(502, "peer_unreachable", (err as Error).message);
    }
    if (hello.clusterId !== this.state.clusterId()) {
      throw new ClusterError(409, "different_cluster", `${url} belongs to cluster ${hello.clusterId}`);
    }
    return this.state.upsertPeer(hello.nodeId, url);
  }

  /**
   * Leaves the cluster: tells every peer (best effort, so the departure
   * replicates from them), then erases local cluster state.
   */
  async leave(): Promise<{ announced: string[]; unreachable: string[] }> {
    const self = this.state.peekNodeId();
    const keys = this.state.keys();
    const announced: string[] = [];
    const unreachable: string[] = [];
    await Promise.all(
      this.state
        .listPeers()
        .filter((p) => p.nodeId !== self)
        .map(async (p) => {
          try {
            await clusterCall({ url: p.url, method: "POST", path: "/cluster/v1/leave", keys, nodeId: self!, body: { nodeId: self } });
            announced.push(p.nodeId);
          } catch {
            unreachable.push(p.nodeId);
          }
        }),
    );
    this.state.leave();
    this.refresh();
    return { announced, unreachable };
  }

  status(): ClusterStatus & { listening: string | null } {
    return { ...this.state.status(), listening: this.listenAddress };
  }

  async close(): Promise<void> {
    this.stopLoop();
    if (this.ticking) await this.ticking.catch(() => {});
    if (this.server) {
      this.server.closeAllConnections();
      await new Promise<void>((resolve) => this.server!.close(() => resolve()));
      this.server = null;
      this.listenAddress = null;
    }
  }
}

export { ClusterHttpError };
