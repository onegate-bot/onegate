/**
 * The gateway proxy.
 *
 * Agents point HTTPS_PROXY at this server with their token as the proxy
 * password (http://agent:og_xxx@gateway:port) and trust the OneGate root CA.
 *
 * CONNECT handling:
 *  - host owned by an integration → TLS-terminate with a minted leaf cert,
 *    parse the inner HTTP, enforce policy, inject credentials, bridge to the
 *    real vendor over fresh TLS, stream the response back.
 *  - any other host → opaque passthrough tunnel (no MITM, no inspection).
 */

import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import type { Duplex } from "node:stream";
import type { Ca } from "../ca.js";
import type { Store } from "../store/db.js";
import { evaluate, normalizeRequestPath } from "../policy.js";
import type { Agent, Connection, LlmStrategy, OwnerNotification, Rule } from "../types.js";
import { connectFlowKind, type Integration, type Registry } from "../integrations/types.js";
import { onSelectionError, selectConnection } from "../llm/strategy.js";
import { createUsageScanner, extractRequestModel, type TokenUsage } from "../llm/usage.js";
import { DISCOVERY_HOST, buildDiscovery } from "../discovery.js";

interface SocketCtx {
  kind?: "integration";
  agent: Agent;
  host: string;
  port: number;
  integration: Integration;
}

/** Inner-request context for the agent-facing discovery endpoint. */
interface DiscoveryCtx {
  kind: "discovery";
  agent: Agent;
  host: string;
}

type InnerCtx = SocketCtx | DiscoveryCtx;

/** A resolved LLM routing decision for one inner request. */
interface LlmRoute {
  vendor: string;
  strategy: LlmStrategy;
  /** The agent's enabled connections of this vendor, in configured order. */
  connections: Connection[];
}

/** Statuses that trigger strategy error handling and the failover retry. */
function isRetryableStatus(status: number | undefined): boolean {
  return status === 429 || (status !== undefined && status >= 500);
}

/** Dedup window for proactive owner deny-notifications: 24 hours in ms. */
export const OWNER_NOTIFY_DEDUP_MS = 24 * 60 * 60 * 1000;

export interface ProxyOptions {
  ca: Ca;
  store: Store;
  registry: Registry;
  /** Extra TLS options for upstream connections (test hook: custom ca). */
  upstreamTls?: tls.ConnectionOptions;
  /** Override upstream target, e.g. route to a stub in tests. */
  upstreamLookup?: (host: string, port: number) => { host: string; port: number };
  log?: (line: string) => void;
  /**
   * fetch implementation used by the owner-notify dispatcher. Defaults to
   * globalThis.fetch. Override in tests to stub the HTTP POST and avoid real
   * network calls.
   */
  notifyFetch?: typeof fetch;
}

const HOP_BY_HOP = new Set([
  "connection",
  "proxy-connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

/**
 * Request headers that must never reach an upstream vendor, on top of the
 * hop-by-hop set.
 *
 * - `authorization`: the caller's client-side auth is replaced by the injected
 *   credential; forwarding it would leak the agent's own token upstream.
 * - `x-onegate-connection`: a OneGate-internal routing control that selects
 *   which stored connection to use. It is consumed entirely by
 *   `resolveConnectionForRequest` / the LLM route resolver and is meaningless
 *   to the vendor, but it carries operator-meaningful connection ids and names
 *   that would otherwise land in third-party request logs.
 */
const STRIPPED_REQUEST_HEADERS = new Set(["authorization", "x-onegate-connection"]);

/**
 * Builds the upstream request headers for a forwarded request: everything the
 * client sent, minus hop-by-hop headers and the OneGate-internal headers above.
 *
 * Shared by both forward paths (the normal integration path and the LLM-routed
 * path) so the two can never drift apart on what they leak upstream.
 */
function forwardHeaders(reqHeaders: http.IncomingHttpHeaders): http.IncomingHttpHeaders {
  const headers: http.IncomingHttpHeaders = {};
  for (const [k, v] of Object.entries(reqHeaders)) {
    if (!HOP_BY_HOP.has(k) && !STRIPPED_REQUEST_HEADERS.has(k)) headers[k] = v;
  }
  return headers;
}

/** Cap for buffered bodies (integrations with `needsBody`). */
function maxBufferedBody(): number {
  const fromEnv = Number(process.env.ONEGATE_MAX_BUFFERED_BODY);
  return Number.isFinite(fromEnv) && fromEnv > 0 ? fromEnv : 32 * 1024 * 1024;
}

class BodyTooLargeError extends Error {
  constructor(limit: number) {
    super(`Request body exceeds the gateway's ${limit} byte signing buffer`);
  }
}

function readBody(req: http.IncomingMessage, limit: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        // Reject but keep draining so the 413 response can still be
        // written back over the (kept-alive) TLS socket.
        chunks.length = 0;
        reject(new BodyTooLargeError(limit));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/** A request header may arrive as a string or string[]; take the first value. */
function singleHeader(value: string | string[] | undefined): string | null {
  if (value === undefined) return null;
  return Array.isArray(value) ? (value[0] ?? null) : value;
}

function parseProxyAuth(header: string | undefined): string | null {
  if (!header) return null;
  const [scheme, value] = header.split(" ");
  if (!scheme || !value) return null;
  if (scheme.toLowerCase() === "basic") {
    const decoded = Buffer.from(value, "base64").toString("utf8");
    const idx = decoded.indexOf(":");
    return idx === -1 ? decoded : decoded.slice(idx + 1);
  }
  if (scheme.toLowerCase() === "bearer") return value;
  return null;
}

/**
 * Validates the host parsed from a CONNECT authority before it is used for
 * integration resolution or leaf-cert minting. A well-formed DNS host contains
 * only letters, digits, dots and hyphens; anything else (path separators, `..`,
 * control chars, whitespace) is rejected. This blocks a crafted CONNECT host
 * such as `../../../tmp/evil.amazonaws.com` from reaching `ca.leafFor`, where it
 * would otherwise write a cert + private key outside the certs directory. The
 * sanitization in `Ca.leafFor` is the backstop; this is the front door.
 *
 * Beyond the charset, we reject any host that is or contains a bare `..`
 * traversal token (e.g. `..` or `a..b`), which the charset alone would admit.
 */
export function isValidConnectHost(host: string): boolean {
  if (!/^[a-z0-9.-]+$/i.test(host)) return false;
  if (host.includes("..")) return false;
  return true;
}

export class GatewayProxy {
  private server: http.Server;
  /** Inner HTTP parser for MITM'd TLS sockets. */
  private inner: http.Server;
  private ctxBySocket = new WeakMap<Duplex, InnerCtx>();
  private opts: ProxyOptions;
  private log: (line: string) => void;
  /**
   * Dedicated upstream agent. The default globalAgent may have captured an
   * ambient corporate proxy via NODE_USE_ENV_PROXY at process start; the
   * gateway must always dial vendors directly.
   */
  private upstreamAgent: https.Agent;
  /**
   * Every live CONNECT tunnel socket. Once a socket is hijacked by the
   * 'connect' handler it is no longer tracked by `this.server`, so
   * `server.closeAllConnections()` cannot reach it and `server.close()`'s
   * callback would otherwise wait forever for the tunnel to drain (a
   * persistent agent tunnel never drains on its own). Tracking them lets
   * `close()` destroy them deterministically for a prompt shutdown.
   */
  private tunnels = new Set<Duplex>();

  constructor(opts: ProxyOptions) {
    this.opts = opts;
    this.log = opts.log ?? (() => {});
    // Teach host resolution about owner-supplied instance origins. Wired here
    // (rather than at each call site) so every proxy, including in tests, sees
    // the same host view as the store it was constructed with.
    opts.registry.setInstanceOriginLookup((host) => opts.store.instanceOriginClaimFor(host));
    this.upstreamAgent = new https.Agent({ keepAlive: true, ...opts.upstreamTls });
    this.server = http.createServer((req, res) => {
      // Plain (non-CONNECT) proxy requests are not supported: the gateway
      // only mediates HTTPS traffic.
      res.writeHead(501, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "OneGate only proxies HTTPS (CONNECT)" }));
    });
    this.server.on("connect", (req, socket, head) => this.onConnect(req, socket, head));
    this.inner = http.createServer((req, res) => this.onInnerRequest(req, res));
    this.inner.on("clientError", (_err, socket) => socket.destroy());
  }

  listen(port: number, host = "0.0.0.0"): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(port, host, () => {
        resolve((this.server.address() as net.AddressInfo).port);
      });
    });
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      this.upstreamAgent.destroy();
      // Destroy every live tunnel socket: hijacked CONNECT sockets are not
      // tracked by the servers, so without this `server.close()` would hang
      // until a tunnel happens to drain (a persistent agent tunnel never does).
      for (const sock of this.tunnels) sock.destroy();
      this.tunnels.clear();
      this.inner.close();
      this.inner.closeAllConnections();
      this.server.close(() => resolve());
      this.server.closeAllConnections();
      // The listeners are closed and all sockets destroyed above; resolve
      // promptly rather than depending solely on the close callback, which can
      // still be delayed by edge-case socket states.
      resolve();
    });
  }

  private onConnect(req: http.IncomingMessage, socket: Duplex, head: Buffer): void {
    const [host, portStr] = (req.url ?? "").split(":");
    const port = Number(portStr) || 443;
    // Reject an empty or malformed host up front. Without a strict charset guard
    // a crafted host containing `/` or `..` flows into ca.leafFor and writes a
    // cert + private key to an arbitrary path (leaf-cert path traversal).
    if (!host || !isValidConnectHost(host)) {
      socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
      return;
    }
    socket.on("error", () => socket.destroy());
    // Track the tunnel so close() can tear it down deterministically.
    this.tunnels.add(socket);
    socket.once("close", () => this.tunnels.delete(socket));

    const token = parseProxyAuth(req.headers["proxy-authorization"]);
    const agent = token ? this.opts.store.getAgentByToken(token) : null;
    if (!agent) {
      this.opts.store.audit({ host, decision: "auth_failed" });
      socket.end(
        'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="onegate"\r\n\r\n',
      );
      return;
    }

    // Agent-facing discovery: a bot CONNECTs to the sentinel host to learn
    // which accounts and URLs it can reach (see #5438, #5450). It is served
    // locally over a MITM leaf, never forwarded upstream.
    if (host.toLowerCase() === DISCOVERY_HOST && port === 443) {
      this.terminateDiscovery(agent, host, socket, head);
      return;
    }

    // A host may be claimed by several integrations (api.github.com belongs
    // to both the github PAT integration and github-app). The connected one
    // wins; with none or several connected, registration order decides.
    const candidates = this.opts.registry.resolveHostCandidates(host);
    const integration =
      candidates.length > 1
        ? (candidates.find((i) => this.opts.store.getCredential(i.id)) ?? candidates[0])
        : (candidates[0] ?? null);
    if (!integration || port !== 443) {
      this.passthrough(agent, host, port, socket, head);
      return;
    }
    this.terminate(agent, integration, host, port, socket, head);
  }

  /** Opaque tunnel for hosts we have no integration for. */
  private passthrough(agent: Agent, host: string, port: number, socket: Duplex, head: Buffer): void {
    const target = this.opts.upstreamLookup?.(host, port) ?? { host, port };
    const upstream = net.connect(target.port, target.host, () => {
      this.opts.store.audit({
        agentId: agent.id,
        agentName: agent.name,
        host,
        decision: "passthrough",
      });
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    upstream.on("error", () => {
      socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
    });
    socket.on("close", () => upstream.destroy());
  }

  /** MITM path: terminate TLS with our leaf cert and parse the inner HTTP. */
  private terminate(
    agent: Agent,
    integration: Integration,
    host: string,
    port: number,
    socket: Duplex,
    head: Buffer,
  ): void {
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    const leaf = this.opts.ca.leafFor(host);
    const tlsSocket = new tls.TLSSocket(socket as net.Socket, {
      isServer: true,
      key: leaf.key,
      cert: leaf.cert,
    });
    if (head.length) tlsSocket.unshift(head);
    tlsSocket.on("error", () => tlsSocket.destroy());
    this.ctxBySocket.set(tlsSocket, { kind: "integration", agent, host, port, integration });
    this.inner.emit("connection", tlsSocket);
  }

  /**
   * MITM path for the agent-facing discovery endpoint. Same TLS termination
   * as terminate(), but the inner request is served locally (no upstream) by
   * handleDiscovery(). The bot trusts our root CA, so the leaf for the
   * sentinel host validates.
   */
  private terminateDiscovery(agent: Agent, host: string, socket: Duplex, head: Buffer): void {
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    const leaf = this.opts.ca.leafFor(host);
    const tlsSocket = new tls.TLSSocket(socket as net.Socket, {
      isServer: true,
      key: leaf.key,
      cert: leaf.cert,
    });
    if (head.length) tlsSocket.unshift(head);
    tlsSocket.on("error", () => tlsSocket.destroy());
    this.ctxBySocket.set(tlsSocket, { kind: "discovery", agent, host });
    this.inner.emit("connection", tlsSocket);
  }

  /**
   * The agent-facing OneGate self-service surface on the onegate.internal
   * sentinel host. Served locally (never forwarded upstream), secret-free.
   *
   *  - GET  /              -> discovery JSON for the authenticated agent.
   *  - POST /connect-links -> mint a single-use OAuth connect link scoped to
   *    the authenticated agent, so the bot can hand it straight to its owner
   *    without the operator having to mint it.
   */
  private handleDiscovery(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    ctx: DiscoveryCtx,
  ): void {
    const method = (req.method ?? "GET").toUpperCase();
    const path = (req.url ?? "/").split("?")[0];

    if (method === "GET" && path === "/") {
      const result = buildDiscovery(this.opts.store, this.opts.registry, ctx.agent);
      this.log(`discovery ${ctx.agent.name} -> ${result.integrations.length} integration(s)`);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(result));
      return;
    }

    if (path === "/connect-links") {
      if (method !== "POST") {
        res.writeHead(405, { "content-type": "application/json", allow: "POST" });
        res.end(JSON.stringify({ error: "method_not_allowed" }));
        return;
      }
      this.handleSelfMintConnectLink(req, res, ctx);
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  }

  /**
   * Mints an onboarding link for the CALLING agent only. The agent is taken
   * from the authenticated proxy token (ctx.agent), never from the request
   * body, so a bot can only ever mint a link scoped to itself. Secret-free:
   * the owner enters their OAuth client id/secret on the wizard page, not here.
   */
  private handleSelfMintConnectLink(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    ctx: DiscoveryCtx,
  ): void {
    const chunks: Buffer[] = [];
    let tooBig = false;
    req.on("data", (c: Buffer) => {
      if (tooBig) return;
      chunks.push(c);
      if (chunks.reduce((n, b) => n + b.length, 0) > 64 * 1024) {
        tooBig = true;
        res.writeHead(413, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "body_too_large" }));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (tooBig) return;
      let body: {
        integrationId?: unknown;
        scopes?: unknown;
        connectionName?: unknown;
        ttlDays?: unknown;
      } = {};
      const raw = Buffer.concat(chunks).toString("utf8").trim();
      if (raw) {
        try {
          body = JSON.parse(raw);
        } catch {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "invalid_json" }));
          return;
        }
      }
      const integrationId = body.integrationId;
      if (!integrationId || typeof integrationId !== "string") {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "integrationId is required" }));
        return;
      }
      const integration = this.opts.registry.get(integrationId);
      if (!integration || !connectFlowKind(integration)) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "integration_not_connectable" }));
        return;
      }
      const link = this.opts.store.createOnboardingLink({
        agentId: ctx.agent.id,
        integrationId: integration.id,
        scopes: Array.isArray(body.scopes) ? body.scopes.map(String) : undefined,
        connectionName:
          typeof body.connectionName === "string" && body.connectionName.trim()
            ? body.connectionName.trim()
            : undefined,
        ttlDays: typeof body.ttlDays === "number" && body.ttlDays > 0 ? body.ttlDays : undefined,
      });
      const base = (process.env.ONEGATE_PUBLIC_URL || "https://app.onegate.bot").replace(/\/$/, "");
      this.log(`connect-link self-mint ${ctx.agent.name} -> ${integration.id}`);
      res.writeHead(201, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          token: link.token,
          url: `${base}/connect/${integration.id}/${link.token}`,
          expiresAt: link.expiresAt,
        }),
      );
    });
    req.on("error", () => {
      if (tooBig) return;
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "bad_request" }));
    });
  }

  /**
   * Fire-and-forget: dispatches an owner notification webhook POST.
   * Marks the row delivered on 2xx or failed otherwise. Never throws.
   */
  private dispatchOwnerNotification(
    row: OwnerNotification,
    payload: {
      agentId: string;
      agentName: string;
      integrationId: string;
      integrationTitle: string;
      connectUrl: string | null;
      connectExpiresAt: string | null;
      reason: string;
    },
    webhookUrl: string,
  ): void {
    const notifyFetch = this.opts.notifyFetch ?? globalThis.fetch;
    const body = JSON.stringify({
      type: "onegate.owner_notify",
      agentId: payload.agentId,
      agentName: payload.agentName,
      integrationId: payload.integrationId,
      integrationTitle: payload.integrationTitle,
      connectUrl: payload.connectUrl,
      connectExpiresAt: payload.connectExpiresAt,
      reason: payload.reason,
      ts: new Date().toISOString(),
    });
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    notifyFetch(webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      signal: controller.signal,
    })
      .then((resp) => {
        clearTimeout(timeout);
        if (resp.ok) {
          this.opts.store.markOwnerNotification(row.id, {
            status: "delivered",
            deliveredAt: new Date().toISOString(),
            incrementAttempt: true,
          });
        } else {
          this.opts.store.markOwnerNotification(row.id, {
            status: "failed",
            error: `HTTP ${resp.status}`,
            incrementAttempt: true,
          });
          this.log(`owner-notify failed for agent ${payload.agentId} / ${payload.integrationId}: HTTP ${resp.status}`);
        }
      })
      .catch((err: unknown) => {
        clearTimeout(timeout);
        const msg = err instanceof Error ? err.message : String(err);
        this.opts.store.markOwnerNotification(row.id, {
          status: "failed",
          error: msg,
          incrementAttempt: true,
        });
        this.log(`owner-notify error for agent ${payload.agentId} / ${payload.integrationId}: ${msg}`);
      });
  }

  /**
   * Checks dedup and, if the agent has a notify webhook configured and the
   * (agent, integration) pair has not been notified within OWNER_NOTIFY_DEDUP_MS,
   * enqueues an owner_notification row and fires the webhook dispatcher
   * asynchronously (non-blocking). Only call this for KNOWN CREDENTIAL
   * integrations (non-LLM, has connect flow). Only call for default-deny
   * (ruleId === null) on the policy branch; always call for
   * connection_not_granted and no_credential branches (those are always
   * "not connected yet" states, regardless of ruleId).
   */
  private maybeNotifyOwner(
    agent: Agent,
    integration: Integration,
    reason: string,
    opts: {
      /**
       * A lapsed access lease: notify with a one-tap RENEWAL link (re-stamps the
       * rule, no credential re-entry) and dedup on `dedupKey` (per lapse) instead
       * of the (agent, integration) time window, so each new lapse always
       * reaches the owner but repeated requests within one lapse do not spam.
       */
      lease?: { ruleId: string; dedupKey: string };
    } = {},
  ): void {
    // LLM vendor integrations have no owner-notify concept.
    if (!connectFlowKind(integration)) return;
    // Only fire if the agent has a webhook configured.
    const webhookUrl = this.opts.store.getAgentNotify(agent.id);
    if (!webhookUrl) return;
    // Dedup: lease lapses dedup per-lapse (dedupKey); everything else dedups on
    // the (agent, integration) time window.
    if (opts.lease) {
      if (this.opts.store.findOwnerNotificationByDedupKey(opts.lease.dedupKey)) return;
    } else {
      const sinceIso = new Date(Date.now() - OWNER_NOTIFY_DEDUP_MS).toISOString();
      if (this.opts.store.findRecentOwnerNotification(agent.id, integration.id, sinceIso)) return;
    }
    // Mint/reuse the right link: a renewal link for a lapsed lease, else connect.
    const base = (process.env.ONEGATE_PUBLIC_URL || "https://app.onegate.bot").replace(/\/$/, "");
    let link;
    let url: string;
    if (opts.lease) {
      link =
        this.opts.store.activeRenewalLinkFor(opts.lease.ruleId) ??
        this.opts.store.createOnboardingLink({
          agentId: agent.id,
          integrationId: integration.id,
          ruleId: opts.lease.ruleId,
        });
      url = `${base}/renew/${link.token}`;
    } else {
      link =
        this.opts.store.activeOnboardingLinkFor(agent.id, integration.id) ??
        this.opts.store.createOnboardingLink({ agentId: agent.id, integrationId: integration.id });
      url = `${base}/connect/${integration.id}/${link.token}`;
    }
    // Enqueue and dispatch.
    const row = this.opts.store.enqueueOwnerNotification({
      agentId: agent.id,
      integrationId: integration.id,
      connectToken: link.token,
      dedupKey: opts.lease?.dedupKey ?? null,
    });
    this.dispatchOwnerNotification(
      row,
      {
        agentId: agent.id,
        agentName: agent.name,
        integrationId: integration.id,
        integrationTitle: integration.title,
        connectUrl: url,
        connectExpiresAt: link.expiresAt,
        reason,
      },
      webhookUrl,
    );
  }

  /**
   * A self-minted, agent-scoped RENEWAL URL for a lapsed access lease. Reuses a
   * live renewal link for the rule when one exists. Opens a one-tap renew page
   * (no credential re-entry). Returned in the deny body so the bot can hand the
   * link to its owner to re-open access for another lease period.
   */
  private renewalUrlFor(
    agent: Agent,
    integration: Integration,
    ruleId: string,
  ): { url: string; expiresAt: string } | null {
    if (!connectFlowKind(integration)) return null;
    const link =
      this.opts.store.activeRenewalLinkFor(ruleId) ??
      this.opts.store.createOnboardingLink({
        agentId: agent.id,
        integrationId: integration.id,
        ruleId,
      });
    const base = (process.env.ONEGATE_PUBLIC_URL || "https://app.onegate.bot").replace(/\/$/, "");
    return { url: `${base}/renew/${link.token}`, expiresAt: link.expiresAt };
  }

  /**
   * A self-minted, agent-scoped connect URL for an integration the calling
   * agent has not connected yet, or null when the integration has no connect
   * flow at all. Works for every connect method: OAuth integrations open the
   * consent wizard, api_key / credentials_import integrations open the
   * paste-your-credential wizard. Reuses a still-live onboarding link when one
   * exists so a bot retrying a call to an unconnected integration does not mint
   * a duplicate link every time. Returned inside not-connected error bodies so
   * the bot can hand the link straight to its owner, instead of wrongly
   * concluding there is no self-service flow and telling the owner to use the
   * admin UI.
   */
  private connectUrlFor(
    agent: Agent,
    integration: Integration,
  ): { url: string; expiresAt: string } | null {
    if (!connectFlowKind(integration)) return null;
    const link =
      this.opts.store.activeOnboardingLinkFor(agent.id, integration.id) ??
      this.opts.store.createOnboardingLink({ agentId: agent.id, integrationId: integration.id });
    const base = (process.env.ONEGATE_PUBLIC_URL || "https://app.onegate.bot").replace(/\/$/, "");
    return { url: `${base}/connect/${integration.id}/${link.token}`, expiresAt: link.expiresAt };
  }

  /**
   * When `host` is claimed as a connection's self-managed instance origin,
   * returns the resolution for THAT connection, else null (meaning: not a
   * self-managed host, resolve normally).
   *
   * The claiming connection is still subject to the grant check. A connection
   * the agent cannot use does not become usable by virtue of owning the host,
   * and the agent is NOT silently served some other connection's credential
   * instead: it gets connection_not_granted, exactly as it would for any
   * ungranted connection.
   */
  private resolveInstanceOriginConnection(
    agent: Agent,
    integration: Integration,
    host: string,
    method: string,
    path: string,
    res: http.ServerResponse,
  ): ({ sent: true } | { sent: false; connection: Connection | null }) | null {
    const claim = this.opts.store.instanceOriginClaimFor(host);
    if (!claim || claim.integrationId !== integration.id) return null;

    const granted = this.opts.store
      .listAppConnectionsForAgent(agent.id, integration.id)
      .some((c) => c.id === claim.connectionId);
    if (!granted) {
      this.opts.store.audit({
        agentId: agent.id,
        agentName: agent.name,
        integrationId: integration.id,
        host,
        method,
        path,
        decision: "connection_not_granted",
        status: 403,
      });
      this.maybeNotifyOwner(agent, integration, "connection_not_granted");
      res.writeHead(403, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: "onegate_connection_not_granted",
          message: `Host "${host}" is the self-managed instance of connection "${claim.connectionId}", which is not granted to agent "${agent.name}".`,
        }),
      );
      return { sent: true };
    }

    const connection = this.opts.store.getConnection(claim.connectionId);
    return connection ? { sent: false, connection } : null;
  }

  /**
   * Resolves the app connection for a request (x-onegate-connection header, else
   * the agent's saved choice, else the tenant default), writing the appropriate
   * error response itself when resolution fails.
   *
   * Returns a discriminated result:
   *   - `{ sent: true }`  — an error response was already written (400
   *     unknown_connection or 403 connection_not_granted); the caller must stop.
   *   - `{ sent: false, connection }` — resolution succeeded; `connection` is the
   *     selected connection, or `null` for the legacy single-credential path.
   *
   * Extracted so both the normal allow path and the deny-branch phase-2 recovery
   * can resolve the connection identically without duplicating the logic.
   *
   * SELF-MANAGED INSTANCES: when `host` is an owner-supplied instance origin,
   * resolution is PINNED to the connection that claimed it. Normal resolution
   * selects by integration id alone, which for a self-hosted deployment would
   * be a credential-redirection bug: a request to gitlab.acme.example could be
   * served the gitlab.com SaaS token (or the reverse). The claiming connection
   * is the only credential that belongs to that host, so it is used directly,
   * subject to the same grant check as any other connection.
   */
  private resolveConnectionForRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    agent: Agent,
    integration: Integration,
    host: string,
    method: string,
    path: string,
  ): { sent: true } | { sent: false; connection: Connection | null } {
    const pinned = this.resolveInstanceOriginConnection(
      agent,
      integration,
      host,
      method,
      path,
      res,
    );
    if (pinned) return pinned;

    const headerValue = singleHeader(req.headers["x-onegate-connection"]);
    const resolved = this.opts.store.resolveAppConnection(agent.id, integration.id, headerValue);
    if (resolved && "error" in resolved) {
      // Default-deny: either the named/selected connection does not exist
      // (unknown_connection, 400) or it exists but is not granted to this agent
      // or its project (connection_not_granted, 403). Never silently fall
      // through to the legacy credential. Both outcomes are audited.
      if (resolved.error === "unknown_connection") {
        this.opts.store.audit({
          agentId: agent.id,
          agentName: agent.name,
          integrationId: integration.id,
          host,
          method,
          path,
          decision: "unknown_connection",
          status: 400,
        });
        res.writeHead(400, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            error: "onegate_unknown_connection",
            message: `No app connection named or with id "${headerValue}" exists for integration "${integration.id}".`,
          }),
        );
        return { sent: true };
      }
      // connection_not_granted
      this.opts.store.audit({
        agentId: agent.id,
        agentName: agent.name,
        integrationId: integration.id,
        host,
        method,
        path,
        decision: "connection_not_granted",
        status: 403,
      });
      this.maybeNotifyOwner(agent, integration, "connection_not_granted");
      const connect = this.connectUrlFor(agent, integration);
      res.writeHead(403, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: "onegate_connection_not_granted",
          message: connect
            ? `No app connection for integration "${integration.id}" is granted to agent "${agent.name}". Open the connect_url to connect one, then retry.`
            : `No app connection for integration "${integration.id}" is granted to agent "${agent.name}". Grant one in the OneGate admin UI.`,
          ...(connect
            ? {
                connect_url: connect.url,
                connect_expires_at: connect.expiresAt,
                hint: "Show connect_url to your owner as a bare link. Opening it lets them connect this integration to you, then retry the request.",
              }
            : {}),
        }),
      );
      return { sent: true };
    }
    return { sent: false, connection: resolved ? resolved.connection : null };
  }

  private async onInnerRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const ctx = this.ctxBySocket.get(req.socket);
    if (!ctx) {
      res.writeHead(500).end();
      return;
    }
    if (ctx.kind === "discovery") {
      this.handleDiscovery(req, res, ctx);
      return;
    }
    const { agent, host, port, integration } = ctx;
    const method = (req.method ?? "GET").toUpperCase();
    // Canonicalize the request target ONCE: percent-decode, collapse dot-segments
    // and duplicate slashes (query preserved). Policy matching, audit AND the
    // upstream forward all use this single canonical form, so a deny glob cannot
    // be evaded with an equivalent-but-encoded path (%2F, //, /../) that the
    // vendor would still honor. See normalizeRequestPath.
    const path = normalizeRequestPath(req.url ?? "/");

    const rules = this.opts.store.rulesForAgent(agent);
    const verdict = evaluate(agent, rules, { integrationId: integration.id, method, path });

    // When phase-1 evaluated to DENY but a connection-scoped rule was held
    // pending (verdict.needsConnection), the deny is not final: a
    // connection-scoped ALLOW rule for the specific connection this request
    // resolves to could still grant access. Resolve the connection now and
    // re-run the policy (phase-2). Only if phase-2 STILL denies do we fall into
    // the deny handler below. This is fail-safe: any resolution error emits its
    // own deny response, and a phase-2 deny is honoured. When the flag is off,
    // needsConnection is never set, so this block is inert and behaviour is
    // unchanged. `preResolved` is threaded to the allow path so the connection
    // is resolved exactly once.
    let effectiveVerdict = verdict;
    let preResolved: { resolved: true; connection: Connection | null } | null = null;
    if (verdict.effect === "deny" && verdict.needsConnection) {
      const r = this.resolveConnectionForRequest(req, res, agent, integration, host, method, path);
      if (r.sent) return; // resolution failed and already denied (fail-safe)
      preResolved = { resolved: true, connection: r.connection };
      effectiveVerdict = evaluate(agent, rules, {
        integrationId: integration.id,
        method,
        path,
        connectionId: r.connection?.id ?? null,
      });
    }

    if (effectiveVerdict.effect === "deny") {
      const verdict = effectiveVerdict;
      this.opts.store.audit({
        agentId: agent.id,
        agentName: agent.name,
        integrationId: integration.id,
        host,
        method,
        path,
        decision: "deny",
        ruleId: verdict.ruleId,
        status: 403,
      });
      // A lapsed access lease is a special default-deny: the integration IS
      // connected, but its time-boxed allow rule expired. Offer a RENEWAL link
      // (one-tap, no credential re-entry) and notify the owner, deduped per
      // lapse so each new expiry always reaches them.
      if (verdict.lapsed && verdict.lapsedRuleId) {
        const renew = this.renewalUrlFor(agent, integration, verdict.lapsedRuleId);
        this.maybeNotifyOwner(agent, integration, "lease_expired", {
          lease: {
            ruleId: verdict.lapsedRuleId,
            dedupKey: `lease:${verdict.lapsedRuleId}:${verdict.lapsedExpiresAt ?? ""}`,
          },
        });
        res.writeHead(403, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            error: "onegate_lease_expired",
            message: `Access to "${integration.id}" for agent "${agent.name}" has expired (time-boxed connection). Open the connect_url to re-allow it for another period, then retry.`,
            ...(renew
              ? {
                  connect_url: renew.url,
                  connect_expires_at: renew.expiresAt,
                  hint: "Show connect_url to your owner as a bare link. Opening it re-allows this connection for another period (no credential re-entry), then retry the request.",
                }
              : {}),
          }),
        );
        return;
      }
      // Offer a connect link ONLY on default-deny (no rule matched, ruleId
      // null) for an OAuth integration: that is the "not wired for this agent
      // yet" state the connect flow resolves. An explicit deny rule is a real
      // policy decision, never bypassable via a connect link.
      const connect =
        verdict.ruleId === null ? this.connectUrlFor(agent, integration) : null;
      // Notify the agent owner only on default-deny (ruleId null). An explicit
      // deny rule is a deliberate policy decision — never notify for those.
      if (verdict.ruleId === null) {
        this.maybeNotifyOwner(agent, integration, "policy_default_deny");
      }
      res.writeHead(403, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: "onegate_policy_denied",
          message: connect
            ? `Integration "${integration.id}" is not connected for agent "${agent.name}". Open the connect_url to connect it, then retry.`
            : `Policy denies ${method} ${host}${path} for agent "${agent.name}"`,
          ...(connect
            ? {
                connect_url: connect.url,
                connect_expires_at: connect.expiresAt,
                hint: "Show connect_url to your owner as a bare link. Opening it lets them connect this integration to you, then retry the request.",
              }
            : {}),
        }),
      );
      return;
    }

    // LLM routing: only when the integration is an LLM vendor AND the agent
    // explicitly enabled LLM routing with at least one connection of this
    // vendor. Everything else (disabled, no config, no matching connections)
    // takes the legacy path below, exactly as before this feature: an agent
    // with its own vendor token (the Gaty case) is unaffected.
    const llmRoute = this.resolveLlmRoute(agent, integration);
    if (llmRoute) {
      // Phase-2 connection-scoped enforcement also applies here. The LLM path
      // picks its own connection (round-robin/fallback) INSIDE handleLlmRequest,
      // and may fail over to another connection mid-flight, so the re-evaluation
      // is done per attempted connection there. We forward the rules and the
      // PHASE-1 needsConnection flag (not the phase-2 one, which was already
      // resolved against a non-LLM connection and would read false) so it can
      // re-check each LLM connection it actually dispatches on. When no
      // connection-scoped rule matched (needsConnection false) or the feature
      // flag is off, this is a no-op and behavior is byte-identical to before.
      await this.handleLlmRequest(
        req,
        res,
        ctx,
        effectiveVerdict.ruleId,
        llmRoute,
        rules,
        verdict.needsConnection ?? false,
      );
      return;
    }

    // App-connection resolution. When the agent (or the tenant) has named
    // app connections for this integration, pick one: the x-onegate-connection
    // header (by name or id), else the agent's saved choice, else the
    // tenant-wide default. When NONE of these resolve (no app connections at
    // all and no saved config), this returns null and we fall through to the
    // legacy single-credential path below, byte-identical to before.
    //
    // If the deny-branch recovery above already resolved the connection (and
    // re-ran the policy to an allow), reuse that result: resolving twice would
    // duplicate audit rows and re-mint connect links.
    let selectedConnection: Connection | null;
    if (preResolved) {
      selectedConnection = preResolved.connection;
    } else {
      const r = this.resolveConnectionForRequest(req, res, agent, integration, host, method, path);
      if (r.sent) return;
      selectedConnection = r.connection;

      // Phase-2 policy check: connection-scoped rules. The phase-1 evaluate()
      // above ran before the connection was resolved, so any connection-scoped
      // rule was held pending (verdict.needsConnection). Now that the connection
      // is known, re-evaluate to let a connection-scoped deny fire (e.g. "deny
      // this path unless the request used connection X"). No-op when no
      // connection-scoped rule matched this request, so unrelated traffic is
      // unaffected. Skipped when preResolved, since the recovery path already
      // ran phase-2 and only reaches here on an allow.
      if (verdict.needsConnection) {
        const finalVerdict = evaluate(agent, rules, {
          integrationId: integration.id,
          method,
          path,
          connectionId: selectedConnection?.id ?? null,
        });
        if (finalVerdict.effect === "deny") {
          this.opts.store.audit({
            agentId: agent.id,
            agentName: agent.name,
            integrationId: integration.id,
            host,
            method,
            path,
            decision: "deny",
            ruleId: finalVerdict.ruleId,
            status: 403,
          });
          res.writeHead(403, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              error: "onegate_policy_denied",
              message: `Policy denies ${method} ${host}${path} for agent "${agent.name}" on the selected connection${
                selectedConnection ? ` "${selectedConnection.name}"` : ""
              }.`,
            }),
          );
          return;
        }
      }
    }

    // A selected app connection supplies a synthetic credential; otherwise the
    // legacy shared credential row.
    const credential = selectedConnection
      ? {
          id: selectedConnection.id,
          integrationId: integration.id,
          name: selectedConnection.name,
          data: selectedConnection.data,
          createdAt: selectedConnection.createdAt,
        }
      : this.opts.store.getCredential(integration.id);
    if (!credential) {
      this.opts.store.audit({
        agentId: agent.id,
        agentName: agent.name,
        integrationId: integration.id,
        host,
        method,
        path,
        decision: "no_credential",
        status: 502,
      });
      this.maybeNotifyOwner(agent, integration, "no_credential");
      const connect = this.connectUrlFor(agent, integration);
      res.writeHead(502, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: "onegate_no_credential",
          message: connect
            ? `No credential connected for integration "${integration.id}". Open the connect_url to connect it, then retry.`
            : `No credential connected for integration "${integration.id}". Connect it in the OneGate admin UI.`,
          ...(connect
            ? {
                connect_url: connect.url,
                connect_expires_at: connect.expiresAt,
                hint: "Show connect_url to your owner as a bare link. Opening it lets them connect this integration to you, then retry the request.",
              }
            : {}),
        }),
      );
      return;
    }

    const headers = forwardHeaders(req.headers);
    headers.host = host;

    // Integrations that sign the payload (e.g. AWS SigV4) need the body
    // before headers can be finalized, so it is buffered up front (bounded).
    // Everyone else keeps the pure streaming path.
    let body: Buffer | undefined;
    if (integration.needsBody) {
      try {
        body = await readBody(req, maxBufferedBody());
      } catch (err) {
        this.opts.store.audit({
          agentId: agent.id,
          agentName: agent.name,
          integrationId: integration.id,
          host,
          method,
          path,
          decision: "body_too_large",
          status: 413,
        });
        res.writeHead(413, { "content-type": "application/json" });
        res.end(
          JSON.stringify({ error: "onegate_body_too_large", message: (err as Error).message }),
        );
        return;
      }
    }

    // Integrations may reassign injectCtx.path to carry URL-path credentials
    // upstream (e.g. Telegram bot tokens). Policy and audit above and below
    // intentionally keep using the original path the agent sent.
    const injectCtx = {
      headers,
      method,
      path,
      host,
      credential,
      store: this.opts.store,
      body,
    };
    try {
      await integration.inject(injectCtx);
    } catch (err) {
      this.log(`inject failed for ${integration.id}: ${(err as Error).message}`);
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "onegate_inject_failed", message: (err as Error).message }));
      return;
    }

    // A buffered body is replayed with an exact content-length (the agent
    // may have sent chunked encoding, which was stripped as hop-by-hop).
    if (body !== undefined) headers["content-length"] = String(body.length);

    const target = this.opts.upstreamLookup?.(host, port) ?? { host, port };
    const upstream = https.request(
      {
        host: target.host,
        port: target.port,
        servername: host,
        method,
        path: injectCtx.path,
        headers,
        agent: this.upstreamAgent,
        ...this.opts.upstreamTls,
      },
      (upRes) => {
        this.opts.store.audit({
          agentId: agent.id,
          agentName: agent.name,
          integrationId: integration.id,
          host,
          method,
          path,
          decision: "allow",
          ruleId: effectiveVerdict.ruleId,
          status: upRes.statusCode ?? null,
          connectionId: selectedConnection?.id ?? null,
          connectionName: selectedConnection?.name ?? null,
        });
        const outHeaders: http.OutgoingHttpHeaders = {};
        for (const [k, v] of Object.entries(upRes.headers)) {
          if (!HOP_BY_HOP.has(k)) outHeaders[k] = v;
        }
        res.writeHead(upRes.statusCode ?? 502, outHeaders);
        upRes.pipe(res);
      },
    );
    upstream.on("error", (err) => {
      this.log(`upstream error for ${host}: ${err.message}`);
      if (!res.headersSent) {
        res.writeHead(502, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "onegate_upstream_error", message: err.message }));
      } else {
        res.destroy();
      }
    });
    if (body !== undefined) {
      upstream.end(body);
    } else {
      req.pipe(upstream);
    }
  }

  /**
   * Resolves whether this request is LLM-routed. Returns null (legacy path)
   * unless the integration declares an llm vendor, the agent has LLM routing
   * enabled, and at least one of its configured connections belongs to the
   * vendor being called.
   */
  private resolveLlmRoute(agent: Agent, integration: Integration): LlmRoute | null {
    if (!integration.llm) return null;
    const cfg = this.opts.store.getAgentLlmConfig(agent.id);
    if (!cfg?.enabled) return null;
    const vendor = integration.llm.vendor;
    const connections: Connection[] = [];
    for (const id of cfg.connectionIds) {
      const conn = this.opts.store.getConnection(id);
      if (conn && conn.kind === "llm" && conn.vendor === vendor) connections.push(conn);
    }
    if (connections.length === 0) return null;
    return { vendor, strategy: cfg.vendorStrategies?.[vendor] ?? cfg.strategy, connections };
  }

  /**
   * The LLM-routed request path. The strategy engine selects a connection,
   * its secret is injected via the integration's llm.inject, and the
   * buffered body lets the proxy retry ONCE on a connection error or a
   * 429/5xx that arrives before any response bytes were streamed back.
   * Every attempt is recorded in llm_usage, the final outcome lands in the
   * audit log with the selected connection and strategy.
   */
  private async handleLlmRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    ctx: SocketCtx,
    ruleId: string | null,
    route: LlmRoute,
    rules: Rule[] = [],
    needsConnection: boolean = false,
  ): Promise<void> {
    const { agent, host, port, integration } = ctx;
    const method = (req.method ?? "GET").toUpperCase();
    // Forward the canonical path (matching the one policy evaluated in
    // onInnerRequest) so the executed LLM request equals the matched request.
    const path = normalizeRequestPath(req.url ?? "/");
    const llm = integration.llm!;
    const ids = route.connections.map((c) => c.id);

    // Phase-2 connection-scoped policy check for the LLM path. Phase-1 ran
    // before any connection was resolved, so a connection-scoped rule was held
    // pending (needsConnection). Now, for whichever connection this path is
    // about to use, re-evaluate; a connection-scoped deny (e.g. "deny this LLM
    // integration unless the request uses connection X") must fire here just as
    // it does on the non-LLM path. Returns true when denied (and has already
    // written the 403 + audited), so the caller must stop. When needsConnection
    // is false (no connection-scoped rule matched) or the flag is off, this is a
    // no-op and never denies.
    const denyIfConnectionScoped = (conn: Connection): boolean => {
      if (!needsConnection) return false;
      const finalVerdict = evaluate(agent, rules, {
        integrationId: integration.id,
        method,
        path,
        connectionId: conn.id,
      });
      if (finalVerdict.effect !== "deny") return false;
      this.opts.store.audit({
        agentId: agent.id,
        agentName: agent.name,
        integrationId: integration.id,
        host,
        method,
        path,
        decision: "deny",
        ruleId: finalVerdict.ruleId,
        status: 403,
      });
      res.writeHead(403, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: "onegate_policy_denied",
          message: `Policy denies ${method} ${host}${path} for agent "${agent.name}" on the selected connection "${conn.name}".`,
        }),
      );
      return true;
    };

    let body: Buffer;
    try {
      body = await readBody(req, maxBufferedBody());
    } catch (err) {
      this.opts.store.audit({
        agentId: agent.id,
        agentName: agent.name,
        integrationId: integration.id,
        host,
        method,
        path,
        decision: "body_too_large",
        status: 413,
      });
      res.writeHead(413, { "content-type": "application/json" });
      res.end(
        JSON.stringify({ error: "onegate_body_too_large", message: (err as Error).message }),
      );
      return;
    }

    // The requested model, parsed from the body (Anthropic/OpenAI) or the URL
    // path (Gemini), recorded on every usage row for per-model analytics.
    const model = extractRequestModel(path, body);

    const persistState = (counters: {
      activeIndex: number;
      rrCursor: number;
      callsSinceFallback: number;
      cooldowns: Record<string, number>;
    }) => this.opts.store.setLlmStrategyState(agent.id, route.vendor, counters);

    const state = this.opts.store.getLlmStrategyState(agent.id, route.vendor);
    const selection = selectConnection(route.strategy, ids, state);
    persistState(selection.state);
    let counters = selection.state;

    const recordUsage = (
      conn: Connection,
      failover: boolean,
      errored: boolean,
      status: number | null,
      tokens?: TokenUsage,
    ) =>
      this.opts.store.recordLlmUsage({
        connectionId: conn.id,
        connectionName: conn.name,
        agentId: agent.id,
        vendor: route.vendor,
        model,
        strategy: route.strategy,
        errors: errored ? 1 : 0,
        inputTokens: tokens?.inputTokens ?? null,
        outputTokens: tokens?.outputTokens ?? null,
        failover,
        status,
      });

    const finalAudit = (conn: Connection, failover: boolean, status: number | null) =>
      this.opts.store.audit({
        agentId: agent.id,
        agentName: agent.name,
        integrationId: integration.id,
        host,
        method,
        path,
        decision: "allow",
        ruleId,
        status,
        connectionId: conn.id,
        connectionName: conn.name,
        llmVendor: route.vendor,
        llmStrategy: route.strategy,
        llmFailover: failover,
      });

    // One upstream attempt with the given connection. Resolves with the
    // upstream response (any status) or rejects on a connection-level or
    // injection failure.
    const attempt = (conn: Connection): Promise<http.IncomingMessage> =>
      new Promise((resolve, reject) => {
        const headers = forwardHeaders(req.headers);
        headers.host = host;
        const injectCtx = {
          headers,
          method,
          path,
          host,
          // Synthetic credential carrying the SELECTED connection's data.
          credential: {
            id: conn.id,
            integrationId: integration.id,
            name: conn.name,
            data: conn.data,
            createdAt: conn.createdAt,
          },
          store: this.opts.store,
          body,
        };
        Promise.resolve()
          .then(() => llm.inject(injectCtx))
          .then(() => {
            headers["content-length"] = String(body.length);
            const target = this.opts.upstreamLookup?.(host, port) ?? { host, port };
            const upstream = https.request(
              {
                host: target.host,
                port: target.port,
                servername: host,
                method,
                path: injectCtx.path,
                headers,
                agent: this.upstreamAgent,
                ...this.opts.upstreamTls,
              },
              resolve,
            );
            upstream.on("error", reject);
            upstream.end(body);
          })
          .catch(reject);
      });

    const streamBack = (upRes: http.IncomingMessage) => {
      const outHeaders: http.OutgoingHttpHeaders = {};
      for (const [k, v] of Object.entries(upRes.headers)) {
        if (!HOP_BY_HOP.has(k)) outHeaders[k] = v;
      }
      res.writeHead(upRes.statusCode ?? 502, outHeaders);
      upRes.pipe(res);
    };

    // Marks the attempt's error in the strategy state and returns the
    // connection to retry with, or null when there is nothing to retry.
    const failOver = (erroredIndex: number): Connection | null => {
      const outcome = onSelectionError(route.strategy, ids, counters, erroredIndex);
      counters = outcome.state;
      persistState(counters);
      return outcome.retryIndex === null ? null : route.connections[outcome.retryIndex];
    };

    let index = selection.index;
    let conn = route.connections[index];
    let failover = false;
    for (;;) {
      // Enforce connection-scoped policy for the connection this iteration will
      // use — both the initially selected one and any failover target — before
      // dispatching upstream. A denied connection never reaches the vendor.
      if (denyIfConnectionScoped(conn)) return;
      let upRes: http.IncomingMessage;
      try {
        upRes = await attempt(conn);
      } catch (err) {
        this.log(`llm upstream error for ${host} via ${conn.id}: ${(err as Error).message}`);
        recordUsage(conn, failover, true, null);
        const next = failover ? null : failOver(index);
        if (next) {
          index = ids.indexOf(next.id);
          conn = next;
          failover = true;
          continue;
        }
        finalAudit(conn, failover, 502);
        res.writeHead(502, { "content-type": "application/json" });
        res.end(
          JSON.stringify({ error: "onegate_upstream_error", message: (err as Error).message }),
        );
        return;
      }
      const status = upRes.statusCode;
      if (isRetryableStatus(status)) {
        recordUsage(conn, failover, true, status ?? null);
        const next = failover ? null : failOver(index);
        if (next) {
          // No bytes have been written back yet (the head is only written in
          // streamBack), so the retry is safe. Drain the errored response to
          // free its socket.
          upRes.resume();
          index = ids.indexOf(next.id);
          conn = next;
          failover = true;
          continue;
        }
        finalAudit(conn, failover, status ?? null);
        streamBack(upRes);
        return;
      }
      finalAudit(conn, failover, status ?? null);
      // Best-effort token accounting: tap the response stream on its way
      // through (the forwarded bytes are never altered, delayed or buffered)
      // and record the usage row once the upstream body ends. Compressed or
      // non-JSON/SSE bodies get no scanner and record null tokens right away.
      const scanner = createUsageScanner(upRes.headers);
      if (!scanner) {
        recordUsage(conn, failover, false, status ?? null);
        streamBack(upRes);
        return;
      }
      let usageRecorded = false;
      const finishUsage = () => {
        if (usageRecorded) return;
        usageRecorded = true;
        recordUsage(conn, failover, false, status ?? null, scanner.result());
      };
      upRes.on("data", (chunk: Buffer) => scanner.feed(chunk));
      // These listeners are attached before streamBack's pipe, so the usage
      // row is written before the client observes the end of the response.
      upRes.once("end", finishUsage);
      upRes.once("close", finishUsage);
      streamBack(upRes);
      return;
    }
  }
}
