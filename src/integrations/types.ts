/**
 * Integration contract. An integration declares which hosts it owns and how
 * to inject credentials into an outgoing request. Community integrations
 * implement this interface and register themselves (see community/README.md).
 */

import type { IncomingHttpHeaders } from "node:http";
import type { Credential } from "../types.js";
import type { Store } from "../store/db.js";

export interface CredentialField {
  key: string;
  label: string;
  secret: boolean;
  /** Optional fields render without `required` and may be left empty. */
  optional?: boolean;
  /** Multiline fields render as a textarea (e.g. pasted JSON key files). */
  multiline?: boolean;
}

/**
 * Optional hints an integration can declare to improve the "ask your LLM for
 * help" prompt shown in the admin UI's connect dialog. All fields are plain
 * text. Integrations without hints still get a sensible generic prompt
 * composed from their metadata (see llm-help.ts).
 */
export interface LlmHelpHints {
  /** What kind of credential this is and how OneGate uses it. */
  credentialType?: string;
  /** Where the user creates it, e.g. a settings URL with navigation hints. */
  whereToCreate?: string;
  /** Scopes or permissions OneGate needs for the API paths it proxies. */
  scopes?: string[];
  /** Extra integration-specific guidance, may span multiple lines. */
  notes?: string;
}

/**
 * Human friendly description of an OAuth permission/scope, shown as a
 * checkbox hint in the connect dialog.
 */
export interface OAuthPermission {
  /** The OAuth scope string (e.g. "repo", "read_user"). */
  scope: string;
  /** User facing name (e.g. "Repositories"). */
  name: string;
  /** Short description (e.g. "Public and private repos, issues, PRs"). */
  description: string;
  /** Access level indicator. */
  access: "read" | "write";
}

/**
 * Declarative OAuth 2.0 descriptor. The generic engine in oauth.ts builds the
 * consent URL, exchanges the authorization code, and refreshes access tokens
 * from this data. All OAuth integrations are bring-your-own-client: the user
 * pastes their own OAuth app's client id and secret in the connect dialog.
 */
export interface OAuthDescriptor {
  /** Authorization (consent) endpoint. */
  authUrl: string;
  /**
   * Token endpoint for the code exchange and refresh grants. Empty for
   * fragment-callback providers that return the token directly (Trello).
   */
  tokenUrl: string;
  /** Scopes requested when the user does not pick their own. */
  defaultScopes: string[];
  /** Human readable scope descriptions. Drives the permissions checkboxes. */
  permissions?: OAuthPermission[];
  /** Extra query params for the auth URL (e.g. access_type=offline). */
  extraAuthParams?: Record<string, string>;
  /** Scope separator in the auth URL. Defaults to a space (Todoist: ","). */
  scopeSeparator?: string;
  /** Providers whose auth URL takes no scope param at all (Monday). */
  omitScopeParam?: boolean;
  /** Auth URL param carrying the client id. Default "client_id" (Trello: "key"). */
  clientIdParam?: string;
  /** Auth URL param carrying the redirect URI. Default "redirect_uri" (Trello: "return_url"). */
  redirectUriParam?: string;
  /** response_type value. Default "code" (Trello: "token"). */
  responseType?: string;
  /** How client credentials ride in token requests: request body (default) or HTTP Basic (Supabase). */
  tokenAuth?: "body" | "basic";
  /** Token request encoding: form (default) or JSON (Atlassian). */
  tokenFormat?: "form" | "json";
  /** Send redirect_uri in the code exchange. Default true (Todoist: false). */
  sendRedirectUriInExchange?: boolean;
  /**
   * Providers that return the token in the URL fragment (#token=...) instead
   * of a code query param. The callback serves a small bridge page that
   * extracts the named param from the fragment and resubmits it as a query
   * parameter for the server.
   */
  fragmentCallback?: { paramName: string };
}

/**
 * A selectable bundle of scopes ("app") for integrations that gate many
 * products behind one OAuth consent (Google: Gmail, Calendar, Drive, ...).
 * The connect dialog renders these as checkboxes.
 */
export interface ScopePack {
  id: string;
  label: string;
  description?: string;
  scopes: string[];
  permissions?: OAuthPermission[];
  /** Checked by default in the connect dialog. */
  default?: boolean;
}

/**
 * In-page guide shown on the self-service connect wizard, walking a bot owner
 * through creating their own OAuth app for this integration. Plain text steps,
 * no markdown. Integrations without one get a generic fallback guide.
 */
export interface ConnectGuide {
  /** Ordered plain-text steps. */
  steps: string[];
  /** Optional link to the provider console where the OAuth app is created. */
  consoleUrl?: string;
}

/** Optional client-side file import that pre-fills connect dialog fields. */
export interface FileImport {
  /** Button label (e.g. "Import service account JSON"). */
  label: string;
  /** File input accept filter (e.g. ".json,application/json"). */
  accept: string;
  /** Maps JSON keys in the file to credential field keys. */
  keyMap?: Record<string, string>;
  /** Put the raw file content into this single field instead of mapping keys. */
  rawField?: string;
}

/**
 * Tells the admin UI which connect dialog to render. Integrations without
 * connect metadata get the plain api_key form built from credentialFields.
 */
export interface ConnectMeta {
  method: "oauth" | "api_key" | "credentials_import";
  /** Short hint shown at the top of the connect dialog. */
  hint?: string;
  /** For credentials_import (and api_key) dialogs: optional file import. */
  fileImport?: FileImport;
}

export interface InjectionContext {
  /** Mutable copy of the request headers. Mutations are forwarded upstream. */
  headers: IncomingHttpHeaders;
  method: string;
  /**
   * Request path. Reassigning it forwards the rewritten path upstream, for
   * APIs that carry credentials in the URL (policy and audit always see the
   * original path the agent sent).
   */
  path: string;
  host: string;
  credential: Credential;
  /** For integrations that need persistent state, e.g. OAuth token caches. */
  store: Store;
  /**
   * Full request body, present only when the integration declares
   * `needsBody` (the gateway buffers the body before calling inject, so
   * signing schemes like AWS SigV4 can hash the payload). A bodyless
   * request yields an empty Buffer.
   */
  body?: Buffer;
}

/**
 * LLM routing metadata. An integration with an `llm` block is an LLM vendor:
 * the proxy may route its hosts through the per-agent strategy engine, which
 * selects one of the agent's LLM connections per request. `inject` receives a
 * synthetic Credential built from the SELECTED connection (its `data` is the
 * connection's data), so it must not assume the app credentials table.
 */
export interface LlmMeta {
  /** Vendor id used for connections, strategy state and usage (anthropic|openai|gemini). */
  vendor: string;
  /** Injects the selected connection's secret into the request. */
  inject(ctx: InjectionContext): void | Promise<void>;
}

/**
 * A host claim narrowed to a path prefix. Lets two integrations with different
 * auth modes share one hostname: the vendor exposes both OAuth product APIs and
 * simple key-based APIs on the same host (www.googleapis.com serves Workspace
 * OAuth APIs and the API-key-only YouTube Data API).
 *
 * `path` must be an absolute, glob-free prefix (e.g. "/youtube/v3"). It matches
 * the prefix itself and anything beneath it, on SEGMENT boundaries only, so
 * "/youtube/v3" matches "/youtube/v3" and "/youtube/v3/search" but never
 * "/youtube/v31".
 */
export interface PathScopedHost {
  host: string;
  path: string;
}

/**
 * One entry in `Integration.hosts`: a bare hostname (claims the whole host, the
 * long-standing form) or a host narrowed to a path prefix.
 */
export type HostClaim = string | PathScopedHost;

export interface Integration {
  id: string;
  title: string;
  /**
   * Hostnames this integration owns. An entry starting with "." matches any
   * subdomain (".googleapis.com" matches "gmail.googleapis.com").
   *
   * An entry may instead be `{ host, path }` to claim only a path prefix of that
   * host (see PathScopedHost). A path-scoped claim is MORE SPECIFIC than a bare
   * host claim: it wins for requests under its prefix while the bare claim keeps
   * serving the rest of the host. Two path-scoped claims on one host resolve
   * longest-prefix-first.
   */
  hosts: HostClaim[];
  /** Fields the admin UI should collect when connecting this integration. */
  credentialFields: CredentialField[];
  /** Grouping label for the admin UI integration list. */
  category?: string;
  /** Connect dialog kind. Defaults to an api_key form over credentialFields. */
  connect?: ConnectMeta;
  /** OAuth descriptor, required when connect.method is "oauth". */
  oauth?: OAuthDescriptor;
  /** Selectable scope bundles for multi-product OAuth consents (Google). */
  scopePacks?: ScopePack[];
  /** In-page owner guide for the self-service connect wizard (OAuth apps). */
  connectGuide?: ConnectGuide;
  /** Optional hints for the "ask your LLM for help" connect prompt. */
  llmHelp?: LlmHelpHints;
  /**
   * When true the gateway buffers the request body (bounded, see
   * ONEGATE_MAX_BUFFERED_BODY) and exposes it as `ctx.body` so inject can
   * sign the payload. Leave unset for plain header injection: the body
   * then streams through untouched.
   */
  needsBody?: boolean;
  /** Present on LLM vendor integrations, enables per-agent connection routing. */
  llm?: LlmMeta;
  /** True for integrations loaded from the community drop-in directory. */
  community?: boolean;
  /**
   * Optional. Returns a NON-SECRET, human-readable summary of one connected
   * account (a credential or connection), surfaced by the agent-facing
   * discovery endpoint. Use it for facts an agent needs to call the API but
   * that OneGate does not otherwise record, e.g. the Jira site URL. The
   * returned object MUST NOT contain any secret material (tokens, passwords).
   */
  accountSummary?(cred: Credential): Record<string, string | null>;
  /** Mutates ctx.headers to carry real credentials. May be async (OAuth refresh). */
  inject(ctx: InjectionContext): void | Promise<void>;
}

/** Normalizes a claim into its object form. */
function claimParts(entry: HostClaim): { host: string; path: string | null } {
  return typeof entry === "string"
    ? { host: entry, path: null }
    : { host: entry.host, path: entry.path };
}

/**
 * How an agent-scoped self-service connect link should let an owner connect
 * this integration, or null when there is no self-service path:
 *  - "oauth"      : the owner brings their OAuth app and consents (the OAuth
 *                   wizard + provider redirect).
 *  - "credential" : the owner pastes a credential (an API key, a token, a
 *                   service-account JSON) into the paste wizard.
 * LLM-vendor integrations are excluded: their access is wired through per-agent
 * LLM routing, not the app connect wizard. This is the single source of truth
 * the proxy (for minting connect_url on not-connected errors) and the admin API
 * (for minting links and picking which wizard to render) both consult, so every
 * connectable integration self-serves the same way.
 */
export function connectFlowKind(integration: Integration): "oauth" | "credential" | null {
  if (integration.llm) return null;
  if (integration.oauth) return "oauth";
  if (integration.credentialFields.length > 0) return "credential";
  return null;
}

/**
 * How specifically an integration's host entry matches a concrete host. Higher
 * wins. An exact host claim always beats a dot-suffix claim, and among suffix
 * claims the longest (most specific) suffix wins, so resolution does not depend
 * on the order integrations were registered in.
 *
 * Returns null when `entry` does not claim `host` at all.
 */
function claimSpecificity(entry: HostClaim, host: string): number | null {
  const { host: pattern, path: prefix } = claimParts(entry);
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();
  if (p.startsWith(".")) {
    if (h.endsWith(p) || h === p.slice(1)) {
      return p.length;
    }
    return null;
  }
  if (h === p) {
    return prefix === null ? EXACT_RANK : EXACT_RANK - 1;
  }
  return null;
}

/** Above any possible suffix length, so exact claims always sort first. */
const EXACT_RANK = Number.MAX_SAFE_INTEGER;

/**
 * The strongest claim `integration` has on `host`, or null when it claims none.
 * An integration listing both an exact host and a covering suffix keeps the
 * exact (stronger) rank.
 */
function bestClaim(integration: Integration, host: string): number | null {
  let best: number | null = null;
  for (const entry of integration.hosts) {
    const rank = claimSpecificity(entry, host);
    if (rank !== null && (best === null || rank > best)) best = rank;
  }
  return best;
}

/**
 * Whether a path-scoped claim's prefix covers `path`.
 *
 * `path` MUST already be canonical (see normalizeRequestPath in policy.ts:
 * percent-decoded once, dot-segments and duplicate slashes collapsed). This
 * function deliberately does NOT normalize: re-normalizing would peel a second
 * percent-decode layer the proxy never applied and never forwards upstream, so a
 * double-encoded path could be scoped to one integration while the vendor serves
 * another. Matching the forwarded path verbatim is what keeps credential
 * injection aligned with the request actually made.
 *
 * Matching is on SEGMENT boundaries: "/youtube/v3" covers "/youtube/v3",
 * "/youtube/v3/" and "/youtube/v3/search", but not "/youtube/v31".
 */
export function pathScopeMatches(prefix: string, path: string): boolean {
  const bare = path.split("?")[0];
  const p = prefix.length > 1 && prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
  if (p === "/" || p === "") return true;
  if (!bare.startsWith(p)) return false;
  const next = bare.charAt(p.length);
  return next === "" || next === "/";
}

/**
 * Integration pairs that deliberately claim identical hosts, keyed by the
 * sorted id pair. Both stay candidates and the proxy picks whichever has a
 * connected credential (see resolveHostCandidates), so an exact-host overlap
 * between these is expected rather than a configuration error.
 */
const INTENTIONAL_HOST_SHARERS = new Set([
  "github\x00github-app",
  "confluence\x00jira",
  "google\x00youtube",
]);

function sharerKey(a: string, b: string): string {
  return a < b ? `${a}\x00${b}` : `${b}\x00${a}`;
}

export class Registry {
  private byId = new Map<string, Integration>();

  register(integration: Integration): void {
    if (this.byId.has(integration.id)) {
      throw new Error(`Integration "${integration.id}" already registered`);
    }
    this.assertNoExactHostCollision(integration);
    this.byId.set(integration.id, integration);
  }

  /**
   * Rejects a new integration that claims the exact same host as an existing
   * one, unless the pair is a known intentional sharer.
   */
  private assertNoExactHostCollision(integration: Integration): void {
    const incoming = new Set(
      integration.hosts
        .map(claimParts)
        .filter(({ host, path }) => path === null && !host.startsWith("."))
        .map(({ host }) => host.toLowerCase()),
    );
    if (incoming.size === 0) return;
    for (const existing of this.byId.values()) {
      if (INTENTIONAL_HOST_SHARERS.has(sharerKey(existing.id, integration.id))) continue;
      for (const entry of existing.hosts) {
        const { host: existingHost, path: existingPath } = claimParts(entry);
        if (existingPath !== null || existingHost.startsWith(".")) continue;
        const host = existingHost.toLowerCase();
        if (incoming.has(host)) {
          throw new Error(
            `Integration "${integration.id}" claims host "${host}" already owned by ` +
              `"${existing.id}". Two integrations claiming the same exact host is ambiguous: ` +
              `rename the host, or add the pair to INTENTIONAL_HOST_SHARERS if both are meant ` +
              `to be candidates.`,
          );
        }
      }
    }
  }

  get(id: string): Integration | null {
    return this.byId.get(id) ?? null;
  }

  list(): Integration[] {
    return [...this.byId.values()];
  }

  /** Finds the integration owning `host`, or null (→ passthrough). */
  resolveHost(host: string): Integration | null {
    return this.resolveHostCandidates(host)[0] ?? null;
  }

  /**
   * All integrations claiming `host`, most specific first. Specificity, not
   * registration order, decides: an exact host claim outranks a dot-suffix
   * claim, and a longer suffix outranks a shorter one.
   *
   * PATH-SCOPED CLAIMS: this is the host-only view, used at CONNECT time when no
   * path is known yet. An integration whose only claim on this host is path-scoped
   * IS included here, so the host still terminates. Narrowing to the one integration
   * that owns the request's path happens later: see resolveHostPathCandidates.
   */
  resolveHostCandidates(host: string): Integration[] {
    const h = host.toLowerCase();
    const matches: { integration: Integration; rank: number; order: number }[] = [];
    let order = 0;
    for (const integration of this.byId.values()) {
      const rank = bestClaim(integration, h);
      if (rank !== null) matches.push({ integration, rank, order });
      order++;
    }
    // Stable by construction: ties fall back to registration order.
    matches.sort((a, b) => b.rank - a.rank || a.order - b.order);
    return matches.map((m) => m.integration);
  }

  /**
   * Candidates for `host` narrowed by the request `path`, most specific first.
   *
   * Resolution rule:
   *  - A path-scoped claim matching `path` is MORE SPECIFIC than a bare host
   *    claim and sorts ahead of it.
   *  - Two matching path-scoped claims sort longest-prefix-first.
   *  - Bare host claims keep their relative specificity and serve everything
   *    a path-scoped claim did not match.
   *  - A path-scoped claim that does NOT match `path` is dropped entirely.
   */
  resolveHostPathCandidates(host: string, path: string): Integration[] {
    const h = host.toLowerCase();
    const scored: { integration: Integration; specificity: number; hostRank: number; order: number }[] = [];
    let order = 0;
    for (const integration of this.byId.values()) {
      const idx = order++;
      let bestPathScore: number | null = null;
      let bestHostRank: number | null = null;
      for (const entry of integration.hosts) {
        const { host: pattern, path: prefix } = claimParts(entry);
        const hostRank = claimSpecificity(pattern.toLowerCase(), h);
        if (hostRank === null) continue;
        if (bestHostRank === null || hostRank > bestHostRank) bestHostRank = hostRank;

        if (prefix == null) {
          if (bestPathScore === null) bestPathScore = 0;
          continue;
        }
        if (!pathScopeMatches(prefix, path)) continue;
        const score = prefix.length;
        if (bestPathScore === null || score > bestPathScore) bestPathScore = score;
      }
      if (bestPathScore !== null && bestHostRank !== null) {
        scored.push({ integration, specificity: bestPathScore, hostRank: bestHostRank, order: idx });
      }
    }
    scored.sort((a, b) => b.specificity - a.specificity || b.hostRank - a.hostRank || a.order - b.order);
    return scored.map((s) => s.integration);
  }
}
