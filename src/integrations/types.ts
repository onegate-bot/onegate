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

export interface Integration {
  id: string;
  title: string;
  /**
   * Hostnames this integration owns. An entry starting with "." matches any
   * subdomain (".googleapis.com" matches "gmail.googleapis.com").
   */
  hosts: string[];
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

export class Registry {
  private byId = new Map<string, Integration>();

  register(integration: Integration): void {
    if (this.byId.has(integration.id)) {
      throw new Error(`Integration "${integration.id}" already registered`);
    }
    this.byId.set(integration.id, integration);
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
   * All integrations claiming `host`, in registration order. A host may have
   * several owners (api.github.com: github PAT and github-app). The proxy
   * picks the first candidate with a connected credential, so connecting
   * exactly one of the overlapping integrations selects it.
   */
  resolveHostCandidates(host: string): Integration[] {
    const h = host.toLowerCase();
    const out: Integration[] = [];
    for (const integration of this.byId.values()) {
      for (const entry of integration.hosts) {
        if (entry.startsWith(".")) {
          if (h.endsWith(entry) || h === entry.slice(1)) {
            out.push(integration);
            break;
          }
        } else if (h === entry) {
          out.push(integration);
          break;
        }
      }
    }
    return out;
  }
}
