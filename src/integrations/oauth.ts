/**
 * Generic OAuth 2.0 engine. Builds consent URLs, exchanges authorization
 * codes and refreshes access tokens from a declarative OAuthDescriptor
 * (see types.ts). Also covers the client_credentials grant used by services
 * with service-account style keys (MongoDB Atlas).
 *
 * Stored credential shape for OAuth integrations:
 *   { clientId, clientSecret, accessToken?, refreshToken?, expiresAt?, scopes? }
 * expiresAt is epoch seconds. Legacy Google credentials
 * ({ clientId, clientSecret, refreshToken }) keep working unchanged.
 *
 * Token calls go through direct node:https (never fetch, the global
 * dispatcher may carry an ambient proxy) and cache in the settings table,
 * sealed at rest (these are live upstream access tokens).
 */

import type { OAuthDescriptor } from "./types.js";
import type { Credential } from "../types.js";
import type { Store } from "../store/db.js";
import { postForm, postJson, type HttpResult } from "../util/http.js";

/** Safety margin: refresh when a token is within a minute of expiry. */
const EXPIRY_MARGIN_MS = 60_000;

function envKey(integrationId: string, kind: "TOKEN" | "AUTH"): string {
  return `ONEGATE_OAUTH_${kind}_URL_${integrationId.toUpperCase().replace(/-/g, "_")}`;
}

/** Token endpoint, overridable per integration for tests. */
export function resolveTokenUrl(integrationId: string, oauth: OAuthDescriptor): string {
  if (integrationId === "google" && process.env.ONEGATE_GOOGLE_TOKEN_URL) {
    return process.env.ONEGATE_GOOGLE_TOKEN_URL;
  }
  return process.env[envKey(integrationId, "TOKEN")] ?? oauth.tokenUrl;
}

/** Authorization endpoint, overridable per integration for tests. */
export function resolveAuthUrl(integrationId: string, oauth: OAuthDescriptor): string {
  return process.env[envKey(integrationId, "AUTH")] ?? oauth.authUrl;
}

export interface AuthUrlParams {
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state: string;
}

/** Builds the consent URL the user's browser is sent to. */
export function buildAuthUrl(
  integrationId: string,
  oauth: OAuthDescriptor,
  { clientId, redirectUri, scopes, state }: AuthUrlParams,
): string {
  const params = new URLSearchParams();
  params.set(oauth.clientIdParam ?? "client_id", clientId);
  params.set(oauth.redirectUriParam ?? "redirect_uri", redirectUri);
  params.set("response_type", oauth.responseType ?? "code");
  if (!oauth.omitScopeParam && scopes.length) {
    params.set("scope", scopes.join(oauth.scopeSeparator ?? " "));
  }
  for (const [k, v] of Object.entries(oauth.extraAuthParams ?? {})) params.set(k, v);
  params.set("state", state);
  const base = resolveAuthUrl(integrationId, oauth);
  return `${base}${base.includes("?") ? "&" : "?"}${params.toString()}`;
}

export interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  error?: string;
  error_description?: string;
  /** Provider-specific extras (Salesforce instance_url), see persistTokenFields. */
  [extra: string]: unknown;
}

function tokenRequest(
  url: string,
  oauth: OAuthDescriptor,
  fields: Record<string, string>,
  clientId: string,
  clientSecret: string,
): Promise<HttpResult> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (oauth.tokenAuth === "basic") {
    headers.authorization =
      "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
  } else {
    fields.client_id = clientId;
    fields.client_secret = clientSecret;
  }
  return oauth.tokenFormat === "json"
    ? postJson(url, fields, headers)
    : postForm(url, new URLSearchParams(fields), headers);
}

function parseTokenResponse(res: HttpResult, what: string): TokenResponse {
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`${what} failed (${res.status}): ${res.body.slice(0, 300)}`);
  }
  let json: TokenResponse;
  try {
    json = JSON.parse(res.body) as TokenResponse;
  } catch {
    throw new Error(`${what} returned a non-JSON response: ${res.body.slice(0, 300)}`);
  }
  if (json.error || !json.access_token) {
    throw new Error(
      `${what} failed: ${json.error_description ?? json.error ?? "no access_token in response"}`,
    );
  }
  return json;
}

export interface ExchangeParams {
  code: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

/** Exchanges an authorization code for tokens at the descriptor's token endpoint. */
export async function exchangeCode(
  integrationId: string,
  oauth: OAuthDescriptor,
  { code, clientId, clientSecret, redirectUri }: ExchangeParams,
): Promise<TokenResponse> {
  const fields: Record<string, string> = { grant_type: "authorization_code", code };
  if (oauth.sendRedirectUriInExchange !== false) fields.redirect_uri = redirectUri;
  const res = await tokenRequest(
    resolveTokenUrl(integrationId, oauth),
    oauth,
    fields,
    clientId,
    clientSecret,
  );
  return parseTokenResponse(res, "Token exchange");
}

/**
 * Credential data keys the engine itself owns. persistTokenFields may never
 * write these, so a provider response cannot clobber the client secret or the
 * tokens through a mapping.
 */
const RESERVED_DATA_KEYS = new Set([
  "clientId",
  "clientSecret",
  "accessToken",
  "refreshToken",
  "expiresAt",
  "scopes",
]);

/**
 * The descriptor's persistTokenFields applied to a token response: response
 * key -> credential data key, string values only, reserved engine keys
 * skipped. Used by both the code exchange and every refresh.
 */
export function pickTokenFields(
  oauth: OAuthDescriptor,
  tokens: TokenResponse,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [from, to] of Object.entries(oauth.persistTokenFields ?? {})) {
    if (RESERVED_DATA_KEYS.has(to)) continue;
    const v = tokens[from];
    if (typeof v === "string" && v) out[to] = v;
  }
  return out;
}

/**
 * Where a credential came from, decided by its id (connections are minted
 * "conn_", legacy credentials "cr_"), never by what exists in the store now.
 * A connection deleted mid-refresh must not fall through to the legacy
 * credentials upsert: that would resurrect a revoked account's secrets as the
 * tenant-wide credential every agent can use.
 */
function isConnectionBacked(cred: Credential): boolean {
  return cred.id.startsWith("conn_");
}

/**
 * The CURRENT stored data of the credential's origin row, or null when that
 * row is gone (a deleted connection, or a legacy credential deleted or
 * replaced by a different row).
 */
function currentOriginData(
  store: Store,
  integrationId: string,
  cred: Credential,
): Record<string, string> | null {
  if (isConnectionBacked(cred)) return store.getConnection(cred.id)?.data ?? null;
  const row = store.getCredential(integrationId);
  return row && row.id === cred.id ? row.data : null;
}

/**
 * Applies `delta` onto the origin row as it is NOW (so a concurrent admin edit
 * or re-authorize is kept), writing only when something changes. Returns false
 * when the origin row no longer exists, in which case nothing is written.
 */
function applyCredentialDelta(
  store: Store,
  integrationId: string,
  cred: Credential,
  delta: Record<string, string>,
): boolean {
  const current = currentOriginData(store, integrationId, cred);
  if (!current) return false;
  if (Object.entries(delta).every(([k, v]) => current[k] === v)) return true;
  const data = { ...current, ...delta };
  // keepTokenCache: the caller caches the token it just minted right after.
  if (isConnectionBacked(cred)) {
    store.updateConnection(cred.id, { data }, { keepTokenCache: true });
  } else {
    store.setCredential(integrationId, cred.name, data, { keepTokenCache: true });
  }
  return true;
}

interface CachedToken {
  token: string;
  /** Epoch ms expiry. */
  exp: number;
}

interface RefreshResult extends CachedToken {
  /** False when the credential's origin row was deleted during the refresh. */
  live: boolean;
}

function cacheKey(integrationId: string, credId: string): string {
  return `oauth_access_token:${integrationId}:${credId}`;
}

/**
 * In-flight refreshes, keyed by the same cache key the resulting token is
 * stored under. Providers that rotate the refresh token on every use (GitLab)
 * invalidate the presented token as soon as the first exchange lands, so two
 * concurrent refreshes against one credential would leave the loser holding a
 * consumed token: its exchange is rejected and, worse, a late write could
 * clobber the winner's freshly rotated token and brick the credential. Callers
 * that arrive while a refresh is running await that same promise instead.
 */
const inFlightRefreshes = new Map<string, Promise<CachedToken>>();

/**
 * Runs a refresh under a per-credential single flight. The entry is cleared in
 * a finally so a rejected refresh never poisons later attempts, and only the
 * owner of the flight persists the token, so a late loser cannot overwrite a
 * newer cache entry.
 */
function refreshSingleFlight(
  key: string,
  run: () => Promise<CachedToken>,
): Promise<CachedToken> {
  const existing = inFlightRefreshes.get(key);
  if (existing) return existing;
  const flight = run().finally(() => {
    // Only retract our own entry: a later flight may already own the key.
    if (inFlightRefreshes.get(key) === flight) inFlightRefreshes.delete(key);
  });
  inFlightRefreshes.set(key, flight);
  return flight;
}

function readCache(store: Store, key: string): string | null {
  // Sealed at rest; a legacy plaintext row still reads, an unreadable one
  // degrades to a cache miss so the token is simply re-minted.
  const cached = store.getSecretSetting<CachedToken>(key);
  if (!cached) return null;
  return cached.exp - Date.now() > EXPIRY_MARGIN_MS ? cached.token : null;
}

async function refreshAccessToken(
  integrationId: string,
  oauth: OAuthDescriptor,
  cred: Credential,
  store: Store,
): Promise<RefreshResult> {
  const { clientId, clientSecret, refreshToken } = cred.data;
  if (!clientId || !clientSecret || !refreshToken) {
    throw new Error(
      `${integrationId} credential needs clientId, clientSecret and refreshToken to refresh`,
    );
  }
  const res = await tokenRequest(
    resolveTokenUrl(integrationId, oauth),
    oauth,
    { grant_type: "refresh_token", refresh_token: refreshToken },
    clientId,
    clientSecret,
  );
  const json = parseTokenResponse(res, `${integrationId} token refresh`);
  // Some providers rotate the refresh token on every use (GitLab). Persist
  // the replacement or the next refresh would fail. Mapped extras
  // (persistTokenFields, e.g. Salesforce's instance_url) are refreshed the
  // same way. Only this delta is applied, onto the origin row as it is now
  // (connection row or legacy credential, chosen by the credential's id).
  const delta = pickTokenFields(oauth, json);
  if (json.refresh_token && json.refresh_token !== refreshToken) {
    delta.refreshToken = json.refresh_token;
  }
  // A credential whose origin row vanished (revoked connection, deleted
  // legacy credential) must not have its freshly minted token cached either.
  const live = applyCredentialDelta(store, integrationId, cred, delta);
  return {
    token: json.access_token!,
    exp: Date.now() + (json.expires_in ?? oauth.defaultExpiresIn ?? 3600) * 1000,
    live,
  };
}

/**
 * Returns a live access token for an OAuth credential, refreshing through the
 * descriptor's token endpoint when needed. Refreshed tokens are cached in the
 * settings table. Credentials without a refresh token (long lived provider
 * tokens like Trello or Monday) return the stored access token as is.
 */
export async function oauthBearerToken(
  integration: { id: string; oauth?: OAuthDescriptor },
  cred: Credential,
  store: Store,
): Promise<string> {
  const { accessToken, refreshToken, expiresAt } = cred.data;

  if (!refreshToken) {
    if (!accessToken) {
      throw new Error(`${integration.id} credential has neither an accessToken nor a refreshToken`);
    }
    return accessToken;
  }

  const key = cacheKey(integration.id, cred.id);
  const cached = readCache(store, key);
  if (cached) return cached;

  // The token stored at connect time may still be fresh.
  if (accessToken && expiresAt) {
    const expMs = Number(expiresAt) * 1000;
    if (Number.isFinite(expMs) && expMs - Date.now() > EXPIRY_MARGIN_MS) return accessToken;
  }

  if (!integration.oauth) {
    throw new Error(`${integration.id} has a refresh token but no OAuth descriptor`);
  }
  const oauth = integration.oauth;
  const fresh = await refreshSingleFlight(key, async () => {
    // Re-read under the flight: a refresh may have completed between our cache
    // miss and this point, in which case there is nothing to exchange.
    const raced = readCache(store, key);
    if (raced) return { token: raced, exp: Date.now() + EXPIRY_MARGIN_MS };
    const { live, ...minted } = await refreshAccessToken(integration.id, oauth, cred, store);
    // Persisted by the flight owner only, so a stale result from an earlier
    // attempt can never overwrite a newer token. A credential deleted
    // mid-refresh (revoked) is never cached.
    if (live) store.setSecretSetting(key, minted);
    return minted;
  });
  return fresh.token;
}

/**
 * client_credentials grant (MongoDB Atlas service accounts). Client id and
 * secret ride in an HTTP Basic header, the minted token is cached in the
 * settings table. `fields` replaces the form body for providers with a
 * variant grant (Zoom Server-to-Server: grant_type=account_credentials plus
 * account_id).
 */
export async function clientCredentialsToken(
  integrationId: string,
  tokenUrl: string,
  cred: Credential,
  store: Store,
  fields: Record<string, string> = { grant_type: "client_credentials" },
): Promise<string> {
  const { clientId, clientSecret } = cred.data;
  if (!clientId || !clientSecret) {
    throw new Error(`${integrationId} credential needs clientId and clientSecret`);
  }
  const key = cacheKey(integrationId, cred.id);
  const cached = readCache(store, key);
  if (cached) return cached;

  const url = process.env[envKey(integrationId, "TOKEN")] ?? tokenUrl;
  const res = await postForm(url, new URLSearchParams(fields), {
    accept: "application/json",
    authorization: "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64"),
  });
  const json = parseTokenResponse(
    res,
    `${integrationId} ${fields.grant_type ?? "client_credentials"} grant`,
  );
  const fresh: CachedToken = {
    token: json.access_token!,
    exp: Date.now() + (json.expires_in ?? 3600) * 1000,
  };
  // A credential deleted while the grant was in flight (revoked connection)
  // must not have its token cached.
  if (currentOriginData(store, integrationId, cred)) store.setSecretSetting(key, fresh);
  return fresh.token;
}
