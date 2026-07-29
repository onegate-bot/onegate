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

interface CachedToken {
  token: string;
  /** Epoch ms expiry. */
  exp: number;
}

function cacheKey(integrationId: string, credId: string): string {
  return `oauth_access_token:${integrationId}:${credId}`;
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
): Promise<CachedToken> {
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
  // the replacement or the next refresh would fail. A connection-backed
  // credential (its id resolves to a connection row) is persisted on the
  // connection; a legacy single credential keeps the credentials table.
  if (json.refresh_token && json.refresh_token !== refreshToken) {
    const nextData = { ...cred.data, refreshToken: json.refresh_token };
    if (store.getConnection(cred.id)) {
      store.updateConnection(cred.id, { data: nextData });
    } else {
      store.setCredential(integrationId, cred.name, nextData);
    }
  }
  return {
    token: json.access_token!,
    exp: Date.now() + (json.expires_in ?? 3600) * 1000,
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
  const fresh = await refreshAccessToken(integration.id, integration.oauth, cred, store);
  store.setSecretSetting(key, fresh);
  return fresh.token;
}

/**
 * client_credentials grant (MongoDB Atlas service accounts). Client id and
 * secret ride in an HTTP Basic header, the minted token is cached in the
 * settings table.
 */
export async function clientCredentialsToken(
  integrationId: string,
  tokenUrl: string,
  cred: Credential,
  store: Store,
): Promise<string> {
  const { clientId, clientSecret } = cred.data;
  if (!clientId || !clientSecret) {
    throw new Error(`${integrationId} credential needs clientId and clientSecret`);
  }
  const key = cacheKey(integrationId, cred.id);
  const cached = readCache(store, key);
  if (cached) return cached;

  const url = process.env[envKey(integrationId, "TOKEN")] ?? tokenUrl;
  const res = await postForm(url, new URLSearchParams({ grant_type: "client_credentials" }), {
    accept: "application/json",
    authorization: "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64"),
  });
  const json = parseTokenResponse(res, `${integrationId} client_credentials grant`);
  const fresh: CachedToken = {
    token: json.access_token!,
    exp: Date.now() + (json.expires_in ?? 3600) * 1000,
  };
  store.setSecretSetting(key, fresh);
  return fresh.token;
}
