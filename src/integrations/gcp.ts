/**
 * Google Cloud Platform integration: a service account key JSON is exchanged
 * for short-lived OAuth2 access tokens via the JWT-bearer grant (the gateway
 * signs an RS256 assertion with the key's private key and posts it to the
 * Google token endpoint). Tokens are cached in the settings table and
 * refreshed when within a minute of expiry, mirroring the Google
 * (Gmail / Calendar / Drive) integration.
 *
 * Host split versus the "google" integration: google owns the Workspace
 * hosts (gmail.googleapis.com, www.googleapis.com) as exact claims, gcp
 * claims the rest of *.googleapis.com (compute, storage, bigquery, pubsub,
 * run, ...) as a dot-suffix. The registry resolves by specificity, so an
 * exact Workspace host always beats this suffix and keeps hitting the
 * OAuth-user integration, whatever order the two are registered in.
 */

import { createHash, createSign } from "node:crypto";
import type { Integration, InjectionContext } from "./types.js";
import type { Store } from "../store/db.js";
import type { Credential } from "../types.js";
import { postForm } from "../util/http.js";

export const GCP_DEFAULT_SCOPE = "https://www.googleapis.com/auth/cloud-platform";

/** The real-world audience. Kept constant even when the URL is overridden for tests. */
const TOKEN_AUDIENCE = "https://oauth2.googleapis.com/token";

function tokenUrl(): string {
  // Overridable for tests.
  return process.env.ONEGATE_GCP_TOKEN_URL ?? TOKEN_AUDIENCE;
}

export interface ServiceAccountKey {
  client_email: string;
  private_key: string;
}

export function parseServiceAccountKey(cred: Credential): ServiceAccountKey {
  const raw = cred.data.serviceAccountJson;
  if (!raw) {
    throw new Error('GCP credential needs the "serviceAccountJson" field');
  }
  let json: Partial<ServiceAccountKey>;
  try {
    json = JSON.parse(raw) as Partial<ServiceAccountKey>;
  } catch {
    throw new Error("GCP serviceAccountJson is not valid JSON (paste the whole key file)");
  }
  if (!json.client_email || !json.private_key) {
    throw new Error("GCP service account JSON must contain client_email and private_key");
  }
  return json as ServiceAccountKey;
}

function b64url(s: string): string {
  return Buffer.from(s).toString("base64url");
}

/** RS256-signed JWT assertion for the urn:ietf:params:oauth:grant-type:jwt-bearer grant. */
export function buildJwtAssertion(key: ServiceAccountKey, scope: string, now = new Date()): string {
  const iat = Math.floor(now.getTime() / 1000);
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = b64url(
    JSON.stringify({
      iss: key.client_email,
      scope,
      aud: TOKEN_AUDIENCE,
      iat,
      exp: iat + 3600,
    }),
  );
  const signer = createSign("RSA-SHA256");
  signer.update(`${header}.${claims}`);
  const signature = signer.sign(key.private_key).toString("base64url");
  return `${header}.${claims}.${signature}`;
}

function scopesFor(cred: Credential): string {
  const override = (cred.data.scopes ?? "").trim();
  return override || GCP_DEFAULT_SCOPE;
}

interface CachedToken {
  token: string;
  /** Epoch ms expiry. */
  exp: number;
}

async function exchangeAssertion(cred: Credential): Promise<CachedToken> {
  const key = parseServiceAccountKey(cred);
  const assertion = buildJwtAssertion(key, scopesFor(cred));
  const res = await postForm(
    tokenUrl(),
    new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }),
  );
  if (res.status !== 200) {
    throw new Error(`GCP token exchange failed (${res.status}): ${res.body.slice(0, 300)}`);
  }
  const json = JSON.parse(res.body) as { access_token: string; expires_in: number };
  return { token: json.access_token, exp: Date.now() + json.expires_in * 1000 };
}

export async function gcpAccessToken(cred: Credential, store: Store): Promise<string> {
  // Scope is part of the key so an admin editing the scopes override never
  // gets served a token minted for the old scopes.
  const scopeTag = createHash("sha256").update(scopesFor(cred)).digest("hex").slice(0, 12);
  const cacheKey = `gcp_access_token:${cred.id}:${scopeTag}`;
  // Sealed at rest; an unreadable row degrades to a cache miss and re-mints.
  const cached = store.getSecretSetting<CachedToken>(cacheKey);
  if (cached && cached.exp - Date.now() > 60_000) return cached.token;
  const fresh = await exchangeAssertion(cred);
  store.setSecretSetting(cacheKey, fresh);
  return fresh.token;
}

export const gcp: Integration = {
  id: "gcp",
  title: "Google Cloud Platform (service account)",
  hosts: [".googleapis.com"],
  category: "Google",
  credentialFields: [
    {
      key: "serviceAccountJson",
      label: "Service account key JSON (paste the whole file)",
      secret: true,
      multiline: true,
    },
    {
      key: "scopes",
      label: "OAuth scopes override (space separated)",
      secret: false,
      optional: true,
    },
  ],
  connect: {
    method: "credentials_import",
    hint: "Paste the service account key JSON, or import the downloaded .json file.",
    fileImport: {
      label: "Import service account key (.json)",
      accept: ".json,application/json",
      rawField: "serviceAccountJson",
    },
  },
  llmHelp: {
    credentialType:
      "A Google Cloud service account key (JSON file). OneGate signs a JWT assertion with the key's private key, exchanges it for short-lived OAuth2 access tokens at the Google token endpoint, and injects them as Bearer tokens on every *.googleapis.com Cloud API call.",
    whereToCreate:
      "Google Cloud Console (https://console.cloud.google.com), IAM and Admin, then Service Accounts. Create a service account (or pick an existing one), grant it the IAM roles the agent needs (for example roles/storage.objectViewer for reading GCS, roles/bigquery.user for queries, prefer narrow roles over Editor or Owner), then open the Keys tab and create a new key of type JSON. The browser downloads the key file once.",
    scopes: [
      "Default OAuth scope: https://www.googleapis.com/auth/cloud-platform (covers all Cloud APIs, actual access is bounded by the service account's IAM roles).",
      "The scopes field can be overridden with a space separated list to narrow the token itself, e.g. https://www.googleapis.com/auth/devstorage.read_only.",
    ],
    notes: [
      'Paste the entire downloaded JSON key file into the "Service account key JSON" field, exactly as downloaded (it contains client_email and private_key).',
      "Leave the scopes override empty unless a narrower token scope is wanted.",
      "This integration is for Cloud APIs (compute, storage, bigquery, pubsub and the rest of *.googleapis.com). Gmail, Calendar and Drive run through the separate Google (Gmail / Calendar / Drive) integration with a user OAuth consent.",
      "Remember to enable each API (for example the Cloud Storage API) on the project in APIs and Services before calling it.",
    ].join("\n"),
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const token = await gcpAccessToken(ctx.credential, ctx.store);
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
