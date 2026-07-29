/**
 * GitHub App installation tokens: fine-grained, org-approved access as an
 * app instead of a user PAT. The credential stores the App ID, the app's
 * RSA private key (PEM) and the installation ID. At request time inject
 * signs a short RS256 app JWT, exchanges it for an installation access
 * token (POST /app/installations/<id>/access_tokens), caches the token
 * until its expiry and injects Bearer on the API hosts or Basic
 * x-access-token for git smart HTTP. Shares all hosts with the github PAT
 * integration, the proxy uses whichever has a connected credential
 * (github first).
 */

import { createSign } from "node:crypto";
import type { Integration, InjectionContext } from "./types.js";
import type { Credential } from "../types.js";
import type { Store } from "../store/db.js";
import { postJson } from "../util/http.js";

/** Refresh the installation token when within a minute of expiry. */
const EXPIRY_MARGIN_MS = 60_000;

function apiBase(): string {
  return process.env.ONEGATE_GITHUB_APP_API_BASE ?? "https://api.github.com";
}

/**
 * Repairs common paste damage in PEM keys: literal \n sequences and
 * single-line bodies (GitHub's downloaded .pem is fine as is).
 */
export function normalizePem(key: string): string {
  let normalized = key.replace(/\\n/g, "\n").trim();
  if (!normalized.startsWith("-----BEGIN") || !normalized.includes("-----END")) {
    throw new Error("Invalid PEM format: missing BEGIN/END markers");
  }
  if (!normalized.includes("\n")) {
    normalized = normalized
      .replace(/(-----BEGIN [A-Z ]+-----)/g, "$1\n")
      .replace(/(-----END [A-Z ]+-----)/g, "\n$1");
    const match = normalized.match(/^(-----BEGIN [A-Z ]+-----)\n([\s\S]+)\n(-----END [A-Z ]+-----)$/);
    if (match) {
      const body = match[2].replace(/\s+/g, "");
      const lines = body.match(/.{1,64}/g) ?? [body];
      normalized = `${match[1]}\n${lines.join("\n")}\n${match[3]}`;
    }
  }
  return normalized;
}

/** Short-lived RS256 app JWT (iss = App ID, 10 minute lifetime). */
export function signGithubAppJwt(appId: string, privateKey: string, now = new Date()): string {
  const iat = Math.floor(now.getTime() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const claims = Buffer.from(
    JSON.stringify({ iss: appId, iat: iat - 60, exp: iat + 600 }),
  ).toString("base64url");
  const unsigned = `${header}.${claims}`;
  const sign = createSign("RSA-SHA256");
  sign.update(unsigned);
  return `${unsigned}.${sign.sign(normalizePem(privateKey), "base64url")}`;
}

export async function githubAppToken(cred: Credential, store: Store): Promise<string> {
  const { appId, privateKey, installationId } = cred.data;
  if (!appId || !privateKey || !installationId) {
    throw new Error('GitHub App credential needs "appId", "privateKey" and "installationId"');
  }

  const cacheKey = `github_app_token:${cred.id}`;
  // Sealed at rest; an unreadable row degrades to a cache miss and re-mints.
  const cached = store.getSecretSetting<{ token: string; exp: number }>(cacheKey);
  if (cached && cached.exp - Date.now() > EXPIRY_MARGIN_MS) return cached.token;

  const jwt = signGithubAppJwt(appId, privateKey);
  const res = await postJson(
    `${apiBase()}/app/installations/${encodeURIComponent(installationId)}/access_tokens`,
    {},
    {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${jwt}`,
      "user-agent": "onegate",
      "x-github-api-version": "2022-11-28",
    },
  );
  if (res.status !== 201) {
    let message = "";
    try {
      message = (JSON.parse(res.body) as { message?: string }).message ?? "";
    } catch {
      // Non-JSON error body.
    }
    throw new Error(
      `GitHub App installation token exchange failed (${res.status})${message ? `: ${message}` : ""}`,
    );
  }
  const json = JSON.parse(res.body) as { token?: string; expires_at?: string };
  if (!json.token) throw new Error("GitHub did not return an installation token");
  const exp = json.expires_at ? new Date(json.expires_at).getTime() : Date.now() + 3_600_000;
  store.setSecretSetting(cacheKey, { token: json.token, exp });
  return json.token;
}

export const githubApp: Integration = {
  id: "github-app",
  title: "GitHub App",
  hosts: ["api.github.com", "uploads.github.com", "github.com", "codeload.github.com"],
  category: "Developer",
  credentialFields: [
    { key: "appId", label: "App ID", secret: false },
    { key: "installationId", label: "Installation ID", secret: false },
    { key: "privateKey", label: "Private key (PEM)", secret: true, multiline: true },
  ],
  connect: {
    method: "credentials_import",
    hint: "App ID and private key from the GitHub App settings page, installation ID from the installation's URL.",
    fileImport: {
      label: "Import private key (.pem)",
      accept: ".pem,application/x-pem-file",
      rawField: "privateKey",
    },
  },
  llmHelp: {
    credentialType:
      "A GitHub App: numeric App ID, the app's RSA private key (.pem download), and the numeric installation ID. OneGate signs app JWTs and mints short-lived installation access tokens automatically (Bearer on the API, Basic x-access-token for git over HTTPS).",
    whereToCreate:
      "GitHub, Settings, Developer settings, GitHub Apps (or org Settings for an org-owned app). Create the app with the repository permissions the agent needs, generate a private key (downloads a .pem), then install the app on the target repos. The installation ID is the number at the end of the installation's URL (Settings, Installations, Configure).",
    scopes: [
      "Permissions are set on the app and confirmed per installation, e.g. Contents read/write plus Pull requests read/write for a coding agent. The installation can be limited to selected repositories.",
    ],
    notes:
      "Installation tokens expire after an hour, OneGate re-mints them transparently. Tokens act as the app, not a user (commits show the app's bot identity). The plain github integration with a PAT covers the same hosts when user identity matters.",
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const token = await githubAppToken(ctx.credential, ctx.store);
    if (ctx.host === "github.com" || ctx.host === "codeload.github.com") {
      ctx.headers.authorization =
        "Basic " + Buffer.from(`x-access-token:${token}`).toString("base64");
    } else {
      ctx.headers.authorization = `Bearer ${token}`;
      ctx.headers["user-agent"] ??= "onegate";
    }
  },
};
