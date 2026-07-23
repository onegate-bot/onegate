/**
 * Docker Hub via username + personal access token. Hub's v2 API wants a
 * JWT from POST /v2/users/login, so inject logs in lazily with the stored
 * PAT, caches the JWT until its exp claim (settings table) and injects it
 * as Bearer. Nothing happens at connect time, a bad credential fails at
 * first use.
 */

import type { Integration, InjectionContext } from "./types.js";
import type { Credential } from "../types.js";
import type { Store } from "../store/db.js";
import { postJson } from "../util/http.js";

const LOGIN_URL = "https://hub.docker.com/v2/users/login";
/** Refresh the JWT when it is within a minute of expiry. */
const EXPIRY_MARGIN_MS = 60_000;

function loginUrl(): string {
  return process.env.ONEGATE_DOCKER_LOGIN_URL ?? LOGIN_URL;
}

/** exp claim of a JWT in epoch ms, or null when unparsable. */
export function jwtExpiryMs(token: string): number | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString()) as { exp?: unknown };
    return typeof decoded.exp === "number" ? decoded.exp * 1000 : null;
  } catch {
    return null;
  }
}

export async function dockerHubToken(cred: Credential, store: Store): Promise<string> {
  const { username, apiToken } = cred.data;
  if (!username || !apiToken) {
    throw new Error('Docker Hub credential needs "username" and "apiToken"');
  }

  const cacheKey = `docker_hub_jwt:${cred.id}`;
  const cachedRaw = store.getSetting(cacheKey);
  if (cachedRaw) {
    const cached = JSON.parse(cachedRaw) as { token: string; exp: number };
    if (cached.exp - Date.now() > EXPIRY_MARGIN_MS) return cached.token;
  }

  const res = await postJson(loginUrl(), { username, password: apiToken }, { accept: "application/json" });
  if (res.status !== 200) {
    let detail = "";
    try {
      detail = (JSON.parse(res.body) as { detail?: string }).detail ?? "";
    } catch {
      // Non-JSON error body.
    }
    throw new Error(`Docker Hub login failed (${res.status})${detail ? `: ${detail}` : ""}`);
  }
  const { token } = JSON.parse(res.body) as { token?: string };
  if (!token) throw new Error("Docker Hub login did not return a token");

  const exp = jwtExpiryMs(token) ?? Date.now() + 3_600_000;
  store.setSetting(cacheKey, JSON.stringify({ token, exp }));
  return token;
}

export const docker: Integration = {
  id: "docker",
  title: "Docker Hub",
  hosts: ["hub.docker.com"],
  category: "Developer",
  credentialFields: [
    { key: "username", label: "Username", secret: false },
    { key: "apiToken", label: "Personal access token", secret: true },
  ],
  connect: {
    method: "api_key",
    hint: "Docker Hub username plus a personal access token. OneGate logs in for a JWT automatically.",
  },
  llmHelp: {
    credentialType:
      'A Docker Hub username and personal access token (starts with "dckr_pat_"). OneGate exchanges them for a Hub JWT at request time and injects it as Bearer.',
    whereToCreate:
      "https://app.docker.com, Account Settings, then Personal access tokens, then Generate new token.",
    scopes: ["Choose Read-only access unless the agent manages repositories or tags."],
    notes:
      "This covers the Hub management API (hub.docker.com/v2/...): repositories, tags, organizations. Pulling and pushing images goes to registry-1.docker.io, which is not covered.",
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const token = await dockerHubToken(ctx.credential, ctx.store);
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
