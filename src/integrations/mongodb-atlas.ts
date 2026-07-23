/**
 * MongoDB Atlas Administration API via a service account. The stored client
 * ID and secret are exchanged lazily for short-lived access tokens with the
 * client_credentials grant (HTTP Basic, cached in the settings table by the
 * shared engine), injected as Bearer on cloud.mongodb.com. Nothing is
 * exchanged at connect time, a bad credential fails at first use.
 */

import type { Integration, InjectionContext } from "./types.js";
import { clientCredentialsToken } from "./oauth.js";

export const ATLAS_TOKEN_URL = "https://cloud.mongodb.com/api/oauth/token";

export const mongodbAtlas: Integration = {
  id: "mongodb-atlas",
  title: "MongoDB Atlas",
  hosts: ["cloud.mongodb.com"],
  category: "Developer",
  credentialFields: [
    { key: "clientId", label: "Client ID", secret: false },
    { key: "clientSecret", label: "Client secret", secret: true },
  ],
  connect: {
    method: "api_key",
    hint: "Paste the client ID and secret of an Atlas service account. Tokens are minted automatically at request time.",
  },
  llmHelp: {
    credentialType:
      'An Atlas service account: client ID (starts with "mdb_sa_id_") and client secret (starts with "mdb_sa_sk_"). OneGate exchanges them for short-lived access tokens with the client_credentials grant and injects Bearer.',
    whereToCreate:
      "Atlas UI: Organization Settings (or Project Settings), then Service Accounts, then Create Service Account. The secret is shown once at creation.",
    scopes: [
      "Pick the narrowest role for the service account (e.g. Project Read Only for monitoring agents) and limit it to the projects the agent needs.",
    ],
    notes:
      'The Administration API lives under /api/atlas/v2/ and needs the versioned Accept header, e.g. "application/vnd.atlas.2023-01-01+json". Database connections (mongodb+srv) do not go through OneGate.',
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const token = await clientCredentialsToken(
      "mongodb-atlas",
      ATLAS_TOKEN_URL,
      ctx.credential,
      ctx.store,
    );
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
