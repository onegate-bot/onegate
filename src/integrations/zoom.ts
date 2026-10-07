/**
 * Zoom via a Server-to-Server OAuth app. The stored account ID, client ID and
 * client secret are exchanged lazily for one-hour access tokens with Zoom's
 * account_credentials grant (HTTP Basic client auth, cached by the shared
 * engine) and injected as Bearer on api.zoom.us. Nothing is exchanged at
 * connect time, a bad credential fails at first use. User-level OAuth (a
 * General app acting as one user) is a follow-up.
 */

import type { Credential } from "../types.js";
import type { Integration, InjectionContext } from "./types.js";
import { clientCredentialsToken } from "./oauth.js";

export const ZOOM_TOKEN_URL = "https://zoom.us/oauth/token";

export const zoom: Integration = {
  id: "zoom",
  title: "Zoom",
  hosts: ["api.zoom.us"],
  category: "Communication",
  credentialFields: [
    { key: "accountId", label: "Account ID", secret: false },
    { key: "clientId", label: "Client ID", secret: false },
    { key: "clientSecret", label: "Client secret", secret: true },
  ],
  connect: {
    method: "api_key",
    hint: "Paste the Account ID, Client ID and Client secret of a Zoom Server-to-Server OAuth app. Tokens are minted automatically at request time.",
  },
  llmHelp: {
    credentialType:
      "A Zoom Server-to-Server OAuth app: Account ID, Client ID and Client secret. OneGate exchanges them for one-hour access tokens (grant_type=account_credentials) and injects Bearer.",
    whereToCreate:
      "Zoom App Marketplace (https://marketplace.zoom.us), Develop, then Build App, then Server-to-Server OAuth App. The App Credentials page shows all three values. Activate the app after adding scopes.",
    scopes: [
      "Add granular scopes on the app's Scopes page, e.g. meeting:read:list_meetings:admin and meeting:read:meeting:admin for reading, meeting:write:meeting:admin to schedule, cloud_recording:read:list_user_recordings:admin for recordings. Server-to-Server apps act account-wide, keep the list short.",
    ],
    notes:
      "The REST API lives under https://api.zoom.us/v2/. Server-to-Server apps have no user of their own, use /v2/users/<email or id>/meetings rather than /users/me.",
  },
  accountSummary(cred: Credential): Record<string, string | null> {
    return { accountId: cred.data.accountId ? String(cred.data.accountId) : null };
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const accountId = ctx.credential.data.accountId;
    if (!accountId) throw new Error('Zoom credential has no "accountId" field');
    const token = await clientCredentialsToken("zoom", ZOOM_TOKEN_URL, ctx.credential, ctx.store, {
      grant_type: "account_credentials",
      account_id: accountId,
    });
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
