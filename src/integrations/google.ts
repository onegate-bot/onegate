/**
 * Google integration: the whole Workspace family (Gmail, Calendar, Drive,
 * Docs, Sheets, Slides, Forms, Tasks, Meet, Chat, Photos, Classroom, the
 * Admin directory, Analytics, Search Console and YouTube) rides through one
 * OAuth connection. The connect dialog offers per-product scope packs (see
 * google-apps.ts) and one consent covers everything selected. Products that
 * share a host (www.googleapis.com) cannot be told apart by host alone, so
 * use path globs in rules for per-product permissions.
 *
 * Credential data: { clientId, clientSecret, refreshToken, accessToken?,
 * expiresAt?, scopes? }. Legacy credentials carrying only the first three
 * keys keep working. The gateway keeps a short-lived access token cached in
 * the settings table and refreshes it transparently near expiry.
 */

import type { Integration, InjectionContext } from "./types.js";
import type { Store } from "../store/db.js";
import type { Credential } from "../types.js";
import { oauthBearerToken } from "./oauth.js";
import { GOOGLE_APPS } from "./google-apps.js";

export const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/calendar",
  "https://www.googleapis.com/auth/drive",
];

/** Live access token for a Google credential (kept for back compat). */
export function googleAccessToken(cred: Credential, store: Store): Promise<string> {
  return oauthBearerToken(google, cred, store);
}

export const google: Integration = {
  id: "google",
  title: "Google Workspace",
  // Workspace product hosts only. The rest of *.googleapis.com (compute,
  // storage, bigquery, vertex, ...) belongs to the gcp service-account
  // integration, which is registered after this one so these explicit
  // hosts win.
  hosts: [
    "gmail.googleapis.com",
    "www.googleapis.com",
    "drive.googleapis.com",
    "docs.googleapis.com",
    "sheets.googleapis.com",
    "slides.googleapis.com",
    "forms.googleapis.com",
    "tasks.googleapis.com",
    "meet.googleapis.com",
    "chat.googleapis.com",
    "photoslibrary.googleapis.com",
    "classroom.googleapis.com",
    "admin.googleapis.com",
    "analyticsdata.googleapis.com",
    "analyticsadmin.googleapis.com",
    "searchconsole.googleapis.com",
    "youtube.googleapis.com",
    "people.googleapis.com",
  ],
  category: "Google",
  credentialFields: [
    { key: "clientId", label: "OAuth client ID", secret: false },
    { key: "clientSecret", label: "OAuth client secret", secret: true },
    { key: "refreshToken", label: "Refresh token (set by the connect flow)", secret: true },
  ],
  connect: {
    method: "oauth",
    hint: "Use credentials from your own Google OAuth client (Web application type).",
  },
  oauth: {
    authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    defaultScopes: GOOGLE_SCOPES,
    extraAuthParams: { access_type: "offline", prompt: "consent" },
  },
  scopePacks: GOOGLE_APPS,
  connectGuide: {
    consoleUrl: "https://console.cloud.google.com/apis/credentials",
    steps: [
      "Open the Google Cloud Console at https://console.cloud.google.com/projectcreate and pick a project (or create one).",
      "Open the API Library at https://console.cloud.google.com/apis/library and enable the API for each product you want to connect below (for example the Gmail API, the Google Calendar API, the Google Drive API).",
      "Open the OAuth consent screen at https://console.cloud.google.com/apis/credentials/consent Choose External, fill in the app name and your email, and add yourself as a test user while the app is in testing mode.",
      "Open Credentials at https://console.cloud.google.com/apis/credentials Click Create credentials, then OAuth client ID, and choose Web application as the type.",
      "Under Authorized redirect URIs, add the redirect URI shown at the top of this page exactly.",
      "Click Create. Copy the client ID and client secret and paste them into the fields below.",
    ],
  },
  llmHelp: {
    credentialType:
      "A Google OAuth 2.0 client of type Web application, plus a refresh token. OneGate uses the refresh token to mint short-lived access tokens and injects them as Bearer tokens.",
    whereToCreate:
      "Google Cloud Console (https://console.cloud.google.com), under APIs and Services, then Credentials. On the same project, enable the APIs for the products you select in the connect dialog (e.g. the Gmail API, the Google Calendar API, the Google Drive API), and configure the OAuth consent screen (add yourself as a test user if the app is in testing mode).",
    scopes: GOOGLE_SCOPES,
    notes: [
      "OneGate has a built-in connect flow (Option A in the connect dialog) that obtains the refresh token for me:",
      "1. I register the redirect URI shown in the dialog (it is my OneGate URL followed by /oauth/google/callback) on the OAuth client in Google Cloud Console.",
      '2. I paste the "OAuth client ID" and "OAuth client secret" into the dialog, tick the Google products I want (Gmail, Calendar, Drive, Sheets, ...), and press the button to open the Google consent screen.',
      "3. After I approve, OneGate exchanges the authorization code and stores the refresh token automatically, so I never handle the refresh token myself.",
      'There is also a manual option (Option B) where I paste "OAuth client ID", "OAuth client secret" and "Refresh token" directly.',
      "One Google connection covers every selected product in a single consent. If Google does not return a refresh token, I must remove the app's earlier grant at https://myaccount.google.com/permissions and run the connect flow again.",
    ].join("\n"),
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const token = await googleAccessToken(ctx.credential, ctx.store);
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
