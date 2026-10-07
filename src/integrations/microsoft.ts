/**
 * Microsoft 365 via Microsoft Graph: Outlook mail and calendar, OneDrive and
 * OneNote ride through one OAuth connection, the way the google integration
 * bundles Gmail, Calendar and Drive. Bring-your-own Microsoft Entra app
 * registration, the multi-tenant `common` endpoints (work, school and
 * personal Microsoft accounts) and offline_access for a refresh token.
 * Microsoft rotates refresh tokens, the shared engine persists the
 * replacement. Every product shares graph.microsoft.com, so per-product
 * permissions are path globs (/v1.0/me/messages/**, /v1.0/me/drive/**).
 */

import type { Integration, InjectionContext, ScopePack } from "./types.js";
import { oauthBearerToken } from "./oauth.js";

/** Sent with every pack: a refresh token and the signed-in user's profile. */
const BASE_SCOPES = ["offline_access", "User.Read"];

export const MICROSOFT_APPS: ScopePack[] = [
  {
    id: "mail",
    label: "Outlook mail",
    description: "Read, organize and send email",
    default: true,
    scopes: [...BASE_SCOPES, "Mail.ReadWrite", "Mail.Send"],
    permissions: [
      { scope: "Mail.ReadWrite", name: "Mailbox", description: "Read, draft, move and delete messages", access: "write" },
      { scope: "Mail.Send", name: "Send mail", description: "Send email as you", access: "write" },
    ],
  },
  {
    id: "calendar",
    label: "Outlook calendar",
    description: "Read and manage calendars and events",
    default: true,
    scopes: [...BASE_SCOPES, "Calendars.ReadWrite"],
    permissions: [
      { scope: "Calendars.ReadWrite", name: "Calendars", description: "View and edit events on your calendars", access: "write" },
    ],
  },
  {
    id: "onedrive",
    label: "OneDrive",
    description: "Read and manage your files",
    default: true,
    scopes: [...BASE_SCOPES, "Files.ReadWrite"],
    permissions: [
      { scope: "Files.ReadWrite", name: "Files", description: "View, create and edit files in your OneDrive", access: "write" },
    ],
  },
  {
    id: "onenote",
    label: "OneNote",
    description: "Read and edit notebooks, sections and pages",
    scopes: [...BASE_SCOPES, "Notes.ReadWrite"],
    permissions: [
      { scope: "Notes.ReadWrite", name: "Notebooks", description: "View and edit your OneNote notebooks", access: "write" },
    ],
  },
];

/** Union of the default packs, deduplicated. */
const DEFAULT_SCOPES = [...new Set(MICROSOFT_APPS.filter((p) => p.default).flatMap((p) => p.scopes))];

export const microsoft: Integration = {
  id: "microsoft",
  title: "Microsoft 365",
  hosts: ["graph.microsoft.com"],
  category: "Productivity",
  credentialFields: [
    { key: "clientId", label: "Application (client) ID", secret: false },
    { key: "clientSecret", label: "Client secret value", secret: true },
    { key: "accessToken", label: "Access token (set by the connect flow)", secret: true, optional: true },
    { key: "refreshToken", label: "Refresh token (set by the connect flow)", secret: true },
  ],
  connect: {
    method: "oauth",
    hint: "Use a multi-tenant Microsoft Entra app registration (Web platform, \"Accounts in any organizational directory and personal Microsoft accounts\") with a client secret. Single-tenant apps are not supported yet.",
  },
  oauth: {
    authUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    defaultScopes: DEFAULT_SCOPES,
  },
  scopePacks: MICROSOFT_APPS,
  connectGuide: {
    consoleUrl: "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
    steps: [
      "Open App registrations in the Microsoft Entra admin center at https://entra.microsoft.com (Identity, Applications, App registrations) and click New registration.",
      "Under Supported account types choose \"Accounts in any organizational directory and personal Microsoft accounts\". OneGate signs in through the common endpoint, so a single-tenant app (your own directory only) fails at consent with AADSTS50194.",
      "Under Redirect URI pick the Web platform and paste the redirect URI shown at the top of this page exactly. Click Register.",
      "Copy the Application (client) ID from the Overview page.",
      "Open Certificates and secrets, click New client secret and copy the secret Value (not the Secret ID).",
      "Optionally add the Microsoft Graph delegated permissions you plan to use under API permissions. Consent happens on the next screen either way.",
    ],
  },
  llmHelp: {
    credentialType:
      "A Microsoft Entra (Azure AD) app registration's Application (client) ID and a client secret value. OneGate runs the OAuth consent against the common endpoint, stores the refresh token (Microsoft rotates it, OneGate keeps the newest) and injects short-lived access tokens as Bearer on graph.microsoft.com.",
    whereToCreate:
      "Microsoft Entra admin center (https://entra.microsoft.com), Identity, Applications, App registrations, New registration. Supported account types must be 'Accounts in any organizational directory and personal Microsoft accounts' (OneGate uses the common endpoint, single-tenant apps fail with AADSTS50194). Redirect URI: Web platform, the URI shown in the OneGate connect dialog. Then Certificates and secrets, New client secret.",
    scopes: [
      "Delegated Microsoft Graph permissions per product: Mail.ReadWrite and Mail.Send (Outlook mail), Calendars.ReadWrite (Outlook calendar), Files.ReadWrite (OneDrive), Notes.ReadWrite (OneNote). offline_access and User.Read are always requested.",
      "Work or school tenants may require an administrator to consent to these permissions before a user can.",
    ],
    notes:
      "Endpoints: /v1.0/me/messages and /v1.0/me/sendMail (mail), /v1.0/me/events and /v1.0/me/calendarView (calendar), /v1.0/me/drive (OneDrive), /v1.0/me/onenote (OneNote). Paste the secret Value, not the Secret ID. Client secrets expire (24 months at most), reconnect with a new one when it does.",
  },
  async inject(ctx: InjectionContext): Promise<void> {
    const token = await oauthBearerToken(microsoft, ctx.credential, ctx.store);
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
