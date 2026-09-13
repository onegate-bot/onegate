/**
 * YouTube Data API v3 integration.
 *
 * Demonstrates and exercises PATH-SCOPED HOST CLAIMS. The YouTube Data API is
 * served on `www.googleapis.com` under `/youtube/v3`, a host the Google
 * Workspace OAuth integration owns outright. The two need DIFFERENT auth modes
 * on that one hostname: Workspace APIs take an OAuth user token, while public
 * YouTube reads (search, videos, channels, playlists) take a plain API key.
 * Before path scoping, an agent asking for the YouTube Data API on that host got
 * the Workspace integration's OAuth credential, or nothing.
 *
 * So this integration claims only `{ host: "www.googleapis.com", path:
 * "/youtube/v3" }` plus the whole of the dedicated `youtube.googleapis.com`
 * alias host. The Workspace integration keeps every other path on
 * www.googleapis.com. See Registry.resolveHostPathCandidates.
 *
 * Auth mode: the API key rides in the `key` QUERY PARAMETER, not a header, so
 * inject rewrites ctx.path. Policy and audit always record the ORIGINAL path the
 * agent sent (see the InjectionContext.path contract), so the key is never
 * audited or matched against.
 */

import type { Integration, InjectionContext } from "./types.js";

/** Path prefix of the YouTube Data API v3 on the shared googleapis host. */
export const YOUTUBE_DATA_API_PATH = "/youtube/v3";

export const youtube: Integration = {
  id: "youtube",
  title: "YouTube Data API",
  hosts: [
    // Path-scoped: only the YouTube Data API subtree of the shared Workspace
    // host. Everything else on www.googleapis.com stays with "google".
    { host: "www.googleapis.com", path: YOUTUBE_DATA_API_PATH },
    // The dedicated alias host serves only YouTube, so claim it whole. Note the
    // "google" integration also lists it: google is registered first, so the
    // connected-credential tie-break decides there, exactly as it did before.
    "youtube.googleapis.com",
  ],
  category: "Google",
  credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
  connect: {
    method: "api_key",
    hint: "A Google API key with the YouTube Data API v3 enabled. Public read endpoints only.",
  },
  connectGuide: {
    consoleUrl: "https://console.cloud.google.com/apis/credentials",
    steps: [
      "Open the Google Cloud Console at https://console.cloud.google.com/projectcreate and pick a project (or create one).",
      "Open the API Library at https://console.cloud.google.com/apis/library/youtube.googleapis.com and enable the YouTube Data API v3 for that project.",
      "Open Credentials at https://console.cloud.google.com/apis/credentials Click Create credentials, then API key.",
      "Optional but recommended: click Edit API key and under API restrictions restrict it to the YouTube Data API v3.",
      "Copy the API key and paste it into the field below.",
    ],
  },
  llmHelp: {
    credentialType:
      "A Google API key (starts with AIza) with the YouTube Data API v3 enabled. OneGate appends it as the key query parameter.",
    whereToCreate:
      "Google Cloud Console (https://console.cloud.google.com), under APIs and Services, then Credentials, then Create credentials, then API key. Enable the YouTube Data API v3 on the same project.",
    scopes: [
      "API keys are not scoped. They authorize PUBLIC read endpoints only (search, videos, channels, playlists).",
    ],
    notes: [
      "Base URL: https://www.googleapis.com/youtube/v3 (https://youtube.googleapis.com/youtube/v3 also works).",
      "Send the request WITHOUT a key parameter, or with any placeholder value. OneGate replaces it with the real key.",
      "An API key cannot read or write private data (a user's own playlists, uploads, subscriptions). Those need OAuth, which is the Google Workspace integration, not this one.",
    ].join("\n"),
  },
  inject(ctx: InjectionContext): void {
    const apiKey = ctx.credential.data.apiKey;
    if (!apiKey) throw new Error('YouTube credential has no "apiKey" field');
    // The key travels as a query parameter. Replace any placeholder the agent
    // sent rather than appending a second `key`, which YouTube rejects.
    const [rawPath, rawQuery = ""] = ctx.path.split("?");
    const params = new URLSearchParams(rawQuery);
    params.set("key", apiKey);
    ctx.path = `${rawPath}?${params.toString()}`;
  },
};
