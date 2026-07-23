# Writing an integration

An integration teaches OneGate three things: which hosts it owns, what credentials to ask the admin for, and how to rewrite a request so it carries the real credential.

## The shape

A single file that default-exports an `Integration` (see `src/integrations/types.ts`):

```js
// slack.js
export default {
  id: "slack",
  title: "Slack",
  hosts: ["slack.com", ".slack.com"],
  credentialFields: [{ key: "token", label: "Bot token", secret: true }],
  inject(ctx) {
    ctx.headers.authorization = `Bearer ${ctx.credential.data.token}`;
  },
};
```

That is a complete, working integration.

## The contract

- **`id`** — unique, lowercase. Used in rules, credentials, the audit log, and the UI.
- **`title`** — human-readable name shown in the UI.
- **`hosts`** — hostnames the gateway terminates for this integration. Plain entries match exactly. A leading dot matches all subdomains (`".slack.com"` matches `api.slack.com` and `files.slack.com`). A host may be claimed by more than one integration (built-in examples: `jira` and `confluence` share `api.atlassian.com`, `github` and `github-app` share the GitHub hosts). The gateway walks claimants in registration order and injects with the first one that has a connected credential, so connecting exactly one of the overlapping integrations selects it. The registry only throws on a duplicate `id`.
- **`credentialFields`** — `{ key, label, secret }` descriptors. The admin UI renders a connect form from these (secret fields become password inputs). The values are stored as the credential's `data` object.
- **`credentialFields`** entries may also set `optional: true` (the UI does not require the field) and `multiline: true` (the UI renders a textarea, for pasted key files like GCP service account JSON).
- **`inject(ctx)`** — called for every allowed request. Mutate `ctx.headers` to carry the real credential. The agent's own `authorization` header has already been stripped. May be `async`. Throwing makes the gateway return `502 onegate_inject_failed` without contacting the vendor.
- **`needsBody`** *(optional)* — set `true` if `inject` must see the request body (payload-signing schemes like AWS SigV4). The gateway then buffers the body (bounded by `ONEGATE_MAX_BUFFERED_BODY`, default 32 MiB, oversize requests get `413 onegate_body_too_large`) and exposes it as `ctx.body` before forwarding with an exact `content-length`. Integrations without this flag keep the pure streaming path.
- **`llmHelp`** *(optional)* — hints for the "Get help from your LLM" prompt on the connect dialog. The admin UI shows a copyable plain-text prompt that users paste into ChatGPT, Claude or any LLM to get step-by-step credential setup guidance. Every integration gets a generic prompt automatically (composed from `title`, `hosts` and `credentialFields`), and `llmHelp` merges in specifics:
  - `credentialType` — what kind of credential this is and how OneGate uses it.
  - `whereToCreate` — where the user creates it (a settings URL with navigation hints).
  - `scopes` — scopes or permissions OneGate needs for the API paths it proxies (array of strings, free-form).
  - `notes` — extra guidance, e.g. which OneGate form field gets which value. May span multiple lines.

  Keep the prose plain text (it must read well outside markdown). See `src/integrations/github.ts` and `src/integrations/google.ts` for well-crafted examples, and `src/integrations/llm-help.ts` for how the final prompt is composed.

`ctx` gives you: `headers`, `method`, `path`, `host`, `credential` (the stored credential row, with `data`), `store` (for caching, see below), and `body` (a Buffer, only when `needsBody` is set).

## Multiple accounts per integration (connections)

An integration can hold more than one account. Beyond the single legacy credential (set with `onegate credentials set`), operators can create named **app connections**, each carrying a different account's `data`. A connection is either **tenant-wide** (the operator's intended shared default) or **agent-bound** (owned by one agent). Each scope tracks its own default connection.

A named app connection is **default-deny**: it is usable by an agent only when it is explicitly **granted** to that agent, or to a **project** the agent belongs to (a project grant applies to every agent whose `project_id` matches). Grants are visible and revocable from both sides (per connection: which agents/projects; per agent: which connections) and are managed with `onegate connections grant|revoke|grants` or on the Connections page in the UI. Granting never exposes the secret.

Your `inject(ctx)` does not change. `ctx.credential` is always the one connection (or legacy credential) OneGate selected for this request, with its `data`. Integration code never sees the others and never chooses between them. The selection happens in the proxy before `inject` runs.

### How OneGate picks the credential

For an app request from an agent, OneGate considers only the connections **granted** to the agent (directly or via its project) and resolves `ctx.credential` among those in this order:

1. The request header `x-onegate-connection: <name-or-id>`, when present. It must name a connection for this integration that is granted to the agent. If the header is set but names nothing granted, OneGate rejects the request with `400 onegate_unknown_connection` and does not fall through. The header is stripped before the request is forwarded upstream, so the vendor never sees it.
2. Otherwise the agent's saved choice for this integration (`onegate agents apps set`), if it still points at a granted connection.
3. Otherwise the tenant-wide default connection for this integration, if it is granted to the agent.
4. Otherwise, **only when the integration has no named app connections at all**, the legacy single credential (`onegate credentials set`), with behavior identical to before this feature.
5. Otherwise the request fails: `403 onegate_connection_not_granted` (audit decision `connection_not_granted`) when named connections exist for the integration but none is granted to the agent, or `502 onegate_no_credential` when nothing is configured.

When an integration has **no named app connections**, behavior is byte-identical to the legacy single-credential path (this is how a single shared credential, such as Gaty's GitHub PAT, keeps working untouched). Once any named app connection exists for an integration, that integration becomes default-deny and an agent reaches it only through a granted connection. An agent that holds several granted accounts of the same integration sends `x-onegate-connection` to pick one per request, or sets a per-integration default once with `onegate agents apps set`. See the CLI guide (`docs/CLI.md`) for the management commands.

### OAuth integrations hold multiple named connections too

OAuth integrations (Google, GitLab, Dropbox and the rest of the `connect.method === "oauth"` set) are also multi-connection. Each named OAuth connection is a regular **app connection** (`kind="app"`, `vendor=<integrationId>`) whose `data` holds that account's `{ clientId, clientSecret, accessToken?, refreshToken?, expiresAt?, scopes? }`. It is created and updated by the **OAuth consent flow**, not by `POST /api/connections` directly (that route rejects an OAuth integration with `400 oauth_connection`, pointing you at the connect flow). On the Integrations page an OAuth card offers **Add connection** (runs the consent flow, optionally naming the connection and binding it to one agent) and, once any exist, **Manage connections**; the Connections page shows each named OAuth connection with **Re-authorize** (re-runs consent against the same connection, rotating its tokens in place), **Edit** and **Disconnect**.

Because a named OAuth connection is an ordinary app connection, it reuses everything above: default-deny grants, tenant-wide-vs-agent-bound scope, per-request `x-onegate-connection` selection, the masked secret preview, and the credential-picking order. The gateway refreshes its access token on demand and persists providers' rotating refresh tokens (such as GitLab's) onto the connection. A legacy single OAuth credential (one set before this feature) keeps working as the fallback when no named OAuth connection exists, and the OAuth card surfaces a **Disconnect legacy** affordance for it.

## Installing a community integration

Drop the file in the community directory (`ONEGATE_COMMUNITY_DIR`, default `<data>/integrations`, in Docker `/data/integrations`) and restart the gateway. Startup logs list every loaded integration. A file that does not default-export a valid integration fails startup loudly rather than being silently skipped.

## Patterns

**Static token (most APIs).** Like the Slack example above. One credential field, one header rewrite.

**Two auth styles by host.** GitHub uses `Bearer` for the API but git-over-HTTP wants Basic. Branch on `ctx.host`:

```js
inject(ctx) {
  const pat = ctx.credential.data.pat;
  if (ctx.host === "github.com" || ctx.host === "codeload.github.com") {
    ctx.headers.authorization =
      "Basic " + Buffer.from(`x-access-token:${pat}`).toString("base64");
  } else {
    ctx.headers.authorization = `Bearer ${pat}`;
  }
}
```

**OAuth refresh tokens.** Store the long-lived refresh token as the credential and mint short-lived access tokens on demand, cached in the settings table via `ctx.store`. See `src/integrations/google.ts` for the full pattern (cache key per credential, refresh when within a minute of expiry).

**URL-path credentials.** Some APIs carry the credential in the URL itself (Telegram puts the bot token in the path). `inject` may reassign `ctx.path` and the gateway forwards the rewritten path upstream. Policy evaluation and the audit log always use the original path the agent sent, so the real credential never shows up in rules or logs. See `src/integrations/telegram-bot.ts`. Request bodies can be read (`needsBody`, for payload signing) but not rewritten, an API that only accepts credentials inside the body cannot be injected by OneGate.

**Payload signing.** When the vendor's auth scheme signs the request body (AWS SigV4), declare `needsBody: true` and hash `ctx.body` inside `inject`. See `src/integrations/aws.ts`.

## Permissions for your integration

Operators control access with rules scoped to your `id`, methods, and path globs. Design your host list so paths are meaningful for permissioning. One real-world example: Calendar and Drive share `www.googleapis.com`, so per-product permission on the Google integration is done with path globs (`/calendar/**`, `/drive/**`).

Host ownership is first-match in registration order, with exact entries and dot-suffix entries (`.googleapis.com`) both supported. The built-in Google integration claims the explicit Workspace hosts and is registered before GCP's broad `.googleapis.com` claim, which is how the two coexist.

## Contributing upstream

Built-in integrations live in `src/integrations/` and are registered in `src/integrations/index.ts`. PRs welcome: add the module, register it, and add a test in `test/integrations.test.ts` proving the header rewrite (and the refresh flow if OAuth-based).

## Built-in integration catalog

Every built-in integration, what it stores, which hosts it owns, and a least-privilege starting point for rules. Suggested policy path globs are starting points, scope them to your agent's real needs. All entries ship a crafted "Get help from your LLM" prompt.

### github

- **Credential:** personal access token (classic or fine-grained). Injected as `Bearer` on the API hosts, as `Basic x-access-token:<pat>` for git smart HTTP.
- **Hosts:** `api.github.com`, `uploads.github.com`, `github.com`, `codeload.github.com`.
- **Suggested policy:** `/repos/**` and `/user` on api.github.com, plus the specific repo paths on github.com if the agent does git over HTTPS.
- **Limitations:** none notable. GraphQL (`/graphql`) is one path, scope the token instead.

### google

- **Credential:** OAuth client (ID + secret) plus a refresh token. The gateway mints short-lived access tokens (cached, refreshed within a minute of expiry) and injects them as `Bearer`. A built-in connect flow obtains the refresh token via browser consent.
- **Hosts:** `gmail.googleapis.com`, `www.googleapis.com` (Workspace only, the rest of `*.googleapis.com` belongs to `gcp`).
- **Suggested policy:** `/gmail/**` on gmail.googleapis.com, `/calendar/**` and `/drive/**` on www.googleapis.com.
- **Limitations:** one user consent covers Gmail, Calendar and Drive together. Per-product permissioning is done with path globs, not separate credentials.

### gemini

- **Credential:** a Google AI Studio API key, injected as the `x-goog-api-key` header. Any `key` query parameter the client sends is rewritten to the real key too.
- **Hosts:** `generativelanguage.googleapis.com` (registered ahead of `gcp`'s dot-suffix claim).
- **Suggested policy:** `/v1beta/models/**`.
- **Limitations:** Generative Language API only. Vertex AI endpoints belong to `gcp` (service account auth). Also available as an LLM vendor for per-agent connection routing, see ARCHITECTURE.md.

### gcp

- **Credential:** a service account key JSON file (pasted whole) plus an optional OAuth scopes override (default `https://www.googleapis.com/auth/cloud-platform`). The gateway signs an RS256 JWT assertion with the key's private key and exchanges it for cached short-lived access tokens (JWT-bearer grant), injected as `Bearer`.
- **Hosts:** `.googleapis.com` (everything not claimed by `google`: compute, storage, bigquery, pubsub, run, ...).
- **Suggested policy:** scope per product host, e.g. `GET` on `/storage/v1/b/my-bucket/**` for storage.googleapis.com. Real access is bounded by the service account's IAM roles, keep those narrow too.
- **Limitations:** Cloud APIs only. Gmail, Calendar and Drive need the `google` integration (user OAuth, domain-wide delegation is not implemented). Each API must be enabled on the GCP project.

### aws (EXPERIMENTAL)

- **Credential:** access key ID, secret access key, optional session token (temporary credentials), optional default region. The gateway computes AWS Signature Version 4 itself: canonical request, payload hash, derived signing key, then sets `Authorization`, `x-amz-date`, `x-amz-content-sha256` (S3) and `x-amz-security-token`.
- **Hosts:** `.amazonaws.com`. Region and service derive from the host (`s3.eu-central-1.amazonaws.com`, `ec2.us-east-1.amazonaws.com`, `bucket.s3.us-west-2.amazonaws.com`, `abc.execute-api.eu-west-1.amazonaws.com`), global endpoints (`iam.amazonaws.com`, `sts.amazonaws.com`) fall back to the credential's default region, then `us-east-1`.
- **Suggested policy:** one rule per service the agent needs, narrowed by method and path glob. Keep the IAM policy on the key itself least-privilege as the primary control.
- **Limitations (why experimental):** request bodies are buffered for payload hashing, capped by `ONEGATE_MAX_BUFFERED_BODY` (default 32 MiB), so very large uploads are rejected with 413. Services whose SigV4 signing name differs from the hostname label (SES signs as `ses` on `email.*` hosts) are not special-cased yet and will fail signature validation. Chunked-upload signing (`STREAMING-AWS4-...`) is not implemented. Agent-supplied `x-amz-date`, `x-amz-content-sha256` and `x-amz-security-token` are stripped and re-signed, other `x-amz-*` headers the agent sends are included in the signature.

### slack

- **Credential:** a bot (`xoxb`) or user (`xoxp`) token, injected as `Bearer`.
- **Hosts:** `slack.com`, `.slack.com`.
- **Suggested policy:** `/api/conversations.*` for reading, `/api/chat.postMessage` for posting.
- **Limitations:** header auth only. Methods that carry the token in a POST body are not injectable (the Web API accepts the Authorization header for all standard methods, so this rarely bites).

### openai

- **Credential:** API key, injected as `Bearer`.
- **Hosts:** `api.openai.com`.
- **Suggested policy:** `/v1/chat/completions`, `/v1/responses`.
- **Limitations:** none notable. Project-scoped keys narrow blast radius at the vendor side.

### anthropic

- **Credential:** API key, injected as the `x-api-key` header (the `authorization` header is left untouched).
- **Hosts:** `api.anthropic.com`.
- **Suggested policy:** `/v1/messages`.
- **Limitations:** none notable.

### jira

- **Credential:** Atlassian account email plus API token, injected as HTTP Basic (`email:token`). An optional, non-secret **Site URL** field (for example `https://your-team.atlassian.net`) can be set on the connection. It is never used for auth, only to tell the agent which site it is working against.
- **Hosts:** `.atlassian.net`, `api.atlassian.com` (one credential covers Jira and Confluence Cloud on every site).
- **Suggested policy:** `/rest/api/3/**` for Jira REST, narrow further per resource.
- **Discovery summary:** Jira implements `accountSummary(cred)`, so the [agent discovery endpoint](ARCHITECTURE.md#agent-discovery-endpoint) reports a non-secret summary for each Jira account: the account `email`, the `siteUrl` (from the optional field above) and the derived `apiBaseUrl`. This lets an agent learn its own Jira site URL without asking a human. The summary omits the API token. When the Site URL field is left empty, `siteUrl` is reported as `null`.
- **Limitations:** classic API tokens carry the full account permissions, prefer scoped tokens where available.

### notion

- **Credential:** internal integration secret, injected as `Bearer`. A default `Notion-Version` header is added when the client sends none.
- **Hosts:** `api.notion.com`.
- **Suggested policy:** `/v1/**`, or split read (`GET /v1/**`) from write.
- **Limitations:** the integration must be invited to each Notion page or database it should see, that is Notion-side configuration.

### linear

- **Credential:** personal API key, injected as a bare `Authorization` header (no Bearer prefix).
- **Hosts:** `api.linear.app`.
- **Suggested policy:** `/graphql` is the only endpoint, method and path rules cannot distinguish queries from mutations, scope the key itself.
- **Limitations:** GraphQL means path-glob policy is all-or-nothing.

### stripe

- **Credential:** secret or restricted key, injected as `Bearer`.
- **Hosts:** `api.stripe.com`, `files.stripe.com`.
- **Suggested policy:** narrow resource globs like `/v1/customers/**`, and prefer a restricted key (read-only where possible).
- **Limitations:** none notable.

### sendgrid

- **Credential:** API key, injected as `Bearer`.
- **Hosts:** `api.sendgrid.com`.
- **Suggested policy:** `/v3/mail/send` only, unless the agent manages templates or lists.
- **Limitations:** none notable.

### brave-search

- **Credential:** subscription token, injected as `X-Subscription-Token`.
- **Hosts:** `api.search.brave.com`.
- **Suggested policy:** `GET /res/v1/web/search`.
- **Limitations:** none notable.

### tavily

- **Credential:** API key, injected as `Bearer`.
- **Hosts:** `api.tavily.com`.
- **Suggested policy:** `/search`, `/extract`.
- **Limitations:** header auth only, the gateway cannot rewrite request bodies, so the legacy body `api_key` style is not injectable (Bearer works on current Tavily).

### telegram-bot

- **Credential:** bot token, rewritten into the URL path (`/bot<placeholder>/method` becomes `/bot<real-token>/method`, same for `/file/bot...` downloads). Policy and audit see the placeholder path, never the token.
- **Hosts:** `api.telegram.org`.
- **Suggested policy:** `/bot*/sendMessage`, `/bot*/get*` (globs match the placeholder path the agent sent).
- **Limitations:** the agent must follow the `/bot<placeholder>/` path convention, bare method paths are rejected.

### discord

- **Credential:** bot token, injected as `Authorization: Bot <token>` (a supplied `Bot ` prefix is kept, not doubled).
- **Hosts:** `discord.com`.
- **Suggested policy:** `/api/v10/**`, narrow per channel or guild resource.
- **Limitations:** bot tokens only, user OAuth flows are not implemented.

### huggingface

- **Credential:** access token, injected as `Bearer`.
- **Hosts:** `huggingface.co`, `.huggingface.co` (hub API and inference).
- **Suggested policy:** `/api/**` for hub metadata, `/models/**` for inference.
- **Limitations:** none notable. Fine-grained tokens narrow access at the vendor side.

### gitlab

- **Credential:** a bring-your-own GitLab OAuth application (Application ID + Secret). The built-in connect flow runs the consent screen, OneGate stores the tokens, refreshes automatically and persists GitLab's rotating refresh tokens. Injected as `Bearer` on `/api/` paths and as `Basic oauth2:<token>` for git smart HTTP.
- **Hosts:** `gitlab.com`.
- **Suggested policy:** `/api/v4/projects/**` plus the specific repo paths if the agent does git over HTTPS.
- **Limitations:** gitlab.com only. Self-managed instances need a community integration with the instance host.

### confluence

- **Credential:** a bring-your-own Atlassian OAuth 2.0 (3LO) app (client ID + secret). The connect flow stores the tokens, `offline_access` is required for refresh. Injected as `Bearer`.
- **Hosts:** `api.atlassian.com` (shared with `jira`, the proxy uses whichever has a connected credential, `jira` first).
- **Suggested policy:** `/oauth/token/accessible-resources` plus `/ex/confluence/**` (narrow to the wiki v2 paths the agent needs).
- **Limitations:** OAuth calls only work through `api.atlassian.com` with the `/ex/confluence/<cloudId>/` prefix. The `*.atlassian.net` site hosts take Basic auth, which the `jira` integration covers for both products.

### dropbox

- **Credential:** a bring-your-own Dropbox app (App key + App secret). The connect flow requests offline access, OneGate stores the refresh token and mints short-lived access tokens. Injected as `Bearer`.
- **Hosts:** `api.dropboxapi.com`, `content.dropboxapi.com`.
- **Suggested policy:** `/2/files/list_folder*` and `/2/files/download` for read-only agents, add `/2/files/upload` for writers (content host carries upload and download).
- **Limitations:** scopes ticked in the connect dialog must also be enabled on the app's Permissions tab in the Dropbox App Console, or the consent screen rejects them.

### cloudflare

- **Credential:** API token (not the legacy Global API Key), injected as `Bearer`.
- **Hosts:** `api.cloudflare.com`.
- **Suggested policy:** `/client/v4/zones/**` narrowed per zone, e.g. `GET` plus the specific `/dns_records` paths for DNS automation.
- **Limitations:** none notable. Token permissions and zone restrictions at the Cloudflare side are the primary control.

### flyio

- **Credential:** Fly.io API token (org or app-scoped deploy token), injected as `Bearer`.
- **Hosts:** `api.machines.dev` (Machines REST API), `api.fly.io` (GraphQL).
- **Suggested policy:** `/v1/apps/<app>/**` on api.machines.dev for a single-app agent.
- **Limitations:** GraphQL on api.fly.io is one path (`/graphql`), use an app-scoped deploy token to bound it.

### vercel

- **Credential:** access token, injected as `Bearer`.
- **Hosts:** `api.vercel.com`.
- **Suggested policy:** `/v6/deployments/**` and `/v9/projects/**` for deployment automation, `GET`-only for monitors.
- **Limitations:** none notable. Create the token team-scoped with an expiration.

### supabase

- **Credential:** a bring-your-own Supabase OAuth app (client ID + secret). The connect flow stores the tokens, refresh uses HTTP Basic client auth. Injected as `Bearer`.
- **Hosts:** `api.supabase.com` (Management API).
- **Suggested policy:** `/v1/projects/**`, `GET`-only unless the agent runs migrations or manages secrets.
- **Limitations:** scopes live on the OAuth app in the Supabase dashboard, not in the authorize URL, so the connect dialog's permission list is informational. Project data APIs (`<ref>.supabase.co`) are separate and not covered.

### resend

- **Credential:** API key, injected as `Bearer`.
- **Hosts:** `api.resend.com`.
- **Suggested policy:** `POST /emails` only for send-only agents.
- **Limitations:** none notable. Domain-restricted sending keys are the tightest vendor-side control.

### todoist

- **Credential:** a bring-your-own Todoist app (client ID + secret). The connect flow stores a long-lived access token (Todoist has no refresh grant). Injected as `Bearer`.
- **Hosts:** `api.todoist.com`.
- **Suggested policy:** `/api/v1/tasks/**` and `/api/v1/projects/**`, `GET`-only for read-only agents.
- **Limitations:** Todoist uses comma-separated scopes and no redirect_uri in the code exchange, both handled by the descriptor. Tokens last until revoked.

### trello

- **Credential:** Trello API key (from a Power-Up) plus a member token returned directly by Trello's authorize page (fragment callback, no code exchange). Injected as `key` and `token` QUERY parameters appended to the path, Trello does not use Authorization headers.
- **Hosts:** `api.trello.com`.
- **Suggested policy:** `/1/boards/**`, `/1/cards/**`, `/1/members/me/**`. Globs match the path as the agent sent it, the appended params do not affect policy.
- **Limitations:** query-param auth means the token rides in URLs at the vendor side (Trello's own design). Audit logs store the agent's path, not the injected params.

### monday

- **Credential:** a bring-your-own monday.com app (client ID + secret). The connect flow stores a long-lived access token (no refresh grant). Injected as `Bearer`.
- **Hosts:** `api.monday.com`.
- **Suggested policy:** `POST /v2` is the only endpoint (GraphQL).
- **Limitations:** GraphQL means path policy cannot split read from write, scope the app's OAuth permissions in the Developer Center instead. The authorize URL takes no scope param.

### linkedin

- **Credential:** a bring-your-own LinkedIn app (client ID + secret). The connect flow stores the access token. Injected as `Bearer`.
- **Hosts:** `api.linkedin.com`.
- **Suggested policy:** `/v2/userinfo` for identity, `/rest/posts/**` for posting.
- **Limitations:** most LinkedIn apps receive no refresh token (programmatic refresh is partner-gated), tokens last about 60 days and the user reconnects. Scopes are granted by products added to the app, not free-form.

### mongodb-atlas

- **Credential:** Atlas service account client ID + secret. OneGate mints short-lived access tokens with the client_credentials grant at request time (cached) and injects `Bearer`. Nothing is exchanged at connect time.
- **Hosts:** `cloud.mongodb.com` (Administration API).
- **Suggested policy:** `/api/atlas/v2/groups/**`, `GET`-only for monitoring agents.
- **Limitations:** covers the Administration API only. Database connections (`mongodb+srv://`) are not HTTP and never go through OneGate. Requests need the versioned Accept header (`application/vnd.atlas.2023-01-01+json`).

### docker

- **Credential:** Docker Hub username + personal access token. OneGate logs in for a Hub JWT lazily, caches it until the token's `exp` and injects `Bearer`.
- **Hosts:** `hub.docker.com` (Hub management API).
- **Suggested policy:** `/v2/repositories/**`, `GET`-only for read-only agents.
- **Limitations:** the image registry (`registry-1.docker.io`) uses a different auth dance and is not covered, this is for repository and org management only. A bad PAT fails at first use, not at connect time.

### jfrog-artifactory

- **Credential:** an Artifactory access token plus the instance host (e.g. `acme.jfrog.io`). Injected as `Bearer`, and only on that exact host.
- **Hosts:** `.jfrog.io` (any tenant, gated to the bound host at inject time).
- **Suggested policy:** `/artifactory/api/npm/**` or the repos the agent pulls from, `GET`-only for consumers.
- **Limitations:** the host binding means one credential per instance. Requests to a different `*.jfrog.io` tenant are refused before any header is added, so a broad dot-suffix policy cannot leak the token.

### github-app

- **Credential:** a GitHub App: App ID, installation ID and the app's RSA private key (.pem, file import supported). OneGate signs RS256 app JWTs, mints installation access tokens (cached about an hour) and injects `Bearer` on the API hosts or `Basic x-access-token` for git over HTTPS.
- **Hosts:** `api.github.com`, `uploads.github.com`, `github.com`, `codeload.github.com` (shared with `github`, the PAT integration stays primary when both are connected).
- **Suggested policy:** `/repos/<org>/**` matching the installation's repository selection.
- **Limitations:** tokens act as the app (bot identity on commits), use the `github` PAT integration when user attribution matters. The installation ID is entered manually (from the installation's settings URL), there is no install-redirect flow.

### elevenlabs

- **Credential:** API key, injected as the `xi-api-key` header.
- **Hosts:** `api.elevenlabs.io`.
- **Suggested policy:** `/v1/text-to-speech/**`, `/v1/speech-to-text/**`, `/v1/voices/**` (narrow to the products the agent uses).
- **Limitations:** none notable. ElevenLabs keys can be scoped per workspace permission at the vendor side, so grant only the permissions the agent needs.

### openrouter

- **Credential:** API key (starts with `sk-or-`), injected as `Bearer`.
- **Hosts:** `openrouter.ai`.
- **Suggested policy:** `/api/v1/chat/completions`, `/api/v1/completions`.
- **LLM vendor:** routable like anthropic, openai and gemini. OpenRouter is an OpenAI-compatible aggregator at `https://openrouter.ai/api/v1`, so point the client's base URL there and use OpenRouter model ids (e.g. `anthropic/claude-3.5-sonnet`). Create the key at https://openrouter.ai/keys.
- **Limitations:** none notable. Cap the key with a credit limit on the OpenRouter dashboard. The client may send `HTTP-Referer` and `X-Title` for attribution, OneGate forwards them unchanged.
