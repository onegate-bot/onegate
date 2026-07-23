# Architecture

OneGate is a single Node.js process with two listeners and one SQLite database.

```
                        ┌────────────────────────────────────────────────┐
                        │                 OneGate process                │
  agent traffic ──────▶ │  proxy listener (:8443)                        │
  (HTTP CONNECT)        │    ├─ proxy auth (agent token)                 │
                        │    ├─ host → integration lookup                │
                        │    ├─ unmatched host → opaque TCP passthrough  │
                        │    └─ matched host → TLS terminate (leaf cert) │
                        │         ├─ policy engine (rules)               │
                        │         ├─ credential injection (integration)  │
                        │         ├─ direct TLS to vendor + bridge       │
                        │         └─ audit log                           │
  admin traffic ──────▶ │  admin listener (:8080)                        │
  (browser / API)       │    ├─ REST API (Bearer admin token)            │
                        │    ├─ static web UI                            │
                        │    ├─ /ca.pem (public)                         │
                        │    └─ /oauth/google/callback (state-protected) │
                        │                                                │
                        │  store: node:sqlite (WAL)  ·  CA: node-forge   │
                        └────────────────────────────────────────────────┘
```

## Components

| Module | Responsibility |
|---|---|
| `src/ca.ts` | Root CA generation at init, leaf certificate minting per host (cached memory + disk, re-minted near expiry) |
| `src/proxy/server.ts` | CONNECT handling, proxy auth, TLS termination, request bridging |
| `src/policy.ts` | Rule evaluation (glob matching, deny-over-allow) |
| `src/store/db.ts` | SQLite store: agents, projects, credentials, rules, audit, settings |
| `src/integrations/` | Integration registry, GitHub and Google built-ins, community loader |
| `src/admin/api.ts` | REST API, OAuth connect flow, static UI hosting |
| `src/cli.ts` | `init`, `start`, `print-ca`, `agent add/list`, `admin reset-token` |

## Request flow (matched host)

1. Agent's HTTP client sends `CONNECT api.github.com:443` to the proxy with `Proxy-Authorization` carrying its `og_` token (Basic password or Bearer).
2. The token's sha256 is looked up. Unknown token: `407` and an `auth_failed` audit row.
3. The target host is resolved against integration host lists (exact match, or dot-prefix suffix match like `.googleapis.com`). No match, or port other than 443: raw TCP passthrough, audited as `passthrough`, never decrypted.
4. On a match the gateway replies `200 Connection Established` and wraps the socket in server-side TLS using a leaf certificate for that host minted from the install-time root CA (this is why agents must trust the root).
5. Each HTTP request inside the tunnel is evaluated by the policy engine. Deny: `403 onegate_policy_denied`, audited.
6. The integration's `inject()` rewrites headers (replacing the agent's placeholder credential with the real one). No stored credential: `502 onegate_no_credential`.
7. The gateway opens a **direct** TLS connection to the real vendor (dedicated keep-alive agent, never an ambient proxy), forwards the request, streams the response back, and writes an `allow` audit row with the upstream status.

## Agent discovery endpoint

An agent often needs an account-specific URL or id that lives only in OneGate (for example its Jira `siteUrl`). The gateway exposes a self-describing, secret-free discovery endpoint so the agent can learn this without asking a human.

The agent makes a normal `CONNECT onegate.internal:443` through the proxy with its `og_` token, then `GET /`. The host `onegate.internal` is a sentinel intercepted in the proxy after token auth: TLS is terminated locally with a leaf from the same root CA the agent already trusts, and the request is served in-process (never forwarded upstream, no audit row). GET only, otherwise `405`.

The JSON response lists every integration the agent has at least one account for, and for each: a coarse `access` hint (`allowed` or `denied`, from the policy engine at path `/`), the account(s) (named app connections granted to the agent, or the legacy shared credential), each account's non-secret `summary` (built by the integration's optional `accountSummary(cred)`, e.g. Jira's `siteUrl` and `apiBaseUrl`), and `defaultAccountId`. A sole account auto-defaults. LLM-vendor integrations fall away naturally (they expose no app accounts). The payload is strictly non-secret: only ids, names, and summary facts, never credential values.

## Policy engine

Rules have: scope (`agent` or `project`), subject id, integration id (or `*`), HTTP methods (or `*`), path glob, effect (`allow` or `deny`).

Evaluation for a request: collect the agent's own rules plus its project's rules, check deny rules first (any match wins), then allow rules, otherwise fall back to the agent's default policy (`allow-all` or `deny-unmatched`).

Path globs: `*` matches one path segment, `**` matches anything. Query strings are excluded from matching. Globs are compiled to anchored regexes and cached.

Google's products share hosts (Calendar and Drive both live on `www.googleapis.com`), so per-product permission is expressed with path globs, e.g. allow `/calendar/**` but not `/drive/**`.

## Data model

SQLite via the built-in `node:sqlite` (Node >= 22.13, zero native dependencies), WAL mode, foreign keys on.

- `projects` (id, name)
- `agents` (id, name, project_id, token_hash unique, default_policy)
- `credentials` (id, integration_id unique, name, data JSON)
- `rules` (id, scope, subject_id, integration_id, methods JSON, path_glob, effect)
- `audit` (ts, agent_id, integration_id, method, host, path, decision, status, rule_id)
- `settings` (key, value) for the admin token hash and cached Google access tokens
- `connections` (id, kind, vendor, name, data JSON, is_default) for multi-credential LLM vendors
- `agent_llm_config` (agent_id, enabled, strategy, connection_ids JSON)
- `llm_strategy_state` (agent_id, vendor, active_index, rr_cursor, calls_since_fallback, cooldowns JSON)
- `llm_usage` (ts, connection_id, agent_id, vendor, strategy, requests, errors, token columns, selected, failover, status)

Secrets at rest: agent and admin tokens are stored only as sha256 hashes. Integration credentials are stored as-is in the database (the gateway must read them to inject), so protect the data directory. See [SECURITY.md](SECURITY.md).

## LLM connection routing

LLM vendors (anthropic, openai, gemini) can hold multiple credentials at once. These live in the `connections` table (kind `llm`, named, exactly one default per vendor), separate from the single-credential `credentials` table that apps keep using.

Per agent, an `agent_llm_config` row holds an enabled flag, a strategy and an ordered list of connection ids. When a request hits an LLM integration host and the agent has an enabled config with at least one connection of that vendor, the proxy routes through the strategy engine (`src/llm/strategy.ts`) instead of the app credential path. When there is no enabled config, behavior is exactly as before: the stored app credential is injected, or `502 onegate_no_credential` when none exists. Hosts of integrations disabled via `ONEGATE_DISABLED_INTEGRATIONS` are not registered at all and fall through to opaque passthrough, which is how a bot whose own LLM backend sits behind the gateway keeps working.

Strategies (state persisted per agent and vendor in `llm_strategy_state`):

- **fallback**: requests go to the connection at `active_index` (initially the first). On an error the index advances to the next connection. While a non-primary connection is active, a call counter runs and after 10 calls the index returns to the primary, retrying it.
- **round-robin**: a cursor rotates through the list, skipping connections that are cooling down. An error puts that connection on a 10-call cooldown (decremented once per selection). If everything is cooling, selection proceeds anyway in cursor order so the agent is never hard-stopped.

In-request failover: LLM hosts are marked `needsBody`, so the request body is buffered and the response head is only written once the upstream answers. On a connection error, an injection error, a 429 or a 5xx before any bytes were streamed, the proxy marks the error in the strategy state and retries exactly once with the next selected connection, replaying the buffered body. A second failure is streamed back to the client as is.

Observability: the final audit row of a routed request carries `connection_id`, `connection_name`, `llm_vendor`, `llm_strategy` and `llm_failover` (these columns are added to existing databases by an idempotent `ALTER TABLE` migration at startup). `GET /api/audit` additionally returns `llmConnectionName`, the connection's CURRENT name resolved from its id (falling back to the name captured at request time, then to the bare id, when the connection has since been deleted), which the UI shows as a Connection column. Each attempt, including errored ones, also writes a row to `llm_usage` with request and error counters, the upstream status and a failover flag.

Token accounting is best effort (`src/llm/usage.ts`): on the success path the proxy taps the upstream response stream and fills `input_tokens` and `output_tokens` on the usage row when the body ends. The forwarded bytes are never altered, delayed or buffered. Detection is shape based: anthropic JSON `usage.input_tokens`/`output_tokens`, anthropic SSE (`message_start` carries the input count, the last `message_delta` carries the cumulative output count, parsed line by line as the stream passes), openai `prompt_tokens`/`completion_tokens` (streams only when the final chunk carries usage via `stream_options.include_usage`), gemini `usageMetadata`. Inspection memory is capped at 256 KiB (JSON bodies past the cap, or a single oversized SSE line, are skipped silently) and compressed or non-JSON, non-SSE bodies are not inspected at all, so their token columns stay null.

## Audit source and reason

Every audit row records a raw `decision` and upstream `status`, but those alone do not tell an operator (or the agent's owner) who actually blocked a request. A `403` could be OneGate refusing on policy, or the vendor itself rejecting the call. To make that legible, `GET /api/audit` derives two extra fields at read time from the existing columns (`src/audit-meta.ts`), so no migration is needed and historical rows are labelled retroactively:

- **`source`** is `onegate` when the row is one of OneGate's own blocks (`deny`, `auth_failed`, `no_credential`, `unknown_connection`, `connection_not_granted`, `body_too_large`), and `upstream` for `allow` and `passthrough` rows where the request reached the vendor.
- **`reason`** is a short plain-words explanation for any non-clean outcome (for example "Blocked by OneGate: no allow rule matches this agent and integration. Add an allow rule to permit it."), and `null` for a clean success.

The admin UI surfaces `source` as a Source column with the `reason` shown as a sub-row, so a denied call reads as "blocked by OneGate, here is why" versus "the vendor returned this status".

## Admin API

All `/api` routes require `Authorization: Bearer <admin token>`. Public exceptions: `/api/health`, `/ca.pem` and the OAuth callback. The long-standing route families are agents (`/api/agents` CRUD plus `rotate-token`), projects (`/api/projects`), integrations and their single app credential (`/api/integrations`, `PUT/DELETE /api/credentials/:integrationId`), the OAuth connect flow (`POST /api/integrations/:id/oauth/start`, `GET /oauth/:id/callback`), rules (`/api/rules`) and the audit log (`GET /api/audit`).

The LLM routing feature adds:

| Route | Behavior |
|---|---|
| `GET /api/connections` | All connections, grouped: `llm` (multi per vendor, default flag) and `apps` (the single-credential integrations, annotated with integration metadata and an `orphaned` flag when the integration is not registered). Each entry carries `hasSecret` (true when a secret is stored) and, for vendors that have one, a non-secret `authMode` discriminator (anthropic: `api_key` or `auth_token`, openai: `api_key` or `auth_json`) so the edit dialog can show that a secret is set and pre-select the stored mode. Secret material itself is never returned. |
| `POST /api/connections` | Create an LLM connection: `{ kind: "llm", vendor, name, data, isDefault? }`. Vendors come from the registry's LLM integrations (anthropic, openai, gemini). anthropic and gemini need `data.apiKey`; openai accepts `{ apiKey }` or an imported auth.json shape `{ accessToken, accountId? }`. The first connection of a vendor becomes its default. |
| `PUT /api/connections/:id` | Edit `name`, `data` (validated against the connection's vendor) or `isDefault` (`true` moves the per-vendor default atomically). An omitted or empty `data` keeps the stored secret, so the edit dialog can save with the secret field left blank. |
| `DELETE /api/connections/:id` | Disconnect. The id is removed from every `agent_llm_config` that references it, those agents' strategy state is reset, and a deleted default is handed to the oldest remaining connection of the vendor. |
| `GET /api/agents/:id/llm` | The agent's LLM routing config, or a disabled default when none was set. |
| `PUT /api/agents/:id/llm` | Set `{ enabled, strategy: "fallback" or "round-robin", connectionIds }` (ordered, each id must be an existing LLM connection). Always resets the agent's persisted strategy state so the new order starts fresh. |
| `GET /api/usage` | LLM usage rollups per connection and per vendor (requests, errors, failovers, input/output tokens) over `?since`/`?until` ISO timestamps (default: the last 7 days), plus the most recent selection events (`?limit`, default 100) with the routed connection, strategy, failover flag and outcome. |

Orphaned credentials (issue #3886): `GET /api/integrations` also lists credentials whose integration id is not in the registry (disabled via `ONEGATE_DISABLED_INTEGRATIONS` or a removed community integration), flagged `orphaned: true` with the credential name, so the UI can offer disconnect. `DELETE /api/credentials/:integrationId` works for them, it never registry-checks.

## Certificate authority

- Root: 2048-bit RSA, 10-year validity, created once at `onegate init`. Key on disk with mode 0600.
- Leaves: minted on demand per host, SHA-256 signed, SANs for the host and `*.host`, 1-year validity, cached in memory and under `certs/`, re-minted when within 7 days of expiry or when the root changed.

## Design choices

- **Plain HTTP CONNECT proxy as the agent interface.** Every language and tool already supports `HTTPS_PROXY`. No SDK to install, nothing agent-side except trusting the root CA.
- **Passthrough by default.** Only hosts claimed by an integration are terminated. Everything else is an opaque tunnel, so the gateway cannot read traffic it has no business reading.
- **Direct upstream dialing.** The gateway uses a dedicated `https.Agent` and never inherits ambient proxy env vars, so credentials always travel directly from gateway to vendor.
- **No build step for the UI.** Vanilla ES modules served statically, so a contributor can edit the admin UI with zero tooling.
