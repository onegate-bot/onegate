# OneGate — Build Plan

> Working plan for the initial implementation. Kept in-repo so contributors can see
> how the project is structured and what is still open.

## What OneGate is

OneGate is a **credential gateway** for AI agents and automation. Agents never hold
real credentials. Instead they send all HTTPS traffic through OneGate, which:

1. Terminates TLS using a **root CA you generate and trust at install time**,
2. Identifies the calling agent by its per-agent gateway token,
3. Checks the request against that agent's **permission rules**,
4. **Injects real credentials** (OAuth access tokens, PATs) for known integrations,
5. Bridges the request over a fresh TLS connection to the real vendor,
6. Writes an **audit log** entry for every request.

Deployment targets: local (Docker image on a workstation) or cloud (same image on a VM).

## Architecture

```
agent (HTTPS_PROXY=http://agent:og_token@gateway:10443, trusts OneGate root CA)
   │  CONNECT api.github.com:443
   ▼
┌─────────────────────────── OneGate ───────────────────────────┐
│ proxy/server.ts   CONNECT handler, agent auth, host routing   │
│   ├── matched integration host → TLS-terminate (leaf cert     │
│   │   minted by ca.ts, signed by root CA)                     │
│   │     ├── policy.ts   allow/deny rules per agent/project    │
│   │     ├── injector    integration.inject(req, credential)   │
│   │     └── forward over real TLS to vendor, stream back      │
│   └── unmatched host → opaque passthrough tunnel (no MITM)    │
│ store/db.ts       sqlite: agents, projects, credentials,      │
│                   rules, audit                                │
│ integrations/     github, google (gmail/calendar/drive), …    │
│ admin/api.ts      REST API + static web UI + Google OAuth     │
└────────────────────────────────────────────────────────────────┘
```

### Components

| Component | File(s) | Notes |
|-----------|---------|-------|
| CA + cert minting | `src/ca.ts` | node-forge. Root CA at init; per-host leaf certs cached on disk + memory. |
| Proxy core | `src/proxy/server.ts` | CONNECT, `Proxy-Authorization` agent auth, MITM for integration hosts only. |
| Policy engine | `src/policy.ts` | Rules: integration + methods + path glob → allow/deny. Deny wins. Per-agent and per-project scope. |
| Store | `src/store/db.ts` | Built-in `node:sqlite` (Node >= 22.13), WAL. Zero native build deps. |
| Integrations | `src/integrations/*` | Interface: `{ id, hosts, inject(ctx) }` + optional OAuth descriptor. Community can drop new files in `integrations/community/`. |
| Admin API | `src/admin/api.ts` | Bearer admin token. CRUD + audit + OAuth connect flow. |
| Web UI | `src/admin/ui/` | No-build vanilla SPA: agents, projects, credentials, rules, audit. |
| CLI | `src/cli.ts` | `onegate init`, `onegate start`, `onegate print-ca`, `onegate agent add`. |

### Credential injection model

- **GitHub**: stored PAT. `api.github.com` → `Authorization: Bearer <pat>`;
  `github.com` (git smart HTTP) → `Authorization: Basic x-access-token:<pat>`.
- **Google (Gmail / Calendar / Drive)**: one Google OAuth app (deployer-provided
  client id/secret) + per-connection refresh token. Gateway keeps an access-token
  cache and refreshes transparently. Hosts: `gmail.googleapis.com`,
  `www.googleapis.com`, `calendar.google.com` etc., scoped per integration.
- Agents send **no** Authorization header (or a placeholder) — the gateway strips
  and replaces it.

### Permission / allowance model

Rule = `{ scope: agent|project, integrationId, methods[], pathGlob, effect }`.
Evaluation: explicit DENY > explicit ALLOW > default (configurable per agent:
`allow-all`, `deny-unmatched`). Every decision is recorded in the audit log.

## Milestones (PRs)

1. **Scaffold + CA** — repo layout, `ca.ts`, tests.
2. **Proxy core + store + policy** — working MITM proxy with audit, tests.
3. **Integrations + OAuth** — GitHub, Google trio, registry, tests.
4. **Admin API + Web UI** — management plane.
5. **Docker + docs** — Dockerfile, compose, deployment + security docs.

## Open questions / later

- Rate limits / quotas per rule ("N calls per day") — schema has a column, enforcement later.
- mTLS between agent and gateway as an alternative to proxy tokens.
- Secret encryption at rest (currently plaintext sqlite on an encrypted volume is assumed; see SECURITY.md).
- Additional integrations: Slack, Notion, Jira, S3…
