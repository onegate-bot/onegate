# OneGate

**The agent security platform, made by agents, for agents.**

An open-source credential gateway for AI agents. OneGate sits between your agents and the services they call (33 built-in integrations from GitHub and Google to Stripe and MongoDB Atlas, plus any community-added integration), injects real credentials at the network edge, and gives you one place to manage which agent may do what.

OneGate is built and maintained by agents, in the open. The threat model, the code, and the reviews come from the same kind of system it protects.

Agents never see a real API key. They talk to vendors through OneGate with a placeholder, and OneGate replaces it with the real credential only for requests that pass your policy.

```
┌─────────┐   HTTPS_PROXY    ┌──────────────────────────┐   direct TLS   ┌──────────┐
│  agent   │ ───────────────▶│         OneGate          │───────────────▶│  vendor  │
│ (no real │   CONNECT +     │ auth → policy → inject   │  real          │  (GitHub,│
│  creds)  │   placeholder   │ credential → audit       │  credential    │  Google) │
└─────────┘                  └──────────────────────────┘                └──────────┘
```

## How it works

1. **Install-time root CA.** `onegate init` mints a root certificate. You trust it on each agent machine (one file, `/ca.pem` from the admin server).
2. **Standard proxy wiring.** Each agent gets `HTTPS_PROXY=http://agent:<token>@gateway:8443`. No SDK, no code changes. Anything that honors proxy env vars works (curl, Node, Python, CLIs).
3. **TLS termination at the gateway.** For hosts that belong to a configured integration, OneGate terminates TLS using a leaf certificate minted from your root CA, applies policy, swaps the placeholder credential for the real one, then opens a direct TLS connection to the vendor and bridges the request. Hosts that match no integration are passed through untouched (no decryption).
4. **Policy and audit.** Allow/deny rules per agent or per project, scoped by integration, HTTP method, and path glob. Every decision is written to an audit log.

## Quick start (Docker)

```sh
docker compose up -d
docker logs onegate        # first boot prints the one-time admin token
```

Open http://localhost:8080, paste the admin token, and you are in the web UI: create agents, connect integrations, set rules, watch the audit log.

## Quick start (from source)

Requires Node >= 22.13 (uses the built-in `node:sqlite`, zero native deps).

```sh
pnpm install
pnpm build
node bin/onegate.js init    # prints the one-time admin token
node bin/onegate.js start
```

## Wiring an agent

```sh
# on the gateway
onegate agent add my-agent            # prints a one-time og_ token

# on the agent machine
export HTTPS_PROXY=http://agent:og_xxxxxxxx@gateway-host:8443
export NODE_EXTRA_CA_CERTS=/path/to/rootCA.pem   # or trust system-wide
curl https://api.github.com/user -H "Authorization: Bearer placeholder"
```

The placeholder is replaced with the real credential at the gateway. New agents default to `deny-unmatched`, so add an allow rule (UI or API) before traffic flows.

## Integrations

Built in (33): **GitHub** (PAT) and **GitHub App** (installation tokens), **Google** (Gmail, Calendar, Drive through one OAuth connection), **GCP** (service accounts for Cloud APIs), **AWS** (experimental gateway-side SigV4), **Slack**, **OpenAI**, **Anthropic**, **Jira / Atlassian**, **Confluence**, **Notion**, **Linear**, **Stripe**, **SendGrid**, **Resend**, **Brave Search**, **Tavily**, **Telegram Bot**, **Discord**, **Hugging Face**, **GitLab**, **Dropbox**, **Cloudflare**, **Fly.io**, **Vercel**, **Supabase**, **Todoist**, **Trello**, **monday.com**, **LinkedIn**, **MongoDB Atlas**, **Docker Hub** and **JFrog Artifactory**. Full catalog with credential types, hosts and suggested policies in [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

OAuth integrations are bring-your-own-client: you create an OAuth app at the vendor, paste its client ID and secret into the connect dialog, pick scopes, and OneGate runs the consent flow and refreshes tokens from then on.

Community integrations are single files dropped into the integrations directory. See [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) to write one in ~30 lines.

## Web UI

Served by the admin server (default port 8080): dashboard, agents (one-time token issue and rotation), projects, a grouped and searchable integration catalog with per-method connect dialogs (OAuth consent with scope pickers, API key forms, credential file imports), rules editor, and a live audit log.

## Documentation

- [Architecture](docs/ARCHITECTURE.md). Components, request flow, data model.
- [Deployment](docs/DEPLOY.md). Docker, compose, cloud VMs, backups.
- [Integrations guide](docs/INTEGRATIONS.md). Build and ship a community integration.
- [Security model](docs/SECURITY.md). Threat model and operational guidance.

## CLI

```
onegate init                 initialize data dir, root CA and admin token
onegate start                run the gateway (proxy + admin UI)
onegate print-ca             print the root CA certificate
onegate admin reset-token    mint a new admin token
onegate agent add <name>     register an agent (--policy, --project)
onegate agent list           list agents
```

Environment: `ONEGATE_DATA` (default `~/.onegate`), `ONEGATE_PROXY_PORT` (8443), `ONEGATE_ADMIN_PORT` (8080), `ONEGATE_BIND`, `ONEGATE_COMMUNITY_DIR`.

## Development

```sh
pnpm install
pnpm test          # vitest, includes a full end-to-end proxy test
pnpm typecheck
```

## License

Apache License 2.0 (see [LICENSE](LICENSE)). Contributions are accepted under the same license (inbound = outbound), no CLA. See [CONTRIBUTING.md](CONTRIBUTING.md). Third-party material bundled in this repository is documented in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
