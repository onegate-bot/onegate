# OneGate CLI

The `onegate` command operates a gateway in two ways:

- **Local commands** read and write the data directory directly (no running server needed).
- **Admin API commands** talk to a running gateway over its admin API, using the admin token.

Local commands are unchanged from earlier releases. This page covers the admin API commands.

## Connecting to a running gateway

Admin API commands need a base URL and an admin token. Resolution order:

| Setting | Flag | Environment | Default |
| --- | --- | --- | --- |
| Base URL | `--host <url>` | `ONEGATE_ADMIN_URL` | `http://localhost:8080` |
| Admin token | `--token <oga_...>` | `ONEGATE_ADMIN_TOKEN` | (required) |

Add `--json` to any admin command for machine-readable output. Without it you get a compact human table or a short confirmation line.

```bash
export ONEGATE_ADMIN_URL=http://localhost:8080
export ONEGATE_ADMIN_TOKEN=oga_...
onegate agents list
onegate --json connections list
```

The client uses Node's `http`/`https` with a dedicated agent and ignores any proxy environment, so it always reaches the local admin API directly.

## LLM connections and per-agent routing

A connection holds one vendor credential. Each vendor (anthropic, openai, gemini) can have several connections and exactly one default. A per-agent route picks which connections an agent uses and in what order.

```bash
# Add an Anthropic API-key connection and make it the default.
onegate connections add --vendor anthropic --name anth-1 --api-key sk-ant-... --default

# Add an Anthropic subscription auth-token connection (Bearer mode).
onegate connections add --vendor anthropic --name anth-2 --auth-token sk-ant-oat-...

# Read a secret from stdin instead of a flag (keeps it out of shell history).
printf '%s' "$TOKEN" | onegate connections add --vendor anthropic --name anth-3 --secret-stdin --auth-token-stdin

onegate connections list
onegate connections set-default <connId>
onegate connections rm <connId>
```

Secret material is never printed. Output reports `hasSecret` only.

Wire an agent to one or more connections:

```bash
onegate agents llm set <agentId> --strategy fallback --connections conn_a,conn_b
onegate agents llm get <agentId>
onegate agents llm clear <agentId>
```

`--strategy` is `fallback` or `round-robin`. `set` enables routing by default. Pass `--disabled` to write a route without turning it on.

### Disabled vendors (self-egress instances)

When a vendor is listed in `ONEGATE_DISABLED_INTEGRATIONS`, the admin API refuses to create a connection for it. That gate is intentional on instances that also proxy their own LLM traffic (for example a gateway that fronts a bot whose own backend is that vendor).

For those instances, `connections add` supports a sanctioned direct-store path:

```bash
onegate connections add --vendor anthropic --name seed-1 --auth-token sk-ant-oat-... --allow-disabled-vendor
```

This writes the connection row straight to the local store, exactly as the server would, and prints a warning that it bypassed the API vendor gate. It replaces the hand-written SQLite seeding that was needed before. The command must run on the gateway host so it can open the data directory. The secret is stored in the local database and never logged.

## App connections and per-agent app accounts

App (service) integrations such as GitHub, Slack and SendGrid can have several named connections, each holding a different account credential. A connection is either **tenant-wide** (shared by every agent) or **agent-bound** (only the named agent may use it). Each scope tracks its own default connection.

```bash
# A tenant-wide GitHub connection, made the default for its scope.
onegate connections add --kind app --integration github --name gh-shared --data pat=ghp_... --default

# An agent-bound GitHub connection (only this agent may use it).
onegate connections add --kind app --integration github --name gh-mine --data pat=ghp_... --agent <agentId>

# Secret material is one or more --data key=value pairs (the integration's credential fields).
onegate connections add --kind app --integration slack --name slack-ops --data token=xoxb-...

onegate connections list           # LLM and app connections, with scope and default columns
onegate connections set-default <connId>
onegate connections rm <connId>
```

`--integration` is the integration id (for example `github`). `--name` is required. Secrets come from `--data` and are never echoed.

### Granting connections (default-deny)

A named app connection is **denied to every agent by default**. It becomes usable only when it is explicitly granted, either to an individual agent or to a project (the grant then applies to every agent whose `project_id` matches). Grants are visible and revocable from both sides.

```bash
onegate connections grants --id <connId>                       # who this connection is granted to
onegate connections grant  --id <connId> --agent <agentId>     # grant to one agent
onegate connections grant  --id <connId> --project <projectId> # grant to every agent in a project
onegate connections revoke --id <connId> --agent <agentId>     # revoke a grant
onegate connections revoke --id <connId> --project <projectId>
```

`grant`/`revoke` take exactly one of `--agent` or `--project`. With no grants, the connection is listed but cannot be selected by any agent (the Connections page shows a default-deny warning). Granting never exposes the secret.

When an agent holds more than one account for the same integration, pick which one it uses by default for that integration:

```bash
onegate agents apps get <agentId>                              # saved choices plus available connections
onegate agents apps set <agentId> <integrationId> --connection <connId>
onegate agents apps clear <agentId> <integrationId>            # fall back to the default connection
```

`agents apps get` lists every connection the agent may use (tenant-wide plus its own) and any saved per-integration choice.

### How a connection is selected at request time

For an app request from an agent, OneGate considers only the connections that are **granted** to the agent (directly or via its project). It resolves among those in this order:

1. The request header `x-onegate-connection: <name-or-id>`, when present. It must name a connection for that integration that is granted to the agent. If the header is set but names nothing granted, the request is rejected (HTTP 400 `onegate_unknown_connection`). The header is stripped before the request is forwarded upstream.
2. Otherwise the agent's saved choice for that integration (`agents apps set`), if it still points at a granted connection.
3. Otherwise the tenant-wide default connection for that integration, if it is granted to the agent.
4. Otherwise, **only when the integration has no named app connections at all**, the legacy single credential set with `onegate credentials set` (unchanged behavior).
5. Otherwise the request fails: HTTP 403 `onegate_connection_not_granted` when named connections exist but none is granted to the agent, or no credential available.

When an integration has no named app connections, behavior is identical to before this feature (the legacy single-credential path). Once any named app connection exists for an integration, that integration is default-deny: an agent reaches it only through a granted connection.

## Agents

```bash
onegate agents list
onegate agents add <name> [--policy allow-all|deny-unmatched] [--project <id>]
onegate agents rename <agentId> <newName>
onegate agents rotate-token <agentId>
onegate agents rm <agentId>
```

`add` and `rotate-token` print the agent token once.

## Rules

```bash
onegate rules list
onegate rules add --scope agent --subject <agentId> --integration github --effect allow --methods GET,POST --path "/**"
onegate rules rm <ruleId>
```

`--effect` is `allow` or `deny`. `--methods` is a comma list (omit for all). `--path` is a glob (defaults to `/**`).

## Credentials and integrations

```bash
onegate integrations list
onegate credentials set <integrationId> --name <n> --data key=value [--data key=value ...]
onegate credentials rm <integrationId>
```

OAuth integrations connect through the browser. The CLI only prints the URL to open:

```bash
onegate integrations connect google --client-id <id> --client-secret <secret> --redirect-base https://gateway.example.com
```

## Audit and usage (read-only)

```bash
onegate audit [--agent <agentId>] [--limit <n>]
onegate usage [--since <ISO>] [--until <ISO>] [--limit <n>]
```

`usage` reports per-connection and per-vendor rollups.

## Projects

```bash
onegate projects list
onegate projects add <name>
onegate projects rm <id>
```

## Exit codes

Admin commands exit non-zero on failure and print a one-line reason to stderr. A rejected admin token reports a 401, an unreachable host reports that the admin API could not be reached, and other API errors surface the server's error and message.
