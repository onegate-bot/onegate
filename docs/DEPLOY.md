# Deployment

OneGate runs anywhere Node >= 22.13 or Docker runs. The two common shapes:

- **Local gateway**: on the same machine or LAN as your agents (Docker or bare Node).
- **Cloud gateway**: a small VM that all your agents point at.

## Local with Docker

```sh
docker compose up -d
docker logs onegate            # first boot prints the one-time admin token
```

Or without compose:

```sh
docker build -t onegate .
docker run -d --name onegate \
  -p 8443:8443 -p 8080:8080 \
  -v onegate-data:/data \
  onegate
docker logs onegate
```

The entrypoint runs `onegate init` automatically on first boot (empty volume) and then `onegate start`. All state lives in the `/data` volume.

## Local from source

```sh
pnpm install && pnpm build
node bin/onegate.js init
node bin/onegate.js start
```

State lives in `~/.onegate` (override with `ONEGATE_DATA`).

## Cloud VM (any provider)

Tested shape: a small Ubuntu VM (2 vCPU is plenty), Docker installed.

```sh
# on the VM
git clone https://github.com/onegate-bot/onegate && cd onegate
docker compose up -d
docker logs onegate            # grab the admin token
```

Then:

1. **Firewall.** Open 8443 (proxy) to your agents only. Keep 8080 (admin) closed to the public internet. Reach it over an SSH tunnel (`ssh -L 8080:localhost:8080 vm`) or put it behind a reverse proxy with TLS and auth. The admin API is token-protected but it should still not be world-reachable.
2. **Distribute trust.** Download the root CA from `http://<vm>:8080/ca.pem` (or `docker exec onegate node bin/onegate.js print-ca`) and trust it on each agent machine, e.g. `export NODE_EXTRA_CA_CERTS=/path/rootCA.pem` for Node agents or the OS trust store.
3. **Register agents.** In the web UI or `docker exec onegate node bin/onegate.js agent add <name>`. Hand each agent its one-time token.
4. **Point agents at the gateway.** `export HTTPS_PROXY=http://agent:<token>@<vm>:8443`.

### systemd instead of Docker

```ini
# /etc/systemd/system/onegate.service
[Unit]
Description=OneGate gateway
After=network.target

[Service]
User=onegate
Environment=ONEGATE_DATA=/var/lib/onegate
ExecStart=/usr/bin/node /opt/onegate/bin/onegate.js start
Restart=always

[Install]
WantedBy=multi-user.target
```

## OAuth redirect for Google connect

The Google connect flow needs the browser to reach the admin server's `/oauth/google/callback`. Use the URL you actually browse the UI on (for a tunneled admin port that is `http://localhost:8080`) as the redirect base, and register `<redirectBase>/oauth/google/callback` in the Google Cloud Console OAuth client. The UI prefills this for you.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `ONEGATE_DATA` | `~/.onegate` (`/data` in Docker) | data directory (CA, db, certs) |
| `ONEGATE_PROXY_PORT` | 8443 | proxy listener |
| `ONEGATE_ADMIN_PORT` | 8080 | admin UI/API listener |
| `ONEGATE_BIND` | 0.0.0.0 | bind address for both listeners |
| `ONEGATE_COMMUNITY_DIR` | `<data>/integrations` | extra integrations directory |
| `ONEGATE_DISABLED_INTEGRATIONS` | (none) | comma/space separated integration ids to drop (their hosts pass through instead of being managed) |

### Disabling integrations

Set `ONEGATE_DISABLED_INTEGRATIONS` (e.g. `anthropic,telegram-bot`) when a host owned by a catalog integration is actually the agent's own backend and must pass straight through. A registered integration host is always MITM-terminated and demands a connected credential, so without this an agent that talks to, say, `api.anthropic.com` for its own LLM (with its own token, not an injectable key) would be denied. Disabling the integration returns its hosts to plain opaque passthrough. This is the right setting when a single OneGate instance doubles as an agent's egress proxy.

## Backup and restore

Everything is in the data directory: `rootCA.pem`, `rootCA.key`, `certs/`, `onegate.db`. Back it up cold (or use SQLite's `.backup`). Restoring it on a new host restores the whole gateway, and agents keep working because they already trust that root CA. Treat the backup as secret material (it contains credentials and the CA key).

## Upgrading

```sh
git pull && docker compose up -d --build
```

The schema is created with `IF NOT EXISTS` and the data volume carries state across image rebuilds.
