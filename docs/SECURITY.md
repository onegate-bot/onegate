# Security model

## What OneGate protects

**The credentials.** Agents never hold real API keys. A leaked agent environment leaks an `og_` proxy token, which you revoke with one click (rotate or delete the agent), instead of a vendor credential with the blast radius of your whole Google account.

**The blast radius.** Per-agent and per-project rules bound what each agent can do, by integration, HTTP method and path. A compromised research agent allowed `GET /gmail/**` cannot send mail or touch Drive even though the underlying Google credential could.

**The record.** Every decision (allow, deny, passthrough, auth failure, missing credential) is one audit row with agent, method, host, path and upstream status.

## What OneGate does NOT protect against

- **A compromised gateway host.** The gateway must read credentials to inject them, so the data directory contains them (and the CA key). Whoever roots the gateway box has everything. Harden that host like a secrets store.
- **Malicious allowed requests.** Policy bounds *which* calls an agent may make, not whether an allowed call is wise. An agent allowed `POST /repos/**` can still open a bad PR.
- **Traffic to non-integrated hosts.** Passthrough tunnels are opaque by design. OneGate neither inspects nor restricts them (it audits the CONNECT). If you need egress control, do it at the firewall.

## Owner approvals (`require_approval`)

A rule with the `require_approval` action holds a matching call instead of forwarding it. The agent gets `403 onegate_approval_pending`, and the owner gets a one-time `/approve/<token>` link (only the token's SHA-256 is stored). Once the owner approves, the agent's retry of the **identical** request goes through **exactly once**:

- **Bound to the request.** Redemption matches the agent, integration, the gating rule, the HTTP method, the canonical path including its query string, and the SHA-256 of the request body. The body is buffered (up to `ONEGATE_MAX_BUFFERED_BODY`, 32 MiB by default) when the call is held, and its hash is stored with the approval; the retry's body must hash the same. An owner who approved `POST /repos/x/issues` with one payload has not approved a different payload on the same path. A held body over the cap is refused with `413`.
- **Atomic, single use.** The redeeming `UPDATE` re-checks `status = 'approved' AND used_at IS NULL`, so of two concurrent retries (or two gateway processes on one database) only one passes. After that the next identical call needs a fresh approval.
- **Never from a refusal.** A pending, rejected or expired approval (the owner's 24-hour window, which also bounds the retry) never lets a call through. An explicit deny rule still beats `require_approval` outright. Approvals recorded before body binding existed carry no body hash and can never be redeemed.
- **Audited.** The redeemed call is an `allow` row carrying the gating rule id and the `approvalId`.

Limitations: the owner's page shows the method and path, not the body (the body itself is never stored, only its hash), so the owner is approving "this exact call the agent made", not a payload they reviewed. An approval is spent when the gateway admits the retry, so a retry that then fails for another reason (no credential connected, upstream error) needs a new approval.

## Trust and the root CA

At install time you mint a root CA and explicitly trust it on each agent machine. That trust is exactly what lets the gateway terminate TLS for integration hosts. Understand the consequences:

- Anyone holding `rootCA.key` can impersonate **any** website to machines that trust that root. The key never leaves the gateway's data directory, is written mode 0600, and should stay that way.
- Prefer scoping the trust to the agent process (`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `curl --cacert`) over installing the root into the OS store of a workstation you also browse on.
- The gateway only terminates hosts claimed by an installed integration. Everything else is passed through untouched, so the root CA is never used for hosts you did not configure.

## Secrets at rest

| Secret | Storage |
|---|---|
| Agent tokens (`og_`) | sha256 hash only, shown once at creation |
| Admin token (`oga_`) | sha256 hash only, shown once at init, constant-time compared |
| Integration credentials | plaintext in SQLite (must be readable to inject) |
| OAuth client (BYOC) and tokens | part of the integration credential, plaintext in SQLite |
| Minted short-lived tokens | cached in the SQLite settings table, refreshed on expiry |
| Root CA key | PEM on disk, mode 0600 |

For OAuth integrations you bring your own OAuth client. The client ID and secret you enter in the connect dialog are stored inside the integration credential, alongside the access and refresh tokens OneGate obtains with them. They get the same protection (and the same exposure) as any other credential. Integrations that mint short-lived tokens at request time (Google, GCP, MongoDB Atlas, Docker Hub, GitHub App) cache those tokens in the settings table, which lives in the same database.

Protect `ONEGATE_DATA` (and its backups) accordingly: it is equivalent to the credentials it holds.

## Network posture

- **Proxy port (8443):** reachable by agents only. Proxy auth is required before any tunneling happens, and failures are audited.
- **Admin port (8080):** token-protected, but do not expose it publicly. Use an SSH tunnel or a TLS-terminating reverse proxy with its own auth. The OAuth callback is protected by a single-use, 10-minute random state.
- The gateway dials vendors directly with a dedicated agent and ignores ambient proxy environment variables, so credentials cannot be siphoned through an injected upstream proxy.

## Operational guidance

- Default agents to `deny-unmatched` (the built-in default) and add narrow allows.
- One agent identity per workload. Shared tokens destroy both audit attribution and revocation granularity.
- Rotate the admin token (`onegate admin reset-token`) if it may have leaked, and rotate agent tokens on any suspicion (one click in the UI).
- Review the audit log for `deny` and `auth_failed` spikes. They are the earliest sign of a confused or compromised agent.
- Keep community integrations under review before dropping them in: an integration runs in-process and receives the credential for its hosts.

## Reporting

Found a vulnerability? Open a private security advisory on the GitHub repo (or contact the maintainer directly) rather than a public issue.
