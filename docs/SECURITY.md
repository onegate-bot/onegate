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

A rule with the `require_approval` action holds a matching call instead of forwarding it. The agent gets `403 onegate_approval_pending` with an `approval_id`, and the owner gets a one-time `/approve/<token>` link on their notify webhook (only the token's SHA-256 is stored). Once the owner approves, the agent's retry of the **identical** request goes through **exactly once**:

- **The agent never holds the decision link.** The approve link is a bearer capability: whoever holds the token can approve the call. So by default it is sent only to the owner (the agent's notify webhook) and never appears in a response to the agent. The agent's 403 carries `approval_id`, `approval_expires_at` and an `approval_status_url` (`https://onegate.internal/approvals/<id>`, a token-free status read scoped to the calling agent). The owner can also decide with `onegate approvals approve <id>` or `POST /api/approvals/<id>/approve`. Lapsed access leases work the same way: the `onegate_lease_expired` 403 carries the `rule_id` but no `/renew/` link. Before this, an agent could POST its own `approval_url` and approve itself, which defeated `require_approval` and lease time-boxing entirely.
- **Bound to the request.** Redemption matches the agent, integration, the gating rule, the upstream host, the HTTP method, the canonical path including its query string, and the SHA-256 of the request body. An approval held for one host of a multi-host integration is not spendable on another host of the same integration; approvals recorded before host binding existed carry no host and can never be redeemed (they are short-lived, so this fails closed at the cost of one re-approval). The body is buffered (up to `ONEGATE_MAX_BUFFERED_BODY`, 32 MiB by default) when the call is held, and its hash is stored with the approval; the retry's body must hash the same. An owner who approved `POST /repos/x/issues` with one payload has not approved a different payload on the same path. A held body over the cap is refused with `413`.
- **Atomic, single use.** The redeeming `UPDATE` re-checks `status = 'approved' AND used_at IS NULL`, so of two concurrent retries (or two gateway processes on one database) only one passes. After that the next identical call needs a fresh approval.
- **Never from a refusal.** A pending, rejected or expired approval (the owner's 24-hour window, which also bounds the retry) never lets a call through. An explicit deny rule still beats `require_approval` outright. Approvals recorded before body binding existed carry no body hash and can never be redeemed.
- **Audited.** The redeemed call is an `allow` row carrying the gating rule id and the `approvalId`.

### Legacy relay mode (`ONEGATE_AGENT_RELAYS_OWNER_LINKS`)

Some deployments use the bot itself as the owner's notification channel: the bot forwards the link to its owner in chat. `ONEGATE_AGENT_RELAYS_OWNER_LINKS=1` puts `approval_url` and the renewal `connect_url` back into the agent's 403 for them. Because the agent now holds the token, every decision on an `/approve/` or `/renew/` page then requires a **second factor the agent never sees**:

- the **owner PIN** (4 to 64 characters, set with `printf %s "$PIN" | onegate approvals pin set` or `PUT /api/settings/owner-pin`; stored as a salted scrypt hash, compared timing-safe, replicated across a cluster), or the **admin token** (always accepted, and the only option when no PIN is set);
- **per-link lockout**: each wrong answer is counted on the link (replicated) and the link locks after **5** wrong answers, even against the right PIN. An attempt is reserved with one conditional `UPDATE` before the PIN is checked, so concurrent guesses cannot exceed the limit. A locked approval stays pending and can still be decided from the admin API or CLI.

The gateway prints a warning at startup when this is set. Residual risk: the agent never sees the PIN, but a compromised bot sits between OneGate and the owner and could try to talk the owner into sending it the PIN ("reply with your PIN to approve"). Owners should only ever type the PIN into the OneGate page. Prefer the default mode with a notify webhook that reaches the owner directly.

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
| Cluster secret (cluster members only) | sealed with the DB key in the node-local `settings` row `cluster.secret`; never sent after the join |
| Cluster join token (`ogj_`) | shown once; stored as a SHA-256 lookup id plus the token-derived payload key sealed with the DB key, erased on use or expiry; single use, 15 min default TTL |

For OAuth integrations you bring your own OAuth client. The client ID and secret you enter in the connect dialog are stored inside the integration credential, alongside the access and refresh tokens OneGate obtains with them. They get the same protection (and the same exposure) as any other credential. Integrations that mint short-lived tokens at request time (Google, GCP, MongoDB Atlas, Docker Hub, GitHub App) cache those tokens in the settings table, which lives in the same database.

Protect `ONEGATE_DATA` (and its backups) accordingly: it is equivalent to the credentials it holds.

## Network posture

- **Proxy port (8443):** reachable by agents only. Proxy auth is required before any tunneling happens, and failures are audited.
- **Admin port (8080):** token-protected, but do not expose it publicly. Use an SSH tunnel or a TLS-terminating reverse proxy with its own auth. The OAuth callback is protected by a single-use, 10-minute random state.
- The gateway dials vendors directly with a dedicated agent and ignores ambient proxy environment variables, so credentials cannot be siphoned through an injected upstream proxy.

## OneGate cluster

A cluster ([CLUSTER.md](CLUSTER.md)) widens the blast radius on purpose: every
member holds the same DB key and root CA key, so compromising any member is
compromising all of them. Harden every node like the first.

- **Cluster listener** (`ONEGATE_CLUSTER_LISTEN`, off by default): bind it to a
  tailnet address and firewall it to the other members. Requests are
  HMAC-authenticated with the cluster secret (60 s replay window plus a nonce
  cache) and responses are AES-256-GCM sealed and bound to the request, so the
  link does not need to be private, but there is no reason to expose it.
- **Join token**: grants the DB key, the CA key and the cluster secret to whoever
  redeems it first. It is single use and short-lived, and the join exchange is
  sealed under it, but move it out of band and pipe it with `--token-stdin`.
- **Admin token**: shared by the cluster (`admin_token_hash` replicates).
  `onegate admin reset-token` on any node rotates it everywhere.
- **Removing a node** (`cluster peers remove`) stops replication to it but does
  not revoke what it holds. If a node is compromised, treat the DB key, the CA
  and every credential as exposed.

## Operational guidance

- Default agents to `deny-unmatched` (the built-in default) and add narrow allows.
- One agent identity per workload. Shared tokens destroy both audit attribution and revocation granularity.
- Rotate the admin token (`onegate admin reset-token`) if it may have leaked, and rotate agent tokens on any suspicion (one click in the UI).
- Review the audit log for `deny` and `auth_failed` spikes. They are the earliest sign of a confused or compromised agent.
- Keep community integrations under review before dropping them in: an integration runs in-process and receives the credential for its hosts.

## Reporting

Found a vulnerability? Open a private security advisory on the GitHub repo (or contact the maintainer directly) rather than a public issue.
