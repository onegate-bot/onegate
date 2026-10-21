# OneGate cluster

A OneGate cluster is two or more OneGate instances that share one configuration
and all serve traffic at the same time (active/active). An agent token, rule,
connection or grant created on any node works on every node within seconds, and
an agent can be moved from one node to another by changing only its proxy URL.

Clustering is off by default. A node that never ran `cluster init` or
`cluster join` behaves exactly as before: no triggers, no extra writes, no
listener.

## What is shared and what stays on the node

| Shared (replicated) | Local (never leaves the node) |
|---|---|
| projects, agents (token hashes), credentials, rules, integration leases | audit log |
| connections (sealed `data`, `inactive_at`, `inactive_reason`) | `connections.auth_failures` (each node counts the 401s it saw) |
| connection grants, agent app/LLM config, agent notify webhooks | `llm_usage`, `llm_strategy_state` (the router's rotation state) |
| onboarding links, approvals (an approval link minted on one node can be decided on another) | owner-notification outbox |
| `settings`: only `admin_token_hash` (one admin token for the cluster) | every other setting: upstream access-token caches, and `cluster.*` (this node's id, the cluster secret, its advertise URL) |
| cluster membership (`cluster_peers`) | the cluster's own bookkeeping (changelog, row versions, cursors, conflicts, join tokens) |
| | in-memory caches and the on-disk leaf-certificate cache |

The settings list is an allow list: a setting added in a future release stays on
its node until someone decides it should be shared. The authoritative list is
`src/store/cluster-schema.ts`, and `test/cluster-schema.test.ts` fails if a table
or a column is added without being classified there.

Every node of a cluster holds the same two secrets, transferred by the join:

- the **DB key** (`db-secret.key`), so a credential sealed on one node opens on
  every node;
- the **root CA** (`rootCA.pem` + `rootCA.key`), so agents trust one CA and any
  node can terminate their TLS.

Sharing both is what makes failover need no agent-side reconfiguration beyond
the proxy URL.

## Consistency model

Eventually consistent, multi-master, last-writer-wins per row.

- **Capture.** On a member node, TEMP triggers on every shared table append each
  local change to `cluster_changelog` with a version `(ts, origin)`: the writing
  node's clock in milliseconds and its node id. Triggers catch every write path,
  including SQLite's own foreign-key cascades. A row's new ts is
  `max(now, previous ts + 1)`, so an edit always supersedes the version the
  editing node last saw, even if that version came from a peer whose clock runs
  ahead.
- **Transport.** Every node pulls from every peer (`GET /cluster/v1/changes`)
  every 2 s, with exponential backoff (to 60 s) for a peer that fails. A node
  serves only its own changes; nothing is relayed. Membership replicates, so the
  mesh stays full as nodes come and go.
- **Apply.** A remote change lands only if its version beats the stored version
  of that row (`cluster_row_meta`, which also keeps tombstones for deletes). A
  tie on ts is broken by comparing node ids, so every node picks the same winner
  whatever order it pulls in. Each page of changes, and the peer's cursor, is
  applied in one transaction.
- **Unique collisions.** Two nodes creating different rows with the same unique
  value (two agents named `bob`, created on two nodes before they synced)
  resolve the same way: the newer version survives and the node that notices
  writes a replicated tombstone for the loser. The loser is gone everywhere,
  including its token. Each resolution is logged and counted in
  `cluster status` (`Conflicts`). Avoid creating same-named objects on two nodes
  at once.
- **Ordering.** Changes from different nodes arrive in pull order, not causal
  order (a grant made on B can arrive before the connection it names, made on
  C). Apply therefore runs with foreign-key enforcement off: the parent arrives
  on a later pull, and every cascade was already captured on the node where it
  happened.

Propagation is normally within one poll interval (about 2 s) per hop; every
node pulls directly from the writer, so it is one hop.

### Clocks

Run NTP on every node. Versions use wall-clock time, so a node whose clock is
ahead by D wins every *concurrent* conflict within D. No edit is lost to an older
version because of skew (see the `max(now, previous + 1)` rule above); skew only
biases who wins a race. `cluster status` shows each peer's measured skew and
marks it with `!` above 2 s.

### Known races

- **OAuth refresh-token rotation.** A refresh writes the connection's `data`,
  which replicates. If two nodes refresh the same connection concurrently and
  the provider rotates refresh tokens, LWW keeps the newer row, and the other
  node's freshly issued refresh token may already have been invalidated by the
  provider. The node that lost simply refreshes again from the winning row on
  its next expiry; if the provider revoked the token family, the connection
  starts returning 401 and is benched (re-authorize it once, on any node).
  Access tokens themselves are cached per node and do not replicate.
- **Single-use links.** Onboarding links and approval decisions are single use
  per node immediately, and cluster-wide after replication. The same link
  redeemed on two nodes within the replication window can succeed on both.
- **OAuth connect flow.** The pending state of an in-progress OAuth connect is
  in the admin process's memory: finish the browser round trip on the node that
  started it.

## Transport and security

The cluster listener is a separate HTTP listener (`ONEGATE_CLUSTER_LISTEN`,
off by default), not the proxy port and not the admin port. Bind it to a
tailnet address and firewall it to the other nodes.

- **Requests** carry an HMAC-SHA256 over method, path and query, sender node id,
  timestamp, nonce and body hash, keyed from the cluster secret. Requests outside
  a 60 s window, or reusing a nonce, are rejected.
- **Responses** are sealed with AES-256-GCM under a key derived from the cluster
  secret and bound to the request nonce, so they can be neither read nor forged
  nor replayed by anyone on the path. The cluster secret never crosses the wire
  after the join.

A WireGuard/Tailscale tailnet is the expected transport, but security does not
depend on it: over plain HTTP an attacker on the path can see that nodes talk
(and the cursor numbers in request URLs) and can drop traffic, but cannot read
config, inject changes or replay old responses. HTTPS URLs also work.

### The join exchange

Joining is the one exchange that carries the crown jewels (the cluster secret,
the DB key and the CA key). It is protected by a **join token**:

- minted on an existing node with `onegate cluster join-token` (default TTL 15
  minutes, maximum 24 h), **single use**;
- the joining node sends only the token's SHA-256 lookup id in clear; its
  request and the response are sealed with keys derived from the token, so an
  observer without the token learns nothing, and a request that does not open
  under the token does not spend it;
- the serving node stores the lookup id plus the token-derived key sealed with
  the DB key (deriving the payload key requires token-equivalent material, so a
  bare hash is not enough), and erases that sealed key on use or expiry.

**Move the join token out of band** (a password manager, an SSH session), never
through a ticket, chat log or shell history. Prefer `--token-stdin`.

## Running a cluster

Configuration:

| Variable | Meaning |
|---|---|
| `ONEGATE_CLUSTER_LISTEN` | cluster listener, `port` or `host:port` (e.g. `100.64.0.10:9443`). Off when unset. |
| `ONEGATE_CLUSTER_ADVERTISE` | default for `--advertise`: the URL peers use to reach this node's listener |
| `ONEGATE_CLUSTER_RETENTION_DAYS` | changelog history kept after every peer has pulled it (default 7) |

### Runbook: two nodes

On **node A** (an existing, running gateway):

```sh
# 1. Upgrade, then restart with the cluster listener on the tailnet address.
ONEGATE_CLUSTER_LISTEN=100.64.0.10:9443 onegate start      # (or set it in the unit file)

# 2. Start the cluster. The advertise URL is how peers reach A's listener.
onegate cluster init --advertise http://100.64.0.10:9443

# 3. Mint a join token for B.
onegate cluster join-token --ttl 15m
```

On **node B** (a fresh host, OneGate installed, NOT started, empty data dir):

```sh
printf %s "$JOIN_TOKEN" | onegate cluster join http://100.64.0.10:9443 \
  --token-stdin --advertise http://100.64.0.11:9443
ONEGATE_CLUSTER_LISTEN=100.64.0.11:9443 onegate start
```

`join` refuses a node that already has agents, connections or rules, unless
`--replace-local-config` is given (which replaces all of them, loudly). A root
CA from an earlier `onegate init` on B is replaced by the cluster CA and B's leaf
cache is cleared. B's admin token becomes the cluster's (the one A uses). Do not
set `ONEGATE_DB_KEY` during the join; afterwards you may move the key from
`db-secret.key` into a secret manager.

Verify, on either node:

```sh
onegate cluster status          # both nodes listed, LAG 0, no ERROR, small SKEW
onegate agents add probe        # on B
onegate agents list             # on A, a few seconds later: probe is there
onegate agents rm <id>          # on A; gone from B shortly after
```

A third node joins the same way, through any member.

### Pointing agents at a second node

Every node accepts the same agent tokens and presents leaves from the same CA,
so failover is only a matter of where the agent sends traffic:

```sh
export HTTPS_PROXY=http://agent:<token>@<node-b>:8443
```

OneGate does not move traffic itself. Options, from simplest:

- **Agent-side**: change the proxy URL (or keep a fallback list in the agent's
  launcher) when a node is down.
- **DNS**: a name with both nodes' addresses, or one you repoint, with a short
  TTL.
- **VIP**: a floating address (keepalived, a cloud load balancer, a Tailscale
  service) in front of the proxy ports.

### Membership

```sh
onegate cluster peers                       # list
onegate cluster peers add <url>             # (re-)add a node by its cluster URL
onegate cluster peers remove <node-id>      # every node stops pulling from it
onegate cluster leave                       # on the node itself
```

`leave` tells every reachable peer to drop the node, then erases the node's
cluster state. Its config stays, and it runs standalone from then on. If a peer
was unreachable, run `cluster peers remove <node-id>` on a remaining node.

The same operations are on the admin API: `GET /api/cluster`,
`POST /api/cluster/init` `{advertiseUrl}`, `POST /api/cluster/join-tokens`
`{ttl}`, `GET|POST /api/cluster/peers` `{url}`,
`DELETE /api/cluster/peers/:nodeId`, `POST /api/cluster/leave`. Join is CLI only:
it runs on a stopped node that has no admin token yet and writes key files.

## Failure modes

- **A peer is down.** The others keep serving and accepting writes. They retry
  the dead peer with backoff; `cluster status` shows its error and lag. When it
  returns, it pulls what it missed and the others pull what it wrote.
- **Split brain.** Both sides keep accepting writes. On heal they exchange
  changes and converge by LWW; unique collisions resolve as described above.
- **A node is lost for good.** Changes it wrote that no peer had pulled yet are
  lost with it (nothing is relayed). Remove it with `cluster peers remove`.
- **A peer's changelog was compacted past a node's cursor** (a node away longer
  than the retention, after every other peer pulled): the pull fails with
  `cursor_compacted`. Re-join that node (leave, then join with
  `--replace-local-config`).
- **A node's database was restored from an older copy.** Its sequence went
  backwards; peers get `cursor_ahead` from it. Re-join it.
- **A join response was lost in transit.** The token is spent and the joiner
  was already added to the peer list: mint a new token, and remove the stray
  peer if the joiner gets a new id.

## Upgrade and rollback

The upgrade is additive: new tables are created on boot (`IF NOT EXISTS`), no
existing table or column changes, and the capture triggers are TEMP triggers
that exist only on a member node's own connections. An older build can still
open and write a clustered database (rollback); its writes are simply not
captured, so stop that node from accepting writes or re-join it after rolling
forward. Mixed versions in one cluster are tolerated for added columns (a column
a peer does not know is ignored, one it lacks keeps its local default), but
upgrade all nodes promptly.

## Compaction

A changelog entry is deleted once every current peer has pulled past it AND it
is older than `ONEGATE_CLUSTER_RETENTION_DAYS` (default 7), checked every ten
minutes. A peer that never pulls holds everything back, so history is only lost
for nodes that were removed.
