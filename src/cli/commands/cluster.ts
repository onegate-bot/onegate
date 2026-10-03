/**
 * OneGate cluster commands.
 *
 *   onegate cluster status
 *   onegate cluster init --advertise <url>
 *   onegate cluster join-token [--ttl 15m]
 *   onegate cluster peers [list] | add <url> | remove <node-id>
 *   onegate cluster leave
 *   onegate cluster join <peer-url> (--token <ogj_> | --token-stdin) --advertise <url> [--replace-local-config]
 *
 * Everything except `join` talks to the running gateway over the admin API.
 * `join` is local: it runs on a fresh, stopped node, before it has an admin
 * token, and writes the cluster's DB key and root CA into the data dir.
 */

import { parseArgs } from "node:util";
import { emit, table } from "../output.js";
import { readSecretFromStdin } from "../secret-input.js";
import type { CliContext } from "../context.js";
import { joinCluster, type JoinResult } from "../../cluster/join.js";

interface PeerStatus {
  nodeId: string;
  url: string;
  self: boolean;
  cursor: number | null;
  remoteHead: number | null;
  lag: number | null;
  lastOkAt: string | null;
  lastError: string | null;
  clockSkewMs: number | null;
}

interface Status {
  enabled: boolean;
  nodeId: string | null;
  clusterId: string | null;
  advertiseUrl: string | null;
  member: boolean;
  head: number;
  changelogRows: number;
  conflicts: number;
  listening: string | null;
  peers: PeerStatus[];
}

/** Clock skew above this is called out: LWW orders writes by wall clock. */
const SKEW_WARN_MS = 2_000;

function printStatus(s: Status): void {
  if (!s.enabled) {
    console.log(`Not in a cluster${s.nodeId ? ` (node id ${s.nodeId})` : ""}.`);
    console.log("Start one with `onegate cluster init --advertise <url>`, or join one with `onegate cluster join`.");
    return;
  }
  console.log(`Node:      ${s.nodeId}${s.member ? "" : "  (REMOVED from the cluster by a peer)"}`);
  console.log(`Cluster:   ${s.clusterId}`);
  console.log(`Advertise: ${s.advertiseUrl}`);
  console.log(`Listener:  ${s.listening ?? "off (set ONEGATE_CLUSTER_LISTEN; peers cannot pull from this node)"}`);
  console.log(`Changelog: head ${s.head}, ${s.changelogRows} retained`);
  console.log(`Conflicts: ${s.conflicts}`);
  console.log("");
  console.log(
    table(
      s.peers.map((p) => ({
        ...p,
        node: p.self ? `${p.nodeId} (self)` : p.nodeId,
        lagCol: p.self ? "-" : p.lag ?? "?",
        skew: p.clockSkewMs === null ? null : `${p.clockSkewMs}ms${Math.abs(p.clockSkewMs) > SKEW_WARN_MS ? " !" : ""}`,
      })) as unknown as Array<Record<string, unknown>>,
      [
        ["NODE", "node"],
        ["URL", "url"],
        ["LAG", "lagCol"],
        ["LAST PULL", "lastOkAt"],
        ["SKEW", "skew"],
        ["ERROR", "lastError"],
      ],
    ),
  );
}

async function status(ctx: CliContext): Promise<void> {
  const s = (await ctx.client().get("/api/cluster")) as Status;
  emit(s, () => printStatus(s));
}

async function init(ctx: CliContext, args: string[]): Promise<void> {
  const { values } = parseArgs({ args, options: { advertise: { type: "string" } } });
  const advertiseUrl = values.advertise ?? process.env.ONEGATE_CLUSTER_ADVERTISE;
  if (!advertiseUrl) {
    throw new Error("usage: onegate cluster init --advertise <url>   (the URL peers use to reach this node's cluster listener)");
  }
  const s = (await ctx.client().post("/api/cluster/init", { advertiseUrl })) as Status;
  emit(s, () => {
    console.log(`Cluster ${s.clusterId} initialized. This node is ${s.nodeId}.`);
    if (!s.listening) console.log("Note: the cluster listener is off. Set ONEGATE_CLUSTER_LISTEN and restart, or peers cannot pull from this node.");
    console.log("Next: `onegate cluster join-token` here, then `onegate cluster join` on the new node.");
  });
}

async function joinToken(ctx: CliContext, args: string[]): Promise<void> {
  const { values } = parseArgs({ args, options: { ttl: { type: "string" } } });
  const body = values.ttl ? { ttl: values.ttl } : {};
  const r = (await ctx.client().post("/api/cluster/join-tokens", body)) as { token: string; expiresAt: string; peerUrl: string | null };
  emit(r, () => {
    console.log(`Join token (single use, expires ${r.expiresAt}):\n\n  ${r.token}\n`);
    console.log("It grants the cluster's DB key and root CA. Move it out of band (not in a ticket or chat log).");
    console.log("On the new node, with OneGate stopped:");
    console.log(`  printf %s '<token>' | onegate cluster join ${r.peerUrl ?? "<this-node-cluster-url>"} --token-stdin --advertise <new-node-cluster-url>`);
  });
}

async function peers(ctx: CliContext, args: string[]): Promise<void> {
  const [sub, arg] = args;
  if (!sub || sub === "list" || sub === "ls") {
    const list = (await ctx.client().get("/api/cluster/peers")) as PeerStatus[];
    emit(list, () => {
      if (!list.length) {
        console.log("no peers (not in a cluster).");
        return;
      }
      console.log(
        table(list as unknown as Array<Record<string, unknown>>, [
          ["NODE", "nodeId"],
          ["URL", "url"],
          ["SELF", "self"],
          ["LAG", "lag"],
        ]),
      );
    });
    return;
  }
  if (sub === "add") {
    if (!arg) throw new Error("usage: onegate cluster peers add <url>");
    const peer = (await ctx.client().post("/api/cluster/peers", { url: arg })) as { nodeId: string; url: string };
    emit(peer, () => console.log(`Peer ${peer.nodeId} at ${peer.url} added.`));
    return;
  }
  if (sub === "remove" || sub === "rm") {
    if (!arg) throw new Error("usage: onegate cluster peers remove <node-id>");
    await ctx.client().del(`/api/cluster/peers/${encodeURIComponent(arg)}`);
    emit({ removed: arg }, () => console.log(`Peer ${arg} removed. Every node stops pulling from it.`));
    return;
  }
  throw new Error(`unknown cluster peers command "${sub}". Try: list, add, remove`);
}

async function leave(ctx: CliContext): Promise<void> {
  const r = (await ctx.client().post("/api/cluster/leave", {})) as { announced: string[]; unreachable: string[] };
  emit(r, () => {
    console.log("This node left the cluster. Its config stays as is, and it now runs standalone.");
    if (r.unreachable.length) {
      console.log(`Could not tell: ${r.unreachable.join(", ")}. Run \`onegate cluster peers remove <this-node-id>\` on a remaining node.`);
    }
  });
}

export async function clusterCommand(ctx: CliContext, sub: string, args: string[]): Promise<void> {
  if (!sub || sub === "status") return status(ctx);
  if (sub === "init") return init(ctx, args);
  if (sub === "join-token") return joinToken(ctx, args);
  if (sub === "peers") return peers(ctx, args);
  if (sub === "leave") return leave(ctx);
  throw new Error(`unknown cluster command "${sub}". Try: status, init, join-token, join, peers, leave`);
}

/**
 * `onegate cluster join`. Takes raw argv (not the global-flag-stripped one),
 * because here --token is the JOIN token, not the admin token.
 */
export async function clusterJoinCommand(
  args: string[],
  dataDir: string,
  join: (opts: Parameters<typeof joinCluster>[0]) => Promise<JoinResult> = joinCluster,
): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      token: { type: "string" },
      "token-stdin": { type: "boolean" },
      advertise: { type: "string" },
      "replace-local-config": { type: "boolean" },
      json: { type: "boolean" },
    },
  });
  const peerUrl = positionals[0];
  const usage =
    "usage: onegate cluster join <peer-cluster-url> (--token <ogj_...> | --token-stdin) --advertise <this-node-cluster-url> [--replace-local-config]";
  if (!peerUrl) throw new Error(usage);
  const token = values["token-stdin"] ? await readSecretFromStdin() : values.token ?? process.env.ONEGATE_CLUSTER_JOIN_TOKEN;
  if (!token) throw new Error(usage);
  const advertiseUrl = values.advertise ?? process.env.ONEGATE_CLUSTER_ADVERTISE;
  if (!advertiseUrl) throw new Error(usage);
  if (values["replace-local-config"]) {
    console.error("WARNING: --replace-local-config: every agent, connection, rule and grant on THIS node will be replaced by the cluster's.");
  }
  const r = await join({ dataDir, peerUrl, token: token.trim(), advertiseUrl, replaceLocalConfig: values["replace-local-config"] });
  emit(r, () => {
    console.log(`Joined cluster ${r.clusterId} as ${r.nodeId} (via ${r.serverNodeId}, ${r.peers} members).`);
    if (r.replacedCa) console.log("This node's previous root CA was replaced by the cluster CA; its leaf cache was cleared.");
    if (r.replacedConfig) console.log("This node's previous config was replaced by the cluster's.");
    console.log("The admin token is now the cluster's (the one issued on the first node).");
    console.log("Next: start OneGate with ONEGATE_CLUSTER_LISTEN set, then `onegate cluster status`.");
  });
}
