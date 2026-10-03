/**
 * `onegate cluster join`: turns a new (stopped) node into a cluster member.
 *
 * Runs against the data dir directly, before the node is first started (there
 * is no admin token yet, and the files it writes are read at boot). It:
 *  1. refuses a node that already holds shared config, unless the operator
 *     passes --replace-local-config;
 *  2. redeems the join token at a peer, receiving the cluster secret, the DB
 *     key, the root CA and a snapshot, all sealed under the token;
 *  3. writes the DB key and the CA with the same file modes `init` uses (and
 *     drops the leaf cache, whose leaves were signed by any previous CA);
 *  4. loads the snapshot and marks the node a member. The peer already added
 *     this node to cluster_peers, which replicates, so every node starts
 *     pulling from it within a poll interval.
 */

import { chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { caExists, caPaths } from "../ca.js";
import { DEFAULT_INTEGRATION_LEASES, Store } from "../store/db.js";
import { isJoinTokenShaped } from "./crypto.js";
import { requestJoin } from "./client.js";
import { ClusterState, validateClusterUrl } from "./state.js";

export interface JoinOptions {
  dataDir: string;
  peerUrl: string;
  token: string;
  /** URL peers will use to reach THIS node's cluster listener. */
  advertiseUrl: string;
  replaceLocalConfig?: boolean;
}

export interface JoinResult {
  nodeId: string;
  clusterId: string;
  serverNodeId: string;
  peers: number;
  /** A root CA existed on this node and was replaced by the cluster's. */
  replacedCa: boolean;
  /** Shared config existed and was replaced (--replace-local-config). */
  replacedConfig: boolean;
}

export async function joinCluster(opts: JoinOptions): Promise<JoinResult> {
  if (process.env.ONEGATE_DB_KEY?.trim()) {
    // The join installs the cluster's DB key as the key file. An env key would
    // shadow it and every replicated secret would fail to open.
    throw new Error(
      "ONEGATE_DB_KEY is set. Unset it for the join; afterwards you may move the key from db-secret.key into your secret manager.",
    );
  }
  if (!isJoinTokenShaped(opts.token)) throw new Error("that is not a join token (expected ogj_...)");
  const peerUrl = validateClusterUrl(opts.peerUrl);
  const advertiseUrl = validateClusterUrl(opts.advertiseUrl);
  const dbPath = join(opts.dataDir, "onegate.db");

  let nodeId = `ogn_${randomBytes(8).toString("hex")}`;
  let replacedConfig = false;
  if (existsSync(dbPath)) {
    const store = new Store(dbPath);
    try {
      const st = new ClusterState(store);
      if (st.isEnabled()) {
        throw new Error(`this node is already in cluster ${st.clusterId()}. Run \`onegate cluster leave\` first.`);
      }
      if (st.hasLocalConfig(DEFAULT_INTEGRATION_LEASES)) {
        if (!opts.replaceLocalConfig) {
          throw new Error(
            "this node already has agents/connections/rules. Joining replaces ALL of them with the cluster's. " +
              "Re-run with --replace-local-config if that is what you want.",
          );
        }
        replacedConfig = true;
      }
      nodeId = st.nodeId();
    } finally {
      store.close();
    }
  }
  const replacedCa = caExists(opts.dataDir);

  const payload = await requestJoin({ url: peerUrl, token: opts.token, nodeId, advertiseUrl });
  if (payload.v !== 1) throw new Error(`unsupported join payload version ${String(payload.v)}`);
  if (Buffer.from(payload.dbKey, "base64").length !== 32) throw new Error("join payload carries a malformed DB key");

  mkdirSync(opts.dataDir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(opts.dataDir, 0o700);
  } catch {
    // not ours to tighten
  }
  const keyPath = join(opts.dataDir, "db-secret.key");
  writeFileSync(keyPath, payload.dbKey, { mode: 0o600 });
  chmodSync(keyPath, 0o600);
  const p = caPaths(opts.dataDir);
  mkdirSync(dirname(p.certPath), { recursive: true });
  mkdirSync(dirname(p.keyPath), { recursive: true });
  writeFileSync(p.certPath, payload.caCert);
  writeFileSync(p.keyPath, payload.caKey, { mode: 0o600 });
  chmodSync(p.keyPath, 0o600);
  // Cached leaves were signed by the previous CA; agents trust the cluster CA.
  rmSync(p.certsDir, { recursive: true, force: true });

  const store = new Store(dbPath);
  try {
    new ClusterState(store).loadJoin({
      clusterId: payload.clusterId,
      clusterSecret: payload.clusterSecret,
      snapshot: payload.snapshot,
      nodeId,
      advertiseUrl,
    });
  } finally {
    store.close();
  }
  return {
    nodeId,
    clusterId: payload.clusterId,
    serverNodeId: payload.serverNodeId,
    peers: payload.snapshot.tables.cluster_peers?.length ?? 0,
    replacedCa,
    replacedConfig,
  };
}
