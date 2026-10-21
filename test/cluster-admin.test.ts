/**
 * `onegate cluster ...` end to end: the CLI talks to a real admin server whose
 * cluster runtime is a real node, and `cluster join` runs locally against a
 * temp data dir. process.exit is trapped so a failing path cannot take down the
 * vitest worker (same pattern as cli-core-coverage.test.ts).
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import http from "node:http";
import { join } from "node:path";
import { createAdminApp, ensureAdminToken } from "../src/admin/api.js";
import { Registry } from "../src/integrations/types.js";
import { setJsonMode } from "../src/cli/output.js";
import { main } from "../src/cli.js";
import { clusterJoinCommand } from "../src/cli/commands/cluster.js";
import { Store } from "../src/store/db.js";
import { ClusterState } from "../src/cluster/state.js";
import { cleanupDirs, joinNewNode, startFirstNode, startNode, stopAll, syncAll, tempDir, type TestNode } from "./cluster-harness.js";

let a: TestNode;
let b: TestNode;
let other: TestNode;
let admin: http.Server;
let logs: string[] = [];
let errs: string[] = [];
let exitCode: number | null = null;
const spies: Array<{ mockRestore: () => void }> = [];

async function run(...argv: string[]): Promise<{ out: string; err: string; exit: number | null }> {
  logs = [];
  errs = [];
  exitCode = null;
  setJsonMode(false);
  try {
    await main(argv);
  } catch (e) {
    if ((e as Error).message !== "__exit__") throw e;
  }
  return { out: logs.join("\n"), err: errs.join("\n"), exit: exitCode };
}

beforeAll(async () => {
  a = await startNode();
  const token = ensureAdminToken(a.store)!;
  admin = http.createServer(createAdminApp({ store: a.store, registry: new Registry(), ca: { rootPem: "x" } as never, version: "test", cluster: a.runtime }));
  await new Promise<void>((r) => admin.listen(0, "127.0.0.1", r));
  process.env.ONEGATE_ADMIN_URL = `http://127.0.0.1:${(admin.address() as { port: number }).port}`;
  process.env.ONEGATE_ADMIN_TOKEN = token;
  spies.push(vi.spyOn(console, "log").mockImplementation((...x: unknown[]) => void logs.push(x.join(" "))));
  spies.push(vi.spyOn(console, "error").mockImplementation((...x: unknown[]) => void errs.push(x.join(" "))));
  spies.push(vi.spyOn(console, "warn").mockImplementation(() => {}));
  spies.push(
    vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      exitCode = code ?? 0;
      throw new Error("__exit__");
    }) as never),
  );
});

afterAll(async () => {
  for (const s of spies) s.mockRestore();
  admin.close();
  await stopAll([a, b, other].filter(Boolean));
  delete process.env.ONEGATE_ADMIN_URL;
  delete process.env.ONEGATE_ADMIN_TOKEN;
  delete process.env.ONEGATE_DATA;
  cleanupDirs();
});

describe("onegate cluster (admin API)", () => {
  it("status before init says the node is standalone", async () => {
    expect((await run("cluster", "status")).out).toMatch(/Not in a cluster/);
    const j = await run("cluster", "--json");
    expect(JSON.parse(j.out)).toMatchObject({ enabled: false, peers: [] });
    expect((await run("cluster", "peers")).out).toMatch(/no peers/);
  });

  it("init needs an advertise URL, rejects a bad one, and refuses to run twice", async () => {
    expect((await run("cluster", "init")).err).toMatch(/--advertise/);
    expect((await run("cluster", "init", "--advertise", "ftp://nope")).err).toMatch(/invalid_url/);
    const ok = await run("cluster", "init", "--advertise", a.url);
    expect(ok.exit).toBeNull();
    expect(ok.out).toMatch(/initialized/);
    a.nodeId = a.runtime.state.peekNodeId()!;
    expect((await run("cluster", "init", "--advertise", a.url)).err).toMatch(/already_in_cluster/);
  });

  it("join-token mints a token and validates --ttl", async () => {
    const r = await run("cluster", "join-token", "--ttl", "15m");
    expect(r.out).toMatch(/ogj_[A-Za-z0-9_-]{43}/);
    expect(r.out).toContain(a.url);
    expect((await run("cluster", "join-token", "--ttl", "whenever")).err).toMatch(/invalid_ttl/);
    expect((await run("cluster", "join-token", "--ttl", "5s")).err).toMatch(/invalid_ttl/);
    const j = await run("cluster", "join-token", "--json");
    expect(JSON.parse(j.out).token).toMatch(/^ogj_/);
  });

  it("peers: list, add (and its failure modes), status table", async () => {
    b = await joinNewNode(a);
    await syncAll([a, b]);
    const list = JSON.parse((await run("cluster", "peers", "list", "--json")).out);
    expect(list.map((p: { nodeId: string }) => p.nodeId).sort()).toEqual([a.nodeId, b.nodeId].sort());
    expect((await run("cluster", "peers")).out).toContain(b.url);
    expect((await run("cluster", "peers", "add", b.url)).out).toContain(`Peer ${b.nodeId}`);
    expect((await run("cluster", "peers", "add", "http://127.0.0.1:1")).err).toMatch(/peer_unreachable|cannot reach|unreachable/);
    other = await startFirstNode(); // a different cluster with its own secret
    expect((await run("cluster", "peers", "add", other.url)).err).toMatch(/different_cluster/);
    expect((await run("cluster", "peers", "add")).err).toMatch(/usage/);
    const st = await run("cluster", "status");
    expect(st.out).toContain(`Node:      ${a.nodeId}`);
    expect(st.out).toMatch(/LAST PULL/);
    expect(st.out).toContain(b.url);
  });

  it("peers remove: not self, not unknown", async () => {
    expect((await run("cluster", "peers", "remove", a.nodeId)).err).toMatch(/cannot_remove_self/);
    expect((await run("cluster", "peers", "rm", "ogn_unknown00")).err).toMatch(/not_found/);
    expect((await run("cluster", "peers", "remove")).err).toMatch(/usage/);
    expect((await run("cluster", "peers", "dance")).err).toMatch(/unknown cluster peers command/);
    expect((await run("cluster", "dance")).err).toMatch(/unknown cluster command/);
  });

  it("cluster join runs locally: --token here is the join token, not the admin token", async () => {
    expect((await run("cluster", "join")).err).toMatch(/usage/);
    expect((await run("cluster", "join", b.url)).err).toMatch(/usage/);
    expect((await run("cluster", "join", b.url, "--token", "ogj_x")).err).toMatch(/usage/); // no --advertise
    const dir = tempDir("clijoin");
    process.env.ONEGATE_DATA = dir;
    const token = b.runtime.state.mintJoinToken().token;
    const r = await run("cluster", "join", b.url, "--token", token, "--advertise", "http://127.0.0.1:1", "--json");
    expect(r.exit).toBeNull();
    const out = JSON.parse(r.out);
    expect(out.clusterId).toBe(a.runtime.state.clusterId());
    const joined = new Store(join(dir, "onegate.db"));
    expect(new ClusterState(joined).isEnabled()).toBe(true);
    joined.close();
    // Human output and the loud --replace-local-config warning, with the join stubbed.
    logs = [];
    errs = [];
    setJsonMode(false);
    await clusterJoinCommand(["http://x", "--token", "ogj_t", "--advertise", "http://y", "--replace-local-config"], dir, async (o) => {
      expect(o.replaceLocalConfig).toBe(true);
      return { nodeId: "ogn_n", clusterId: "ogc_c", serverNodeId: "ogn_s", peers: 3, replacedCa: true, replacedConfig: true };
    });
    expect(errs.join("\n")).toMatch(/WARNING/);
    expect(logs.join("\n")).toMatch(/previous root CA was replaced/);
  });

  it("leave announces the departure to the peers, then the node is standalone", async () => {
    // Drop the third (never started) member so the announcement set is just B.
    a.runtime.state.removePeer(JSON.parse((await run("cluster", "peers", "--json")).out).find((p: { nodeId: string; self: boolean }) => !p.self && p.nodeId !== b.nodeId)?.nodeId ?? "none");
    const r = await run("cluster", "leave", "--json");
    expect(JSON.parse(r.out).announced).toEqual([b.nodeId]);
    expect(b.runtime.state.listPeers().map((p) => p.nodeId)).not.toContain(a.nodeId);
    expect((await run("cluster", "status")).out).toMatch(/Not in a cluster/);
    expect((await run("cluster", "leave")).err).toMatch(/cluster_not_initialized/);
  });
});
