/**
 * CLI coverage for the commands no other suite drives end to end:
 *
 *  - `onegate approvals list|approve|reject` (held require_approval requests);
 *  - `onegate connections activate|deactivate|set-instance-origin`, the grant
 *    allow-rule messages, and the INACTIVE / instance columns of `list`;
 *  - `onegate agents llm get` with per-vendor strategies;
 *  - `onegate cluster` human output against an injected runtime (listener off,
 *    peers remove, leave with unreachable peers).
 *
 * Each test drives main() against a real admin app (test/admin-harness.ts) and
 * checks both the printed output and the state the command left in the store.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { setJsonMode } from "../src/cli/output.js";
import { main } from "../src/cli.js";
import { startAdmin, type AdminHarness } from "./admin-harness.js";

let h: AdminHarness;
let logs: string[] = [];
let errs: string[] = [];
let exitCode: number | null = null;
const spies: Array<{ mockRestore(): void }> = [];

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

function pointCliAt(target: AdminHarness): void {
  process.env.ONEGATE_ADMIN_URL = target.base;
  process.env.ONEGATE_ADMIN_TOKEN = target.token;
}

beforeAll(async () => {
  h = await startAdmin({ publicBaseUrl: "https://gate.example" });
  pointCliAt(h);
  spies.push(
    vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => void logs.push(a.join(" "))),
    vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => void errs.push(a.join(" "))),
    vi.spyOn(process.stdout, "write").mockImplementation(((chunk: unknown) => {
      logs.push(String(chunk));
      return true;
    }) as never),
    vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      exitCode = code ?? 0;
      throw new Error("__exit__");
    }) as never),
  );
});

afterAll(async () => {
  for (const s of spies) s.mockRestore();
  delete process.env.ONEGATE_ADMIN_URL;
  delete process.env.ONEGATE_ADMIN_TOKEN;
  await h.close();
});

describe("onegate approvals", () => {
  let agentId: string;
  let otherId: string;

  function hold(agent: string, path: string) {
    const rule = h.store.createRule({
      scope: "agent",
      subjectId: agent,
      integrationId: "github",
      methods: ["POST"],
      pathGlob: "/**",
      effect: "deny",
      action: "require_approval",
    });
    return h.store.createApproval({ agentId: agent, integrationId: "github", ruleId: rule.id, method: "POST", path });
  }

  beforeAll(() => {
    agentId = h.store.createAgent("cli-approver").agent.id;
    otherId = h.store.createAgent("cli-other").agent.id;
  });

  it("list on an empty store says so", async () => {
    const { out, exit } = await run("approvals", "list");
    expect(exit).toBeNull();
    expect(out).toBe("no approvals.");
  });

  it("list renders a table, and --agent narrows it", async () => {
    const mine = hold(agentId, "/repos/acme/app/merges");
    const theirs = hold(otherId, "/repos/acme/other/merges");
    const all = await run("approvals", "ls");
    expect(all.out).toMatch(/ID\s+AGENT\s+INTEGRATION\s+METHOD\s+HOST\s+PATH\s+STATUS\s+EXPIRES/);
    expect(all.out).toContain(mine.id);
    expect(all.out).toContain(theirs.id);
    // The decision token is never printed.
    expect(all.out).not.toContain(mine.token);

    const narrowed = await run("--json", "approvals", "list", "--agent", otherId);
    const rows = JSON.parse(narrowed.out) as Array<{ id: string; status: string }>;
    expect(rows.map((r) => r.id)).toEqual([theirs.id]);
    expect(rows[0].status).toBe("pending");
  });

  it("approve and reject transition the row and print the new status", async () => {
    const a = hold(agentId, "/a");
    const ok = await run("approvals", "approve", a.id);
    expect(ok.out).toBe(`Approval ${a.id}: approved.`);
    expect(h.store.getApproval(a.id)?.status).toBe("approved");

    const b = hold(agentId, "/b");
    const no = await run("--json", "approvals", "reject", b.id);
    expect(JSON.parse(no.out)).toMatchObject({ id: b.id, status: "rejected" });
    expect(h.store.getApproval(b.id)?.status).toBe("rejected");
  });

  it("deciding an already-decided approval fails with the API's 409, leaving it unchanged", async () => {
    const a = hold(agentId, "/c");
    await run("approvals", "reject", a.id);
    const again = await run("approvals", "approve", a.id);
    expect(again.exit).toBe(1);
    expect(again.err).toContain("API error 409: approval_not_pending");
    expect(h.store.getApproval(a.id)?.status).toBe("rejected");
  });

  it("an unknown id is a clean 404 error", async () => {
    const r = await run("approvals", "approve", "apr_nope");
    expect(r.exit).toBe(1);
    expect(r.err).toContain("API error 404: unknown_approval");
  });

  it("approve/reject without an id print usage; an unknown verb lists the valid ones", async () => {
    for (const verb of ["approve", "reject"]) {
      const r = await run("approvals", verb);
      expect(r.exit).toBe(1);
      expect(r.err).toContain(`usage: onegate approvals ${verb} <id>`);
    }
    const bad = await run("approvals", "snooze");
    expect(bad.exit).toBe(1);
    expect(bad.err).toContain('unknown approvals command "snooze". Try: list, approve, reject');
  });
});

describe("onegate connections lifecycle", () => {
  let connId: string;
  let agentId: string;

  beforeAll(async () => {
    agentId = h.store.createAgent("cli-conn-agent").agent.id;
    const r = await run(
      "--json",
      "connections",
      "add",
      "--kind",
      "app",
      "--integration",
      "jfrog-artifactory",
      "--name",
      "jf-cli",
      "--data",
      "token=eyJcli",
      "--data",
      "host=jf.acme.example",
    );
    connId = (JSON.parse(r.out) as { id: string }).id;
  });

  it("deactivate benches the connection; list shows it INACTIVE with the reason", async () => {
    const r = await run("connections", "deactivate", connId, "--reason", "key rotation");
    expect(r.out).toBe(`"jf-cli" (${connId}) is inactive and will not be selected.`);
    expect(h.store.getConnection(connId)?.inactiveAt).toBeTruthy();
    const list = await run("connections", "list");
    expect(list.out).toMatch(/INACTIVE since \d{4}-\d{2}-\d{2} \d{2}:\d{2}: .*key rotation/);
  });

  it("deactivate without a reason still works", async () => {
    const r = await run("--json", "connections", "deactivate", connId);
    expect(JSON.parse(r.out).id).toBe(connId);
  });

  it("activate puts it back in rotation", async () => {
    const r = await run("connections", "activate", connId);
    expect(r.out).toBe(`"jf-cli" (${connId}) is active again and back in rotation.`);
    expect(h.store.getConnection(connId)?.inactiveAt ?? null).toBeNull();
  });

  it("activate/deactivate without an id print usage", async () => {
    expect((await run("connections", "activate")).err).toContain("usage: onegate connections activate <id>");
    expect((await run("connections", "deactivate")).err).toContain(
      "usage: onegate connections deactivate <id> [--reason <text>]",
    );
  });

  it("set-instance-origin pins the connection, shows in list, and --clear releases it", async () => {
    const set = await run("connections", "set-instance-origin", connId, "https://jf.acme.example");
    expect(set.out).toBe(`"jf-cli" (${connId}) now targets https://jf.acme.example.`);
    expect(h.store.getConnection(connId)?.instanceOrigin).toBe("https://jf.acme.example");
    expect((await run("connections", "list")).out).toContain("https://jf.acme.example");

    const clear = await run("connections", "set-instance-origin", connId, "--clear");
    expect(clear.out).toBe(`"jf-cli" (${connId}) no longer targets a self-managed instance.`);
    expect(h.store.getConnection(connId)?.instanceOrigin ?? null).toBeNull();
  });

  it("set-instance-origin surfaces server-side refusals and needs an origin or --clear", async () => {
    const reserved = await run("connections", "set-instance-origin", connId, "https://api.github.com");
    expect(reserved.exit).toBe(1);
    expect(reserved.err).toContain("instance_origin_reserved_host");
    const usage = await run("connections", "set-instance-origin", connId);
    expect(usage.exit).toBe(1);
    expect(usage.err).toContain("usage: onegate connections set-instance-origin <id>");
  });

  it("grants on an ungranted connection explains it is unusable", async () => {
    const r = await run("connections", "grants", "--id", connId);
    expect(r.out).toBe(`connection ${connId} is granted to no agent or project (default-deny: unusable).`);
  });

  it("grant reports the synthesized allow rule, and a re-grant reports the existing one", async () => {
    const first = await run("connections", "grant", "--id", connId, "--agent", agentId);
    const created = first.out.match(/Created allow rule (\S+) so this grant is usable on its own\./);
    expect(created).not.toBeNull();
    expect(h.store.getRule(created![1])?.effect).toBe("allow");
    const again = await run("connections", "grant", "--id", connId, "--agent", agentId);
    expect(again.out).toContain(`Existing rule ${created![1]} already covers this integration (left unchanged).`);
  });

});

describe("onegate agents llm get with per-vendor strategies", () => {
  it("renders the per-vendor overrides", async () => {
    const agentId = h.store.createAgent("cli-llm-vs").agent.id;
    const a = h.store.createConnection({ kind: "llm", vendor: "openai", name: "oa", data: { apiKey: "sk-1" } });
    const set = await run(
      "agents",
      "llm",
      "set",
      agentId,
      "--connections",
      a.id,
      "--vendor-strategy",
      "openai=round-robin",
    );
    expect(set.out).toContain("per-vendor=[openai=round-robin]");
    const got = await run("agents", "llm", "get", agentId);
    expect(got.out).toContain("per-vendor:  openai=round-robin");
    expect(got.out).toContain(`connections: ${a.id}`);
  });

  it("refuses malformed --vendor-strategy values before calling the API", async () => {
    const agentId = h.store.createAgent("cli-llm-bad").agent.id;
    for (const [value, msg] of [
      ["openai", 'must be "vendor=strategy"'],
      [" =fallback", "missing a vendor name"],
      ["openai=random", 'must be "fallback" or "round-robin"'],
    ]) {
      const r = await run("agents", "llm", "set", agentId, "--vendor-strategy", value);
      expect(r.exit).toBe(1);
      expect(r.err).toContain(msg);
    }
    expect(h.store.getAgentLlmConfig(agentId)).toBeNull();
  });

  it("an unknown llm verb names the valid ones", async () => {
    const r = await run("agents", "llm", "reset", "x");
    expect(r.err).toContain('unknown "agents llm" command "reset". Try: get, set, clear');
  });
});

describe("misc command edges", () => {
  it("projects add prints the created project", async () => {
    const r = await run("projects", "add", "cli-proj");
    expect(r.out).toMatch(/^Project "cli-proj" created \(\S+\)\.$/);
    expect(h.store.listProjects().some((p) => p.name === "cli-proj")).toBe(true);
  });

  it("rules add rejects an unknown --action locally, creating nothing", async () => {
    const agentId = h.store.createAgent("cli-rule-action").agent.id;
    const before = h.store.listRules().length;
    const r = await run(
      "rules",
      "add",
      "--scope",
      "agent",
      "--subject",
      agentId,
      "--integration",
      "github",
      "--effect",
      "deny",
      "--action",
      "require_aproval",
    );
    expect(r.exit).toBe(1);
    expect(r.err).toContain('invalid --action "require_aproval" (only "require_approval" is supported)');
    expect(h.store.listRules().length).toBe(before);
  });

  it("rules add with --action require_approval prints the action, not the effect", async () => {
    const agentId = h.store.createAgent("cli-rule-gate").agent.id;
    const r = await run(
      "rules",
      "add",
      "--scope",
      "agent",
      "--subject",
      agentId,
      "--integration",
      "github",
      "--effect",
      "deny",
      "--action",
      "require_approval",
    );
    expect(r.out).toMatch(/^Rule \S+: require_approval agent:/);
  });
});

describe("onegate cluster human output (injected runtime)", () => {
  let c: AdminHarness;
  const removed: string[] = [];

  beforeAll(async () => {
    const fake = {
      status: () => ({
        enabled: true,
        nodeId: "node-a",
        clusterId: "cl-1",
        advertiseUrl: "https://a.example:9443",
        listening: null,
        member: true,
        head: 0,
        changelogRows: 0,
        conflicts: 0,
        peers: [],
      }),
      refresh: () => {},
      addPeer: async () => ({}),
      leave: async () => ({ announced: ["node-b"], unreachable: ["node-c"] }),
      state: {
        init: () => {},
        peekNodeId: () => "node-a",
        removePeer: (id: string) => {
          removed.push(id);
          return true;
        },
        mintJoinToken: () => ({ token: "t", expiresAt: "e" }),
        advertiseUrl: () => null,
      },
    };
    c = await startAdmin({ cluster: fake as never });
    pointCliAt(c);
  });

  afterAll(async () => {
    pointCliAt(h);
    await c.close();
  });

  it("init warns when the cluster listener is off", async () => {
    const r = await run("cluster", "init", "--advertise", "https://a.example:9443");
    expect(r.out).toContain("Cluster cl-1 initialized. This node is node-a.");
    expect(r.out).toContain("Note: the cluster listener is off.");
  });

  it("peers remove confirms and calls through to the runtime", async () => {
    const r = await run("cluster", "peers", "rm", "node-b");
    expect(r.out).toBe("Peer node-b removed. Every node stops pulling from it.");
    expect(removed).toEqual(["node-b"]);
  });

  it("leave names the peers it could not tell", async () => {
    const r = await run("cluster", "leave");
    expect(r.out).toContain("This node left the cluster.");
    expect(r.out).toContain("Could not tell: node-c.");
  });
});
