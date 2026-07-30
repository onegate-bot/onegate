import { describe, it, expect, beforeEach } from "vitest";
import { Store } from "../src/store/db.js";
import { buildRegistry } from "../src/integrations/index.js";
import { buildDiscovery, DISCOVERY_HOST } from "../src/discovery.js";
import type { Registry } from "../src/integrations/types.js";

let store: Store;
let registry: Registry;

beforeEach(async () => {
  store = new Store(":memory:");
  registry = await buildRegistry();
});

function allowAll(agentId: string, integrationId: string): void {
  store.createRule({
    scope: "agent",
    subjectId: agentId,
    integrationId,
    methods: ["*"],
    pathGlob: "/**",
    effect: "allow",
  });
}

describe("DISCOVERY_HOST", () => {
  it("is the internal sentinel host", () => {
    expect(DISCOVERY_HOST).toBe("onegate.internal");
  });
});

describe("buildDiscovery", () => {
  it("surfaces a granted Jira connection with its non-secret account summary", () => {
    const { agent } = store.createAgent("hermi");
    allowAll(agent.id, "jira");
    const conn = store.createConnection({
      kind: "app",
      vendor: "jira",
      name: "Eli Jira",
      data: { email: "me@x.com", apiToken: "supersecret", siteUrl: "eli.atlassian.net" },
    });
    store.grantConnection(conn.id, "agent", agent.id);

    const result = buildDiscovery(store, registry, agent);
    const jira = result.integrations.find((i) => i.id === "jira");
    expect(jira).toBeDefined();
    expect(jira!.accounts).toHaveLength(1);
    expect(jira!.accounts[0].summary).toEqual({
      email: "me@x.com",
      siteUrl: "https://eli.atlassian.net",
      apiBaseUrl: "https://eli.atlassian.net/rest/api/3",
    });
    // never leaks the token
    expect(JSON.stringify(result)).not.toContain("supersecret");
  });

  it("auto-defaults the sole account", () => {
    const { agent } = store.createAgent("a");
    allowAll(agent.id, "jira");
    const conn = store.createConnection({
      kind: "app",
      vendor: "jira",
      name: "only",
      data: { email: "x@y.com", apiToken: "t", siteUrl: "x.atlassian.net" },
    });
    store.grantConnection(conn.id, "agent", agent.id);

    const jira = buildDiscovery(store, registry, agent).integrations.find((i) => i.id === "jira")!;
    expect(jira.defaultAccountId).toBe(conn.id);
    expect(jira.accounts[0].isDefault).toBe(true);
  });

  it("respects the store default across multiple accounts", () => {
    const { agent } = store.createAgent("a");
    allowAll(agent.id, "github");
    const c1 = store.createConnection({ kind: "app", vendor: "github", name: "one", data: { pat: "a" } });
    const c2 = store.createConnection({
      kind: "app",
      vendor: "github",
      name: "two",
      data: { pat: "b" },
      isDefault: true,
    });
    store.grantConnection(c1.id, "agent", agent.id);
    store.grantConnection(c2.id, "agent", agent.id);

    const gh = buildDiscovery(store, registry, agent).integrations.find((i) => i.id === "github")!;
    expect(gh.accounts).toHaveLength(2);
    expect(gh.defaultAccountId).toBe(c2.id);
    expect(gh.accounts.find((a) => a.id === c2.id)!.isDefault).toBe(true);
    expect(gh.accounts.find((a) => a.id === c1.id)!.isDefault).toBe(false);
  });

  it("falls back to the legacy shared credential when no named connections exist", () => {
    const { agent } = store.createAgent("a");
    allowAll(agent.id, "github");
    store.setCredential("github", "shared", { pat: "legacy" });

    const gh = buildDiscovery(store, registry, agent).integrations.find((i) => i.id === "github")!;
    expect(gh.accounts).toHaveLength(1);
    expect(gh.accounts[0].name).toBe("shared");
    expect(gh.accounts[0].isDefault).toBe(true);
  });

  it("does NOT advertise the legacy credential when the proxy would deny (named conn exists, not granted)", () => {
    const { agent } = store.createAgent("mine");
    const { agent: other } = store.createAgent("other");
    allowAll(agent.id, "github");
    // A named app connection exists for github, but it is granted to another agent.
    const conn = store.createConnection({
      kind: "app",
      vendor: "github",
      name: "theirs",
      data: { pat: "notmine" },
    });
    store.grantConnection(conn.id, "agent", other.id);
    // ...and a legacy shared credential also exists.
    store.setCredential("github", "legacy-shared", { pat: "legacypat" });

    // The proxy denies this agent outright.
    expect(store.resolveAppConnection(agent.id, "github", undefined)).toEqual({
      error: "connection_not_granted",
    });

    // Discovery must agree: no github entry at all, and no disclosure of the
    // shared credential's name or material.
    const result = buildDiscovery(store, registry, agent);
    expect(result.integrations.map((i) => i.id)).not.toContain("github");
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("legacy-shared");
    expect(serialized).not.toContain("legacypat");
  });

  it("still advertises the granted named connection, not the legacy credential", () => {
    const { agent } = store.createAgent("mine");
    allowAll(agent.id, "github");
    const conn = store.createConnection({
      kind: "app",
      vendor: "github",
      name: "mine-conn",
      data: { pat: "p" },
    });
    store.grantConnection(conn.id, "agent", agent.id);
    store.setCredential("github", "legacy-shared", { pat: "legacypat" });

    const gh = buildDiscovery(store, registry, agent).integrations.find((i) => i.id === "github")!;
    expect(gh.accounts).toHaveLength(1);
    expect(gh.accounts[0].id).toBe(conn.id);
    expect(gh.defaultAccountId).toBe(conn.id);
  });

  it("omits integrations the agent has no account for, and LLM vendors", () => {
    const { agent } = store.createAgent("a");
    allowAll(agent.id, "jira");
    const conn = store.createConnection({
      kind: "app",
      vendor: "jira",
      name: "j",
      data: { email: "x@y.com", apiToken: "t", siteUrl: "x.atlassian.net" },
    });
    store.grantConnection(conn.id, "agent", agent.id);

    const result = buildDiscovery(store, registry, agent);
    const ids = result.integrations.map((i) => i.id);
    expect(ids).toContain("jira");
    expect(ids).not.toContain("github");
    expect(ids).not.toContain("anthropic");
    expect(ids).not.toContain("gemini");
  });

  it("reflects allow vs deny in the coarse access hint", () => {
    const { agent } = store.createAgent("a");
    const conn = store.createConnection({
      kind: "app",
      vendor: "jira",
      name: "j",
      data: { email: "x@y.com", apiToken: "t", siteUrl: "x.atlassian.net" },
    });
    store.grantConnection(conn.id, "agent", agent.id);

    // no allow rule yet -> denied (default-deny)
    let jira = buildDiscovery(store, registry, agent).integrations.find((i) => i.id === "jira")!;
    expect(jira.access).toBe("denied");

    allowAll(agent.id, "jira");
    jira = buildDiscovery(store, registry, agent).integrations.find((i) => i.id === "jira")!;
    expect(jira.access).toBe("allowed");
  });

  it("carries the agent identity and sorts integrations by id", () => {
    const { agent } = store.createAgent("hermi");
    allowAll(agent.id, "jira");
    allowAll(agent.id, "github");
    const j = store.createConnection({
      kind: "app",
      vendor: "jira",
      name: "j",
      data: { email: "x@y.com", apiToken: "t", siteUrl: "x.atlassian.net" },
    });
    const g = store.createConnection({ kind: "app", vendor: "github", name: "g", data: { pat: "p" } });
    store.grantConnection(j.id, "agent", agent.id);
    store.grantConnection(g.id, "agent", agent.id);

    const result = buildDiscovery(store, registry, agent);
    expect(result.agent).toEqual({ id: agent.id, name: "hermi" });
    const ids = result.integrations.map((i) => i.id);
    expect(ids).toEqual([...ids].sort((a, b) => a.localeCompare(b)));
  });
});
