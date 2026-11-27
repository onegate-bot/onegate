/**
 * Host-qualified rule globs (`<hostGlob>[/<pathGlob>]`).
 *
 * Regression for a deny rule written as `http-intake.logs.us5.datadoghq.com/**`
 * that never fired: the path matcher only ever saw `/...` paths, and the host
 * is not claimed by any integration, so its traffic took the opaque passthrough
 * tunnel, which consulted no rules at all. These tests pin:
 *   - the pure host-glob parser / matcher / validator,
 *   - ruleMatches on a TLS-terminated request (host + path),
 *   - passthrough enforcement: a denied host gets 403 + a deny audit row, while
 *     a host no deny names still tunnels (passthrough stays default-open).
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  evaluate,
  hostGlobMatches,
  InvalidPathGlobError,
  isHostQualifiedGlob,
  parseHostQualifiedGlob,
  passthroughDenyRule,
  ruleMatches,
  validatePathGlob,
} from "../src/policy.js";
import type { Agent, Rule } from "../src/types.js";
import { initCa } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { Registry } from "../src/integrations/types.js";
import { GatewayProxy } from "../src/proxy/server.js";

function agent(defaultPolicy: Agent["defaultPolicy"] = "deny-unmatched"): Agent {
  return { id: "ag_1", name: "test", tokenHash: "x", projectId: null, defaultPolicy, createdAt: "" };
}

function rule(partial: Partial<Rule>): Rule {
  return {
    id: "rl_1",
    scope: "agent",
    subjectId: "ag_1",
    integrationId: "*",
    methods: ["*"],
    pathGlob: "/**",
    effect: "deny",
    createdAt: "",
    ...partial,
  };
}

describe("parseHostQualifiedGlob", () => {
  it("splits host and path parts, defaulting the path to /**", () => {
    expect(parseHostQualifiedGlob("http-intake.logs.us5.datadoghq.com/**")).toEqual({
      hostGlob: "http-intake.logs.us5.datadoghq.com",
      pathGlob: "/**",
    });
    expect(parseHostQualifiedGlob("*.datadoghq.com")).toEqual({ hostGlob: "*.datadoghq.com", pathGlob: "/**" });
    expect(parseHostQualifiedGlob("**.Example.COM/v1/*")).toEqual({
      hostGlob: "**.example.com",
      pathGlob: "/v1/*",
    });
  });

  it("returns null for plain path globs and malformed host globs", () => {
    for (const g of ["/v1/**", "**", "*", "logs/**", "*.*", "**.**", "bad_host.com", "a**b.example.com", ".example.com", "example..com", "host:443.com"]) {
      expect(parseHostQualifiedGlob(g), g).toBeNull();
      expect(isHostQualifiedGlob(g), g).toBe(false);
    }
  });
});

describe("validatePathGlob", () => {
  it("accepts /... paths and host-qualified globs", () => {
    for (const g of ["/", "/**", "/v1/*/x", "api.example.com", "*.datadoghq.com", "**.datadoghq.com/**", "api-*.example.com/v1/**", "10.0.0.1"]) {
      expect(() => validatePathGlob(g), g).not.toThrow();
    }
  });

  it("rejects anything else with a message naming both accepted forms", () => {
    for (const g of ["**", "logs/**", "*.*", "", "foo"]) {
      expect(() => validatePathGlob(g), g).toThrow(InvalidPathGlobError);
    }
    expect(() => validatePathGlob("logs/**")).toThrow(/starting with "\/".*host-qualified/);
  });
});

describe("hostGlobMatches", () => {
  it("matches exact hosts case-insensitively and ignores a trailing dot", () => {
    const g = "http-intake.logs.us5.datadoghq.com";
    expect(hostGlobMatches(g, "http-intake.logs.us5.datadoghq.com")).toBe(true);
    expect(hostGlobMatches(g, "HTTP-Intake.Logs.US5.DatadogHQ.com")).toBe(true);
    expect(hostGlobMatches(g, "http-intake.logs.us5.datadoghq.com.")).toBe(true);
    expect(hostGlobMatches(g, "api.us5.datadoghq.com")).toBe(false);
    expect(hostGlobMatches(g, "xhttp-intake.logs.us5.datadoghq.com")).toBe(false);
  });

  it("* matches exactly one label", () => {
    expect(hostGlobMatches("*.datadoghq.com", "api.datadoghq.com")).toBe(true);
    expect(hostGlobMatches("*.datadoghq.com", "logs.us5.datadoghq.com")).toBe(false);
    expect(hostGlobMatches("*.datadoghq.com", "datadoghq.com")).toBe(false);
    expect(hostGlobMatches("*.datadoghq.com", "datadoghq.com.evil.net")).toBe(false);
  });

  it("* inside a label matches within that label only", () => {
    expect(hostGlobMatches("api-*.example.com", "api-eu.example.com")).toBe(true);
    expect(hostGlobMatches("api-*.example.com", "api-.example.com")).toBe(true);
    expect(hostGlobMatches("api-*.example.com", "api-eu.x.example.com")).toBe(false);
    expect(hostGlobMatches("api-*.example.com", "web.example.com")).toBe(false);
  });

  it("** matches zero or more labels", () => {
    expect(hostGlobMatches("**.datadoghq.com", "datadoghq.com")).toBe(true);
    expect(hostGlobMatches("**.datadoghq.com", "api.datadoghq.com")).toBe(true);
    expect(hostGlobMatches("**.datadoghq.com", "http-intake.logs.us5.datadoghq.com")).toBe(true);
    expect(hostGlobMatches("**.datadoghq.com", "datadoghq.com.evil.net")).toBe(false);
    expect(hostGlobMatches("**.datadoghq.com", "notdatadoghq.com")).toBe(false);
    expect(hostGlobMatches("logs.**.com", "logs.a.b.com")).toBe(true);
    expect(hostGlobMatches("logs.**.com", "logs.com")).toBe(true);
    expect(hostGlobMatches("api.example.**", "api.example.co.uk")).toBe(true);
  });
});

describe("ruleMatches with host-qualified globs (terminated requests)", () => {
  const req = { integrationId: "vendor", method: "GET", path: "/v1/admin/users", host: "api.example.com" };

  it("matches on host + path", () => {
    expect(ruleMatches(rule({ pathGlob: "api.example.com/v1/admin/**" }), req)).toBe(true);
    expect(ruleMatches(rule({ pathGlob: "api.example.com" }), req)).toBe(true);
    expect(ruleMatches(rule({ pathGlob: "*.example.com/**" }), req)).toBe(true);
    expect(ruleMatches(rule({ pathGlob: "api.example.com/v2/**" }), req)).toBe(false);
    expect(ruleMatches(rule({ pathGlob: "other.example.com/**" }), req)).toBe(false);
  });

  it("never matches a request that carries no host", () => {
    const { host: _host, ...noHost } = req;
    expect(ruleMatches(rule({ pathGlob: "api.example.com/**" }), noHost)).toBe(false);
  });

  it("host is case-insensitive for allow and deny; the path keeps the effect asymmetry", () => {
    const upper = { ...req, host: "API.Example.com", path: "/V1/Admin/users" };
    expect(ruleMatches(rule({ effect: "deny", pathGlob: "api.example.com/v1/admin/**" }), upper)).toBe(true);
    expect(ruleMatches(rule({ effect: "allow", pathGlob: "api.example.com/v1/admin/**" }), upper)).toBe(false);
    expect(
      ruleMatches(rule({ effect: "allow", pathGlob: "api.example.com/v1/admin/**" }), { ...upper, path: req.path }),
    ).toBe(true);
  });

  it("keeps legacy non-host globs (stored before validation) unchanged", () => {
    expect(ruleMatches(rule({ pathGlob: "**" }), req)).toBe(true);
  });

  it("a host-qualified deny beats a broad allow in evaluate()", () => {
    const rules = [
      rule({ id: "allow", effect: "allow", integrationId: "vendor", pathGlob: "/**" }),
      rule({ id: "deny", pathGlob: "api.example.com/v1/admin/**" }),
    ];
    expect(evaluate(agent(), rules, req).ruleId).toBe("deny");
    expect(evaluate(agent(), rules, { ...req, path: "/v1/ok" })).toMatchObject({ effect: "allow", ruleId: "allow" });
  });
});

describe("passthroughDenyRule", () => {
  const host = "http-intake.logs.us5.datadoghq.com";

  it("returns the first live host-qualified deny whose host matches", () => {
    const r = rule({ id: "dd", pathGlob: `${host}/**` });
    expect(passthroughDenyRule([r], host)?.id).toBe("dd");
    expect(passthroughDenyRule([r], "api.datadoghq.com")).toBeNull();
  });

  it("ignores the path part, methods and integration (fail-closed on an opaque tunnel)", () => {
    const r = rule({ id: "narrow", pathGlob: `${host}/api/v2/logs`, methods: ["POST"], integrationId: "datadog" });
    expect(passthroughDenyRule([r], host)?.id).toBe("narrow");
  });

  it("blocks on a require_approval rule too (it is persisted as a deny)", () => {
    const r = rule({ id: "gate", action: "require_approval", pathGlob: "*.datadoghq.com" });
    expect(passthroughDenyRule([r], "api.datadoghq.com")?.id).toBe("gate");
  });

  it("skips allow rules, plain path globs, connection-scoped and lapsed rules", () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const rules = [
      rule({ effect: "allow", pathGlob: `${host}/**` }),
      rule({ pathGlob: "/**" }),
      rule({ pathGlob: "**" }),
      rule({ pathGlob: `${host}/**`, connectionId: "cn_1", connectionScope: "except" }),
      rule({ pathGlob: `${host}/**`, expiresAt: past }),
    ];
    expect(passthroughDenyRule(rules, host)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Proxy-level: passthrough enforcement and MITM host-qualified deny.
// ---------------------------------------------------------------------------

const VENDOR_HOST = "api.example-vendor.com";
const DD_HOST = "http-intake.logs.us5.datadoghq.com";

describe("proxy: host-qualified deny rules", () => {
  let dir: string;
  let store: Store;
  let proxy: GatewayProxy;
  let proxyPort: number;
  let stub: https.Server;
  let caPem: string;
  let token: string;
  let otherToken: string;
  let agentId: string;
  let ddRuleId: string;
  let narrowRuleId: string;
  let adminRuleId: string;
  const logs: string[] = [];

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "onegate-hostdeny-"));
    const ca = initCa(dir);
    caPem = ca.rootPem;
    store = new Store(":memory:");

    stub = https.createServer(
      {
        SNICallback: (servername, cb) => {
          const leaf = ca.leafFor(servername || VENDOR_HOST);
          cb(null, tls.createSecureContext({ key: leaf.key, cert: leaf.cert }));
        },
      },
      (req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, path: req.url }));
      },
    );
    await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
    const stubPort = (stub.address() as { port: number }).port;

    const registry = new Registry();
    registry.register({
      id: "vendor",
      title: "Example Vendor",
      hosts: [VENDOR_HOST],
      credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
      inject(ctx) {
        ctx.headers.authorization = `Bearer ${ctx.credential.data.apiKey}`;
      },
    });
    store.setCredential("vendor", "k", { apiKey: "secret" });

    const a = store.createAgent("host-deny-agent", { defaultPolicy: "deny-unmatched" });
    token = a.token;
    agentId = a.agent.id;
    store.createRule({
      scope: "agent",
      subjectId: agentId,
      integrationId: "vendor",
      methods: ["*"],
      pathGlob: "/**",
      effect: "allow",
    });
    adminRuleId = store.createRule({
      scope: "agent",
      subjectId: agentId,
      integrationId: "*",
      methods: ["*"],
      pathGlob: `${VENDOR_HOST}/v1/admin/**`,
      effect: "deny",
    }).id;
    ddRuleId = store.createRule({
      scope: "agent",
      subjectId: agentId,
      integrationId: "*",
      methods: ["*"],
      pathGlob: `${DD_HOST}/**`,
      effect: "deny",
    }).id;
    // A narrower path part on an opaque host must still block the whole host.
    narrowRuleId = store.createRule({
      scope: "agent",
      subjectId: agentId,
      integrationId: "*",
      methods: ["POST"],
      pathGlob: "files.example.net/upload/**",
      effect: "deny",
    }).id;
    // A host-qualified ALLOW changes nothing on passthrough.
    store.createRule({
      scope: "agent",
      subjectId: agentId,
      integrationId: "*",
      methods: ["*"],
      pathGlob: "api.datadoghq.com/**",
      effect: "allow",
    });

    otherToken = store.createAgent("unrestricted-agent", { defaultPolicy: "deny-unmatched" }).token;

    proxy = new GatewayProxy({
      ca,
      store,
      registry,
      upstreamTls: { ca: caPem },
      // Keeps everything local: MITM upstreams and passthrough tunnels both
      // land on the stub.
      upstreamLookup: () => ({ host: "127.0.0.1", port: stubPort }),
      log: (line) => logs.push(line),
    });
    proxyPort = await proxy.listen(0, "127.0.0.1");
  });

  afterAll(async () => {
    await proxy.close();
    stub.closeAllConnections();
    stub.close();
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  function connect(authority: string, tok = token): Promise<number> {
    return new Promise((resolve, reject) => {
      const req = http.request({
        host: "127.0.0.1",
        port: proxyPort,
        method: "CONNECT",
        path: authority,
        headers: { "proxy-authorization": "Basic " + Buffer.from(`agent:${tok}`).toString("base64") },
        agent: false,
      });
      req.on("connect", (res, socket) => {
        socket.destroy();
        resolve(res.statusCode ?? 0);
      });
      req.on("response", (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.on("error", reject);
      req.end();
    });
  }

  function viaMitm(path: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const connectReq = http.request({
        host: "127.0.0.1",
        port: proxyPort,
        method: "CONNECT",
        path: `${VENDOR_HOST}:443`,
        headers: { "proxy-authorization": "Basic " + Buffer.from(`agent:${token}`).toString("base64") },
        agent: false,
      });
      connectReq.on("connect", (connectRes, socket) => {
        if (connectRes.statusCode !== 200) {
          socket.destroy();
          resolve(-1);
          return;
        }
        const tlsSocket = tls.connect({ socket, servername: VENDOR_HOST, ca: caPem }, () => {
          const req = https.request(
            { createConnection: () => tlsSocket, host: VENDOR_HOST, method: "GET", path },
            (res) => {
              res.resume();
              res.on("end", () => {
                resolve(res.statusCode ?? 0);
                tlsSocket.end();
              });
            },
          );
          req.on("error", reject);
          req.end();
        });
        tlsSocket.on("error", reject);
      });
      connectReq.on("error", reject);
      connectReq.end();
    });
  }

  it("refuses a passthrough CONNECT to a denied host with 403 and audits a deny with the rule id", async () => {
    expect(await connect(`${DD_HOST}:443`)).toBe(403);
    const entry = store.listAudit({ limit: 50 }).find((e) => e.host === DD_HOST);
    expect(entry).toMatchObject({ decision: "deny", status: 403, ruleId: ddRuleId, agentId });
    expect(logs.some((l) => l.includes(`passthrough denied host-deny-agent -> ${DD_HOST}:443 (rule ${ddRuleId})`))).toBe(
      true,
    );
  });

  it("cannot be dodged with host casing or a trailing root dot", async () => {
    expect(await connect("HTTP-INTAKE.logs.US5.datadoghq.com:443")).toBe(403);
    expect(await connect(`${DD_HOST}.:443`)).toBe(403);
  });

  it("blocks the whole host when the deny's path part and methods are narrower (fail-closed)", async () => {
    expect(await connect("files.example.net:443")).toBe(403);
    expect(store.listAudit({ limit: 50 }).find((e) => e.host === "files.example.net")?.ruleId).toBe(narrowRuleId);
  });

  it("still tunnels to a host no deny names, and a host-qualified allow changes nothing", async () => {
    expect(await connect("api.datadoghq.com:443")).toBe(200);
    expect(await connect("unrelated.example.org:443")).toBe(200);
    const decisions = store
      .listAudit({ limit: 50 })
      .filter((e) => e.host === "api.datadoghq.com" || e.host === "unrelated.example.org")
      .map((e) => e.decision);
    expect(decisions).toEqual(["passthrough", "passthrough"]);
  });

  it("applies only to the agent the rule is scoped to", async () => {
    expect(await connect(`${DD_HOST}:443`, otherToken)).toBe(200);
  });

  it("enforces a host-qualified deny on a TLS-terminated request, case-insensitively, without blocking the rest", async () => {
    expect(await viaMitm("/v1/admin/users")).toBe(403);
    expect(await viaMitm("/V1/Admin/users")).toBe(403);
    const denied = store
      .listAudit({ limit: 50 })
      .filter((e) => e.host === VENDOR_HOST && e.decision === "deny");
    expect(denied.every((e) => e.ruleId === adminRuleId)).toBe(true);
    expect(denied.length).toBeGreaterThanOrEqual(2);
    expect(await viaMitm("/v1/ok")).toBe(200);
  });
});
