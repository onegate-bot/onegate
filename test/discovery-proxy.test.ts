/**
 * End-to-end test of the agent-facing discovery endpoint over the proxy:
 *
 *   client --CONNECT onegate.internal:443--> GatewayProxy --(served locally)
 *
 * The proxy terminates TLS with a leaf from the OneGate root CA (the bot
 * trusts that CA), then serves the discovery JSON without forwarding upstream.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import tls from "node:tls";
import { initCa } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { buildRegistry } from "../src/integrations/index.js";
import { GatewayProxy } from "../src/proxy/server.js";
import { DISCOVERY_HOST } from "../src/discovery.js";

let dir: string;
let store: Store;
let proxy: GatewayProxy;
let proxyPort: number;
let caPem: string;
let agentToken: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-discovery-"));
  const ca = initCa(dir);
  caPem = ca.rootPem;
  store = new Store(":memory:");
  const registry = await buildRegistry();

  const { agent, token } = store.createAgent("hermi", { defaultPolicy: "deny-unmatched" });
  agentToken = token;
  store.createRule({
    scope: "agent",
    subjectId: agent.id,
    integrationId: "jira",
    methods: ["*"],
    pathGlob: "/**",
    effect: "allow",
  });
  const conn = store.createConnection({
    kind: "app",
    vendor: "jira",
    name: "Eli Jira",
    data: { email: "me@x.com", apiToken: "supersecret", siteUrl: "eli.atlassian.net" },
  });
  store.grantConnection(conn.id, "agent", agent.id);

  proxy = new GatewayProxy({
    ca,
    store,
    registry,
    upstreamTls: { ca: caPem },
    upstreamLookup: () => ({ host: "127.0.0.1", port: 1 }),
  });
  proxyPort = await proxy.listen(0, "127.0.0.1");
});

afterAll(async () => {
  await proxy.close();
  rmSync(dir, { recursive: true, force: true });
});

/** Sends a request to the discovery sentinel host through the proxy. */
function discover(opts: {
  token: string | null;
  method?: string;
  path?: string;
  body?: string;
}): Promise<{ status: number; body: string; connectStatus: number }> {
  return new Promise((resolve, reject) => {
    const connectHeaders: Record<string, string> = {};
    if (opts.token) {
      connectHeaders["proxy-authorization"] =
        "Basic " + Buffer.from(`agent:${opts.token}`).toString("base64");
    }
    const connectReq = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "CONNECT",
      path: `${DISCOVERY_HOST}:443`,
      headers: connectHeaders,
      agent: false,
    });
    connectReq.on("connect", (connectRes, socket) => {
      if (connectRes.statusCode !== 200) {
        socket.destroy();
        resolve({ status: 0, body: "", connectStatus: connectRes.statusCode ?? 0 });
        return;
      }
      const tlsSocket = tls.connect({ socket, servername: DISCOVERY_HOST, ca: caPem }, () => {
        const reqHeaders: Record<string, string> = {};
        if (opts.body !== undefined) {
          reqHeaders["content-type"] = "application/json";
          reqHeaders["content-length"] = String(Buffer.byteLength(opts.body));
        }
        const req = http.request(
          {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            createConnection: () => tlsSocket as any,
            host: DISCOVERY_HOST,
            method: opts.method ?? "GET",
            path: opts.path ?? "/",
            headers: reqHeaders,
          },
          (res) => {
            let body = "";
            res.on("data", (c) => (body += c));
            res.on("end", () => {
              resolve({ status: res.statusCode ?? 0, body, connectStatus: 200 });
              tlsSocket.end();
            });
          },
        );
        req.on("error", reject);
        if (opts.body !== undefined) req.write(opts.body);
        req.end();
      });
      tlsSocket.on("error", reject);
    });
    connectReq.on("error", reject);
    connectReq.end();
  });
}

describe("discovery endpoint over the proxy", () => {
  it("rejects CONNECT without a valid token (407)", async () => {
    const r = await discover({ token: null });
    expect(r.connectStatus).toBe(407);
  });

  it("serves the agent's reachable accounts as JSON", async () => {
    const r = await discover({ token: agentToken });
    expect(r.status).toBe(200);
    const payload = JSON.parse(r.body);
    expect(payload.agent.name).toBe("hermi");
    const jira = payload.integrations.find((i: { id: string }) => i.id === "jira");
    expect(jira).toBeDefined();
    expect(jira.access).toBe("allowed");
    expect(jira.accounts[0].summary.siteUrl).toBe("https://eli.atlassian.net");
    expect(jira.defaultAccountId).toBe(jira.accounts[0].id);
    // never leaks the token
    expect(r.body).not.toContain("supersecret");
  });

  it("returns 404 for an unknown path", async () => {
    const r = await discover({ token: agentToken, method: "POST", path: "/nope" });
    expect(r.status).toBe(404);
  });
});

describe("self-mint connect-links over the proxy", () => {
  it("mints a connect link for an OAuth integration scoped to the caller", async () => {
    const r = await discover({
      token: agentToken,
      method: "POST",
      path: "/connect-links",
      body: JSON.stringify({ integrationId: "google" }),
    });
    expect(r.status).toBe(201);
    const payload = JSON.parse(r.body);
    expect(typeof payload.token).toBe("string");
    expect(payload.token.length).toBeGreaterThan(20);
    expect(payload.url).toContain(`/connect/google/${payload.token}`);
    expect(typeof payload.expiresAt).toBe("string");

    // the minted link is scoped to the calling agent, not any body-supplied id
    const link = store.getOnboardingLink(payload.token);
    expect(link).toBeTruthy();
    const hermi = store.getAgentByToken(agentToken);
    expect(link!.agentId).toBe(hermi!.id);
    expect(link!.integrationId).toBe("google");
  });

  it("ignores a body-supplied agentId and self-scopes to the caller", async () => {
    const r = await discover({
      token: agentToken,
      method: "POST",
      path: "/connect-links",
      body: JSON.stringify({ integrationId: "google", agentId: "ag_someone_else" }),
    });
    expect(r.status).toBe(201);
    const payload = JSON.parse(r.body);
    const link = store.getOnboardingLink(payload.token);
    const hermi = store.getAgentByToken(agentToken);
    expect(link!.agentId).toBe(hermi!.id);
  });

  it("mints a connect link for a credential (non-OAuth) integration", async () => {
    const r = await discover({
      token: agentToken,
      method: "POST",
      path: "/connect-links",
      body: JSON.stringify({ integrationId: "jira" }),
    });
    expect(r.status).toBe(201);
    const payload = JSON.parse(r.body);
    expect(payload.url).toContain(`/connect/jira/${payload.token}`);
  });

  it("rejects a non-connectable integration (400 integration_not_connectable)", async () => {
    const r = await discover({
      token: agentToken,
      method: "POST",
      path: "/connect-links",
      body: JSON.stringify({ integrationId: "anthropic" }), // LLM vendor, wired via routing
    });
    expect(r.status).toBe(400);
    expect(JSON.parse(r.body).error).toBe("integration_not_connectable");
  });

  it("rejects a missing integrationId (400)", async () => {
    const r = await discover({
      token: agentToken,
      method: "POST",
      path: "/connect-links",
      body: JSON.stringify({}),
    });
    expect(r.status).toBe(400);
  });

  it("rejects a GET on /connect-links (405)", async () => {
    const r = await discover({ token: agentToken, method: "GET", path: "/connect-links" });
    expect(r.status).toBe(405);
  });
});
