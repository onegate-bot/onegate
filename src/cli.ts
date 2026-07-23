/**
 * OneGate CLI.
 *
 *   onegate init                      generate root CA, db and admin token
 *   onegate start                     run proxy + admin server
 *   onegate print-ca                  print the root CA certificate (PEM)
 *   onegate admin reset-token         mint a new admin token
 *   onegate agent add <name> [...]    register an agent, print its token
 *   onegate agent list
 *
 * Data directory: $ONEGATE_DATA or ~/.onegate
 * Ports: $ONEGATE_PROXY_PORT (default 8443), $ONEGATE_ADMIN_PORT (default 8080)
 */

import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { initCa, loadCa, caExists, caPaths } from "./ca.js";
import { Store } from "./store/db.js";
import { buildRegistry } from "./integrations/index.js";
import { GatewayProxy } from "./proxy/server.js";
import { createAdminApp, ensureAdminToken, resetAdminToken } from "./admin/api.js";
import { createContext } from "./cli/context.js";
import { setJsonMode } from "./cli/output.js";
import { ApiError } from "./cli/client.js";
import { connectionsCommand, agentsLlmCommand, agentsAppsCommand, agentsNotifyCommand } from "./cli/commands/connections.js";
import { agentsCommand } from "./cli/commands/agents.js";
import { rulesCommand } from "./cli/commands/rules.js";
import { credentialsCommand, integrationsCommand } from "./cli/commands/integrations.js";
import { auditCommand, usageCommand } from "./cli/commands/observe.js";
import { projectsCommand } from "./cli/commands/projects.js";

function dataDir(): string {
  return process.env.ONEGATE_DATA ?? join(homedir(), ".onegate");
}

function dbPath(): string {
  return join(dataDir(), "onegate.db");
}

function version(): string {
  try {
    const pkg = JSON.parse(
      readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8"),
    ) as { version: string };
    return pkg.version;
  } catch {
    return "unknown";
  }
}

function fail(msg: string): never {
  console.error(`onegate: ${msg}`);
  process.exit(1);
}

async function cmdInit(): Promise<void> {
  const dir = dataDir();
  if (caExists(dir)) fail(`already initialized (${dir}). Delete the directory to start over.`);
  const ca = initCa(dir);
  const store = new Store(dbPath());
  const adminToken = ensureAdminToken(store)!;
  store.close();
  void ca;
  console.log(`OneGate initialized in ${dir}\n`);
  console.log(`Root CA:      ${caPaths(dir).certPath}`);
  console.log(`Admin token:  ${adminToken}`);
  console.log(`\nThis token is shown ONCE. Store it now.`);
  console.log(`\nNext steps:`);
  console.log(`  1. onegate start`);
  console.log(`  2. Open the admin UI (default http://localhost:8080) and paste the token.`);
  console.log(`  3. Trust the root CA on each agent machine (download at /ca.pem).`);
}

async function cmdStart(): Promise<void> {
  const dir = dataDir();
  if (!caExists(dir)) fail(`not initialized. Run \`onegate init\` first.`);
  const proxyPort = Number(process.env.ONEGATE_PROXY_PORT ?? 8443);
  const adminPort = Number(process.env.ONEGATE_ADMIN_PORT ?? 8080);
  const bindHost = process.env.ONEGATE_BIND ?? "0.0.0.0";

  const ca = loadCa(dir);
  const store = new Store(dbPath());
  const communityDir = process.env.ONEGATE_COMMUNITY_DIR ?? join(dir, "integrations");
  const registry = await buildRegistry(communityDir);

  const proxy = new GatewayProxy({ ca, store, registry, log: (l) => console.error(`[proxy] ${l}`) });
  await proxy.listen(proxyPort, bindHost);

  const app = createAdminApp({ store, registry, ca, version: version() });
  const adminServer = http.createServer(app);
  await new Promise<void>((resolve) => adminServer.listen(adminPort, bindHost, resolve));

  console.log(`OneGate ${version()}`);
  console.log(`  proxy:  http://${bindHost}:${proxyPort}  (agents: HTTPS_PROXY=http://agent:<token>@host:${proxyPort})`);
  console.log(`  admin:  http://${bindHost}:${adminPort}  (UI + API; root CA at /ca.pem)`);
  console.log(`  data:   ${dir}`);
  console.log(`  integrations: ${registry.list().map((i) => i.id).join(", ")}`);

  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log("\nshutting down…");
    // Hard backstop: never let a stuck socket hang the stop. Without this a
    // single non-draining tunnel would keep the process alive until systemd's
    // SIGKILL timeout, leaving the proxy down the whole window.
    const hardExit = setTimeout(() => process.exit(0), 2000);
    hardExit.unref();
    try {
      await proxy.close();
      adminServer.close();
      store.close();
    } catch {
      // best effort; we exit regardless
    }
    clearTimeout(hardExit);
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

function cmdPrintCa(): void {
  const dir = dataDir();
  if (!caExists(dir)) fail("not initialized.");
  process.stdout.write(readFileSync(caPaths(dir).certPath, "utf8"));
}

function cmdAdminResetToken(): void {
  const store = new Store(dbPath());
  const token = resetAdminToken(store);
  store.close();
  console.log(`New admin token: ${token}`);
  console.log("The previous token is now invalid.");
}

function cmdAgentAdd(args: string[]): void {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      policy: { type: "string", default: "deny-unmatched" },
      project: { type: "string" },
    },
  });
  const name = positionals[0];
  if (!name) fail("usage: onegate agent add <name> [--policy allow-all|deny-unmatched] [--project <id>]");
  if (values.policy !== "allow-all" && values.policy !== "deny-unmatched") {
    fail("--policy must be allow-all or deny-unmatched");
  }
  const store = new Store(dbPath());
  const { agent, token } = store.createAgent(name, {
    projectId: values.project ?? null,
    defaultPolicy: values.policy,
  });
  store.close();
  const proxyPort = process.env.ONEGATE_PROXY_PORT ?? 8443;
  console.log(`Agent "${agent.name}" created (${agent.id}, default: ${agent.defaultPolicy})`);
  console.log(`Token (shown ONCE): ${token}`);
  console.log(`\nAgent setup:`);
  console.log(`  export HTTPS_PROXY=http://agent:${token}@<gateway-host>:${proxyPort}`);
  console.log(`  trust the root CA (onegate print-ca, or download /ca.pem from the admin server)`);
}

function cmdAgentList(): void {
  const store = new Store(dbPath());
  const agents = store.listAgents();
  store.close();
  if (!agents.length) {
    console.log("no agents.");
    return;
  }
  for (const a of agents) {
    console.log(`${a.id}  ${a.name}  policy=${a.defaultPolicy}  project=${a.projectId ?? "-"}`);
  }
}

const HELP = `OneGate — open-source credential gateway for AI agents

Usage:

Local commands (operate the data dir directly):
  onegate init                 initialize data dir, root CA and admin token
  onegate start                run the gateway (proxy + admin UI)
  onegate print-ca             print the root CA certificate
  onegate admin reset-token    mint a new admin token
  onegate agent add <name>     register an agent (--policy, --project)
  onegate agent list           list agents

Admin API commands (talk to a running gateway over --host + admin token):
  onegate connections list
  onegate connections add --vendor <v> --name <n> [--api-key|--auth-token|--auth-json|--secret-stdin] [--default]   (LLM)
  onegate connections add --kind app --integration <id> --name <n> --data k=v [--data k=v...] [--agent <id>] [--default]
  onegate connections set-default <id>
  onegate connections rm <id>
  onegate connections grants --id <conn>                                     list grants on an app connection
  onegate connections grant  --id <conn> (--agent <id> | --project <id>)     grant a named app connection (default-deny)
  onegate connections revoke --id <conn> (--agent <id> | --project <id>)     revoke a grant
  onegate agents list|add <name>|rename <id> <name>|rm <id>|rotate-token <id>
  onegate agents llm get|set|clear <agentId> [--strategy fallback|round-robin] [--connections id1,id2] [--enabled|--disabled]
  onegate agents apps get <agentId>|set <agentId> <integrationId> --connection <id>|clear <agentId> <integrationId>
  onegate agents notify get <agentId>|set <agentId> --url <webhookUrl>|clear <agentId>
  onegate rules list|add|rm
  onegate integrations list
  onegate integrations connect <id> --client-id X --client-secret Y --redirect-base URL
  onegate credentials set <integrationId> --name N --data k=v [--data k=v...]
  onegate credentials rm <integrationId>
  onegate audit [--agent <id>] [--limit N]
  onegate usage [--since ISO] [--until ISO] [--limit N]
  onegate projects list|add <name>|rm <id>

Global flags (admin API commands):
  --host <url>     admin API base URL (default http://localhost:8080, or ONEGATE_ADMIN_URL)
  --token <oga_>   admin token (or ONEGATE_ADMIN_TOKEN)
  --json           machine-readable JSON output

Environment:
  ONEGATE_DATA            data directory (default ~/.onegate)
  ONEGATE_PROXY_PORT      proxy port (default 8443)
  ONEGATE_ADMIN_PORT      admin port (default 8080)
  ONEGATE_BIND            bind address (default 0.0.0.0)
  ONEGATE_COMMUNITY_DIR   extra integrations dir (default <data>/integrations)
  ONEGATE_ADMIN_URL       admin API base URL for CLI commands
  ONEGATE_ADMIN_TOKEN     admin token for CLI commands
`;

/**
 * Strips the global flags (--host, --token, --json) from anywhere in argv,
 * applies --json, and returns the remaining args plus a CLI context. parseArgs
 * with strict:false leaves unknown command flags for the sub-command to parse.
 */
function extractGlobals(argv: string[]): { rest: string[]; ctx: ReturnType<typeof createContext> } {
  const rest: string[] = [];
  let host: string | undefined;
  let token: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") {
      setJsonMode(true);
    } else if (a === "--host") {
      host = argv[++i];
    } else if (a.startsWith("--host=")) {
      host = a.slice("--host=".length);
    } else if (a === "--token") {
      token = argv[++i];
    } else if (a.startsWith("--token=")) {
      token = a.slice("--token=".length);
    } else {
      rest.push(a);
    }
  }
  return { rest, ctx: createContext({ host, token }) };
}

export async function main(argv = process.argv.slice(2)): Promise<void> {
  const { rest: cleaned, ctx } = extractGlobals(argv);
  const [cmd, sub, ...rest] = cleaned;

  // Local commands (no admin API, operate the data dir directly).
  if (cmd === "init") return cmdInit();
  if (cmd === "start") return cmdStart();
  if (cmd === "print-ca") return cmdPrintCa();
  if (cmd === "admin" && sub === "reset-token") return cmdAdminResetToken();
  if (cmd === "agent" && sub === "add") return cmdAgentAdd(rest);
  if (cmd === "agent" && sub === "list") return cmdAgentList();

  // Admin API commands.
  try {
    if (cmd === "connections") return await connectionsCommand(ctx, sub, rest);
    if (cmd === "agents" && sub === "llm") return await agentsLlmCommand(ctx, rest[0], rest.slice(1));
    if (cmd === "agents" && sub === "apps") return await agentsAppsCommand(ctx, rest[0], rest.slice(1));
    if (cmd === "agents" && sub === "notify") return await agentsNotifyCommand(ctx, rest[0], rest.slice(1));
    if (cmd === "agents") return await agentsCommand(ctx, sub, rest);
    if (cmd === "rules") return await rulesCommand(ctx, sub, rest);
    if (cmd === "integrations") return await integrationsCommand(ctx, sub, rest);
    if (cmd === "credentials") return await credentialsCommand(ctx, sub, rest);
    if (cmd === "audit") return await auditCommand(ctx, cleaned.slice(1));
    if (cmd === "usage") return await usageCommand(ctx, cleaned.slice(1));
    if (cmd === "projects") return await projectsCommand(ctx, sub, rest);
  } catch (err) {
    if (err instanceof ApiError) fail(err.message);
    fail((err as Error).message);
  }

  console.log(HELP);
  if (cmd && cmd !== "help" && cmd !== "--help") process.exit(1);
}

const isDirectRun =
  process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isDirectRun) {
  main().catch((err) => fail((err as Error).message));
}
