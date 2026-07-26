/**
 * M1 (the painkiller): LLM connections + per-agent LLM routing.
 *
 *   onegate connections list
 *   onegate connections add --vendor <v> --name <n> [secret flags] [--default]   (LLM)
 *   onegate connections add --kind app --integration <id> --name <n> --data-stdin [--agent <id>] [--default]
 *   onegate connections set-default <id>
 *   onegate connections rm <id>
 *   onegate connections grants --id <conn>                          (list grants)
 *   onegate connections grant  --id <conn> (--agent <id> | --project <id>)
 *   onegate connections revoke --id <conn> (--agent <id> | --project <id>)
 *   onegate agents llm get <agentId>
 *   onegate agents llm set <agentId> --enabled --strategy <s> --connections id1,id2
 *                                    [--vendor-strategy anthropic=round-robin]...
 *   onegate agents llm clear <agentId>
 *   onegate agents apps get <agentId>
 *   onegate agents apps set <agentId> <integrationId> --connection <id>
 *   onegate agents apps clear <agentId> <integrationId>
 *
 * `connections add` normally posts to the admin API. When the vendor is in
 * ONEGATE_DISABLED_INTEGRATIONS the API rejects it (the vendor gate is
 * intentional for self-egress instances). The sanctioned --allow-disabled-vendor
 * flag then writes the connection row directly to the local store, replacing the
 * hand-written SQLite seeding we do today. Secrets come from flags or stdin and
 * are never logged.
 *
 * Prefer the stdin forms (--secret-stdin, --data-stdin). A secret passed as an
 * argv flag is visible in `ps`, in /proc/<pid>/cmdline to any local user, and in
 * shell history. The argv flags remain for backwards compatibility only.
 */

import { parseArgs } from "node:util";
import { disabledIntegrations } from "../../integrations/index.js";
import { emit, table } from "../output.js";
import {
  parseDataPairs,
  readDataPairsFromStdin,
  readSecretFromStdin,
  rejectDuplicateSecretInput,
} from "../secret-input.js";
import type { CliContext } from "../context.js";

/** Builds the connection `data` object from secret flags, reading stdin when asked. */
async function collectSecretData(
  values: Record<string, unknown>,
): Promise<Record<string, string>> {
  const data: Record<string, string> = {};
  const readStdin = readSecretFromStdin;

  const apiKey = values["api-key"] as string | undefined;
  const authToken = values["auth-token"] as string | undefined;
  const authJson = values["auth-json"] as string | undefined;
  const fromStdin = values["secret-stdin"] === true;

  if (fromStdin) {
    const secret = await readStdin();
    if (!secret) throw new Error("no secret on stdin");
    if (authToken !== undefined || values["auth-token-stdin"] === true) {
      data.authToken = secret;
      data.authMode = "auth_token";
    } else {
      data.apiKey = secret;
    }
    return data;
  }

  if (apiKey) data.apiKey = apiKey;
  if (authToken) {
    data.authToken = authToken;
    data.authMode = "auth_token";
  }
  if (authJson) {
    // openai auth.json import: accept a JSON object with accessToken / accountId.
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(authJson) as Record<string, unknown>;
    } catch {
      throw new Error("--auth-json must be valid JSON");
    }
    for (const [k, v] of Object.entries(parsed)) {
      if (typeof v === "string") data[k] = v;
    }
  }
  if (Object.keys(data).length === 0) {
    throw new Error(
      "no secret given. Use --api-key, --auth-token, --auth-json or --secret-stdin.",
    );
  }
  return data;
}

interface PublicConnection {
  id: string;
  vendor: string;
  name: string;
  isDefault: boolean;
  hasSecret?: boolean;
  authMode?: string;
}

interface AppConnection extends PublicConnection {
  ownerAgentId: string | null;
  ownerAgentName: string | null;
  legacy?: boolean;
}

async function list(ctx: CliContext): Promise<void> {
  const res = (await ctx.client().get("/api/connections")) as {
    llm: PublicConnection[];
    apps: AppConnection[];
  };
  emit(res, () => {
    if (!res.llm.length) {
      console.log("no LLM connections.");
    } else {
      console.log("LLM connections:");
      console.log(
        table(
          res.llm as unknown as Array<Record<string, unknown>>,
          [
            ["ID", "id"],
            ["VENDOR", "vendor"],
            ["NAME", "name"],
            ["DEFAULT", "isDefault"],
            ["MODE", "authMode"],
          ],
        ),
      );
    }
    console.log("");
    if (!res.apps.length) {
      console.log("no app connections.");
      return;
    }
    console.log("App connections:");
    const appRows = res.apps.map((a) => ({
      id: a.id,
      vendor: a.vendor,
      name: a.name,
      scope: a.legacy
        ? "shared (legacy)"
        : a.ownerAgentId
          ? `agent: ${a.ownerAgentName ?? a.ownerAgentId}`
          : "tenant-wide",
      isDefault: a.isDefault,
    }));
    console.log(
      table(appRows, [
        ["ID", "id"],
        ["INTEGRATION", "vendor"],
        ["NAME", "name"],
        ["SCOPE", "scope"],
        ["DEFAULT", "isDefault"],
      ]),
    );
  });
}

async function add(ctx: CliContext, args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      kind: { type: "string", default: "llm" },
      vendor: { type: "string" },
      integration: { type: "string" },
      agent: { type: "string" },
      name: { type: "string" },
      data: { type: "string", multiple: true, default: [] },
      "data-stdin": { type: "boolean", default: false },
      "api-key": { type: "string" },
      "auth-token": { type: "string" },
      "auth-json": { type: "string" },
      "secret-stdin": { type: "boolean", default: false },
      "auth-token-stdin": { type: "boolean", default: false },
      default: { type: "boolean", default: false },
      "allow-disabled-vendor": { type: "boolean", default: false },
    },
  });

  if (values.kind === "app") return addApp(ctx, values);
  if (values.kind !== "llm") throw new Error('--kind must be "llm" or "app"');

  const vendor = values.vendor;
  const name = values.name;
  if (!vendor || !name) {
    throw new Error(
      "usage: onegate connections add --vendor <v> --name <n> [--api-key X | --auth-token X | --auth-json X | --secret-stdin] [--default]",
    );
  }
  const data = await collectSecretData(values);
  const isDefault = values.default === true;

  const disabled = disabledIntegrations();
  if (disabled.has(vendor)) {
    if (!values["allow-disabled-vendor"]) {
      throw new Error(
        `vendor "${vendor}" is in ONEGATE_DISABLED_INTEGRATIONS, so POST /api/connections would reject it.\n` +
          `Re-run with --allow-disabled-vendor to write the connection directly to the store (this bypasses the API vendor gate by design, for self-egress instances like Gaty).`,
      );
    }
    // Sanctioned direct-store seed path. The API will not accept a disabled
    // vendor, so write the row exactly as the server's store does. The secret
    // is written to the local db and never printed.
    console.error(
      `warning: writing connection directly to the store (bypassing the API vendor gate) because "${vendor}" is disabled.`,
    );
    const store = ctx.store();
    const conn = store.createConnection({ kind: "llm", vendor, name, data, isDefault });
    store.close();
    emit(redact(conn), () =>
      console.log(`Connection "${conn.name}" created (${conn.id}, vendor=${conn.vendor}, default=${conn.isDefault}).`),
    );
    return;
  }

  const conn = (await ctx.client().post("/api/connections", {
    kind: "llm",
    vendor,
    name,
    data,
    isDefault,
  })) as PublicConnection;
  emit(conn, () =>
    console.log(`Connection "${conn.name}" created (${conn.id}, vendor=${conn.vendor}, default=${conn.isDefault}).`),
  );
}

/**
 * Adds a named app (service) connection. Scope is tenant-wide by default, or
 * agent-bound when --agent <id> is given. Secret material comes from newline
 * separated key=value pairs on stdin (--data-stdin, preferred) or from --data
 * k=v flags (legacy, exposes the secret in argv), and is never echoed back.
 */
async function addApp(ctx: CliContext, values: Record<string, unknown>): Promise<void> {
  const integration = (values.integration as string | undefined) ?? (values.vendor as string | undefined);
  const name = values.name as string | undefined;
  if (!integration || !name) {
    throw new Error(
      "usage: onegate connections add --kind app --integration <id> --name <n> (--data-stdin | --data k=v [--data k=v...]) [--agent <id>] [--default]",
    );
  }
  const pairs = (values.data as string[]) ?? [];
  const fromStdin = values["data-stdin"] === true;
  rejectDuplicateSecretInput("--data", "--data-stdin", pairs.length > 0, fromStdin);
  if (!fromStdin && !pairs.length) {
    throw new Error(
      "at least one --data k=v is required for an app connection (prefer --data-stdin, --data exposes the secret in ps and shell history)",
    );
  }
  const data = fromStdin ? await readDataPairsFromStdin() : parseDataPairs(pairs);
  const conn = (await ctx.client().post("/api/connections", {
    kind: "app",
    vendor: integration,
    name,
    data,
    ownerAgentId: (values.agent as string | undefined) ?? null,
    isDefault: values.default === true,
  })) as AppConnection;
  emit(conn, () => {
    const scope = conn.ownerAgentId ? `agent ${conn.ownerAgentName ?? conn.ownerAgentId}` : "tenant-wide";
    console.log(
      `App connection "${conn.name}" created (${conn.id}, integration=${conn.vendor}, scope=${scope}, default=${conn.isDefault}).`,
    );
  });
}

/** Strips secret material from a store Connection before emitting. */
function redact(conn: {
  id: string;
  kind: string;
  vendor: string;
  name: string;
  isDefault: boolean;
  data: Record<string, string>;
  createdAt: string;
  updatedAt: string;
}): Record<string, unknown> {
  return {
    id: conn.id,
    kind: conn.kind,
    vendor: conn.vendor,
    name: conn.name,
    isDefault: conn.isDefault,
    hasSecret: Object.values(conn.data).some((v) => v && v.trim() !== ""),
    createdAt: conn.createdAt,
    updatedAt: conn.updatedAt,
  };
}

async function setDefault(ctx: CliContext, args: string[]): Promise<void> {
  const id = args[0];
  if (!id) throw new Error("usage: onegate connections set-default <id>");
  const conn = (await ctx.client().put(`/api/connections/${encodeURIComponent(id)}`, {
    isDefault: true,
  })) as PublicConnection;
  emit(conn, () => console.log(`"${conn.name}" (${conn.id}) is now the default for ${conn.vendor}.`));
}

async function remove(ctx: CliContext, args: string[]): Promise<void> {
  const id = args[0];
  if (!id) throw new Error("usage: onegate connections rm <id>");
  await ctx.client().del(`/api/connections/${encodeURIComponent(id)}`);
  emit({ removed: id }, () => console.log(`Removed connection ${id}.`));
}

// ---- named app connection grants (default-deny authorization) ----

interface Grant {
  scope: string;
  subjectId: string;
  subjectName: string | null;
  createdAt: string;
}

/** Resolves the connection id and the grant subject (agent or project) from flags. */
function grantTarget(args: string[]): {
  connId: string;
  scope: "agent" | "project";
  subjectId: string;
} {
  const { values } = parseArgs({
    args,
    options: {
      id: { type: "string" },
      agent: { type: "string" },
      project: { type: "string" },
    },
  });
  const connId = values.id as string | undefined;
  const agent = values.agent as string | undefined;
  const project = values.project as string | undefined;
  if (!connId) throw new Error("--id <connectionId> is required");
  if ((agent && project) || (!agent && !project)) {
    throw new Error("give exactly one of --agent <id> or --project <id>");
  }
  return agent
    ? { connId, scope: "agent", subjectId: agent }
    : { connId, scope: "project", subjectId: project! };
}

async function grantsList(ctx: CliContext, args: string[]): Promise<void> {
  const { values } = parseArgs({ args, options: { id: { type: "string" } } });
  const id = values.id as string | undefined;
  if (!id) throw new Error("usage: onegate connections grants --id <connectionId>");
  const grants = (await ctx.client().get(
    `/api/connections/${encodeURIComponent(id)}/grants`,
  )) as Grant[];
  emit(grants, () => {
    if (!grants.length) {
      console.log(`connection ${id} is granted to no agent or project (default-deny: unusable).`);
      return;
    }
    console.log(`grants for connection ${id}:`);
    console.log(
      table(
        grants.map((g) => ({
          scope: g.scope,
          subject: g.subjectName ?? g.subjectId,
          subjectId: g.subjectId,
        })),
        [
          ["SCOPE", "scope"],
          ["SUBJECT", "subject"],
          ["SUBJECT ID", "subjectId"],
        ],
      ),
    );
  });
}

async function grant(ctx: CliContext, args: string[]): Promise<void> {
  let target;
  try {
    target = grantTarget(args);
  } catch (err) {
    throw new Error(
      `usage: onegate connections grant --id <connectionId> (--agent <id> | --project <id>)\n${(err as Error).message}`,
    );
  }
  const { connId, scope, subjectId } = target;
  await ctx.client().post(`/api/connections/${encodeURIComponent(connId)}/grants`, {
    scope,
    subjectId,
  });
  emit({ connectionId: connId, scope, subjectId, granted: true }, () =>
    console.log(`Granted connection ${connId} to ${scope} ${subjectId}.`),
  );
}

async function revoke(ctx: CliContext, args: string[]): Promise<void> {
  let target;
  try {
    target = grantTarget(args);
  } catch (err) {
    throw new Error(
      `usage: onegate connections revoke --id <connectionId> (--agent <id> | --project <id>)\n${(err as Error).message}`,
    );
  }
  const { connId, scope, subjectId } = target;
  await ctx
    .client()
    .del(
      `/api/connections/${encodeURIComponent(connId)}/grants/${encodeURIComponent(
        scope,
      )}/${encodeURIComponent(subjectId)}`,
    );
  emit({ connectionId: connId, scope, subjectId, revoked: true }, () =>
    console.log(`Revoked connection ${connId} from ${scope} ${subjectId}.`),
  );
}

export async function connectionsCommand(ctx: CliContext, sub: string, args: string[]): Promise<void> {
  if (sub === "list" || sub === "ls") return list(ctx);
  if (sub === "add") return add(ctx, args);
  if (sub === "set-default") return setDefault(ctx, args);
  if (sub === "rm" || sub === "remove" || sub === "delete") return remove(ctx, args);
  if (sub === "grants") return grantsList(ctx, args);
  if (sub === "grant") return grant(ctx, args);
  if (sub === "revoke") return revoke(ctx, args);
  throw new Error(
    `unknown connections command "${sub ?? ""}". Try: list, add, set-default, rm, grants, grant, revoke`,
  );
}

// ---- per-agent LLM routing (onegate agents llm ...) ----

interface LlmConfig {
  agentId: string;
  enabled: boolean;
  strategy: string;
  vendorStrategies?: Record<string, string>;
  connectionIds: string[];
  updatedAt: string | null;
}

/** Parse repeatable `--vendor-strategy vendor=strategy` flags into a map. */
function parseVendorStrategies(raw: string[]): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  for (const item of raw) {
    const eq = item.indexOf("=");
    if (eq <= 0) throw new Error(`--vendor-strategy must be "vendor=strategy", got "${item}"`);
    const vendor = item.slice(0, eq).trim();
    const strategy = item.slice(eq + 1).trim();
    if (!vendor) throw new Error(`--vendor-strategy is missing a vendor name in "${item}"`);
    if (strategy !== "fallback" && strategy !== "round-robin") {
      throw new Error(`--vendor-strategy for "${vendor}" must be "fallback" or "round-robin"`);
    }
    out[vendor] = strategy;
  }
  return Object.keys(out).length ? out : undefined;
}

async function llmGet(ctx: CliContext, agentId: string): Promise<void> {
  if (!agentId) throw new Error("usage: onegate agents llm get <agentId>");
  const cfg = (await ctx.client().get(`/api/agents/${encodeURIComponent(agentId)}/llm`)) as LlmConfig;
  emit(cfg, () => {
    console.log(`agent:       ${cfg.agentId}`);
    console.log(`enabled:     ${cfg.enabled}`);
    console.log(`strategy:    ${cfg.strategy}`);
    const vs = cfg.vendorStrategies ?? {};
    const vsKeys = Object.keys(vs);
    console.log(
      `per-vendor:  ${vsKeys.length ? vsKeys.map((v) => `${v}=${vs[v]}`).join(", ") : "- (all vendors use the strategy above)"}`,
    );
    console.log(`connections: ${cfg.connectionIds.length ? cfg.connectionIds.join(", ") : "-"}`);
    console.log(`updated:     ${cfg.updatedAt ?? "-"}`);
  });
}

async function llmSet(ctx: CliContext, agentId: string, args: string[]): Promise<void> {
  if (!agentId)
    throw new Error(
      "usage: onegate agents llm set <agentId> --strategy <s> --connections id1,id2 [--vendor-strategy vendor=s]... [--enabled|--disabled]",
    );
  const { values } = parseArgs({
    args,
    options: {
      enabled: { type: "boolean" },
      disabled: { type: "boolean" },
      strategy: { type: "string", default: "fallback" },
      // Repeatable per-vendor override. Omitting it clears any existing
      // overrides, matching how --connections replaces the whole list.
      "vendor-strategy": { type: "string", multiple: true, default: [] },
      connections: { type: "string", default: "" },
    },
  });
  if (values.strategy !== "fallback" && values.strategy !== "round-robin") {
    throw new Error('--strategy must be "fallback" or "round-robin"');
  }
  const connectionIds = (values.connections as string)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  // Default to enabled when neither flag is given (the common case for "set").
  const enabled = values.disabled === true ? false : values.enabled !== false;
  const vendorStrategies = parseVendorStrategies(values["vendor-strategy"] as string[]);
  const cfg = (await ctx.client().put(`/api/agents/${encodeURIComponent(agentId)}/llm`, {
    enabled,
    strategy: values.strategy,
    vendorStrategies,
    connectionIds,
  })) as LlmConfig;
  emit(cfg, () => {
    const vs = cfg.vendorStrategies ?? {};
    const vsText = Object.keys(vs).length
      ? ` per-vendor=[${Object.keys(vs)
          .map((v) => `${v}=${vs[v]}`)
          .join(", ")}]`
      : "";
    console.log(
      `LLM routing for ${cfg.agentId}: enabled=${cfg.enabled} strategy=${cfg.strategy}${vsText} connections=[${cfg.connectionIds.join(", ")}]`,
    );
  });
}

async function llmClear(ctx: CliContext, agentId: string): Promise<void> {
  if (!agentId) throw new Error("usage: onegate agents llm clear <agentId>");
  const cfg = (await ctx.client().put(`/api/agents/${encodeURIComponent(agentId)}/llm`, {
    enabled: false,
    strategy: "fallback",
    connectionIds: [],
  })) as LlmConfig;
  emit(cfg, () => console.log(`LLM routing cleared for ${cfg.agentId} (disabled, no connections).`));
}

export async function agentsLlmCommand(ctx: CliContext, verb: string, args: string[]): Promise<void> {
  const agentId = args[0];
  const rest = args.slice(1);
  if (verb === "get") return llmGet(ctx, agentId);
  if (verb === "set") return llmSet(ctx, agentId, rest);
  if (verb === "clear") return llmClear(ctx, agentId);
  throw new Error(`unknown "agents llm" command "${verb ?? ""}". Try: get, set, clear`);
}

// ---- per-agent app account selection (onegate agents apps ...) ----

interface AppConfig {
  integrationId: string;
  connectionId: string;
  updatedAt: string;
}

interface AgentAppsView {
  agentId: string;
  configs: AppConfig[];
  available: AppConnection[];
}

async function appsGet(ctx: CliContext, agentId: string): Promise<void> {
  if (!agentId) throw new Error("usage: onegate agents apps get <agentId>");
  const view = (await ctx.client().get(
    `/api/agents/${encodeURIComponent(agentId)}/apps`,
  )) as AgentAppsView;
  emit(view, () => {
    console.log(`agent: ${view.agentId}`);
    console.log("");
    if (!view.configs.length) {
      console.log("saved app account choices: none (each integration uses its default connection).");
    } else {
      console.log("saved app account choices:");
      const byId = new Map(view.available.map((c) => [c.id, c]));
      console.log(
        table(
          view.configs.map((c) => {
            const conn = byId.get(c.connectionId);
            return {
              integration: c.integrationId,
              connection: conn ? conn.name : c.connectionId,
              connectionId: c.connectionId,
            };
          }),
          [
            ["INTEGRATION", "integration"],
            ["CONNECTION", "connection"],
            ["CONNECTION ID", "connectionId"],
          ],
        ),
      );
    }
    console.log("");
    if (!view.available.length) {
      console.log("available app connections: none.");
      return;
    }
    console.log("available app connections (tenant-wide plus this agent's own):");
    console.log(
      table(
        view.available.map((c) => ({
          id: c.id,
          integration: c.vendor,
          name: c.name,
          scope: c.ownerAgentId ? `agent: ${c.ownerAgentName ?? c.ownerAgentId}` : "tenant-wide",
          isDefault: c.isDefault,
        })),
        [
          ["ID", "id"],
          ["INTEGRATION", "integration"],
          ["NAME", "name"],
          ["SCOPE", "scope"],
          ["DEFAULT", "isDefault"],
        ],
      ),
    );
  });
}

async function appsSet(ctx: CliContext, agentId: string, args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { connection: { type: "string" } },
  });
  const integrationId = positionals[0];
  const connectionId = values.connection;
  if (!agentId || !integrationId || !connectionId) {
    throw new Error("usage: onegate agents apps set <agentId> <integrationId> --connection <id>");
  }
  const res = (await ctx.client().put(
    `/api/agents/${encodeURIComponent(agentId)}/apps/${encodeURIComponent(integrationId)}`,
    { connectionId },
  )) as AppConfig & { agentId: string };
  emit(res, () =>
    console.log(`agent ${res.agentId} will use connection ${res.connectionId} for ${res.integrationId}.`),
  );
}

async function appsClear(ctx: CliContext, agentId: string, args: string[]): Promise<void> {
  const integrationId = args[0];
  if (!agentId || !integrationId) {
    throw new Error("usage: onegate agents apps clear <agentId> <integrationId>");
  }
  const res = (await ctx.client().put(
    `/api/agents/${encodeURIComponent(agentId)}/apps/${encodeURIComponent(integrationId)}`,
    { connectionId: null },
  )) as { agentId: string; integrationId: string; connectionId: string | null };
  emit(res, () =>
    console.log(`Cleared ${res.integrationId} choice for agent ${res.agentId} (will use the default connection).`),
  );
}

export async function agentsAppsCommand(ctx: CliContext, verb: string, args: string[]): Promise<void> {
  const agentId = args[0];
  const rest = args.slice(1);
  if (verb === "get") return appsGet(ctx, agentId);
  if (verb === "set") return appsSet(ctx, agentId, rest);
  if (verb === "clear") return appsClear(ctx, agentId, rest);
  throw new Error(`unknown "agents apps" command "${verb ?? ""}". Try: get, set, clear`);
}

// ---- per-agent owner notify webhook (onegate agents notify ...) ----

interface NotifyConfig {
  agentId: string;
  webhookUrl: string | null;
}

async function notifyGet(ctx: CliContext, agentId: string): Promise<void> {
  if (!agentId) throw new Error("usage: onegate agents notify get <agentId>");
  const cfg = (await ctx.client().get(`/api/agents/${encodeURIComponent(agentId)}/notify`)) as NotifyConfig;
  emit(cfg, () => {
    console.log(`agent:      ${cfg.agentId}`);
    console.log(`webhook:    ${cfg.webhookUrl ?? "(not set)"}`);
  });
}

async function notifySet(ctx: CliContext, agentId: string, args: string[]): Promise<void> {
  if (!agentId) throw new Error("usage: onegate agents notify set <agentId> --url <webhookUrl>");
  const { values } = parseArgs({
    args,
    options: { url: { type: "string" } },
  });
  if (!values.url) throw new Error("usage: onegate agents notify set <agentId> --url <webhookUrl>");
  const cfg = (await ctx.client().put(`/api/agents/${encodeURIComponent(agentId)}/notify`, {
    webhookUrl: values.url,
  })) as NotifyConfig;
  emit(cfg, () => console.log(`Notify webhook for ${cfg.agentId} set.`));
}

async function notifyClear(ctx: CliContext, agentId: string): Promise<void> {
  if (!agentId) throw new Error("usage: onegate agents notify clear <agentId>");
  await ctx.client().del(`/api/agents/${encodeURIComponent(agentId)}/notify`);
  emit({ cleared: agentId }, () => console.log(`Notify webhook for ${agentId} cleared.`));
}

export async function agentsNotifyCommand(ctx: CliContext, verb: string, args: string[]): Promise<void> {
  const agentId = args[0];
  const rest = args.slice(1);
  if (verb === "get") return notifyGet(ctx, agentId);
  if (verb === "set") return notifySet(ctx, agentId, rest);
  if (verb === "clear") return notifyClear(ctx, agentId);
  throw new Error(`unknown "agents notify" command "${verb ?? ""}". Try: get, set, clear`);
}
