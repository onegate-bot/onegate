/**
 * M2: policy rules CRUD over the admin API.
 *
 *   onegate rules list
 *   onegate rules add --scope agent|project --subject <id> --integration <id>
 *                     --effect allow|deny [--methods GET,POST] [--path /**]
 *   onegate rules rm <id>
 */

import { parseArgs } from "node:util";
import { emit, table } from "../output.js";
import type { CliContext } from "../context.js";

interface Rule {
  id: string;
  scope: string;
  subjectId: string;
  integrationId: string;
  methods: string[];
  pathGlob: string;
  effect: string;
  expiresAt?: string | null;
  leaseTtlSeconds?: number | null;
  connectionId?: string | null;
  connectionScope?: "only" | "except";
}

/** Human summary of a rule's access lease for the LEASE column. */
function leaseCell(r: Rule): string {
  if (!r.leaseTtlSeconds) return "-";
  const hrs = r.leaseTtlSeconds % 3600 === 0 ? `${r.leaseTtlSeconds / 3600}h` : `${r.leaseTtlSeconds}s`;
  if (!r.expiresAt) return hrs;
  const expired = Date.parse(r.expiresAt) <= Date.now();
  return `${hrs} ${expired ? "(expired)" : "until " + r.expiresAt}`;
}

async function list(ctx: CliContext): Promise<void> {
  const rules = (await ctx.client().get("/api/rules")) as Rule[];
  emit(rules, () => {
    if (!rules.length) {
      console.log("no rules.");
      return;
    }
    const withLease = rules.map((r) => ({
      ...r,
      lease: leaseCell(r),
      connection: r.connectionScope ? `${r.connectionScope} ${r.connectionId}` : "-",
    }));
    console.log(
      table(withLease as unknown as Array<Record<string, unknown>>, [
        ["ID", "id"],
        ["SCOPE", "scope"],
        ["SUBJECT", "subjectId"],
        ["INTEGRATION", "integrationId"],
        ["METHODS", "methods"],
        ["PATH", "pathGlob"],
        ["EFFECT", "effect"],
        ["CONNECTION", "connection"],
        ["LEASE", "lease"],
      ]),
    );
  });
}

async function add(ctx: CliContext, args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      scope: { type: "string" },
      subject: { type: "string" },
      integration: { type: "string" },
      effect: { type: "string" },
      methods: { type: "string", default: "*" },
      path: { type: "string", default: "/**" },
      ttl: { type: "string" },
      connection: { type: "string" },
      "connection-scope": { type: "string" },
    },
  });
  if (!values.scope || !values.subject || !values.integration || !values.effect) {
    throw new Error(
      "usage: onegate rules add --scope agent|project --subject <id> --integration <id> --effect allow|deny [--methods GET,POST] [--path /**] [--ttl <seconds|Nh>] [--connection <conn-id> --connection-scope only|except]",
    );
  }
  const connectionScope = values["connection-scope"] as string | undefined;
  if (connectionScope != null && connectionScope !== "only" && connectionScope !== "except") {
    throw new Error(`invalid --connection-scope "${connectionScope}" (use "only" or "except")`);
  }
  if (connectionScope != null && !values.connection) {
    throw new Error("--connection-scope requires --connection <conn-id>");
  }
  if (values.connection && connectionScope == null) {
    throw new Error("--connection requires --connection-scope only|except");
  }
  const methods = (values.methods as string)
    .split(",")
    .map((m) => m.trim())
    .filter(Boolean);
  const ttlSeconds = values.ttl != null ? parseTtl(values.ttl as string) : undefined;
  const rule = (await ctx.client().post("/api/rules", {
    scope: values.scope,
    subjectId: values.subject,
    integrationId: values.integration,
    effect: values.effect,
    methods,
    pathGlob: values.path,
    ...(ttlSeconds != null ? { ttlSeconds } : {}),
    ...(values.connection ? { connectionId: values.connection, connectionScope } : {}),
  })) as Rule;
  emit(rule, () =>
    console.log(
      `Rule ${rule.id}: ${rule.effect} ${rule.scope}:${rule.subjectId} -> ${rule.integrationId} ${rule.methods.join(",")} ${rule.pathGlob}${rule.connectionScope ? ` [connection ${rule.connectionScope} ${rule.connectionId}]` : ""}${rule.leaseTtlSeconds ? ` [lease ${leaseCell(rule)}]` : ""}`,
    ),
  );
}

/** Parses a TTL flag: bare seconds, or an "Nh"/"Nm" shorthand. */
function parseTtl(v: string): number {
  const m = v.trim().match(/^(\d+)\s*(h|m|s)?$/i);
  if (!m) throw new Error(`invalid --ttl "${v}" (use seconds, or "8h" / "30m")`);
  const n = Number(m[1]);
  const unit = (m[2] ?? "s").toLowerCase();
  return unit === "h" ? n * 3600 : unit === "m" ? n * 60 : n;
}

async function renew(ctx: CliContext, args: string[]): Promise<void> {
  const id = args[0];
  if (!id) throw new Error("usage: onegate rules renew <id>");
  const rule = (await ctx.client().post(`/api/rules/${encodeURIComponent(id)}/renew`, {})) as Rule;
  emit(rule, () => console.log(`Renewed rule ${rule.id}: lease ${leaseCell(rule)}`));
}

async function remove(ctx: CliContext, args: string[]): Promise<void> {
  const id = args[0];
  if (!id) throw new Error("usage: onegate rules rm <id>");
  await ctx.client().del(`/api/rules/${encodeURIComponent(id)}`);
  emit({ removed: id }, () => console.log(`Removed rule ${id}.`));
}

export async function rulesCommand(ctx: CliContext, sub: string, args: string[]): Promise<void> {
  if (sub === "list" || sub === "ls") return list(ctx);
  if (sub === "add") return add(ctx, args);
  if (sub === "renew") return renew(ctx, args);
  if (sub === "rm" || sub === "remove" || sub === "delete") return remove(ctx, args);
  throw new Error(`unknown rules command "${sub ?? ""}". Try: list, add, renew, rm`);
}
