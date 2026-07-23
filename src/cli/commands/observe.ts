/**
 * M4: read-only observability.
 *
 *   onegate audit [--agent <id>] [--limit N]
 *   onegate usage [--since ISO] [--until ISO] [--limit N]
 */

import { parseArgs } from "node:util";
import { emit, table } from "../output.js";
import type { CliContext } from "../context.js";

interface AuditRow {
  ts: string;
  agentName: string | null;
  integrationId: string | null;
  host: string;
  method: string | null;
  path: string | null;
  decision: string;
  status: number | null;
  llmConnectionName: string | null;
}

export async function auditCommand(ctx: CliContext, args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      agent: { type: "string" },
      limit: { type: "string" },
    },
  });
  const qs = new URLSearchParams();
  if (values.agent) qs.set("agentId", values.agent as string);
  if (values.limit) qs.set("limit", values.limit as string);
  const path = `/api/audit${qs.toString() ? `?${qs.toString()}` : ""}`;
  const rows = (await ctx.client().get(path)) as AuditRow[];
  emit(rows, () => {
    if (!rows.length) {
      console.log("no audit rows.");
      return;
    }
    console.log(
      table(rows as unknown as Array<Record<string, unknown>>, [
        ["TS", "ts"],
        ["AGENT", "agentName"],
        ["HOST", "host"],
        ["METHOD", "method"],
        ["PATH", "path"],
        ["DECISION", "decision"],
        ["STATUS", "status"],
        ["CONNECTION", "llmConnectionName"],
      ]),
    );
  });
}

interface UsageResponse {
  since: string;
  until: string | null;
  connections: Array<{
    connectionId: string;
    connectionName: string | null;
    vendor: string | null;
    requests: number;
    errors: number;
    failovers: number;
    inputTokens: number;
    outputTokens: number;
  }>;
  vendors: Array<{
    vendor: string | null;
    requests: number;
    errors: number;
    failovers: number;
    inputTokens: number;
    outputTokens: number;
  }>;
  turnEstimate?: { estimated: boolean; gapMs: number };
  models: Array<{
    vendor: string | null;
    model: string | null;
    requests: number;
    errors: number;
    failovers: number;
    inputTokens: number;
    outputTokens: number;
    estimatedTurns?: number;
  }>;
  bots: Array<{
    agentId: string | null;
    agentName: string | null;
    vendor: string | null;
    model: string | null;
    requests: number;
    errors: number;
    inputTokens: number;
    outputTokens: number;
    estimatedTurns?: number;
  }>;
  recent: unknown[];
}

export async function usageCommand(ctx: CliContext, args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      since: { type: "string" },
      until: { type: "string" },
      limit: { type: "string" },
    },
  });
  const qs = new URLSearchParams();
  if (values.since) qs.set("since", values.since as string);
  if (values.until) qs.set("until", values.until as string);
  if (values.limit) qs.set("limit", values.limit as string);
  const path = `/api/usage${qs.toString() ? `?${qs.toString()}` : ""}`;
  const res = (await ctx.client().get(path)) as UsageResponse;
  emit(res, () => {
    console.log(`Usage since ${res.since}${res.until ? ` until ${res.until}` : ""}`);
    console.log("");
    console.log("By connection:");
    if (!res.connections.length) {
      console.log("  (none)");
    } else {
      console.log(
        table(res.connections as unknown as Array<Record<string, unknown>>, [
          ["CONNECTION", "connectionName"],
          ["VENDOR", "vendor"],
          ["REQUESTS", "requests"],
          ["ERRORS", "errors"],
          ["FAILOVERS", "failovers"],
          ["IN TOK", "inputTokens"],
          ["OUT TOK", "outputTokens"],
        ]),
      );
    }
    console.log("");
    console.log("By vendor:");
    if (!res.vendors.length) {
      console.log("  (none)");
    } else {
      console.log(
        table(res.vendors as unknown as Array<Record<string, unknown>>, [
          ["VENDOR", "vendor"],
          ["REQUESTS", "requests"],
          ["ERRORS", "errors"],
          ["FAILOVERS", "failovers"],
          ["IN TOK", "inputTokens"],
          ["OUT TOK", "outputTokens"],
        ]),
      );
    }
    console.log("");
    console.log("By model:");
    if (!res.models?.length) {
      console.log("  (none)");
    } else {
      console.log(
        table(
          res.models.map((m) => ({
            ...m,
            model: m.model ?? "(unknown)",
            estimatedTurns: m.estimatedTurns ?? 0,
          })) as unknown as Array<Record<string, unknown>>,
          [
            ["VENDOR", "vendor"],
            ["MODEL", "model"],
            ["REQUESTS", "requests"],
            ["EST TURNS", "estimatedTurns"],
            ["ERRORS", "errors"],
            ["IN TOK", "inputTokens"],
            ["OUT TOK", "outputTokens"],
          ],
        ),
      );
    }
    console.log("");
    console.log("By bot + model:");
    if (!res.bots?.length) {
      console.log("  (none)");
    } else {
      console.log(
        table(
          res.bots.map((b) => ({
            ...b,
            bot: b.agentName ?? "(unknown)",
            model: b.model ?? "(unknown)",
            estimatedTurns: b.estimatedTurns ?? 0,
          })) as unknown as Array<Record<string, unknown>>,
          [
            ["BOT", "bot"],
            ["VENDOR", "vendor"],
            ["MODEL", "model"],
            ["REQUESTS", "requests"],
            ["EST TURNS", "estimatedTurns"],
            ["ERRORS", "errors"],
            ["IN TOK", "inputTokens"],
            ["OUT TOK", "outputTokens"],
          ],
        ),
      );
    }
    console.log("");
    console.log(
      `EST TURNS = estimated conversational turns, inferred from request gaps (>${Math.round(
        (res.turnEstimate?.gapMs ?? 60_000) / 1000,
      )}s = new turn). Approximate, not exact.`,
    );
  });
}
