/**
 * U5: held requests raised by `require_approval` rules.
 *
 *   onegate approvals list [--agent <id>]
 *   onegate approvals approve <id>
 *   onegate approvals reject <id>
 *
 * The owner's one-tap link (`/approve/:token`) is the primary surface; this is
 * the operator equivalent. Both go through the same single-use transition, so
 * an approval that is no longer pending is refused here too.
 */

import { parseArgs } from "node:util";
import { emit, table } from "../output.js";
import type { CliContext } from "../context.js";

interface Approval {
  id: string;
  agentId: string;
  integrationId: string;
  ruleId: string;
  method: string;
  path: string;
  status: string;
  createdAt: string;
  expiresAt: string;
  decidedAt?: string | null;
}

async function list(ctx: CliContext, args: string[]): Promise<void> {
  const { values } = parseArgs({ args, options: { agent: { type: "string" } } });
  const qs = values.agent ? `?agentId=${encodeURIComponent(values.agent as string)}` : "";
  const approvals = (await ctx.client().get(`/api/approvals${qs}`)) as Approval[];
  emit(approvals, () => {
    if (!approvals.length) {
      console.log("no approvals.");
      return;
    }
    console.log(
      table(approvals as unknown as Array<Record<string, unknown>>, [
        ["ID", "id"],
        ["AGENT", "agentId"],
        ["INTEGRATION", "integrationId"],
        ["METHOD", "method"],
        ["PATH", "path"],
        ["STATUS", "status"],
        ["EXPIRES", "expiresAt"],
      ]),
    );
  });
}

async function decide(ctx: CliContext, verb: "approve" | "reject", args: string[]): Promise<void> {
  const id = args[0];
  if (!id) throw new Error(`usage: onegate approvals ${verb} <id>`);
  const approval = (await ctx
    .client()
    .post(`/api/approvals/${encodeURIComponent(id)}/${verb}`, {})) as Approval;
  emit(approval, () => console.log(`Approval ${approval.id}: ${approval.status}.`));
}

export async function approvalsCommand(ctx: CliContext, sub: string, args: string[]): Promise<void> {
  if (sub === "list" || sub === "ls") return list(ctx, args);
  if (sub === "approve") return decide(ctx, "approve", args);
  if (sub === "reject") return decide(ctx, "reject", args);
  throw new Error(`unknown approvals command "${sub ?? ""}". Try: list, approve, reject`);
}
