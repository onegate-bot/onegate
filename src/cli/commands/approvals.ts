/**
 * U5: held requests raised by `require_approval` rules.
 *
 *   onegate approvals list [--agent <id>]
 *   onegate approvals approve <id>
 *   onegate approvals reject <id>
 *   printf %s "$PIN" | onegate approvals pin set
 *   onegate approvals pin clear | status
 *
 * The PIN is the owner's second factor on approve/renew links when the
 * gateway runs with ONEGATE_AGENT_RELAYS_OWNER_LINKS (links go to the agent).
 * It is read from stdin so it never lands in shell history or `ps`.
 *
 * The owner's one-tap link (`/approve/:token`) is the primary surface; this is
 * the operator equivalent. Both go through the same single-use transition, so
 * an approval that is no longer pending is refused here too.
 */

import { parseArgs } from "node:util";
import { emit, table } from "../output.js";
import type { CliContext } from "../context.js";
import { readRequiredSecretFromStdin } from "../secret-input.js";

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
        ["HOST", "host"],
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

interface PinState {
  set: boolean;
  required: boolean;
}

async function pin(ctx: CliContext, args: string[]): Promise<void> {
  const verb = args[0];
  let state: PinState;
  if (verb === "set") {
    const value = await readRequiredSecretFromStdin("PIN");
    state = (await ctx.client().put("/api/settings/owner-pin", { pin: value })) as PinState;
  } else if (verb === "clear") {
    state = (await ctx.client().del("/api/settings/owner-pin")) as PinState;
  } else if (verb === "status") {
    state = (await ctx.client().get("/api/settings/owner-pin")) as PinState;
  } else {
    throw new Error('usage: printf %s "$PIN" | onegate approvals pin set | onegate approvals pin clear | onegate approvals pin status');
  }
  emit(state, () =>
    console.log(
      `Owner PIN: ${state.set ? "set" : "not set"}. ` +
        (state.required
          ? "Approve/renew links require it (ONEGATE_AGENT_RELAYS_OWNER_LINKS is on)."
          : "Links go to the owner only, so they do not ask for it (ONEGATE_AGENT_RELAYS_OWNER_LINKS is off)."),
    ),
  );
}

export async function approvalsCommand(ctx: CliContext, sub: string, args: string[]): Promise<void> {
  if (sub === "list" || sub === "ls") return list(ctx, args);
  if (sub === "approve") return decide(ctx, "approve", args);
  if (sub === "reject") return decide(ctx, "reject", args);
  if (sub === "pin") return pin(ctx, args);
  throw new Error(`unknown approvals command "${sub ?? ""}". Try: list, approve, reject, pin`);
}
