/**
 * M2: agents CRUD parity over the admin API.
 *
 *   onegate agents list
 *   onegate agents add <name> [--policy allow-all|deny-unmatched] [--project <id>]
 *   onegate agents rename <id> <newName>
 *   onegate agents rm <id>
 *   onegate agents rotate-token <id>
 *
 * (The legacy `onegate agent add|list` local-store commands stay for bootstrap.)
 */

import { parseArgs } from "node:util";
import { emit, table } from "../output.js";
import type { CliContext } from "../context.js";

interface PublicAgent {
  id: string;
  name: string;
  projectId: string | null;
  defaultPolicy: string;
  createdAt: string;
}

async function list(ctx: CliContext): Promise<void> {
  const agents = (await ctx.client().get("/api/agents")) as PublicAgent[];
  emit(agents, () => {
    if (!agents.length) {
      console.log("no agents.");
      return;
    }
    console.log(
      table(agents as unknown as Array<Record<string, unknown>>, [
        ["ID", "id"],
        ["NAME", "name"],
        ["POLICY", "defaultPolicy"],
        ["PROJECT", "projectId"],
      ]),
    );
  });
}

async function add(ctx: CliContext, args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      policy: { type: "string", default: "deny-unmatched" },
      project: { type: "string" },
    },
  });
  const name = positionals[0];
  if (!name) throw new Error("usage: onegate agents add <name> [--policy allow-all|deny-unmatched] [--project <id>]");
  if (values.policy !== "allow-all" && values.policy !== "deny-unmatched") {
    throw new Error("--policy must be allow-all or deny-unmatched");
  }
  const res = (await ctx.client().post("/api/agents", {
    name,
    defaultPolicy: values.policy,
    projectId: values.project ?? null,
  })) as PublicAgent & { token: string };
  emit(res, () => {
    console.log(`Agent "${res.name}" created (${res.id}, default: ${res.defaultPolicy}).`);
    console.log(`Token (shown ONCE): ${res.token}`);
  });
}

async function rename(ctx: CliContext, args: string[]): Promise<void> {
  const [id, name] = args;
  if (!id || !name) throw new Error("usage: onegate agents rename <id> <newName>");
  const res = (await ctx.client().patch(`/api/agents/${encodeURIComponent(id)}`, { name })) as PublicAgent;
  emit(res, () => console.log(`Agent ${res.id} renamed to "${res.name}".`));
}

async function remove(ctx: CliContext, args: string[]): Promise<void> {
  const id = args[0];
  if (!id) throw new Error("usage: onegate agents rm <id>");
  await ctx.client().del(`/api/agents/${encodeURIComponent(id)}`);
  emit({ removed: id }, () => console.log(`Removed agent ${id}.`));
}

async function rotateToken(ctx: CliContext, args: string[]): Promise<void> {
  const id = args[0];
  if (!id) throw new Error("usage: onegate agents rotate-token <id>");
  const res = (await ctx.client().post(`/api/agents/${encodeURIComponent(id)}/rotate-token`)) as {
    token: string;
  };
  emit(res, () => {
    console.log(`New token for ${id} (shown ONCE): ${res.token}`);
    console.log("The previous token is now invalid.");
  });
}

export async function agentsCommand(ctx: CliContext, sub: string, args: string[]): Promise<void> {
  if (sub === "list" || sub === "ls") return list(ctx);
  if (sub === "add") return add(ctx, args);
  if (sub === "rename") return rename(ctx, args);
  if (sub === "rm" || sub === "remove" || sub === "delete") return remove(ctx, args);
  if (sub === "rotate-token") return rotateToken(ctx, args);
  throw new Error(`unknown agents command "${sub ?? ""}". Try: list, add, rename, rm, rotate-token, llm`);
}
