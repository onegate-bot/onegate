/**
 * M5: projects CRUD over the admin API.
 *
 *   onegate projects list
 *   onegate projects add <name>
 *   onegate projects rm <id>
 */

import { emit, table } from "../output.js";
import type { CliContext } from "../context.js";

interface Project {
  id: string;
  name: string;
  createdAt: string;
}

async function list(ctx: CliContext): Promise<void> {
  const projects = (await ctx.client().get("/api/projects")) as Project[];
  emit(projects, () => {
    if (!projects.length) {
      console.log("no projects.");
      return;
    }
    console.log(
      table(projects as unknown as Array<Record<string, unknown>>, [
        ["ID", "id"],
        ["NAME", "name"],
        ["CREATED", "createdAt"],
      ]),
    );
  });
}

async function add(ctx: CliContext, args: string[]): Promise<void> {
  const name = args[0];
  if (!name) throw new Error("usage: onegate projects add <name>");
  const project = (await ctx.client().post("/api/projects", { name })) as Project;
  emit(project, () => console.log(`Project "${project.name}" created (${project.id}).`));
}

async function remove(ctx: CliContext, args: string[]): Promise<void> {
  const id = args[0];
  if (!id) throw new Error("usage: onegate projects rm <id>");
  await ctx.client().del(`/api/projects/${encodeURIComponent(id)}`);
  emit({ removed: id }, () => console.log(`Removed project ${id}.`));
}

export async function projectsCommand(ctx: CliContext, sub: string, args: string[]): Promise<void> {
  if (sub === "list" || sub === "ls") return list(ctx);
  if (sub === "add") return add(ctx, args);
  if (sub === "rm" || sub === "remove" || sub === "delete") return remove(ctx, args);
  throw new Error(`unknown projects command "${sub ?? ""}". Try: list, add, rm`);
}
