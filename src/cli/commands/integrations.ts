/**
 * M3: integrations (list + OAuth connect URL) and credentials (set/rm).
 *
 *   onegate integrations list
 *   onegate integrations connect <id> --client-id X --client-secret-stdin --redirect-base URL [--scopes a,b]
 *   onegate credentials set <integrationId> --name N --data-stdin [key]
 *   onegate credentials rm <integrationId>
 *
 * OAuth connect is browser-only by design: the CLI starts the flow and prints
 * the URL for the operator to open. It never completes OAuth headlessly.
 *
 * Secret material should be piped in via the --*-stdin flags. The legacy
 * argv-bearing forms (--client-secret, --data k=v) still work but expose the
 * secret in `ps`, /proc/<pid>/cmdline and shell history.
 */

import { parseArgs } from "node:util";
import { emit, table } from "../output.js";
import {
  parseDataPairs,
  readDataPairsFromStdin,
  readRequiredSecretFromStdin,
  rejectDuplicateSecretInput,
} from "../secret-input.js";
import type { CliContext } from "../context.js";

interface IntegrationView {
  id: string;
  title: string;
  category: string;
  connected: boolean;
  credentialName: string | null;
  orphaned: boolean;
  llm: { vendor: string } | null;
  leaseDefaultSeconds: number | null;
}

/** "8h" / "1800s" / "-" for a lease default. */
function fmtLease(seconds: number | null | undefined): string {
  if (!seconds) return "-";
  return seconds % 3600 === 0 ? `${seconds / 3600}h` : `${seconds}s`;
}

/** Parses a lease flag: bare seconds, or "Nh"/"Nm" shorthand. */
function parseLease(v: string): number {
  const m = v.trim().match(/^(\d+)\s*(h|m|s)?$/i);
  if (!m) throw new Error(`invalid duration "${v}" (use seconds, or "8h" / "30m")`);
  const n = Number(m[1]);
  const unit = (m[2] ?? "s").toLowerCase();
  return unit === "h" ? n * 3600 : unit === "m" ? n * 60 : n;
}

async function list(ctx: CliContext): Promise<void> {
  const items = (await ctx.client().get("/api/integrations")) as IntegrationView[];
  emit(items, () => {
    if (!items.length) {
      console.log("no integrations.");
      return;
    }
    const rows = items.map((i) => ({
      id: i.id,
      title: i.title,
      category: i.category,
      connected: i.connected,
      llm: i.llm ? i.llm.vendor : "-",
      timebox: fmtLease(i.leaseDefaultSeconds),
    }));
    console.log(
      table(rows, [
        ["ID", "id"],
        ["TITLE", "title"],
        ["CATEGORY", "category"],
        ["CONNECTED", "connected"],
        ["LLM", "llm"],
        ["TIMEBOX", "timebox"],
      ]),
    );
  });
}

async function connect(ctx: CliContext, args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      "client-id": { type: "string" },
      "client-secret": { type: "string" },
      "client-secret-stdin": { type: "boolean", default: false },
      "redirect-base": { type: "string" },
      scopes: { type: "string" },
    },
  });
  const id = positionals[0];
  if (!id || !values["client-id"] || !values["redirect-base"]) {
    throw new Error(
      "usage: onegate integrations connect <id> --client-id X (--client-secret-stdin | --client-secret Y) --redirect-base URL [--scopes a,b]",
    );
  }
  rejectDuplicateSecretInput(
    "--client-secret",
    "--client-secret-stdin",
    values["client-secret"] !== undefined,
    values["client-secret-stdin"] === true,
  );
  const clientSecret =
    values["client-secret-stdin"] === true
      ? await readRequiredSecretFromStdin("client secret")
      : ((values["client-secret"] as string | undefined) ?? "");
  const body: Record<string, unknown> = {
    clientId: values["client-id"],
    clientSecret,
    redirectBase: values["redirect-base"],
  };
  if (values.scopes) {
    body.scopes = (values.scopes as string).split(",").map((s) => s.trim()).filter(Boolean);
  }
  const res = (await ctx.client().post(`/api/integrations/${encodeURIComponent(id)}/oauth/start`, body)) as {
    url: string;
    redirectUri: string;
  };
  emit(res, () => {
    console.log("Open this URL in a browser to authorize (OAuth completes in the browser, not the CLI):");
    console.log("");
    console.log(res.url);
    console.log("");
    console.log(`Redirect URI registered: ${res.redirectUri}`);
  });
}

/**
 * Manage an integration's default access lease (time-box):
 *   onegate integrations lease list
 *   onegate integrations lease set <id> <duration>   (e.g. 8h, 30m, 3600)
 *   onegate integrations lease clear <id>
 */
async function lease(ctx: CliContext, args: string[]): Promise<void> {
  const verb = args[0];
  if (!verb || verb === "list" || verb === "ls") {
    const rows = (await ctx.client().get("/api/integration-leases")) as Array<{
      integrationId: string;
      ttlSeconds: number;
    }>;
    emit(rows, () => {
      if (!rows.length) {
        console.log("no time-boxed integrations.");
        return;
      }
      console.log(
        table(
          rows.map((r) => ({ id: r.integrationId, ttl: fmtLease(r.ttlSeconds) })),
          [
            ["INTEGRATION", "id"],
            ["DEFAULT TIMEBOX", "ttl"],
          ],
        ),
      );
    });
    return;
  }
  if (verb === "set") {
    const id = args[1];
    const dur = args[2];
    if (!id || !dur) throw new Error("usage: onegate integrations lease set <id> <duration>");
    const ttlSeconds = parseLease(dur);
    const res = (await ctx
      .client()
      .put(`/api/integration-leases/${encodeURIComponent(id)}`, { ttlSeconds })) as {
      integrationId: string;
      ttlSeconds: number | null;
    };
    emit(res, () => console.log(`${res.integrationId} is time-boxed, default ${fmtLease(res.ttlSeconds)}.`));
    return;
  }
  if (verb === "clear" || verb === "rm") {
    const id = args[1];
    if (!id) throw new Error("usage: onegate integrations lease clear <id>");
    await ctx.client().del(`/api/integration-leases/${encodeURIComponent(id)}`);
    emit({ integrationId: id, ttlSeconds: null }, () =>
      console.log(`${id} is now a regular (non-time-boxed) integration.`),
    );
    return;
  }
  throw new Error(`unknown integrations lease command "${verb}". Try: list, set, clear`);
}

export async function integrationsCommand(ctx: CliContext, sub: string, args: string[]): Promise<void> {
  if (sub === "list" || sub === "ls") return list(ctx);
  if (sub === "connect") return connect(ctx, args);
  if (sub === "lease") return lease(ctx, args);
  throw new Error(`unknown integrations command "${sub ?? ""}". Try: list, connect, lease`);
}

// ---- credentials ----

async function credentialsSet(ctx: CliContext, args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      name: { type: "string" },
      data: { type: "string", multiple: true, default: [] },
      "data-stdin": { type: "boolean", default: false },
    },
  });
  const integrationId = positionals[0];
  if (!integrationId) {
    throw new Error(
      "usage: onegate credentials set <integrationId> --name N (--data-stdin [key] | --data k=v [--data k=v...])",
    );
  }
  const pairs = values.data as string[];
  const fromStdin = values["data-stdin"] === true;
  rejectDuplicateSecretInput("--data", "--data-stdin", pairs.length > 0, fromStdin);
  if (!fromStdin && !pairs.length) {
    throw new Error("at least one --data k=v is required (prefer --data-stdin, --data exposes the secret in ps and shell history)");
  }
  // `--data-stdin [key]` may name a sole key, letting the caller pipe the raw
  // secret with no key=value framing at all.
  const data = fromStdin ? await readDataPairsFromStdin(positionals[1]) : parseDataPairs(pairs);
  const res = (await ctx.client().put(`/api/credentials/${encodeURIComponent(integrationId)}`, {
    name: values.name ?? integrationId,
    data,
  })) as { id: string; integrationId: string; name: string };
  // Never echo the secret values back.
  emit({ id: res.id, integrationId: res.integrationId, name: res.name }, () =>
    console.log(`Credential set for ${res.integrationId} ("${res.name}").`),
  );
}

async function credentialsRm(ctx: CliContext, args: string[]): Promise<void> {
  const integrationId = args[0];
  if (!integrationId) throw new Error("usage: onegate credentials rm <integrationId>");
  await ctx.client().del(`/api/credentials/${encodeURIComponent(integrationId)}`);
  emit({ removed: integrationId }, () => console.log(`Removed credential for ${integrationId}.`));
}

export async function credentialsCommand(ctx: CliContext, sub: string, args: string[]): Promise<void> {
  if (sub === "set" || sub === "add") return credentialsSet(ctx, args);
  if (sub === "rm" || sub === "remove" || sub === "delete") return credentialsRm(ctx, args);
  throw new Error(`unknown credentials command "${sub ?? ""}". Try: set, rm`);
}
