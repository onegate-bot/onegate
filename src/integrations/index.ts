/**
 * Builds the integration registry: built-ins plus any community
 * integrations dropped into `integrations/community/` (each file default-
 * exports an Integration, see community/README.md).
 */

import { readdirSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { Registry, type Integration } from "./types.js";
import { github } from "./github.js";
import { google } from "./google.js";
import { gemini } from "./gemini.js";
import { gcp } from "./gcp.js";
import { aws } from "./aws.js";
import { slack } from "./slack.js";
import { openai } from "./openai.js";
import { anthropic } from "./anthropic.js";
import { jira } from "./jira.js";
import { notion } from "./notion.js";
import { linear } from "./linear.js";
import { stripe } from "./stripe.js";
import { sendgrid } from "./sendgrid.js";
import { braveSearch } from "./brave-search.js";
import { tavily } from "./tavily.js";
import { telegramBot } from "./telegram-bot.js";
import { discord } from "./discord.js";
import { huggingface } from "./huggingface.js";
import { gitlab } from "./gitlab.js";
import { confluence } from "./confluence.js";
import { dropbox } from "./dropbox.js";
import { cloudflare } from "./cloudflare.js";
import { flyio } from "./flyio.js";
import { hetzner } from "./hetzner.js";
import { vercel } from "./vercel.js";
import { supabase } from "./supabase.js";
import { resend } from "./resend.js";
import { todoist } from "./todoist.js";
import { trello } from "./trello.js";
import { monday } from "./monday.js";
import { linkedin } from "./linkedin.js";
import { mongodbAtlas } from "./mongodb-atlas.js";
import { docker } from "./docker.js";
import { jfrogArtifactory } from "./jfrog-artifactory.js";
import { githubApp } from "./github-app.js";
import { elevenlabs } from "./elevenlabs.js";
import { openrouter } from "./openrouter.js";
import { make } from "./make.js";

/**
 * Built-ins. Array order does NOT decide which integration owns a host:
 * `Registry.resolveHostCandidates` ranks claims by specificity, so an exact
 * host claim always beats a dot-suffix claim and a longer suffix beats a
 * shorter one. Reordering this array cannot silently re-route a host (and
 * therefore change which credential gets injected).
 *  - google's and gemini's explicit *.googleapis.com hosts outrank gcp's
 *    `.googleapis.com` dot-suffix claim by specificity, not by position.
 *  - confluence/jira (api.atlassian.com) and github/github-app (every github
 *    host) are equally specific exact claims, so they stay multiple
 *    candidates and the proxy picks the one with a connected credential.
 *    Among those ties this array's order is the tiebreak, which keeps jira
 *    and the PAT github integration primary when both sides are connected.
 */
const BUILTINS: Integration[] = [
  github,
  google,
  gemini,
  gcp,
  aws,
  slack,
  openai,
  openrouter,
  anthropic,
  jira,
  notion,
  linear,
  stripe,
  sendgrid,
  braveSearch,
  tavily,
  telegramBot,
  discord,
  huggingface,
  gitlab,
  confluence,
  dropbox,
  cloudflare,
  flyio,
  hetzner,
  vercel,
  supabase,
  resend,
  todoist,
  trello,
  monday,
  linkedin,
  mongodbAtlas,
  docker,
  jfrogArtifactory,
  githubApp,
  elevenlabs,
  make,
];

/**
 * Integration ids to skip, from `ONEGATE_DISABLED_INTEGRATIONS` (comma or
 * space separated). A disabled integration's hosts fall through to plain
 * passthrough instead of being MITM-terminated and requiring a connected
 * credential. This matters when a single OneGate instance doubles as an
 * agent's own egress proxy and one of its backend hosts (e.g. api.anthropic.com
 * for the agent's LLM, api.telegram.org for its chat adapter) collides with a
 * catalog integration the operator does not want managed here.
 */
export function disabledIntegrations(
  env: string | undefined = process.env.ONEGATE_DISABLED_INTEGRATIONS,
): Set<string> {
  return new Set(
    (env ?? "")
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

export async function buildRegistry(communityDir?: string): Promise<Registry> {
  const registry = new Registry();
  const disabled = disabledIntegrations();
  for (const integration of BUILTINS) {
    if (disabled.has(integration.id)) continue;
    registry.register(integration);
  }
  if (communityDir) await loadCommunity(registry, communityDir);
  return registry;
}

export async function loadCommunity(registry: Registry, dir: string): Promise<string[]> {
  let files: string[];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".js") || f.endsWith(".mjs"));
  } catch {
    return [];
  }
  const loaded: string[] = [];
  for (const file of files) {
    const mod = (await import(pathToFileURL(join(dir, file)).href)) as {
      default?: Integration;
    };
    const integration = mod.default;
    if (!integration?.id || !integration.hosts || typeof integration.inject !== "function") {
      throw new Error(`Community integration ${file} must default-export an Integration`);
    }
    registry.register({ ...integration, community: true });
    loaded.push(integration.id);
  }
  return loaded;
}
