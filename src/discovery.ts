/**
 * Agent-facing discovery. An agent that has authenticated to the proxy (its
 * og_ token) can ask "which accounts and URLs can I reach", so a bot learns
 * the Jira site URL (and any other non-secret account facts) without the
 * operator having to paste it into the prompt. See #5438 (reason 1) and #5450
 * (make it generic across every connection, not Jira only).
 *
 * The payload is strictly NON-SECRET: it never includes tokens, passwords or
 * any credential material. Per integration it lists the agent's reachable
 * accounts and, when an integration declares accountSummary, the non-secret
 * facts that summary returns. A single account is flagged as the default the
 * proxy uses automatically when no x-onegate-connection header is sent.
 */

import type { Store } from "./store/db.js";
import type { HostClaim, Registry } from "./integrations/types.js";
import type { Agent, Connection, Credential } from "./types.js";
import { evaluate } from "./policy.js";

/** The host an agent CONNECTs to over the proxy to reach discovery. */
export const DISCOVERY_HOST = "onegate.internal";

export interface DiscoveryAccount {
  /** Connection or credential id. Pass as x-onegate-connection to select it. */
  id: string;
  name: string;
  /** True for the account the proxy uses when no x-onegate-connection is sent. */
  isDefault: boolean;
  /** Non-secret account facts (e.g. Jira siteUrl), or null when none declared. */
  summary: Record<string, string | null> | null;
}

export interface DiscoveryIntegration {
  id: string;
  title: string;
  /**
   * Hosts this integration serves. A path-scoped claim is rendered as
   * "host/prefix" (e.g. "www.googleapis.com/youtube/v3"), which is exactly the
   * base an agent should call. Bare host claims render unchanged, so the wire
   * format is still a plain string list.
   */
  hosts: string[];
  /**
   * Coarse policy hint at path "/": "allowed" when an allow rule covers this
   * integration, "denied" otherwise. Specific paths may still differ, this is
   * a quick "can I use this at all" signal for the agent.
   */
  access: "allowed" | "denied";
  accounts: DiscoveryAccount[];
  /** id of the auto-selected account, or null when the agent has none. */
  defaultAccountId: string | null;
}

export interface DiscoveryResult {
  agent: { id: string; name: string };
  integrations: DiscoveryIntegration[];
}

/**
 * Renders one host claim for the agent-facing payload. A bare claim is the
 * hostname unchanged (so nothing an agent already reads ever changes). A
 * path-scoped claim renders as "host/prefix", which is the base the agent
 * should actually call, e.g. "www.googleapis.com/youtube/v3".
 */
function renderHostClaim(entry: HostClaim): string {
  return typeof entry === "string" ? entry : `${entry.host}${entry.path}`;
}

function synthCredential(integrationId: string, c: Connection): Credential {
  return {
    id: c.id,
    integrationId,
    name: c.name,
    data: c.data,
    createdAt: c.createdAt,
  };
}

/** Safely call an integration's accountSummary, never throwing. */
function summaryFor(
  integration: { accountSummary?(cred: Credential): Record<string, string | null> },
  cred: Credential,
): Record<string, string | null> | null {
  if (!integration.accountSummary) return null;
  try {
    return integration.accountSummary(cred);
  } catch {
    return null;
  }
}

/**
 * Builds the discovery payload for one authenticated agent. Generic across all
 * integrations: an integration appears when the agent has at least one
 * reachable account for it (a granted named app connection, or the legacy
 * shared credential). LLM vendors carry no app accounts, so they fall away
 * naturally.
 */
export function buildDiscovery(
  store: Store,
  registry: Registry,
  agent: Agent,
): DiscoveryResult {
  const rules = store.rulesForAgent(agent);
  const integrations: DiscoveryIntegration[] = [];

  for (const integration of registry.list()) {
    const accounts: DiscoveryAccount[] = [];

    // Granted named app connections for this agent + integration.
    const conns = store.listAppConnectionsForAgent(agent.id, integration.id);

    // What the proxy would pick with no x-onegate-connection header.
    const resolved = store.resolveAppConnection(agent.id, integration.id, undefined);
    let defaultId: string | null =
      resolved && "connection" in resolved ? resolved.connection.id : null;

    for (const c of conns) {
      accounts.push({
        id: c.id,
        name: c.name,
        isDefault: c.id === defaultId,
        summary: summaryFor(integration, synthCredential(integration.id, c)),
      });
    }

    // No named connections: fall back to the legacy shared credential.
    if (accounts.length === 0) {
      const legacy = store.getCredential(integration.id);
      if (legacy) {
        accounts.push({
          id: legacy.id,
          name: legacy.name,
          isDefault: true,
          summary: summaryFor(integration, legacy),
        });
        defaultId = legacy.id;
      }
    }

    // Nothing for this agent to discover here.
    if (accounts.length === 0) continue;

    // Exactly one account and the store flagged no default: it is the default.
    if (!defaultId && accounts.length === 1) {
      accounts[0].isDefault = true;
      defaultId = accounts[0].id;
    }

    const verdict = evaluate(agent, rules, {
      integrationId: integration.id,
      method: "GET",
      path: "/",
    });

    integrations.push({
      id: integration.id,
      title: integration.title,
      hosts: integration.hosts.map(renderHostClaim),
      access: verdict.effect === "deny" ? "denied" : "allowed",
      accounts,
      defaultAccountId: defaultId,
    });
  }

  integrations.sort((a, b) => a.id.localeCompare(b.id));
  return { agent: { id: agent.id, name: agent.name }, integrations };
}
