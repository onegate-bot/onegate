/**
 * Composes the "ask your LLM for help" prompt for an integration. The admin
 * UI shows this on each integration's connect dialog so users who do not
 * know how to create a credential can paste it into ChatGPT, Claude or any
 * other LLM and get full step-by-step guidance.
 *
 * The prompt is plain text (no markdown required to render it) and is built
 * entirely from the integration's metadata, merged with the optional
 * `llmHelp` hints when the integration declares them. Community integrations
 * without hints get the generic version automatically.
 */

import type { Integration } from "./types.js";

export function composeLlmHelpPrompt(integration: Integration): string {
  const hints = integration.llmHelp ?? {};
  const fieldLines = integration.credentialFields.map(
    (f) => `- "${f.label}"${f.secret ? " (secret, treated like a password)" : ""}`,
  );

  const lines: string[] = [
    "I am setting up OneGate, a self-hosted credential gateway for AI agents.",
    "OneGate sits between an AI agent and external APIs as an HTTPS proxy. It stores the real credentials and injects them into the agent's requests, so the agent itself never holds them.",
    "",
    `I need to connect the "${integration.title}" integration. OneGate will proxy and authenticate requests to these hosts: ${integration.hosts.join(", ")}.`,
    "",
    "OneGate's admin UI asks me to fill in these credential fields:",
    ...(fieldLines.length ? fieldLines : ["- (this integration declares no credential fields)"]),
  ];

  if (hints.credentialType) lines.push("", `Credential type needed: ${hints.credentialType}`);
  if (hints.whereToCreate) lines.push("", `Where it is created: ${hints.whereToCreate}`);
  if (hints.scopes?.length) {
    lines.push("", "Scopes or permissions OneGate needs:", ...hints.scopes.map((s) => `- ${s}`));
  }
  if (hints.notes) lines.push("", hints.notes);

  lines.push(
    "",
    "Please give me numbered step-by-step instructions that cover:",
    "1. How to create this credential with this provider, with exact navigation and sample values where helpful.",
    "2. Which scopes or permissions to grant and why they are needed.",
    "3. What to paste into each OneGate admin UI field, using the exact field names listed above.",
    "Assume I am not familiar with this provider's settings. Keep it concrete and beginner friendly.",
  );

  return lines.join("\n");
}
