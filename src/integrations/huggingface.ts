/**
 * Hugging Face integration. The access token is sent as a Bearer token.
 * One host entry (.huggingface.co) covers the hub API and file downloads
 * on huggingface.co plus api-inference and router subdomains.
 */

import type { Integration, InjectionContext } from "./types.js";

export const huggingface: Integration = {
  id: "huggingface",
  title: "Hugging Face",
  hosts: [".huggingface.co"],
  category: "AI",
  credentialFields: [{ key: "token", label: "Access token", secret: true }],
  llmHelp: {
    credentialType:
      "A Hugging Face access token (starts with hf_). OneGate sends it as a Bearer token.",
    whereToCreate:
      "https://huggingface.co/settings/tokens (Settings, then Access Tokens, then Create new token).",
    scopes: [
      "Fine-grained tokens are recommended. Grant read access to repos or inference as needed, write only if the agent uploads models or datasets.",
    ],
    notes:
      "One token covers huggingface.co (hub API, file downloads), api-inference.huggingface.co and router.huggingface.co (inference providers).",
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.token;
    if (!token) throw new Error('Hugging Face credential has no "token" field');
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
