/**
 * Google Gemini integration (Generative Language API). The stored API key is
 * injected as the x-goog-api-key header. Clients that carry a placeholder
 * key in the `?key=` query param get it rewritten to the real key too, since
 * the API accepts either and a stale query key would otherwise win.
 *
 * Owns generativelanguage.googleapis.com as an exact claim, which google does
 * not list and which outranks gcp's `.googleapis.com` dot-suffix claim by
 * specificity, whatever order the three are registered in.
 */

import type { Integration, InjectionContext } from "./types.js";

/** Rewrites an existing `key` query param to the real API key, if present. */
function rewriteKeyParam(path: string, apiKey: string): string {
  const qIndex = path.indexOf("?");
  if (qIndex === -1) return path;
  const params = new URLSearchParams(path.slice(qIndex + 1));
  if (!params.has("key")) return path;
  params.set("key", apiKey);
  return `${path.slice(0, qIndex)}?${params.toString()}`;
}

function injectKey(ctx: InjectionContext, apiKey: string): void {
  ctx.headers["x-goog-api-key"] = apiKey;
  ctx.path = rewriteKeyParam(ctx.path, apiKey);
}

export const gemini: Integration = {
  id: "gemini",
  title: "Google Gemini",
  hosts: ["generativelanguage.googleapis.com"],
  category: "AI",
  credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
  llmHelp: {
    credentialType:
      "A Google AI Studio API key (starts with AIza). OneGate injects it as the x-goog-api-key header, and rewrites any key query parameter the client sends.",
    whereToCreate:
      "https://aistudio.google.com/apikey (Google AI Studio, then Get API key, then Create API key).",
    scopes: [
      "AI Studio keys are not scoped per endpoint. They authenticate the Generative Language API (generativelanguage.googleapis.com) only, Vertex AI uses GCP credentials instead.",
    ],
    notes:
      'Paste the key into the "API key" field. This covers the Gemini API at generativelanguage.googleapis.com, not Vertex AI (use the GCP integration for that).',
  },
  // LLM calls are POSTs with a body. Buffering it (bounded) lets the proxy
  // replay the request once when the strategy engine fails over mid-request.
  needsBody: true,
  llm: {
    vendor: "gemini",
    inject(ctx: InjectionContext): void {
      const apiKey = ctx.credential.data.apiKey;
      if (!apiKey) throw new Error('Gemini LLM connection has no "apiKey" field');
      injectKey(ctx, apiKey);
    },
  },
  inject(ctx: InjectionContext): void {
    const apiKey = ctx.credential.data.apiKey;
    if (!apiKey) throw new Error('Gemini credential has no "apiKey" field');
    injectKey(ctx, apiKey);
  },
};
