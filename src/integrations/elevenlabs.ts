/**
 * ElevenLabs integration. The API key is injected as the xi-api-key header,
 * which is how the ElevenLabs API authenticates on api.elevenlabs.io (text to
 * speech, speech to text, voices, dubbing and the rest of the v1 endpoints).
 */

import type { Integration, InjectionContext } from "./types.js";

export const elevenlabs: Integration = {
  id: "elevenlabs",
  title: "ElevenLabs",
  hosts: ["api.elevenlabs.io"],
  category: "AI",
  credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
  llmHelp: {
    credentialType:
      "An ElevenLabs API key (starts with sk_). OneGate injects it as the xi-api-key header.",
    whereToCreate:
      "https://elevenlabs.io/app/settings/api-keys (sign in, open Settings, then API Keys, then Create API Key).",
    scopes: [
      "ElevenLabs keys can be scoped per workspace permission (text to speech, speech to text, voices, dubbing). Grant only the permissions the agent needs.",
    ],
    notes:
      "One key covers api.elevenlabs.io. Send any placeholder xi-api-key header and OneGate replaces it with the stored key.",
  },
  inject(ctx: InjectionContext): void {
    const apiKey = ctx.credential.data.apiKey;
    if (!apiKey) throw new Error('ElevenLabs credential has no "apiKey" field');
    ctx.headers["xi-api-key"] = apiKey;
  },
};
