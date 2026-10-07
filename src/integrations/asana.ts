/** Asana personal access token, injected as Bearer on app.asana.com (/api/1.0). */

import type { Integration, InjectionContext } from "./types.js";

export const asana: Integration = {
  id: "asana",
  title: "Asana",
  hosts: ["app.asana.com"],
  category: "Productivity",
  credentialFields: [{ key: "token", label: "Personal access token", secret: true }],
  connect: {
    method: "api_key",
    hint: "A personal access token from the Asana developer console. It acts as your user.",
  },
  llmHelp: {
    credentialType: "An Asana personal access token. OneGate sends it as a Bearer token.",
    whereToCreate:
      "https://app.asana.com/0/my-apps (Asana developer console, then Personal access tokens, then Create new token).",
    scopes: [
      "Personal access tokens carry the full permissions of your Asana user in every workspace you belong to. Narrow the agent with OneGate rules (method and path), or use a dedicated Asana user for it.",
    ],
    notes: "The REST API lives under https://app.asana.com/api/1.0/. app.asana.com also serves the web app, scope rules to /api/1.0/**.",
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.token;
    if (!token) throw new Error('Asana credential has no "token" field');
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
