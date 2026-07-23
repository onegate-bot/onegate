/**
 * Fly.io API token, injected as Bearer on both the Machines API
 * (api.machines.dev) and the GraphQL/REST host (api.fly.io). Org and
 * app-scoped deploy tokens narrow access at the vendor side.
 */

import type { Integration, InjectionContext } from "./types.js";

export const flyio: Integration = {
  id: "flyio",
  title: "Fly.io",
  hosts: ["api.machines.dev", "api.fly.io"],
  category: "Infrastructure",
  credentialFields: [{ key: "apiToken", label: "API token", secret: true }],
  llmHelp: {
    credentialType:
      'A Fly.io token (usually starts with "FlyV1 fm2_"). OneGate sends it as a Bearer token.',
    whereToCreate:
      "fly.io dashboard (Account, then Access Tokens) or the CLI: `fly tokens create org` for an org token, `fly tokens create deploy -a <app>` for a single app.",
    scopes: [
      "Prefer an app-scoped deploy token over an org token when the agent only manages one app.",
    ],
    notes:
      "The same token works on api.machines.dev (Machines REST API) and api.fly.io (GraphQL). Fly tokens may contain a space (FlyV1 prefix), paste the whole thing.",
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.apiToken;
    if (!token) throw new Error('Fly.io credential has no "apiToken" field');
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
