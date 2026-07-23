/**
 * Hetzner Cloud API token, injected as Bearer on api.hetzner.cloud (servers,
 * firewalls, networks, volumes, load balancers, images, SSH keys). One token
 * per Hetzner Cloud project. NOTE: this covers the Cloud API only, not the
 * Hetzner DNS API (dns.hetzner.com, which uses a different Auth-API-Token
 * header) or the dedicated-server Robot API (Basic auth).
 */

import type { Integration, InjectionContext } from "./types.js";

export const hetzner: Integration = {
  id: "hetzner",
  title: "Hetzner Cloud",
  hosts: ["api.hetzner.cloud"],
  category: "Infrastructure",
  credentialFields: [{ key: "apiToken", label: "API token", secret: true }],
  llmHelp: {
    credentialType:
      "A Hetzner Cloud API token (a 64-character project token). OneGate sends it as a Bearer token.",
    whereToCreate:
      "Hetzner Cloud Console (console.hetzner.cloud): pick the project, then Security, then API Tokens, then Generate API Token.",
    scopes: [
      "The token is scoped to the single project it is created in.",
      "Choose Read for provisioning checks and inventory, or Read & Write to create or change servers, firewalls, and networks.",
    ],
    notes:
      "This token works on the Cloud API (api.hetzner.cloud) only. The Hetzner DNS API and the dedicated-server Robot API use separate credentials and are not covered here.",
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.apiToken;
    if (!token) throw new Error('Hetzner credential has no "apiToken" field');
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
