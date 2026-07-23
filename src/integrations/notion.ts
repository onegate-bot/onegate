/**
 * Notion integration. The stored internal integration secret is sent as a
 * Bearer token. The Notion API requires a Notion-Version header on every
 * call, OneGate adds a sane default when the client does not set one.
 */

import type { Integration, InjectionContext } from "./types.js";

const DEFAULT_NOTION_VERSION = "2022-06-28";

export const notion: Integration = {
  id: "notion",
  title: "Notion",
  hosts: ["api.notion.com"],
  category: "Productivity",
  credentialFields: [{ key: "token", label: "Integration secret", secret: true }],
  llmHelp: {
    credentialType:
      "A Notion internal integration secret (starts with ntn_ or secret_). OneGate sends it as a Bearer token and adds a default Notion-Version header when the client does not set one.",
    whereToCreate:
      "https://www.notion.so/my-integrations (create an internal integration in the workspace, then copy the secret).",
    scopes: [
      "Choose the integration's capabilities when creating it: read content, update content, insert content, and user information as needed.",
      "Notion only exposes pages and databases explicitly shared with the integration. Open each page, use the connections menu and add the integration.",
    ],
    notes: 'Paste the secret into the "Integration secret" field.',
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.token;
    if (!token) throw new Error('Notion credential has no "token" field');
    ctx.headers.authorization = `Bearer ${token}`;
    if (!ctx.headers["notion-version"]) ctx.headers["notion-version"] = DEFAULT_NOTION_VERSION;
  },
};
