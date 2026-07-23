/**
 * Trello's first-party authorization flow: no code exchange at all. The
 * authorize page returns a long-lived token in the URL fragment
 * (callback_method=fragment), the callback bridge resubmits it and the
 * server stores it. Requests authenticate with key and token QUERY
 * parameters, not headers, so inject rewrites ctx.path. Policy globs and
 * audit see the path as the agent sent it (params are appended after
 * policy evaluation).
 */

import type { Integration, InjectionContext } from "./types.js";

export const trello: Integration = {
  id: "trello",
  title: "Trello",
  hosts: ["api.trello.com"],
  category: "Productivity",
  credentialFields: [
    { key: "clientId", label: "API key", secret: false },
    { key: "accessToken", label: "Token (set by the connect flow)", secret: true },
  ],
  connect: {
    method: "oauth",
    hint: "Use the API key from a Trello Power-Up. Trello returns the token directly, there is no code exchange.",
  },
  oauth: {
    authUrl: "https://trello.com/1/authorize",
    tokenUrl: "",
    defaultScopes: ["read", "write", "account"],
    scopeSeparator: ",",
    clientIdParam: "key",
    redirectUriParam: "return_url",
    responseType: "token",
    fragmentCallback: { paramName: "token" },
    extraAuthParams: { callback_method: "fragment", expiration: "never", name: "OneGate" },
    permissions: [
      { scope: "read", name: "Read boards & cards", description: "View cards, lists, boards, and organizations", access: "read" },
      { scope: "write", name: "Write boards & cards", description: "Add and edit cards, lists, and boards", access: "write" },
      { scope: "account", name: "Account", description: "View the member's profile details and email", access: "read" },
    ],
  },
  llmHelp: {
    credentialType:
      "A Trello API key (from a Power-Up) plus a member token that Trello's authorize page returns directly. OneGate appends both as query parameters (key=..., token=...) on every request, Trello does not use Authorization headers.",
    whereToCreate:
      "https://trello.com/power-ups/admin: create a Power-Up to get the API key, set the allowed origin to the OneGate redirect URI shown in the connect dialog, then run the connect flow.",
    scopes: ["Drop the write scope for read-only agents. expiration=never is requested by default."],
    notes:
      "Send requests WITHOUT key and token params, OneGate adds them. The API lives under /1/ (e.g. GET /1/members/me/boards).",
  },
  inject(ctx: InjectionContext): void {
    const key = ctx.credential.data.clientId;
    const token = ctx.credential.data.accessToken;
    if (!key || !token) {
      throw new Error('Trello credential needs "clientId" (API key) and "accessToken" (token)');
    }
    const sep = ctx.path.includes("?") ? "&" : "?";
    ctx.path = `${ctx.path}${sep}key=${encodeURIComponent(key)}&token=${encodeURIComponent(token)}`;
  },
};
