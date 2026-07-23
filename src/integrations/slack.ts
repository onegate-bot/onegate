/**
 * Slack integration. One stored token (bot xoxb- or user xoxp-) is sent as a
 * Bearer token on every Web API call.
 *
 * Limitation: Slack's Web API also accepts the token inside the POST body
 * (a form field named "token"). A header gateway cannot rewrite request
 * bodies, so clients must authenticate via the Authorization header. Every
 * official Slack SDK does this when constructed with a token, send any
 * placeholder and OneGate replaces it.
 */

import type { Integration, InjectionContext } from "./types.js";

export const slack: Integration = {
  id: "slack",
  title: "Slack",
  hosts: ["slack.com", ".slack.com"],
  category: "Communication",
  credentialFields: [{ key: "token", label: "Slack token (xoxb or xoxp)", secret: true }],
  llmHelp: {
    credentialType:
      "A Slack token, either a bot token (starts with xoxb-) from a Slack app or a user token (starts with xoxp-). OneGate sends it as a Bearer token in the Authorization header on every Web API call.",
    whereToCreate:
      "https://api.slack.com/apps (create or open an app, add scopes under OAuth and Permissions, then install the app to the workspace and copy the token).",
    scopes: [
      "Pick OAuth scopes matching what the agent does, for example channels:read and channels:history to read public channels, chat:write to post messages, users:read to look up people.",
      "Bot tokens act as the app's bot user. User tokens act as the installing user and can usually see more, grant them carefully.",
    ],
    notes:
      "Important limitation: OneGate injects the token only in the Authorization header. Slack also accepts tokens inside the POST body (a form field named token), and a header gateway cannot rewrite request bodies. Configure the Slack client with any placeholder token, official SDKs put it in the Authorization header, which OneGate then replaces with the real one.",
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.token;
    if (!token) throw new Error('Slack credential has no "token" field');
    ctx.headers.authorization = `Bearer ${token}`;
  },
};
