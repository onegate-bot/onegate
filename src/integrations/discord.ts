/**
 * Discord integration. The stored bot token is sent as
 * "Authorization: Bot <token>" on REST calls to discord.com. The realtime
 * gateway websocket is not proxied, this covers the HTTP API only.
 */

import type { Integration, InjectionContext } from "./types.js";

export const discord: Integration = {
  id: "discord",
  title: "Discord",
  hosts: ["discord.com"],
  category: "Communication",
  credentialFields: [{ key: "botToken", label: "Bot token", secret: true }],
  llmHelp: {
    credentialType:
      'A Discord bot token. OneGate sends it as "Authorization: Bot <token>" (the Bot prefix is added automatically if it is missing).',
    whereToCreate:
      "https://discord.com/developers/applications (create an application, open the Bot tab, then Reset Token to reveal the token).",
    scopes: [
      "Permissions are granted when inviting the bot to a server through the OAuth2 URL generator, pick the minimal permission set. Privileged intents (message content, server members) are toggled on the Bot tab.",
    ],
    notes:
      "REST calls go to https://discord.com/api/v10/... and are proxied. The realtime gateway websocket is not covered.",
  },
  inject(ctx: InjectionContext): void {
    const botToken = ctx.credential.data.botToken;
    if (!botToken) throw new Error('Discord credential has no "botToken" field');
    ctx.headers.authorization = botToken.startsWith("Bot ") ? botToken : `Bot ${botToken}`;
  },
};
