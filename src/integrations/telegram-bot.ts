/**
 * Telegram Bot API integration. Telegram carries the bot token in the URL
 * path (/bot<token>/method and /file/bot<token>/<path>), not in a header.
 * The agent calls the API with any placeholder token in the path and the
 * gateway rewrites the path segment to carry the real token (the proxy
 * forwards a reassigned ctx.path upstream). Policy and audit always see the
 * placeholder path the agent sent, so the real token never appears in
 * rules or logs. Write policy globs against the placeholder path, for
 * example a glob of "/bot*" followed by "/sendMessage".
 */

import type { Integration, InjectionContext } from "./types.js";

const BOT_PATH = /^(\/file)?\/bot[^/]*(\/|$)/;

export const telegramBot: Integration = {
  id: "telegram-bot",
  title: "Telegram Bot",
  hosts: ["api.telegram.org"],
  category: "Communication",
  credentialFields: [{ key: "token", label: "Bot token", secret: true }],
  llmHelp: {
    credentialType:
      "A Telegram bot token from BotFather (looks like 123456:ABC-xyz). Telegram puts the token in the URL path, so OneGate rewrites the request path and swaps the agent's placeholder token for the real one.",
    whereToCreate:
      "In Telegram, message @BotFather, send /newbot to create a bot (or /token for an existing one) and copy the token it returns.",
    scopes: [
      "Bot tokens are all or nothing, anyone holding the token fully controls the bot. Keeping it in OneGate instead of the agent is exactly the point.",
    ],
    notes:
      "The agent should call https://api.telegram.org/bot<placeholder>/<method> with any placeholder token, for example /bot000:placeholder/sendMessage. OneGate replaces whatever sits between /bot and the next slash with the real token. File downloads via /file/bot<placeholder>/... are rewritten the same way. Policy globs match the placeholder path the agent sent, for example /bot*/sendMessage.",
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.token;
    if (!token) throw new Error('Telegram credential has no "token" field');
    if (!BOT_PATH.test(ctx.path)) {
      throw new Error(
        'Telegram Bot API paths look like "/bot<placeholder>/<method>" (or "/file/bot<placeholder>/..."). Put any placeholder token in the path and OneGate swaps in the real one.',
      );
    }
    ctx.path = ctx.path.replace(BOT_PATH, (_m, file: string | undefined, tail: string) => {
      return `${file ?? ""}/bot${token}${tail}`;
    });
  },
};
