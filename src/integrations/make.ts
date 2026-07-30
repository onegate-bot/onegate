/**
 * Make (make.com) API token, injected as `Authorization: Token <token>`.
 *
 * Make is region-sharded: there is no single API host. An account lives in a
 * zone and its API base is `https://<zone>.make.com/api/v2/...` (eu1, eu2,
 * us1, us2, ...). We claim the `.make.com` suffix so any current or future
 * zone resolves without a hardcoded list. Make's scheme is the literal word
 * `Token`, not `Bearer`.
 */

import type { Integration, InjectionContext } from "./types.js";

export const make: Integration = {
  id: "make",
  title: "Make",
  hosts: [".make.com"],
  category: "Automation",
  credentialFields: [{ key: "apiToken", label: "API token", secret: true }],
  llmHelp: {
    credentialType:
      'A Make API token (a UUID like "12345678-12ef-abcd-1234-1234567890ab"). OneGate sends it as "Authorization: Token <token>" (the literal word Token, not Bearer).',
    whereToCreate:
      "In Make: click your profile avatar, then Profile, then the API / Authentication tab, then Add token. Grant only the scopes the agent needs.",
    scopes: [
      "Make tokens are scope-limited at creation. Pick the narrowest scopes (for example scenarios:read) unless the agent must write.",
    ],
    notes:
      "Make is region-sharded: call your own zone's host, https://<zone>.make.com/api/v2/... where <zone> is the subdomain shown in your browser when logged into Make (eu1, eu2, us1, us2, ...). There is no single api.make.com host. OneGate only injects the token into that REST API shape (a path under /api/). Requests to webhook ingress (https://hook.<zone>.make.com/...) or to non-API pages are refused rather than authenticated, because a webhook endpoint is created by any Make user and can log the headers it receives.",
  },
  inject(ctx: InjectionContext): void {
    const token = ctx.credential.data.apiToken;
    if (!token) throw new Error('Make credential has no "apiToken" field');
    // The `.make.com` suffix claim is deliberately broad (Make is region
    // sharded, see above), but it also swallows surfaces that are NOT the
    // REST API and must never see the operator's token:
    //  - `hook.<zone>.make.com/<webhook-id>` is webhook INGRESS. Any Make user
    //    can create a webhook there and configure a scenario to capture and
    //    display the incoming request headers, so injecting here hands the
    //    token straight to a third party who reads it from their own execution
    //    log. Same defect class as the Jira `*.atlassian.net` binding.
    //  - `www.make.com` and the `<zone>.make.com` app UI are not the API.
    // The REST API is entirely under `/api/`, so require that prefix and
    // refuse the webhook ingress subdomain outright.
    const host = ctx.host.toLowerCase();
    const isWebhookIngress = host === "hook.make.com" || /(^|\.)hook\.[^.]+\.make\.com$/.test(host);
    const path = ctx.path ?? "";
    const isApiPath = path === "/api" || path.startsWith("/api/") || path.startsWith("/api?");
    if (isWebhookIngress || !isApiPath) {
      throw new Error(
        `Make credential is only injected into the Make REST API (https://<zone>.make.com/api/...), ` +
          `refusing to authenticate ${ctx.host}${path}. Webhook ingress (hook.<zone>.make.com) and ` +
          `non-API paths never receive the token.`,
      );
    }
    ctx.headers.authorization = `Token ${token}`;
  },
};
