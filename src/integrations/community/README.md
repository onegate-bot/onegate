# Community integrations

Drop a `.js` (or `.mjs`) file in the community directory
(`ONEGATE_COMMUNITY_DIR`, default `<data>/integrations`) that default-exports
an `Integration`:

```js
// slack.js
export default {
  id: "slack",
  title: "Slack",
  hosts: ["slack.com", ".slack.com"],
  credentialFields: [{ key: "token", label: "Bot token", secret: true }],
  inject(ctx) {
    ctx.headers.authorization = `Bearer ${ctx.credential.data.token}`;
  },
};
```

Contract:

- `id` — unique, lowercase. Used in rules, credentials and the audit log.
- `hosts` — hostnames the gateway should intercept for this integration.
  A leading dot matches all subdomains (`".slack.com"` ⇒ `api.slack.com`).
- `credentialFields` — what the admin UI asks for when connecting.
- `inject(ctx)` — mutate `ctx.headers` to carry real credentials.
  May be `async`. `ctx.store` is available for token caches
  (see `../google.ts` for an OAuth refresh example).

The gateway loads these at startup. Hosts must not overlap with another
registered integration.
