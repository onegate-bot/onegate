# Contributing to OneGate

Thanks for your interest in contributing. This document covers the dev setup, the project layout, and what we expect from a pull request.

## Dev setup

Requirements: **Node >= 22.13** (OneGate uses the built-in `node:sqlite`, zero native deps) and pnpm, pinned via `packageManager` in `package.json`.

```sh
corepack enable        # activates the pinned pnpm version
pnpm install
pnpm test              # vitest, includes a full end-to-end proxy test
pnpm typecheck
pnpm build
```

`pnpm dev` runs the CLI from source via tsx.

## Project layout

```
bin/                 CLI entry point (onegate.js)
src/
  cli.ts             CLI commands (init, start, agent, admin, print-ca)
  ca.ts              root CA init and per-host leaf cert minting
  policy.ts          allow/deny rule engine (deny > allow > default)
  proxy/server.ts    HTTP CONNECT gateway with TLS termination + injection
  admin/             admin API (Express) and the no-build web UI
  store/db.ts        node:sqlite persistence layer
  integrations/      built-in integrations (GitHub, Google) + community loader
  util/              shared HTTP helpers
test/                vitest suites, one per module, plus setup.ts
docs/                architecture, deployment, integrations, security docs
docker/              container entrypoint
```

## Adding an integration

There are two paths, described in detail in [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md):

- **Community integration** — a single drop-in JS file that default-exports an `Integration` (see `src/integrations/types.ts`). Users place it in the community directory (`ONEGATE_COMMUNITY_DIR`, default `<data>/integrations`) and restart the gateway. No code changes to OneGate required, and no PR needed to use it.
- **Built-in integration** — lives in `src/integrations/` and is registered in `src/integrations/index.ts`. To contribute one upstream: add the module, register it in `index.ts`, and add a test in `test/integrations.test.ts` proving the header rewrite (and the refresh flow if OAuth-based).

If in doubt, start with a community integration. We promote widely useful ones to built-ins.

## Pull request expectations

- **One logical change per PR.** Small, reviewable diffs merge faster.
- **Tests pass:** `pnpm test` must be green. Add or update tests for any behavior change.
- **Typecheck clean:** `pnpm typecheck` must produce no errors.
- **Docs updated** if behavior, CLI flags, env vars, or the integration contract changed.
- **No new runtime dependencies** without prior discussion in an issue. Zero native deps is a deliberate constraint.

## Testing notes

Tests run entirely against local stub servers. `test/setup.ts` strips ambient proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NODE_USE_ENV_PROXY`, etc.) so test clients reach `127.0.0.1` directly. **Do not write tests that depend on proxy env vars being set**, and keep new client code in tests pointed at the local stubs.

## Reporting bugs and proposing features

Use the issue forms. For security vulnerabilities, do **not** open a public issue, see [SECURITY.md](SECURITY.md).

## License of contributions

OneGate is licensed under the Apache License 2.0. By submitting a contribution (a pull request, a patch, or any other work) you agree that your contribution is licensed under the same Apache License 2.0 (inbound = outbound). There is no separate CLA to sign.
