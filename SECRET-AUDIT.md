# OneGate open-source snapshot — secret audit

**Audit date:** 2026-07-23
**Auditor:** Claritas (agent)
**Payload:** the OneGate source tree in this snapshot (`onegate-oss/`), destined for the public repo `onegate-bot/onegate`.
**Source:** a shallow (`--depth 1`) clone of the private `onegate-bot/onegate` baseline at commit `ff9ea13` ("Time-boxed connection access (access leases) (#40)"). History was NOT carried over (see "No-history" below).

## RESULT: CLEAN

No live secrets, private keys, credential material, or internal infrastructure identifiers were found in the payload. Safe to publish.

## Scope and method

OneGate is a credential gateway, so the audit specifically hunted for the artifacts such a system handles. Every check below was run against the full tree (excluding `node_modules/` and the lockfile's dependency hashes).

### 1. Credential / key files — NONE
Searched for `*.pem`, `*.key`, `*.enc`, `*.p12`, `*.pfx`, `.env`, `id_*`, `*.crt`, `*.keystore`. **No matches.** The `.enc` key files that exist on the live deployment (`onegate-db-key.txt.enc`, `onegate-rootCA.key.enc`) are NOT in the tree and were never cloned. `data/` (runtime CA, DB, admin token) is git-ignored and absent.

### 2. Token / secret prefixes — only test fixtures
Searched for `og_`, `sk-ant-oat01`, `sk-ant-api03`, `ghp_`, `github_pat_`, `gho_`, `xoxp/xoxb`, `GOCSPX-`, `AKIA`, `AIza`, `hf_`, `conn_`, `ag_`, `rl_`.
All hits are in test suites (`test/*.test.ts`), `scripts/ui-smoke.mjs`, and the masking utility (`src/util/mask.ts`). Every one is a hardcoded FAKE fixture used to exercise parsing/masking logic (e.g. `ghp_LongPatToken1234567890`, `xoxb-SUPERSECRET`, `sk-ant-api03-secret`, `sk-ant-api03...4GwA`). None correspond to a real credential.

### 3. Private keys — generated at runtime, not stored
`test/integrations.test.ts` contains `-----BEGIN PRIVATE KEY-----` references, but the key material is produced in-test by `generateKeyPairSync("rsa", ...)` (line 468) to exercise the Google service-account JWT-signing path. No private key is committed. The `robot@proj.iam.gserviceaccount.com` email is a fixture, not a real service account.

### 4. Internal infrastructure — NONE
Searched for fleet VM IPs (`178.104.9.163`, `157.90.119.103`), the docker bridge (`172.17.0.1`), the Tailscale node IP (`100.80.60.86`), secret paths (`/root/onegate-secrets`, `/srv/bots`), the tenant uid (`166535`), and `tenant-ziv`. **No matches.** The only `/opt/onegate` reference is a generic systemd `ExecStart` install path in `docs/DEPLOY.md`, which is public deployment documentation, not a secret.

### 5. Generic secret patterns — NONE
Searched for `password|secret|api_key|private_key|access_token|client_secret` assigned to a literal 16+ char string outside tests/examples. **No matches.**

### 6. Personal / owner attribution — normalized
- LICENSE copyright changed from "Ziv Isaiah" to "OneGate" (see License below).
- All `github.com/zivisaiah/onegate` URLs (docs, site, issue templates, docker-compose) repointed to `github.com/onegate-bot/onegate`.
- No `getclarity`, `Clarity`, or other personal/company identifiers remain.
- Emails in tests are placeholders (`me@x.com`, `x@y.com`, `z@x.io`).

### 7. CI is fork-safe
`.github/workflows/ci.yml` uses no repository secrets and no `env:` credentials. It runs `pnpm install`, typecheck, and test only, so pull requests from forks run green without any secret exposure.

## Changes made while preparing the snapshot

- **License changed MIT to Apache-2.0** (`LICENSE`, `package.json`, `README.md`, `THIRD-PARTY-NOTICES.md`) to match the chosen OneCLI open-source model. Added `NOTICE` (Apache convention). Third-party dependency licenses (e.g. simple-icons, webawesome, both MIT) are unchanged and still documented in `THIRD-PARTY-NOTICES.md`.
- **Added inbound = outbound clause** to `CONTRIBUTING.md` (no CLA).
- **Positioning:** README now leads with "The agent security platform, made by agents."
- **Added framework files:** `.github/CODEOWNERS` (owner `@onegate-bot/maintainers`), `.env.example` (placeholders only).
- **Repointed repo URLs** to `onegate-bot/onegate`.

## No-history

The public snapshot is a working tree only. The `.git` directory was removed before packaging, so no private commit history (which could contain secrets from earlier states) is carried into the public repo. The owning agent initializes a fresh git history with a single commit.

## Recommendation

Publish. Before flipping the repo public, re-run a grep for the token prefixes above on the pushed tree as a final gate (documented in the bring-up instructions, Step 6).
