/**
 * Admin plane: REST API + static web UI + Google OAuth connect flow.
 *
 * All /api routes require `Authorization: Bearer <admin token>`. The admin
 * token is generated once (see ensureAdminToken) and only its sha256 hash is
 * stored. The OAuth callback route is unauthenticated by necessity (it is a
 * browser redirect target) and is protected by a single-use random state.
 */

import express from "express";
import { timingSafeEqual, randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Store, hashToken } from "../store/db.js";
import type { Connection, OnboardingLink } from "../types.js";
import { connectFlowKind, type Integration, type OAuthDescriptor, type Registry } from "../integrations/types.js";
import type { Ca } from "../ca.js";
import { composeLlmHelpPrompt } from "../integrations/llm-help.js";
import { buildAuthUrl, exchangeCode } from "../integrations/oauth.js";
import { previewPrimarySecret, llmPreferredSecretKeys } from "../util/mask.js";
import { brandLogoTile } from "./logo-render.js";
import { deriveLlmMode, type LlmMode } from "../llm/mode.js";
import type { Agent } from "../types.js";

const ADMIN_TOKEN_KEY = "admin_token_hash";

export function ensureAdminToken(store: Store): string | null {
  if (store.getSetting(ADMIN_TOKEN_KEY)) return null;
  const token = `oga_${randomBytes(24).toString("hex")}`;
  store.setSetting(ADMIN_TOKEN_KEY, hashToken(token));
  return token;
}

export function resetAdminToken(store: Store): string {
  const token = `oga_${randomBytes(24).toString("hex")}`;
  store.setSetting(ADMIN_TOKEN_KEY, hashToken(token));
  return token;
}

function checkAdminToken(store: Store, header: string | undefined): boolean {
  const stored = store.getSetting(ADMIN_TOKEN_KEY);
  if (!stored || !header?.startsWith("Bearer ")) return false;
  const given = Buffer.from(hashToken(header.slice(7)));
  const expected = Buffer.from(stored);
  return given.length === expected.length && timingSafeEqual(given, expected);
}

interface OauthPending {
  integrationId: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string[];
  createdAt: number;
  /**
   * Multi-OAuth: when set, the callback writes a named kind='app' connection
   * instead of the legacy single credential. connectionId set = re-authorize an
   * existing connection (update in place); else create a new one named
   * connectionName, optionally agent-bound (ownerAgentId) and/or default.
   */
  connectionName?: string;
  connectionId?: string;
  ownerAgentId?: string | null;
  isDefault?: boolean;
  /**
   * Connect-wizard branch: when set, the callback also grants the new
   * connection to this agent, ensures an agent-scoped allow rule for the
   * integration, and marks the onboarding link used. Absent = plain admin flow.
   */
  wizardToken?: string;
  wizardAgentId?: string;
  /**
   * Connect-wizard lease override for a time-boxed integration, carried through
   * the OAuth round-trip. NULL/undefined = inherit the integration default.
   * 0 = always-on. >0 = custom lease seconds. Stamped onto the created
   * connection so the allow-rule lease resolves from it.
   */
  leaseTtlSeconds?: number | null;
}

export interface AdminApiOptions {
  store: Store;
  registry: Registry;
  ca: Ca;
  version: string;
  /** Overridable in tests (kept for back compat; generic overrides exist via
   *  ONEGATE_OAUTH_{AUTH,TOKEN}_URL_<ID> env vars). */
  googleAuthUrl?: string;
  googleTokenUrl?: string;
}

/** Minimal HTML escaping for the OAuth result pages. */
function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/**
 * OneGate keyhole glyph (inner shapes, 64x64 viewBox) drawn in currentColor.
 * Shared by the wordmark mark and the paired-logo tile so both stay in sync.
 */
const KEYHOLE_GLYPH =
  `<circle cx="32" cy="35" r="10" fill="currentColor" opacity=".16"/>` +
  `<path d="M19 49V31C19 21.4 24.8 16 32 16C39.2 16 45 21.4 45 31V49" fill="none" stroke="currentColor" stroke-width="5.5" stroke-linecap="round" stroke-linejoin="round"/>` +
  `<path d="M13.5 49H50.5" fill="none" stroke="currentColor" stroke-width="5.5" stroke-linecap="round"/>` +
  `<circle cx="32" cy="35" r="5" fill="currentColor"/>`;

/**
 * OneGate brand-mark: the arch + keyhole, drawn in currentColor so it inherits
 * the brand accent. Mirrors the admin UI wordmark.
 */
const BRAND_MARK_SVG =
  `<svg viewBox="0 0 64 64" width="30" height="30" aria-hidden="true" focusable="false">${KEYHOLE_GLYPH}</svg>`;

/**
 * Small padlock, drawn in currentColor. Used in the paired-logo connector and
 * the "your bot never sees this credential" trust panel to signal that the
 * credential is sealed inside OneGate.
 */
const LOCK_SVG =
  `<svg viewBox="0 0 24 24" width="1.05em" height="1.05em" fill="none" stroke="currentColor" ` +
  `stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">` +
  `<rect x="4.5" y="10.5" width="15" height="9.5" rx="2.2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/></svg>`;

/**
 * Renders the OneGate keyhole inside a rounded brand-tinted tile, `size` px
 * square, to pair visually with a vendor's brandLogoTile.
 */
function oneGateLogoTile(size: number): string {
  const r = Math.round(size * 0.22);
  const pad = size * 0.22;
  const inner = size - pad * 2;
  return (
    `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img" aria-label="OneGate logo">` +
    `<rect width="${size}" height="${size}" rx="${r}" fill="#4f46e5" opacity=".12"/>` +
    `<svg x="${pad}" y="${pad}" width="${inner}" height="${inner}" viewBox="0 0 64 64" style="color:#4f46e5">${KEYHOLE_GLYPH}</svg></svg>`
  );
}

/**
 * Paired-logo header for a connect wizard: the vendor's logo, a locked
 * connector, and the OneGate mark. Shows the owner at a glance which service
 * they are connecting and that OneGate sits in the middle holding the key.
 */
function pairedLogoHeader(integration: Integration): string {
  return (
    `<div class="og-pair">` +
    `${brandLogoTile(integration.id, integration.title, 54)}` +
    `<span class="og-connector">${LOCK_SVG}</span>` +
    `${oneGateLogoTile(54)}` +
    `</div>`
  );
}

/**
 * Trust panel shown on every connect wizard: states plainly that the bot never
 * sees the credential, OneGate holds it encrypted, and the agent only ever
 * sends a placeholder.
 */
const TRUST_PANEL =
  `<div class="og-trust"><span class="og-trust-icon">${LOCK_SVG}</span>` +
  `<div><strong>Your bot never sees this credential.</strong> ` +
  `<span class="og-muted">OneGate stores it encrypted and attaches it to requests at the network edge. ` +
  `The agent only ever sends a placeholder, so your credential is never exposed in chat or to the model.</span></div></div>`;

/**
 * Inline "connected" checkmark. Rendered as SVG (not a ✓ glyph) so it looks
 * identical on every device and never depends on the viewer's system font.
 */
const CHECK_SVG =
  `<svg viewBox="0 0 24 24" width="1em" height="1em" fill="none" stroke="#16a34a" ` +
  `stroke-width="3" stroke-linecap="round" stroke-linejoin="round" ` +
  `aria-hidden="true" focusable="false" style="vertical-align:-.12em">` +
  `<path d="M20 6 9 17l-5-5"/></svg>`;

/**
 * Self-contained CSS for the public pages. These render standalone through the
 * public edge (no admin bundle), so the OneGate design tokens (indigo brand,
 * system font, card, medium radius, light/dark) are inlined here to match the
 * admin UI without any external stylesheet.
 */
const PUBLIC_PAGE_CSS =
  `:root{--og-brand:#4f46e5;--og-brand-hover:#4338ca;--og-bg:#f6f7f9;--og-surface:#fff;` +
  `--og-text:#1a1d23;--og-muted:#5b6270;--og-border:#e4e7ec;--og-input:#fff;--og-code:#f3f4f6;` +
  `--og-radius:16px;--og-radius-sm:9px;` +
  `--og-font:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;` +
  `--og-mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}` +
  `@media(prefers-color-scheme:dark){:root{--og-bg:#0f1115;--og-surface:#171a21;--og-text:#e8eaed;` +
  `--og-muted:#9aa1ad;--og-border:#2a2f39;--og-input:#0f1115;--og-code:#1c2029;--og-brand:#818cf8;--og-brand-hover:#a5b0ff}}` +
  `*{box-sizing:border-box}html,body{margin:0}` +
  `body{font-family:var(--og-font);background:var(--og-bg);color:var(--og-text);line-height:1.55;` +
  `-webkit-font-smoothing:antialiased;padding:2rem 1rem;display:flex;justify-content:center}` +
  `.og-wrap{width:100%;max-width:34rem}.og-wrap.wide{max-width:44rem}` +
  `.og-brand{display:flex;align-items:center;gap:.55rem;font-weight:700;font-size:1.15rem;` +
  `letter-spacing:-.01em;margin:0 0 1.25rem .15rem}.og-brand .og-mark{color:var(--og-brand);display:inline-flex}` +
  `.og-card{background:var(--og-surface);border:1px solid var(--og-border);border-radius:var(--og-radius);` +
  `padding:1.6rem 1.7rem;box-shadow:0 1px 2px rgba(16,24,40,.04),0 8px 24px -12px rgba(16,24,40,.12)}` +
  `.og-card h1{font-size:1.4rem;margin:.1rem 0 .6rem;letter-spacing:-.02em}` +
  `.og-card h2{font-size:1.02rem;margin:1.5rem 0 .5rem;letter-spacing:-.01em}` +
  `.og-card p{margin:.5rem 0}.og-muted{color:var(--og-muted)}` +
  `.og-card a{color:var(--og-brand);text-decoration:none;font-weight:500}.og-card a:hover{text-decoration:underline}` +
  `.og-card ol,.og-card ul{margin:.5rem 0;padding-left:1.2rem}.og-card li{margin:.35rem 0}` +
  `label{display:block;margin:.85rem 0;font-weight:500;font-size:.92rem}` +
  `input[type=text],input[type=password],.og-input{width:100%;margin-top:.35rem;padding:.6rem .7rem;` +
  `font:inherit;font-size:.95rem;color:var(--og-text);background:var(--og-input);border:1px solid var(--og-border);border-radius:var(--og-radius-sm)}` +
  `input:focus{outline:none;border-color:var(--og-brand);box-shadow:0 0 0 3px rgba(79,70,229,.2)}` +
  `.og-redirect{display:flex;gap:.5rem;align-items:stretch}` +
  `.og-redirect input{flex:1;font-family:var(--og-mono);font-size:.85rem;background:var(--og-code)}` +
  `fieldset{border:1px solid var(--og-border);border-radius:var(--og-radius-sm);padding:.6rem .9rem;margin:.6rem 0}` +
  `legend{font-weight:600;font-size:.9rem;padding:0 .35rem}fieldset label{font-weight:400;margin:.4rem 0}` +
  `.og-btn{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;font:inherit;font-weight:600;` +
  `font-size:.95rem;padding:.6rem 1.1rem;border-radius:var(--og-radius-sm);border:1px solid transparent;` +
  `background:var(--og-brand);color:#fff;cursor:pointer;text-decoration:none}` +
  `.og-btn:hover{background:var(--og-brand-hover);text-decoration:none}` +
  `.og-btn.secondary{background:transparent;color:var(--og-brand);border-color:var(--og-border)}` +
  `.og-btn.secondary:hover{background:var(--og-code)}` +
  `.og-btn.block{width:100%;margin-top:1.2rem;padding:.7rem 1.2rem;font-size:1rem}` +
  `.og-console{margin:.4rem 0 1rem}.og-foot{margin:1.1rem .2rem 0;font-size:.8rem;color:var(--og-muted);text-align:center}` +
  `.og-pair{display:flex;align-items:center;justify-content:center;gap:.8rem;margin:.1rem 0 1.3rem}` +
  `.og-pair svg{display:block}` +
  `.og-connector{display:inline-flex;align-items:center;gap:.4rem;color:var(--og-brand)}` +
  `.og-connector::before,.og-connector::after{content:"";width:16px;border-top:2px dashed var(--og-border)}` +
  `.og-trust{display:flex;gap:.65rem;align-items:flex-start;margin:1rem 0 .3rem;padding:.75rem .9rem;` +
  `background:var(--og-code);border:1px solid var(--og-border);border-radius:var(--og-radius-sm);font-size:.9rem}` +
  `.og-trust-icon{flex:none;color:var(--og-brand);margin-top:.15rem;display:inline-flex}` +
  `.og-trust strong{font-weight:600}`;

/** Wraps page content in the branded OneGate shell (card + wordmark, light/dark). */
function publicShell(opts: { docTitle: string; body: string; wide?: boolean }): string {
  return (
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<meta name="theme-color" content="#4f46e5">` +
    `<title>${opts.docTitle}</title><style>${PUBLIC_PAGE_CSS}</style></head>` +
    `<body><div class="og-wrap${opts.wide ? " wide" : ""}">` +
    `<div class="og-brand"><span class="og-mark">${BRAND_MARK_SVG}</span>OneGate</div>` +
    `<div class="og-card">${opts.body}</div>` +
    `<div class="og-foot">Credential gateway for AI agents</div>` +
    `</div></body></html>`
  );
}

/**
 * Turns bare http(s) URLs inside already-escaped text into links, so any "go to
 * X" instruction becomes clickable. Input must already be HTML-escaped.
 */
function linkify(escaped: string): string {
  return escaped.replace(
    /(https?:\/\/[^\s<)]+[^\s<).,])/g,
    (u) => `<a href="${u}" target="_blank" rel="noopener noreferrer">${u}</a>`,
  );
}

function resultPage(title: string, body: string): string {
  return publicShell({ docTitle: "OneGate", body: `<h1>${title}</h1><p>${linkify(body)}</p>` });
}

/**
 * Bridge page for providers that return the token in the URL fragment
 * (Trello). The fragment never reaches the server, so this page merges the
 * fragment params into the query string and reloads.
 */
const FRAGMENT_BRIDGE_PAGE = publicShell({
  docTitle: "Connecting…",
  body:
    `<h1>Completing the connection…</h1><p class="og-muted">One moment while we finish connecting your account.</p>` +
    `<script>(() => {` +
    `const frag = new URLSearchParams(location.hash.slice(1));` +
    `const query = new URLSearchParams(location.search);` +
    `for (const [k, v] of frag) query.set(k, v);` +
    `query.set("fragment_bridged", "1");` +
    `location.replace(location.pathname + "?" + query.toString());` +
    `})();</script>`,
});

export function createAdminApp(opts: AdminApiOptions): express.Express {
  const { store, registry, ca } = opts;
  const app = express();
  app.use(express.json());

  const pendingOauth = new Map<string, OauthPending>();

  /**
   * Persist the result of an OAuth round-trip. When the pending state carries a
   * connection name (multi-OAuth), the data lands as a named kind='app'
   * connection (created, or updated in place when re-authorizing an existing
   * one). Writing the connection directly bypasses validateAppData on purpose:
   * OAuth integrations declare no credentialFields, so the data shape
   * ({clientId, accessToken, ...}) would not pass it. With no connection name,
   * the legacy single credentials row is kept for back-compat.
   */
  function persistOauthResult(
    integration: Integration,
    pending: OauthPending,
    data: Record<string, string>,
  ): string | null {
    if (pending.connectionId) {
      store.updateConnection(pending.connectionId, { data });
      return pending.connectionId;
    }
    if (pending.connectionName) {
      const conn = store.createConnection({
        kind: "app",
        vendor: integration.id,
        name: pending.connectionName,
        data,
        ownerAgentId: pending.ownerAgentId ?? null,
        isDefault: pending.isDefault ?? false,
        leaseTtlSeconds: pending.leaseTtlSeconds ?? null,
      });
      return conn.id;
    }
    store.setCredential(integration.id, `${integration.title} OAuth`, data);
    return null;
  }

  /**
   * Connect-wizard auto-wire. Runs only when the pending entry carries a wizard
   * token + agent. Grants the freshly created connection to the agent, ensures
   * an agent-scoped allow rule for the integration exists, and marks the link
   * used. Best-effort per step, but any real failure surfaces to the caller.
   */
  function autowireWizardConnection(
    integration: Integration,
    agentId: string,
    connectionId: string | null,
    wizardToken: string,
  ): void {
    if (connectionId) store.grantConnection(connectionId, "agent", agentId);
    // Resolve the effective access lease for this integration/connection: the
    // owner's per-connection override (chosen in the wizard) wins over the
    // integration default. null = no lease (regular, non-time-boxed).
    const connLeaseTtl = connectionId ? store.getConnection(connectionId)?.leaseTtlSeconds ?? null : null;
    const ttl = store.effectiveLeaseTtlSeconds(integration.id, connLeaseTtl);
    const expiresAt = ttl ? new Date(Date.now() + ttl * 1000).toISOString() : null;
    const agent = store.getAgent(agentId);
    if (agent) {
      const existing = store
        .rulesForAgent(agent)
        .find(
          (r) =>
            r.scope === "agent" &&
            r.subjectId === agentId &&
            r.integrationId === integration.id &&
            r.effect === "allow",
        );
      if (existing) {
        // Re-connecting refreshes the lease on the existing allow rule (a new
        // period starts now, or clears the lease if now always-on).
        store.stampRuleLease(existing.id, expiresAt, ttl);
      } else {
        store.createRule({
          scope: "agent",
          subjectId: agentId,
          integrationId: integration.id,
          methods: ["*"],
          pathGlob: "/**",
          effect: "allow",
          expiresAt,
          leaseTtlSeconds: ttl,
        });
      }
    }
    store.markOnboardingLinkUsed(wizardToken);
  }

  function finishWizard(
    integration: Integration,
    pending: OauthPending,
    connectionId: string | null,
  ): void {
    if (!pending.wizardToken || !pending.wizardAgentId) return;
    autowireWizardConnection(integration, pending.wizardAgentId, connectionId, pending.wizardToken);
  }

  // ---- public routes ----

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true, version: opts.version });
  });

  /** Root CA download so operators can distribute trust easily. */
  app.get("/ca.pem", (_req, res) => {
    res.type("application/x-pem-file").send(ca.rootPem);
  });

  /** Per-integration OAuth descriptor with test overrides applied. */
  function descriptorFor(integration: Integration): OAuthDescriptor | null {
    if (!integration.oauth) return null;
    if (integration.id === "google" && (opts.googleAuthUrl || opts.googleTokenUrl)) {
      return {
        ...integration.oauth,
        authUrl: opts.googleAuthUrl ?? integration.oauth.authUrl,
        tokenUrl: opts.googleTokenUrl ?? integration.oauth.tokenUrl,
      };
    }
    return integration.oauth;
  }

  /**
   * Generic OAuth redirect target (one route serves every integration,
   * including the legacy /oauth/google/callback URI). Unauthenticated by
   * necessity, protected by the single-use random state.
   */
  app.get("/oauth/:integrationId/callback", async (req, res) => {
    const integration = registry.get(req.params.integrationId);
    const oauth = integration ? descriptorFor(integration) : null;
    if (!integration || !oauth) {
      res.status(404).send(resultPage("Unknown integration", "This OneGate has no such OAuth integration."));
      return;
    }
    const q = req.query as Record<string, string | undefined>;
    if (q.error) {
      res
        .status(400)
        .send(resultPage("Connection failed", `${esc(integration.title)} returned an error: ${esc(q.error)}`));
      return;
    }

    // Fragment-callback providers (Trello) put the token after a "#", which
    // the browser never sends. Serve the bridge page once; it resubmits the
    // fragment params as query params.
    const fragParam = oauth.fragmentCallback?.paramName;
    if (fragParam && !q[fragParam] && !q.fragment_bridged) {
      res.type("html").send(FRAGMENT_BRIDGE_PAGE);
      return;
    }

    const state = q.state;
    const pending = state ? pendingOauth.get(state) : undefined;
    if (state) pendingOauth.delete(state);
    if (!pending || pending.integrationId !== integration.id) {
      res.status(400).send(resultPage("Connection failed", "Invalid or expired OAuth state. Restart the connect flow."));
      return;
    }

    // If the agent was deleted between starting consent and the callback, the
    // connection we would persist has no owner to attach to. Reject cleanly
    // instead of storing an orphaned credential.
    if (pending.wizardAgentId && !store.getAgent(pending.wizardAgentId)) {
      invalidLinkPage(res);
      return;
    }

    const isWizard = Boolean(pending.wizardToken && pending.wizardAgentId);
    const done = () => {
      if (isWizard) {
        const agent = pending.wizardAgentId ? store.getAgent(pending.wizardAgentId) : null;
        const who = agent ? esc(agent.name) : "Your bot";
        res.send(
          resultPage(
            `${who} is connected ${CHECK_SVG}`,
            `${who} can now use your ${esc(integration.title)} account. You can close this tab.`,
          ),
        );
        return;
      }
      res.send(
        resultPage(
          `${esc(integration.title)} connected ${CHECK_SVG}`,
          "You can close this tab and return to OneGate.",
        ),
      );
    };

    if (fragParam) {
      const token = q[fragParam];
      if (!token) {
        res.status(400).send(resultPage("Connection failed", `${esc(integration.title)} did not return a token.`));
        return;
      }
      const connId = persistOauthResult(integration, pending, {
        clientId: pending.clientId,
        ...(pending.clientSecret ? { clientSecret: pending.clientSecret } : {}),
        accessToken: token,
      });
      finishWizard(integration, pending, connId);
      done();
      return;
    }

    if (!q.code) {
      res.status(400).send(resultPage("Connection failed", "Missing authorization code. Restart the connect flow."));
      return;
    }
    try {
      const tokens = await exchangeCode(integration.id, oauth, {
        code: q.code,
        clientId: pending.clientId,
        clientSecret: pending.clientSecret,
        redirectUri: pending.redirectUri,
      });
      if (integration.id === "google" && !tokens.refresh_token) {
        res
          .status(502)
          .send(
            resultPage(
              "Connection failed",
              "Google did not return a refresh token. Remove the app's prior grant at myaccount.google.com/permissions and retry.",
            ),
          );
        return;
      }
      const data: Record<string, string> = {
        clientId: pending.clientId,
        clientSecret: pending.clientSecret,
        accessToken: tokens.access_token!,
      };
      if (tokens.refresh_token) data.refreshToken = tokens.refresh_token;
      if (tokens.expires_in) {
        data.expiresAt = String(Math.floor(Date.now() / 1000) + tokens.expires_in);
      }
      const grantedScopes = tokens.scope ?? pending.scopes.join(" ");
      if (grantedScopes) data.scopes = grantedScopes;
      const connId = persistOauthResult(integration, pending, data);
      finishWizard(integration, pending, connId);
      done();
    } catch (err) {
      res.status(502).send(resultPage("Connection failed", esc((err as Error).message)));
    }
  });

  // ---- public connect wizard (per-app, token-scoped, NOT admin-gated) ----

  /** Base URL the wizard links and redirect URIs are built against. */
  function publicBase(): string {
    return (process.env.ONEGATE_PUBLIC_URL || "https://app.onegate.bot").replace(/\/$/, "");
  }

  /** Friendly page for an invalid, expired, or already-used wizard link. */
  function invalidLinkPage(res: express.Response): void {
    res
      .status(410)
      .send(
        resultPage(
          "This link is no longer valid",
          "This connect link has expired or was already used. Ask your bot to start the connection again and it will send you a fresh link.",
        ),
      );
  }

  /** Human duration, e.g. 28800 -> "8h". */
  function fmtDuration(seconds: number): string {
    if (seconds % 3600 === 0) return `${seconds / 3600}h`;
    if (seconds % 60 === 0) return `${seconds / 60}m`;
    return `${seconds}s`;
  }

  /**
   * The owner's access-lease override control, shown ONLY for a time-boxed
   * integration. The owner keeps the integration default, sets a custom hours
   * duration, or chooses always-on (an infinite time box = not time-boxed).
   * Empty string for a regular (non-time-boxed) integration.
   */
  function leaseOverrideControl(integration: Integration): string {
    const def = store.getIntegrationLease(integration.id);
    if (!def || def <= 0) return "";
    return (
      `<fieldset class="og-lease"><legend>Access duration</legend>` +
      `<p class="og-muted">This is a time-boxed connection. Access auto-expires after the period below, then you get a one-tap link to re-allow it (no credential re-entry).</p>` +
      `<label><input type="radio" name="leaseMode" value="default" checked> Default (${esc(fmtDuration(def))})</label>` +
      `<label><input type="radio" name="leaseMode" value="custom"> Custom <input type="number" name="leaseHours" min="1" step="1" placeholder="hours"> hours</label>` +
      `<label><input type="radio" name="leaseMode" value="always"> Always-on (no time limit)</label>` +
      `</fieldset>`
    );
  }

  /**
   * Reads the wizard's lease-override choice. null = inherit the integration
   * default. 0 = always-on. >0 = custom lease seconds. An invalid custom value
   * falls back to null (inherit default).
   */
  function parseLeaseOverride(body: Record<string, unknown>): number | null {
    const mode = typeof body.leaseMode === "string" ? body.leaseMode : "default";
    if (mode === "always") return 0;
    if (mode === "custom") {
      const h = Number(body.leaseHours);
      return Number.isFinite(h) && h > 0 ? Math.round(h * 3600) : null;
    }
    return null;
  }

  /**
   * Renders the self-service connect wizard for one agent + one integration.
   * The owner brings their own OAuth app, pastes its client id and secret, picks
   * scopes, and starts consent. No secrets are ever pre-filled or echoed.
   */
  function wizardPage(integration: Integration, link: OnboardingLink): string {
    const base = publicBase();
    const redirectUri = `${base}/oauth/${integration.id}/callback`;
    const guide = integration.connectGuide ?? {
      steps: [
        `Create an OAuth app in your ${esc(integration.title)} developer console.`,
        "Set its redirect URI to the value shown at the top of this page exactly.",
        "Copy the app's client id and client secret and paste them into the fields below.",
      ],
    };
    // Steps may embed bare URLs ("go to https://..."); linkify makes them
    // clickable so every "go to X" instruction carries a real link.
    const guideSteps = guide.steps.map((s) => `<li>${linkify(esc(s))}</li>`).join("");
    const consoleLink = guide.consoleUrl
      ? `<p class="og-console"><a class="og-btn secondary" href="${esc(guide.consoleUrl)}" target="_blank" rel="noopener noreferrer">Open the ${esc(
          integration.title,
        )} console ↗</a></p>`
      : "";

    // Scope picker. Google exposes product scope-packs as checkboxes, everything
    // else uses its descriptor default scopes carried through as hidden fields.
    let scopePicker = "";
    if (integration.scopePacks && integration.scopePacks.length) {
      const preset = link.scopes;
      const boxes = integration.scopePacks
        .map((pack) => {
          const packScopes = pack.scopes.join(" ");
          const checked = preset ? pack.scopes.some((s) => preset.includes(s)) : pack.default === true;
          return (
            `<label>` +
            `<input type="checkbox" name="scopePack" value="${esc(packScopes)}"${checked ? " checked" : ""}> ` +
            `${esc(pack.label)}${pack.description ? ` <span class="og-muted">(${esc(pack.description)})</span>` : ""}` +
            `</label>`
          );
        })
        .join("");
      scopePicker = `<fieldset><legend>Products to connect</legend>${boxes}</fieldset>`;
    } else {
      const descriptor = descriptorFor(integration);
      const defaults = link.scopes && link.scopes.length ? link.scopes : descriptor?.defaultScopes ?? [];
      scopePicker = defaults.map((s) => `<input type="hidden" name="scope" value="${esc(s)}">`).join("");
    }

    const secretRequired = !descriptorFor(integration)?.fragmentCallback;
    const body =
      pairedLogoHeader(integration) +
      `<h1>Connect ${esc(integration.title)}</h1>` +
      `<p class="og-muted">Bring your own ${esc(integration.title)} OAuth app and connect it to your OneGate agent.</p>` +
      TRUST_PANEL +
      `<h2>1. Add this redirect URI</h2>` +
      `<p>Add this exact redirect URI to your OAuth app.</p>` +
      `<div class="og-redirect">` +
      `<input id="redirect" readonly value="${esc(redirectUri)}">` +
      `<button type="button" class="og-btn secondary" onclick="navigator.clipboard.writeText(document.getElementById('redirect').value);this.textContent='Copied'">Copy</button>` +
      `</div>` +
      `<h2>2. Create your OAuth app</h2>${consoleLink}<ol>${guideSteps}</ol>` +
      `<h2>3. Paste your OAuth app credentials</h2>` +
      `<form method="post" action="${esc(base)}/connect/${esc(integration.id)}/${esc(link.token)}/start">` +
      `<label>Client ID` +
      `<input type="text" name="clientId" required autocomplete="off"></label>` +
      `<label>Client secret` +
      `<input type="password" name="clientSecret"${secretRequired ? " required" : ""} autocomplete="off"></label>` +
      scopePicker +
      leaseOverrideControl(integration) +
      `<button type="submit" class="og-btn block">Connect ${esc(integration.title)}</button>` +
      `</form>`;
    return publicShell({ docTitle: `Connect ${esc(integration.title)} to OneGate`, body, wide: true });
  }

  /**
   * Renders the paste-your-credential wizard for a non-OAuth integration
   * (api_key or credentials_import). The owner follows the integration's guide,
   * pastes the credential fields (a token, a JSON key blob, and so on), and
   * submits. Same auto-wire as OAuth: on submit the connection is created,
   * granted to the agent, and an allow rule is ensured. Secrets go straight
   * into OneGate, never through chat, and nothing is pre-filled or echoed.
   */
  function credentialWizardPage(integration: Integration, link: OnboardingLink): string {
    const base = publicBase();
    const guide = integration.connectGuide;
    const consoleLink = guide?.consoleUrl
      ? `<p class="og-console"><a class="og-btn secondary" href="${esc(guide.consoleUrl)}" target="_blank" rel="noopener noreferrer">Open the ${esc(
          integration.title,
        )} console ↗</a></p>`
      : "";
    const guideSteps = (guide?.steps ?? []).map((s) => `<li>${linkify(esc(s))}</li>`).join("");
    const hint = integration.connect?.hint
      ? `<p class="og-muted">${linkify(esc(integration.connect.hint))}</p>`
      : "";
    const stepsBlock = guideSteps
      ? `<h2>1. Create your ${esc(integration.title)} credential</h2>${consoleLink}<ol>${guideSteps}</ol>` +
        `<h2>2. Paste it below</h2>`
      : "";
    const fields = (integration.credentialFields ?? [])
      .map((f) => {
        const optional = f.optional === true;
        const input = f.multiline
          ? `<textarea name="${esc(f.key)}" rows="6"${optional ? "" : " required"} autocomplete="off"></textarea>`
          : `<input type="${f.secret ? "password" : "text"}" name="${esc(f.key)}"${
              optional ? "" : " required"
            } autocomplete="off">`;
        return (
          `<label>${esc(f.label)}${optional ? ' <span class="og-muted">(optional)</span>' : ""}` +
          `${input}</label>`
        );
      })
      .join("");
    const body =
      pairedLogoHeader(integration) +
      `<h1>Connect ${esc(integration.title)}</h1>` +
      `<p class="og-muted">Connect your ${esc(integration.title)} account to your OneGate agent.</p>` +
      TRUST_PANEL +
      hint +
      stepsBlock +
      `<form method="post" action="${esc(base)}/connect/${esc(integration.id)}/${esc(link.token)}/submit">` +
      fields +
      leaseOverrideControl(integration) +
      `<button type="submit" class="og-btn block">Connect ${esc(integration.title)}</button>` +
      `</form>`;
    return publicShell({ docTitle: `Connect ${esc(integration.title)} to OneGate`, body, wide: true });
  }

  /** GET the wizard page for a scoped link. Rendered as HTML, never redirects. */
  app.get("/connect/:integrationId/:token", (req, res) => {
    const integration = registry.get(req.params.integrationId);
    const kind = integration ? connectFlowKind(integration) : null;
    if (!integration || !kind) {
      res.status(404).send(resultPage("Unknown integration", "This OneGate has no such connectable integration."));
      return;
    }
    const link = store.getOnboardingLink(req.params.token);
    if (!store.isOnboardingLinkValid(link) || link!.integrationId !== integration.id) {
      invalidLinkPage(res);
      return;
    }
    // Don't render the wizard for a link whose agent has been deleted.
    if (!store.getAgent(link!.agentId)) {
      invalidLinkPage(res);
      return;
    }
    const isOauth = kind === "oauth" && descriptorFor(integration);
    res.type("html").send(isOauth ? wizardPage(integration, link!) : credentialWizardPage(integration, link!));
  });

  /**
   * Starts consent from the wizard. Public but token-validated: builds the
   * redirect URI, stores a pending entry carrying the wizard token + agent, and
   * redirects the browser to the provider's consent screen. The callback then
   * auto-wires the connection, grant and allow rule (see finishWizard).
   */
  app.post("/connect/:integrationId/:token/start", express.urlencoded({ extended: false }), (req, res) => {
    const integration = registry.get(req.params.integrationId);
    const oauth = integration ? descriptorFor(integration) : null;
    if (!integration || !oauth) {
      res.status(404).send(resultPage("Unknown integration", "This OneGate has no such OAuth integration."));
      return;
    }
    const link = store.getOnboardingLink(req.params.token);
    if (!store.isOnboardingLinkValid(link) || link!.integrationId !== integration.id) {
      invalidLinkPage(res);
      return;
    }
    // The link's agent may have been deleted after the link was minted; a
    // credential connected now would be orphaned. Reject the redeem cleanly.
    if (!store.getAgent(link!.agentId)) {
      invalidLinkPage(res);
      return;
    }
    const body = (req.body ?? {}) as Record<string, unknown>;
    const clientId = typeof body.clientId === "string" ? body.clientId.trim() : "";
    const clientSecret = typeof body.clientSecret === "string" ? body.clientSecret : "";
    const secretRequired = !oauth.fragmentCallback;
    if (!clientId || (secretRequired && !clientSecret)) {
      res
        .status(400)
        .send(resultPage("Missing details", "Enter your OAuth app client id and secret, then try again."));
      return;
    }

    // Scopes: google sends one or more scopePack values (space-joined scope
    // groups), other integrations send hidden scope fields, else fall back to
    // the link preset then the descriptor defaults.
    const scopeSet = new Set<string>();
    const packVals = ([] as string[]).concat((body.scopePack as string | string[] | undefined) ?? []);
    for (const v of packVals) for (const s of String(v).split(/\s+/).filter(Boolean)) scopeSet.add(s);
    const scopeVals = ([] as string[]).concat((body.scope as string | string[] | undefined) ?? []);
    for (const s of scopeVals) if (s) scopeSet.add(String(s));
    let scopes = [...scopeSet];
    if (!scopes.length) scopes = link!.scopes && link!.scopes.length ? link!.scopes : oauth.defaultScopes;

    const state = randomBytes(16).toString("hex");
    let redirectUri = `${publicBase()}/oauth/${integration.id}/callback`;
    if (oauth.fragmentCallback) redirectUri += `?state=${state}`;
    pendingOauth.set(state, {
      integrationId: integration.id,
      clientId,
      clientSecret: clientSecret ?? "",
      redirectUri,
      scopes,
      createdAt: Date.now(),
      connectionName: link!.connectionName ?? `${integration.title} (self-service)`,
      ownerAgentId: link!.agentId,
      isDefault: false,
      wizardToken: link!.token,
      wizardAgentId: link!.agentId,
      leaseTtlSeconds: parseLeaseOverride(body),
    });
    for (const [k, v] of pendingOauth) {
      if (Date.now() - v.createdAt > 600_000) pendingOauth.delete(k);
    }
    const url = buildAuthUrl(integration.id, oauth, { clientId, redirectUri, scopes, state });
    res.redirect(url);
  });

  /**
   * Submits a pasted credential from the non-OAuth wizard (api_key /
   * credentials_import). Public but token-validated: reads the integration's
   * declared credentialFields from the form, validates them, creates the app
   * connection, then auto-wires it to the agent (grant + allow rule) and marks
   * the link used. The mirror of the OAuth callback for paste credentials.
   */
  app.post(
    "/connect/:integrationId/:token/submit",
    express.urlencoded({ extended: false, limit: "512kb" }),
    (req, res) => {
      const integration = registry.get(req.params.integrationId);
      if (!integration || connectFlowKind(integration) !== "credential") {
        res
          .status(404)
          .send(resultPage("Unknown integration", "This OneGate has no such connectable integration."));
        return;
      }
      const link = store.getOnboardingLink(req.params.token);
      if (!store.isOnboardingLinkValid(link) || link!.integrationId !== integration.id) {
        invalidLinkPage(res);
        return;
      }
      // Reject a redeem whose agent was deleted after the link was minted;
      // otherwise the connection + grant we create would be orphaned.
      if (!store.getAgent(link!.agentId)) {
        invalidLinkPage(res);
        return;
      }
      const form = (req.body ?? {}) as Record<string, unknown>;
      const data: Record<string, string> = {};
      for (const f of integration.credentialFields ?? []) {
        const v = form[f.key];
        if (typeof v === "string" && v.trim() !== "") data[f.key] = f.multiline ? v : v.trim();
      }
      const err = validateAppData(integration.id, data);
      if (err) {
        res
          .status(400)
          .send(resultPage("Missing details", `Please check the form and try again: ${esc(err)}.`));
        return;
      }
      const conn = store.createConnection({
        kind: "app",
        vendor: integration.id,
        name: link!.connectionName ?? `${integration.title} (self-service)`,
        data,
        ownerAgentId: link!.agentId,
        isDefault: false,
        leaseTtlSeconds: parseLeaseOverride(form),
      });
      autowireWizardConnection(integration, link!.agentId, conn.id, link!.token);
      const agent = store.getAgent(link!.agentId);
      const who = agent ? esc(agent.name) : "Your bot";
      res.send(
        resultPage(
          `${who} is connected ${CHECK_SVG}`,
          `${who} can now use your ${esc(integration.title)} account. You can close this tab.`,
        ),
      );
    },
  );

  /**
   * One-tap renewal page for a time-boxed (leased) connection. The proxy mints
   * a renewal link (`/renew/:token`) when an allow rule's lease has lapsed and
   * notifies the owner. The link is a RENEWAL link (link.ruleId set): opening it
   * re-allows the bot for another lease period WITHOUT re-entering any
   * credential. GET renders the confirm page; POST re-stamps the lease.
   */
  app.get("/renew/:token", (req, res) => {
    const link = store.getOnboardingLink(req.params.token);
    if (!store.isOnboardingLinkValid(link) || !link!.ruleId) {
      invalidLinkPage(res);
      return;
    }
    const rule = store.getRule(link!.ruleId);
    if (!rule) {
      invalidLinkPage(res);
      return;
    }
    const integration = registry.get(link!.integrationId);
    const title = integration ? esc(integration.title) : esc(link!.integrationId);
    const agent = store.getAgent(link!.agentId);
    const who = agent ? esc(agent.name) : "Your bot";
    const period = rule.leaseTtlSeconds ? fmtDuration(rule.leaseTtlSeconds) : null;
    const forPeriod = period ? ` for another ${period}` : "";
    res.type("html").send(
      publicShell({
        docTitle: "OneGate",
        body:
          `<h1>Re-allow ${who} to use ${title}?</h1>` +
          `<p class="og-muted">${who}'s time-boxed access to your ${title} account has expired. ` +
          `Re-allowing grants ${who} access${forPeriod}. Your credential is never re-entered and ${who} never sees it.</p>` +
          `<form method="post" action="${publicBase()}/renew/${esc(link!.token)}">` +
          `<button class="og-btn" type="submit">Re-allow${forPeriod}</button>` +
          `</form>`,
      }),
    );
  });

  app.post("/renew/:token", express.urlencoded({ extended: false }), (req, res) => {
    const link = store.getOnboardingLink(req.params.token);
    if (!store.isOnboardingLinkValid(link) || !link!.ruleId) {
      invalidLinkPage(res);
      return;
    }
    const renewed = store.renewRule(link!.ruleId);
    if (!renewed) {
      invalidLinkPage(res);
      return;
    }
    store.markOnboardingLinkUsed(link!.token);
    const integration = registry.get(link!.integrationId);
    const title = integration ? esc(integration.title) : esc(link!.integrationId);
    const agent = store.getAgent(link!.agentId);
    const who = agent ? esc(agent.name) : "Your bot";
    const period = renewed.leaseTtlSeconds ? fmtDuration(renewed.leaseTtlSeconds) : null;
    const untilPhrase =
      period && renewed.expiresAt
        ? ` for the next ${period}`
        : "";
    res.send(
      resultPage(
        `${who} is re-allowed ${CHECK_SVG}`,
        `${who} can use your ${title} account again${untilPhrase}. You can close this tab.`,
      ),
    );
  });

  // ---- admin auth gate ----

  app.use("/api", (req, res, next) => {
    if (!checkAdminToken(store, req.headers.authorization)) {
      res.status(401).json({ error: "invalid_admin_token" });
      return;
    }
    next();
  });

  // ---- agents ----

  /**
   * Derives the agent's three-state LLM mode (managed/passthrough/blocked) from
   * its saved route, the route's connection vendors, and its rules + default
   * policy. Pure read, no new setting. Used by both the agent list and the
   * per-agent LLM endpoint so the badge is consistent across surfaces.
   */
  function agentLlmMode(agent: Agent): LlmMode {
    const cfg = store.getAgentLlmConfig(agent.id);
    const enabled = cfg?.enabled ?? false;
    const connectionVendors: string[] = [];
    for (const id of cfg?.connectionIds ?? []) {
      const conn = store.getConnection(id);
      if (conn && conn.kind === "llm") connectionVendors.push(conn.vendor);
    }
    const rules = store.rulesForAgent(agent).map((r) => ({
      integrationId: r.integrationId,
      effect: r.effect,
    }));
    return deriveLlmMode({
      enabled,
      connectionVendors,
      rules,
      defaultAllow: agent.defaultPolicy === "allow-all",
    });
  }

  function withLlmMode(agent: Agent) {
    return { ...publicAgent(agent), llmMode: agentLlmMode(agent) };
  }

  app.get("/api/agents", (_req, res) => {
    res.json(store.listAgents().map(withLlmMode));
  });

  app.post("/api/agents", (req, res) => {
    const { name, projectId, defaultPolicy } = req.body ?? {};
    if (!name) {
      res.status(400).json({ error: "name_required" });
      return;
    }
    try {
      const { agent, token } = store.createAgent(name, { projectId, defaultPolicy });
      res.status(201).json({ ...publicAgent(agent), token });
    } catch (err) {
      res.status(409).json({ error: (err as Error).message });
    }
  });

  app.patch("/api/agents/:id", (req, res) => {
    const { name, projectId, defaultPolicy } = req.body ?? {};
    const updated = store.updateAgent(req.params.id, { name, projectId, defaultPolicy });
    if (!updated) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    res.json(publicAgent(updated));
  });

  app.post("/api/agents/:id/rotate-token", (req, res) => {
    const token = store.rotateAgentToken(req.params.id);
    if (!token) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    res.json({ token });
  });

  app.delete("/api/agents/:id", (req, res) => {
    store.deleteAgent(req.params.id);
    res.status(204).end();
  });

  // ---- projects ----

  app.get("/api/projects", (_req, res) => res.json(store.listProjects()));

  app.post("/api/projects", (req, res) => {
    if (!req.body?.name) {
      res.status(400).json({ error: "name_required" });
      return;
    }
    try {
      res.status(201).json(store.createProject(req.body.name));
    } catch (err) {
      res.status(409).json({ error: (err as Error).message });
    }
  });

  app.delete("/api/projects/:id", (req, res) => {
    store.deleteProject(req.params.id);
    res.status(204).end();
  });

  // ---- integrations & credentials ----

  app.get("/api/integrations", (_req, res) => {
    const creds = new Map(store.listCredentials().map((c) => [c.integrationId, c]));
    // Count named connections (the live multi-connection model) per integration
    // so the Integrations page can show "N connections" instead of the legacy
    // single connected/not-connected state. App connections are keyed by
    // vendor=integration id, LLM connections by the integration's llm vendor.
    const connCount = new Map<string, number>();
    // A named app connection is default-deny: it exists but is unusable by any
    // bot until granted to an agent or project. Surface the granted count too so
    // the Integrations page can flag connections that exist yet reach no bot
    // (FL2 U3). LLM connections are not grant-gated, so they always count as
    // granted.
    const grantedCount = new Map<string, number>();
    for (const c of store.listConnections()) {
      const key = `${c.kind}:${c.vendor}`;
      connCount.set(key, (connCount.get(key) ?? 0) + 1);
      if (c.kind === "llm" || store.countGrantsForConnection(c.id) > 0) {
        grantedCount.set(key, (grantedCount.get(key) ?? 0) + 1);
      }
    }
    const registered = registry.list().map((i) => ({
      id: i.id,
      title: i.title,
      hosts: i.hosts,
      category: i.category ?? "Other",
      credentialFields: i.credentialFields,
      connect: {
        method: i.connect?.method ?? (i.oauth ? "oauth" : "api_key"),
        hint: i.connect?.hint ?? null,
        fileImport: i.connect?.fileImport ?? null,
      },
      oauth: i.oauth
        ? {
            authUrl: i.oauth.authUrl,
            defaultScopes: i.oauth.defaultScopes,
            permissions: i.oauth.permissions ?? [],
            fragment: Boolean(i.oauth.fragmentCallback),
          }
        : null,
      scopePacks: i.scopePacks ?? null,
      connected: creds.has(i.id),
      credentialName: creds.get(i.id)?.name ?? null,
      connectionCount: i.llm
        ? (connCount.get(`llm:${i.llm.vendor}`) ?? 0)
        : (connCount.get(`app:${i.id}`) ?? 0),
      grantedConnectionCount: i.llm
        ? (grantedCount.get(`llm:${i.llm.vendor}`) ?? 0)
        : (grantedCount.get(`app:${i.id}`) ?? 0),
      llmHelpPrompt: composeLlmHelpPrompt(i),
      llm: i.llm ? { vendor: i.llm.vendor } : null,
      community: Boolean(i.community),
      // Access-lease default: seconds when this integration is time-boxed, else
      // null (a regular, non-time-boxed integration). Owners can override per
      // connection at connect time.
      leaseDefaultSeconds: store.getIntegrationLease(i.id),
      orphaned: false,
    }));
    // Credentials whose integration is not registered (disabled via
    // ONEGATE_DISABLED_INTEGRATIONS, or a removed community integration)
    // would otherwise be invisible and impossible to disconnect from the UI
    // (issue #3886). Surface them flagged orphaned so the UI can offer
    // disconnect; DELETE /api/credentials/:integrationId works for them.
    const registeredIds = new Set(registered.map((i) => i.id));
    const orphaned = store
      .listCredentials()
      .filter((c) => !registeredIds.has(c.integrationId))
      .map((c) => ({
        id: c.integrationId,
        title: c.integrationId,
        hosts: [] as string[],
        category: "Disconnected",
        credentialFields: [],
        connect: { method: "api_key" as const, hint: null, fileImport: null },
        oauth: null,
        scopePacks: null,
        connected: true,
        credentialName: c.name,
        connectionCount: 0,
        grantedConnectionCount: 0,
        llmHelpPrompt: null,
        llm: null,
        community: false,
        orphaned: true,
      }));
    res.json([...registered, ...orphaned]);
  });

  // ---- integration access-lease catalog (time-boxed defaults) ----

  /** Lists integrations that are time-boxed by default, with their TTL. */
  app.get("/api/integration-leases", (_req, res) => {
    res.json(
      store.listIntegrationLeases().map((l) => ({
        integrationId: l.integrationId,
        ttlSeconds: l.ttlSeconds,
        updatedAt: l.updatedAt,
      })),
    );
  });

  /**
   * Marks an integration time-boxed with a default lease TTL, or clears it back
   * to regular (non-time-boxed). Body: { ttlSeconds } where a positive integer
   * sets/updates the default, and 0 or null clears it. This is the catalog-level
   * default an operator sets when curating the available connection types; the
   * owner can still override per connection at connect time.
   */
  app.put("/api/integration-leases/:integrationId", (req, res) => {
    const { integrationId } = req.params;
    if (!registry.get(integrationId)) {
      res.status(404).json({ error: "unknown_integration" });
      return;
    }
    const raw = (req.body ?? {}).ttlSeconds;
    if (raw === null || raw === 0 || raw === "0") {
      store.clearIntegrationLease(integrationId);
      res.json({ integrationId, ttlSeconds: null });
      return;
    }
    const ttl = Number(raw);
    if (!Number.isFinite(ttl) || ttl <= 0 || !Number.isInteger(ttl)) {
      res.status(400).json({ error: "ttl_seconds_positive_integer_required" });
      return;
    }
    store.setIntegrationLease(integrationId, ttl);
    res.json({ integrationId, ttlSeconds: ttl });
  });

  app.delete("/api/integration-leases/:integrationId", (req, res) => {
    store.clearIntegrationLease(req.params.integrationId);
    res.json({ integrationId: req.params.integrationId, ttlSeconds: null });
  });

  app.put("/api/credentials/:integrationId", (req, res) => {
    const { integrationId } = req.params;
    if (!registry.get(integrationId)) {
      res.status(404).json({ error: "unknown_integration" });
      return;
    }
    const { name, data } = req.body ?? {};
    if (!data || typeof data !== "object") {
      res.status(400).json({ error: "data_required" });
      return;
    }
    const cred = store.setCredential(integrationId, name ?? integrationId, data);
    res.json({ id: cred.id, integrationId, name: cred.name });
  });

  app.delete("/api/credentials/:integrationId", (req, res) => {
    store.deleteCredential(req.params.integrationId);
    res.status(204).end();
  });

  // ---- connections (multi-credential, LLM routing) ----

  /** LLM vendor ids known to this registry (anthropic, openai, gemini, ...). */
  function llmVendors(): Set<string> {
    return new Set(
      registry
        .list()
        .filter((i) => i.llm)
        .map((i) => i.llm!.vendor),
    );
  }

  /**
   * Validates LLM connection secret material. anthropic accepts an apiKey OR a
   * subscription authToken (optionally tagged with authMode). gemini needs an
   * apiKey. openai accepts an apiKey OR an imported auth.json shape
   * (accessToken with optional accountId). Unknown llm vendors (community)
   * just need some non-empty material. Returns an error string or null.
   */
  function validateLlmData(vendor: string, data: unknown): string | null {
    if (!data || typeof data !== "object" || Array.isArray(data)) return "data must be an object";
    const d = data as Record<string, unknown>;
    for (const [k, v] of Object.entries(d)) {
      if (typeof v !== "string") return `data.${k} must be a string`;
    }
    if (vendor === "openai") {
      if (!d.apiKey && !d.accessToken) return 'openai connections need "apiKey" or "accessToken"';
      return null;
    }
    if (vendor === "anthropic") {
      if (d.authMode !== undefined && d.authMode !== "api_key" && d.authMode !== "auth_token") {
        return 'anthropic "authMode" must be "api_key" or "auth_token"';
      }
      if (d.authMode === "auth_token") {
        if (!d.authToken) return 'anthropic auth-token connections need "authToken"';
        return null;
      }
      if (d.authMode === "api_key") {
        if (!d.apiKey) return 'anthropic api-key connections need "apiKey"';
        return null;
      }
      if (!d.apiKey && !d.authToken) {
        return 'anthropic connections need "apiKey" or "authToken"';
      }
      return null;
    }
    if (vendor === "gemini") {
      if (!d.apiKey) return `${vendor} connections need "apiKey"`;
      return null;
    }
    if (Object.values(d).every((v) => !v)) return "data must carry at least one non-empty value";
    return null;
  }

  /**
   * Derives a non-secret discriminator describing how a connection authenticates,
   * so the edit dialog can pre-select the right mode without ever seeing the
   * secret. For anthropic this is "api_key" or "auth_token" (matching the
   * integration's own inference: explicit authMode wins, else authToken implies
   * auth_token). For openai it is "api_key" or "auth_json" (an imported
   * auth.json carries accessToken instead of apiKey). Other vendors have no
   * meaningful mode, so undefined is returned and the field is omitted.
   */
  function connectionAuthMode(vendor: string, data: Record<string, string>): string | undefined {
    if (vendor === "anthropic") {
      if (data.authMode === "auth_token" || data.authMode === "api_key") return data.authMode;
      return data.authToken ? "auth_token" : "api_key";
    }
    if (vendor === "openai") {
      return data.accessToken && !data.apiKey ? "auth_json" : "api_key";
    }
    return undefined;
  }

  /**
   * Connections never leave the API with their secret material. The response
   * carries `hasSecret` (true when any non-empty secret field is stored) and,
   * for vendors that have one, a non-secret `authMode` discriminator so the
   * edit dialog can show that a secret is set and pre-select the stored mode.
   */
  function publicConnection(c: {
    id: string;
    kind: string;
    vendor: string;
    name: string;
    data?: Record<string, string>;
    ownerAgentId?: string | null;
    isDefault: boolean;
    leaseTtlSeconds?: number | null;
    createdAt: string;
    updatedAt: string;
  }) {
    const data = c.data ?? {};
    const authMode = connectionAuthMode(c.vendor, data);
    // For app connections the secret preview should track the integration's
    // declared secret fields; for llm connections the vendor's preferred keys.
    const integration = c.kind === "app" ? registry.get(c.vendor) : null;
    const secretKeys = (integration?.credentialFields ?? []).filter((f) => f.secret).map((f) => f.key);
    // A non-secret masked preview of the primary secret so an operator can
    // recognise which key is stored. Derived server-side; the raw secret is
    // never returned (see previewPrimarySecret / maskSecret).
    const secretPreview = previewPrimarySecret(
      data,
      c.kind === "app"
        ? { secretKeys }
        : { preferredKeys: llmPreferredSecretKeys(c.vendor) },
    );
    const ownerAgentId = c.ownerAgentId ?? null;
    return {
      id: c.id,
      kind: c.kind,
      vendor: c.vendor,
      name: c.name,
      ownerAgentId,
      ownerAgentName: ownerAgentId ? (store.getAgent(ownerAgentId)?.name ?? null) : null,
      isDefault: c.isDefault,
      createdAt: c.createdAt,
      updatedAt: c.updatedAt,
      hasSecret: Object.values(data).some((v) => typeof v === "string" && v.trim() !== ""),
      secretPreview,
      // App connections are default-deny: surface how many grants exist so the
      // list view can flag ungranted (= unusable) connections. LLM connections
      // are governed by routing, not grants, so this stays 0 for them.
      ...(c.kind === "app" ? { grantCount: store.countGrantsForConnection(c.id) } : {}),
      // Access lease: for app connections surface whether this connection is
      // time-boxed and its effective duration. leaseOverrideSeconds is the
      // owner's per-connection choice (null=inherit, 0=always-on, >0=custom);
      // leaseEffectiveSeconds is what actually applies (null=not time-boxed).
      ...(c.kind === "app"
        ? {
            leaseOverrideSeconds: c.leaseTtlSeconds ?? null,
            leaseEffectiveSeconds: store.effectiveLeaseTtlSeconds(c.vendor, c.leaseTtlSeconds ?? null),
          }
        : {}),
      ...(authMode !== undefined ? { authMode } : {}),
    };
  }

  /**
   * Validates app connection secret material against the integration's
   * declared credentialFields. Required fields must be present and non-empty,
   * every value must be a string, and unknown keys are rejected. Returns an
   * error string or null.
   */
  function validateAppData(integrationId: string, data: unknown): string | null {
    const integration = registry.get(integrationId);
    if (!integration) return `unknown integration "${integrationId}"`;
    if (!data || typeof data !== "object" || Array.isArray(data)) return "data must be an object";
    const d = data as Record<string, unknown>;
    const fields = integration.credentialFields ?? [];
    const known = new Set(fields.map((f) => f.key));
    for (const [k, v] of Object.entries(d)) {
      if (!known.has(k)) return `unknown field "${k}"`;
      if (typeof v !== "string") return `data.${k} must be a string`;
    }
    for (const f of fields) {
      if (f.optional) continue;
      const v = d[f.key];
      if (typeof v !== "string" || v.trim() === "") return `data.${f.key} is required`;
    }
    if (fields.length > 0 && Object.values(d).every((v) => !v)) {
      return "data must carry at least one non-empty value";
    }
    return null;
  }

  /**
   * All connections, grouped. `llm` rows come from the connections table
   * (multi per vendor, one default each). `apps` mirrors the single-credential
   * integrations so the UI has one connections view; app entries carry the
   * integration metadata and an orphaned flag when the integration is not
   * registered. Secret values are never returned.
   */
  /** Non-secret integration metadata block for an app connection row. */
  function appIntegrationMeta(integrationId: string) {
    const integration = registry.get(integrationId);
    return {
      integration: integration
        ? {
            id: integration.id,
            title: integration.title,
            category: integration.category ?? "Other",
            community: Boolean(integration.community),
          }
        : null,
      orphaned: !integration,
    };
  }

  app.get("/api/connections", (_req, res) => {
    const llm = store.listConnections({ kind: "llm" }).map(publicConnection);
    // Legacy single-credential rows (the credentials table) stay as
    // tenant-wide app entries with a synthetic shape (legacy: true). They have
    // no owner and are always the implicit default for their integration.
    const legacy = store.listCredentials().map((c) => {
      const integration = registry.get(c.integrationId);
      const secretKeys = (integration?.credentialFields ?? [])
        .filter((f) => f.secret)
        .map((f) => f.key);
      const secretPreview = previewPrimarySecret(c.data, { secretKeys });
      return {
        id: c.id,
        kind: "app" as const,
        vendor: c.integrationId,
        name: c.name,
        ownerAgentId: null,
        ownerAgentName: null,
        legacy: true,
        isDefault: true,
        createdAt: c.createdAt,
        updatedAt: c.createdAt,
        hasSecret: true,
        secretPreview,
        ...appIntegrationMeta(c.integrationId),
      };
    });
    // New multi-account app connections (the connections table, kind app).
    const named = store.listConnections({ kind: "app" }).map((c) => ({
      ...publicConnection(c),
      legacy: false,
      ...appIntegrationMeta(c.vendor),
    }));
    res.json({ llm, apps: [...legacy, ...named] });
  });

  app.post("/api/connections", (req, res) => {
    const { kind, vendor, name, data, isDefault, ownerAgentId } = req.body ?? {};
    if (kind !== "llm" && kind !== "app") {
      res.status(400).json({ error: "unsupported_kind", message: 'kind must be "llm" or "app"' });
      return;
    }
    if (typeof name !== "string" || !name.trim()) {
      res.status(400).json({ error: "name_required" });
      return;
    }
    if (kind === "app") {
      // vendor is the integration id, validated against the registry.
      const appIntegration = typeof vendor === "string" ? registry.get(vendor) : undefined;
      if (!appIntegration) {
        res.status(400).json({
          error: "unknown_vendor",
          message: `vendor must be a known integration id`,
        });
        return;
      }
      // OAuth connections cannot be minted by a direct POST: they need the
      // browser round-trip (POST /api/integrations/:id/oauth/start) to obtain a
      // token. Guide the caller there instead of failing on empty data.
      if (appIntegration.oauth) {
        res.status(400).json({
          error: "oauth_connection",
          message: `${appIntegration.title} uses OAuth. Create the connection via the OAuth connect flow (POST /api/integrations/${appIntegration.id}/oauth/start with a connectionName).`,
        });
        return;
      }
      let owner: string | null = null;
      if (ownerAgentId !== undefined && ownerAgentId !== null) {
        if (typeof ownerAgentId !== "string" || !store.getAgent(ownerAgentId)) {
          res.status(400).json({ error: "unknown_agent", message: "ownerAgentId must be an existing agent id" });
          return;
        }
        owner = ownerAgentId;
      }
      const dataError = validateAppData(vendor, data);
      if (dataError) {
        res.status(400).json({ error: "invalid_data", message: dataError });
        return;
      }
      const conn = store.createConnection({
        kind: "app",
        vendor,
        name: name.trim(),
        data,
        ownerAgentId: owner,
        isDefault: isDefault === true,
      });
      res.status(201).json(publicConnection(conn));
      return;
    }
    // kind === "llm"
    if (typeof vendor !== "string" || !llmVendors().has(vendor)) {
      res.status(400).json({
        error: "unknown_vendor",
        message: `vendor must be one of: ${[...llmVendors()].sort().join(", ")}`,
      });
      return;
    }
    const dataError = validateLlmData(vendor, data);
    if (dataError) {
      res.status(400).json({ error: "invalid_data", message: dataError });
      return;
    }
    const conn = store.createConnection({
      kind: "llm",
      vendor,
      name: name.trim(),
      data,
      isDefault: isDefault === true,
    });
    res.status(201).json(publicConnection(conn));
  });

  app.put("/api/connections/:id", (req, res) => {
    const cur = store.getConnection(req.params.id);
    if (!cur) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    const { name, data, isDefault, ownerAgentId } = req.body ?? {};
    if (name !== undefined && (typeof name !== "string" || !name.trim())) {
      res.status(400).json({ error: "invalid_name" });
      return;
    }
    if (isDefault !== undefined && typeof isDefault !== "boolean") {
      res.status(400).json({ error: "invalid_is_default" });
      return;
    }
    // The owner bucket of a connection cannot change after creation (it would
    // move the connection between the tenant-wide and agent-bound buckets and
    // strand saved per-agent choices). Reject any attempt that differs.
    if (ownerAgentId !== undefined && (ownerAgentId ?? null) !== cur.ownerAgentId) {
      res.status(400).json({
        error: "owner_immutable",
        message: "ownerAgentId cannot be changed after creation",
      });
      return;
    }
    // An omitted or empty `data` on update means "keep the stored secret". The
    // edit dialog sends no data when the secret field is left blank, so the
    // existing secret must never be overwritten with nothing.
    const emptyData =
      data !== undefined &&
      data !== null &&
      typeof data === "object" &&
      !Array.isArray(data) &&
      Object.keys(data).length === 0;
    const nextData = data === undefined || emptyData ? undefined : data;
    if (nextData !== undefined) {
      const dataError =
        cur.kind === "llm"
          ? validateLlmData(cur.vendor, nextData)
          : validateAppData(cur.vendor, nextData);
      if (dataError) {
        res.status(400).json({ error: "invalid_data", message: dataError });
        return;
      }
    }
    const updated = store.updateConnection(req.params.id, {
      name: name === undefined ? undefined : name.trim(),
      data: nextData,
      isDefault,
    });
    res.json(publicConnection(updated!));
  });

  /**
   * Disconnects a connection. Any agent_llm_config referencing it has the
   * id removed from its ordered list (the config itself stays, including its
   * enabled flag), and the affected agents' strategy state is reset so
   * counters never point at a connection that no longer exists. The store
   * promotes the oldest remaining connection of the vendor to default when
   * the default is deleted.
   */
  app.delete("/api/connections/:id", (req, res) => {
    const cur = store.getConnection(req.params.id);
    if (cur) {
      if (cur.kind === "app") {
        store.removeConnectionFromAppConfigs(cur.id);
        // OAuth connections cache a live access token in settings keyed on the
        // connection id. Purge it so a re-created connection never reuses it.
        if (registry.get(cur.vendor)?.oauth) {
          store.deleteSetting(`oauth_access_token:${cur.vendor}:${cur.id}`);
        }
      } else {
        for (const agentId of store.removeConnectionFromLlmConfigs(cur.id)) {
          store.clearLlmStrategyState(agentId);
        }
      }
      store.deleteConnection(cur.id);
    }
    res.status(204).end();
  });

  // ---- connection grants (default-deny authorization) ----

  /**
   * Lists the agents/projects a named app connection is granted to. Each grant
   * carries a resolved subjectName for display. Per-connection side of the
   * bidirectional allocation view.
   */
  app.get("/api/connections/:id/grants", (req, res) => {
    const conn = store.getConnection(req.params.id);
    if (!conn || conn.kind !== "app") {
      res.status(404).json({ error: "not_found", message: "no such app connection" });
      return;
    }
    res.json(store.listGrantsForConnection(conn.id));
  });

  /**
   * Grants a named app connection to an agent or a project (the existing
   * "group of agents"). Validates the scope enum and that the subject exists.
   * Idempotent: re-granting is a no-op 201.
   */
  app.post("/api/connections/:id/grants", (req, res) => {
    const conn = store.getConnection(req.params.id);
    if (!conn || conn.kind !== "app") {
      res.status(404).json({ error: "not_found", message: "no such app connection" });
      return;
    }
    const { scope, subjectId } = req.body ?? {};
    if (scope !== "agent" && scope !== "project") {
      res.status(400).json({ error: "invalid_scope", message: 'scope must be "agent" or "project"' });
      return;
    }
    if (typeof subjectId !== "string" || subjectId.trim() === "") {
      res.status(400).json({ error: "invalid_subject", message: "subjectId is required" });
      return;
    }
    const exists = scope === "agent" ? store.getAgent(subjectId) : store.getProject(subjectId);
    if (!exists) {
      res.status(404).json({ error: scope === "agent" ? "unknown_agent" : "unknown_project" });
      return;
    }
    store.grantConnection(conn.id, scope, subjectId);
    res.status(201).json({ connectionId: conn.id, scope, subjectId });
  });

  /** Revokes a grant. No-op (204) if the grant does not exist. */
  app.delete("/api/connections/:id/grants/:scope/:subjectId", (req, res) => {
    const conn = store.getConnection(req.params.id);
    if (!conn || conn.kind !== "app") {
      res.status(404).json({ error: "not_found", message: "no such app connection" });
      return;
    }
    const scope = req.params.scope;
    if (scope !== "agent" && scope !== "project") {
      res.status(400).json({ error: "invalid_scope", message: 'scope must be "agent" or "project"' });
      return;
    }
    store.revokeConnection(conn.id, scope, req.params.subjectId);
    res.status(204).end();
  });

  // ---- per-agent LLM routing config ----

  app.get("/api/agents/:id/llm", (req, res) => {
    const agent = store.getAgent(req.params.id);
    if (!agent) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    const cfg = store.getAgentLlmConfig(agent.id);
    const base = cfg ?? {
      agentId: agent.id,
      enabled: false,
      strategy: "fallback",
      connectionIds: [],
      updatedAt: null,
    };
    res.json({ ...base, mode: agentLlmMode(agent) });
  });

  /**
   * Sets the agent's LLM routing config and resets its persisted strategy
   * state (active index, cursor, cooldowns), so a reconfiguration always
   * starts fresh from the new connection order.
   */
  app.put("/api/agents/:id/llm", (req, res) => {
    const agent = store.getAgent(req.params.id);
    if (!agent) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    const { enabled, strategy, connectionIds } = req.body ?? {};
    if (typeof enabled !== "boolean") {
      res.status(400).json({ error: "invalid_enabled", message: "enabled must be a boolean" });
      return;
    }
    if (strategy !== "fallback" && strategy !== "round-robin") {
      res.status(400).json({ error: "invalid_strategy", message: 'strategy must be "fallback" or "round-robin"' });
      return;
    }
    if (!Array.isArray(connectionIds) || connectionIds.some((id) => typeof id !== "string")) {
      res.status(400).json({ error: "invalid_connection_ids", message: "connectionIds must be an array of strings" });
      return;
    }
    if (new Set(connectionIds).size !== connectionIds.length) {
      res.status(400).json({ error: "invalid_connection_ids", message: "connectionIds must not repeat" });
      return;
    }
    for (const id of connectionIds) {
      const conn = store.getConnection(id);
      if (!conn || conn.kind !== "llm") {
        res.status(400).json({
          error: "unknown_connection",
          message: `"${id}" is not an LLM connection`,
        });
        return;
      }
    }
    const cfg = store.setAgentLlmConfig(agent.id, { enabled, strategy, connectionIds });
    store.clearLlmStrategyState(agent.id);
    res.json(cfg);
  });

  // ---- per-agent app account selection ----

  /**
   * Lists the agent's saved per-integration app account choices, plus the set
   * of app connections this agent may use for each integration (tenant-wide
   * plus its own agent-bound connections). The UI uses this to render the
   * per-agent app accounts section.
   */
  app.get("/api/agents/:id/apps", (req, res) => {
    const agent = store.getAgent(req.params.id);
    if (!agent) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    const configs = store.listAgentAppConfigs(agent.id).map((c) => ({
      integrationId: c.integrationId,
      connectionId: c.connectionId,
      updatedAt: c.updatedAt,
    }));
    // Annotate each available connection with how it is granted to this agent:
    // a direct (scope='agent') grant is revocable from the agent form; a grant
    // inherited via the agent's project is shown but not revocable here (manage
    // it on the Connections page, where it affects every agent in the project).
    const projectName = agent.projectId ? (store.getProject(agent.projectId)?.name ?? null) : null;
    const available = store.listAppConnectionsForAgent(agent.id).map((c) => {
      const grants = store.listGrantsForConnection(c.id);
      const direct = grants.some((g) => g.scope === "agent" && g.subjectId === agent.id);
      return {
        ...publicConnection(c),
        grantVia: direct ? "agent" : "project",
        grantProjectId: direct ? null : agent.projectId,
        grantProjectName: direct ? null : projectName,
      };
    });
    res.json({ agentId: agent.id, configs, available });
  });

  /**
   * Per-agent side of the bidirectional allocation view: the app connections
   * granted to this agent (directly or via its project), each annotated with
   * the saved default-account choice for its integration. Never serializes raw
   * secret data.
   */
  app.get("/api/agents/:id/connections", (req, res) => {
    const agent = store.getAgent(req.params.id);
    if (!agent) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    const savedByIntegration = new Map(
      store.listAgentAppConfigs(agent.id).map((c) => [c.integrationId, c.connectionId]),
    );
    const granted = store.listGrantedConnectionsForAgent(agent.id).map((c) => ({
      ...publicConnection(c),
      ...appIntegrationMeta(c.vendor),
      savedDefault: savedByIntegration.get(c.vendor) === c.id,
    }));
    res.json({ agentId: agent.id, granted });
  });

  /**
   * Saves or clears the agent's app account choice for one integration. A null
   * (or omitted) connectionId clears the choice. The connection must be an app
   * connection this agent is permitted to use (tenant-wide or its own).
   */
  app.put("/api/agents/:id/apps/:integrationId", (req, res) => {
    const agent = store.getAgent(req.params.id);
    if (!agent) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    const integrationId = req.params.integrationId;
    if (!registry.get(integrationId)) {
      res.status(400).json({ error: "unknown_integration", message: `unknown integration "${integrationId}"` });
      return;
    }
    const { connectionId } = req.body ?? {};
    if (connectionId === undefined || connectionId === null || connectionId === "") {
      store.clearAgentAppConfig(agent.id, integrationId);
      res.json({ agentId: agent.id, integrationId, connectionId: null, updatedAt: null });
      return;
    }
    if (typeof connectionId !== "string") {
      res.status(400).json({ error: "invalid_connection_id", message: "connectionId must be a string" });
      return;
    }
    const permitted = store.listAppConnectionsForAgent(agent.id, integrationId);
    const conn = permitted.find((c) => c.id === connectionId);
    if (!conn) {
      res.status(400).json({
        error: "unknown_connection",
        message: `"${connectionId}" is not an app connection available to agent "${agent.name}" for integration "${integrationId}"`,
      });
      return;
    }
    const cfg = store.setAgentAppConfig(agent.id, integrationId, connectionId);
    res.json(cfg);
  });

  // ---- per-agent owner notify webhook ----

  /**
   * GET /api/agents/:id/notify — returns the agent's current notify webhook URL
   * (masked for safety: only shown in full on explicit get, never in list APIs).
   */
  app.get("/api/agents/:id/notify", (req, res) => {
    const agent = store.getAgent(req.params.id);
    if (!agent) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    const webhookUrl = store.getAgentNotify(agent.id);
    res.json({ agentId: agent.id, webhookUrl });
  });

  /**
   * PUT /api/agents/:id/notify { webhookUrl } — sets the notify webhook URL
   * for an agent. Stored encrypted at rest.
   */
  app.put("/api/agents/:id/notify", (req, res) => {
    const agent = store.getAgent(req.params.id);
    if (!agent) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    const { webhookUrl } = req.body ?? {};
    if (typeof webhookUrl !== "string" || !webhookUrl.trim()) {
      res.status(400).json({ error: "invalid_webhook_url", message: "webhookUrl must be a non-empty string" });
      return;
    }
    store.setAgentNotify(agent.id, webhookUrl.trim());
    res.json({ agentId: agent.id, webhookUrl: webhookUrl.trim() });
  });

  /**
   * DELETE /api/agents/:id/notify — clears the notify webhook URL for an agent.
   */
  app.delete("/api/agents/:id/notify", (req, res) => {
    const agent = store.getAgent(req.params.id);
    if (!agent) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    store.clearAgentNotify(agent.id);
    res.status(204).end();
  });

  /**
   * GET /api/owner-notifications — lists recent owner notifications for
   * observability. Optional ?status filter, ?limit (default 100, max 500).
   */
  app.get("/api/owner-notifications", (req, res) => {
    const limit = req.query.limit ? Number(req.query.limit) : 100;
    if (!Number.isInteger(limit) || limit < 1) {
      res.status(400).json({ error: "invalid_limit" });
      return;
    }
    const status = req.query.status as string | undefined;
    const validStatuses = new Set(["pending", "delivered", "failed", "suppressed"]);
    if (status && !validStatuses.has(status)) {
      res.status(400).json({ error: "invalid_status", message: `status must be one of: ${[...validStatuses].join(", ")}` });
      return;
    }
    const rows = store.listOwnerNotifications({
      limit,
      status: status as "pending" | "delivered" | "failed" | "suppressed" | undefined,
    });
    res.json(rows);
  });

  // ---- usage ----

  /**
   * LLM usage: per-connection and per-vendor rollups (requests, errors,
   * failovers, tokens) over an optional ISO time range (?since, ?until,
   * default the last 7 days), plus the most recent selection events
   * (?limit, default 100) showing which connection each request routed to.
   */
  app.get("/api/usage", (req, res) => {
    const parseTs = (v: unknown): string | null | undefined => {
      if (v === undefined) return undefined;
      const ms = Date.parse(String(v));
      return Number.isNaN(ms) ? null : new Date(ms).toISOString();
    };
    const since = parseTs(req.query.since);
    const until = parseTs(req.query.until);
    if (since === null || until === null) {
      res.status(400).json({ error: "invalid_time_range", message: "since/until must be ISO timestamps" });
      return;
    }
    const effectiveSince = since ?? new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();
    const range = { since: effectiveSince, until };
    const limit = req.query.limit ? Number(req.query.limit) : 100;
    if (!Number.isInteger(limit) || limit < 1) {
      res.status(400).json({ error: "invalid_limit" });
      return;
    }
    const names = new Map(store.listConnections().map((c) => [c.id, c.name]));
    const agentNames = new Map(store.listAgents().map((a) => [a.id, a.name]));
    // Estimated turns (see store.segmentTurns): OneGate sees requests, not
    // turns, so these are inferred from request gaps and are an ESTIMATE. Merge
    // them onto the model and bot rollups so the UI/CLI can show a turns column.
    const turnsByModel = new Map(
      store.estimatedTurnsByModel(range).map((t) => [`${t.vendor ?? ""}|${t.model ?? ""}`, t.estimatedTurns]),
    );
    const turnsByBotModel = new Map(
      store
        .estimatedTurnsByAgentModel(range)
        .map((t) => [`${t.agentId ?? ""}|${t.vendor ?? ""}|${t.model ?? ""}`, t.estimatedTurns]),
    );
    res.json({
      since: effectiveSince,
      until: until ?? null,
      // Flags turn counts below as inferred, not exact. TURN_GAP_MS = 60000.
      turnEstimate: { estimated: true, gapMs: 60_000 },
      connections: store.llmUsageByConnection(range).map((r) => ({
        ...r,
        // Prefer the connection's current name; deleted connections keep the
        // last name the usage log saw.
        connectionName: names.get(r.connectionId) ?? r.connectionName,
      })),
      vendors: store.llmUsageByVendor(range),
      models: store.llmUsageByModel(range).map((r) => ({
        ...r,
        estimatedTurns: turnsByModel.get(`${r.vendor ?? ""}|${r.model ?? ""}`) ?? 0,
      })),
      // Per bot per model. agent_id is resolved to the current agent name;
      // deleted agents fall back to their raw id.
      bots: store.llmUsageByAgentModel(range).map((r) => ({
        ...r,
        agentName: (r.agentId && agentNames.get(r.agentId)) ?? r.agentId,
        estimatedTurns:
          turnsByBotModel.get(`${r.agentId ?? ""}|${r.vendor ?? ""}|${r.model ?? ""}`) ?? 0,
      })),
      recent: store.listLlmUsage({ limit, ...range }).map((e) => ({
        id: e.id,
        ts: e.ts,
        agentId: e.agentId,
        vendor: e.vendor,
        connectionId: e.connectionId,
        connectionName: names.get(e.connectionId) ?? e.connectionName,
        strategy: e.strategy,
        failover: e.failover,
        outcome: e.errors > 0 ? "error" : "ok",
        status: e.status,
        inputTokens: e.inputTokens,
        outputTokens: e.outputTokens,
      })),
    });
  });

  // ---- OAuth connect (generic, every integration with a descriptor) ----

  app.post("/api/integrations/:integrationId/oauth/start", (req, res) => {
    const integration = registry.get(req.params.integrationId);
    if (!integration) {
      res.status(404).json({ error: "unknown_integration" });
      return;
    }
    const oauth = descriptorFor(integration);
    if (!oauth) {
      res.status(400).json({ error: "oauth_not_supported" });
      return;
    }
    const { clientId, clientSecret, redirectBase, scopes, connectionName, connectionId, ownerAgentId, isDefault } =
      req.body ?? {};
    // Fragment providers (Trello) authorize with the client id alone; the
    // secret is optional there and stored only for completeness.
    const secretRequired = !oauth.fragmentCallback;
    if (!clientId || !redirectBase || (secretRequired && !clientSecret)) {
      res.status(400).json({
        error: secretRequired
          ? "clientId, clientSecret and redirectBase are required"
          : "clientId and redirectBase are required",
      });
      return;
    }
    let requestedScopes = oauth.defaultScopes;
    if (scopes !== undefined) {
      if (!Array.isArray(scopes) || scopes.some((s) => typeof s !== "string")) {
        res.status(400).json({ error: "scopes must be an array of strings" });
        return;
      }
      requestedScopes = scopes;
    }
    // Multi-OAuth: either re-authorize an existing named connection
    // (connectionId), or create a new one (connectionName). Absent both = the
    // legacy single-credential connect (kept for back-compat).
    let reauthConn: Connection | null = null;
    if (connectionId !== undefined) {
      if (typeof connectionId !== "string") {
        res.status(400).json({ error: "connectionId must be a string" });
        return;
      }
      reauthConn = store.getConnection(connectionId);
      if (!reauthConn || reauthConn.kind !== "app" || reauthConn.vendor !== integration.id) {
        res.status(404).json({ error: "unknown_connection" });
        return;
      }
    } else if (connectionName !== undefined) {
      if (typeof connectionName !== "string" || !connectionName.trim()) {
        res.status(400).json({ error: "connectionName must be a non-empty string" });
        return;
      }
      if (ownerAgentId !== undefined && ownerAgentId !== null) {
        if (typeof ownerAgentId !== "string" || !store.getAgent(ownerAgentId)) {
          res.status(400).json({ error: "unknown ownerAgentId" });
          return;
        }
      }
    }
    const state = randomBytes(16).toString("hex");
    let redirectUri = `${String(redirectBase).replace(/\/$/, "")}/oauth/${integration.id}/callback`;
    // Fragment providers do not echo the state param back; carry it in the
    // redirect URI's own query string instead.
    if (oauth.fragmentCallback) redirectUri += `?state=${state}`;
    pendingOauth.set(state, {
      integrationId: integration.id,
      clientId,
      clientSecret: clientSecret ?? "",
      redirectUri,
      scopes: requestedScopes,
      createdAt: Date.now(),
      ...(reauthConn ? { connectionId: reauthConn.id } : {}),
      ...(reauthConn ? {} : connectionName !== undefined ? { connectionName: String(connectionName).trim() } : {}),
      ...(reauthConn ? {} : { ownerAgentId: ownerAgentId ?? null, isDefault: isDefault === true }),
    });
    // Single-use states; drop anything older than 10 minutes.
    for (const [k, v] of pendingOauth) {
      if (Date.now() - v.createdAt > 600_000) pendingOauth.delete(k);
    }
    const url = buildAuthUrl(integration.id, oauth, {
      clientId,
      redirectUri,
      scopes: requestedScopes,
      state,
    });
    res.json({ url, redirectUri });
  });

  // ---- rules ----

  app.get("/api/rules", (_req, res) => res.json(store.listRules()));

  app.post("/api/rules", (req, res) => {
    const { scope, subjectId, integrationId, methods, pathGlob, effect, ttlSeconds, connectionId, connectionScope } =
      req.body ?? {};
    if (!scope || !subjectId || !integrationId || !effect) {
      res.status(400).json({ error: "scope, subjectId, integrationId and effect are required" });
      return;
    }
    // Optional connection scoping: pins the rule to a specific app connection.
    // connectionScope "only"|"except" is required when connectionId is given.
    if (connectionScope != null && connectionScope !== "only" && connectionScope !== "except") {
      res.status(400).json({ error: 'connectionScope must be "only" or "except"' });
      return;
    }
    if (connectionScope != null && !connectionId) {
      res.status(400).json({ error: "connectionScope requires connectionId" });
      return;
    }
    if (connectionId && connectionScope == null) {
      res.status(400).json({ error: "connectionId requires connectionScope" });
      return;
    }
    // Optional access lease on an allow rule: ttlSeconds>0 sets a time box that
    // expires at now+ttl; 0/null = no lease. Only meaningful on allow rules.
    let expiresAt: string | null = null;
    let leaseTtl: number | null = null;
    if (effect === "allow" && ttlSeconds != null && Number(ttlSeconds) > 0) {
      leaseTtl = Math.floor(Number(ttlSeconds));
      expiresAt = new Date(Date.now() + leaseTtl * 1000).toISOString();
    }
    res.status(201).json(
      store.createRule({
        scope,
        subjectId,
        integrationId,
        methods: Array.isArray(methods) && methods.length ? methods : ["*"],
        pathGlob: pathGlob || "/**",
        effect,
        expiresAt,
        leaseTtlSeconds: leaseTtl,
        ...(connectionId ? { connectionId, connectionScope } : {}),
      }),
    );
  });

  /**
   * One-tap-equivalent renewal over the admin API: re-stamps a leased allow
   * rule's expiry to now + its recorded TTL. No-op on a rule with no lease.
   */
  app.post("/api/rules/:id/renew", (req, res) => {
    const renewed = store.renewRule(req.params.id);
    if (!renewed) {
      res.status(404).json({ error: "unknown_rule" });
      return;
    }
    res.json(renewed);
  });

  app.delete("/api/rules/:id", (req, res) => {
    store.deleteRule(req.params.id);
    res.status(204).end();
  });

  // ---- connect-wizard onboarding links (admin mint) ----

  app.post("/api/onboarding-links", (req, res) => {
    const { agentId, integrationId, scopes, connectionName, ttlDays } = req.body ?? {};
    if (!agentId || !integrationId) {
      res.status(400).json({ error: "agentId and integrationId are required" });
      return;
    }
    if (!store.getAgent(String(agentId))) {
      res.status(404).json({ error: "unknown_agent" });
      return;
    }
    const integration = registry.get(String(integrationId));
    if (!integration || !connectFlowKind(integration)) {
      res.status(400).json({ error: "integration_not_connectable" });
      return;
    }
    const link = store.createOnboardingLink({
      agentId: String(agentId),
      integrationId: integration.id,
      scopes: Array.isArray(scopes) ? scopes.map(String) : undefined,
      connectionName: typeof connectionName === "string" && connectionName.trim() ? connectionName.trim() : undefined,
      ttlDays: typeof ttlDays === "number" && ttlDays > 0 ? ttlDays : undefined,
    });
    const base = (process.env.ONEGATE_PUBLIC_URL || "https://app.onegate.bot").replace(/\/$/, "");
    res.status(201).json({
      token: link.token,
      url: `${base}/connect/${integration.id}/${link.token}`,
      expiresAt: link.expiresAt,
    });
  });

  app.get("/api/onboarding-links", (req, res) => {
    const agentId = req.query.agentId ? String(req.query.agentId) : undefined;
    // Admin-only list. The token is included so an operator can rebuild the
    // connect URL and revoke a link (DELETE /api/onboarding-links/:token).
    res.json(
      store.listOnboardingLinks(agentId).map((l) => ({
        token: l.token,
        agentId: l.agentId,
        integrationId: l.integrationId,
        connectionName: l.connectionName,
        createdAt: l.createdAt,
        expiresAt: l.expiresAt,
        usedAt: l.usedAt,
        valid: store.isOnboardingLinkValid(l),
      })),
    );
  });

  app.delete("/api/onboarding-links/:token", (req, res) => {
    store.deleteOnboardingLink(req.params.token);
    res.status(204).end();
  });

  // ---- audit ----

  app.get("/api/audit", (req, res) => {
    const rows = store.listAudit({
      limit: req.query.limit ? Number(req.query.limit) : undefined,
      agentId: req.query.agentId ? String(req.query.agentId) : undefined,
    });
    // Resolve each LLM-routed row's connection id to the connection's CURRENT
    // name so a rename shows through. The id falls back to the name captured at
    // request time, then to the bare id, when the connection has been deleted.
    const currentNames = new Map(store.listConnections().map((c) => [c.id, c.name]));
    res.json(
      rows.map((r) => ({
        ...r,
        llmConnectionName: r.connectionId
          ? currentNames.get(r.connectionId) ?? r.connectionName ?? r.connectionId
          : null,
      })),
    );
  });

  // ---- static web UI ----

  const uiDir = join(dirname(fileURLToPath(import.meta.url)), "ui");
  app.use(express.static(uiDir));

  return app;
}

function publicAgent(a: {
  id: string;
  name: string;
  projectId: string | null;
  defaultPolicy: string;
  createdAt: string;
}) {
  return {
    id: a.id,
    name: a.name,
    projectId: a.projectId,
    defaultPolicy: a.defaultPolicy,
    createdAt: a.createdAt,
  };
}

