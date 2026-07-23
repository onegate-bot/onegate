// UI sanity smoke: serve the static admin UI (with a tiny mock /api) and load
// it in headless Chromium. Fails on: page errors, console errors/warnings
// (Web Awesome reports component autoload failures as warnings), unexpected
// 404s, wa-* components never defined, the auth screen not visible, or any
// app page failing to render its content marker. Runs mobile + desktop.
//
// Playwright is resolved from PW_DIR (a directory containing node_modules with
// playwright installed) so the repo's own lockfile stays untouched:
//   mkdir -p /tmp/pw && cd /tmp/pw && npm i playwright@1.52.0
//   npx --prefix /tmp/pw playwright install --with-deps chromium
//   PW_DIR=/tmp/pw node scripts/ui-smoke.mjs

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "admin", "ui");
const MARKER = "OneGate";
const REQUIRED_COMPONENTS = ["wa-button", "wa-input", "wa-drawer", "wa-dialog"];
// Components every authed page set must end up defining.
const AUTHED_COMPONENTS = ["wa-badge", "wa-select", "wa-spinner"];
const API_404_OK = /^\/api\//; // unmocked backend routes 404 under static serving

// Known-benign third-party noise to ignore. WebAwesome's <wa-option> runs its
// slot-change handler during the upgrade window before the parent <wa-select>
// has defined its own handleDefaultSlotChange, throwing a transient
// "controller.handleDefaultSlotChange is not a function". The select still
// upgrades and renders correctly; the error is intermittent and internal to the
// vendored WA build, so it must not fail the smoke. Matched by exact signature
// only so real errors still surface.
const IGNORED_ERRORS = [/handleDefaultSlotChange is not a function/];
const isIgnored = (text) => IGNORED_ERRORS.some((re) => re.test(text));

const require = createRequire(join(process.env.PW_DIR || process.cwd(), "x.js"));
const { chromium } = require("playwright");

// ------------------------------------------------------------- mock backend

const NOW = new Date().toISOString();
const MOCK_INTEGRATION = (over) => ({
  id: "github",
  title: "GitHub",
  hosts: ["api.github.com"],
  category: "Developer",
  credentialFields: [{ key: "pat", label: "Personal access token", secret: true }],
  connect: { method: "api_key", hint: null, fileImport: null },
  oauth: null,
  scopePacks: null,
  connected: false,
  credentialName: null,
  connectionCount: 0,
  grantedConnectionCount: 0,
  llmHelpPrompt: "help",
  llm: null,
  community: false,
  orphaned: false,
  ...over,
});

const MOCK_API = {
  "/api/health": { ok: true, version: "0.0.0-smoke" },
  "/api/agents": [
    { id: "ag_smoke", name: "smoke-agent", projectId: "pr_smoke", defaultPolicy: "deny-unmatched", createdAt: NOW, llmMode: "managed" },
  ],
  "/api/projects": [{ id: "pr_smoke", name: "smoke-project", createdAt: NOW }],
  "/api/rules": [
    {
      id: "rl_smoke", scope: "agent", subjectId: "ag_smoke", integrationId: "github",
      methods: ["*"], pathGlob: "/**", effect: "allow", createdAt: NOW,
    },
  ],
  "/api/audit": [
    {
      ts: NOW, agentName: "smoke-agent", decision: "allow", method: "GET",
      host: "api.github.com", path: "/user", status: 200, llmConnectionName: null,
      source: "upstream", reason: "Allowed by OneGate",
    },
    {
      ts: NOW, agentName: "smoke-agent", decision: "allow", method: "POST",
      host: "api.anthropic.com", path: "/v1/messages", status: 200, llmConnectionName: "Anthropic smoke",
      source: "upstream", reason: "Allowed by OneGate",
    },
    {
      ts: NOW, agentName: "smoke-agent", decision: "deny", method: "GET",
      host: "your-team.atlassian.net", path: "/rest/api/3/myself", status: 403, llmConnectionName: null,
      source: "onegate", reason: "Blocked by OneGate. Add an allow rule",
    },
  ],
  "/api/integrations": [
    MOCK_INTEGRATION({ connected: true, credentialName: "GitHub PAT", connectionCount: 2, grantedConnectionCount: 2 }),
    MOCK_INTEGRATION({
      id: "anthropic", title: "Anthropic", hosts: ["api.anthropic.com"], category: "AI",
      credentialFields: [{ key: "apiKey", label: "API key", secret: true }], llm: { vendor: "anthropic" },
      connectionCount: 1, grantedConnectionCount: 1,
    }),
    MOCK_INTEGRATION({
      id: "openai", title: "OpenAI", hosts: ["api.openai.com"], category: "AI",
      credentialFields: [{ key: "apiKey", label: "API key", secret: true }], llm: { vendor: "openai" },
      connectionCount: 1, grantedConnectionCount: 1,
    }),
    // FL2 U3: a named app connection that exists but is granted to no bot, so
    // it is unusable (default-deny). The card must flag this, not show green.
    MOCK_INTEGRATION({
      id: "stripe", title: "Stripe", hosts: ["api.stripe.com"], category: "Payments",
      credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
      connectionCount: 1, grantedConnectionCount: 0,
    }),
    MOCK_INTEGRATION({
      id: "gitlab", title: "GitLab", hosts: ["gitlab.com"], category: "Developer",
      credentialFields: [], connect: { method: "oauth", hint: null, fileImport: null },
      oauth: { authUrl: "https://gitlab.com/oauth/authorize" },
      // Multi-OAuth (FL1): one named OAuth connection plus a legacy shared
      // credential, so the OAuth card shows a count badge, "Add connection",
      // "Manage connections" and "Disconnect legacy".
      connected: true, credentialName: "GitLab legacy", connectionCount: 1,
    }),
    MOCK_INTEGRATION({
      id: "smoke-custom", title: "Smoke Custom", hosts: ["api.smoke.dev"], category: "Other",
      connected: true, credentialName: "Custom cred", community: true, connectionCount: 1,
    }),
    // Legacy descriptor-less OAuth integration (no oauth descriptor): keeps
    // Connect / Disconnect on the Integrations card (FL2 D1 carve-out).
    MOCK_INTEGRATION({
      id: "legacy-oauth", title: "Legacy OAuth", hosts: ["api.legacy.dev"], category: "Other",
      credentialFields: [], connect: { method: "oauth", hint: null, fileImport: null },
      oauth: null, connected: true, credentialName: "Legacy cred",
    }),
    MOCK_INTEGRATION({
      id: "old-thing", title: "old-thing", hosts: [], category: "Disconnected",
      credentialFields: [], connected: true, credentialName: "Orphan cred", llmHelpPrompt: null, orphaned: true,
    }),
  ],
  "/api/connections": {
    llm: [
      { id: "conn_a", kind: "llm", vendor: "anthropic", name: "Anthropic smoke", isDefault: true, hasSecret: true, secretPreview: "sk-ant-api03...4GwA", authMode: "auth_token", createdAt: NOW, updatedAt: NOW },
      { id: "conn_b", kind: "llm", vendor: "openai", name: "OpenAI smoke", isDefault: true, hasSecret: true, secretPreview: "sk-proj-AbCd...wxyz", authMode: "api_key", createdAt: NOW, updatedAt: NOW },
    ],
    apps: [
      {
        id: "cred_1", kind: "app", vendor: "github", name: "GitHub PAT", isDefault: true,
        createdAt: NOW, updatedAt: NOW, orphaned: false, secretPreview: "ghp_AbCdEfGh...7890",
        integration: { id: "github", title: "GitHub", category: "Developer", community: false },
      },
      {
        id: "cred_2", kind: "app", vendor: "smoke-custom", name: "Custom cred", isDefault: true,
        createdAt: NOW, updatedAt: NOW, orphaned: false,
        integration: { id: "smoke-custom", title: "Smoke Custom", category: "Other", community: true },
      },
      {
        id: "cred_3", kind: "app", vendor: "old-thing", name: "Orphan cred", isDefault: true,
        createdAt: NOW, updatedAt: NOW, orphaned: true, integration: null,
      },
      // Multi-OAuth (FL1): a named OAuth connection. Because its integration
      // connects via OAuth, the Connections page renders a "Re-authorize"
      // button beside Edit/Disconnect.
      {
        id: "conn_gl", kind: "app", vendor: "gitlab", name: "GitLab work", isDefault: true,
        createdAt: NOW, updatedAt: NOW, orphaned: false, secretPreview: "ya29.AbCdEf...wxyz",
        integration: { id: "gitlab", title: "GitLab", category: "Developer", community: false },
      },
    ],
  },
  "/api/agents/ag_smoke/llm": {
    agentId: "ag_smoke", enabled: true, strategy: "fallback", connectionIds: ["conn_a", "conn_b"], updatedAt: NOW, mode: "managed",
  },
  // Agent form "App accounts": two github connections available to the agent,
  // one granted directly (revocable here) and one inherited via the project
  // (shown disabled). Exercises the agent-side disallow control.
  "/api/agents/ag_smoke/apps": {
    agentId: "ag_smoke",
    configs: [{ integrationId: "github", connectionId: "cred_1" }],
    available: [
      {
        id: "cred_1", kind: "app", vendor: "github", name: "GitHub PAT", isDefault: true,
        ownerAgentId: "ag_smoke", createdAt: NOW, updatedAt: NOW, orphaned: false, secretPreview: "ghp_AbCdEfGh...7890",
        integration: { id: "github", title: "GitHub", category: "Developer", community: false },
        grantVia: "agent", grantProjectId: null, grantProjectName: null,
      },
      {
        id: "cred_4", kind: "app", vendor: "github", name: "GitHub shared", isDefault: false,
        ownerAgentId: null, createdAt: NOW, updatedAt: NOW, orphaned: false, secretPreview: "ghp_ShArEdXx...1234",
        integration: { id: "github", title: "GitHub", category: "Developer", community: false },
        grantVia: "project", grantProjectId: "pr_smoke", grantProjectName: "smoke-project",
      },
    ],
  },
  "/api/usage": {
    since: NOW,
    until: null,
    connections: [
      { connectionId: "conn_a", connectionName: "Anthropic smoke", vendor: "anthropic", requests: 12, errors: 1, failovers: 1, inputTokens: 3400, outputTokens: 1800 },
    ],
    vendors: [{ vendor: "anthropic", requests: 12, errors: 1, failovers: 1, inputTokens: 3400, outputTokens: 1800 }],
    recent: [
      {
        id: 1, ts: NOW, agentId: "ag_smoke", vendor: "anthropic", connectionId: "conn_a",
        connectionName: "Anthropic smoke", strategy: "fallback", failover: true, outcome: "ok",
        status: 200, inputTokens: 200, outputTokens: 90,
      },
    ],
  },
};

// Page set checked while authed: hash route → content marker that proves the
// view actually rendered with the mock data.
const PAGES = [
  { hash: "#/dashboard", marker: "Recent activity" },
  { hash: "#/agents", marker: "smoke-agent" },
  { hash: "#/projects", marker: "smoke-project" },
  { hash: "#/integrations", marker: "GitHub" },
  { hash: "#/connections", marker: "Anthropic smoke" },
  { hash: "#/rules", marker: "deny" },
  { hash: "#/audit", marker: "Blocked by OneGate" },
  { hash: "#/usage", marker: "Recent selections" },
];

const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".json": "application/json" };
// Per-connection grants (default-deny authorization). cred_1 is granted to the
// smoke agent + project so the "Granted to" column renders both chip kinds;
// cred_2 has none so the default-deny warning renders.
const MOCK_GRANTS = {
  cred_1: [
    { scope: "agent", subjectId: "ag_smoke", subjectName: "smoke-agent", createdAt: NOW },
    { scope: "project", subjectId: "pr_smoke", subjectName: "smoke-project", createdAt: NOW },
  ],
  cred_2: [],
};

const server = createServer(async (req, res) => {
  let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
  // Connect wizard: POST mints a single-use onboarding link (M5).
  if (p === "/api/onboarding-links" && req.method === "POST") {
    res.writeHead(201, { "content-type": "application/json" });
    return res.end(
      JSON.stringify({
        token: "smoke-token",
        url: `${base}connect/gitlab/smoke-token`,
        expiresAt: NOW,
      }),
    );
  }
  // Dynamic: GET /api/connections/:id/grants → grant list for that connection.
  const grantMatch = /^\/api\/connections\/([^/]+)\/grants$/.exec(p);
  if (grantMatch && req.method === "GET") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify(MOCK_GRANTS[grantMatch[1]] ?? []));
  }
  const mock = MOCK_API[p];
  if (mock !== undefined) {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify(mock));
  }
  if (p.endsWith("/")) p += "index.html";
  const file = normalize(join(ROOT, p));
  if (!file.startsWith(normalize(ROOT))) { res.writeHead(403); return res.end(); }
  try {
    const buf = await readFile(file);
    res.writeHead(200, { "content-type": types[extname(file)] || "application/octet-stream" });
    res.end(buf);
  } catch { res.writeHead(404); res.end("not found"); }
});
await new Promise((r) => server.listen(0, r));
const base = `http://localhost:${server.address().port}/`;

const launchOpts = { args: ["--no-sandbox"] };
// Allow pointing at a system Chromium when no Playwright-managed browser is installed.
if (process.env.PW_CHROMIUM) launchOpts.executablePath = process.env.PW_CHROMIUM;
const browser = await chromium.launch(launchOpts);
let failures = [];

function watch(page, problems) {
  page.on("pageerror", (e) => {
    if (isIgnored(String(e))) return;
    problems.push(`pageerror: ${e}`);
  });
  page.on("console", (m) => {
    if (m.type() !== "error" && m.type() !== "warning") return;
    if (isIgnored(m.text())) return;
    const at = m.location()?.url ?? "";
    if (API_404_OK.test(new URL(at, base).pathname)) return; // expected: unmocked backend route
    problems.push(`console.${m.type()}: ${m.text().slice(0, 200)}`);
  });
  page.on("response", (r) => {
    const path = new URL(r.url()).pathname;
    if (r.status() === 404 && !API_404_OK.test(path)) problems.push(`404: ${path}`);
  });
}

for (const viewport of [{ width: 390, height: 800 }, { width: 1280, height: 800 }]) {
  const label = `${viewport.width}px`;
  const problems = [];

  // Pass A: no token stored → the auth screen must show.
  {
    const page = await browser.newPage({ viewport });
    watch(page, problems);
    await page.goto(base, { waitUntil: "networkidle", timeout: 30000 });
    await page.waitForTimeout(1500);
    for (const tag of REQUIRED_COMPONENTS) {
      const defined = await page.evaluate((t) => !!customElements.get(t), tag);
      if (!defined) problems.push(`component never defined: <${tag}>`);
    }
    const text = await page.evaluate(() => document.body.innerText);
    if (!text.includes(MARKER)) problems.push(`marker "${MARKER}" not visible (body text: ${JSON.stringify(text.slice(0, 120))})`);
    await page.close();
  }

  // Pass B: token in storage (the mock accepts anything) → every page renders.
  {
    const page = await browser.newPage({ viewport });
    watch(page, problems);
    await page.addInitScript(() => localStorage.setItem("onegate_admin_token", "oga_smoke"));
    await page.goto(base, { waitUntil: "networkidle", timeout: 30000 });
    await page.waitForTimeout(1200);
    for (const { hash, marker } of PAGES) {
      await page.goto(base + hash, { timeout: 30000 });
      const ok = await page
        .waitForFunction((m) => document.body.innerText.includes(m), marker, { timeout: 8000 })
        .then(() => true)
        .catch(() => false);
      if (!ok) {
        const text = await page.evaluate(() => document.body.innerText);
        problems.push(`page ${hash}: marker "${marker}" not visible (body text: ${JSON.stringify(text.slice(0, 160))})`);
      }
    }
    for (const tag of [...REQUIRED_COMPONENTS, ...AUTHED_COMPONENTS]) {
      const defined = await page.evaluate((t) => !!customElements.get(t), tag);
      if (!defined) problems.push(`component never defined: <${tag}>`);
    }

    // The Connections page must render a masked secret preview, and that
    // preview must be the mock's masked string, never an unmasked secret.
    await page.goto(base + "#/connections", { timeout: 30000 });
    const previews = await page
      .waitForFunction(
        () => {
          const nodes = [...document.querySelectorAll(".secret-preview")];
          return nodes.length ? nodes.map((n) => n.textContent.trim()) : false;
        },
        undefined,
        { timeout: 8000 },
      )
      .then((h) => h.jsonValue())
      .catch(() => null);
    if (!previews || !previews.includes("sk-ant-api03...4GwA")) {
      problems.push(`connections: masked secret preview not rendered (saw ${JSON.stringify(previews)})`);
    }

    // Default-deny grants UI: the "Granted to" column must render chips for a
    // granted connection, a default-deny warning for an ungranted one, and an
    // "Add grant" control on each named app connection.
    const grantUi = await page
      .waitForFunction(
        () => {
          const cells = [...document.querySelectorAll(".grants-cell")];
          if (!cells.length) return false;
          return {
            cells: cells.length,
            chips: document.querySelectorAll(".grant-chip").length,
            warnings: document.querySelectorAll(".grant-warning").length,
            adders: document.querySelectorAll("[data-add-grant]").length,
            revokers: document.querySelectorAll("[data-revoke-conn]").length,
          };
        },
        undefined,
        { timeout: 8000 },
      )
      .then((h) => h.jsonValue())
      .catch(() => null);
    if (!grantUi || grantUi.chips < 2 || grantUi.warnings < 1 || grantUi.adders < 1 || grantUi.revokers < 2) {
      problems.push(`connections: grants control not rendered (saw ${JSON.stringify(grantUi)})`);
    }

    // Multi-OAuth (FL1): a named OAuth connection must offer a "Re-authorize"
    // button (re-runs the consent flow against the same connection) beside
    // Edit/Disconnect.
    const reauth = await page.evaluate(() => document.querySelectorAll("[data-reauth-conn]").length).catch(() => 0);
    if (!reauth) {
      problems.push(`connections: OAuth re-authorize control not rendered (saw ${reauth})`);
    }

    // Agent-side disallow control: opening the agent editor must render, in the
    // "App accounts" section, a per-connection disallow button that is enabled
    // for a directly-granted connection and disabled for a project-inherited
    // one (so a grant can be revoked from the agent level, not only Connections).
    await page.goto(base + "#/agents", { timeout: 30000 });
    await page.waitForFunction(() => document.querySelector("[data-edit]"), undefined, { timeout: 8000 }).catch(() => {});

    // D3: derived LLM-mode badge in the agent LIST (managed/passthrough/blocked).
    const listMode = await page
      .waitForFunction(
        () => {
          const cell = document.querySelector("[data-llm-mode]");
          if (!cell) return false;
          const badge = cell.querySelector("wa-badge");
          if (!badge) return false;
          return { mode: cell.getAttribute("data-llm-mode"), text: badge.textContent.trim() };
        },
        undefined,
        { timeout: 8000 },
      )
      .then((h) => h.jsonValue())
      .catch(() => null);
    if (!listMode || listMode.mode !== "managed" || !listMode.text) {
      problems.push(`agents: list LLM-mode badge not rendered (saw ${JSON.stringify(listMode)})`);
    }

    // Connect wizard (M5): each agent row carries a "Connect link" button that
    // opens the connect-link dialog and mints a single-use onboarding link.
    const connectBtn = await page
      .waitForFunction(() => !!document.querySelector("[data-connect]"), undefined, { timeout: 8000 })
      .then(() => true)
      .catch(() => false);
    if (!connectBtn) {
      problems.push("agents: connect-link button not rendered");
    }

    await page.evaluate(() => document.querySelector("[data-edit]")?.click());

    // D3: read-only LLM-mode indicator in the agent EDITOR modal.
    const editorMode = await page
      .waitForFunction(
        () => {
          const row = document.querySelector(".llm-mode-row[data-llm-mode]");
          if (!row) return false;
          const badge = row.querySelector("wa-badge");
          if (!badge) return false;
          return { mode: row.getAttribute("data-llm-mode"), text: badge.textContent.trim() };
        },
        undefined,
        { timeout: 8000 },
      )
      .then((h) => h.jsonValue())
      .catch(() => null);
    if (!editorMode || editorMode.mode !== "managed" || !editorMode.text) {
      problems.push(`agents: editor LLM-mode indicator not rendered (saw ${JSON.stringify(editorMode)})`);
    }
    const agentRevoke = await page
      .waitForFunction(
        () => {
          const btns = [...document.querySelectorAll("[data-agent-revoke-conn]")];
          if (!btns.length) return false;
          return {
            total: btns.length,
            enabled: btns.filter((b) => !b.disabled).length,
            disabled: btns.filter((b) => b.disabled).length,
          };
        },
        undefined,
        { timeout: 8000 },
      )
      .then((h) => h.jsonValue())
      .catch(() => null);
    if (!agentRevoke || agentRevoke.enabled < 1 || agentRevoke.disabled < 1) {
      problems.push(`agents: app-account disallow control not rendered (saw ${JSON.stringify(agentRevoke)})`);
    }

    // Integrations page (multi-connection paradigm, #5038 + FL1 multi-OAuth):
    // app/llm cards must show a connection-count badge + an "Add connection"
    // button + a "Manage connections" button when count>0. OAuth cards (FL1) get
    // the SAME paradigm: "Add connection" (data-add-oauth), "Manage connections"
    // when named connections exist, and a "Disconnect legacy" affordance for any
    // legacy shared credential. data-connect survives only on orphaned/legacy
    // descriptor-less cards.
    await page.goto(base + "#/integrations", { timeout: 30000 });
    const intUi = await page
      .waitForFunction(
        () => {
          const adders = document.querySelectorAll("[data-add-app],[data-add-llm]");
          if (!adders.length) return false;
          return {
            addApp: document.querySelectorAll("[data-add-app]").length,
            addLlm: document.querySelectorAll("[data-add-llm]").length,
            addOauth: document.querySelectorAll("[data-add-oauth]").length,
            manage: document.querySelectorAll("[data-manage]").length,
            disconnect: document.querySelectorAll("[data-disconnect]").length,
            badges: document.querySelectorAll(".card.integration wa-badge").length,
            legacyConnect: document.querySelectorAll("[data-connect]").length,
            // FL2 U4: connected/available/all segmented filter.
            filterBtns: document.querySelectorAll("#integration-filter wa-button").length,
            // FL2 U3: a named connection granted to no bot must flag a risk
            // (Stripe mock: connectionCount 1, grantedConnectionCount 0).
            warnBadge: document.querySelectorAll('.card.integration wa-badge[variant="warning"]').length,
            warnHint: document.querySelectorAll(".card.integration .hint.warn").length,
          };
        },
        undefined,
        { timeout: 8000 },
      )
      .then((h) => h.jsonValue())
      .catch(() => null);
    if (
      !intUi ||
      intUi.addApp < 1 ||
      intUi.addLlm < 1 ||
      intUi.addOauth < 1 ||
      intUi.manage < 1 ||
      intUi.disconnect < 1 ||
      intUi.badges < 1 ||
      intUi.legacyConnect < 1 ||
      intUi.filterBtns < 3 ||
      intUi.warnBadge < 1 ||
      intUi.warnHint < 1
    ) {
      problems.push(`integrations: FL2 discovery controls not rendered (saw ${JSON.stringify(intUi)})`);
    }

    // FL2 U1/U2: a "Manage" button deep-links to the Connections page focused on
    // one integration via #/connections?focus=<id>, and the Connections page
    // exposes a live search box + a focus chip that narrows the listing.
    await page.goto(base + "#/connections?focus=github", { timeout: 30000 });
    const connFocus = await page
      .waitForFunction(
        () => {
          const search = document.querySelector("#conn-search");
          const focusBar = document.querySelector(".focus-bar");
          if (!search) return false;
          // With focus=github, only github app connections should remain visible.
          const vendors = new Set(
            [...document.querySelectorAll("#conn-sections .card tbody tr")]
              .filter((tr) => tr.offsetParent !== null)
              .map((tr) => tr.getAttribute("data-vendor")),
          );
          return {
            hasSearch: !!search,
            hasFocusBar: !!focusBar,
            otherVendors: [...vendors].filter((v) => v && v !== "github").length,
          };
        },
        undefined,
        { timeout: 8000 },
      )
      .then((h) => h.jsonValue())
      .catch(() => null);
    if (!connFocus || !connFocus.hasSearch || !connFocus.hasFocusBar || connFocus.otherVendors > 0) {
      problems.push(`connections: FL2 focus/search not rendered (saw ${JSON.stringify(connFocus)})`);
    }

    await page.close();
  }

  if (problems.length) failures.push(...problems.map((p) => `[${label}] ${p}`));
}

await browser.close();
server.close();

if (failures.length) {
  console.error("UI smoke FAILED:");
  failures.forEach((f) => console.error("  " + f));
  process.exit(1);
}
console.log(`UI smoke passed (auth + ${PAGES.length} pages, mobile + desktop).`);
