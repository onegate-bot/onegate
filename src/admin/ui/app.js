/**
 * OneGate admin UI. Vanilla ES module on Web Awesome components, no build step.
 * Organized as: helpers → theme → API client → auth → dialog/toast → one
 * section per view → router & boot.
 */

import { beginGeneration, currentGeneration, isCurrentGeneration } from "./render-generation.js";

const TOKEN_KEY = "onegate_admin_token";
const VIEWS = ["dashboard", "agents", "projects", "integrations", "connections", "rules", "audit", "usage"];
const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const PROXY_PORT = 8443;

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

// ---------------------------------------------------------------- helpers

/** Escape a value for safe interpolation into HTML. */
function esc(v) {
  return String(v ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
}

function fmtDate(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
}

/** "8h" / "30m" / "45s" for an access-lease duration in seconds. Falsy -> "". */
function fmtLeaseSeconds(s) {
  if (!s) return "";
  return s % 3600 === 0 ? `${s / 3600}h` : s % 60 === 0 ? `${s / 60}m` : `${s}s`;
}

/**
 * Parse an access-lease duration input: bare seconds, or "Nh"/"Nm"/"Ns".
 * Blank or "0" -> null (regular, not time-boxed). Throws on garbage.
 */
function parseLeaseInput(v) {
  const t = String(v ?? "").trim();
  if (!t || t === "0") return null;
  const m = t.match(/^(\d+)\s*(h|m|s)?$/i);
  if (!m) throw new Error(`invalid duration "${t}" (use "8h", "30m", or seconds)`);
  const n = Number(m[1]);
  const unit = (m[2] ?? "s").toLowerCase();
  const secs = unit === "h" ? n * 3600 : unit === "m" ? n * 60 : n;
  return secs > 0 ? secs : null;
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  if (btn) {
    const old = btn.textContent;
    btn.textContent = "Copied ✓";
    btn.disabled = true;
    setTimeout(() => {
      btn.textContent = old;
      btn.disabled = false;
    }, 1400);
  }
}

/** Wire every [data-copy-text] button inside `root` to copy its payload. */
function wireCopyButtons(root) {
  $$("[data-copy-text]", root).forEach((btn) => {
    btn.addEventListener("click", () => copyText(btn.dataset.copyText, btn));
  });
}

// ---------------------------------------------------------------- vendored icons

// Point Web Awesome's icon resolver at the vendored Font Awesome subset so no
// request ever leaves for ka-f.fontawesome.com (Claw DS: vendored, never CDN).
{
  // .src (not getAttribute) so the URL is absolute. A relative string is a bare
  // module specifier to import() and rejects, killing this entire module.
  const loaderSrc = document.querySelector('script[src$="webawesome.loader.js"]').src;
  const { setIconPath } = await import(loaderSrc);
  setIconPath(loaderSrc.replace(/\/webawesome\.loader\.js$/, "/icons"));
}

// ---------------------------------------------------------------- theme

const THEME_KEY = "onegate_theme";
const darkMedia = window.matchMedia("(prefers-color-scheme: dark)");

function effectiveTheme() {
  const stored = localStorage.getItem(THEME_KEY);
  if (stored === "light" || stored === "dark") return stored;
  return darkMedia.matches ? "dark" : "light";
}

function applyTheme() {
  const dark = effectiveTheme() === "dark";
  document.documentElement.classList.toggle("wa-dark", dark);
  document.documentElement.classList.toggle("wa-light", !dark);
  const label = dark ? "Switch to light mode" : "Switch to dark mode";
  $$(".theme-toggle").forEach((b) => {
    b.textContent = dark ? "☀ Light mode" : "☾ Dark mode";
    b.setAttribute("aria-label", label);
    b.title = label;
  });
}

$$(".theme-toggle").forEach((b) =>
  b.addEventListener("click", () => {
    localStorage.setItem(THEME_KEY, effectiveTheme() === "dark" ? "light" : "dark");
    applyTheme();
  }),
);
darkMedia.addEventListener("change", applyTheme);
applyTheme();

// ---------------------------------------------------------------- toast

function toast(msg, kind = "error") {
  const region = $("#toast-region");
  const note = document.createElement("wa-callout");
  note.setAttribute("variant", kind === "success" ? "success" : "danger");
  note.setAttribute("size", "s");
  note.textContent = msg;
  region.append(note);
  setTimeout(() => note.remove(), 4500);
}

// ---------------------------------------------------------------- API client

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function api(path, opts = {}) {
  let res;
  try {
    res = await fetch(path, {
      ...opts,
      headers: {
        Authorization: `Bearer ${localStorage.getItem(TOKEN_KEY) ?? ""}`,
        ...(opts.body ? { "Content-Type": "application/json" } : {}),
        ...opts.headers,
      },
    });
  } catch (err) {
    throw new ApiError(`Network error: ${err.message}`, 0);
  }
  if (res.status === 401) {
    logout("Admin token rejected. Sign in again.");
    throw new ApiError("unauthorized", 401);
  }
  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.json()).error ?? "";
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(detail || `${res.status} ${res.statusText}`, res.status);
  }
  return res.status === 204 ? null : res.json();
}

// ---------------------------------------------------------------- auth

function showAuth(message) {
  $("#app").classList.add("hidden");
  $("#auth-screen").classList.remove("hidden");
  const err = $("#auth-error");
  err.textContent = message ?? "";
  err.classList.toggle("hidden", !message);
  $("#auth-token").focus();
}

function showApp() {
  $("#auth-screen").classList.add("hidden");
  $("#app").classList.remove("hidden");
  route();
}

function logout(message) {
  localStorage.removeItem(TOKEN_KEY);
  closeModal(true);
  showAuth(message);
}

/** Returns true if the token is accepted, false on 401. Throws on other failures. */
async function verifyToken(token) {
  const res = await fetch("/api/agents", { headers: { Authorization: `Bearer ${token}` } });
  if (res.status === 401) return false;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return true;
}

$("#auth-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const token = ($("#auth-token").value ?? "").trim();
  if (!token) return;
  const btn = $('#auth-form wa-button[type="submit"]');
  btn.disabled = true;
  try {
    if (await verifyToken(token)) {
      localStorage.setItem(TOKEN_KEY, token);
      $("#auth-token").value = "";
      showApp();
    } else {
      showAuth("Invalid admin token.");
    }
  } catch (err) {
    showAuth(`Could not reach the server: ${err.message}`);
  } finally {
    btn.disabled = false;
  }
});

$("#logout").addEventListener("click", () => logout());
$("#logout-drawer").addEventListener("click", () => {
  closeDrawer();
  logout();
});

// ---------------------------------------------------------------- mobile nav drawer

const drawer = $("#nav-drawer");
$("#drawer-nav").innerHTML = $("#nav").innerHTML;

function closeDrawer() {
  drawer.open = false;
}

$("#open-nav").addEventListener("click", () => {
  drawer.open = true;
});
$("#drawer-nav").addEventListener("click", (e) => {
  if (e.target.closest("a")) closeDrawer();
});

// ---------------------------------------------------------------- modal (wa-dialog)

const modal = $("#modal");
let modalSticky = false;
let modalForceClose = false;
let onModalClose = null;

function openModal(html, { sticky = false, label = "" } = {}) {
  modalSticky = sticky;
  modalForceClose = false;
  onModalClose = null;
  modal.label = label;
  modal.innerHTML = html;
  modal.open = true;
  $$("[data-close]", modal).forEach((b) => b.addEventListener("click", () => closeModal(true)));
  wireCopyButtons(modal);
  return modal;
}

function closeModal(force = false) {
  if (modalSticky && !force) return;
  if (!modal.open) return;
  modalForceClose = true;
  modal.open = false;
}

// Block backdrop/escape/✕ dismissal of sticky modals. Guard on e.target so
// wa-hide events bubbling out of nested components (e.g. wa-details) are ignored.
modal.addEventListener("wa-hide", (e) => {
  if (e.target !== modal) return;
  if (modalSticky && !modalForceClose) e.preventDefault();
});

modal.addEventListener("wa-after-hide", (e) => {
  if (e.target !== modal) return;
  modal.innerHTML = "";
  modalSticky = false;
  modalForceClose = false;
  if (onModalClose) {
    const cb = onModalClose;
    onModalClose = null;
    cb();
  }
});

/**
 * Styled replacement for window.confirm(). Resolves true on confirm, false
 * when the dialog is dismissed any other way (cancel, escape, backdrop).
 */
function confirmModal({ title, body, confirmLabel = "Confirm", danger = true }) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => {
      if (!done) {
        done = true;
        resolve(v);
      }
    };
    openModal(
      `
      <p class="modal-body">${esc(body)}</p>
      <div class="modal-actions">
        <wa-button type="button" appearance="outlined" data-close>Cancel</wa-button>
        <wa-button type="button" variant="${danger ? "danger" : "brand"}" id="confirm-ok">${esc(confirmLabel)}</wa-button>
      </div>
    `,
      { label: title },
    );
    onModalClose = () => finish(false);
    $("#confirm-ok", modal).addEventListener("click", () => {
      finish(true);
      closeModal(true);
    });
  });
}

/**
 * Set an integration's default access lease (time-box). Resolves to a number of
 * seconds, 0 for regular (cleared), or null if cancelled. The owner who makes an
 * actual connection can still override this per-connection at connect time.
 */
function timeboxModal(integration) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => {
      if (!done) {
        done = true;
        resolve(v);
      }
    };
    const cur = integration.leaseDefaultSeconds;
    openModal(
      `
      <p class="modal-body">Time-boxed connections lapse after a set period. When a bot's access lapses it is denied and the owner gets a one-tap renewal link. The owner who connects the credential can override this at connect time, including "always-on".</p>
      <div class="field">
        <span class="field-label">Default time-box</span>
        <wa-input id="timebox-dur" value="${esc(fmtLeaseSeconds(cur))}" placeholder="e.g. 8h, 30m, or blank for regular"></wa-input>
        <span class="muted small-text">Blank or 0 means regular (not time-boxed).</span>
      </div>
      <div class="modal-actions">
        <wa-button type="button" appearance="outlined" data-close>Cancel</wa-button>
        <wa-button type="button" variant="brand" id="timebox-save">Save</wa-button>
      </div>
    `,
      { label: `Time-box ${integration.title}` },
    );
    onModalClose = () => finish(null);
    $("#timebox-save", modal).addEventListener("click", () => {
      let secs;
      try {
        secs = parseLeaseInput($("#timebox-dur", modal).value);
      } catch (err) {
        toast(err.message);
        return;
      }
      finish(secs ?? 0);
      closeModal(true);
    });
  });
}

/** One-time display of a freshly minted agent token. Sticky: only the explicit button closes it. */
function showTokenModal(heading, token) {
  const envLine = `HTTPS_PROXY=http://agent:${token}@${location.hostname}:${PROXY_PORT}`;
  openModal(
    `
    <wa-callout variant="warning">
      <strong>Save this token now.</strong> It is shown only once and cannot be recovered.
      You can rotate it later if it is lost.
    </wa-callout>
    <div class="field" style="margin-top:1rem">
      <span class="field-label">Agent token</span>
      <div class="copy-row">
        <code class="copy-box">${esc(token)}</code>
        <wa-button type="button" size="s" appearance="outlined" data-copy-text="${esc(token)}">Copy</wa-button>
      </div>
    </div>
    <div class="field">
      <span class="field-label">Ready-made proxy env line</span>
      <div class="copy-row">
        <code class="copy-box">${esc(envLine)}</code>
        <wa-button type="button" size="s" appearance="outlined" data-copy-text="${esc(envLine)}">Copy</wa-button>
      </div>
    </div>
    <div class="modal-actions">
      <wa-button type="button" variant="brand" data-close>I saved the token</wa-button>
    </div>
  `,
    { sticky: true, label: heading },
  );
}

// ---------------------------------------------------------------- shared fragments

function emptyState(text) {
  return `<p class="empty">${esc(text)}</p>`;
}

function loadingState(label = "Loading") {
  return `<div class="loading"><wa-spinner aria-hidden="true"></wa-spinner>${esc(label)}…</div>`;
}

const DECISION_VARIANTS = {
  allow: "success",
  deny: "danger",
  passthrough: "neutral",
  auth_failed: "warning",
  no_credential: "warning",
};

function decisionBadge(decision) {
  const variant = DECISION_VARIANTS[decision] ?? "neutral";
  return `<wa-badge variant="${variant}" appearance="filled-outlined">${esc(decision)}</wa-badge>`;
}

// Tells the operator at a glance whether OneGate blocked the request or the
// upstream service did. A 403 OneGate writes for a default-deny agent looks
// identical in status to a 403 the API returns, so the source label is the
// disambiguator (see audit-meta.ts).
function sourceBadge(r) {
  if (r.source === "onegate") {
    return `<wa-badge variant="danger" appearance="filled" title="${esc(r.reason ?? "")}">Blocked by OneGate</wa-badge>`;
  }
  if (r.reason) {
    return `<wa-badge variant="warning" appearance="filled-outlined" title="${esc(r.reason)}">Upstream</wa-badge>`;
  }
  return `<span class="muted">–</span>`;
}

function policyBadge(policy) {
  const variant = policy === "allow-all" ? "warning" : "success";
  return `<wa-badge variant="${variant}" appearance="filled-outlined">${esc(policy)}</wa-badge>`;
}

// Derived LLM-mode meta (managed/passthrough/blocked). Server-computed, read only.
const LLM_MODE_META = {
  managed: {
    variant: "success",
    label: "Managed",
    help: "OneGate injects a managed connection key with failover and usage accounting.",
  },
  passthrough: {
    variant: "neutral",
    label: "Passthrough",
    help: "Agent uses its own key. OneGate forwards without injecting.",
  },
  blocked: {
    variant: "danger",
    label: "Blocked",
    help: "LLM will not work through OneGate. Route is off with connections attached, or policy denies the route vendor.",
  },
};

function llmModeBadge(mode) {
  const meta = LLM_MODE_META[mode] ?? LLM_MODE_META.passthrough;
  return `<wa-badge variant="${meta.variant}" appearance="filled-outlined" title="${esc(meta.help)}">${esc(meta.label)}</wa-badge>`;
}

function auditTable(rows) {
  if (!rows.length) return emptyState("No requests recorded yet.");
  return `
    <div class="table-wrap"><table>
      <thead><tr>
        <th>Time</th><th>Agent</th><th>Decision</th><th>Source</th><th>Method</th>
        <th>Host</th><th>Path</th><th>Connection</th><th>Status</th>
      </tr></thead>
      <tbody>${rows
        .map(
          (r) => `<tr>
            <td class="muted nowrap">${esc(fmtDate(r.ts))}</td>
            <td>${esc(r.agentName ?? "–")}</td>
            <td>${decisionBadge(r.decision)}</td>
            <td>${sourceBadge(r)}</td>
            <td class="mono">${esc(r.method ?? "–")}</td>
            <td class="mono">${esc(r.host)}</td>
            <td class="mono cell-clip" title="${esc(r.path ?? "")}">${esc(r.path ?? "–")}</td>
            <td class="cell-clip" title="${esc(r.llmConnectionName ?? "")}">${r.llmConnectionName ? esc(r.llmConnectionName) : `<span class="muted">–</span>`}</td>
            <td class="mono">${r.status == null ? "–" : esc(r.status)}</td>
          </tr>${
            r.reason
              ? `<tr class="audit-reason-row"><td></td><td colspan="8" class="muted audit-reason">${esc(r.reason)}</td></tr>`
              : ""
          }`,
        )
        .join("")}</tbody>
    </table></div>`;
}

function selectOptions(items, { selected = null, none = null } = {}) {
  const opts = [];
  if (none) opts.push(`<wa-option value="">${esc(none)}</wa-option>`);
  for (const it of items) {
    const sel = it.value === selected ? " selected" : "";
    opts.push(`<wa-option value="${esc(it.value)}"${sel}>${esc(it.label)}</wa-option>`);
  }
  return opts.join("");
}

// ------------------------------------------- integration connect dialogs
// Shared by the Integrations and Connections views. Every entry point takes
// an `onSaved` callback that re-renders whichever view opened the dialog.

function llmHelpHtml(integration) {
  if (!integration.llmHelpPrompt) return "";
  return `
    <wa-details class="llm-help" summary="Get help from your LLM">
      <p class="hint">
        Not sure how to create this credential? Copy this prompt into ChatGPT, Claude or any
        other LLM and it will walk you through the setup step by step.
      </p>
      <pre class="prompt-preview">${esc(integration.llmHelpPrompt)}</pre>
      <wa-button type="button" size="s" appearance="outlined" data-copy-text="${esc(integration.llmHelpPrompt)}">
        Copy prompt
      </wa-button>
    </wa-details>`;
}

function credentialFieldsHtml(integration) {
  return integration.credentialFields
    .map((f) => {
      const label = `${esc(f.label)}${f.optional ? " (optional)" : ""}`;
      const required = f.optional ? "" : "required";
      if (f.multiline) {
        return `<wa-textarea class="field" name="cred_${esc(f.key)}" label="${label}" rows="7" ${required}
                  spellcheck="false" autocomplete="off"></wa-textarea>`;
      }
      return `<wa-input class="field" name="cred_${esc(f.key)}" label="${label}"
                type="${f.secret ? "password" : "text"}" ${required}
                spellcheck="false" autocomplete="off"></wa-input>`;
    })
    .join("");
}

async function submitCredentials(integration, form, onSaved) {
  const fd = new FormData(form);
  const data = {};
  for (const f of integration.credentialFields) data[f.key] = String(fd.get(`cred_${f.key}`) ?? "").trim();
  await api(`/api/credentials/${encodeURIComponent(integration.id)}`, {
    method: "PUT",
    body: JSON.stringify({ name: String(fd.get("cred_name") ?? "").trim() || integration.title, data }),
  });
  closeModal(true);
  toast(`${integration.title} connected.`, "success");
  await onSaved();
}

function fileImportHtml(fi) {
  if (!fi) return "";
  return `
    <div class="field file-import-row">
      <input type="file" id="cred-file" accept="${esc(fi.accept)}" class="hidden">
      <wa-button type="button" appearance="outlined" id="cred-file-btn">${esc(fi.label)}</wa-button>
      <span class="hint" id="cred-file-note"></span>
    </div>`;
}

/** Wires the optional file import button to pre-fill the manual form. */
function wireFileImport(integration) {
  const fi = integration.connect.fileImport;
  const input = $("#cred-file", modal);
  if (!fi || !input) return;
  const note = $("#cred-file-note", modal);
  $("#cred-file-btn", modal).addEventListener("click", () => input.click());
  input.addEventListener("change", async () => {
    const file = input.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      if (fi.rawField) {
        const field = $(`[name="cred_${fi.rawField}"]`, modal);
        if (field) field.value = text.trim();
        note.textContent = `Loaded ${file.name}.`;
      } else if (fi.keyMap) {
        const json = JSON.parse(text);
        let filled = 0;
        for (const [jsonKey, fieldKey] of Object.entries(fi.keyMap)) {
          const field = $(`[name="cred_${fieldKey}"]`, modal);
          if (field && json[jsonKey] != null) {
            field.value = String(json[jsonKey]);
            filled++;
          }
        }
        note.textContent = filled
          ? `Loaded ${file.name}, filled ${filled} field${filled === 1 ? "" : "s"}.`
          : `No matching keys found in ${file.name}.`;
      }
    } catch (err) {
      note.textContent = "";
      toast(`Could not read file: ${err.message}`);
    }
    input.value = "";
  });
}

function manualFormHtml(integration, submitLabel) {
  return `
    <form id="cred-form">
      ${fileImportHtml(integration.connect.fileImport)}
      <wa-input class="field" name="cred_name" label="Credential name" spellcheck="false"
                value="${esc(integration.credentialName ?? integration.title)}"></wa-input>
      ${credentialFieldsHtml(integration)}
      <div class="modal-actions">
        <wa-button type="button" appearance="outlined" data-close>Cancel</wa-button>
        <wa-button type="submit" variant="brand">${esc(submitLabel)}</wa-button>
      </div>
    </form>`;
}

function openManualModal(integration, onSaved) {
  openModal(
    `
    ${llmHelpHtml(integration)}
    ${integration.connect.hint ? `<p class="hint">${esc(integration.connect.hint)}</p>` : ""}
    ${integration.connected ? `<p class="hint">Saving replaces the stored credential entirely. All fields are required.</p>` : ""}
    ${manualFormHtml(integration, integration.connected ? "Save credentials" : "Connect")}
  `,
    { label: `${integration.connected ? "Edit" : "Connect"} ${integration.title}` },
  );
  wireFileImport(integration);
  $("#cred-form", modal).addEventListener("submit", (e) => {
    e.preventDefault();
    submitCredentials(integration, e.target, onSaved).catch((err) => toast(`Save failed: ${err.message}`));
  });
}

/**
 * Scope picker for the OAuth flow. Scope packs (Google products) win over
 * permission checkboxes; integrations with neither show the default scopes
 * read-only, or a note when scopes live on the app itself.
 */
function scopePickerHtml(integration) {
  if (integration.scopePacks?.length) {
    return `
      <div class="field">
        <span class="field-label">Products to include in the consent</span>
        <div class="scope-list">
          ${integration.scopePacks
            .map(
              (p) => `<wa-checkbox name="scope-pack" value="${esc(p.id)}" ${p.default ? "checked" : ""}>
                ${esc(p.label)}${p.description ? ` <span class="muted small-text">· ${esc(p.description)}</span>` : ""}
              </wa-checkbox>`,
            )
            .join("")}
        </div>
      </div>`;
  }
  const perms = integration.oauth.permissions ?? [];
  if (perms.length) {
    const defaults = new Set(integration.oauth.defaultScopes);
    return `
      <div class="field">
        <span class="field-label">Scopes to request</span>
        <div class="scope-list">
          ${perms
            .map(
              (p) => `<wa-checkbox name="scope-perm" value="${esc(p.scope)}" ${defaults.has(p.scope) ? "checked" : ""}>
                ${esc(p.name)} <span class="muted small-text">· ${esc(p.description ?? p.scope)}</span>
              </wa-checkbox>`,
            )
            .join("")}
        </div>
      </div>`;
  }
  if (integration.oauth.defaultScopes.length) {
    return `
      <div class="field">
        <span class="field-label">Scopes requested</span>
        <p class="mono small-text muted">${integration.oauth.defaultScopes.map(esc).join(" ")}</p>
      </div>`;
  }
  return `<p class="hint">Scopes are configured on the OAuth app itself, not in the authorize URL.</p>`;
}

/** Reads the scope picker back into a scopes array, or null to use server defaults. */
function pickedScopes(integration, form) {
  if (integration.scopePacks?.length) {
    const checkedIds = new Set(
      $$("wa-checkbox[name=scope-pack]", form)
        .filter((b) => b.checked)
        .map((b) => b.value),
    );
    const scopes = new Set();
    for (const p of integration.scopePacks) {
      if (checkedIds.has(p.id)) for (const s of p.scopes) scopes.add(s);
    }
    return [...scopes];
  }
  const permBoxes = $$("wa-checkbox[name=scope-perm]", form);
  if (permBoxes.length) {
    const permScopes = new Set(permBoxes.map((b) => b.value));
    // Keep default scopes that have no checkbox (e.g. offline_access).
    const scopes = integration.oauth.defaultScopes.filter((s) => !permScopes.has(s));
    for (const b of permBoxes) if (b.checked) scopes.push(b.value);
    return scopes;
  }
  return null;
}

/**
 * OAuth connect dialog. Three modes via opts:
 *   - default (no opts): legacy single-credential connect/edit (Option A flow +
 *     Option B manual paste). Used by the back-compat legacy credential path.
 *   - opts.named: create a NAMED kind="app" OAuth connection (collects a
 *     connection name + optional owner scope + default). Drops Option B.
 *   - opts.connection: re-authorize an existing named connection (re-runs the
 *     flow, keeping the connection's name, scope and grants).
 */
function openOauthModal(integration, onSaved, opts = {}) {
  const fragment = integration.oauth.fragment;
  const callbackUrl = `${location.origin}/oauth/${integration.id}/callback`;
  const reauth = Boolean(opts.connection);
  const named = reauth || opts.named === true;
  const agents = opts.agents ?? [];

  const nameField =
    named && !reauth
      ? `<wa-input class="field" name="connectionName" label="Connection name" required spellcheck="false"
                autocomplete="off" placeholder="e.g. ${esc(integration.title)} · work account"></wa-input>`
      : "";

  const ownerHtml =
    named && !reauth
      ? `<wa-select class="field" name="ownerAgentId" label="Scope" value="">
              ${selectOptions(
                agents.map((a) => ({ value: a.id, label: `Agent: ${a.name}` })),
                { none: "Tenant-wide (shared by every agent)" },
              )}
            </wa-select>
            <p class="hint">Default-deny: a new connection is usable by no bot until you grant it on the Connections page.</p>`
      : "";

  const defaultBox =
    named && !reauth
      ? `<wa-checkbox name="isDefault" class="field">Make this the default connection for its scope</wa-checkbox>`
      : "";

  openModal(
    `
    ${llmHelpHtml(integration)}

    ${reauth ? `<p class="hint">Re-run the OAuth flow to refresh the tokens for <strong>${esc(opts.connection.name)}</strong>. Its name, scope and grants stay in place.</p>` : ""}
    ${named ? "" : `<h3>Option A · OAuth connect flow</h3>`}
    <p class="hint">
      ${esc(integration.connect.hint ?? "Use the client ID and secret of your own OAuth app.")}
      Register this redirect URI on the app, then approve in the popup.
    </p>
    <div class="copy-row">
      <code class="copy-box">${esc(callbackUrl)}</code>
      <wa-button type="button" size="s" appearance="outlined" data-copy-text="${esc(callbackUrl)}">Copy</wa-button>
    </div>
    <form id="oauth-form">
      ${nameField}
      ${ownerHtml}
      <wa-input class="field" name="clientId" label="${fragment ? "API key" : "Client ID"}" required
                spellcheck="false" autocomplete="off"></wa-input>
      ${
        fragment
          ? ""
          : `<wa-input class="field" name="clientSecret" label="Client secret" type="password" required
                spellcheck="false" autocomplete="off"></wa-input>`
      }
      <wa-input class="field" name="redirectBase" label="Redirect base (this server's browser-reachable URL)"
                required spellcheck="false" value="${esc(location.origin)}"></wa-input>
      ${scopePickerHtml(integration)}
      ${defaultBox}
      <wa-button type="submit" variant="brand">Open ${esc(integration.title)} consent screen</wa-button>
      <p id="oauth-note" class="hint hidden">
        Consent screen opened in a new tab. After approving, come back and reopen this
        page to see the connection. If no tab opened, allow popups and retry.
      </p>
    </form>

    ${
      named
        ? ""
        : `<hr class="divider">
           <h3>Option B · Enter credentials manually</h3>
           <p class="hint">Paste existing credentials instead of running the flow.</p>
           ${manualFormHtml(integration, integration.connected ? "Save credentials" : "Connect")}`
    }
  `,
    {
      label: reauth
        ? `Re-authorize ${opts.connection.name}`
        : named
          ? `Add ${integration.title} connection`
          : `${integration.connected ? "Edit" : "Connect"} ${integration.title}`,
    },
  );

  $("#oauth-form", modal).addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    const fd = new FormData(form);
    const scopes = pickedScopes(integration, form);
    const connectionName = String(fd.get("connectionName") ?? "").trim();
    if (named && !reauth && !connectionName) {
      toast("Enter a connection name.");
      return;
    }
    const ownerAgentId = $('wa-select[name="ownerAgentId"]', modal)?.value || null;
    const wantsDefault = Boolean($('wa-checkbox[name="isDefault"]', modal)?.checked);
    // Open the window synchronously so popup blockers stay quiet, then point it at the provider.
    const popup = window.open("", "_blank");
    try {
      const { url } = await api(`/api/integrations/${encodeURIComponent(integration.id)}/oauth/start`, {
        method: "POST",
        body: JSON.stringify({
          clientId: String(fd.get("clientId") ?? "").trim(),
          clientSecret: String(fd.get("clientSecret") ?? "").trim(),
          redirectBase: String(fd.get("redirectBase") ?? "").trim(),
          ...(scopes ? { scopes } : {}),
          ...(reauth ? { connectionId: opts.connection.id } : {}),
          ...(named && !reauth ? { connectionName, ownerAgentId, isDefault: wantsDefault } : {}),
        }),
      });
      if (popup) popup.location = url;
      else window.open(url, "_blank");
      $("#oauth-note", modal).classList.remove("hidden");
    } catch (err) {
      if (popup) popup.close();
      toast(`OAuth start failed: ${err.message}`);
    }
  });

  // Option B (manual paste) only exists in the legacy single-credential mode.
  if (!named) {
    wireFileImport(integration);
    $("#cred-form", modal).addEventListener("submit", (e) => {
      e.preventDefault();
      submitCredentials(integration, e.target, onSaved).catch((err) => toast(`Save failed: ${err.message}`));
    });
  }
}

/** Routes to the right connect dialog for an integration. */
function openConnectModal(integration, onSaved) {
  if (integration.connect.method === "oauth" && integration.oauth) openOauthModal(integration, onSaved);
  else openManualModal(integration, onSaved);
}

// ------------------------------------------- LLM connection dialogs

const LLM_STRATEGIES = [
  { value: "fallback", label: "fallback (primary first, next on failure)" },
  { value: "round-robin", label: "round-robin (rotate per request)" },
];

/** LLM vendor list (anthropic, openai, gemini, ...) from the integration catalog. */
function llmVendorsOf(integrations) {
  return integrations.filter((i) => i.llm && !i.orphaned).map((i) => ({ vendor: i.llm.vendor, title: i.title, credentialFields: i.credentialFields }));
}

/**
 * App integrations that can hold a named credential connection: not LLM, not
 * orphaned, connected with secret fields (not OAuth). OAuth integrations are
 * connected from the Integrations page, not the named-connection dialog.
 */
function appVendorsOf(integrations) {
  return integrations
    .filter(
      (i) =>
        !i.llm &&
        !i.orphaned &&
        i.connect?.method !== "oauth" &&
        Array.isArray(i.credentialFields) &&
        i.credentialFields.length > 0,
    )
    .map((i) => ({
      vendor: i.id,
      title: i.title,
      credentialFields: i.credentialFields,
    }));
}

/**
 * Extracts secret material from a Codex-CLI style auth.json. Returns
 * { apiKey } or { accessToken, accountId? }, or throws on an unusable file.
 */
function parseOpenaiAuthJson(text) {
  const json = JSON.parse(text);
  if (json.OPENAI_API_KEY) return { apiKey: String(json.OPENAI_API_KEY) };
  const tokens = json.tokens && typeof json.tokens === "object" ? json.tokens : {};
  if (tokens.access_token) {
    const accountId = tokens.account_id ?? json.OPENAI_ACCOUNT_ID;
    return { accessToken: String(tokens.access_token), ...(accountId ? { accountId: String(accountId) } : {}) };
  }
  throw new Error("no OPENAI_API_KEY or tokens.access_token found");
}

/**
 * Add/edit dialog for an LLM connection. On create the vendor is selectable;
 * on edit it is fixed and an empty secret keeps the stored one. openai offers
 * an API key mode and an auth.json import mode.
 */
function openLlmConnectionModal({ vendors, connection = null, onSaved }) {
  const editing = Boolean(connection);
  let vendor = editing ? connection.vendor : (vendors[0]?.vendor ?? "");
  // Pre-select the stored auth mode when editing so the dialog reflects what is
  // configured. The API returns a non-secret `authMode` discriminator per
  // connection ("api_key" / "auth_token" for anthropic, "api_key" / "auth_json"
  // for openai) without ever returning the secret itself.
  const hasSecret = editing ? Boolean(connection.hasSecret) : false;
  let openaiMode = editing && connection.authMode === "auth_json" ? "auth_json" : "api_key";
  let anthropicMode = editing && connection.authMode === "auth_token" ? "auth_token" : "api_key";
  const vendorMeta = () => vendors.find((v) => v.vendor === vendor) ?? { vendor, title: vendor, credentialFields: [] };

  // When editing a connection that already has a secret, the field is optional
  // and we show a masked indicator. Leaving it blank keeps the stored secret,
  // typing a value replaces it.
  const secretIsSet = () => editing && hasSecret;
  // When a secret is already stored, surface the masked indicator INSIDE the
  // input box (as its placeholder) rather than as a separate line below, and
  // drop to a one-line "leave blank to keep" hint.
  const secretPh = (normal) => (secretIsSet() ? "•••••••• secret set" : normal);
  const secretSetHint = () =>
    secretIsSet()
      ? `<p class="hint">Leave blank to keep the current secret, or type a new value to replace it.</p>`
      : "";

  const secretHtml = () => {
    const req = editing ? "" : "required";
    const keepHint = secretSetHint();
    if (vendor === "openai") {
      return `
        <div class="field">
          <wa-radio-group id="openai-mode" label="Credential" value="${esc(openaiMode)}" orientation="horizontal">
            <wa-radio value="api_key">API key</wa-radio>
            <wa-radio value="auth_json">Import auth.json</wa-radio>
          </wa-radio-group>
        </div>
        ${
          openaiMode === "api_key"
            ? `<wa-input class="field" name="llm_apiKey" label="API key" type="password" ${req}
                 spellcheck="false" autocomplete="off" placeholder="${esc(secretPh("sk-..."))}"></wa-input>`
            : `
            <div class="field file-import-row">
              <input type="file" id="authjson-file" accept=".json,application/json" class="hidden">
              <wa-button type="button" appearance="outlined" id="authjson-btn">Import auth.json</wa-button>
              <span class="hint" id="authjson-note"></span>
            </div>
            <wa-input class="field" name="llm_accessToken" label="Access token" type="password" ${req}
                      spellcheck="false" autocomplete="off" placeholder="${esc(secretPh(""))}"></wa-input>
            <wa-input class="field" name="llm_accountId" label="Account ID (optional)"
                      spellcheck="false" autocomplete="off"></wa-input>`
        }
        ${keepHint}`;
    }
    if (vendor === "anthropic") {
      return `
        <div class="field">
          <wa-radio-group id="anthropic-mode" label="Credential" value="${esc(anthropicMode)}" orientation="horizontal">
            <wa-radio value="api_key">API key</wa-radio>
            <wa-radio value="auth_token">Subscription auth token</wa-radio>
          </wa-radio-group>
        </div>
        ${
          anthropicMode === "auth_token"
            ? `<wa-input class="field" name="llm_authToken" label="Subscription auth token" type="password" ${req}
                 spellcheck="false" autocomplete="off" placeholder="${esc(secretPh("from: claude setup-token"))}"></wa-input>
               <p class="hint">A long-lived token from <span class="mono">claude setup-token</span>. OneGate sends it as Authorization: Bearer with the oauth-2025-04-20 beta header. Note: subscription tokens are intended for Claude Code, load-balancing several through a proxy is a gray area with Anthropic.</p>`
            : `<wa-input class="field" name="llm_apiKey" label="API key" type="password" ${req}
                 spellcheck="false" autocomplete="off" placeholder="${esc(secretPh("sk-ant-..."))}"></wa-input>`
        }
        ${keepHint}`;
    }
    const fields = vendorMeta().credentialFields;
    if (!fields.length) {
      return `<wa-input class="field" name="llm_apiKey" label="API key" type="password" ${req}
                spellcheck="false" autocomplete="off" placeholder="${esc(secretPh(""))}"></wa-input>${keepHint}`;
    }
    return (
      fields
        .map((f) => {
          const optional = editing || f.optional;
          // Mask only secret fields; non-secret fields keep their plain placeholder.
          const ph = f.secret ? ` placeholder="${esc(secretPh(""))}"` : "";
          return `<wa-input class="field" name="llm_${esc(f.key)}" label="${esc(f.label)}${f.optional ? " (optional)" : ""}"
                  type="${f.secret ? "password" : "text"}" ${optional ? "" : "required"}
                  spellcheck="false" autocomplete="off"${ph}></wa-input>`;
        })
        .join("") + keepHint
    );
  };

  openModal(
    `
    <form id="llm-conn-form">
      ${
        editing
          ? `<div class="field"><span class="field-label">Vendor</span>
               <p class="mono small-text vendor-static">${esc(vendorMeta().title)}</p></div>`
          : `<wa-select class="field" name="vendor" label="Vendor" value="${esc(vendor)}">
               ${selectOptions(vendors.map((v) => ({ value: v.vendor, label: v.title })))}
             </wa-select>`
      }
      <wa-input class="field" name="name" label="Connection name" required spellcheck="false"
                autocomplete="off" value="${esc(connection?.name ?? "")}" placeholder="e.g. Anthropic · prod"></wa-input>
      <div id="llm-secret-section">${secretHtml()}</div>
      ${
        editing && connection.isDefault
          ? `<p class="hint">This is the default ${esc(vendorMeta().title)} connection. Make another connection default to change that.</p>`
          : `<wa-checkbox name="isDefault" class="field">Make this the default connection for its vendor</wa-checkbox>`
      }
      <div class="modal-actions">
        <wa-button type="button" appearance="outlined" data-close>Cancel</wa-button>
        <wa-button type="submit" variant="brand">${editing ? "Save changes" : "Add connection"}</wa-button>
      </div>
    </form>
  `,
    { label: editing ? `Edit ${connection.name}` : "Add LLM connection" },
  );

  const form = $("#llm-conn-form", modal);
  const secretSection = $("#llm-secret-section", modal);

  function wireSecretSection() {
    const modeGroup = $("#openai-mode", modal);
    if (modeGroup) {
      modeGroup.addEventListener("change", () => {
        openaiMode = modeGroup.value;
        secretSection.innerHTML = secretHtml();
        wireSecretSection();
      });
    }
    const anthropicGroup = $("#anthropic-mode", modal);
    if (anthropicGroup) {
      anthropicGroup.addEventListener("change", () => {
        anthropicMode = anthropicGroup.value;
        secretSection.innerHTML = secretHtml();
        wireSecretSection();
      });
    }
    const fileInput = $("#authjson-file", modal);
    if (fileInput) {
      const note = $("#authjson-note", modal);
      $("#authjson-btn", modal).addEventListener("click", () => fileInput.click());
      fileInput.addEventListener("change", async () => {
        const file = fileInput.files?.[0];
        if (!file) return;
        try {
          const parsed = parseOpenaiAuthJson(await file.text());
          if (parsed.apiKey) {
            // The file carries a plain API key: switch modes and prefill it.
            openaiMode = "api_key";
            secretSection.innerHTML = secretHtml();
            wireSecretSection();
            $('[name="llm_apiKey"]', modal).value = parsed.apiKey;
            toast(`Found OPENAI_API_KEY in ${file.name}, switched to API key mode.`, "success");
          } else {
            $('[name="llm_accessToken"]', modal).value = parsed.accessToken;
            if (parsed.accountId) $('[name="llm_accountId"]', modal).value = parsed.accountId;
            note.textContent = `Loaded ${file.name}.`;
          }
        } catch (err) {
          note.textContent = "";
          toast(`Could not read auth.json: ${err.message}`);
        }
        fileInput.value = "";
      });
    }
  }
  wireSecretSection();

  const vendorSel = $('wa-select[name="vendor"]', modal);
  if (vendorSel) {
    vendorSel.addEventListener("change", () => {
      vendor = vendorSel.value;
      openaiMode = "api_key";
      anthropicMode = "api_key";
      secretSection.innerHTML = secretHtml();
      wireSecretSection();
    });
  }

  /** Secret material from the form, or null when every secret field is empty. */
  function collectData() {
    const val = (n) => {
      const el = $(`[name="${n}"]`, modal);
      return el ? String(el.value ?? "").trim() : "";
    };
    if (vendor === "openai") {
      if (openaiMode === "api_key") {
        const apiKey = val("llm_apiKey");
        return apiKey ? { apiKey } : null;
      }
      const accessToken = val("llm_accessToken");
      const accountId = val("llm_accountId");
      if (!accessToken) return null;
      return { accessToken, ...(accountId ? { accountId } : {}) };
    }
    if (vendor === "anthropic") {
      if (anthropicMode === "auth_token") {
        const authToken = val("llm_authToken");
        return authToken ? { authMode: "auth_token", authToken } : null;
      }
      const apiKey = val("llm_apiKey");
      return apiKey ? { authMode: "api_key", apiKey } : null;
    }
    const fields = vendorMeta().credentialFields;
    if (!fields.length) {
      const apiKey = val("llm_apiKey");
      return apiKey ? { apiKey } : null;
    }
    const data = {};
    let any = false;
    for (const f of fields) {
      const v = val(`llm_${f.key}`);
      if (v) {
        data[f.key] = v;
        any = true;
      }
    }
    return any ? data : null;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = String($('[name="name"]', modal).value ?? "").trim();
    if (!name) return;
    const data = collectData();
    if (!editing && !data) {
      toast("Enter the connection's secret material.");
      return;
    }
    const defaultBox = $('wa-checkbox[name="isDefault"]', modal);
    const wantsDefault = Boolean(defaultBox?.checked);
    try {
      if (editing) {
        await api(`/api/connections/${encodeURIComponent(connection.id)}`, {
          method: "PUT",
          body: JSON.stringify({
            name,
            ...(data ? { data } : {}),
            ...(wantsDefault && !connection.isDefault ? { isDefault: true } : {}),
          }),
        });
        closeModal(true);
        toast("Connection updated.", "success");
      } else {
        await api("/api/connections", {
          method: "POST",
          body: JSON.stringify({ kind: "llm", vendor, name, data, isDefault: wantsDefault }),
        });
        closeModal(true);
        toast(`LLM connection "${name}" added.`, "success");
      }
      await onSaved();
    } catch (err) {
      toast(`Save failed: ${err.message}`);
    }
  });
}

/**
 * Add or edit a named app credential connection (kind="app"). Unlike legacy
 * single-credential integrations, an app connection has its own name, can be
 * tenant-wide (shared by every agent) or bound to one agent, and can be made
 * the default for its bucket. The owner cannot be changed after creation.
 * `vendors` is appVendorsOf(integrations); `agents` is the agent list.
 */
function openAppConnectionModal({ vendors, agents, vendor, connection, onSaved, isOauth }) {
  const editing = Boolean(connection);
  vendor = editing ? connection.vendor : vendor || vendors[0]?.vendor;
  const hasSecret = editing ? Boolean(connection.hasSecret) : false;
  const vendorMeta = () =>
    vendors.find((v) => v.vendor === vendor) ?? { vendor, title: vendor, credentialFields: [] };

  const secretIsSet = () => editing && hasSecret;
  const secretPh = (normal) => (secretIsSet() ? "•••••••• secret set" : normal);
  const secretSetHint = () =>
    secretIsSet()
      ? `<p class="hint">Leave blank to keep the current secret, or type a new value to replace it.</p>`
      : "";

  const fieldsHtml = () => {
    if (isOauth) {
      return `<div class="field"><p class="hint">OAuth tokens are managed by the connect flow. Use "Re-authorize" on this connection to refresh them. Editing here changes only the name and default.</p></div>`;
    }
    const fields = vendorMeta().credentialFields ?? [];
    if (!fields.length) {
      return `<wa-input class="field" name="app_apiKey" label="API key" type="password" ${editing ? "" : "required"}
                spellcheck="false" autocomplete="off" placeholder="${esc(secretPh(""))}"></wa-input>${secretSetHint()}`;
    }
    return (
      fields
        .map((f) => {
          const optional = editing || f.optional;
          const ph = f.secret ? ` placeholder="${esc(secretPh(""))}"` : "";
          return `<wa-input class="field" name="app_${esc(f.key)}" label="${esc(f.label)}${f.optional ? " (optional)" : ""}"
                  type="${f.secret ? "password" : "text"}" ${optional ? "" : "required"}
                  spellcheck="false" autocomplete="off"${ph}></wa-input>`;
        })
        .join("") + secretSetHint()
    );
  };

  const ownerHtml = () => {
    if (editing) {
      const label = connection.ownerAgentId
        ? `Agent: ${connection.ownerAgentName ?? connection.ownerAgentId}`
        : "Tenant-wide (shared by every agent)";
      return `<div class="field"><span class="field-label">Scope</span>
                <p class="small-text">${esc(label)}</p>
                <p class="hint">The scope of a connection cannot be changed after creation.</p></div>`;
    }
    return `<wa-select class="field" name="ownerAgentId" label="Scope" value="">
              ${selectOptions(
                agents.map((a) => ({ value: a.id, label: `Agent: ${a.name}` })),
                { none: "Tenant-wide (shared by every agent)" },
              )}
            </wa-select>`;
  };

  openModal(
    `
    <form id="app-conn-form">
      ${
        editing
          ? `<div class="field"><span class="field-label">Integration</span>
               <p class="mono small-text vendor-static">${esc(vendorMeta().title)}</p></div>`
          : `<wa-select class="field" name="vendor" label="Integration" value="${esc(vendor)}">
               ${selectOptions(vendors.map((v) => ({ value: v.vendor, label: v.title })))}
             </wa-select>`
      }
      <wa-input class="field" name="name" label="Connection name" required spellcheck="false"
                autocomplete="off" value="${esc(connection?.name ?? "")}" placeholder="e.g. GitHub · work account"></wa-input>
      ${ownerHtml()}
      <div id="app-secret-section">${fieldsHtml()}</div>
      ${
        editing && connection.isDefault
          ? `<p class="hint">This is the default connection for its scope. Make another connection default to change that.</p>`
          : `<wa-checkbox name="isDefault" class="field">Make this the default connection for its scope</wa-checkbox>`
      }
      <div class="modal-actions">
        <wa-button type="button" appearance="outlined" data-close>Cancel</wa-button>
        <wa-button type="submit" variant="brand">${editing ? "Save changes" : "Add connection"}</wa-button>
      </div>
    </form>
  `,
    { label: editing ? `Edit ${connection.name}` : "Add app connection" },
  );

  const form = $("#app-conn-form", modal);
  const secretSection = $("#app-secret-section", modal);

  const vendorSel = $('wa-select[name="vendor"]', modal);
  if (vendorSel) {
    vendorSel.addEventListener("change", () => {
      vendor = vendorSel.value;
      secretSection.innerHTML = fieldsHtml();
    });
  }

  /** Secret material from the form, or null when every secret field is empty. */
  function collectData() {
    if (isOauth) return null;
    const val = (n) => {
      const el = $(`[name="${n}"]`, modal);
      return el ? String(el.value ?? "").trim() : "";
    };
    const fields = vendorMeta().credentialFields ?? [];
    if (!fields.length) {
      const apiKey = val("app_apiKey");
      return apiKey ? { apiKey } : null;
    }
    const data = {};
    let any = false;
    for (const f of fields) {
      const v = val(`app_${f.key}`);
      if (v) {
        data[f.key] = v;
        any = true;
      }
    }
    return any ? data : null;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = String($('[name="name"]', modal).value ?? "").trim();
    if (!name) return;
    const data = collectData();
    if (!editing && !data) {
      toast("Enter the connection's secret material.");
      return;
    }
    const defaultBox = $('wa-checkbox[name="isDefault"]', modal);
    const wantsDefault = Boolean(defaultBox?.checked);
    try {
      if (editing) {
        await api(`/api/connections/${encodeURIComponent(connection.id)}`, {
          method: "PUT",
          body: JSON.stringify({
            name,
            ...(data ? { data } : {}),
            ...(wantsDefault && !connection.isDefault ? { isDefault: true } : {}),
          }),
        });
        closeModal(true);
        toast("Connection updated.", "success");
      } else {
        const ownerAgentId = $('wa-select[name="ownerAgentId"]', modal)?.value || null;
        await api("/api/connections", {
          method: "POST",
          body: JSON.stringify({ kind: "app", vendor, name, data, ownerAgentId, isDefault: wantsDefault }),
        });
        closeModal(true);
        toast(`App connection "${name}" added.`, "success");
      }
      await onSaved();
    } catch (err) {
      toast(`Save failed: ${err.message}`);
    }
  });
}

// ---------------------------------------------------------------- view: dashboard

async function renderDashboard(root) {
  const gen = currentGeneration();
  const [health, agents, projects, integrations, rules, audit] = await Promise.all([
    fetch("/api/health").then((r) => r.json()),
    api("/api/agents"),
    api("/api/projects"),
    api("/api/integrations"),
    api("/api/rules"),
    api("/api/audit?limit=10"),
  ]);
  const connected = integrations.filter((i) => i.connected).length;
  const stats = [
    { label: "Agents", value: agents.length, href: "#/agents" },
    { label: "Projects", value: projects.length, href: "#/projects" },
    { label: "Connected integrations", value: `${connected} / ${integrations.length}`, href: "#/integrations" },
    { label: "Rules", value: rules.length, href: "#/rules" },
  ];
  const caEnv = "NODE_EXTRA_CA_CERTS=./onegate-ca.pem";

  if (!isCurrentGeneration(gen)) return; // navigated away while loading
  root.innerHTML = `
    <header class="view-header">
      <h1>Dashboard</h1>
      <wa-badge variant="${health.ok ? "success" : "danger"}" appearance="filled-outlined" class="health">
        ${health.ok ? "healthy" : "unhealthy"} · v${esc(health.version)}
      </wa-badge>
    </header>

    <div class="stat-grid">
      ${stats
        .map(
          (s) => `<a class="card stat" href="${esc(s.href)}">
            <span class="stat-value">${esc(s.value)}</span>
            <span class="stat-label">${esc(s.label)}</span>
          </a>`,
        )
        .join("")}
    </div>

    <div class="card">
      <h2>Setup</h2>
      <p class="muted">
        Agents reach external APIs through OneGate's HTTPS proxy on port ${PROXY_PORT}.
        For TLS interception to work, each agent must trust the OneGate root CA.
      </p>
      <div class="setup-row">
        <wa-button appearance="outlined" href="/ca.pem" download="onegate-ca.pem">Download root CA (ca.pem)</wa-button>
        <div class="copy-row grow">
          <code class="copy-box">${esc(caEnv)}</code>
          <wa-button type="button" size="s" appearance="outlined" data-copy-text="${esc(caEnv)}">Copy</wa-button>
        </div>
      </div>
      <p class="hint">
        Node agents: set NODE_EXTRA_CA_CERTS to the downloaded file.
        Python: REQUESTS_CA_BUNDLE / SSL_CERT_FILE. curl: --cacert onegate-ca.pem.
        Then create an agent to get its HTTPS_PROXY line.
      </p>
    </div>

    <div class="card">
      <div class="card-head">
        <h2>Recent activity</h2>
        <wa-button size="s" appearance="outlined" href="#/audit">View all</wa-button>
      </div>
      ${auditTable(audit)}
    </div>
  `;
  wireCopyButtons(root);
}

// ---------------------------------------------------------------- view: agents

async function renderAgents(root) {
  const gen = currentGeneration();
  const [agents, projects] = await Promise.all([api("/api/agents"), api("/api/projects")]);
  const projectName = (id) => projects.find((p) => p.id === id)?.name ?? null;

  if (!isCurrentGeneration(gen)) return; // navigated away while loading
  root.innerHTML = `
    <header class="view-header">
      <h1>Agents</h1>
      <wa-button type="button" variant="brand" id="new-agent">New agent</wa-button>
    </header>
    <div class="card">
      ${
        agents.length
          ? `<div class="table-wrap"><table>
              <thead><tr>
                <th>Name</th><th>ID</th><th>Project</th><th>Default policy</th><th>LLM mode</th><th>Created</th><th></th>
              </tr></thead>
              <tbody>${agents
                .map(
                  (a) => `<tr>
                    <td><strong>${esc(a.name)}</strong></td>
                    <td class="mono muted">${esc(a.id)}</td>
                    <td>${esc(projectName(a.projectId) ?? "–")}</td>
                    <td>${policyBadge(a.defaultPolicy)}</td>
                    <td data-llm-mode="${esc(a.llmMode ?? "passthrough")}">${llmModeBadge(a.llmMode)}</td>
                    <td class="muted nowrap">${esc(fmtDate(a.createdAt))}</td>
                    <td class="actions">
                      <wa-button type="button" size="s" appearance="outlined" data-edit="${esc(a.id)}">Edit</wa-button>
                      <wa-button type="button" size="s" appearance="outlined" data-connect="${esc(a.id)}">Connect link</wa-button>
                      <wa-button type="button" size="s" appearance="outlined" data-rotate="${esc(a.id)}">Rotate token</wa-button>
                      <wa-button type="button" size="s" appearance="outlined" variant="danger" data-delete="${esc(a.id)}">Delete</wa-button>
                    </td>
                  </tr>`,
                )
                .join("")}</tbody>
            </table></div>`
          : emptyState("No agents yet. Create one to get a proxy token.")
      }
    </div>
  `;

  const policyOptions = (selected) =>
    selectOptions(
      [
        { value: "deny-unmatched", label: "deny-unmatched (recommended)" },
        { value: "allow-all", label: "allow-all" },
      ],
      { selected },
    );
  const projectOptions = (selected) =>
    selectOptions(
      projects.map((p) => ({ value: p.id, label: p.name })),
      { selected, none: "No project" },
    );

  /**
   * Agent create/edit dialog. Editing an existing agent also shows the LLM
   * routing section (enable, strategy, ordered connection list). On submit,
   * `onSubmit(body, llmCfg)` gets the routing config only when it changed
   * (saving it resets the agent's routing state on the server).
   */
  async function agentFormModal(title, submitLabel, agent, onSubmit) {
    let llmCfg = null;
    let llmConnections = [];
    let apps = null;
    if (agent) {
      const [cfg, conns, appsResp] = await Promise.all([
        api(`/api/agents/${encodeURIComponent(agent.id)}/llm`),
        api("/api/connections"),
        api(`/api/agents/${encodeURIComponent(agent.id)}/apps`),
      ]);
      llmCfg = cfg;
      llmConnections = conns.llm;
      apps = appsResp;
    }
    const connById = (id) => llmConnections.find((c) => c.id === id);
    // Drop ids of connections that no longer exist, the server rejects them.
    let order = (llmCfg?.connectionIds ?? []).filter((id) => connById(id));
    const savedVendorStrategies = llmCfg?.vendorStrategies ?? {};
    // Distinct vendors present in the current order (source for the per-vendor
    // strategy overrides). Recomputed on each render.
    const orderVendors = () => {
      const seen = [];
      for (const id of order) {
        const v = connById(id)?.vendor;
        if (v && !seen.includes(v)) seen.push(v);
      }
      return seen;
    };
    const initial = llmCfg
      ? JSON.stringify({
          enabled: llmCfg.enabled,
          strategy: llmCfg.strategy,
          vendorStrategies: savedVendorStrategies,
          connectionIds: order,
        })
      : null;

    const llmSectionHtml = !agent
      ? ""
      : `
      <hr class="divider">
      <div class="llm-routing">
        <h3>LLM routing</h3>
        <div class="llm-mode-row" data-llm-mode="${esc(llmCfg.mode ?? "passthrough")}">
          ${llmModeBadge(llmCfg.mode)}
          <span class="hint llm-mode-help">${esc((LLM_MODE_META[llmCfg.mode] ?? LLM_MODE_META.passthrough).help)} Save to refresh the mode.</span>
        </div>
        <p class="hint">
          Route this agent's LLM requests across named connections.
          Saving resets the agent's routing state (active connection, cooldowns).
        </p>
        <wa-switch class="field" id="llm-enabled" ${llmCfg.enabled ? "checked" : ""}>Enable LLM routing</wa-switch>
        <wa-select class="field" id="llm-strategy" label="Strategy" value="${esc(llmCfg.strategy)}">
          ${selectOptions(LLM_STRATEGIES, { selected: llmCfg.strategy })}
        </wa-select>
        <div class="field">
          <span class="field-label">Connection order${llmCfg.strategy === "fallback" ? " (first = primary)" : ""}</span>
          <ol class="order-list" id="llm-order"></ol>
          <div class="order-add">
            <wa-select id="llm-add-select" label="Add connection" value=""></wa-select>
            <wa-button type="button" size="s" appearance="outlined" id="llm-add-btn">Add</wa-button>
          </div>
          ${llmConnections.length ? "" : `<p class="hint">No LLM connections exist yet. Create one on the Connections page first.</p>`}
        </div>
        <div class="field" id="llm-vendor-strategies"></div>
      </div>`;

    // Per-agent app accounts: for each app integration this agent can use,
    // which named connection it picks by default (the tenant default is used
    // when left unset, and any request can still override with the
    // x-onegate-connection header). Grouped by integration vendor.
    const appAvailable = apps?.available ?? [];
    const appByVendor = new Map();
    for (const c of appAvailable) {
      if (!appByVendor.has(c.vendor)) appByVendor.set(c.vendor, []);
      appByVendor.get(c.vendor).push(c);
    }
    const savedAppChoice = new Map((apps?.configs ?? []).map((c) => [c.integrationId, c.connectionId]));
    const appVendorList = [...appByVendor.keys()].sort();
    const appTitleOf = (vendor) =>
      appByVendor.get(vendor)?.find((c) => c.integration?.title)?.integration?.title ?? vendor;

    const appSectionHtml =
      !agent || !appVendorList.length
        ? ""
        : `
      <hr class="divider">
      <div class="app-accounts">
        <h3>App accounts</h3>
        <p class="hint">
          When this agent holds several accounts of the same service, choose which
          one it uses by default. Leave a service on its default to use the
          tenant-wide default connection. A request can override per call with the
          <span class="mono">x-onegate-connection</span> header.
        </p>
        ${appVendorList
          .map((vendor) => {
            const conns = appByVendor.get(vendor);
            const opts = conns.map((c) => ({
              value: c.id,
              label: `${c.name}${c.ownerAgentId ? "" : " (tenant-wide)"}${c.isDefault ? " · default" : ""}`,
            }));
            const selected = savedAppChoice.get(vendor) ?? "";
            // Per-connection disallow control: a connection granted directly to
            // this agent can be revoked here; one inherited via the agent's
            // project is shown disabled (manage it on the Connections page).
            const grantChips = conns
              .map((c) => {
                const direct = c.grantVia === "agent";
                const tip = direct
                  ? `Disallow "${esc(c.name)}" for this agent`
                  : `Granted via project ${esc(c.grantProjectName ?? c.grantProjectId ?? "")}, manage on the Connections page`;
                return `<wa-badge class="agent-grant-chip" variant="${direct ? "neutral" : "brand"}" title="${tip}">
                          ${esc(c.name)}
                          <button type="button" class="grant-x"
                                  data-agent-revoke-conn="${esc(c.id)}"
                                  ${direct ? "" : "disabled"}
                                  aria-label="${tip}" title="${tip}">&times;</button>
                        </wa-badge>`;
              })
              .join("");
            return `<div class="app-account-row">
                      <wa-select class="field app-account-select" data-app-vendor="${esc(vendor)}"
                         label="${esc(appTitleOf(vendor))}" value="${esc(selected)}">
                        ${selectOptions(opts, { selected, none: "Use default connection" })}
                      </wa-select>
                      <div class="agent-grants" data-app-vendor-grants="${esc(vendor)}">
                        <span class="field-label">Allowed connections</span>
                        <div class="agent-grants-chips">${grantChips}</div>
                      </div>
                    </div>`;
          })
          .join("")}
      </div>`;

    openModal(
      `
      <form id="agent-form">
        <wa-input class="field" name="name" label="Name" required spellcheck="false"
                  value="${esc(agent?.name ?? "")}" placeholder="my-agent"></wa-input>
        <wa-select class="field" name="projectId" label="Project"
                   value="${esc(agent?.projectId ?? "")}">${projectOptions(agent?.projectId ?? null)}</wa-select>
        <wa-select class="field" name="defaultPolicy" label="Default policy"
                   value="${esc(agent?.defaultPolicy ?? "deny-unmatched")}">${policyOptions(agent?.defaultPolicy ?? "deny-unmatched")}</wa-select>
        ${llmSectionHtml}
        ${appSectionHtml}
        <div class="modal-actions">
          <wa-button type="button" appearance="outlined" data-close>Cancel</wa-button>
          <wa-button type="submit" variant="brand">${esc(submitLabel)}</wa-button>
        </div>
      </form>
    `,
      { label: title },
    );

    function drawOrder() {
      const list = $("#llm-order", modal);
      if (!list) return;
      list.innerHTML = order.length
        ? order
            .map((id, idx) => {
              const c = connById(id);
              return `<li data-id="${esc(id)}">
                <span class="order-pos">${idx + 1}</span>
                <span class="order-name"><strong>${esc(c.name)}</strong> <span class="muted small-text">${esc(c.vendor)}</span></span>
                <span class="order-actions">
                  <wa-button type="button" size="s" appearance="plain" data-move="-1" aria-label="Move up" ${idx === 0 ? "disabled" : ""}>↑</wa-button>
                  <wa-button type="button" size="s" appearance="plain" data-move="1" aria-label="Move down" ${idx === order.length - 1 ? "disabled" : ""}>↓</wa-button>
                  <wa-button type="button" size="s" appearance="plain" data-remove aria-label="Remove">✕</wa-button>
                </span>
              </li>`;
            })
            .join("")
        : `<li class="order-empty muted">No connections in the order yet.</li>`;
      const addSel = $("#llm-add-select", modal);
      const remaining = llmConnections.filter((c) => !order.includes(c.id));
      addSel.innerHTML = selectOptions(
        remaining.map((c) => ({ value: c.id, label: `${c.name} (${c.vendor})` })),
        { none: remaining.length ? "Pick a connection" : "All connections added" },
      );
      addSel.value = "";
      $$("[data-move]", list).forEach((btn) => {
        btn.addEventListener("click", () => {
          const id = btn.closest("li").dataset.id;
          const from = order.indexOf(id);
          const to = from + Number(btn.dataset.move);
          if (to < 0 || to >= order.length) return;
          [order[from], order[to]] = [order[to], order[from]];
          drawOrder();
        });
      });
      $$("[data-remove]", list).forEach((btn) => {
        btn.addEventListener("click", () => {
          order = order.filter((id) => id !== btn.closest("li").dataset.id);
          drawOrder();
        });
      });
      drawVendorStrategies();
    }

    // Per-vendor strategy overrides. One select per distinct vendor in the
    // order. "Default" (no override) inherits the global strategy above. The
    // current picks are preserved across re-renders by reading the live
    // selects before rebuilding.
    function drawVendorStrategies() {
      const box = $("#llm-vendor-strategies", modal);
      if (!box) return;
      const current = {};
      for (const sel of $$("[data-vendor-strategy]", box)) {
        if (sel.value) current[sel.dataset.vendorStrategy] = sel.value;
      }
      const vendors = orderVendors();
      if (!vendors.length) {
        box.innerHTML = "";
        return;
      }
      box.innerHTML = `
        <span class="field-label">Per-vendor strategy</span>
        <p class="hint">Override the strategy for a specific vendor. Default inherits the strategy above.</p>
        ${vendors
          .map((vendor) => {
            const selected = current[vendor] ?? savedVendorStrategies[vendor] ?? "";
            return `<wa-select class="field" data-vendor-strategy="${esc(vendor)}"
                       label="${esc(vendor)} strategy" value="${esc(selected)}">
                      ${selectOptions(LLM_STRATEGIES, { selected, none: "Default (inherit global)" })}
                    </wa-select>`;
          })
          .join("")}`;
    }

    if (agent) {
      drawOrder();
      $("#llm-add-btn", modal).addEventListener("click", () => {
        const id = $("#llm-add-select", modal).value;
        if (!id || order.includes(id)) return;
        order.push(id);
        drawOrder();
      });
      // Disallow a directly-granted app connection from the agent side. This
      // calls the same DELETE grant route the Connections page uses, then
      // re-opens the editor so the chips and selects reflect the new grants.
      // Project-inherited chips are disabled (handled in markup), so any
      // enabled button here is always a scope='agent' grant.
      for (const btn of $$("[data-agent-revoke-conn]", modal)) {
        if (btn.disabled) continue;
        btn.addEventListener("click", async () => {
          const connId = btn.dataset.agentRevokeConn;
          btn.disabled = true;
          try {
            await api(
              `/api/connections/${encodeURIComponent(connId)}/grants/agent/${encodeURIComponent(agent.id)}`,
              { method: "DELETE" },
            );
            toast("Connection disallowed for this agent.", "success");
            closeModal(true);
            await agentFormModal(title, submitLabel, agent, onSubmit);
          } catch (err) {
            btn.disabled = false;
            toast(`Failed to disallow: ${err.message}`);
          }
        });
      }
    }

    /** Routing config from the form, or null when it matches the saved one. */
    function readLlmConfig() {
      if (!agent) return null;
      const vendorStrategies = {};
      for (const sel of $$("[data-vendor-strategy]", modal)) {
        if (sel.value) vendorStrategies[sel.dataset.vendorStrategy] = sel.value;
      }
      const next = {
        enabled: Boolean($("#llm-enabled", modal).checked),
        strategy: $("#llm-strategy", modal).value || "fallback",
        vendorStrategies,
        connectionIds: [...order],
      };
      return JSON.stringify(next) === initial ? null : next;
    }

    /**
     * App account choices that changed versus the saved config. Each entry is
     * { integrationId, connectionId } where connectionId null clears the choice.
     */
    function readAppChanges() {
      if (!agent) return [];
      const changes = [];
      for (const sel of $$(".app-account-select", modal)) {
        const integrationId = sel.dataset.appVendor;
        const next = sel.value || null;
        const prev = savedAppChoice.get(integrationId) ?? null;
        if (next !== prev) changes.push({ integrationId, connectionId: next });
      }
      return changes;
    }

    $("#agent-form", modal).addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      try {
        await onSubmit(
          {
            name: String(fd.get("name") ?? "").trim(),
            projectId: fd.get("projectId") || null,
            defaultPolicy: fd.get("defaultPolicy"),
          },
          readLlmConfig(),
          readAppChanges(),
        );
      } catch (err) {
        toast(`Failed: ${err.message}`);
      }
    });
  }

  $("#new-agent", root).addEventListener("click", () => {
    agentFormModal("New agent", "Create agent", null, async (body) => {
      const created = await api("/api/agents", { method: "POST", body: JSON.stringify(body) });
      showTokenModal(`Agent "${created.name}" created`, created.token);
      await renderAgents(root);
    });
  });

  $$("[data-edit]", root).forEach((btn) => {
    const agent = agents.find((a) => a.id === btn.dataset.edit);
    btn.addEventListener("click", () => {
      agentFormModal(`Edit ${agent.name}`, "Save changes", agent, async (body, llmCfg, appChanges) => {
        await api(`/api/agents/${encodeURIComponent(agent.id)}`, {
          method: "PATCH",
          body: JSON.stringify(body),
        });
        if (llmCfg) {
          await api(`/api/agents/${encodeURIComponent(agent.id)}/llm`, {
            method: "PUT",
            body: JSON.stringify(llmCfg),
          });
        }
        for (const ch of appChanges ?? []) {
          await api(
            `/api/agents/${encodeURIComponent(agent.id)}/apps/${encodeURIComponent(ch.integrationId)}`,
            { method: "PUT", body: JSON.stringify({ connectionId: ch.connectionId }) },
          );
        }
        const appsChanged = (appChanges ?? []).length > 0;
        closeModal(true);
        toast(
          llmCfg || appsChanged
            ? `Agent updated${llmCfg ? ", LLM routing reset" : ""}${appsChanged ? ", app accounts saved" : ""}.`
            : "Agent updated.",
          "success",
        );
        await renderAgents(root);
      }).catch((err) => toast(`Failed to open editor: ${err.message}`));
    });
  });

  $$("[data-connect]", root).forEach((btn) => {
    const agent = agents.find((a) => a.id === btn.dataset.connect);
    btn.addEventListener("click", () => {
      connectLinkModal(agent).catch((err) => toast(`Could not open connect link: ${err.message}`));
    });
  });

  $$("[data-rotate]", root).forEach((btn) => {
    const agent = agents.find((a) => a.id === btn.dataset.rotate);
    btn.addEventListener("click", async () => {
      const ok = await confirmModal({
        title: "Rotate token?",
        body: `The current token for "${agent.name}" stops working immediately and a new one is shown once.`,
        confirmLabel: "Rotate token",
      });
      if (!ok) return;
      try {
        const { token } = await api(`/api/agents/${encodeURIComponent(agent.id)}/rotate-token`, {
          method: "POST",
        });
        showTokenModal(`New token for "${agent.name}"`, token);
      } catch (err) {
        toast(`Rotate failed: ${err.message}`);
      }
    });
  });

  $$("[data-delete]", root).forEach((btn) => {
    const agent = agents.find((a) => a.id === btn.dataset.delete);
    btn.addEventListener("click", async () => {
      const ok = await confirmModal({
        title: "Delete agent?",
        body: `Agent "${agent.name}" is removed. Its token and rules stop working immediately.`,
        confirmLabel: "Delete agent",
      });
      if (!ok) return;
      try {
        await api(`/api/agents/${encodeURIComponent(agent.id)}`, { method: "DELETE" });
        toast("Agent deleted.", "success");
        await renderAgents(root);
      } catch (err) {
        toast(`Delete failed: ${err.message}`);
      }
    });
  });
}

/**
 * "Connect link" dialog for an agent. Lets the operator mint a scoped,
 * single-use onboarding link for one OAuth integration. The bot owner opens
 * the link, pastes their own OAuth client id and secret, runs consent, and
 * OneGate auto-wires the connection, grant and allow rule for this agent.
 */
async function connectLinkModal(agent) {
  const integrations = await api("/api/integrations");
  const oauthIntegrations = integrations
    .filter((i) => i.connect?.method === "oauth")
    .sort((a, b) => a.title.localeCompare(b.title));

  if (!oauthIntegrations.length) {
    openModal(
      `<p class="modal-body">There are no OAuth integrations available to connect.</p>
       <div class="modal-actions"><wa-button type="button" appearance="outlined" data-close>Close</wa-button></div>`,
      { label: `Connect link for ${agent.name}` },
    );
    return;
  }

  openModal(
    `
    <p class="hint">
      Mint a single-use link for this agent. Send it to the bot owner. They paste their own
      OAuth client id and secret, run consent, and OneGate wires the connection, grant and
      allow rule for "${esc(agent.name)}" automatically. The link is shown once and expires.
    </p>
    <div class="field">
      <wa-select id="cl-integration" label="Integration" value="${esc(oauthIntegrations[0].id)}">
        ${selectOptions(oauthIntegrations.map((i) => ({ value: i.id, label: i.title })), {
          selected: oauthIntegrations[0].id,
        })}
      </wa-select>
    </div>
    <div class="field">
      <wa-input id="cl-name" label="Connection name (optional)" placeholder="e.g. Slack for ${esc(agent.name)}"></wa-input>
    </div>
    <div class="field">
      <wa-input id="cl-ttl" type="number" min="1" max="90" value="7" label="Link valid for (days)"></wa-input>
    </div>
    <div class="modal-actions">
      <wa-button type="button" appearance="outlined" data-close>Cancel</wa-button>
      <wa-button type="button" variant="brand" id="cl-create">Create link</wa-button>
    </div>
  `,
    { label: `Connect link for ${agent.name}` },
  );

  $("#cl-create", modal).addEventListener("click", async () => {
    const integrationId = $("#cl-integration", modal).value;
    const nameRaw = ($("#cl-name", modal).value || "").trim();
    const ttlRaw = parseInt($("#cl-ttl", modal).value, 10);
    const body = { agentId: agent.id, integrationId };
    if (nameRaw) body.connectionName = nameRaw;
    if (Number.isFinite(ttlRaw) && ttlRaw > 0) body.ttlDays = ttlRaw;
    try {
      const link = await api("/api/onboarding-links", { method: "POST", body: JSON.stringify(body) });
      showConnectLink(agent, integrationId, link);
    } catch (err) {
      toast(`Could not create link: ${err.message}`);
    }
  });
}

/** Shows a freshly minted onboarding link with copy and expiry. */
function showConnectLink(agent, integrationId, link) {
  openModal(
    `
    <wa-callout variant="brand">
      <strong>Send this link to the bot owner.</strong> It works once and expires
      ${esc(fmtDate(link.expiresAt))}.
    </wa-callout>
    <div class="field" style="margin-top:1rem">
      <span class="field-label">Connect link for ${esc(agent.name)} (${esc(integrationId)})</span>
      <div class="copy-row">
        <code class="copy-box">${esc(link.url)}</code>
        <wa-button type="button" size="s" appearance="outlined" data-copy-text="${esc(link.url)}">Copy</wa-button>
      </div>
    </div>
    <div class="modal-actions">
      <wa-button type="button" variant="brand" data-close>Done</wa-button>
    </div>
  `,
    { label: "Connect link created" },
  );
}

// ---------------------------------------------------------------- view: projects

async function renderProjects(root) {
  const gen = currentGeneration();
  const [projects, agents] = await Promise.all([api("/api/projects"), api("/api/agents")]);
  const agentCount = (id) => agents.filter((a) => a.projectId === id).length;

  if (!isCurrentGeneration(gen)) return; // navigated away while loading
  root.innerHTML = `
    <header class="view-header">
      <h1>Projects</h1>
    </header>
    <div class="card">
      <form id="project-form" class="inline-form">
        <wa-input name="name" required spellcheck="false" placeholder="New project name"
                  label="Project name"></wa-input>
        <wa-button type="submit" variant="brand">Create project</wa-button>
      </form>
    </div>
    <div class="card">
      ${
        projects.length
          ? `<div class="table-wrap"><table>
              <thead><tr><th>Name</th><th>ID</th><th>Agents</th><th>Created</th><th></th></tr></thead>
              <tbody>${projects
                .map(
                  (p) => `<tr>
                    <td><strong>${esc(p.name)}</strong></td>
                    <td class="mono muted">${esc(p.id)}</td>
                    <td>${agentCount(p.id)}</td>
                    <td class="muted nowrap">${esc(fmtDate(p.createdAt))}</td>
                    <td class="actions">
                      <wa-button type="button" size="s" appearance="outlined" variant="danger" data-delete="${esc(p.id)}">Delete</wa-button>
                    </td>
                  </tr>`,
                )
                .join("")}</tbody>
            </table></div>`
          : emptyState("No projects yet. Projects group agents so rules can target the whole group.")
      }
    </div>
  `;

  $("#project-form", root).addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = String(new FormData(e.target).get("name") ?? "").trim();
    if (!name) return;
    try {
      await api("/api/projects", { method: "POST", body: JSON.stringify({ name }) });
      toast(`Project "${name}" created.`, "success");
      await renderProjects(root);
    } catch (err) {
      toast(`Create failed: ${err.message}`);
    }
  });

  $$("[data-delete]", root).forEach((btn) => {
    const project = projects.find((p) => p.id === btn.dataset.delete);
    btn.addEventListener("click", async () => {
      const ok = await confirmModal({
        title: "Delete project?",
        body: `Project "${project.name}" is removed. Its agents are kept but become unassigned.`,
        confirmLabel: "Delete project",
      });
      if (!ok) return;
      try {
        await api(`/api/projects/${encodeURIComponent(project.id)}`, { method: "DELETE" });
        toast("Project deleted.", "success");
        await renderProjects(root);
      } catch (err) {
        toast(`Delete failed: ${err.message}`);
      }
    });
  });
}

// ---------------------------------------------------------------- view: integrations

// Integration ids that ship a vendored brand SVG under
// vendor/integration-icons/. Every other id renders a monogram fallback.
// Keep in sync with scripts/extract-integration-icons.mjs.
const BRAND_ICON_IDS = new Set([
  "anthropic", "gemini", "huggingface", "discord", "github", "gitlab",
  "supabase", "mongodb-atlas", "docker", "jfrog-artifactory", "github-app",
  "resend", "google", "dropbox", "cloudflare", "flyio", "vercel", "notion",
  "linear", "jira", "confluence", "todoist", "trello", "stripe",
  "brave-search", "telegram-bot", "gcp",
]);

// Deterministic accent for monogram fallbacks: hash the id to one of a small
// palette that reads cleanly in both light and dark mode.
const MONOGRAM_COLORS = [
  "#4f46e5", "#0d9488", "#b45309", "#be123c", "#7c3aed", "#0369a1", "#15803d",
];

function monogramFor(id, title) {
  let hash = 0;
  for (let n = 0; n < id.length; n++) hash = (hash * 31 + id.charCodeAt(n)) >>> 0;
  const color = MONOGRAM_COLORS[hash % MONOGRAM_COLORS.length];
  const letters = (title || id).replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase() || "?";
  return { color, letters };
}

// Inlined brand SVGs (text) keyed by id, populated once per integrations
// render so the markup can carry currentColor and adapt to the theme.
const brandIconCache = new Map();

async function loadBrandIcons(ids) {
  await Promise.all(
    ids
      .filter((id) => BRAND_ICON_IDS.has(id) && !brandIconCache.has(id))
      .map(async (id) => {
        try {
          const res = await fetch(`vendor/integration-icons/${encodeURIComponent(id)}.svg`);
          brandIconCache.set(id, res.ok ? await res.text() : null);
        } catch {
          brandIconCache.set(id, null);
        }
      }),
  );
}

function iconHtml(i) {
  const svg = brandIconCache.get(i.id);
  if (BRAND_ICON_IDS.has(i.id) && svg) {
    return `<span class="integration-icon brand" aria-hidden="true">${svg}</span>`;
  }
  const { color, letters } = monogramFor(i.id, i.title);
  return `<span class="integration-icon monogram" aria-hidden="true" style="background:${color}">${esc(letters)}</span>`;
}

async function renderIntegrations(root) {
  const gen = currentGeneration();
  const [integrations, agents] = await Promise.all([api("/api/integrations"), api("/api/agents")]);
  await loadBrandIcons(integrations.map((i) => i.id));

  // The live model: app, LLM and OAuth integrations hold MULTIPLE named
  // connections (see the Connections page), not a single connect/disconnect
  // credential. The Integrations page surfaces that with a per-integration
  // count plus "Add connection" / "Manage connections". OAuth integrations
  // additionally keep their legacy single credential readable for back-compat.
  const appVendors = appVendorsOf(integrations);
  const llmVendors = llmVendorsOf(integrations);
  const appVendorIds = new Set(appVendors.map((v) => v.vendor));

  // app/llm/oauth integrations use the multi-connection model; only orphaned
  // legacy credentials (no live descriptor) fall back to the legacy card.
  function modelOf(i) {
    if (i.orphaned) return "orphaned";
    if (i.llm) return "llm";
    if (i.connect?.method === "oauth" && i.oauth) return "oauth-multi";
    if (appVendorIds.has(i.id)) return "app";
    return "oauth"; // field-less / descriptor-less legacy card
  }
  // How many active connections back this integration, for badges and counts.
  function connCountOf(i) {
    const m = modelOf(i);
    // OAuth also counts a legacy single credential alongside named connections.
    if (m === "oauth-multi") return (i.connectionCount ?? 0) + (i.connected ? 1 : 0);
    if (m === "app" || m === "llm") return i.connectionCount ?? 0;
    return i.connected ? 1 : 0; // legacy oauth / orphaned credential
  }
  const totalConns = integrations.reduce((n, i) => n + connCountOf(i), 0);

  if (!isCurrentGeneration(gen)) return; // navigated away while loading
  root.innerHTML = `
    <header class="view-header">
      <h1>Integrations</h1>
      <span class="muted">${integrations.length} integrations, ${totalConns} active connection${totalConns === 1 ? "" : "s"}</span>
    </header>
    <div class="card search-card">
      <wa-input id="integration-search" placeholder="Search by name, host or category"
                label="Search" clearable spellcheck="false" autocomplete="off"></wa-input>
      <div class="segmented" id="integration-filter" role="group" aria-label="Filter integrations">
        <wa-button type="button" size="s" data-mode="all" variant="brand">All</wa-button>
        <wa-button type="button" size="s" data-mode="connected" appearance="outlined">Connected</wa-button>
        <wa-button type="button" size="s" data-mode="available" appearance="outlined">Available</wa-button>
      </div>
    </div>
    <div id="integration-list"></div>
  `;

  function methodLabel(i) {
    return { oauth: "OAuth", api_key: "API key", credentials_import: "Import" }[i.connect?.method] ?? "";
  }

  // How many of an integration's connections are actually usable by a bot. A
  // named app/OAuth connection is default-deny: it exists but reaches no bot
  // until granted. LLM connections and legacy shared credentials are not
  // grant-gated, so they are always usable once present (FL2 U3).
  function usableCountOf(i) {
    const m = modelOf(i);
    if (m === "llm") return i.connectionCount ?? 0;
    if (m === "app") return i.grantedConnectionCount ?? 0;
    if (m === "oauth-multi") return (i.grantedConnectionCount ?? 0) + (i.connected ? 1 : 0);
    return i.connected ? 1 : 0; // legacy single credential / orphaned
  }

  // One consistent status badge for every card type (FL2 U5), and the place the
  // default-deny trap is surfaced (FL2 U3): connections that exist but reach no
  // bot read as a warning, not a reassuring green count.
  function badgeFor(i) {
    const m = modelOf(i);
    if (m === "orphaned") return { variant: "warning", text: "needs cleanup" };
    if (m === "oauth") {
      return i.connected
        ? { variant: "success", text: "connected" }
        : { variant: "neutral", text: "not connected" };
    }
    const count = connCountOf(i);
    if (count === 0) return { variant: "neutral", text: "no connections" };
    const plural = count === 1 ? "" : "s";
    if (usableCountOf(i) === 0) {
      return { variant: "warning", text: `${count} connection${plural}, none granted` };
    }
    return { variant: "success", text: `${count} connection${plural}` };
  }

  // Short, consistent helper line under each card (FL2 U5).
  function hintFor(i, model) {
    if (model === "orphaned") {
      return `<p class="hint">Credential for a disabled integration. Review and remove it on the Connections page.</p>`;
    }
    if (model === "oauth") {
      return i.connected
        ? `<p class="hint">Credential: ${esc(i.credentialName ?? i.id)}</p>`
        : `<p class="hint">${esc(methodLabel(i))} connect</p>`;
    }
    const verb = model === "llm" ? "route" : "grant";
    const count = connCountOf(i);
    if (count === 0) return `<p class="hint">No connections yet. Add one, then ${verb} it to a bot.</p>`;
    if (usableCountOf(i) === 0) {
      return `<p class="hint warn">Not granted to any bot, so it is unusable. Grant it on the Connections page.</p>`;
    }
    return `<p class="hint">Manage, ${verb} or edit on the Connections page.</p>`;
  }

  // Access leases (time-boxing) apply to credential/OAuth integrations whose
  // grants are per-bot allow rules. LLM routes and orphaned creds are excluded.
  function canTimebox(model) {
    return model === "oauth" || model === "oauth-multi" || model === "app";
  }

  // Small status line under the hint showing the integration's default time-box.
  function timeboxLine(i, model) {
    if (!canTimebox(model)) return "";
    const s = i.leaseDefaultSeconds;
    return s
      ? `<p class="hint"><wa-badge variant="warning" appearance="filled-outlined">Time-boxed: ${esc(fmtLeaseSeconds(s))}</wa-badge> default. Owners can override at connect time.</p>`
      : "";
  }

  // The card's action row. Discovery-only by design (FL2 D1): "Add connection"
  // here, all management ("Manage") deep-links to the Connections page. Legacy
  // single-credential integrations keep Connect/Disconnect because the
  // Connections page has no add path for them.
  function actionsHtml(i, model) {
    if (model === "orphaned") {
      return `<wa-button type="button" appearance="outlined" data-manage="${esc(i.id)}">Review</wa-button>`;
    }
    const timebox = canTimebox(model)
      ? `<wa-button type="button" appearance="outlined" data-timebox="${esc(i.id)}">${i.leaseDefaultSeconds ? "Time-box" + " · " + esc(fmtLeaseSeconds(i.leaseDefaultSeconds)) : "Time-box"}</wa-button>`
      : "";
    if (model === "oauth") {
      return `
        <wa-button type="button" ${i.connected ? 'appearance="outlined"' : 'variant="brand"'} data-connect="${esc(i.id)}">
          ${i.connected ? "Edit credentials" : "Connect"}
        </wa-button>
        ${i.connected ? `<wa-button type="button" appearance="outlined" variant="danger" data-disconnect="${esc(i.id)}">Disconnect</wa-button>` : ""}
        ${timebox}`;
    }
    const addAttr =
      model === "llm" ? "data-add-llm" : model === "oauth-multi" ? "data-add-oauth" : "data-add-app";
    const manage =
      connCountOf(i) > 0
        ? `<wa-button type="button" appearance="outlined" data-manage="${esc(i.id)}">Manage</wa-button>`
        : "";
    return `
      <wa-button type="button" variant="brand" ${addAttr}="${esc(i.id)}">Add connection</wa-button>
      ${manage}
      ${timebox}`;
  }

  // Unified lean discovery card (FL2 D1 + U5): icon, title, method, one status
  // badge, one hint, the action row.
  function cardHtml(i) {
    const model = modelOf(i);
    const badge = badgeFor(i);
    const sub = model === "orphaned" ? "Disconnected" : methodLabel(i);
    return `<div class="card integration">
      <div class="card-head">
        <div class="integration-title">
          ${iconHtml(i)}
          <div class="integration-heading">
            <h2>${esc(i.title)}</h2>
            ${sub ? `<span class="muted integration-method">${esc(sub)}</span>` : ""}
          </div>
        </div>
        <wa-badge variant="${badge.variant}" appearance="filled-outlined">${esc(badge.text)}</wa-badge>
      </div>
      ${hintFor(i, model)}
      ${timeboxLine(i, model)}
      <div class="card-actions">${actionsHtml(i, model)}</div>
    </div>`;
  }

  const list = $("#integration-list", root);
  const search = $("#integration-search", root);
  const filterBtns = $$("#integration-filter wa-button", root);
  // Connected/Available/All quick filter (FL2 U4).
  let mode = "all";

  function draw() {
    const q = String(search.value ?? "").trim().toLowerCase();
    const visible = integrations.filter((i) => {
      if (q && ![i.title, i.id, i.category, ...i.hosts].join(" ").toLowerCase().includes(q)) {
        return false;
      }
      if (mode === "connected") return connCountOf(i) > 0;
      if (mode === "available") return connCountOf(i) === 0;
      return true;
    });
    if (!visible.length) {
      list.innerHTML = emptyState("No integrations match.");
      return;
    }
    const groups = new Map();
    for (const i of visible) {
      const cat = i.category ?? "Other";
      if (!groups.has(cat)) groups.set(cat, []);
      groups.get(cat).push(i);
    }
    const cats = [...groups.keys()].sort((a, b) =>
      a === "Other" ? 1 : b === "Other" ? -1 : a.localeCompare(b),
    );
    list.innerHTML = cats
      .map((cat) => {
        // Connected first within each category (FL2 U4), then alphabetical.
        const items = groups
          .get(cat)
          .slice()
          .sort(
            (a, b) =>
              (connCountOf(b) > 0) - (connCountOf(a) > 0) || a.title.localeCompare(b.title),
          );
        const active = items.filter((i) => connCountOf(i) > 0).length;
        return `
          <h2 class="category-title">${esc(cat)}
            <span class="muted category-count">${active} / ${items.length} active</span>
          </h2>
          <div class="integration-grid">${items.map(cardHtml).join("")}</div>`;
      })
      .join("");
    wireCards();
  }

  search.addEventListener("input", draw);
  filterBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      mode = btn.dataset.mode;
      filterBtns.forEach((b) => {
        const on = b.dataset.mode === mode;
        b.setAttribute("variant", on ? "brand" : "neutral");
        if (on) b.removeAttribute("appearance");
        else b.setAttribute("appearance", "outlined");
      });
      draw();
    });
  });

  function wireCards() {
    const reload = () => renderIntegrations(root);

    $$("[data-add-app]", list).forEach((btn) => {
      const id = btn.dataset.addApp;
      // Lock the dialog to this integration (single-vendor list) so "Add
      // connection" on a card always creates a connection for that integration.
      const only = appVendors.filter((v) => v.vendor === id);
      btn.addEventListener("click", () =>
        openAppConnectionModal({ vendors: only.length ? only : appVendors, agents, vendor: id, onSaved: reload }),
      );
    });

    $$("[data-add-llm]", list).forEach((btn) => {
      const integration = integrations.find((i) => i.id === btn.dataset.addLlm);
      const only = llmVendors.filter((v) => v.vendor === integration?.llm?.vendor);
      btn.addEventListener("click", () =>
        openLlmConnectionModal({ vendors: only.length ? only : llmVendors, onSaved: reload }),
      );
    });

    $$("[data-add-oauth]", list).forEach((btn) => {
      const integration = integrations.find((i) => i.id === btn.dataset.addOauth);
      // Named OAuth connection: the connect dialog also collects a connection
      // name + owner + default, then runs the browser round-trip. On success
      // the callback creates a kind='app' connection (denied to all until
      // granted, same as any named app connection).
      btn.addEventListener("click", () =>
        openOauthModal(integration, reload, { named: true, agents }),
      );
    });

    $$("[data-manage]", list).forEach((btn) => {
      btn.addEventListener("click", () => {
        // Deep-link to the Connections page pre-filtered to this integration
        // (FL2 U1). The focus filter is read from the hash by renderConnections.
        location.hash = "#/connections?focus=" + encodeURIComponent(btn.dataset.manage);
      });
    });

    $$("[data-connect]", list).forEach((btn) => {
      const integration = integrations.find((i) => i.id === btn.dataset.connect);
      btn.addEventListener("click", () => openConnectModal(integration, reload));
    });

    $$("[data-disconnect]", list).forEach((btn) => {
      const integration = integrations.find((i) => i.id === btn.dataset.disconnect);
      btn.addEventListener("click", async () => {
        const ok = await confirmModal({
          title: `Disconnect ${integration.title}?`,
          body: "The stored credential is deleted and agent calls to this integration will fail until it is reconnected.",
          confirmLabel: "Disconnect",
        });
        if (!ok) return;
        try {
          await api(`/api/credentials/${encodeURIComponent(integration.id)}`, { method: "DELETE" });
          toast(`${integration.title} disconnected.`, "success");
          await renderIntegrations(root);
        } catch (err) {
          toast(`Disconnect failed: ${err.message}`);
        }
      });
    });

    $$("[data-timebox]", list).forEach((btn) => {
      const integration = integrations.find((i) => i.id === btn.dataset.timebox);
      btn.addEventListener("click", async () => {
        const secs = await timeboxModal(integration);
        if (secs === null) return; // cancelled
        try {
          if (secs > 0) {
            await api(`/api/integration-leases/${encodeURIComponent(integration.id)}`, {
              method: "PUT",
              body: JSON.stringify({ ttlSeconds: secs }),
            });
            toast(`${integration.title} is time-boxed (${fmtLeaseSeconds(secs)} default).`, "success");
          } else {
            await api(`/api/integration-leases/${encodeURIComponent(integration.id)}`, { method: "DELETE" });
            toast(`${integration.title} is now a regular connection.`, "success");
          }
          await renderIntegrations(root);
        } catch (err) {
          toast(`Time-box update failed: ${err.message}`);
        }
      });
    });
  }

  draw();
}

// ---------------------------------------------------------------- view: connections

async function renderConnections(root) {
  const gen = currentGeneration();
  const [conns, integrations, agents, projects] = await Promise.all([
    api("/api/connections"),
    api("/api/integrations"),
    api("/api/agents"),
    api("/api/projects"),
  ]);
  const vendors = llmVendorsOf(integrations);
  const appVendors = appVendorsOf(integrations);
  const vendorTitle = (v) => vendors.find((x) => x.vendor === v)?.title ?? v;
  const integrationOf = (id) => integrations.find((i) => i.id === id && !i.orphaned) ?? null;
  const refresh = () => renderConnections(root);

  // FL2 U1/U2: optional focus filter, deep-linked from an Integrations card's
  // "Manage" button as #/connections?focus=<integrationId>. Read from the hash
  // so it survives the post-mutation refresh() (which re-renders from the hash).
  const focus = hashParams().get("focus");
  const focusIntegration = focus ? integrations.find((i) => i.id === focus) : null;
  const focusLlmVendor = focusIntegration?.llm?.vendor ?? null;
  const matchesFocus = (a) => !focus || a.vendor === focus;

  const llm = conns.llm.filter((c) => !focus || c.vendor === focusLlmVendor);
  const services = conns.apps.filter((a) => !a.orphaned && !a.integration?.community && matchesFocus(a));
  const custom = conns.apps.filter((a) => !a.orphaned && a.integration?.community && matchesFocus(a));
  const orphans = conns.apps.filter((a) => a.orphaned && matchesFocus(a));

  // Default-deny: each named (non-legacy) app connection is unusable until
  // granted to an agent or a project. Fetch the grants for the named ones so
  // the table can show "Granted to" chips and a warning when empty.
  const namedApps = conns.apps.filter((a) => !a.legacy);
  const grantsByConn = new Map(
    await Promise.all(
      namedApps.map(async (a) => [a.id, await api(`/api/connections/${encodeURIComponent(a.id)}/grants`)]),
    ),
  );
  const agentName = (id) => agents.find((x) => x.id === id)?.name ?? id;
  const projectName = (id) => projects.find((x) => x.id === id)?.name ?? id;

  // A subtle masked preview of the stored secret, so an operator can tell which
  // key is stored without it ever being exposed. The API only ever sends the
  // already-masked preview; the raw secret never reaches the client.
  const secretPreview = (c) =>
    c.secretPreview ? `<div class="mono muted small-text secret-preview">${esc(c.secretPreview)}</div>` : "";

  // Access-lease badge for an app connection: shows whether the connection is
  // time-boxed and its effective duration. leaseEffectiveSeconds null = a
  // regular (non-time-boxed) connection, so nothing is shown.
  const fmtLeaseDur = (s) => (s % 3600 === 0 ? `${s / 3600}h` : s % 60 === 0 ? `${s / 60}m` : `${s}s`);
  const leaseCell = (c) => {
    const eff = c.leaseEffectiveSeconds;
    if (!eff) return `<span class="muted small-text">always-on</span>`;
    return `<wa-badge variant="warning" appearance="filled-outlined" title="Time-boxed: access lapses after this period, owner gets a renewal link">${fmtLeaseDur(eff)}</wa-badge>`;
  };

  const llmRows = llm
    .map(
      (c) => `<tr data-vendor="${esc(c.vendor)}">
        <td><strong>${esc(c.name)}</strong>${secretPreview(c)}</td>
        <td>${esc(vendorTitle(c.vendor))}</td>
        <td>${
          c.isDefault
            ? `<wa-badge variant="brand" appearance="filled-outlined">default</wa-badge>`
            : `<wa-button type="button" size="s" appearance="plain" data-set-default="${esc(c.id)}">Set default</wa-button>`
        }</td>
        <td class="muted nowrap">${esc(fmtDate(c.createdAt))}</td>
        <td class="actions">
          <wa-button type="button" size="s" appearance="outlined" data-edit-llm="${esc(c.id)}">Edit</wa-button>
          <wa-button type="button" size="s" appearance="outlined" variant="danger" data-delete-llm="${esc(c.id)}">Disconnect</wa-button>
        </td>
      </tr>`,
    )
    .join("");

  // Scope label for an app connection: a legacy single-credential row and a
  // tenant-wide named connection are both shared, an owned one names its agent.
  const scopeCell = (a) => {
    if (a.legacy) return `<span class="muted small-text">shared (legacy)</span>`;
    if (a.ownerAgentId)
      return `<wa-badge variant="neutral" appearance="filled-outlined">${esc(a.ownerAgentName ?? a.ownerAgentId)}</wa-badge>`;
    return `<span class="muted small-text">tenant-wide</span>`;
  };

  // Default badge / set-default control. Legacy rows are always the implicit
  // default for their integration and cannot be changed here.
  const defaultCell = (a) => {
    if (a.legacy) return `<wa-badge variant="brand" appearance="filled-outlined">default</wa-badge>`;
    return a.isDefault
      ? `<wa-badge variant="brand" appearance="filled-outlined">default</wa-badge>`
      : `<wa-button type="button" size="s" appearance="plain" data-set-default-app="${esc(a.id)}">Set default</wa-button>`;
  };

  // "Granted to" cell: chips for each agent/project grant with a remove (x), an
  // "Add grant" control, and a clear default-deny warning when empty. Legacy
  // single-credential rows are shared and not gated, so they show no grants UI.
  const grantsCell = (a) => {
    if (a.legacy) return `<span class="muted small-text">shared (legacy)</span>`;
    const grants = grantsByConn.get(a.id) ?? [];
    const chips = grants
      .map(
        (g) =>
          `<wa-badge class="grant-chip" variant="${g.scope === "project" ? "brand" : "neutral"}" appearance="filled-outlined">${
            g.scope === "project" ? "project: " : ""
          }${esc(g.subjectName ?? (g.scope === "project" ? projectName(g.subjectId) : agentName(g.subjectId)))}<button type="button" class="grant-x" title="Revoke" data-revoke-conn="${esc(a.id)}" data-revoke-scope="${esc(g.scope)}" data-revoke-subject="${esc(g.subjectId)}">&times;</button></wa-badge>`,
      )
      .join(" ");
    const warning = grants.length
      ? ""
      : `<div class="grant-warning small-text">Not granted to any bot (default-deny: unusable)</div>`;
    return `<div class="grants-cell">${chips}${warning}<wa-button type="button" size="s" appearance="plain" class="add-grant" data-add-grant="${esc(a.id)}">+ Grant</wa-button></div>`;
  };

  const appRows = (items) =>
    items
      .map(
        (a) => `<tr data-vendor="${esc(a.vendor)}">
          <td><strong>${esc(a.name)}</strong>${secretPreview(a)}</td>
          <td>${esc(a.integration?.title ?? a.vendor)}</td>
          <td>${scopeCell(a)}</td>
          <td>${grantsCell(a)}</td>
          <td>${leaseCell(a)}</td>
          <td>${defaultCell(a)}</td>
          <td class="muted nowrap">${esc(fmtDate(a.createdAt))}</td>
          <td class="actions">
            ${
              a.legacy
                ? `<wa-button type="button" size="s" appearance="outlined" data-edit-legacy="${esc(a.vendor)}">Edit</wa-button>
                   <wa-button type="button" size="s" appearance="outlined" variant="danger" data-delete-legacy="${esc(a.vendor)}">Disconnect</wa-button>`
                : `${
                    integrationOf(a.vendor)?.connect?.method === "oauth"
                      ? `<wa-button type="button" size="s" appearance="outlined" data-reauth-conn="${esc(a.id)}">Re-authorize</wa-button>`
                      : ""
                  }<wa-button type="button" size="s" appearance="outlined" data-edit-conn="${esc(a.id)}">Edit</wa-button>
                   <wa-button type="button" size="s" appearance="outlined" variant="danger" data-delete-conn="${esc(a.id)}">Disconnect</wa-button>`
            }
          </td>
        </tr>`,
      )
      .join("");

  const appTable = (items) => `
    <div class="table-wrap"><table>
      <thead><tr><th>Name</th><th>Integration</th><th>Scope</th><th>Granted to</th><th>Access</th><th>Default</th><th>Connected</th><th></th></tr></thead>
      <tbody>${appRows(items)}</tbody>
    </table></div>`;

  if (!isCurrentGeneration(gen)) return; // navigated away while loading
  root.innerHTML = `
    <header class="view-header">
      <h1>Connections</h1>
      <wa-button type="button" variant="brand" id="add-llm">Add LLM connection</wa-button>
    </header>
    <p class="muted page-note">
      Everything OneGate can inject. LLM vendors and services both support multiple
      named connections (one default each). A service connection can be tenant-wide
      (shared by every agent) or bound to one agent, and an agent holding several
      accounts of the same service picks one per request with the
      <span class="mono">x-onegate-connection</span> header.
    </p>

    ${
      focus
        ? `<div class="focus-bar">
            <wa-badge variant="brand" appearance="filled-outlined">Filtered: ${esc(focusIntegration?.title ?? focus)}</wa-badge>
            <a href="#/connections" class="focus-clear">Clear filter</a>
          </div>`
        : ""
    }

    <div class="card search-card">
      <wa-input id="conn-search" placeholder="Search connections by name, vendor or integration"
                label="Search" clearable spellcheck="false" autocomplete="off"></wa-input>
    </div>

    <div id="conn-sections">
    <div class="card">
      <div class="card-head"><h2>LLMs</h2><span class="muted">${llm.length} connection${llm.length === 1 ? "" : "s"}</span></div>
      ${
        llm.length
          ? `<div class="table-wrap"><table>
              <thead><tr><th>Name</th><th>Vendor</th><th>Default</th><th>Created</th><th></th></tr></thead>
              <tbody>${llmRows}</tbody>
            </table></div>`
          : emptyState("No LLM connections yet. Add one to route agent LLM traffic through OneGate.")
      }
    </div>

    <div class="card">
      <div class="card-head"><h2>Services</h2>
        <div class="card-head-actions">
          <wa-button type="button" size="s" variant="brand" id="add-app">Add app connection</wa-button>
          <wa-button size="s" appearance="outlined" href="#/integrations">Connect a service</wa-button>
        </div>
      </div>
      ${services.length ? appTable(services) : emptyState("No services connected. Add an app connection or connect one from the Integrations page.")}
    </div>

    ${
      custom.length
        ? `<div class="card">
            <div class="card-head"><h2>Custom</h2><span class="muted">community integrations</span></div>
            ${appTable(custom)}
          </div>`
        : ""
    }

    ${
      orphans.length
        ? `<div class="card">
            <div class="card-head"><h2>Orphaned</h2></div>
            <p class="hint">
              These credentials belong to integrations that are disabled or no longer installed.
              They are never injected. Disconnect them to clean up.
            </p>
            <div class="table-wrap"><table>
              <thead><tr><th>Name</th><th>Integration id</th><th>Connected</th><th></th></tr></thead>
              <tbody>${orphans
                .map(
                  (a) => `<tr data-vendor="${esc(a.vendor)}">
                    <td><strong>${esc(a.name)}</strong>${secretPreview(a)}</td>
                    <td class="mono muted">${esc(a.vendor)}</td>
                    <td class="muted nowrap">${esc(fmtDate(a.createdAt))}</td>
                    <td class="actions">
                      ${
                        a.legacy
                          ? `<wa-button type="button" size="s" appearance="outlined" variant="danger" data-delete-legacy="${esc(a.vendor)}">Disconnect</wa-button>`
                          : `<wa-button type="button" size="s" appearance="outlined" variant="danger" data-delete-conn="${esc(a.id)}">Disconnect</wa-button>`
                      }
                    </td>
                  </tr>`,
                )
                .join("")}</tbody>
            </table></div>
          </div>`
        : ""
    }
    </div>
  `;

  // FL2 U2: live search across the rendered connection tables. Hides rows whose
  // text does not match, then hides any section card with no visible rows.
  const searchInput = $("#conn-search", root);
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      const q = String(searchInput.value ?? "").trim().toLowerCase();
      $$("#conn-sections .card", root).forEach((card) => {
        const rows = $$("tbody tr", card);
        if (!rows.length) return;
        let shown = 0;
        rows.forEach((tr) => {
          const hit = !q || tr.textContent.toLowerCase().includes(q);
          tr.style.display = hit ? "" : "none";
          if (hit) shown += 1;
        });
        card.style.display = shown ? "" : "none";
      });
    });
  }

  $("#add-llm", root).addEventListener("click", () => {
    if (!vendors.length) {
      toast("No LLM vendor integrations are registered on this instance.");
      return;
    }
    openLlmConnectionModal({ vendors, onSaved: refresh });
  });

  $$("[data-edit-llm]", root).forEach((btn) => {
    const connection = llm.find((c) => c.id === btn.dataset.editLlm);
    btn.addEventListener("click", () => openLlmConnectionModal({ vendors, connection, onSaved: refresh }));
  });

  $$("[data-set-default]", root).forEach((btn) => {
    const connection = llm.find((c) => c.id === btn.dataset.setDefault);
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/connections/${encodeURIComponent(connection.id)}`, {
          method: "PUT",
          body: JSON.stringify({ isDefault: true }),
        });
        toast(`"${connection.name}" is now the default ${vendorTitle(connection.vendor)} connection.`, "success");
        await refresh();
      } catch (err) {
        toast(`Failed: ${err.message}`);
      }
    });
  });

  $$("[data-delete-llm]", root).forEach((btn) => {
    const connection = llm.find((c) => c.id === btn.dataset.deleteLlm);
    btn.addEventListener("click", async () => {
      const ok = await confirmModal({
        title: `Disconnect ${connection.name}?`,
        body: "The stored secret is deleted and the connection is removed from every agent's LLM routing order.",
        confirmLabel: "Disconnect",
      });
      if (!ok) return;
      try {
        await api(`/api/connections/${encodeURIComponent(connection.id)}`, { method: "DELETE" });
        toast(`"${connection.name}" disconnected.`, "success");
        await refresh();
      } catch (err) {
        toast(`Disconnect failed: ${err.message}`);
      }
    });
  });

  // Add a named app connection (kind="app"). OAuth integrations are connected
  // from the Integrations page, so the dialog only offers secret-field ones.
  $("#add-app", root).addEventListener("click", () => {
    if (!appVendors.length) {
      toast("No app integrations with secret credentials are registered on this instance.");
      return;
    }
    openAppConnectionModal({ vendors: appVendors, agents, onSaved: refresh });
  });

  // Named app connections (legacy: false) are edited / deleted / promoted by id.
  $$("[data-edit-conn]", root).forEach((btn) => {
    const connection = conns.apps.find((a) => a.id === btn.dataset.editConn);
    const integration = integrationOf(connection?.vendor);
    const isOauth = integration?.connect?.method === "oauth";
    // OAuth vendors are not in appVendors (they have no secret fields), so an
    // OAuth-backed connection needs its vendor added to the list for the modal
    // to resolve a title. Editing it only renames / re-defaults (no secret).
    const editVendors = isOauth
      ? [...appVendors, { vendor: connection.vendor, title: integration.title, credentialFields: [] }]
      : appVendors;
    btn.addEventListener("click", () =>
      openAppConnectionModal({ vendors: editVendors, agents, connection, onSaved: refresh, isOauth }),
    );
  });

  // Re-authorize an OAuth-backed connection: re-runs the browser OAuth round
  // trip and updates the existing connection's tokens in place (preserves its
  // grants). Token refresh is done here, not via the Edit dialog.
  $$("[data-reauth-conn]", root).forEach((btn) => {
    const connection = conns.apps.find((a) => a.id === btn.dataset.reauthConn);
    const integration = integrationOf(connection?.vendor);
    btn.addEventListener("click", () => {
      if (!integration) {
        toast("This connection's integration is not available on this instance.");
        return;
      }
      openOauthModal(integration, refresh, { connection });
    });
  });

  $$("[data-set-default-app]", root).forEach((btn) => {
    const connection = conns.apps.find((a) => a.id === btn.dataset.setDefaultApp);
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/connections/${encodeURIComponent(connection.id)}`, {
          method: "PUT",
          body: JSON.stringify({ isDefault: true }),
        });
        toast(`"${connection.name}" is now the default connection for its scope.`, "success");
        await refresh();
      } catch (err) {
        toast(`Failed: ${err.message}`);
      }
    });
  });

  $$("[data-delete-conn]", root).forEach((btn) => {
    const connection = conns.apps.find((a) => a.id === btn.dataset.deleteConn);
    btn.addEventListener("click", async () => {
      const ok = await confirmModal({
        title: `Disconnect ${connection.name}?`,
        body: "The stored secret is deleted, the connection is removed, and any agent that selected it falls back to its default.",
        confirmLabel: "Disconnect",
      });
      if (!ok) return;
      try {
        await api(`/api/connections/${encodeURIComponent(connection.id)}`, { method: "DELETE" });
        toast(`"${connection.name}" disconnected.`, "success");
        await refresh();
      } catch (err) {
        toast(`Disconnect failed: ${err.message}`);
      }
    });
  });

  // Grant a named app connection to an agent or project (default-deny: a new
  // connection is usable by no bot until granted). Grants are revocable from
  // the chips in the "Granted to" column.
  $$("[data-add-grant]", root).forEach((btn) => {
    const connection = conns.apps.find((a) => a.id === btn.dataset.addGrant);
    if (!connection) return;
    btn.addEventListener("click", () => {
      const existing = grantsByConn.get(connection.id) ?? [];
      const isGranted = (scope, id) =>
        existing.some((g) => g.scope === scope && g.subjectId === id);
      const agentOpts = agents
        .filter((a) => !isGranted("agent", a.id))
        .map((a) => ({ value: a.id, label: a.name }));
      const projectOpts = projects
        .filter((p) => !isGranted("project", p.id))
        .map((p) => ({ value: p.id, label: p.name }));
      const firstAgent = agentOpts[0]?.value ?? "";
      const firstProject = projectOpts[0]?.value ?? "";

      openModal(
        `
        <p class="muted small-text">Grant this connection to an agent, or to a project (applies to every agent in that project).</p>
        <form id="grant-form">
          <wa-select class="field" name="scope" label="Scope" value="agent">
            <wa-option value="agent">agent</wa-option>
            <wa-option value="project">project</wa-option>
          </wa-select>
          <wa-select class="field grow" name="agentId" label="Agent" value="${esc(firstAgent)}">
            ${selectOptions(agentOpts)}
          </wa-select>
          <wa-select class="field grow hidden" name="projectId" label="Project" value="${esc(firstProject)}">
            ${selectOptions(projectOpts)}
          </wa-select>
          <div class="modal-actions">
            <wa-button type="button" appearance="outlined" data-close>Cancel</wa-button>
            <wa-button type="submit" variant="brand" id="grant-save">Grant</wa-button>
          </div>
        </form>`,
        { label: `Grant "${connection.name}"` },
      );
      const scopeSel = $('[name="scope"]', modal);
      const agentSel = $('[name="agentId"]', modal);
      const projectSel = $('[name="projectId"]', modal);
      scopeSel.addEventListener("change", () => {
        const isProject = scopeSel.value === "project";
        agentSel.classList.toggle("hidden", isProject);
        projectSel.classList.toggle("hidden", !isProject);
      });
      $("#grant-form", modal).addEventListener("submit", async (e) => {
        e.preventDefault();
        const scope = scopeSel.value;
        const subjectId = scope === "project" ? projectSel.value : agentSel.value;
        if (!subjectId) {
          toast(`No ${scope} available to grant.`);
          return;
        }
        try {
          await api(`/api/connections/${encodeURIComponent(connection.id)}/grants`, {
            method: "POST",
            body: JSON.stringify({ scope, subjectId }),
          });
          closeModal(true);
          toast("Granted.", "success");
          await refresh();
        } catch (err) {
          toast(`Grant failed: ${err.message}`);
        }
      });
    });
  });

  $$("[data-revoke-conn]", root).forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.preventDefault();
      e.stopPropagation();
      const { revokeConn, revokeScope, revokeSubject } = btn.dataset;
      try {
        await api(
          `/api/connections/${encodeURIComponent(revokeConn)}/grants/${encodeURIComponent(
            revokeScope,
          )}/${encodeURIComponent(revokeSubject)}`,
          { method: "DELETE" },
        );
        toast("Grant revoked.", "success");
        await refresh();
      } catch (err) {
        toast(`Revoke failed: ${err.message}`);
      }
    });
  });

  // Legacy single-credential rows (the credentials table) keep the old
  // integration-keyed connect dialog and the /api/credentials/:id delete path.
  $$("[data-edit-legacy]", root).forEach((btn) => {
    const integration = integrationOf(btn.dataset.editLegacy);
    btn.addEventListener("click", () => {
      if (integration) openConnectModal(integration, refresh);
      else toast("This integration is not registered, so its credential cannot be edited.");
    });
  });

  $$("[data-delete-legacy]", root).forEach((btn) => {
    const integrationId = btn.dataset.deleteLegacy;
    const entry = conns.apps.find((a) => a.vendor === integrationId && a.legacy);
    btn.addEventListener("click", async () => {
      const ok = await confirmModal({
        title: `Disconnect ${entry?.integration?.title ?? integrationId}?`,
        body: "The stored credential is deleted and agent calls to this integration will fail until it is reconnected.",
        confirmLabel: "Disconnect",
      });
      if (!ok) return;
      try {
        await api(`/api/credentials/${encodeURIComponent(integrationId)}`, { method: "DELETE" });
        toast("Disconnected.", "success");
        await refresh();
      } catch (err) {
        toast(`Disconnect failed: ${err.message}`);
      }
    });
  });
}

// ---------------------------------------------------------------- view: rules

async function renderRules(root) {
  const gen = currentGeneration();
  const [rules, agents, projects, integrations] = await Promise.all([
    api("/api/rules"),
    api("/api/agents"),
    api("/api/projects"),
    api("/api/integrations"),
  ]);
  const subjectName = (rule) => {
    const pool = rule.scope === "agent" ? agents : projects;
    return pool.find((s) => s.id === rule.subjectId)?.name ?? rule.subjectId;
  };
  const integrationTitle = (id) =>
    id === "*" ? "All integrations" : (integrations.find((i) => i.id === id)?.title ?? id);

  if (!isCurrentGeneration(gen)) return; // navigated away while loading
  root.innerHTML = `
    <header class="view-header">
      <h1>Rules</h1>
      <wa-button type="button" variant="brand" id="new-rule">New rule</wa-button>
    </header>
    <p class="muted page-note">
      Rules decide which requests get credentials injected. Deny beats allow.
      Agents with the deny-unmatched policy need at least one allow rule to call anything.
    </p>
    <div class="card">
      ${
        rules.length
          ? `<div class="table-wrap"><table>
              <thead><tr>
                <th>Effect</th><th>Scope</th><th>Subject</th><th>Integration</th>
                <th>Methods</th><th>Path</th><th>Created</th><th></th>
              </tr></thead>
              <tbody>${rules
                .map(
                  (r) => `<tr>
                    <td>${decisionBadge(r.effect)}</td>
                    <td>${esc(r.scope)}</td>
                    <td><strong>${esc(subjectName(r))}</strong></td>
                    <td>${esc(integrationTitle(r.integrationId))}</td>
                    <td class="mono">${r.methods.map(esc).join(", ")}</td>
                    <td class="mono">${esc(r.pathGlob)}</td>
                    <td class="muted nowrap">${esc(fmtDate(r.createdAt))}</td>
                    <td class="actions">
                      <wa-button type="button" size="s" appearance="outlined" variant="danger" data-delete="${esc(r.id)}">Delete</wa-button>
                    </td>
                  </tr>`,
                )
                .join("")}</tbody>
            </table></div>`
          : emptyState("No rules yet. Create one to allow an agent or project to use an integration.")
      }
    </div>
  `;

  $("#new-rule", root).addEventListener("click", () => {
    const subjectsFor = (scope) =>
      (scope === "agent" ? agents : projects).map((s) => ({ value: s.id, label: s.name }));
    const integrationOpts = [
      { value: "*", label: "All integrations (*)" },
      ...integrations.map((i) => ({ value: i.id, label: i.title })),
    ];
    const firstSubject = subjectsFor("agent")[0]?.value ?? "";

    openModal(
      `
      <form id="rule-form">
        <div class="field-row">
          <wa-select class="field" name="scope" label="Scope" value="agent">
            <wa-option value="agent">agent</wa-option>
            <wa-option value="project">project</wa-option>
          </wa-select>
          <wa-select class="field grow" name="subjectId" label="Subject" required
                     value="${esc(firstSubject)}">${selectOptions(subjectsFor("agent"))}</wa-select>
        </div>
        <wa-select class="field" name="integrationId" label="Integration" value="*">
          ${selectOptions(integrationOpts)}
        </wa-select>
        <div class="field">
          <span class="field-label">Methods</span>
          <div class="check-row">
            <wa-checkbox name="method-all" checked>all (*)</wa-checkbox>
            ${HTTP_METHODS.map(
              (m) => `<wa-checkbox name="method" value="${m}" disabled>${m}</wa-checkbox>`,
            ).join("")}
          </div>
        </div>
        <wa-input class="field" name="pathGlob" label="Path glob (* = one segment, ** = anything)"
                  class="mono" spellcheck="false" value="/**"></wa-input>
        <div class="field">
          <wa-radio-group name="effect" label="Effect" value="allow" orientation="horizontal">
            <wa-radio value="allow">allow</wa-radio>
            <wa-radio value="deny">deny</wa-radio>
          </wa-radio-group>
        </div>
        <div class="modal-actions">
          <wa-button type="button" appearance="outlined" data-close>Cancel</wa-button>
          <wa-button type="submit" variant="brand">Create rule</wa-button>
        </div>
      </form>
    `,
      { label: "New rule" },
    );

    const form = $("#rule-form", modal);
    const scopeSel = $("wa-select[name=scope]", form);
    const subjectSel = $("wa-select[name=subjectId]", form);
    scopeSel.addEventListener("change", () => {
      const subjects = subjectsFor(scopeSel.value);
      subjectSel.innerHTML = selectOptions(subjects);
      subjectSel.value = subjects[0]?.value ?? "";
    });
    const allBox = $("wa-checkbox[name=method-all]", form);
    const methodBoxes = $$("wa-checkbox[name=method]", form);
    allBox.addEventListener("change", () => {
      methodBoxes.forEach((b) => {
        b.disabled = allBox.checked;
        if (allBox.checked) b.checked = false;
      });
    });

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!subjectSel.value) {
        toast(`No ${scopeSel.value}s exist yet. Create one first.`);
        return;
      }
      const methods = allBox.checked ? ["*"] : methodBoxes.filter((b) => b.checked).map((b) => b.value);
      if (!methods.length) {
        toast("Pick at least one method, or check all (*).");
        return;
      }
      try {
        await api("/api/rules", {
          method: "POST",
          body: JSON.stringify({
            scope: scopeSel.value,
            subjectId: subjectSel.value,
            integrationId: $("wa-select[name=integrationId]", form).value,
            methods,
            pathGlob: ($("wa-input[name=pathGlob]", form).value ?? "").trim() || "/**",
            effect: new FormData(form).get("effect"),
          }),
        });
        closeModal(true);
        toast("Rule created.", "success");
        await renderRules(root);
      } catch (err) {
        toast(`Create failed: ${err.message}`);
      }
    });
  });

  $$("[data-delete]", root).forEach((btn) => {
    btn.addEventListener("click", async () => {
      const ok = await confirmModal({
        title: "Delete rule?",
        body: "Access decisions change immediately for the affected agents.",
        confirmLabel: "Delete rule",
      });
      if (!ok) return;
      try {
        await api(`/api/rules/${encodeURIComponent(btn.dataset.delete)}`, { method: "DELETE" });
        toast("Rule deleted.", "success");
        await renderRules(root);
      } catch (err) {
        toast(`Delete failed: ${err.message}`);
      }
    });
  });
}

// ---------------------------------------------------------------- view: audit

async function renderAudit(root) {
  const gen = currentGeneration();
  const agents = await api("/api/agents");

  if (!isCurrentGeneration(gen)) return; // navigated away while loading
  root.innerHTML = `
    <header class="view-header">
      <h1>Audit log</h1>
      <div class="toolbar">
        <wa-select id="audit-agent" label="Agent" value="">
          ${selectOptions(
            agents.map((a) => ({ value: a.id, label: a.name })),
            { none: "All agents" },
          )}
        </wa-select>
        <wa-button type="button" appearance="outlined" id="audit-refresh">Refresh</wa-button>
      </div>
    </header>
    <div class="card" id="audit-table">${loadingState("Loading audit log")}</div>
  `;

  async function load() {
    const agentId = $("#audit-agent", root).value;
    const qs = agentId ? `&agentId=${encodeURIComponent(agentId)}` : "";
    try {
      const rows = await api(`/api/audit?limit=200${qs}`);
      if (!isCurrentGeneration(gen)) return; // navigated away while loading
      $("#audit-table", root).innerHTML = auditTable(rows);
    } catch (err) {
      if (err.status !== 401) toast(`Failed to load audit log: ${err.message}`);
    }
  }

  $("#audit-agent", root).addEventListener("change", load);
  $("#audit-refresh", root).addEventListener("click", load);
  await load();
}

// ---------------------------------------------------------------- view: usage

const USAGE_RANGES = [
  { value: "24h", label: "Last 24 hours", ms: 24 * 3600 * 1000 },
  { value: "7d", label: "Last 7 days", ms: 7 * 24 * 3600 * 1000 },
  { value: "30d", label: "Last 30 days", ms: 30 * 24 * 3600 * 1000 },
];

function fmtNum(n) {
  return n == null ? "–" : Number(n).toLocaleString();
}

async function renderUsage(root) {
  const gen = currentGeneration();
  const agents = await api("/api/agents");
  const agentName = (id) => agents.find((a) => a.id === id)?.name ?? id ?? "–";

  if (!isCurrentGeneration(gen)) return; // navigated away while loading
  root.innerHTML = `
    <header class="view-header">
      <h1>LLM usage</h1>
      <div class="toolbar">
        <wa-select id="usage-range" label="Range" value="7d">
          ${selectOptions(USAGE_RANGES.map((r) => ({ value: r.value, label: r.label })), { selected: "7d" })}
        </wa-select>
        <wa-button type="button" appearance="outlined" id="usage-refresh">Refresh</wa-button>
      </div>
    </header>
    <p class="muted page-note">
      Routing decisions and request totals for agents with LLM routing enabled.
      Token counts are best-effort: streamed or compressed responses may not report them.
    </p>
    <div id="usage-body">${loadingState("Loading usage")}</div>
  `;

  async function load() {
    const rangeSel = $("#usage-range", root);
    const range = USAGE_RANGES.find((r) => r.value === rangeSel.value) ?? USAGE_RANGES[1];
    const since = new Date(Date.now() - range.ms).toISOString();
    let data;
    try {
      data = await api(`/api/usage?since=${encodeURIComponent(since)}&limit=100`);
    } catch (err) {
      if (err.status !== 401) toast(`Failed to load usage: ${err.message}`);
      return;
    }
    if (!isCurrentGeneration(gen)) return; // navigated away while loading

    // opts.turns adds an "Est. turns" column (estimated conversational turns,
    // inferred from request gaps, see turnEstimate). Only the model/bot rollups
    // pass it; the header wording flags the numbers as estimates.
    const rollupTable = (rows, firstCol, firstCell, opts = {}) =>
      rows.length
        ? `<div class="table-wrap"><table>
            <thead><tr>
              <th>${esc(firstCol)}</th><th>Requests</th>${opts.turns ? `<th title="Estimated conversational turns, inferred from request gaps. Approximate, not exact.">Est. turns</th>` : ""}<th>Errors</th><th>Failovers</th>
              <th>Input tokens</th><th>Output tokens</th><th>Last used</th>
            </tr></thead>
            <tbody>${rows
              .map(
                (r) => `<tr>
                  <td>${firstCell(r)}</td>
                  <td>${fmtNum(r.requests)}</td>
                  ${opts.turns ? `<td>${fmtNum(r.estimatedTurns ?? 0)} <span class="muted small-text">est.</span></td>` : ""}
                  <td>${r.errors ? `<span class="usage-errors">${fmtNum(r.errors)}</span>` : "0"}</td>
                  <td>${fmtNum(r.failovers)}</td>
                  <td>${fmtNum(r.inputTokens)}</td>
                  <td>${fmtNum(r.outputTokens)}</td>
                  <td class="muted nowrap">${r.lastUsed ? esc(fmtDate(r.lastUsed)) : "–"}</td>
                </tr>`,
              )
              .join("")}</tbody>
          </table></div>`
        : emptyState("No LLM requests recorded in this range.");

    const gapSec = Math.round((data.turnEstimate?.gapMs ?? 60000) / 1000);
    const turnsNote = `<p class="muted small-text">Est. turns are estimated conversational turns, inferred from the gap between requests (a gap over ${gapSec}s starts a new turn). Approximate, not an exact count.</p>`;

    const recentTable = data.recent.length
      ? `<div class="table-wrap"><table>
          <thead><tr>
            <th>Time</th><th>Agent</th><th>Vendor</th><th>Connection</th>
            <th>Strategy</th><th>Failover</th><th>Outcome</th>
          </tr></thead>
          <tbody>${data.recent
            .map(
              (e) => `<tr>
                <td class="muted nowrap">${esc(fmtDate(e.ts))}</td>
                <td>${esc(agentName(e.agentId))}</td>
                <td>${esc(e.vendor ?? "–")}</td>
                <td><strong>${esc(e.connectionName ?? e.connectionId)}</strong></td>
                <td class="mono">${esc(e.strategy ?? "–")}</td>
                <td>${e.failover ? `<wa-badge variant="warning" appearance="filled-outlined">failover</wa-badge>` : `<span class="muted">–</span>`}</td>
                <td><wa-badge variant="${e.outcome === "ok" ? "success" : "danger"}" appearance="filled-outlined">${esc(e.outcome)}</wa-badge></td>
              </tr>`,
            )
            .join("")}</tbody>
        </table></div>`
      : emptyState("No routing decisions recorded in this range.");

    $("#usage-body", root).innerHTML = `
      <div class="card">
        <div class="card-head"><h2>By connection</h2></div>
        ${rollupTable(data.connections, "Connection", (r) => `<strong>${esc(r.connectionName ?? r.connectionId)}</strong> <span class="muted small-text">${esc(r.vendor ?? "")}</span>`)}
      </div>
      <div class="card">
        <div class="card-head"><h2>By vendor</h2></div>
        ${rollupTable(data.vendors, "Vendor", (r) => `<strong>${esc(r.vendor ?? "unknown")}</strong>`)}
      </div>
      <div class="card">
        <div class="card-head"><h2>By model</h2></div>
        ${rollupTable(data.models ?? [], "Model", (r) => `<strong>${esc(r.model ?? "unknown")}</strong> <span class="muted small-text">${esc(r.vendor ?? "")}</span>`, { turns: true })}
        ${turnsNote}
      </div>
      <div class="card">
        <div class="card-head"><h2>By bot + model</h2></div>
        ${rollupTable(data.bots ?? [], "Bot", (r) => `<strong>${esc(r.agentName ?? r.agentId ?? "unknown")}</strong> <span class="muted small-text">${esc(r.model ?? "unknown")} · ${esc(r.vendor ?? "")}</span>`, { turns: true })}
        ${turnsNote}
      </div>
      <div class="card">
        <div class="card-head"><h2>Recent selections</h2></div>
        ${recentTable}
      </div>
    `;
  }

  $("#usage-range", root).addEventListener("change", load);
  $("#usage-refresh", root).addEventListener("click", load);
  await load();
}

// ---------------------------------------------------------------- router & boot

const renderers = {
  dashboard: renderDashboard,
  agents: renderAgents,
  projects: renderProjects,
  integrations: renderIntegrations,
  connections: renderConnections,
  rules: renderRules,
  audit: renderAudit,
  usage: renderUsage,
};

function currentView() {
  const v = location.hash.replace(/^#\/?/, "").split("?")[0];
  return VIEWS.includes(v) ? v : "dashboard";
}

// Query params after the hash view, e.g. #/connections?focus=github (FL2 U1).
function hashParams() {
  const q = location.hash.split("?")[1] ?? "";
  return new URLSearchParams(q);
}

async function route() {
  // Bump first: any render still in flight from a previous navigation is now
  // stale and will abandon its writes rather than paint over this view.
  const gen = beginGeneration();
  const view = currentView();
  $$("#nav a, #drawer-nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === view));
  closeDrawer();
  const root = $("#view");
  root.innerHTML = loadingState(`Loading ${view}`);
  try {
    await renderers[view](root);
  } catch (err) {
    if (err.status === 401) return; // logout() already took over
    if (!isCurrentGeneration(gen)) return; // navigated away, do not paint a stale error
    root.innerHTML = `<div class="card error-block">Failed to load ${esc(view)}: ${esc(err.message)}</div>`;
  }
}

window.addEventListener("hashchange", () => {
  if (!$("#app").classList.contains("hidden")) route();
});

(async function boot() {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) {
    showAuth();
    return;
  }
  try {
    if (await verifyToken(token)) showApp();
    else logout("Stored token is no longer valid. Sign in again.");
  } catch (err) {
    showAuth(`Could not reach the server: ${err.message}`);
  }
})();
