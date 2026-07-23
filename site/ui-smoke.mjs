// UI sanity smoke for the OneGate landing page. Serves site/ statically and
// loads it in headless Chromium at mobile and desktop widths, in both light
// and dark themes. Fails on: page errors, console errors OR warnings
// (Web Awesome reports component autoload failures as warnings), unexpected
// 404s, or the hero content not being visible.
//
// Playwright is resolved from PW_DIR (a directory with playwright installed):
//   mkdir -p /tmp/pw && cd /tmp/pw && npm i playwright@1.52.0
// The browser binary is taken from PW_CHROMIUM (default /usr/bin/chromium).
//   PW_DIR=/tmp/pw node site/ui-smoke.mjs

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, extname, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const ROOT = dirname(fileURLToPath(import.meta.url));
const MARKER = "credential gateway for AI agents";

// Known-benign third-party noise to ignore, matched by exact signature so real
// problems still surface. WebAwesome's <wa-option> can run its slot-change
// handler during the upgrade window before its parent <wa-select> defines
// handleDefaultSlotChange. The landing page does not use wa-select, but the
// filter is kept for parity with the admin smoke test.
const IGNORED_ERRORS = [/handleDefaultSlotChange is not a function/];
const isIgnored = (text) => IGNORED_ERRORS.some((re) => re.test(text));

const require = createRequire(join(process.env.PW_DIR || process.cwd(), "x.js"));
const { chromium } = require("playwright");

const types = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".json": "application/json",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

const server = createServer(async (req, res) => {
  let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (p.endsWith("/")) p += "index.html";
  const file = normalize(join(ROOT, p));
  if (!file.startsWith(normalize(ROOT))) {
    res.writeHead(403);
    return res.end();
  }
  try {
    const buf = await readFile(file);
    res.writeHead(200, { "content-type": types[extname(file)] || "application/octet-stream" });
    res.end(buf);
  } catch {
    res.writeHead(404);
    res.end("not found");
  }
});
await new Promise((r) => server.listen(0, r));
const base = `http://localhost:${server.address().port}/`;

const browser = await chromium.launch({
  args: ["--no-sandbox"],
  executablePath: process.env.PW_CHROMIUM || "/usr/bin/chromium",
});
const failures = [];

function watch(page, problems) {
  page.on("pageerror", (e) => {
    if (isIgnored(String(e))) return;
    problems.push(`pageerror: ${e}`);
  });
  page.on("console", (m) => {
    if (m.type() !== "error" && m.type() !== "warning") return;
    if (isIgnored(m.text())) return;
    problems.push(`console.${m.type()}: ${m.text().slice(0, 200)}`);
  });
  page.on("response", (r) => {
    if (r.status() === 404) problems.push(`404: ${new URL(r.url()).pathname}`);
  });
}

for (const viewport of [{ width: 390, height: 800 }, { width: 1280, height: 900 }]) {
  for (const theme of ["light", "dark"]) {
    const label = `${viewport.width}px/${theme}`;
    const problems = [];
    const page = await browser.newPage({ viewport });
    watch(page, problems);
    await page.addInitScript((t) => localStorage.setItem("onegate_theme", t), theme);
    await page.goto(base, { waitUntil: "networkidle", timeout: 30000 });
    await page.waitForTimeout(1200);

    const themeOk = await page.evaluate(
      (t) => document.documentElement.classList.contains(t === "dark" ? "wa-dark" : "wa-light"),
      theme,
    );
    if (!themeOk) problems.push(`theme class for ${theme} not applied`);

    const text = await page.evaluate(() => document.body.innerText);
    if (!text.includes(MARKER)) {
      problems.push(`marker "${MARKER}" not visible (body text: ${JSON.stringify(text.slice(0, 140))})`);
    }

    // No horizontal scroll at any width.
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    if (overflow > 1) problems.push(`horizontal overflow of ${overflow}px`);

    if (problems.length) failures.push(...problems.map((p) => `[${label}] ${p}`));
    await page.close();
  }
}

await browser.close();
server.close();

if (failures.length) {
  console.error("UI smoke FAILED:");
  failures.forEach((f) => console.error("  " + f));
  process.exit(1);
}
console.log("UI smoke passed (mobile + desktop, light + dark, console clean).");
