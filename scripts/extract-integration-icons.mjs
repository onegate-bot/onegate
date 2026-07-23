// One-off build-time helper: extracts brand SVGs from simple-icons (MIT, CC0 icon
// data) and writes them to src/admin/ui/vendor/integration-icons/<id>.svg.
// Runtime never imports simple-icons. Run with: node scripts/extract-integration-icons.mjs
import * as si from "simple-icons";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "src", "admin", "ui", "vendor", "integration-icons");
mkdirSync(outDir, { recursive: true });

// integration id -> simple-icons slug (the part after "si", title-cased).
// null = no brand icon in simple-icons, render a monogram fallback instead.
const slugById = {
  anthropic: "Anthropic",
  openai: null,
  gemini: "Googlegemini",
  huggingface: "Huggingface",
  slack: null,
  discord: "Discord",
  github: "Github",
  gitlab: "Gitlab",
  supabase: "Supabase",
  "mongodb-atlas": "Mongodb",
  docker: "Docker",
  "jfrog-artifactory": "Jfrog",
  "github-app": "Github",
  sendgrid: null,
  resend: "Resend",
  google: "Google",
  dropbox: "Dropbox",
  cloudflare: "Cloudflare",
  flyio: "Flydotio",
  vercel: "Vercel",
  notion: "Notion",
  linear: "Linear",
  jira: "Jira",
  confluence: "Confluence",
  todoist: "Todoist",
  trello: "Trello",
  monday: null,
  linkedin: null,
  stripe: "Stripe",
  tavily: null,
  "brave-search": "Brave",
  "telegram-bot": "Telegram",
  gcp: "Googlecloud",
  aws: null,
};

const written = [];
const fallback = [];

for (const [id, slug] of Object.entries(slugById)) {
  if (slug == null) {
    fallback.push(id);
    continue;
  }
  const icon = si["si" + slug];
  if (!icon) {
    console.error(`MISSING simple-icons slug for ${id}: si${slug}`);
    fallback.push(id);
    continue;
  }
  // simple-icons exposes a 24x24 path. Wrap it as a standalone SVG using
  // currentColor so it adapts to light/dark theme.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" role="img" aria-label="${icon.title}"><title>${icon.title}</title><path fill="currentColor" d="${icon.path}"/></svg>\n`;
  writeFileSync(join(outDir, `${id}.svg`), svg);
  written.push(id);
}

console.log(`brand icons written (${written.length}):`, written.join(", "));
console.log(`monogram fallback (${fallback.length}):`, fallback.join(", "));
