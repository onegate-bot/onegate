/**
 * Renders vendor brand logos for the self-service connect pages. Data lives in
 * the generated logos.ts; this module turns an integration id into an inline
 * SVG tile. Real marks (simple-icons single-path) draw the brand-coloured path
 * on a tinted tile; brands without a bundled mark draw a monogram of the first
 * letter on a brand-coloured tile. Everything is inline SVG so the page makes
 * no third-party request.
 */

import { INTEGRATION_LOGOS } from "./logos.js";

/** Escapes text for safe inclusion in an SVG/HTML attribute or text node. */
function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Returns an inline SVG string for a vendor logo tile (`size` px square). Draws
 * the real brand mark when one is bundled, otherwise a brand-coloured monogram
 * tile. `fallbackTitle` (the integration's own title) is used for the label and
 * monogram when the id has no logo entry at all.
 */
export function brandLogoTile(id: string, fallbackTitle: string, size = 44): string {
  const logo = INTEGRATION_LOGOS[id];
  const title = logo?.title ?? fallbackTitle;
  const hex = logo?.hex ?? "6366F1";
  const r = Math.round(size * 0.22);
  const frame =
    `width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" ` +
    `role="img" aria-label="${esc(title)} logo"`;

  if (logo?.path) {
    const pad = size * 0.22;
    const inner = size - pad * 2;
    return (
      `<svg ${frame}>` +
      `<rect width="${size}" height="${size}" rx="${r}" fill="#${esc(hex)}" opacity=".1"/>` +
      `<svg x="${pad}" y="${pad}" width="${inner}" height="${inner}" viewBox="0 0 24 24">` +
      `<path d="${esc(logo.path)}" fill="#${esc(hex)}"/></svg></svg>`
    );
  }

  const letter = (title.trim()[0] || "?").toUpperCase();
  return (
    `<svg ${frame}>` +
    `<rect width="${size}" height="${size}" rx="${r}" fill="#${esc(hex)}"/>` +
    `<text x="50%" y="52%" dominant-baseline="central" text-anchor="middle" ` +
    `font-family="-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif" ` +
    `font-size="${Math.round(size * 0.5)}" font-weight="700" fill="#fff">${esc(letter)}</text></svg>`
  );
}
