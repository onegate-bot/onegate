/**
 * brandLogoTile renders a self-contained inline SVG for a vendor logo: the real
 * simple-icons mark when bundled, otherwise a brand-coloured monogram tile.
 */
import { describe, it, expect } from "vitest";
import { brandLogoTile } from "../src/admin/logo-render.js";
import { INTEGRATION_LOGOS } from "../src/admin/logos.js";

describe("brandLogoTile", () => {
  it("renders a real single-path mark for a bundled brand (make)", () => {
    const svg = brandLogoTile("make", "Make");
    expect(svg).toContain('aria-label="Make logo"');
    expect(svg).toContain("<path d="); // the vendor's single-path mark
    expect(svg).toContain(`#${INTEGRATION_LOGOS.make!.hex}`);
    // No monogram text node when we have the real mark.
    expect(svg).not.toContain("<text");
  });

  it("renders a monogram tile for a brand simple-icons dropped (slack)", () => {
    const svg = brandLogoTile("slack", "Slack");
    expect(svg).toContain('aria-label="Slack logo"');
    expect(svg).toContain("<text"); // monogram fallback
    expect(svg).toContain(">S</text>"); // first letter of the title
    expect(svg).toContain(`#${INTEGRATION_LOGOS.slack!.hex}`);
  });

  it("falls back to a monogram from the given title for an unknown id", () => {
    const svg = brandLogoTile("no-such-integration", "Zeta");
    expect(svg).toContain('aria-label="Zeta logo"');
    expect(svg).toContain(">Z</text>");
    expect(svg).toContain("#6366F1"); // default indigo tile
  });

  it("escapes the label so a hostile title cannot break out of the attribute", () => {
    const svg = brandLogoTile("no-such-integration", 'Ev"il<>&');
    expect(svg).not.toContain('Ev"il<>&');
    expect(svg).toContain("&quot;");
    expect(svg).toContain("&lt;");
  });

  it("has an entry for every non-LLM connectable integration id", async () => {
    const { buildRegistry } = await import("../src/integrations/index.js");
    const registry = await buildRegistry();
    const { connectFlowKind } = await import("../src/integrations/types.js");
    const missing = registry
      .list()
      .filter((i) => connectFlowKind(i) !== null)
      .filter((i) => !INTEGRATION_LOGOS[i.id])
      .map((i) => i.id);
    expect(missing).toEqual([]);
  });
});
