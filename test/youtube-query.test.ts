/**
 * YouTube injects its API key into the query string. The path must be split on
 * the FIRST "?" only, so a literal "?" inside a query value survives.
 */

import { describe, it, expect } from "vitest";
import { youtube } from "../src/integrations/youtube.js";
import { Store } from "../src/store/db.js";

const store = new Store(":memory:");

function inject(path: string, apiKey = "AIzaREAL") {
  const ctx = {
    headers: {},
    method: "GET",
    host: "www.googleapis.com",
    path,
    credential: { id: "cr", integrationId: "youtube", name: "yt", data: { apiKey }, createdAt: "" },
    store,
  };
  youtube.inject(ctx);
  return ctx;
}

describe("youtube key injection with a literal '?' in the query", () => {
  it("keeps everything after a second '?' and adds the key once", () => {
    const ctx = inject("/youtube/v3/search?q=what?now&part=snippet");
    const url = new URL(ctx.path, "https://www.googleapis.com");
    expect(url.pathname).toBe("/youtube/v3/search");
    expect(url.searchParams.get("q")).toBe("what?now");
    expect(url.searchParams.get("part")).toBe("snippet");
    expect(url.searchParams.getAll("key")).toEqual(["AIzaREAL"]);
    expect(ctx.headers).toEqual({});
  });

  it("replaces a placeholder key that follows a '?'-bearing value", () => {
    const ctx = inject("/youtube/v3/search?q=a?b?c&key=PLACEHOLDER");
    const url = new URL(ctx.path, "https://x");
    expect(url.searchParams.get("q")).toBe("a?b?c");
    expect(url.searchParams.getAll("key")).toEqual(["AIzaREAL"]);
  });

  it("handles a bare path and a trailing '?'", () => {
    expect(inject("/youtube/v3/channels").path).toBe("/youtube/v3/channels?key=AIzaREAL");
    expect(inject("/youtube/v3/channels?").path).toBe("/youtube/v3/channels?key=AIzaREAL");
  });
});
