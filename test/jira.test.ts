import { describe, it, expect } from "vitest";
import { jira, normalizeSiteUrl } from "../src/integrations/jira.js";
import type { Credential } from "../src/types.js";

function cred(data: Record<string, string>): Credential {
  return {
    id: "cr_1",
    integrationId: "jira",
    name: "Jira",
    data,
    createdAt: "2026-06-22T00:00:00.000Z",
  };
}

describe("normalizeSiteUrl", () => {
  it("adds https and strips a trailing slash", () => {
    expect(normalizeSiteUrl("eli.atlassian.net")).toBe("https://eli.atlassian.net");
    expect(normalizeSiteUrl("https://eli.atlassian.net/")).toBe("https://eli.atlassian.net");
  });

  it("keeps an explicit scheme and host", () => {
    expect(normalizeSiteUrl("https://team.atlassian.net")).toBe("https://team.atlassian.net");
  });

  it("returns null for empty or unusable input", () => {
    expect(normalizeSiteUrl("")).toBeNull();
    expect(normalizeSiteUrl("   ")).toBeNull();
    expect(normalizeSiteUrl(undefined)).toBeNull();
    expect(normalizeSiteUrl(null)).toBeNull();
  });
});

describe("jira.accountSummary", () => {
  it("returns the email, normalized site URL and REST base", () => {
    const s = jira.accountSummary!(cred({ email: "me@x.com", siteUrl: "eli.atlassian.net" }));
    expect(s).toEqual({
      email: "me@x.com",
      siteUrl: "https://eli.atlassian.net",
      apiBaseUrl: "https://eli.atlassian.net/rest/api/3",
    });
  });

  it("nulls the URLs when no site URL was recorded", () => {
    const s = jira.accountSummary!(cred({ email: "me@x.com" }));
    expect(s).toEqual({ email: "me@x.com", siteUrl: null, apiBaseUrl: null });
  });

  it("carries no secret material", () => {
    const s = jira.accountSummary!(cred({ email: "me@x.com", apiToken: "supersecret", siteUrl: "t.atlassian.net" }));
    expect(JSON.stringify(s)).not.toContain("supersecret");
  });
});

describe("jira.inject", () => {
  it("sets HTTP Basic auth from email:apiToken", () => {
    const headers: Record<string, string> = {};
    jira.inject({
      headers,
      method: "GET",
      path: "/rest/api/3/myself",
      host: "eli.atlassian.net",
      credential: cred({ email: "me@x.com", apiToken: "tok" }),
      store: {} as never,
    });
    const expected = "Basic " + Buffer.from("me@x.com:tok").toString("base64");
    expect(headers.authorization).toBe(expected);
  });

  it("throws when a field is missing", () => {
    expect(() =>
      jira.inject({
        headers: {},
        method: "GET",
        path: "/",
        host: "eli.atlassian.net",
        credential: cred({ email: "me@x.com" }),
        store: {} as never,
      }),
    ).toThrow();
  });
});
