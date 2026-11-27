import { describe, it, expect, vi, afterEach } from "vitest";
import { redactTokenBody, TokenEndpointError } from "../src/integrations/oauth.js";

describe("redactTokenBody", () => {
  it("blanks form-encoded token values (GitHub's default token reply)", () => {
    const out = redactTokenBody("access_token=gho_LIVE123&scope=repo&token_type=bearer&refresh_token=ghr_X");
    expect(out).not.toContain("gho_LIVE123");
    expect(out).not.toContain("ghr_X");
    expect(out).toContain("access_token=[redacted]");
    expect(out).toContain("scope=repo");
  });

  it("blanks JSON credential fields, including escaped quotes and truncated values", () => {
    const out = redactTokenBody('{"access_token":"ya29.\\"abc","client_secret":"s3cr3t","error":"invalid_grant","id_token":"eyJhbGciOi');
    expect(out).not.toMatch(/ya29|s3cr3t|eyJhbGciOi/);
    expect(out).toContain('"error":"invalid_grant"');
    expect(out).toContain('"access_token":"[redacted]"');
  });

  it("leaves bodies without credentials untouched", () => {
    const body = '{"error":"invalid_client","error_description":"Client authentication failed"}';
    expect(redactTokenBody(body)).toBe(body);
    expect(redactTokenBody("<html>Bad Gateway</html>")).toBe("<html>Bad Gateway</html>");
  });
});

describe("TokenEndpointError", () => {
  afterEach(() => vi.restoreAllMocks());

  it("never logs or exposes a token echoed in the vendor body", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const err = new TokenEndpointError("token exchange returned a non-JSON response (200)", 200, "access_token=gho_LIVE123&scope=repo");
    expect(err.detail).toBe("access_token=[redacted]&scope=repo");
    expect(warn.mock.calls.flat().join(" ")).not.toContain("gho_LIVE123");
  });
});
