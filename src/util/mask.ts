/**
 * Helpers for surfacing a NON-secret preview of a stored credential so an
 * operator can recognise which key is stored without ever exposing it. The
 * full secret must never leave the server. Only a short masked preview built
 * here is ever returned by the API or rendered in the UI.
 */

/**
 * Builds a masked preview of a secret.
 *
 * Rules:
 *  - Empty or whitespace-only input returns null (the UI shows nothing).
 *  - The head (first up to 12 chars) and tail (last 4 chars) are only shown
 *    together when there is a genuinely hidden middle, i.e. the secret is long
 *    enough (> 16 chars) that the head and tail do not overlap and at least
 *    one character stays concealed. Result, e.g. "sk-ant-api03-...4GwA".
 *  - For shorter secrets (<= 16 chars), only the last 4 characters are shown,
 *    prefixed with an ellipsis, e.g. "...4GwA". The leading part is never
 *    revealed, so a short secret is never fully exposed.
 *
 * The preview never contains more than the first 12 plus the last 4
 * characters of the original secret, and a short secret never appears in full.
 */
export function maskSecret(secret: string): string | null {
  if (typeof secret !== "string") return null;
  const trimmed = secret.trim();
  if (trimmed === "") return null;
  const last4 = trimmed.slice(-4);
  // Only reveal a head when 12 (head) + 4 (tail) leaves a hidden middle,
  // otherwise the head+tail would cover (and thus expose) the whole secret.
  if (trimmed.length <= 16) {
    return `...${last4}`;
  }
  const head = trimmed.slice(0, 12);
  return `${head}...${last4}`;
}

/**
 * Picks the primary secret value out of a connection/credential `data` bag and
 * returns its masked preview, or null when there is no usable secret.
 *
 * Selection order:
 *  1. A preferred key from `preferredKeys` (in order) that holds a non-empty
 *     string. This lets the caller point at the vendor's main secret (e.g.
 *     anthropic apiKey/authToken, openai apiKey/accessToken).
 *  2. The first key listed in `secretKeys` (the integration's secret-typed
 *     credential fields) that holds a non-empty string.
 *  3. As a last resort, the first non-empty string value in `data`.
 *
 * Robust by design: any missing/empty material yields null.
 */
export function previewPrimarySecret(
  data: Record<string, string> | undefined | null,
  opts: { preferredKeys?: string[]; secretKeys?: string[] } = {},
): string | null {
  if (!data || typeof data !== "object") return null;
  const nonEmpty = (key: string): string | null => {
    const v = data[key];
    return typeof v === "string" && v.trim() !== "" ? v : null;
  };

  for (const key of opts.preferredKeys ?? []) {
    const v = nonEmpty(key);
    if (v !== null) return maskSecret(v);
  }
  for (const key of opts.secretKeys ?? []) {
    const v = nonEmpty(key);
    if (v !== null) return maskSecret(v);
  }
  for (const v of Object.values(data)) {
    if (typeof v === "string" && v.trim() !== "") return maskSecret(v);
  }
  return null;
}

/**
 * Per-vendor preferred secret keys for LLM connections, used so the preview
 * targets the actual auth secret rather than a non-secret companion field.
 */
export function llmPreferredSecretKeys(vendor: string): string[] {
  switch (vendor) {
    case "anthropic":
      return ["authToken", "apiKey"];
    case "openai":
      return ["apiKey", "accessToken"];
    case "gemini":
      return ["apiKey"];
    case "openrouter":
      return ["apiKey"];
    default:
      return ["apiKey", "token", "accessToken", "authToken"];
  }
}
