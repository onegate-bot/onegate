/**
 * The public base URL owner-facing links are built on: approve, connect and
 * renew links, plus the OAuth redirect URI.
 *
 * Those links carry one-time tokens, so they must point at THIS gateway. When
 * `ONEGATE_PUBLIC_URL` is unset the base falls back to the admin listener's own
 * address (which only works from the gateway's network), never to a hosted
 * domain the operator does not control.
 */

/** Hosts that mean "every interface" and are not reachable as a link target. */
const WILDCARD_BINDS = new Set(["", "0.0.0.0", "::", "[::]"]);

export interface PublicBaseUrl {
  /** Absolute http(s) URL with no trailing slash. */
  url: string;
  /** True when ONEGATE_PUBLIC_URL was unset and the admin listener was used. */
  fallback: boolean;
}

/**
 * Validates an explicit public URL: absolute, http or https, no query or
 * fragment (links are built by appending paths). Returns it without trailing
 * slashes. A path prefix is kept, for a gateway served under a reverse-proxy
 * subpath. Throws on anything else.
 */
export function parsePublicUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new Error(`ONEGATE_PUBLIC_URL must be an absolute http(s) URL, got "${raw}"`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(`ONEGATE_PUBLIC_URL must use http or https, got "${raw}"`);
  }
  if (u.search || u.hash) {
    throw new Error(`ONEGATE_PUBLIC_URL must not carry a query or fragment, got "${raw}"`);
  }
  return `${u.origin}${u.pathname}`.replace(/\/+$/, "");
}

/**
 * Resolves the public base URL. `publicUrl` wins when set (validated, throws
 * when malformed). Otherwise the admin listener: `http://<bind>:<adminPort>`,
 * with `localhost` standing in for an unset or wildcard bind address.
 */
export function resolvePublicBaseUrl(opts: {
  publicUrl?: string;
  bind?: string;
  adminPort?: number;
}): PublicBaseUrl {
  if (opts.publicUrl && opts.publicUrl.trim()) {
    return { url: parsePublicUrl(opts.publicUrl), fallback: false };
  }
  const bind = (opts.bind ?? "").trim();
  let host = WILDCARD_BINDS.has(bind) ? "localhost" : bind;
  // A bare IPv6 literal needs brackets in a URL.
  if (host.includes(":") && !host.startsWith("[")) host = `[${host}]`;
  return { url: `http://${host}:${opts.adminPort ?? 8080}`, fallback: true };
}

/**
 * The same resolution read straight from the environment
 * (`ONEGATE_PUBLIC_URL`, `ONEGATE_BIND`, `ONEGATE_ADMIN_PORT`). Used when an
 * embedder or test builds the proxy or admin app without passing a resolved
 * base; `onegate start` resolves once at startup and passes it in.
 */
export function publicBaseUrlFromEnv(env: NodeJS.ProcessEnv = process.env): PublicBaseUrl {
  const port = Number(env.ONEGATE_ADMIN_PORT);
  return resolvePublicBaseUrl({
    publicUrl: env.ONEGATE_PUBLIC_URL,
    bind: env.ONEGATE_BIND,
    adminPort: Number.isFinite(port) && port > 0 ? port : 8080,
  });
}
