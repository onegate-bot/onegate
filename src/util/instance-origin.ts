/**
 * Validation for owner-supplied instance origins.
 *
 * An integration may declare `supportsInstanceOrigin`, letting a connection
 * carry the origin of a self-managed deployment (self-hosted GitLab, Jira Data
 * Center, n8n, Grafana, Airbyte, ...). Host resolution then treats that origin's
 * host as belonging to the integration, so OneGate will MITM-terminate it and
 * inject that connection's credential.
 *
 * That makes this function security-critical: it decides which extra hosts
 * OneGate is willing to proxy and inject secrets into. An unvalidated origin is
 * a server-side request forgery primitive (the proxy runs inside the operator's
 * network and would happily terminate TLS for 169.254.169.254 and hand it a
 * credential). Every guard below exists to keep an owner from pointing OneGate
 * at infrastructure that is not theirs to reach.
 *
 * Guards, in order:
 *  - https scheme only (http and every other scheme rejected).
 *  - no userinfo, path, query or fragment: an origin is scheme + host [+ port].
 *  - no default-port redundancy and no non-443 port (see PORT POLICY below).
 *  - no bare IP literal, v4 or v6, in any notation. Only DNS names are accepted
 *    (see IP LITERAL POLICY below).
 *  - the resolved host must not be a loopback, link-local, private, or
 *    otherwise internal name.
 *
 * PORT POLICY: only the implicit https port (443) is accepted, and it must not
 * be written out. A non-default port is rejected. The proxy's CONNECT handler
 * only MITM-terminates port 443 (any other port takes the passthrough path and
 * is never credential-injected), so accepting a port here would store an origin
 * that silently never receives its credential. Rejecting it keeps the stored
 * data honest about what OneGate can actually do. Supporting alternate ports
 * means teaching the CONNECT path to terminate them, which is deliberately out
 * of scope for this change.
 *
 * IP LITERAL POLICY: bare IP literals are rejected outright, including public
 * ones. Three reasons: an IP literal cannot be covered by a publicly trusted
 * TLS certificate in the general case, the private/loopback/link-local blocklist
 * below is only meaningful against literals (a DNS name can still resolve into
 * those ranges, see the DNS REBINDING note), and a self-managed enterprise
 * deployment is addressed by a hostname in practice. Requiring a DNS name keeps
 * the accepted surface to things an owner demonstrably controls a name for.
 *
 * DNS REBINDING (documented limitation, deliberately not solved here): these
 * are name-level guards. A hostname the owner controls can still resolve to a
 * private address, and this validator does not resolve DNS. Blocking that
 * needs resolution-time enforcement in the proxy's outbound connect path
 * (resolve, check the resulting address, then pin the connection to it), which
 * is a separate change with its own failure modes. What this validator does
 * guarantee is that an owner cannot name an internal address directly, and (via
 * the caller) cannot claim a host a builtin integration already owns.
 */

/** Literal hostnames that always denote the local machine. */
const LOCAL_HOSTNAMES = new Set(["localhost", "ip6-localhost", "ip6-loopback"]);

/**
 * Hostname suffixes that denote internal-only namespaces. `.localhost` is
 * reserved to loopback by RFC 6761 and `.local` is mDNS.
 */
const LOCAL_SUFFIXES = [".localhost", ".local"];

export interface InstanceOriginError {
  /** Stable machine-readable reason, surfaced as an API error code. */
  code: string;
  /** Operator-facing explanation. Never contains secret material. */
  message: string;
}

/**
 * Normalises and validates an owner-supplied instance origin.
 *
 * Returns the canonical origin string (lowercased scheme and host, no trailing
 * slash, no port) or an error describing why it was refused. The canonical form
 * is what callers must persist and compare, so two spellings of one origin can
 * never be stored as two distinct claims.
 */
export function normalizeInstanceOrigin(
  raw: unknown,
): { origin: string; host: string } | { error: InstanceOriginError } {
  if (typeof raw !== "string" || !raw.trim()) {
    return {
      error: { code: "invalid_instance_origin", message: "instanceOrigin must be a non-empty string" },
    };
  }
  const trimmed = raw.trim();

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return {
      error: {
        code: "invalid_instance_origin",
        message: `instanceOrigin must be an absolute https URL, e.g. https://gitlab.example.com (got "${trimmed}")`,
      },
    };
  }

  if (url.protocol !== "https:") {
    return {
      error: {
        code: "instance_origin_not_https",
        message: `instanceOrigin must use https (got "${url.protocol.replace(":", "")}"). OneGate only terminates TLS.`,
      },
    };
  }

  // Credentials in the origin would be stored in a non-secret column and are
  // never a legitimate part of an instance origin.
  if (url.username || url.password) {
    return {
      error: {
        code: "instance_origin_has_userinfo",
        message: "instanceOrigin must not contain a username or password",
      },
    };
  }

  // An origin is scheme + host (+ port). URL normalises a bare origin's
  // pathname to "/", so anything longer is a real path.
  if (url.pathname && url.pathname !== "/") {
    return {
      error: {
        code: "instance_origin_has_path",
        message: `instanceOrigin must not contain a path (got "${url.pathname}"). Supply only the origin, e.g. https://gitlab.example.com`,
      },
    };
  }
  if (url.search) {
    return {
      error: { code: "instance_origin_has_query", message: "instanceOrigin must not contain a query string" },
    };
  }
  if (url.hash) {
    return {
      error: { code: "instance_origin_has_fragment", message: "instanceOrigin must not contain a fragment" },
    };
  }

  // PORT POLICY: reject any explicit port. URL clears `port` when it equals the
  // scheme default, so a non-empty port here is always non-443.
  if (url.port) {
    return {
      error: {
        code: "instance_origin_port_unsupported",
        message: `instanceOrigin must not specify a port (got ":${url.port}"). OneGate only intercepts https on port 443.`,
      },
    };
  }

  const host = url.hostname.toLowerCase();
  const blocked = blockedHostReason(host);
  if (blocked) {
    return { error: { code: "instance_origin_blocked_host", message: blocked } };
  }

  return { origin: `https://${host}`, host };
}

/**
 * Returns a rejection reason when `host` denotes an internal, loopback,
 * link-local or otherwise non-routable target, or null when it is acceptable.
 *
 * `host` must already be lowercased. IPv6 literals arrive from URL.hostname
 * wrapped in square brackets.
 */
function blockedHostReason(host: string): string | null {
  if (!host) return "instanceOrigin must contain a hostname";

  // --- IPv6 literal (URL.hostname keeps the brackets) ---
  if (host.startsWith("[") && host.endsWith("]")) {
    const addr = host.slice(1, -1);
    return `instanceOrigin must be a DNS hostname, not an IP address (got "${addr}"). ${IP_LITERAL_HINT}`;
  }

  // --- IPv4 literal, and the malformed/alternate notations that smuggle one ---
  // Anything made only of digits and dots is an attempted IPv4 literal (this
  // also catches decimal/octal forms like 2130706433 and 0177.0.0.1, which
  // resolve to loopback but are not dotted-quad).
  if (/^[0-9.]+$/.test(host)) {
    return `instanceOrigin must be a DNS hostname, not an IP address (got "${host}"). ${IP_LITERAL_HINT}`;
  }
  // Hex/other numeric forms (0x7f000001) likewise never denote a real DNS name.
  if (/^0x[0-9a-f]+$/.test(host)) {
    return `instanceOrigin must be a DNS hostname, not an IP address (got "${host}"). ${IP_LITERAL_HINT}`;
  }

  // --- Internal names ---
  if (LOCAL_HOSTNAMES.has(host)) {
    return `instanceOrigin must not point at the local machine (got "${host}")`;
  }
  for (const suffix of LOCAL_SUFFIXES) {
    if (host.endsWith(suffix)) {
      return `instanceOrigin must not use the internal "${suffix}" namespace (got "${host}")`;
    }
  }

  // A single-label host (no dot) is not a public DNS name: it is an intranet
  // short name that resolves via search domains, i.e. internal by definition.
  if (!host.includes(".")) {
    return `instanceOrigin must be a fully qualified domain name (got "${host}")`;
  }

  return null;
}

const IP_LITERAL_HINT =
  "OneGate requires a DNS name so the host can present a valid TLS certificate and cannot name an internal address directly.";

/**
 * True when `host` falls in a range that must never be reachable through an
 * owner-supplied origin. Exported for the proxy/tests and for any future
 * resolution-time enforcement, which is the only place a DNS name's actual
 * address can be checked.
 *
 * Covers: loopback 127/8 and ::1, unspecified 0.0.0.0 and ::, link-local
 * 169.254/16 (including the cloud metadata address 169.254.169.254) and fe80::/10,
 * private 10/8, 172.16/12, 192.168/16, carrier-grade NAT 100.64/10, and IPv6
 * unique-local fc00::/7.
 */
export function isBlockedAddress(addr: string): boolean {
  const a = addr.trim().toLowerCase().replace(/^\[|\]$/g, "");

  // ---- IPv6 ----
  if (a.includes(":")) {
    if (a === "::1") return true; // loopback
    if (a === "::") return true; // unspecified
    // Unique-local fc00::/7 -> first byte 0xfc or 0xfd.
    if (/^f[cd][0-9a-f]{0,2}:/.test(a)) return true;
    // Link-local fe80::/10 -> fe80 through febf.
    if (/^fe[89ab][0-9a-f]?:/.test(a)) return true;
    // IPv4-mapped (::ffff:127.0.0.1) delegates to the IPv4 rules.
    const mapped = /^::ffff:([0-9.]+)$/.exec(a);
    if (mapped) return isBlockedAddress(mapped[1]);
    return false;
  }

  // ---- IPv4 ----
  const parts = a.split(".");
  if (parts.length !== 4) return false;
  const octets = parts.map((p) => Number(p));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [o0, o1] = octets;
  if (o0 === 127) return true; // loopback 127/8
  if (o0 === 0) return true; // unspecified / "this network" 0/8
  if (o0 === 10) return true; // private 10/8
  if (o0 === 172 && o1 >= 16 && o1 <= 31) return true; // private 172.16/12
  if (o0 === 192 && o1 === 168) return true; // private 192.168/16
  if (o0 === 169 && o1 === 254) return true; // link-local incl. 169.254.169.254
  if (o0 === 100 && o1 >= 64 && o1 <= 127) return true; // CGNAT 100.64/10
  return false;
}
