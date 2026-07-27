/**
 * Certificate authority for OneGate.
 *
 * At install time (`onegate init`) we generate a root CA. The operator trusts
 * this CA on every machine/agent that will use the gateway. At runtime the
 * proxy asks for a leaf certificate per intercepted host; leaves are minted
 * on demand, signed by the root, and cached in memory and on disk.
 */

import forge from "node-forge";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  chmodSync,
  readdirSync,
  statSync,
  rmSync,
} from "node:fs";
import { join } from "node:path";

const ROOT_DAYS = 3650;
const LEAF_DAYS = 365;
const ROOT_BITS = 2048;
const LEAF_BITS = 2048;

/**
 * Maximum number of distinct hosts kept as minted leaves, in memory and on disk.
 *
 * Leaves are minted on demand per CONNECT host, and an integration may claim a
 * whole domain suffix (`.googleapis.com`), which `resolveHostCandidates` matches
 * for any subdomain. So the set of hosts an authorized agent can steer the proxy
 * into minting for is unbounded: `a1.googleapis.com`, `a2.googleapis.com`, ... .
 * Each distinct host costs an RSA-2048 keygen, a permanent Map entry and two
 * files, so without a cap one agent can exhaust memory and disk. The default is
 * far above any realistic working set (a deployment talks to tens of hosts), so
 * normal workloads never evict.
 */
export const DEFAULT_LEAF_CACHE_MAX = 512;

/** Resolves the leaf cache cap, letting operators tune it per deployment. */
export function leafCacheMax(): number {
  const raw = process.env.ONEGATE_LEAF_CACHE_MAX?.trim();
  if (!raw) return DEFAULT_LEAF_CACHE_MAX;
  const n = Number(raw);
  // Reject non-numeric, non-integer, zero and negative values rather than
  // treating them as "no limit": a misconfigured env var must never silently
  // reopen the unbounded-growth DoS this cap exists to close.
  if (!Number.isInteger(n) || n < 1) return DEFAULT_LEAF_CACHE_MAX;
  return n;
}

export interface LeafCert {
  /** PEM-encoded certificate. */
  cert: string;
  /** PEM-encoded private key. */
  key: string;
}

/**
 * Derives a filesystem-safe, path-traversal-proof key from a host used as both
 * the in-memory cache key and the on-disk leaf filename. Lowercasing collapses
 * case variants (so `API.GitHub.com` and `api.github.com` share one leaf, not
 * two, avoiding redundant keygen and disk bloat), and replacing every character
 * outside `[a-z0-9._-]` neutralizes `/`, `\`, `..`, and any other separator so
 * `join(certsDir, ...)` can never escape certsDir. The upstream CONNECT-host
 * guard already rejects malformed hosts; this is defense in depth so a leaf
 * path is safe regardless of caller.
 */
export function hostCacheKey(host: string): string {
  return host
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, "_")
    // Collapse any run of dots so no `..` traversal token survives in the
    // filename even after separators are neutralized.
    .replace(/\.{2,}/g, ".")
    // A key that is only dots (e.g. from a "." or ".." host) would name the
    // current/parent directory; fall back to a fixed safe token.
    .replace(/^\.+$/, "_");
}

function randomSerial(): string {
  // Positive, 16-byte serial. First hex digit forced < 8 so the integer is positive.
  const bytes = forge.util.bytesToHex(forge.random.getBytesSync(16));
  return "0" + bytes.slice(1);
}

function makeRootCa(commonName: string): LeafCert {
  const keys = forge.pki.rsa.generateKeyPair(ROOT_BITS);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = randomSerial();
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + ROOT_DAYS * 86_400_000);

  const attrs = [
    { name: "commonName", value: commonName },
    { name: "organizationName", value: "OneGate" },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs); // self-signed
  cert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
    { name: "subjectKeyIdentifier" },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    cert: forge.pki.certificateToPem(cert),
    key: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

export class Ca {
  private rootCert: forge.pki.Certificate;
  private rootKey: forge.pki.PrivateKey;
  readonly rootPem: string;
  /**
   * LRU of minted leaves keyed by `hostCacheKey(host)`. A `Map` iterates in
   * insertion order, so re-inserting on every hit makes the first key the
   * least-recently-used one and eviction is a single `keys().next()`.
   */
  private cache = new Map<string, LeafCert>();
  private certsDir: string;
  /** Hard cap on distinct cached hosts, in memory and on disk. */
  private readonly maxEntries: number;

  constructor(rootCertPem: string, rootKeyPem: string, certsDir: string) {
    this.rootPem = rootCertPem;
    this.rootCert = forge.pki.certificateFromPem(rootCertPem);
    this.rootKey = forge.pki.privateKeyFromPem(rootKeyPem);
    this.certsDir = certsDir;
    this.maxEntries = leafCacheMax();
    mkdirSync(certsDir, { recursive: true });
  }

  /** Number of leaves currently held in memory. Exposed for tests/diagnostics. */
  get cacheSize(): number {
    return this.cache.size;
  }

  /** The effective cap for this instance. Exposed for tests/diagnostics. */
  get cacheLimit(): number {
    return this.maxEntries;
  }

  /** Marks `key` as most-recently-used without changing its value. */
  private touch(key: string, leaf: LeafCert): void {
    this.cache.delete(key);
    this.cache.set(key, leaf);
  }

  /**
   * Inserts `key` as most-recently-used, then evicts the least-recently-used
   * entries until the cache is back within its cap. Each in-memory eviction
   * removes the matching pair from `certsDir` too, so the on-disk cert
   * directory is bounded in step with memory rather than growing forever.
   */
  private store(key: string, leaf: LeafCert): void {
    this.touch(key, leaf);
    while (this.cache.size > this.maxEntries) {
      const oldest = this.cache.keys().next();
      if (oldest.done) break;
      this.cache.delete(oldest.value);
      this.removeFromDisk(oldest.value);
    }
  }

  /**
   * Deletes the on-disk pair for an evicted key. Best-effort: a leaf is
   * regenerable, so a failure here (read-only dir, concurrent removal) must
   * never break the request that triggered the eviction.
   */
  private removeFromDisk(key: string): void {
    for (const suffix of [".crt", ".key"]) {
      try {
        rmSync(join(this.certsDir, `${key}${suffix}`), { force: true });
      } catch {
        // ignore
      }
    }
  }

  /**
   * Drops the oldest on-disk leaves until at most `maxEntries` pairs remain.
   *
   * Eviction driven by the in-memory LRU alone cannot bound the directory
   * across restarts: a fresh process starts with an empty Map but inherits
   * every leaf a previous process wrote, so an attacker could grow the
   * directory without limit one restart at a time. This runs once per mint,
   * treating the directory itself as the source of truth. Ordering is by
   * mtime (oldest first), which for leaves matches least-recently-minted.
   */
  private pruneDisk(keepKey: string): void {
    let names: string[];
    try {
      names = readdirSync(this.certsDir);
    } catch {
      return;
    }
    // One entry per leaf: count by cert, the key file follows it.
    const keys = names.filter((n) => n.endsWith(".crt")).map((n) => n.slice(0, -4));
    if (keys.length <= this.maxEntries) return;

    const withTime = keys.map((key) => {
      let mtime = 0;
      try {
        mtime = statSync(join(this.certsDir, `${key}.crt`)).mtimeMs;
      } catch {
        // Unreadable entries sort oldest so they are cleaned up first.
      }
      return { key, mtime };
    });
    withTime.sort((a, b) => a.mtime - b.mtime);

    let excess = keys.length - this.maxEntries;
    for (const { key } of withTime) {
      if (excess <= 0) break;
      // Never evict the leaf we just minted for the in-flight request, nor one
      // still held in memory (that would desync disk from the LRU).
      if (key === keepKey || this.cache.has(key)) continue;
      this.removeFromDisk(key);
      excess--;
    }
  }

  /**
   * Returns a leaf certificate for `host`, minting and caching it if needed.
   * The cert covers both `host` and `*.host` so e.g. one cert serves
   * `googleapis.com` subdomain lookups when the proxy normalizes hosts.
   */
  leafFor(host: string): LeafCert {
    // Normalize + sanitize the host before it touches any Map key or disk path.
    // `key` is lowercased so case variants share one leaf; the filesystem name
    // additionally strips path separators so a crafted host can never escape
    // certsDir (defense in depth behind the CONNECT-host guard in the proxy).
    const key = hostCacheKey(host);
    const cached = this.cache.get(key);
    if (cached) {
      // A hit makes this the most-recently-used entry, so a hot host is never
      // evicted by a flood of one-shot hosts.
      this.touch(key, cached);
      return cached;
    }

    const diskCert = join(this.certsDir, `${key}.crt`);
    const diskKey = join(this.certsDir, `${key}.key`);
    if (existsSync(diskCert) && existsSync(diskKey)) {
      const fromDisk = this.loadValidLeaf(diskCert, diskKey);
      if (fromDisk) {
        this.store(key, fromDisk);
        return fromDisk;
      }
    }

    // Mint against the lowercased host so the cert Subject/SAN is the canonical
    // hostname (TLS SNI matching is case-insensitive), independent of the
    // sanitized on-disk filename.
    const leaf = this.mintLeaf(host.toLowerCase());
    writeFileSync(diskCert, leaf.cert);
    // Create the private key 0600 in the same syscall as the write: passing the
    // mode later via chmodSync leaves a window where the file exists at
    // umask-default (typically 0644) and any local process can open a handle
    // that stays readable after the chmod. The chmodSync below is belt and
    // braces -- writeFileSync's mode only applies when the file is created, so
    // it does not tighten a pre-existing (e.g. previously 0644) key file.
    writeFileSync(diskKey, leaf.key, { mode: 0o600 });
    chmodSync(diskKey, 0o600);
    this.store(key, leaf);
    // Bound the directory itself, which outlives this process's LRU.
    this.pruneDisk(key);
    return leaf;
  }

  private loadValidLeaf(certPath: string, keyPath: string): LeafCert | null {
    try {
      const certPem = readFileSync(certPath, "utf8");
      const cert = forge.pki.certificateFromPem(certPem);
      // Re-mint when within 7 days of expiry or signed by a different root.
      if (cert.validity.notAfter.getTime() - Date.now() < 7 * 86_400_000) return null;
      if (!this.rootCert.verify(cert)) return null;
      return { cert: certPem, key: readFileSync(keyPath, "utf8") };
    } catch {
      return null;
    }
  }

  private mintLeaf(host: string): LeafCert {
    const keys = forge.pki.rsa.generateKeyPair(LEAF_BITS);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = randomSerial();
    cert.validity.notBefore = new Date(Date.now() - 60_000);
    cert.validity.notAfter = new Date(Date.now() + LEAF_DAYS * 86_400_000);

    cert.setSubject([{ name: "commonName", value: host }]);
    cert.setIssuer(this.rootCert.subject.attributes);
    cert.setExtensions([
      { name: "basicConstraints", cA: false, critical: true },
      {
        name: "keyUsage",
        digitalSignature: true,
        keyEncipherment: true,
        critical: true,
      },
      { name: "extKeyUsage", serverAuth: true },
      {
        name: "subjectAltName",
        altNames: [
          { type: 2, value: host }, // dNSName
          { type: 2, value: `*.${host}` },
        ],
      },
      { name: "subjectKeyIdentifier" },
      // Authority Key Identifier tying the leaf to the root's Subject Key
      // Identifier. OpenSSL 3.x (e.g. Python 3.13 / httpx clients) strict-
      // rejects a leaf that lacks an AKI when its issuer carries an SKI with
      // "missing Authority Key Identifier"; curl and Node are lenient. Without
      // this, any OpenSSL-3-strict agent behind the proxy fails TLS verification.
      {
        name: "authorityKeyIdentifier",
        keyIdentifier: this.rootCert.generateSubjectKeyIdentifier().getBytes(),
        authorityCertIssuer: true,
        serialNumber: this.rootCert.serialNumber,
      },
    ]);
    cert.sign(this.rootKey as forge.pki.rsa.PrivateKey, forge.md.sha256.create());

    return {
      cert: forge.pki.certificateToPem(cert),
      key: forge.pki.privateKeyToPem(keys.privateKey),
    };
  }
}

export interface CaPaths {
  certPath: string;
  keyPath: string;
  certsDir: string;
}

/**
 * Resolves the CA cert/key/cache paths for a data dir. The private key path can
 * be overridden with ONEGATE_CA_KEY_FILE (and the cert with ONEGATE_CA_CERT_FILE)
 * so the CA private key can live outside the data dir, keeping it out of the
 * data-dir backup blast radius. The leaf cache stays in the data dir (leaves are
 * regenerable). Defaults preserve the original in-data-dir layout.
 */
export function caPaths(dataDir: string): CaPaths {
  const envCert = process.env.ONEGATE_CA_CERT_FILE?.trim();
  const envKey = process.env.ONEGATE_CA_KEY_FILE?.trim();
  return {
    certPath: envCert || join(dataDir, "rootCA.pem"),
    keyPath: envKey || join(dataDir, "rootCA.key"),
    certsDir: join(dataDir, "certs"),
  };
}

export function caExists(dataDir: string): boolean {
  const p = caPaths(dataDir);
  return existsSync(p.certPath) && existsSync(p.keyPath);
}

/**
 * Generates the root CA for a new installation. Refuses to overwrite an
 * existing CA: replacing it silently would invalidate every trust store
 * that imported the old certificate.
 */
export function initCa(dataDir: string, commonName = "OneGate Root CA"): Ca {
  const p = caPaths(dataDir);
  if (caExists(dataDir)) {
    throw new Error(`Root CA already exists at ${p.certPath}. Delete it explicitly to re-init.`);
  }
  mkdirSync(dataDir, { recursive: true });
  const root = makeRootCa(commonName);
  writeFileSync(p.certPath, root.cert);
  // Same reasoning as leafFor: create the root key 0600 atomically rather than
  // relying on a follow-up chmod. This key signs every MITM leaf, so a reader
  // who wins the race can forge certificates for any intercepted host.
  writeFileSync(p.keyPath, root.key, { mode: 0o600 });
  chmodSync(p.keyPath, 0o600);
  return new Ca(root.cert, root.key, p.certsDir);
}

export function loadCa(dataDir: string): Ca {
  const p = caPaths(dataDir);
  if (!caExists(dataDir)) {
    throw new Error(`No root CA found in ${dataDir}. Run \`onegate init\` first.`);
  }
  return new Ca(readFileSync(p.certPath, "utf8"), readFileSync(p.keyPath, "utf8"), p.certsDir);
}
