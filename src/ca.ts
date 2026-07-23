/**
 * Certificate authority for OneGate.
 *
 * At install time (`onegate init`) we generate a root CA. The operator trusts
 * this CA on every machine/agent that will use the gateway. At runtime the
 * proxy asks for a leaf certificate per intercepted host; leaves are minted
 * on demand, signed by the root, and cached in memory and on disk.
 */

import forge from "node-forge";
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";

const ROOT_DAYS = 3650;
const LEAF_DAYS = 365;
const ROOT_BITS = 2048;
const LEAF_BITS = 2048;

export interface LeafCert {
  /** PEM-encoded certificate. */
  cert: string;
  /** PEM-encoded private key. */
  key: string;
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
  private cache = new Map<string, LeafCert>();
  private certsDir: string;

  constructor(rootCertPem: string, rootKeyPem: string, certsDir: string) {
    this.rootPem = rootCertPem;
    this.rootCert = forge.pki.certificateFromPem(rootCertPem);
    this.rootKey = forge.pki.privateKeyFromPem(rootKeyPem);
    this.certsDir = certsDir;
    mkdirSync(certsDir, { recursive: true });
  }

  /**
   * Returns a leaf certificate for `host`, minting and caching it if needed.
   * The cert covers both `host` and `*.host` so e.g. one cert serves
   * `googleapis.com` subdomain lookups when the proxy normalizes hosts.
   */
  leafFor(host: string): LeafCert {
    const cached = this.cache.get(host);
    if (cached) return cached;

    const diskCert = join(this.certsDir, `${host}.crt`);
    const diskKey = join(this.certsDir, `${host}.key`);
    if (existsSync(diskCert) && existsSync(diskKey)) {
      const fromDisk = this.loadValidLeaf(diskCert, diskKey);
      if (fromDisk) {
        this.cache.set(host, fromDisk);
        return fromDisk;
      }
    }

    const leaf = this.mintLeaf(host);
    writeFileSync(diskCert, leaf.cert);
    writeFileSync(diskKey, leaf.key);
    chmodSync(diskKey, 0o600);
    this.cache.set(host, leaf);
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
  writeFileSync(p.keyPath, root.key);
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
