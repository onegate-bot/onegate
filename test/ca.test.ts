import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync, existsSync, statSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import forge from "node-forge";
import { initCa, loadCa, caExists, caPaths, Ca, hostCacheKey } from "../src/ca.js";
import { readdirSync } from "node:fs";

let dir: string;
let ca: Ca;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "onegate-ca-"));
  ca = initCa(dir, "OneGate Test CA");
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("initCa", () => {
  it("creates root cert and key on disk", () => {
    const p = caPaths(dir);
    expect(existsSync(p.certPath)).toBe(true);
    expect(existsSync(p.keyPath)).toBe(true);
    expect(caExists(dir)).toBe(true);
  });

  it("key file is owner-only", () => {
    const mode = statSync(caPaths(dir).keyPath).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("root cert is a CA with the requested CN", () => {
    const cert = forge.pki.certificateFromPem(ca.rootPem);
    expect(cert.subject.getField("CN").value).toBe("OneGate Test CA");
    const bc = cert.getExtension("basicConstraints") as { cA: boolean };
    expect(bc.cA).toBe(true);
  });

  it("refuses to overwrite an existing CA", () => {
    expect(() => initCa(dir)).toThrow(/already exists/);
  });
});

describe("leafFor", () => {
  it("mints a leaf signed by the root, with host + wildcard SANs", () => {
    const leaf = ca.leafFor("api.github.com");
    const cert = forge.pki.certificateFromPem(leaf.cert);
    const root = forge.pki.certificateFromPem(ca.rootPem);
    expect(root.verify(cert)).toBe(true);
    expect(cert.subject.getField("CN").value).toBe("api.github.com");
    const san = cert.getExtension("subjectAltName") as {
      altNames: Array<{ value: string }>;
    };
    const names = san.altNames.map((a) => a.value);
    expect(names).toContain("api.github.com");
    expect(names).toContain("*.api.github.com");
  });

  it("leaf carries an Authority Key Identifier matching the root's Subject Key Identifier", () => {
    const leaf = ca.leafFor("api.anthropic.com");
    const cert = forge.pki.certificateFromPem(leaf.cert);
    const root = forge.pki.certificateFromPem(ca.rootPem);
    const aki = cert.getExtension("authorityKeyIdentifier") as
      | { value: string }
      | undefined;
    expect(aki).toBeDefined();
    // The root's SKI bytes must appear inside the leaf's AKI extension value,
    // so OpenSSL 3.x strict verification (Missing Authority Key Identifier) passes.
    const rootSki = root.generateSubjectKeyIdentifier().getBytes();
    expect(aki!.value.includes(rootSki)).toBe(true);
  });

  it("caches: same host returns identical cert", () => {
    const a = ca.leafFor("gmail.googleapis.com");
    const b = ca.leafFor("gmail.googleapis.com");
    expect(a.cert).toBe(b.cert);
  });

  it("persists leaves: a reloaded Ca reuses the disk cert", () => {
    const first = ca.leafFor("www.googleapis.com");
    const reloaded = loadCa(dir);
    const second = reloaded.leafFor("www.googleapis.com");
    expect(second.cert).toBe(first.cert);
  });

  it("leaf is accepted by node:tls when the root is trusted", async () => {
    const leaf = ca.leafFor("localhost");
    const server = tls.createServer({ cert: leaf.cert, key: leaf.key }, (sock) => {
      sock.end("ok");
    });
    await new Promise<void>((res) => server.listen(0, "127.0.0.1", res));
    const port = (server.address() as { port: number }).port;

    const verified = await new Promise<boolean>((resolve) => {
      const sock = tls.connect(
        { host: "127.0.0.1", port, servername: "localhost", ca: ca.rootPem },
        () => {
          resolve(sock.authorized);
          sock.end();
        },
      );
      sock.on("error", () => resolve(false));
    });
    server.close();
    expect(verified).toBe(true);
  });
});

describe("leafFor host sanitization (path traversal + cache)", () => {
  it("hostCacheKey neutralizes path separators and traversal sequences", () => {
    const key = hostCacheKey("../../../tmp/evil.amazonaws.com");
    expect(key).not.toContain("/");
    expect(key).not.toContain("..");
    expect(key).toMatch(/^[a-z0-9._-]+$/);
  });

  it("a traversal host writes only inside certsDir, never escaping it", () => {
    const traversalDir = mkdtempSync(join(tmpdir(), "onegate-trav-"));
    try {
      const localCa = initCa(traversalDir, "Traversal CA");
      const certsDir = caPaths(traversalDir).certsDir;
      // Snapshot files elsewhere in the data dir before the crafted mint.
      const beforeDataDir = readdirSync(traversalDir).sort();
      localCa.leafFor("../../../tmp/evil.amazonaws.com");
      // No new files leaked into the data dir (parent of certsDir) or above.
      const afterDataDir = readdirSync(traversalDir).sort();
      expect(afterDataDir).toEqual(beforeDataDir);
      // Every file the mint created lives inside certsDir with a safe name.
      const written = readdirSync(certsDir);
      expect(written.length).toBeGreaterThan(0);
      for (const name of written) {
        expect(name).not.toContain("/");
        expect(name).not.toContain("..");
        expect(name).toMatch(/^[a-z0-9._-]+\.(crt|key)$/);
      }
    } finally {
      rmSync(traversalDir, { recursive: true, force: true });
    }
  });

  it("case-insensitive host returns the same cached leaf (one keygen)", () => {
    const a = ca.leafFor("API.Example.Com");
    const b = ca.leafFor("api.example.com");
    expect(a.cert).toBe(b.cert);
    expect(a.key).toBe(b.key);
    // Only one on-disk leaf pair for the collapsed key.
    const certsDir = caPaths(dir).certsDir;
    const files = readdirSync(certsDir).filter((f) => f.startsWith("api.example.com"));
    expect(files.sort()).toEqual(["api.example.com.crt", "api.example.com.key"]);
  });

  it("a normal host still mints a valid leaf signed by the root", () => {
    const leaf = ca.leafFor("normal.example.org");
    const cert = forge.pki.certificateFromPem(leaf.cert);
    const root = forge.pki.certificateFromPem(ca.rootPem);
    expect(root.verify(cert)).toBe(true);
    expect(cert.subject.getField("CN").value).toBe("normal.example.org");
  });
});

describe("loadCa", () => {
  it("throws a helpful error when no CA exists", () => {
    expect(() => loadCa(join(tmpdir(), "onegate-nonexistent"))).toThrow(/onegate init/);
  });
});

describe("CA key path override (ONEGATE_CA_KEY_FILE)", () => {
  const saved = {
    key: process.env.ONEGATE_CA_KEY_FILE,
    cert: process.env.ONEGATE_CA_CERT_FILE,
  };
  afterAll(() => {
    if (saved.key === undefined) delete process.env.ONEGATE_CA_KEY_FILE;
    else process.env.ONEGATE_CA_KEY_FILE = saved.key;
    if (saved.cert === undefined) delete process.env.ONEGATE_CA_CERT_FILE;
    else process.env.ONEGATE_CA_CERT_FILE = saved.cert;
  });

  it("caPaths honors the env overrides, cache dir stays in the data dir", () => {
    process.env.ONEGATE_CA_KEY_FILE = "/etc/onegate/rootCA.key";
    process.env.ONEGATE_CA_CERT_FILE = "/etc/onegate/rootCA.pem";
    const p = caPaths("/var/lib/onegate");
    expect(p.keyPath).toBe("/etc/onegate/rootCA.key");
    expect(p.certPath).toBe("/etc/onegate/rootCA.pem");
    expect(p.certsDir).toBe(join("/var/lib/onegate", "certs"));
    delete process.env.ONEGATE_CA_KEY_FILE;
    delete process.env.ONEGATE_CA_CERT_FILE;
    // Cleared env falls back to the in-data-dir defaults.
    const d = caPaths("/var/lib/onegate");
    expect(d.keyPath).toBe(join("/var/lib/onegate", "rootCA.key"));
  });

  it("loadCa works with the private key relocated outside the data dir", () => {
    const dataDir = mkdtempSync(join(tmpdir(), "onegate-relo-"));
    const keyDir = mkdtempSync(join(tmpdir(), "onegate-key-"));
    try {
      const made = initCa(dataDir, "Relocate CA");
      // Move the private key out of the data dir, point env at the new home.
      const src = join(dataDir, "rootCA.key");
      const dst = join(keyDir, "rootCA.key");
      renameSync(src, dst);
      process.env.ONEGATE_CA_KEY_FILE = dst;
      expect(existsSync(join(dataDir, "rootCA.key"))).toBe(false);
      expect(caExists(dataDir)).toBe(true);
      const loaded = loadCa(dataDir);
      // The relocated CA still mints leaves the original root verifies.
      const leaf = loaded.leafFor("api.anthropic.com");
      const cert = forge.pki.certificateFromPem(leaf.cert);
      const root = forge.pki.certificateFromPem(made.rootPem);
      expect(root.verify(cert)).toBe(true);
    } finally {
      delete process.env.ONEGATE_CA_KEY_FILE;
      rmSync(dataDir, { recursive: true, force: true });
      rmSync(keyDir, { recursive: true, force: true });
    }
  });
});
