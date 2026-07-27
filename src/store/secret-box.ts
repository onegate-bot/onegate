/**
 * Envelope encryption for secret-bearing columns at rest (credential and
 * connection `data` blobs: API keys, tokens, OAuth refresh tokens).
 *
 * AES-256-GCM. The key lives OUTSIDE the database: either ONEGATE_DB_KEY in
 * the environment (base64 or hex, 32 bytes) or an auto-generated key file in
 * the data directory (0600, in a 0700 dir). That way a leaked DB file, a
 * backup, or a partial read does not expose plaintext secrets. It does not
 * defend against a full host compromise while the key sits on the same box:
 * for that, set ONEGATE_DB_KEY from a secret manager and keep it off disk.
 *
 * Reads are backward compatible: a value written before encryption existed is
 * plain JSON and is parsed as-is. Sealed values carry a marker prefix.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const MARKER = "enc.v1:";
const ALGO = "aes-256-gcm";
const IV_LEN = 12;
const TAG_LEN = 16;

export class SecretBox {
  private readonly key: Buffer;

  constructor(key: Buffer) {
    if (key.length !== 32) throw new Error("SecretBox key must be 32 bytes");
    this.key = key;
  }

  /** True when a stored string is an encrypted envelope (vs legacy plaintext). */
  isSealed(stored: string): boolean {
    return stored.startsWith(MARKER);
  }

  seal(value: unknown): string {
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv(ALGO, this.key, iv);
    const pt = Buffer.from(JSON.stringify(value), "utf8");
    const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
    const tag = cipher.getAuthTag();
    return MARKER + Buffer.concat([iv, tag, ct]).toString("base64");
  }

  open<T = unknown>(stored: string): T {
    if (!this.isSealed(stored)) {
      // Legacy plaintext JSON, written before encryption was introduced.
      return JSON.parse(stored) as T;
    }
    const raw = Buffer.from(stored.slice(MARKER.length), "base64");
    const iv = raw.subarray(0, IV_LEN);
    const tag = raw.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const ct = raw.subarray(IV_LEN + TAG_LEN);
    const decipher = createDecipheriv(ALGO, this.key, iv);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return JSON.parse(pt.toString("utf8")) as T;
  }
}

function decodeKey(raw: string): Buffer {
  const s = raw.trim();
  // 64 hex chars => 32 bytes. Otherwise treat as base64.
  if (/^[0-9a-fA-F]{64}$/.test(s)) return Buffer.from(s, "hex");
  return Buffer.from(s, "base64");
}

/**
 * Resolves the encryption key for a database path. Order: ONEGATE_DB_KEY env,
 * then a persisted key file next to the DB, else a freshly generated key
 * written there (0600). In-memory DBs get an ephemeral per-process key.
 */
export function loadSecretKey(dbPath: string): Buffer {
  const env = process.env.ONEGATE_DB_KEY;
  if (env && env.trim()) {
    const buf = decodeKey(env);
    if (buf.length !== 32) {
      throw new Error("ONEGATE_DB_KEY must decode to 32 bytes (64 hex chars or base64)");
    }
    return buf;
  }
  if (dbPath === ":memory:") return randomBytes(32);

  const dir = dirname(dbPath);
  const keyPath = join(dir, "db-secret.key");
  if (existsSync(keyPath)) return readKeyFile(keyPath);

  const key = randomBytes(32);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // `wx` (O_CREAT|O_EXCL) is load-bearing, do NOT relax it to a plain write.
  // The proxy server and the CLI are separate processes that each build their
  // own Store against the same data dir, so on an empty data dir (first boot,
  // or after the key file is lost) they can both fall through the existsSync
  // check above. Without O_EXCL each would generate a DIFFERENT key, seal rows
  // with its own in-memory key, and the last writeFileSync would silently
  // overwrite the other's key file. Rows sealed under the losing key then fail
  // AES-GCM auth forever: permanent, silent credential loss with no error at
  // write time. With `wx` exactly one generated key can ever reach disk, and
  // the EEXIST loser re-reads the winner's file so both processes converge on
  // the same key. The re-read goes through readKeyFile, which validates length
  // and throws on a corrupt file rather than generating yet another key --
  // that fallback is the very hazard this branch exists to remove.
  try {
    writeFileSync(keyPath, key.toString("base64"), { mode: 0o600, flag: "wx" });
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code !== "EEXIST") throw err;
    return readKeyFile(keyPath);
  }
  chmodSync(keyPath, 0o600);
  return key;
}

/** Reads and validates a persisted key file. Throws if it is not a 32-byte key. */
function readKeyFile(keyPath: string): Buffer {
  const buf = decodeKey(readFileSync(keyPath, "utf8"));
  if (buf.length !== 32) throw new Error(`${keyPath} is corrupt (expected a 32-byte key)`);
  return buf;
}
