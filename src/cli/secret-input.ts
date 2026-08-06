/**
 * Shared secret-input helpers for the CLI.
 *
 * Secrets passed as command-line arguments leak: they are visible in `ps`, in
 * /proc/<pid>/cmdline to any local user on the box, and they land in shell
 * history. Every command that accepts secret material therefore offers a stdin
 * form (`--<thing>-stdin`) which is the preferred way to supply it:
 *
 *   printf %s "$SECRET" | onegate credentials set stripe --name s --data-stdin apiKey
 *
 * The legacy argv-bearing flags still work for backwards compatibility, but the
 * help text marks them insecure and callers should migrate.
 */

/** Reads stdin to EOF and returns it as a trimmed utf8 string. */
export async function readSecretFromStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8").trim();
}

/**
 * Reads a single secret from stdin, failing with `label` context when stdin is
 * empty. Used by flags that carry exactly one secret value (e.g. an OAuth
 * client secret).
 */
export async function readRequiredSecretFromStdin(label: string): Promise<string> {
  const secret = await readSecretFromStdin();
  if (!secret) throw new Error(`no ${label} on stdin`);
  return secret;
}

/**
 * Reads newline-separated `key=value` pairs from stdin, for the --data-stdin
 * form of the credential/app-connection commands. Blank lines are skipped so a
 * trailing newline in a heredoc is harmless. A bare `key` line is also accepted
 * when `soleKey` is given, letting a caller pipe just the raw secret:
 *
 *   printf %s "$TOKEN" | onegate credentials set stripe --data-stdin apiKey
 */
export async function readDataPairsFromStdin(soleKey?: string): Promise<Record<string, string>> {
  const raw = await readSecretFromStdin();
  if (!raw) throw new Error("no data on stdin");

  // Sole-key form: the whole of stdin is the value for the named key. Only
  // valid when the payload does not itself look like key=value lines.
  if (soleKey && !raw.includes("\n") && !/^[^=\s]+=/.test(raw)) {
    return { [soleKey]: raw };
  }

  const data: Record<string, string> = {};
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 1) throw new Error(`--data-stdin lines must be key=value, got "${trimmed}"`);
    data[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
  }
  if (!Object.keys(data).length) throw new Error("no data on stdin");
  return data;
}

/**
 * Parses argv-supplied `--data k=v` pairs. Kept here next to the stdin reader
 * so both forms produce an identical shape and stay in sync.
 */
export function parseDataPairs(pairs: string[]): Record<string, string> {
  const data: Record<string, string> = {};
  for (const p of pairs) {
    const eq = p.indexOf("=");
    if (eq < 1) throw new Error(`--data must be key=value, got "${p}"`);
    data[p.slice(0, eq)] = p.slice(eq + 1);
  }
  return data;
}

/**
 * Rejects supplying the same secret through both the argv flag and stdin. The
 * two forms are mutually exclusive so there is never an ambiguous precedence.
 */
export function rejectDuplicateSecretInput(
  argvFlag: string,
  stdinFlag: string,
  argvGiven: boolean,
  stdinGiven: boolean,
): void {
  if (argvGiven && stdinGiven) {
    throw new Error(`${argvFlag} and ${stdinFlag} are mutually exclusive. Use ${stdinFlag} (${argvFlag} exposes the secret in ps and shell history).`);
  }
}
