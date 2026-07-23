/**
 * Output helpers for the CLI: a global --json mode and a simple aligned table
 * renderer for the default human-readable output.
 */

let jsonMode = false;

export function setJsonMode(on: boolean): void {
  jsonMode = on;
}

export function isJsonMode(): boolean {
  return jsonMode;
}

/**
 * Emits a result. In --json mode the value is printed as pretty JSON and the
 * human lines are skipped. Otherwise `human` is called to print friendly text.
 */
export function emit(value: unknown, human: () => void): void {
  if (jsonMode) {
    console.log(JSON.stringify(value, null, 2));
    return;
  }
  human();
}

/** Renders rows as an aligned text table. `columns` are [header, key] pairs. */
export function table(
  rows: Array<Record<string, unknown>>,
  columns: Array<[string, string]>,
): string {
  const headers = columns.map(([h]) => h);
  const body = rows.map((r) => columns.map(([, k]) => cell(r[k])));
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...body.map((r) => r[i].length), 0),
  );
  const line = (cells: string[]) =>
    cells.map((c, i) => c.padEnd(widths[i])).join("  ").trimEnd();
  return [line(headers), ...body.map(line)].join("\n");
}

function cell(v: unknown): string {
  if (v === null || v === undefined) return "-";
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (Array.isArray(v)) return v.join(",");
  return String(v);
}
