/**
 * Best-effort token usage extraction from LLM vendor responses.
 *
 * The proxy taps the upstream response stream (never altering, delaying or
 * buffering what is forwarded to the agent) and feeds the bytes to a scanner.
 * When the response ends, the scanner yields whatever token counts it could
 * find. Anything unparseable, compressed or oversized simply yields nulls.
 *
 * Detection is shape based rather than vendor based, so it covers:
 * - anthropic JSON:        { usage: { input_tokens, output_tokens } }
 * - anthropic SSE:         message_start carries message.usage.input_tokens,
 *                          message_delta events carry usage.output_tokens
 *                          (cumulative, last one wins)
 * - openai JSON/SSE:       { usage: { prompt_tokens, completion_tokens } }
 *                          (streaming only when the final chunk carries usage,
 *                          i.e. stream_options.include_usage was set)
 * - gemini JSON:           { usageMetadata: { promptTokenCount,
 *                          candidatesTokenCount } }
 */

import type http from "node:http";
import {
  brotliDecompressSync,
  gunzipSync,
  inflateSync,
  inflateRawSync,
} from "node:zlib";

export interface TokenUsage {
  inputTokens: number | null;
  outputTokens: number | null;
}

/**
 * Best-effort extraction of the target model id from an outbound LLM request.
 *
 * Anthropic and OpenAI carry the model in the JSON request body ({ "model": ...
 * }). Gemini names the model in the URL path instead
 * (/v1beta/models/<model>:generateContent), so fall back to the path. Returns
 * null when nothing parseable is found, which the usage rollups render as
 * "(unknown)". Never throws.
 */
export function extractRequestModel(path: string, body: Buffer | undefined): string | null {
  // Body first: Anthropic / OpenAI and any vendor that echoes model in JSON.
  if (body && body.length > 0 && body.length <= USAGE_SCAN_CAP) {
    try {
      const parsed = JSON.parse(body.toString("utf8"));
      if (parsed && typeof parsed === "object") {
        const m = (parsed as Record<string, unknown>).model;
        if (typeof m === "string" && m.trim()) return m.trim();
      }
    } catch {
      /* not JSON, fall through to the path */
    }
  }
  // Gemini path form: /v1beta/models/<model>:generateContent (or :streamGenerateContent).
  const match = /\/models\/([^/:?#]+)/.exec(path);
  if (match) {
    // decodeURIComponent throws URIError on a malformed escape (a `%` not
    // followed by two hex digits). Such paths DO reach here: the canonicalizer
    // preserves malformed escapes as literals rather than rejecting them. This
    // function is documented as never throwing and is called on the hot request
    // path without a try/catch, so fall back to the raw matched segment instead
    // of propagating. Well-formed input decodes exactly as before.
    let decoded: string;
    try {
      decoded = decodeURIComponent(match[1]);
    } catch {
      decoded = match[1];
    }
    const m = decoded.trim();
    if (m) return m;
  }
  return null;
}

/** Hard cap on the DECOMPRESSED bytes any inner scanner sees. Past it, scanning bails silently. */
export const USAGE_SCAN_CAP = 256 * 1024;

/**
 * Hard cap on the RAW (still compressed) bytes the decompressing wrapper will
 * buffer before it gives up. This bounds inspector memory so a huge response
 * cannot OOM the proxy. A compressed body past this cap yields null usage. The
 * decompressed output is separately capped at USAGE_SCAN_CAP, so a small
 * payload that expands enormously is also bounded.
 */
export const USAGE_COMPRESSED_BUFFER_CAP = 4 * 1024 * 1024;

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/**
 * Pulls token counts out of a single parsed JSON value, whatever the vendor.
 * Returns nulls for fields the value does not carry.
 */
export function usageFromObject(obj: unknown): TokenUsage {
  const out: TokenUsage = { inputTokens: null, outputTokens: null };
  if (!obj || typeof obj !== "object") return out;
  const o = obj as Record<string, any>;
  // Anthropic streaming wraps the initial usage inside message_start's message.
  const u = o.usage ?? o.message?.usage;
  if (u && typeof u === "object") {
    const base = num(u.input_tokens) ?? num(u.prompt_tokens);
    // Anthropic prompt caching reports only the freshly-read input in
    // input_tokens and puts the rest of the prompt in separate cache fields.
    // The real input size is the uncached input plus the cache-read and
    // cache-creation tokens, so fold them in when present. Vendors without
    // caching (openai prompt_tokens, gemini) leave these null, so this is a
    // no-op there and never double counts.
    const cacheRead = num(u.cache_read_input_tokens);
    const cacheCreate = num(u.cache_creation_input_tokens);
    if (base !== null || cacheRead !== null || cacheCreate !== null) {
      out.inputTokens = (base ?? 0) + (cacheRead ?? 0) + (cacheCreate ?? 0);
    }
    out.outputTokens = num(u.output_tokens) ?? num(u.completion_tokens);
  }
  const g = o.usageMetadata;
  if (g && typeof g === "object") {
    out.inputTokens = out.inputTokens ?? num(g.promptTokenCount);
    out.outputTokens = out.outputTokens ?? num(g.candidatesTokenCount);
  }
  return out;
}

/** Parses a complete JSON body (string or bytes) into token counts. */
export function usageFromJson(body: string | Buffer): TokenUsage {
  try {
    return usageFromObject(JSON.parse(body.toString("utf8" as BufferEncoding)));
  } catch {
    return { inputTokens: null, outputTokens: null };
  }
}

export interface UsageScanner {
  /** Feed a raw response chunk. Never throws. */
  feed(chunk: Buffer): void;
  /** The tokens found so far (call after the response ended). */
  result(): TokenUsage;
}

/**
 * SSE scanner: processes `data:` lines as they stream by, keeping only the
 * current incomplete line in memory (capped). Later events override earlier
 * ones per field, which matches anthropic's cumulative message_delta usage.
 */
class SseScanner implements UsageScanner {
  private carry = "";
  private skippingOversizedLine = false;
  private found: TokenUsage = { inputTokens: null, outputTokens: null };

  feed(chunk: Buffer): void {
    let text = this.carry + chunk.toString("utf8");
    this.carry = "";
    for (;;) {
      const nl = text.indexOf("\n");
      if (nl === -1) break;
      const line = text.slice(0, nl);
      text = text.slice(nl + 1);
      if (this.skippingOversizedLine) {
        this.skippingOversizedLine = false;
        continue;
      }
      this.handleLine(line);
    }
    if (this.skippingOversizedLine) return;
    if (text.length > USAGE_SCAN_CAP) {
      // A single SSE line larger than the cap: drop it and resume at the
      // next newline so the trailing usage events are still seen.
      this.skippingOversizedLine = true;
      this.carry = "";
    } else {
      this.carry = text;
    }
  }

  private handleLine(rawLine: string): void {
    const line = rawLine.replace(/\r$/, "");
    if (!line.startsWith("data:")) return;
    const payload = line.slice(5).trim();
    if (!payload || payload === "[DONE]") return;
    try {
      const t = usageFromObject(JSON.parse(payload));
      if (t.inputTokens !== null) this.found.inputTokens = t.inputTokens;
      if (t.outputTokens !== null) this.found.outputTokens = t.outputTokens;
    } catch {
      /* not JSON, ignore */
    }
  }

  result(): TokenUsage {
    // A trailing data: line without a final newline still counts.
    if (this.carry && !this.skippingOversizedLine) this.handleLine(this.carry);
    this.carry = "";
    return { ...this.found };
  }
}

/** JSON scanner: accumulates up to the cap, parses once at the end. */
class JsonScanner implements UsageScanner {
  private chunks: Buffer[] = [];
  private size = 0;
  private overflowed = false;

  feed(chunk: Buffer): void {
    if (this.overflowed) return;
    this.size += chunk.length;
    if (this.size > USAGE_SCAN_CAP) {
      this.overflowed = true;
      this.chunks = [];
      return;
    }
    this.chunks.push(chunk);
  }

  result(): TokenUsage {
    if (this.overflowed || this.chunks.length === 0)
      return { inputTokens: null, outputTokens: null };
    return usageFromJson(Buffer.concat(this.chunks));
  }
}

/** Content encodings whose body we can decompress for inspection. */
type SupportedEncoding = "gzip" | "deflate" | "br";

/** One-shot synchronous decompressor per supported encoding. */
function decompressSync(encoding: SupportedEncoding, raw: Buffer): Buffer {
  switch (encoding) {
    case "gzip":
      return gunzipSync(raw);
    case "br":
      return brotliDecompressSync(raw);
    case "deflate":
      // deflate on the wire is sometimes zlib-wrapped (RFC 1950) and sometimes
      // raw (RFC 1951). Try the wrapped form first, fall back to raw.
      try {
        return inflateSync(raw);
      } catch {
        return inflateRawSync(raw);
      }
  }
}

/**
 * Wraps an inner JSON/SSE scanner for a compressed response. It buffers the raw
 * compressed chunks as they stream by (forwarding is handled independently by
 * the proxy, these bytes are an inspection-only copy), then on result() it
 * decompresses ONCE, caps the output, feeds the inner scanner, and returns its
 * usage. Any decompression failure, or hitting the raw buffer cap, yields nulls
 * without ever throwing. Inspection never alters, reorders or delays the
 * forwarded bytes.
 */
class DecompressingScanner implements UsageScanner {
  private chunks: Buffer[] = [];
  private size = 0;
  private overflowed = false;

  constructor(
    private readonly encoding: SupportedEncoding,
    private readonly inner: UsageScanner,
  ) {}

  feed(chunk: Buffer): void {
    if (this.overflowed) return;
    this.size += chunk.length;
    if (this.size > USAGE_COMPRESSED_BUFFER_CAP) {
      // Too much compressed data to safely buffer: give up and drop what we have.
      this.overflowed = true;
      this.chunks = [];
      return;
    }
    this.chunks.push(chunk);
  }

  result(): TokenUsage {
    const nulls: TokenUsage = { inputTokens: null, outputTokens: null };
    if (this.overflowed || this.chunks.length === 0) return nulls;
    try {
      let body = decompressSync(this.encoding, Buffer.concat(this.chunks));
      // Cap the DECOMPRESSED bytes the inner scanner sees so a small payload
      // that expands huge still gets bounded. A truncated JSON body simply
      // fails to parse and yields nulls, which is the safe outcome.
      if (body.length > USAGE_SCAN_CAP) body = body.subarray(0, USAGE_SCAN_CAP);
      this.inner.feed(body);
      return this.inner.result();
    } catch {
      // Corrupt or truncated stream, unknown framing, etc. Never crash.
      return nulls;
    } finally {
      this.chunks = [];
    }
  }
}

/**
 * Picks an inner scanner (SSE vs JSON) from the content type, or null when the
 * body is neither JSON nor SSE.
 */
function innerScannerFor(contentType: string): UsageScanner | null {
  if (contentType.includes("text/event-stream")) return new SseScanner();
  if (contentType.includes("application/json") || contentType.includes("+json"))
    return new JsonScanner();
  return null;
}

/**
 * Picks a scanner for an upstream response, or null when the body cannot be
 * inspected: non-JSON, non-SSE content types, and compressed bodies whose
 * encoding we do not support. Supported compressions (gzip, deflate, br) are
 * inspected via a decompressing wrapper that NEVER touches the forwarded bytes.
 */
export function createUsageScanner(headers: http.IncomingHttpHeaders): UsageScanner | null {
  const contentType = String(headers["content-type"] ?? "").toLowerCase();
  const encoding = String(headers["content-encoding"] ?? "identity").toLowerCase().trim();

  if (encoding === "identity" || encoding === "") {
    return innerScannerFor(contentType);
  }

  if (encoding === "gzip" || encoding === "deflate" || encoding === "br") {
    const inner = innerScannerFor(contentType);
    if (!inner) return null;
    return new DecompressingScanner(encoding, inner);
  }

  // Unknown or multi-value (e.g. "gzip, br") encodings: do not attempt to
  // decompress, record null usage just like before.
  return null;
}
