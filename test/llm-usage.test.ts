/**
 * Token usage accounting (M6): pure parser/scanner tests plus an e2e through
 * the gateway proxy against a fake upstream serving anthropic-style JSON and
 * SSE responses.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import {
  gzipSync,
  gunzipSync,
  deflateSync,
  brotliCompressSync,
  brotliDecompressSync,
} from "node:zlib";
import { initCa } from "../src/ca.js";
import { Store } from "../src/store/db.js";
import { Registry } from "../src/integrations/types.js";
import { GatewayProxy } from "../src/proxy/server.js";
import {
  createUsageScanner,
  extractRequestModel,
  usageFromJson,
  usageFromObject,
  USAGE_SCAN_CAP,
  USAGE_COMPRESSED_BUFFER_CAP,
} from "../src/llm/usage.js";

describe("extractRequestModel (pure)", () => {
  it("reads the model from an anthropic/openai JSON body", () => {
    const body = Buffer.from(JSON.stringify({ model: "claude-opus-4-8", messages: [] }));
    expect(extractRequestModel("/v1/messages", body)).toBe("claude-opus-4-8");
  });

  it("reads the model from an openai body", () => {
    const body = Buffer.from(JSON.stringify({ model: "gpt-5-mini", input: "hi" }));
    expect(extractRequestModel("/v1/chat/completions", body)).toBe("gpt-5-mini");
  });

  it("falls back to the gemini URL path when the body has no model", () => {
    expect(
      extractRequestModel("/v1beta/models/gemini-3-flash-preview:generateContent", undefined),
    ).toBe("gemini-3-flash-preview");
  });

  it("handles the gemini streaming path form", () => {
    expect(
      extractRequestModel(
        "/v1beta/models/gemini-3-flash:streamGenerateContent?alt=sse",
        Buffer.from("not json"),
      ),
    ).toBe("gemini-3-flash");
  });

  it("prefers the body model over the path when both are present", () => {
    const body = Buffer.from(JSON.stringify({ model: "claude-sonnet-4-6" }));
    expect(extractRequestModel("/v1beta/models/gemini-3-flash:generateContent", body)).toBe(
      "claude-sonnet-4-6",
    );
  });

  it("returns null when neither body nor path names a model", () => {
    expect(extractRequestModel("/v1/messages", Buffer.from("{}"))).toBeNull();
    expect(extractRequestModel("/health", undefined)).toBeNull();
  });

  it("percent-decodes a well-formed escape in the path model segment", () => {
    expect(extractRequestModel("/v1beta/models/gemini%2Dtest:generateContent", undefined)).toBe(
      "gemini-test",
    );
  });

  // The documented contract on extractRequestModel is "Never throws", and the
  // LLM handler calls it on the hot request path without a try/catch. Malformed
  // percent-escapes survive canonicalization (policy's decodeOnce preserves
  // them by design rather than throwing), so they reach this function verbatim.
  it("never throws on malformed percent-escapes in the path", () => {
    const malformed = [
      "/v1beta/models/%:generateContent",
      "/v1beta/models/%%3AgenerateContent",
      "/v1beta/models/%zz:generateContent",
      "/v1beta/models/%E0%A4:generateContent",
      "/v1beta/models/%",
    ];
    for (const path of malformed) {
      expect(() => extractRequestModel(path, undefined)).not.toThrow();
    }
  });

  it("falls back to the raw matched segment when the escape is malformed", () => {
    // The canonicalized form of "/v1beta/models/%%3AgenerateContent": policy's
    // decodeOnce turns %3A into ":" and leaves the stray "%" as a literal.
    expect(extractRequestModel("/v1beta/models/%:generateContent", undefined)).toBe("%");
    expect(extractRequestModel("/v1beta/models/gemini%zz:generateContent", undefined)).toBe(
      "gemini%zz",
    );
  });

  it("still prefers a valid body model when the path is malformed", () => {
    const body = Buffer.from(JSON.stringify({ model: "claude-opus-4-8" }));
    expect(extractRequestModel("/v1beta/models/%:generateContent", body)).toBe("claude-opus-4-8");
  });
});

describe("usageFromObject / usageFromJson (pure)", () => {
  it("parses anthropic non-streaming usage", () => {
    expect(
      usageFromObject({ id: "msg_1", usage: { input_tokens: 17, output_tokens: 230 } }),
    ).toEqual({ inputTokens: 17, outputTokens: 230 });
  });

  it("parses openai usage (prompt/completion tokens)", () => {
    expect(
      usageFromObject({ usage: { prompt_tokens: 9, completion_tokens: 12, total_tokens: 21 } }),
    ).toEqual({ inputTokens: 9, outputTokens: 12 });
  });

  it("parses gemini usageMetadata", () => {
    expect(
      usageFromObject({ usageMetadata: { promptTokenCount: 5, candidatesTokenCount: 7 } }),
    ).toEqual({ inputTokens: 5, outputTokens: 7 });
  });

  it("parses anthropic message_start (usage nested in message)", () => {
    expect(
      usageFromObject({
        type: "message_start",
        message: { usage: { input_tokens: 25, output_tokens: 1 } },
      }),
    ).toEqual({ inputTokens: 25, outputTokens: 1 });
  });

  it("folds anthropic prompt-cache tokens into input (non-streaming)", () => {
    // Claude Code caches the big system prompt, so input_tokens is tiny and the
    // bulk lands in the cache fields. The real input is the sum of all three.
    expect(
      usageFromObject({
        usage: {
          input_tokens: 2,
          cache_read_input_tokens: 18000,
          cache_creation_input_tokens: 540,
          output_tokens: 82,
        },
      }),
    ).toEqual({ inputTokens: 18542, outputTokens: 82 });
  });

  it("counts anthropic cache tokens even when input_tokens is absent", () => {
    expect(
      usageFromObject({
        message: { usage: { cache_read_input_tokens: 1000, output_tokens: 5 } },
      }),
    ).toEqual({ inputTokens: 1000, outputTokens: 5 });
  });

  it("does not invent input from cache fields for openai/gemini shapes", () => {
    // openai prompt_tokens already includes any cached portion, so no cache
    // fields are present and the count is taken verbatim (no double counting).
    expect(
      usageFromObject({ usage: { prompt_tokens: 9, completion_tokens: 12 } }),
    ).toEqual({ inputTokens: 9, outputTokens: 12 });
  });

  it("returns nulls for shapes without usage, non-objects and bad JSON", () => {
    expect(usageFromObject({ choices: [] })).toEqual({ inputTokens: null, outputTokens: null });
    expect(usageFromObject(null)).toEqual({ inputTokens: null, outputTokens: null });
    expect(usageFromObject("x")).toEqual({ inputTokens: null, outputTokens: null });
    expect(usageFromJson("{not json")).toEqual({ inputTokens: null, outputTokens: null });
    expect(usageFromObject({ usage: { input_tokens: "5" } })).toEqual({
      inputTokens: null,
      outputTokens: null,
    });
  });
});

describe("SSE scanner (pure)", () => {
  const sseHeaders = { "content-type": "text/event-stream" };

  it("collects anthropic streaming usage across events, last delta wins", () => {
    const s = createUsageScanner(sseHeaders)!;
    expect(s).not.toBeNull();
    const events = [
      'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":25,"output_tokens":1}}}\n\n',
      'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"hi"}}\n\n',
      'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":40}}\n\n',
      'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":90}}\n\n',
      "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    ];
    for (const e of events) s.feed(Buffer.from(e));
    expect(s.result()).toEqual({ inputTokens: 25, outputTokens: 90 });
  });

  it("sums anthropic cache tokens from message_start, last output delta wins", () => {
    const s = createUsageScanner(sseHeaders)!;
    const events = [
      'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":3,"cache_read_input_tokens":12000,"cache_creation_input_tokens":200,"output_tokens":1}}}\n\n',
      'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":150}}\n\n',
      "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    ];
    for (const e of events) s.feed(Buffer.from(e));
    expect(s.result()).toEqual({ inputTokens: 12203, outputTokens: 150 });
  });

  it("handles data lines split across chunk boundaries", () => {
    const s = createUsageScanner(sseHeaders)!;
    const line = 'data: {"type":"message_delta","usage":{"output_tokens":55}}\n';
    for (const ch of line.match(/.{1,7}/gs)!) s.feed(Buffer.from(ch));
    expect(s.result().outputTokens).toBe(55);
  });

  it("handles openai-style streams: usage only when the final chunk carries it", () => {
    const without = createUsageScanner(sseHeaders)!;
    without.feed(Buffer.from('data: {"choices":[{"delta":{"content":"a"}}]}\n\ndata: [DONE]\n\n'));
    expect(without.result()).toEqual({ inputTokens: null, outputTokens: null });

    const withUsage = createUsageScanner(sseHeaders)!;
    withUsage.feed(Buffer.from('data: {"choices":[{"delta":{"content":"a"}}]}\n\n'));
    withUsage.feed(
      Buffer.from('data: {"choices":[],"usage":{"prompt_tokens":3,"completion_tokens":8}}\n\ndata: [DONE]\n\n'),
    );
    expect(withUsage.result()).toEqual({ inputTokens: 3, outputTokens: 8 });
  });

  it("skips an oversized line but still sees later usage events", () => {
    const s = createUsageScanner(sseHeaders)!;
    s.feed(Buffer.from('data: {"type":"message_start","message":{"usage":{"input_tokens":12,"output_tokens":1}}}\n'));
    // One enormous data line, larger than the cap, fed without a newline.
    const huge = 'data: {"big":"' + "x".repeat(USAGE_SCAN_CAP + 1024);
    s.feed(Buffer.from(huge));
    s.feed(Buffer.from('"}\n'));
    s.feed(Buffer.from('data: {"type":"message_delta","usage":{"output_tokens":77}}\n'));
    expect(s.result()).toEqual({ inputTokens: 12, outputTokens: 77 });
  });

  it("counts a trailing data line without a final newline", () => {
    const s = createUsageScanner(sseHeaders)!;
    s.feed(Buffer.from('data: {"usage":{"input_tokens":2,"output_tokens":3}}'));
    expect(s.result()).toEqual({ inputTokens: 2, outputTokens: 3 });
  });
});

describe("JSON scanner + scanner selection (pure)", () => {
  it("parses a JSON body fed in chunks", () => {
    const s = createUsageScanner({ "content-type": "application/json; charset=utf-8" })!;
    const body = JSON.stringify({ usage: { input_tokens: 4, output_tokens: 6 } });
    s.feed(Buffer.from(body.slice(0, 10)));
    s.feed(Buffer.from(body.slice(10)));
    expect(s.result()).toEqual({ inputTokens: 4, outputTokens: 6 });
  });

  it("bails silently past the cap", () => {
    const s = createUsageScanner({ "content-type": "application/json" })!;
    s.feed(Buffer.alloc(USAGE_SCAN_CAP + 1, 0x7b));
    s.feed(Buffer.from(JSON.stringify({ usage: { input_tokens: 1, output_tokens: 1 } })));
    expect(s.result()).toEqual({ inputTokens: null, outputTokens: null });
  });

  it("returns a scanner for supported compressed JSON and SSE bodies", () => {
    expect(
      createUsageScanner({ "content-type": "application/json", "content-encoding": "gzip" }),
    ).not.toBeNull();
    expect(
      createUsageScanner({ "content-type": "text/event-stream", "content-encoding": "br" }),
    ).not.toBeNull();
  });

  it("refuses unsupported encodings and non-JSON/SSE bodies", () => {
    expect(
      createUsageScanner({ "content-type": "application/json", "content-encoding": "zstd" }),
    ).toBeNull();
    // Multi-value encodings are not decompressed.
    expect(
      createUsageScanner({ "content-type": "application/json", "content-encoding": "gzip, br" }),
    ).toBeNull();
    // Supported encoding but a body type we never inspect.
    expect(
      createUsageScanner({ "content-type": "text/html", "content-encoding": "gzip" }),
    ).toBeNull();
    expect(createUsageScanner({ "content-type": "text/html" })).toBeNull();
    expect(createUsageScanner({})).toBeNull();
  });
});

describe("compressed body scanning (pure)", () => {
  const usageBody = JSON.stringify({ usage: { input_tokens: 11, output_tokens: 22 } });

  it("parses a gzip'd JSON body", () => {
    const s = createUsageScanner({
      "content-type": "application/json",
      "content-encoding": "gzip",
    })!;
    s.feed(gzipSync(Buffer.from(usageBody)));
    expect(s.result()).toEqual({ inputTokens: 11, outputTokens: 22 });
  });

  it("parses a gzip'd JSON body fed in chunks", () => {
    const s = createUsageScanner({
      "content-type": "application/json",
      "content-encoding": "gzip",
    })!;
    const gz = gzipSync(Buffer.from(usageBody));
    const mid = Math.floor(gz.length / 2);
    s.feed(gz.subarray(0, mid));
    s.feed(gz.subarray(mid));
    expect(s.result()).toEqual({ inputTokens: 11, outputTokens: 22 });
  });

  it("parses a deflate'd JSON body", () => {
    const s = createUsageScanner({
      "content-type": "application/json",
      "content-encoding": "deflate",
    })!;
    s.feed(deflateSync(Buffer.from(usageBody)));
    expect(s.result()).toEqual({ inputTokens: 11, outputTokens: 22 });
  });

  it("parses a brotli'd JSON body", () => {
    const s = createUsageScanner({
      "content-type": "application/json",
      "content-encoding": "br",
    })!;
    s.feed(brotliCompressSync(Buffer.from(usageBody)));
    expect(s.result()).toEqual({ inputTokens: 11, outputTokens: 22 });
  });

  it("parses a gzip'd SSE stream, last delta wins", () => {
    const sse =
      'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":25,"output_tokens":1}}}\n\n' +
      'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":90}}\n\n' +
      'event: message_stop\ndata: {"type":"message_stop"}\n\n';
    const s = createUsageScanner({
      "content-type": "text/event-stream",
      "content-encoding": "gzip",
    })!;
    s.feed(gzipSync(Buffer.from(sse)));
    expect(s.result()).toEqual({ inputTokens: 25, outputTokens: 90 });
  });

  it("yields nulls on a corrupt gzip stream and never throws", () => {
    const s = createUsageScanner({
      "content-type": "application/json",
      "content-encoding": "gzip",
    })!;
    const gz = gzipSync(Buffer.from(usageBody));
    // Corrupt the body bytes after the header so inflation fails.
    const corrupt = Buffer.from(gz);
    corrupt[corrupt.length - 4] ^= 0xff;
    corrupt[Math.floor(corrupt.length / 2)] ^= 0xff;
    s.feed(corrupt);
    expect(() => s.result()).not.toThrow();
    expect(s.result()).toEqual({ inputTokens: null, outputTokens: null });
  });

  it("yields nulls on a truncated gzip stream", () => {
    const s = createUsageScanner({
      "content-type": "application/json",
      "content-encoding": "gzip",
    })!;
    const gz = gzipSync(Buffer.from(usageBody));
    s.feed(gz.subarray(0, gz.length - 5)); // drop the trailing bytes
    expect(s.result()).toEqual({ inputTokens: null, outputTokens: null });
  });

  it("bails to null when the raw compressed buffer exceeds its cap", () => {
    const s = createUsageScanner({
      "content-type": "application/json",
      "content-encoding": "gzip",
    })!;
    // Feed more raw bytes than USAGE_COMPRESSED_BUFFER_CAP without finishing.
    const block = Buffer.alloc(1024 * 1024, 0x41);
    for (let fed = 0; fed <= USAGE_COMPRESSED_BUFFER_CAP; fed += block.length) s.feed(block);
    expect(s.result()).toEqual({ inputTokens: null, outputTokens: null });
  });

  it("caps the decompressed bytes but still parses usage that fits", () => {
    // A small gzip that expands well past USAGE_SCAN_CAP. The usage object sits
    // at the very front so it survives the slice, the huge filler after it is
    // dropped. The result is a valid prefix object, not the full (now truncated)
    // body, so we assert the front-loaded usage is recovered.
    const front = '{"usage":{"input_tokens":3,"output_tokens":4},"filler":"';
    const filler = "z".repeat(USAGE_SCAN_CAP + 64 * 1024);
    const big = front + filler + '"}';
    const s = createUsageScanner({
      "content-type": "application/json",
      "content-encoding": "gzip",
    })!;
    s.feed(gzipSync(Buffer.from(big)));
    // The body is sliced mid-string so JSON.parse of the whole fails. This
    // documents that the cap is enforced on decompressed bytes without crashing.
    expect(() => s.result()).not.toThrow();
    expect(s.result()).toEqual({ inputTokens: null, outputTokens: null });
  });

  it("parses front-loaded SSE usage even when later events overflow the cap", () => {
    // The usage-bearing events come first, then a giant filler event past the
    // decompressed cap. The SSE inner scanner processes the early events before
    // the slice boundary, so usage is still recovered.
    const head =
      'data: {"type":"message_start","message":{"usage":{"input_tokens":7,"output_tokens":1}}}\n\n' +
      'data: {"type":"message_delta","usage":{"output_tokens":42}}\n\n';
    const tail = 'data: {"junk":"' + "y".repeat(USAGE_SCAN_CAP + 64 * 1024) + '"}\n\n';
    const s = createUsageScanner({
      "content-type": "text/event-stream",
      "content-encoding": "gzip",
    })!;
    s.feed(gzipSync(Buffer.from(head + tail)));
    expect(s.result()).toEqual({ inputTokens: 7, outputTokens: 42 });
  });
});

// ---- e2e through the proxy ----

const LLM_HOST = "api.usage-vendor.test";
const VENDOR = "usagevendor";

let dir: string;
let store: Store;
let proxy: GatewayProxy;
let proxyPort: number;
let stub: https.Server;
let caPem: string;
let agentToken: string;
let connId: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "onegate-llm-usage-"));
  const ca = initCa(dir);
  caPem = ca.rootPem;
  store = new Store(":memory:");

  stub = https.createServer(
    {
      SNICallback: (servername, cb) => {
        const leaf = ca.leafFor(servername);
        cb(null, tls.createSecureContext({ key: leaf.key, cert: leaf.cert }));
      },
    },
    (req, res) => {
      req.resume();
      req.on("end", () => {
        if (req.url === "/v1/messages-sse") {
          res.writeHead(200, { "content-type": "text/event-stream" });
          res.write(
            'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":25,"output_tokens":1}}}\n\n',
          );
          res.write('event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"hello"}}\n\n');
          res.write('event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":90}}\n\n');
          res.end("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
          return;
        }
        if (req.url === "/v1/messages-gzip") {
          const gz = gzipSync(
            Buffer.from(JSON.stringify({ usage: { input_tokens: 5, output_tokens: 6 } })),
          );
          res.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip" });
          res.end(gz);
          return;
        }
        if (req.url === "/v1/messages-br") {
          const br = brotliCompressSync(
            Buffer.from(JSON.stringify({ usage: { input_tokens: 8, output_tokens: 9 } })),
          );
          res.writeHead(200, { "content-type": "application/json", "content-encoding": "br" });
          res.end(br);
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            id: "msg_1",
            content: [{ type: "text", text: "hi" }],
            usage: { input_tokens: 17, output_tokens: 230 },
          }),
        );
      });
    },
  );
  await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
  const stubPort = (stub.address() as { port: number }).port;

  const registry = new Registry();
  registry.register({
    id: VENDOR,
    title: "Usage Vendor",
    hosts: [LLM_HOST],
    credentialFields: [{ key: "apiKey", label: "API key", secret: true }],
    needsBody: true,
    llm: {
      vendor: VENDOR,
      inject(ctx) {
        ctx.headers["x-api-key"] = ctx.credential.data.apiKey;
      },
    },
    inject(ctx) {
      ctx.headers["x-api-key"] = ctx.credential.data.apiKey;
    },
  });

  const created = store.createAgent("usage-agent", { defaultPolicy: "allow-all" });
  agentToken = created.token;
  const conn = store.createConnection({
    kind: "llm",
    vendor: VENDOR,
    name: "metered",
    data: { apiKey: "key-1" },
  });
  connId = conn.id;
  store.setAgentLlmConfig(created.agent.id, {
    enabled: true,
    strategy: "fallback",
    connectionIds: [connId],
  });

  proxy = new GatewayProxy({
    ca,
    store,
    registry,
    upstreamTls: { ca: caPem },
    upstreamLookup: () => ({ host: "127.0.0.1", port: stubPort }),
  });
  proxyPort = await proxy.listen(0, "127.0.0.1");
});

afterAll(async () => {
  await proxy.close();
  stub.closeAllConnections();
  stub.close();
  rmSync(dir, { recursive: true, force: true });
});

function viaProxy(path: string): Promise<{ status: number; body: string; raw: Buffer }> {
  return new Promise((resolve, reject) => {
    const connectReq = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "CONNECT",
      path: `${LLM_HOST}:443`,
      headers: {
        "proxy-authorization": "Basic " + Buffer.from(`agent:${agentToken}`).toString("base64"),
      },
      agent: false,
    });
    connectReq.on("connect", (connectRes, socket) => {
      if (connectRes.statusCode !== 200) {
        socket.destroy();
        reject(new Error(`CONNECT ${connectRes.statusCode}`));
        return;
      }
      const tlsSocket = tls.connect({ socket, servername: LLM_HOST, ca: caPem }, () => {
        const req = https.request(
          {
            createConnection: () => tlsSocket,
            host: LLM_HOST,
            method: "POST",
            path,
            headers: { "content-type": "application/json" },
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (c) => chunks.push(c));
            res.on("end", () => {
              const raw = Buffer.concat(chunks);
              resolve({ status: res.statusCode ?? 0, body: raw.toString(), raw });
              tlsSocket.end();
            });
          },
        );
        req.on("error", reject);
        req.end("{}");
      });
      tlsSocket.on("error", reject);
    });
    connectReq.on("error", reject);
    connectReq.end();
  });
}

describe("token accounting through the proxy (e2e)", () => {
  it("records anthropic-style JSON usage and forwards the body untouched", async () => {
    const r = await viaProxy("/v1/messages");
    expect(r.status).toBe(200);
    expect(JSON.parse(r.body).usage.output_tokens).toBe(230);
    const row = store.listLlmUsage({ connectionId: connId })[0];
    expect(row.inputTokens).toBe(17);
    expect(row.outputTokens).toBe(230);
    expect(row.errors).toBe(0);
  });

  it("records anthropic-style SSE usage while streaming the events untouched", async () => {
    const r = await viaProxy("/v1/messages-sse");
    expect(r.status).toBe(200);
    expect(r.body).toContain("event: message_start");
    expect(r.body).toContain("message_stop");
    const row = store.listLlmUsage({ connectionId: connId })[0];
    expect(row.inputTokens).toBe(25);
    expect(row.outputTokens).toBe(90);
  });

  it("records usage from a gzip'd body, delivered byte for byte", async () => {
    const r = await viaProxy("/v1/messages-gzip");
    expect(r.status).toBe(200);
    // The forwarded body is the ORIGINAL gzip bytes, untouched by inspection:
    // decoding them client-side yields the source JSON exactly.
    expect(JSON.parse(gunzipSync(r.raw).toString())).toEqual({
      usage: { input_tokens: 5, output_tokens: 6 },
    });
    const row = store.listLlmUsage({ connectionId: connId })[0];
    expect(row.inputTokens).toBe(5);
    expect(row.outputTokens).toBe(6);
  });

  it("records usage from a brotli'd body, delivered byte for byte", async () => {
    const r = await viaProxy("/v1/messages-br");
    expect(r.status).toBe(200);
    expect(JSON.parse(brotliDecompressSync(r.raw).toString())).toEqual({
      usage: { input_tokens: 8, output_tokens: 9 },
    });
    const row = store.listLlmUsage({ connectionId: connId })[0];
    expect(row.inputTokens).toBe(8);
    expect(row.outputTokens).toBe(9);
  });
});
