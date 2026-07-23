/**
 * AWS integration (EXPERIMENTAL): the gateway computes AWS Signature
 * Version 4 itself. Agents call *.amazonaws.com with no credentials at all
 * (or dummy SDK credentials, the auth headers are stripped and re-signed)
 * and the gateway signs each request with the stored access key.
 *
 * Body handling: SigV4 signs a hash of the payload, so this integration
 * declares `needsBody` and the proxy buffers the request body (bounded by
 * ONEGATE_MAX_BUFFERED_BODY, default 32 MiB) before signing. Requests with
 * bodies above the cap are rejected with 413. When no body is available
 * (community use of the signer outside the proxy), S3 is signed with
 * UNSIGNED-PAYLOAD, which S3 accepts, and other services get the empty-body
 * hash, which is only correct for bodyless requests.
 *
 * Region and service are derived from the host (s3.eu-central-1,
 * ec2.us-east-1, bucket.s3.us-west-2, abc123.execute-api.eu-west-1, ...).
 * Global endpoints like iam.amazonaws.com fall back to the credential's
 * default region (then us-east-1). Services whose signing name differs from
 * their hostname label (e.g. SES's "email.*" hosts sign as "ses") are not
 * special-cased yet, that is part of why this is experimental.
 */

import { createHash, createHmac } from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";
import type { Integration, InjectionContext } from "./types.js";

function sha256hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function hmac(key: string | Buffer, data: string): Buffer {
  return createHmac("sha256", key).update(data).digest();
}

const EMPTY_BODY_SHA256 = sha256hex("");
const REGION_RE = /^[a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-\d+$/;

export interface AwsTarget {
  service: string;
  region: string;
}

/** Derives signing service and region from an *.amazonaws.com host. */
export function deriveAwsTarget(host: string, defaultRegion?: string): AwsTarget {
  const labels = host.toLowerCase().replace(/\.amazonaws\.com$/, "").split(".");
  const last = labels[labels.length - 1];
  if (labels.length >= 2 && REGION_RE.test(last)) {
    return { service: labels[labels.length - 2], region: last };
  }
  return { service: last, region: defaultRegion || "us-east-1" };
}

function rfc3986(s: string): string {
  return encodeURIComponent(s).replace(
    /[!'()*]/g,
    (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase(),
  );
}

function canonicalQuery(rawQuery: string): string {
  if (!rawQuery) return "";
  const pairs: Array<[string, string]> = [];
  for (const part of rawQuery.split("&")) {
    if (!part) continue;
    const eq = part.indexOf("=");
    const rawKey = eq === -1 ? part : part.slice(0, eq);
    const rawVal = eq === -1 ? "" : part.slice(eq + 1);
    pairs.push([rfc3986(decodeURIComponent(rawKey)), rfc3986(decodeURIComponent(rawVal))]);
  }
  pairs.sort(([ak, av], [bk, bv]) => (ak === bk ? (av < bv ? -1 : 1) : ak < bk ? -1 : 1));
  return pairs.map(([k, v]) => `${k}=${v}`).join("&");
}

/** AWS4-HMAC-SHA256 signing key derivation (exported for the test vectors). */
export function deriveSigningKey(
  secretAccessKey: string,
  dateStamp: string,
  region: string,
  service: string,
): Buffer {
  const kDate = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, "aws4_request");
}

export interface SignV4Params {
  method: string;
  /** Path as sent by the agent, query string included. */
  path: string;
  /** Mutated in place: x-amz-date, authorization (and friends) are set. */
  headers: IncomingHttpHeaders;
  body?: Buffer;
  host: string;
  service: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  /** Fixed clock for tests. */
  now?: Date;
}

/**
 * Signs the request per AWS SigV4. Signed headers: host, content-type when
 * present, and every x-amz-* header (x-amz-date is always set here,
 * x-amz-security-token when a session token exists, x-amz-content-sha256
 * for S3).
 */
export function signV4(p: SignV4Params): void {
  const now = p.now ?? new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const dateStamp = amzDate.slice(0, 8);

  const qIdx = p.path.indexOf("?");
  const rawPath = qIdx === -1 ? p.path : p.path.slice(0, qIdx);
  const rawQuery = qIdx === -1 ? "" : p.path.slice(qIdx + 1);

  const isS3 = p.service === "s3";
  const payloadHash =
    p.body !== undefined ? sha256hex(p.body) : isS3 ? "UNSIGNED-PAYLOAD" : EMPTY_BODY_SHA256;

  p.headers["x-amz-date"] = amzDate;
  if (p.sessionToken) p.headers["x-amz-security-token"] = p.sessionToken;
  if (isS3) p.headers["x-amz-content-sha256"] = payloadHash;

  const toSign = new Map<string, string>();
  toSign.set("host", p.host.toLowerCase());
  const contentType = p.headers["content-type"];
  if (contentType) toSign.set("content-type", String(contentType));
  for (const [k, v] of Object.entries(p.headers)) {
    const lower = k.toLowerCase();
    if (lower.startsWith("x-amz-") && v !== undefined) toSign.set(lower, String(v));
  }
  const signedKeys = [...toSign.keys()].sort();
  const canonicalHeaders = signedKeys
    .map((k) => `${k}:${toSign.get(k)!.trim().replace(/\s+/g, " ")}\n`)
    .join("");
  const signedHeaders = signedKeys.join(";");

  const canonicalRequest = [
    p.method.toUpperCase(),
    rawPath || "/",
    canonicalQuery(rawQuery),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const scope = `${dateStamp}/${p.region}/${p.service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    scope,
    sha256hex(canonicalRequest),
  ].join("\n");
  const signature = createHmac(
    "sha256",
    deriveSigningKey(p.secretAccessKey, dateStamp, p.region, p.service),
  )
    .update(stringToSign)
    .digest("hex");

  p.headers.authorization = `AWS4-HMAC-SHA256 Credential=${p.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

export const aws: Integration = {
  id: "aws",
  title: "AWS (experimental)",
  hosts: [".amazonaws.com"],
  needsBody: true,
  category: "Infrastructure",
  credentialFields: [
    { key: "accessKeyId", label: "Access key ID", secret: false },
    { key: "secretAccessKey", label: "Secret access key", secret: true },
    { key: "sessionToken", label: "Session token (for temporary credentials)", secret: true, optional: true },
    { key: "defaultRegion", label: "Default region (fallback for global endpoints)", secret: false, optional: true },
  ],
  llmHelp: {
    credentialType:
      "EXPERIMENTAL. An AWS access key pair (access key ID plus secret access key, optionally a session token for temporary credentials). OneGate computes the AWS Signature Version 4 itself at the gateway, signing the full request including a hash of the body, so the agent never holds AWS credentials.",
    whereToCreate:
      "AWS Console, IAM, Users, pick or create a user, Security credentials tab, Create access key. Prefer a dedicated IAM user (or temporary STS credentials) with a least-privilege policy for what the agent actually needs, never root account keys.",
    scopes: [
      "Permissions come from the IAM policies attached to the key's user or role, not from OneGate. Grant only the actions and resources the agent needs, e.g. s3:GetObject on one bucket.",
    ],
    notes: [
      "EXPERIMENTAL: gateway-side SigV4 is new and not every AWS service shape is covered.",
      "Region and service are derived from the hostname (s3.eu-central-1.amazonaws.com, ec2.us-east-1.amazonaws.com, bucket.s3.us-west-2.amazonaws.com). For global endpoints like iam.amazonaws.com the default region field is used (falls back to us-east-1).",
      "Request bodies are buffered at the gateway for payload hashing, bodies above the configured cap (default 32 MiB, env ONEGATE_MAX_BUFFERED_BODY) are rejected, so very large S3 uploads do not work yet.",
      "Services whose SigV4 signing name differs from their hostname label (for example SES, which uses email.* hosts but signs as ses) are not special-cased yet and will fail signature validation.",
      "Call the APIs without credentials, or with dummy SDK credentials, the gateway strips agent-supplied x-amz-date, x-amz-content-sha256 and x-amz-security-token and re-signs from scratch.",
    ].join("\n"),
  },
  inject(ctx: InjectionContext): void {
    const { accessKeyId, secretAccessKey, sessionToken, defaultRegion } = ctx.credential.data;
    if (!accessKeyId || !secretAccessKey) {
      throw new Error('AWS credential needs both "accessKeyId" and "secretAccessKey" fields');
    }
    const { service, region } = deriveAwsTarget(ctx.host, defaultRegion);
    // Drop any agent-supplied SigV4 artifacts (dummy SDK signatures) so the
    // gateway's own values are the only ones signed and sent.
    for (const k of Object.keys(ctx.headers)) {
      const lower = k.toLowerCase();
      if (
        lower === "x-amz-date" ||
        lower === "x-amz-content-sha256" ||
        lower === "x-amz-security-token"
      ) {
        delete ctx.headers[k];
      }
    }
    signV4({
      method: ctx.method,
      path: ctx.path,
      headers: ctx.headers,
      body: ctx.body,
      host: ctx.host,
      service,
      region,
      accessKeyId,
      secretAccessKey,
      sessionToken: sessionToken || undefined,
    });
  },
};
