/**
 * Inbound webhook verification primitives.
 *
 * Built-in channels compose these helpers, and custom channels use the same
 * ones. Each helper returns a result and never throws on untrusted input, so
 * the channel owns the response it sends back to the platform.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Caller-supplied inbound webhook verifier. A channel calls it instead of its
 * built-in signature check, for example when a trusted proxy such as Vercel
 * Connect authenticates the request before it reaches eve.
 *
 * The return value selects how the channel handles the request:
 *
 * - Throw, reject, or return a falsy value (`null`, `undefined`, `false`,
 *   `""`, `0`): the channel rejects the request with a 401.
 * - Return a string: the channel accepts the request and parses that string
 *   as the body instead of the raw body.
 * - Return any other truthy value: the channel accepts the request and parses
 *   the raw body.
 *
 * A verifier replaces every built-in check, including the timestamp policy,
 * so it must enforce its own.
 */
export type WebhookVerifier = (request: Request, body: string) => unknown | Promise<unknown>;

/**
 * Runs a {@link WebhookVerifier} and returns the body the channel must parse,
 * or `null` when the verifier rejects the request. A thrown error propagates.
 */
export async function runWebhookVerifier(
  verifier: WebhookVerifier,
  request: Request,
  body: string,
): Promise<string | null> {
  const result = await verifier(request, body);
  if (!result) return null;
  return typeof result === "string" ? result : body;
}

/**
 * Compares two secrets without leaking which byte differs. Use it for every
 * signature or token check, because `===` returns on the first mismatch and
 * lets a caller time the comparison.
 */
export function constantTimeCompare(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/** Digest encoding a platform uses in its signature header. */
export type HmacDigestEncoding = "hex" | "base64";

/** Input for {@link verifyHmacSha256}. */
export interface HmacSha256SignatureInput {
  /** Exact bytes the platform signed, usually the raw request body. */
  readonly payload: string;
  /** Shared secret from the platform's webhook configuration. */
  readonly secret: string;
  /** Signature header value as received, including any prefix. */
  readonly signature: string;
  /** Text the platform writes before the digest, for example `sha256=`. */
  readonly prefix?: string;
  /** Digest encoding. Defaults to `hex`. */
  readonly encoding?: HmacDigestEncoding;
}

/** Computes an HMAC-SHA256 digest. Use it to sign fixtures in tests. */
export function signHmacSha256(
  payload: string,
  secret: string,
  encoding: HmacDigestEncoding = "hex",
): string {
  return createHmac("sha256", secret).update(payload).digest(encoding);
}

/**
 * Recomputes an HMAC-SHA256 signature over the signed bytes and compares it
 * with the received header in constant time.
 */
export function verifyHmacSha256(input: HmacSha256SignatureInput): boolean {
  const digest = signHmacSha256(input.payload, input.secret, input.encoding);
  return constantTimeCompare(`${input.prefix ?? ""}${digest}`, input.signature);
}

/** Input for {@link verifyWebhookTimestamp}. */
export interface WebhookTimestampInput {
  /** Timestamp the platform attached to the request, in epoch milliseconds. */
  readonly timestampMs: number;
  /** Largest allowed distance from `now`, in milliseconds. */
  readonly maxSkewMs: number;
  /** Current time in epoch milliseconds. Defaults to `Date.now()`. */
  readonly now?: number;
}

/**
 * Checks that a request timestamp is close to the current time, which bounds
 * the window in which a captured request can be replayed. Returns `false` for
 * a missing or malformed timestamp. Throws when `maxSkewMs` is not a
 * non-negative finite number, because that is a configuration error.
 */
export function verifyWebhookTimestamp(input: WebhookTimestampInput): boolean {
  if (!Number.isFinite(input.maxSkewMs) || input.maxSkewMs < 0) {
    throw new Error("verifyWebhookTimestamp: maxSkewMs must be a non-negative finite number.");
  }
  if (!Number.isFinite(input.timestampMs)) return false;
  return Math.abs((input.now ?? Date.now()) - input.timestampMs) <= input.maxSkewMs;
}
