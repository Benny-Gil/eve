import {
  resolveLinearWebhookSecret,
  type LinearWebhookSecret,
} from "#public/channels/linear/auth.js";
import {
  runWebhookVerifier,
  signHmacSha256,
  verifyHmacSha256,
  verifyWebhookTimestamp,
  type WebhookVerifier,
} from "#public/channels/webhook.js";
import { isObject } from "#shared/guards.js";

export interface LinearVerifyOptions {
  /** Max allowed webhook timestamp skew in milliseconds. Defaults to 60s. */
  readonly maxSkewMs?: number;
  readonly webhookSecret?: LinearWebhookSecret;
  /** Replaces the HMAC and timestamp checks, for example behind a trusted proxy. */
  readonly webhookVerifier?: WebhookVerifier;
}

/** Verifies a Linear webhook request and returns its raw body. */
export async function verifyLinearRequest(
  request: Request,
  options: LinearVerifyOptions,
): Promise<string> {
  const body = await request.text();

  if (options.webhookVerifier !== undefined) {
    const verified = await runWebhookVerifier(options.webhookVerifier, request, body);
    if (verified === null) {
      throw new Error("linearChannel: inbound webhook verifier rejected the request.");
    }
    return verified;
  }

  const secret = await resolveLinearWebhookSecret(options.webhookSecret);
  const signature = request.headers.get("linear-signature") ?? "";
  if (!signature) {
    throw new Error("linearChannel: inbound request missing Linear-Signature.");
  }
  if (!verifyHmacSha256({ payload: body, secret, signature })) {
    throw new Error("linearChannel: inbound request signature mismatch.");
  }

  const timestampMs = readWebhookTimestamp(body);
  if (!verifyWebhookTimestamp({ maxSkewMs: options.maxSkewMs ?? 60_000, timestampMs })) {
    throw new Error("linearChannel: inbound request timestamp outside allowed skew.");
  }
  return body;
}

/** Signs a raw Linear webhook body for tests and local fixtures. */
export function signLinearWebhookBody(body: string, secret: string): string {
  return signHmacSha256(body, secret);
}

function readWebhookTimestamp(body: string): number {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body) as unknown;
  } catch {
    throw new Error("linearChannel: inbound request body is not valid JSON.");
  }

  const timestamp = isObject(parsed) ? parsed.webhookTimestamp : undefined;
  if (typeof timestamp !== "number" || !Number.isFinite(timestamp)) {
    throw new Error("linearChannel: inbound request missing webhookTimestamp.");
  }
  return timestamp;
}
