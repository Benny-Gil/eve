/**
 * Telegram inbound-webhook verification.
 *
 * When you configure a webhook with `secret_token`, Telegram includes
 * that exact value in `X-Telegram-Bot-Api-Secret-Token` on every
 * webhook request. The native channel verifies the header directly or
 * delegates to a caller-supplied verifier for forwarded webhooks.
 */

import {
  constantTimeCompare,
  runWebhookVerifier,
  type WebhookVerifier,
} from "#public/channels/webhook.js";

/** Secret token you set on Telegram's `setWebhook` call. */
export type TelegramWebhookSecretToken = string | (() => string | Promise<string>);

/** Options for {@link verifyTelegramRequest}. */
export interface TelegramVerifyOptions {
  readonly secretToken: TelegramWebhookSecretToken | undefined;
  /** Replaces the secret-token check, for example behind a trusted proxy. */
  readonly webhookVerifier?: WebhookVerifier;
}

/** Resolves a Telegram webhook secret, falling back to `TELEGRAM_WEBHOOK_SECRET_TOKEN`. */
export async function resolveTelegramWebhookSecretToken(
  secretToken?: TelegramWebhookSecretToken,
): Promise<string> {
  const source = secretToken ?? process.env.TELEGRAM_WEBHOOK_SECRET_TOKEN;
  if (!source) throw new Error("TELEGRAM_WEBHOOK_SECRET_TOKEN is required.");
  return typeof source === "function" ? await source() : source;
}

/**
 * Verifies an inbound Telegram webhook and returns its raw body.
 *
 * Throws when no secret/verifier is configured, the secret header is
 * missing, or the supplied verifier/header rejects.
 */
export async function verifyTelegramRequest(
  request: Request,
  options: TelegramVerifyOptions,
): Promise<string> {
  const body = await request.text();

  if (options.webhookVerifier !== undefined) {
    const verified = await runWebhookVerifier(options.webhookVerifier, request, body);
    if (verified === null) {
      throw new Error("telegramChannel: inbound webhook verifier rejected the request.");
    }
    return verified;
  }

  const secretToken = await resolveTelegramWebhookSecretToken(options.secretToken);
  const header = request.headers.get("x-telegram-bot-api-secret-token") ?? "";
  if (!header) {
    throw new Error("telegramChannel: inbound request missing Telegram secret-token header.");
  }
  if (!constantTimeCompare(secretToken, header)) {
    throw new Error("telegramChannel: inbound request secret-token mismatch.");
  }
  return body;
}
