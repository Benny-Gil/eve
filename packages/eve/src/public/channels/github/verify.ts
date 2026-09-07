import {
  resolveGitHubWebhookSecret,
  type GitHubWebhookSecret,
} from "#public/channels/github/auth.js";
import {
  runWebhookVerifier,
  signHmacSha256,
  verifyHmacSha256,
  type WebhookVerifier,
} from "#public/channels/webhook.js";

/** Options for {@link verifyGitHubRequest}. */
export interface GitHubVerifyOptions {
  readonly webhookSecret?: GitHubWebhookSecret;
  /** Replaces the HMAC check, for example with Connect's Vercel OIDC verifier. */
  readonly webhookVerifier?: WebhookVerifier;
}

/**
 * Verifies a GitHub webhook request and returns its raw body. The raw body is
 * required because GitHub signs the exact bytes it delivered.
 *
 * When a {@link WebhookVerifier} is supplied, it replaces the built-in HMAC
 * check: GitHub's webhook secret is never read and the verifier owns the
 * accept/reject decision.
 */
export async function verifyGitHubRequest(
  request: Request,
  options: GitHubVerifyOptions,
): Promise<string> {
  const body = await request.text();

  if (options.webhookVerifier !== undefined) {
    const verified = await runWebhookVerifier(options.webhookVerifier, request, body);
    if (verified === null) {
      throw new Error("githubChannel: inbound webhook verifier rejected the request.");
    }
    return verified;
  }

  const secret = await resolveGitHubWebhookSecret(options.webhookSecret);
  const signature = request.headers.get("x-hub-signature-256") ?? "";
  if (!signature) {
    throw new Error("githubChannel: inbound request missing X-Hub-Signature-256.");
  }
  if (!verifyHmacSha256({ payload: body, prefix: "sha256=", secret, signature })) {
    throw new Error("githubChannel: inbound request signature mismatch.");
  }
  return body;
}

/** Signs a raw GitHub webhook body for tests and local fixtures. */
export function signGitHubWebhookBody(body: string, secret: string): string {
  return `sha256=${signHmacSha256(body, secret)}`;
}
