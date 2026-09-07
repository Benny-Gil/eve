---
issue: https://github.com/vercel/eve/issues/3106
status: proposed
last_updated: "2026-09-07"
---

# Shared channel webhook verification

## Summary

Every platform channel verifies inbound webhooks with private code. Three channels carry the same `constantTimeCompare` function, five channels declare the same `webhookVerifier` callback type under a different name, and a custom channel author has no exported primitive to compose. This proposal adds one public module, `eve/channels/webhook`, that owns the verifier contract and the signature primitives. The built-in channels compose it, and the documentation for custom channels describes the contract.

## Authoring API

```ts
import {
  constantTimeCompare,
  runWebhookVerifier,
  signHmacSha256,
  verifyHmacSha256,
  verifyWebhookTimestamp,
  type WebhookVerifier,
} from "eve/channels/webhook";

type WebhookVerifier = (request: Request, body: string) => unknown | Promise<unknown>;

function runWebhookVerifier(
  verifier: WebhookVerifier,
  request: Request,
  body: string,
): Promise<string | null>;

function constantTimeCompare(a: string, b: string): boolean;

function signHmacSha256(payload: string, secret: string, encoding?: "hex" | "base64"): string;

function verifyHmacSha256(input: {
  readonly payload: string;
  readonly secret: string;
  readonly signature: string;
  readonly prefix?: string;
  readonly encoding?: "hex" | "base64";
}): boolean;

function verifyWebhookTimestamp(input: {
  readonly timestampMs: number;
  readonly maxSkewMs: number;
  readonly now?: number;
}): boolean;
```

## Semantics

The primitives return a result and never throw on untrusted input. The channel decides the response, so a custom route can answer 401 and a built-in channel can keep its current error messages.

- `constantTimeCompare` compares the UTF-8 bytes of both strings with `timingSafeEqual`. It returns `false` when the byte lengths differ.
- `verifyHmacSha256` recomputes the digest over `payload`, prepends `prefix`, and compares the result with `signature` in constant time. `encoding` defaults to `hex`.
- `verifyWebhookTimestamp` returns `true` when `timestampMs` is a finite number within `maxSkewMs` of `now`. It throws when `maxSkewMs` is not a non-negative finite number, because that is a configuration error and not untrusted input.
- `runWebhookVerifier` applies the shared callback contract. A thrown error propagates. A falsy result returns `null`. A string result replaces the body. Any other truthy result keeps the raw body.

The `WebhookVerifier` contract is unchanged from the current channels. A verifier replaces every built-in check, including the timestamp policy.

## Module placement

`eve/channels` is a capability-tracked authoring surface. Every type it exports must be reachable from the channel capability roots, so a new standalone type there requires a new capability epoch and a retained compatibility fixture. `eve/channels/auth` already holds route-level verification helpers on a sibling subpath outside that surface. `eve/channels/webhook` follows the same placement.

## Built-in channel changes

- GitHub, Linear, and Telegram drop their private `constantTimeCompare` and call the shared primitives. GitHub passes `prefix: "sha256="`. Linear keeps its own `webhookTimestamp` body parsing and calls `verifyWebhookTimestamp` for the skew check.
- Discord calls `verifyWebhookTimestamp` with its header timestamp converted to milliseconds. An invalid `maxSkewSeconds` now throws instead of accepting every timestamp.
- GitHub, Linear, Telegram, Discord, and Teams type their `webhookVerifier` credential as `WebhookVerifier` and call `runWebhookVerifier`.
- The `GitHubWebhookVerifier`, `LinearWebhookVerifier`, `TelegramWebhookVerifier`, `DiscordWebhookVerifier`, and `TeamsWebhookVerifier` exports are removed. eve is pre-1.0 and prefers one definition over five aliases.
- Slack, Twilio, Linq, and iMessage keep the Chat SDK primitives they already delegate to. `SlackWebhookVerifier` has the same shape as `WebhookVerifier`, so a verifier typed with the shared type is assignable to it. Replacing that vendored alias is a separate change.

## Documentation

- `docs/channels/custom.mdx` gains a "Verify inbound webhooks" section with a worked HMAC and timestamp example, the primitive list, and the `webhookVerifier` result table.
- `docs/reference/typescript-api.md` lists the new subpath.
- `docs/concepts/security-model.md` links the custom channel section.

## Out of scope

- Ed25519 and JWT verification stay inside the Discord and Teams channels. No other channel needs them.
- A generic `verifyHmac` with a selectable algorithm. Every eve-owned HMAC check uses SHA-256, and Twilio's SHA-1 check lives in the Chat SDK primitive.
