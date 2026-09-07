---
"eve": minor
---

Add `eve/channels/webhook` with the shared `WebhookVerifier` type and the `constantTimeCompare`, `verifyHmacSha256`, `verifyWebhookTimestamp`, and `runWebhookVerifier` primitives that the built-in channels now compose. The `GitHubWebhookVerifier`, `LinearWebhookVerifier`, `TelegramWebhookVerifier`, `DiscordWebhookVerifier`, and `TeamsWebhookVerifier` type exports are removed; import `WebhookVerifier` from `eve/channels/webhook` instead.
