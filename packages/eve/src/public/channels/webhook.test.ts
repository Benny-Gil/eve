import { describe, expect, it, vi } from "vitest";

import {
  constantTimeCompare,
  runWebhookVerifier,
  signHmacSha256,
  verifyHmacSha256,
  verifyWebhookTimestamp,
  type WebhookVerifier,
} from "#public/channels/webhook.js";

const SECRET = "webhook-secret";

describe("constantTimeCompare", () => {
  it("returns true only for identical strings", () => {
    expect(constantTimeCompare("abc", "abc")).toBe(true);
    expect(constantTimeCompare("abc", "abd")).toBe(false);
    expect(constantTimeCompare("", "")).toBe(true);
  });

  it("returns false for different lengths, including multibyte text", () => {
    expect(constantTimeCompare("abc", "abcd")).toBe(false);
    expect(constantTimeCompare("é", "e")).toBe(false);
    expect(constantTimeCompare("é", "ab")).toBe(false);
  });
});

describe("verifyHmacSha256", () => {
  const payload = JSON.stringify({ action: "created" });

  it("accepts a hex digest and rejects another secret", () => {
    const signature = signHmacSha256(payload, SECRET);

    expect(verifyHmacSha256({ payload, secret: SECRET, signature })).toBe(true);
    expect(verifyHmacSha256({ payload, secret: "other", signature })).toBe(false);
    expect(verifyHmacSha256({ payload: `${payload} `, secret: SECRET, signature })).toBe(false);
  });

  it("honors a header prefix", () => {
    const signature = `sha256=${signHmacSha256(payload, SECRET)}`;

    expect(verifyHmacSha256({ payload, prefix: "sha256=", secret: SECRET, signature })).toBe(true);
    expect(verifyHmacSha256({ payload, secret: SECRET, signature })).toBe(false);
  });

  it("honors a base64 digest encoding", () => {
    const signature = signHmacSha256(payload, SECRET, "base64");

    expect(verifyHmacSha256({ encoding: "base64", payload, secret: SECRET, signature })).toBe(true);
    expect(verifyHmacSha256({ payload, secret: SECRET, signature })).toBe(false);
  });

  it("rejects an empty or malformed signature", () => {
    expect(verifyHmacSha256({ payload, secret: SECRET, signature: "" })).toBe(false);
    expect(verifyHmacSha256({ payload, secret: SECRET, signature: "sha256=bad" })).toBe(false);
  });
});

describe("verifyWebhookTimestamp", () => {
  const now = 1_700_000_000_000;

  it("accepts timestamps inside the skew window and rejects the rest", () => {
    expect(verifyWebhookTimestamp({ maxSkewMs: 60_000, now, timestampMs: now })).toBe(true);
    expect(verifyWebhookTimestamp({ maxSkewMs: 60_000, now, timestampMs: now - 60_000 })).toBe(
      true,
    );
    expect(verifyWebhookTimestamp({ maxSkewMs: 60_000, now, timestampMs: now + 60_000 })).toBe(
      true,
    );
    expect(verifyWebhookTimestamp({ maxSkewMs: 60_000, now, timestampMs: now - 60_001 })).toBe(
      false,
    );
    expect(verifyWebhookTimestamp({ maxSkewMs: 60_000, now, timestampMs: now + 60_001 })).toBe(
      false,
    );
  });

  it("defaults now to the current time", () => {
    expect(verifyWebhookTimestamp({ maxSkewMs: 60_000, timestampMs: Date.now() })).toBe(true);
    expect(verifyWebhookTimestamp({ maxSkewMs: 60_000, timestampMs: Date.now() - 120_000 })).toBe(
      false,
    );
  });

  it("rejects malformed timestamps", () => {
    for (const timestampMs of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(verifyWebhookTimestamp({ maxSkewMs: 60_000, now, timestampMs })).toBe(false);
    }
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, -1])(
    "throws for an invalid maxSkewMs (%s)",
    (maxSkewMs) => {
      expect(() => verifyWebhookTimestamp({ maxSkewMs, now, timestampMs: now })).toThrow(
        "maxSkewMs must be a non-negative finite number",
      );
    },
  );
});

describe("runWebhookVerifier", () => {
  const request = new Request("https://example.com/webhook", { body: "{}", method: "POST" });

  it("passes the request and raw body to the verifier", async () => {
    const verifier = vi.fn<WebhookVerifier>(async () => true);

    await expect(runWebhookVerifier(verifier, request, "{}")).resolves.toBe("{}");
    expect(verifier).toHaveBeenCalledWith(request, "{}");
  });

  it("returns null for every falsy result", async () => {
    for (const value of [null, undefined, false, "", 0]) {
      await expect(runWebhookVerifier(async () => value, request, "{}")).resolves.toBeNull();
    }
  });

  it("returns a string result as the replacement body", async () => {
    await expect(runWebhookVerifier(() => '{"ok":true}', request, "{}")).resolves.toBe(
      '{"ok":true}',
    );
  });

  it("keeps the raw body for other truthy results", async () => {
    await expect(runWebhookVerifier(() => ({ sub: "svc" }), request, "{}")).resolves.toBe("{}");
  });

  it("propagates a thrown error", async () => {
    await expect(
      runWebhookVerifier(
        async () => {
          throw new Error("not authorized");
        },
        request,
        "{}",
      ),
    ).rejects.toThrow("not authorized");
  });
});
