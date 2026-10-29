// Unit coverage for the envelope builder, byte-clamp, and signed cursor.

import { describe, expect, it } from "vitest";
import {
  buildEnvelope,
  buildErrorEnvelope,
  clampToFitBytes,
  safeBuildEnvelope,
} from "../src/envelope.js";
import { ValidationError } from "../src/errors.js";
import { createCursorSigner } from "../src/cursor.js";

describe("envelope", () => {
  it("builds a success envelope with the standard fields", () => {
    const s = buildEnvelope({ data: { x: 1 }, api_endpoint_called: "POST /x", correlation_id: "cid" });
    const j = JSON.parse(s);
    expect(j.data).toEqual({ x: 1 });
    expect(j.error).toBeNull();
    expect(j.next_cursor).toBeNull();
    expect(j.api_endpoint_called).toBe("POST /x");
    expect(j.cache_meta).toEqual({ hit: false, age_s: 0, ttl_s: 0 });
  });

  it("renders an error envelope from an error payload", () => {
    const s = buildErrorEnvelope({
      error: {
        code: "not_found",
        http_status: 404,
        upstream_errors: [],
        retry_after_s: null,
        hint: "check the id",
        message: "missing",
      },
      api_endpoint_called: "POST /x",
      correlation_id: "cid",
    });
    const j = JSON.parse(s);
    expect(j.data).toBeNull();
    expect(j.error.code).toBe("not_found");
  });

  it("safeBuildEnvelope falls back to response_too_large past the ceiling", () => {
    const huge = { blob: "a".repeat(120_000) };
    const s = safeBuildEnvelope({ data: huge, api_endpoint_called: "POST /x", correlation_id: "cid" });
    const j = JSON.parse(s);
    expect(j.error.code).toBe("response_too_large");
  });

  it("clampToFitBytes keeps a prefix that fits the budget", () => {
    const items = Array.from({ length: 500 }, (_, i) => ({ i, pad: "x".repeat(50) }));
    const { kept, truncated } = clampToFitBytes(items, (k) => ({ items: k, count: k.length }), 4000);
    expect(kept.length).toBeGreaterThan(0);
    expect(kept.length).toBeLessThan(items.length);
    expect(kept.length + truncated).toBe(items.length);
  });
});

describe("cursor signer", () => {
  it("round-trips a signed payload", async () => {
    const signer = await createCursorSigner("test-hmac-key-0000000000000000");
    const payload = { v: 1, queryId: "q1", forwardTag: "ft", lastStepSeen: 3, totalSteps: 7, cumulativeRows: 12 };
    const cursor = await signer.sign(payload);
    expect(cursor.startsWith("psl1.")).toBe(true);
    expect(await signer.verify(cursor)).toEqual(payload);
  });

  it("rejects a tampered cursor", async () => {
    const signer = await createCursorSigner("test-hmac-key-0000000000000000");
    const cursor = await signer.sign({ a: 1 });
    const tampered = cursor.slice(0, -2) + (cursor.endsWith("AA") ? "BB" : "AA");
    await expect(signer.verify(tampered)).rejects.toBeInstanceOf(ValidationError);
  });

  it("rejects a cursor minted by a different key", async () => {
    const a = await createCursorSigner("key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const b = await createCursorSigner("key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    const cursor = await a.sign({ a: 1 });
    await expect(b.verify(cursor)).rejects.toBeInstanceOf(ValidationError);
  });
});
