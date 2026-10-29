// Uniform success/error envelope + 80KB byte ceiling. Same contract as cf-mcp's
// envelope.ts. The ceiling is a conservative 4-bytes-per-token estimate of the
// MCP client's ~25K-token output budget; exceeding it returns `response_too_large`
// instead of silently truncating.

import { PurpleMcpError, ErrorPayload, ResponseTooLargeError } from "./errors.js";

export const RESPONSE_BYTE_CEILING = 80_000;

// Working budget for the tool's `data` payload. The remainder (~3KB) covers the
// envelope wrapper + a small safety margin.
export const DATA_BYTE_BUDGET = RESPONSE_BYTE_CEILING - 3_000;

const VESTIGIAL_CACHE_META = { hit: false, age_s: 0, ttl_s: 0 } as const;

export interface SuccessEnvelope {
  data: unknown;
  next_cursor: string | null;
  cache_meta: typeof VESTIGIAL_CACHE_META;
  api_endpoint_called: string;
  correlation_id: string;
  error: null;
}

export interface ErrorEnvelope {
  data: null;
  next_cursor: null;
  cache_meta: typeof VESTIGIAL_CACHE_META;
  api_endpoint_called: string;
  correlation_id: string;
  error: ErrorPayload;
}

export function newCorrelationId(): string {
  return crypto.randomUUID();
}

export interface BuildArgs {
  data: unknown;
  api_endpoint_called: string;
  correlation_id: string;
  next_cursor?: string | null;
}

// Builds the success envelope as a JSON string. Throws ResponseTooLargeError when
// serialized size exceeds the ceiling — caller renders that as an error envelope.
export function buildEnvelope(args: BuildArgs): string {
  const payload: SuccessEnvelope = {
    data: args.data,
    next_cursor: args.next_cursor ?? null,
    cache_meta: VESTIGIAL_CACHE_META,
    api_endpoint_called: args.api_endpoint_called,
    correlation_id: args.correlation_id,
    error: null,
  };
  const serialized = JSON.stringify(payload);
  if (new TextEncoder().encode(serialized).byteLength > RESPONSE_BYTE_CEILING) {
    throw new ResponseTooLargeError(
      `Response payload ${serialized.length} bytes exceeds ceiling ${RESPONSE_BYTE_CEILING} bytes.`,
      {
        hint:
          "Reduce the `first`/`limit` parameter, narrow the time range, or paginate with the cursor from a smaller query.",
      },
    );
  }
  return serialized;
}

export interface BuildErrorArgs {
  error: PurpleMcpError | ErrorPayload;
  api_endpoint_called: string;
  correlation_id: string;
}

export function buildErrorEnvelope(args: BuildErrorArgs): string {
  const payload: ErrorPayload =
    args.error instanceof PurpleMcpError ? args.error.toPayload() : args.error;
  const env: ErrorEnvelope = {
    data: null,
    next_cursor: null,
    cache_meta: VESTIGIAL_CACHE_META,
    api_endpoint_called: args.api_endpoint_called,
    correlation_id: args.correlation_id,
    error: payload,
  };
  return JSON.stringify(env);
}

// `buildEnvelope` + automatic error-envelope fallback on size overflow. Never throws.
export function safeBuildEnvelope(args: BuildArgs): string {
  try {
    return buildEnvelope(args);
  } catch (e) {
    if (e instanceof ResponseTooLargeError) {
      return buildErrorEnvelope({
        error: e,
        api_endpoint_called: args.api_endpoint_called,
        correlation_id: args.correlation_id,
      });
    }
    throw e;
  }
}

// Clamp a list of items so the serialized `data` fits under the byte budget.
// Binary-searches the longest prefix that fits. See cf-mcp envelope.ts for the
// usage pattern; identical semantics.
export function clampToFitBytes<T>(
  items: T[],
  buildData: (kept: T[]) => unknown,
  budget = DATA_BYTE_BUDGET,
): { kept: T[]; truncated: number } {
  if (items.length === 0) return { kept: [], truncated: 0 };

  const encoder = new TextEncoder();
  const measure = (n: number): number =>
    encoder.encode(JSON.stringify(buildData(items.slice(0, n)))).byteLength;

  if (measure(items.length) <= budget) {
    return { kept: items, truncated: 0 };
  }
  if (measure(1) > budget) {
    return { kept: [], truncated: items.length };
  }

  let lo = 1;
  let hi = items.length;
  let best = 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (measure(mid) <= budget) {
      best = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return { kept: items.slice(0, best), truncated: items.length - best };
}
