// Per-request SentinelOne console client. Port of purple-mcp's
// graphql_client_base.py + the REST inventory client, unified onto `fetch`.
//
// Differences from the Python source:
//   - No persistent httpx.AsyncClient; Workers have no cross-request client
//     state, so every PurpleClient is per-invocation and uses global `fetch`.
//   - Retry policy unified with cf-mcp: retry transport errors + 502/503/504
//     with exponential backoff + jitter (max 3 attempts). 429 is surfaced
//     verbatim with retry_after_s so the agent plans its own backoff (the
//     Python base only retried transport errors; this is a superset).

import {
  UpstreamErrorEntry,
  PurpleMcpError,
  UpstreamError,
  classifyHttpStatus,
} from "./errors.js";
import { getUserAgent } from "./user-agent.js";

const RETRYABLE_STATUSES = new Set([502, 503, 504]);
const RETRY_MAX_ATTEMPTS = 3;
const RETRY_BASE_DELAY_MS = 500;
const RETRY_MULTIPLIER = 2.0;
const RETRY_JITTER_FRAC = 0.25;

export interface PurpleClientOptions {
  baseUrl: string;          // console base, e.g. https://tenant.sentinelone.net (no trailing slash)
  consoleToken: string;     // shared SentinelOne console API token
  userId?: string;          // appended to the User-Agent for server-side attribution
  fetchImpl?: typeof fetch; // test override
}

export interface RawRequestArgs {
  method: string;
  path: string;                  // absolute path beginning with '/'
  params?: Record<string, string | number | boolean | undefined>;
  jsonBody?: unknown;
  // Send exactly once. For state-changing calls (e.g. agent upgrade) where a
  // retried request could queue the same action twice.
  noRetry?: boolean;
}

export class PurpleClient {
  private readonly baseUrl: string;
  private readonly consoleToken: string;
  private readonly userAgent: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: PurpleClientOptions) {
    if (!opts.consoleToken) throw new Error("PurpleClient requires a non-empty consoleToken");
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.consoleToken = opts.consoleToken;
    this.userAgent = getUserAgent(opts.userId);
    const fallback: typeof fetch = (input, init) => fetch(input, init);
    this.fetchImpl = opts.fetchImpl ?? fallback;
  }

  // Execute a GraphQL POST against an absolute endpoint path. Returns the
  // `data` object; raises on HTTP error, GraphQL `errors`, or missing data —
  // matching graphql_client_base.execute_query.
  async graphql(
    endpointPath: string,
    query: string,
    variables: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    const body = await this.requestJson({
      method: "POST",
      path: endpointPath,
      jsonBody: { query, variables },
    });

    const errors = body["errors"];
    if (Array.isArray(errors) && errors.length > 0) {
      const upstream = errors.filter(
        (e): e is UpstreamErrorEntry => typeof e === "object" && e !== null,
      );
      throw new UpstreamError(`GraphQL query returned ${errors.length} error(s).`, {
        http_status: 200,
        upstream_errors: upstream,
        hint: "Check the query syntax, filter field names, and that the console token has access to this dataset.",
      });
    }

    const data = body["data"];
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      throw new UpstreamError("GraphQL response missing 'data' object.", { http_status: 200 });
    }
    return data as Record<string, unknown>;
  }

  // REST/JSON request with retry + error classification.
  async requestJson(args: RawRequestArgs): Promise<Record<string, unknown>> {
    const method = args.method.toUpperCase();

    let lastResponse: Response | null = null;
    let lastError: Error | null = null;
    const maxAttempts = args.noRetry ? 1 : RETRY_MAX_ATTEMPTS;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        lastResponse = await this.send(method, args.path, args.params, args.jsonBody);
      } catch (e) {
        lastError = e as Error;
        if (attempt + 1 >= maxAttempts) {
          throw new UpstreamError(
            `HTTP transport error after ${maxAttempts} attempt(s): ${lastError.message}`,
            { hint: "The SentinelOne console is unreachable. Check network and try again." },
          );
        }
        await sleep(jitteredDelay(attempt));
        continue;
      }

      if (RETRYABLE_STATUSES.has(lastResponse.status) && attempt + 1 < maxAttempts) {
        await sleep(jitteredDelay(attempt));
        continue;
      }
      break;
    }

    if (!lastResponse) {
      throw new UpstreamError(`No response received after ${RETRY_MAX_ATTEMPTS} attempts.`, {
        hint: "Internal error in the purple-mcp retry loop.",
      });
    }
    return await this.handleResponse(method, args.path, lastResponse);
  }

  private async send(
    method: string,
    path: string,
    params: RawRequestArgs["params"],
    jsonBody: unknown,
  ): Promise<Response> {
    const url = new URL(this.baseUrl + path);
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        if (v === undefined || v === null) continue;
        url.searchParams.append(k, String(v));
      }
    }
    const headers: Record<string, string> = {
      authorization: `Bearer ${this.consoleToken}`,
      accept: "application/json",
      "user-agent": this.userAgent,
    };
    const init: RequestInit = { method, headers };
    if (jsonBody !== undefined && jsonBody !== null) {
      headers["content-type"] = "application/json";
      init.body = JSON.stringify(jsonBody);
    }
    return this.fetchImpl(url.toString(), init);
  }

  private async handleResponse(
    method: string,
    path: string,
    response: Response,
  ): Promise<Record<string, unknown>> {
    if (response.status >= 200 && response.status < 300) {
      const text = await response.text();
      if (!text) return {};
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        throw new UpstreamError(`SentinelOne returned 2xx with non-JSON body for ${method} ${path}.`, {
          http_status: response.status,
          hint: "Unexpected payload format; check the console status page.",
        });
      }
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        throw new UpstreamError(`SentinelOne returned 2xx with non-object JSON body for ${method} ${path}.`, {
          http_status: response.status,
        });
      }
      return body as Record<string, unknown>;
    }

    let errBody: unknown = {};
    try {
      const text = await response.text();
      if (text) errBody = JSON.parse(text);
    } catch {
      /* swallow — errBody remains {} */
    }

    const upstream = extractUpstreamErrors(errBody);
    const retryAfter = parseRetryAfter(response.headers);
    const ExcCls = classifyHttpStatus(response.status);

    let hint: string | undefined;
    if (response.status === 429) {
      hint =
        "Hit the SentinelOne API rate limit. retry_after_s tells the agent how long to wait before re-issuing this call. purple-mcp does not retry 429 automatically.";
    } else if (response.status === 401 || response.status === 403) {
      hint = "The shared console token is missing, expired, or lacks permission for this dataset.";
    }

    const snippet = upstream.length ? JSON.stringify(upstream) : await safeBodyPreview(response);
    const message = `SentinelOne returned ${response.status} on ${method} ${path}: ${snippet}`;
    throw new ExcCls(message, {
      http_status: response.status,
      upstream_errors: upstream,
      retry_after_s: retryAfter,
      hint: hint ?? null,
    }) as PurpleMcpError;
  }
}

function extractUpstreamErrors(body: unknown): UpstreamErrorEntry[] {
  if (!body || typeof body !== "object") return [];
  const errs = (body as Record<string, unknown>).errors;
  if (!Array.isArray(errs)) return [];
  return errs.filter(
    (e): e is UpstreamErrorEntry => typeof e === "object" && e !== null && !Array.isArray(e),
  );
}

function parseRetryAfter(headers: Headers): number | null {
  const raw = headers.get("retry-after");
  if (!raw) return null;
  const n = parseInt(raw.trim(), 10);
  return Number.isFinite(n) ? n : null;
}

async function safeBodyPreview(response: Response): Promise<string> {
  try {
    const t = await response.clone().text();
    return JSON.stringify(t.slice(0, 200));
  } catch {
    return '""';
  }
}

function jitteredDelay(attempt: number): number {
  const base = RETRY_BASE_DELAY_MS * Math.pow(RETRY_MULTIPLIER, attempt);
  const span = base * RETRY_JITTER_FRAC;
  return base + (Math.random() * 2 - 1) * span;
}

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}
