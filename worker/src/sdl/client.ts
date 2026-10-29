// SDL Query API client. Port of purple-mcp's libs/sdl/sdl_query_client.py onto
// `fetch`. The SDL base URL is the console base with `/sdl` appended (see the
// Python SDLSettings.validate_base_url). Stateless: each call is independent;
// the `X-Dataset-Query-Forward-Tag` returned by submit must be echoed on every
// follow-up ping/delete so the backend routes to the same query instance.
//
//   submit  POST   /sdl/v2/api/queries                       -> {result, forwardTag}
//   ping    GET    /sdl/v2/api/queries/{id}?lastStepSeen=N   (+ forward-tag header)
//   delete  DELETE /sdl/v2/api/queries/{id}                  (+ forward-tag header)

import { UpstreamError, classifyHttpStatus, PurpleMcpError } from "../errors.js";
import { getUserAgent } from "../user-agent.js";
import {
  SdlPqAttributes,
  SdlQueryPriority,
  SdlQueryResult,
  parseSdlResult,
} from "./types.js";

const SDL_API_PATH = "/sdl";
const FORWARD_TAG_HEADER = "x-dataset-query-forward-tag";

const RETRYABLE_STATUSES = new Set([429, 500, 502, 503, 504]);
const RETRY_MAX_ATTEMPTS = 4; // http_max_retries(3) + 1, matching the Python policy
const RETRY_BASE_DELAY_MS = 100;
const RETRY_MAX_DELAY_MS = 5000;

export interface SdlClientOptions {
  consoleBaseUrl: string;  // e.g. https://tenant.sentinelone.net (no trailing slash, no /sdl)
  consoleToken: string;
  userId?: string;
  fetchImpl?: typeof fetch;
}

export interface SdlSubmitArgs {
  startTime: string;       // ISO-8601, relative ('24h'), or epoch (s/ms/ns) — passed through
  endTime: string;
  pq: SdlPqAttributes;
  tenant?: boolean;
  accountIds?: string[];
  queryPriority?: SdlQueryPriority;
}

export interface SdlSubmitResult {
  result: SdlQueryResult;
  forwardTag: string;
}

export class SdlClient {
  private readonly base: string;       // includes /sdl
  private readonly token: string;
  private readonly userAgent: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: SdlClientOptions) {
    if (!opts.consoleToken) throw new Error("SdlClient requires a non-empty consoleToken");
    const root = opts.consoleBaseUrl.replace(/\/+$/, "");
    this.base = root.endsWith(SDL_API_PATH) ? root : root + SDL_API_PATH;
    this.token = opts.consoleToken;
    this.userAgent = getUserAgent(opts.userId);
    const fallback: typeof fetch = (input, init) => fetch(input, init);
    this.fetchImpl = opts.fetchImpl ?? fallback;
  }

  async submit(args: SdlSubmitArgs): Promise<SdlSubmitResult> {
    const payload: Record<string, unknown> = {
      startTime: args.startTime,
      endTime: args.endTime,
      queryType: "PQ",
      queryPriority: args.queryPriority ?? "LOW",
      pq: {
        query: args.pq.query,
        resultType: args.pq.resultType,
        frequency: args.pq.frequency,
      },
    };
    if (args.tenant !== undefined) payload["tenant"] = args.tenant;
    if (args.accountIds !== undefined) payload["accountIds"] = args.accountIds;

    const res = await this.request("POST", "/v2/api/queries", { jsonBody: payload });
    const forwardTag = res.headers.get(FORWARD_TAG_HEADER) ?? "";
    const body = await this.json(res, "POST", "/v2/api/queries");
    if (!forwardTag) {
      throw new UpstreamError("SDL submit succeeded but returned no X-Dataset-Query-Forward-Tag.", {
        hint: "The SDL backend did not provide a routing tag; retry the query.",
      });
    }
    return { result: parseSdlResult(body), forwardTag };
  }

  async ping(queryId: string, forwardTag: string, lastStepSeen: number): Promise<SdlQueryResult> {
    const res = await this.request("GET", `/v2/api/queries/${encodeURIComponent(queryId)}`, {
      params: { lastStepSeen },
      extraHeaders: { [FORWARD_TAG_HEADER]: forwardTag },
    });
    const body = await this.json(res, "GET", `/v2/api/queries/${queryId}`);
    return parseSdlResult(body);
  }

  // Best-effort cleanup. Never throws — a failed delete just leaves the query to
  // expire by its server-side TTL (~30s).
  async deleteQuery(queryId: string, forwardTag: string): Promise<boolean> {
    try {
      const res = await this.request("DELETE", `/v2/api/queries/${encodeURIComponent(queryId)}`, {
        extraHeaders: { [FORWARD_TAG_HEADER]: forwardTag },
      });
      return res.status === 204;
    } catch {
      return false;
    }
  }

  private async request(
    method: string,
    path: string,
    opts: {
      params?: Record<string, string | number | boolean | undefined>;
      jsonBody?: unknown;
      extraHeaders?: Record<string, string>;
    } = {},
  ): Promise<Response> {
    let lastErr: Error | null = null;
    for (let attempt = 0; attempt < RETRY_MAX_ATTEMPTS; attempt++) {
      let res: Response;
      try {
        res = await this.send(method, path, opts);
      } catch (e) {
        lastErr = e as Error;
        if (attempt + 1 >= RETRY_MAX_ATTEMPTS) {
          throw new UpstreamError(`SDL transport error after ${RETRY_MAX_ATTEMPTS} attempts: ${lastErr.message}`, {
            hint: "The SDL endpoint is unreachable.",
          });
        }
        await sleep(expoJitter(attempt));
        continue;
      }
      if (RETRYABLE_STATUSES.has(res.status) && attempt + 1 < RETRY_MAX_ATTEMPTS) {
        await sleep(expoJitter(attempt));
        continue;
      }
      if (res.status >= 400 && res.status !== 204) {
        await this.raiseForStatus(method, path, res);
      }
      return res;
    }
    throw new UpstreamError("SDL request exhausted retries with no response.");
  }

  private async send(
    method: string,
    path: string,
    opts: {
      params?: Record<string, string | number | boolean | undefined>;
      jsonBody?: unknown;
      extraHeaders?: Record<string, string>;
    },
  ): Promise<Response> {
    const url = new URL(this.base + path);
    if (opts.params) {
      for (const [k, v] of Object.entries(opts.params)) {
        if (v === undefined || v === null) continue;
        url.searchParams.append(k, String(v));
      }
    }
    const headers: Record<string, string> = {
      authorization: `Bearer ${this.token}`,
      accept: "application/json",
      "user-agent": this.userAgent,
      ...(opts.extraHeaders ?? {}),
    };
    const init: RequestInit = { method, headers };
    if (opts.jsonBody !== undefined && opts.jsonBody !== null) {
      headers["content-type"] = "application/json";
      init.body = JSON.stringify(opts.jsonBody);
    }
    return this.fetchImpl(url.toString(), init);
  }

  private async json(res: Response, method: string, path: string): Promise<Record<string, unknown>> {
    const text = await res.text();
    if (!text) return {};
    try {
      const body = JSON.parse(text);
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        throw new Error("non-object");
      }
      return body as Record<string, unknown>;
    } catch {
      throw new UpstreamError(`SDL returned a non-JSON body for ${method} ${path}.`, {
        http_status: res.status,
      });
    }
  }

  private async raiseForStatus(method: string, path: string, res: Response): Promise<never> {
    let preview = "";
    try {
      preview = (await res.clone().text()).slice(0, 200);
    } catch {
      /* ignore */
    }
    const ExcCls = classifyHttpStatus(res.status);
    const retryAfter = parseInt(res.headers.get("retry-after") ?? "", 10);
    throw new ExcCls(`SDL returned ${res.status} on ${method} ${path}: ${JSON.stringify(preview)}`, {
      http_status: res.status,
      retry_after_s: Number.isFinite(retryAfter) ? retryAfter : null,
    }) as PurpleMcpError;
  }
}

function expoJitter(attempt: number): number {
  const base = Math.min(RETRY_MAX_DELAY_MS, RETRY_BASE_DELAY_MS * Math.pow(2, attempt));
  return base + Math.random() * base; // initial=0.1s, exp_base=2, max=5s, jitter — same spirit as Python
}

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}
