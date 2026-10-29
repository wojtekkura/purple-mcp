// Typed exception hierarchy + wire-format error payload. Same shape as cf-mcp's
// errors.ts so the SOC agent sees a uniform error contract across MCP servers.
//
// Upstream SentinelOne GraphQL errors are preserved verbatim under `upstream_errors`
// (analogous to cf-mcp's `cf_errors`) so the agent keeps diagnostic context.

export type ErrorCode =
  | "rate_limited"
  | "auth"
  | "not_found"
  | "validation"
  | "upstream"
  | "response_too_large"
  | "denied";

export interface UpstreamErrorEntry {
  message?: string;
  [k: string]: unknown;
}

export interface ErrorPayload {
  code: ErrorCode;
  http_status: number | null;
  upstream_errors: UpstreamErrorEntry[];
  retry_after_s: number | null;
  hint: string | null;
  message: string;
}

export interface PurpleMcpErrorOpts {
  http_status?: number | null;
  upstream_errors?: UpstreamErrorEntry[];
  retry_after_s?: number | null;
  hint?: string | null;
}

export class PurpleMcpError extends Error {
  readonly code: ErrorCode = "upstream";
  readonly http_status: number | null;
  readonly upstream_errors: UpstreamErrorEntry[];
  readonly retry_after_s: number | null;
  readonly hint: string | null;

  constructor(message: string, opts: PurpleMcpErrorOpts = {}) {
    super(message);
    this.name = this.constructor.name;
    this.http_status = opts.http_status ?? null;
    this.upstream_errors = opts.upstream_errors ?? [];
    this.retry_after_s = opts.retry_after_s ?? null;
    this.hint = opts.hint ?? null;
  }

  toPayload(): ErrorPayload {
    return {
      code: this.code,
      http_status: this.http_status,
      upstream_errors: this.upstream_errors,
      retry_after_s: this.retry_after_s,
      hint: this.hint,
      message: this.message,
    };
  }
}

export class AuthError extends PurpleMcpError { override readonly code: ErrorCode = "auth"; }
export class NotFoundError extends PurpleMcpError { override readonly code: ErrorCode = "not_found"; }
export class ValidationError extends PurpleMcpError { override readonly code: ErrorCode = "validation"; }
export class RateLimitedError extends PurpleMcpError { override readonly code: ErrorCode = "rate_limited"; }
export class UpstreamError extends PurpleMcpError { override readonly code: ErrorCode = "upstream"; }
export class ResponseTooLargeError extends PurpleMcpError { override readonly code: ErrorCode = "response_too_large"; }
export class DeniedError extends PurpleMcpError { override readonly code: ErrorCode = "denied"; }

export function classifyHttpStatus(status: number): typeof PurpleMcpError {
  if (status === 401 || status === 403) return AuthError;
  if (status === 404) return NotFoundError;
  if (status === 429) return RateLimitedError;
  if (status >= 400 && status < 500) return ValidationError;
  return UpstreamError;
}

export function isPurpleMcpError(e: unknown): e is PurpleMcpError {
  return e instanceof PurpleMcpError;
}
