// Per-call context + the runTool envelope wrapper. Port of cf-mcp's tool-base.ts,
// adapted to purple-mcp's three upstream surfaces (GraphQL, REST, SDL).
//
// Every tool is a closure (ctx, args) => Promise<string> returning the wire-format
// JSON envelope. `runTool` captures the try/PurpleMcpError/envelope-build pattern.

import { PurpleClient } from "./http-client.js";
import { SdlClient } from "./sdl/client.js";
import type { CursorSigner } from "./cursor.js";
import {
  buildErrorEnvelope,
  newCorrelationId,
  safeBuildEnvelope,
} from "./envelope.js";
import { PurpleMcpError, isPurpleMcpError, ValidationError } from "./errors.js";

// Absolute endpoint paths resolved from env, shared by every tool.
export interface PurpleEndpoints {
  consoleGraphql: string;       // Purple AI
  alertsGraphql: string;
  misconfigurationsGraphql: string;
  vulnerabilitiesGraphql: string;
  inventoryRest: string;
}

// Purple AI request identity (non-secret bits from [vars], team token from secrets).
export interface PurpleAiConfig {
  accountId: string;
  teamToken: string;
  sessionId: string;
  emailAddress: string;
  consoleVersion: string;
}

export interface SdlRuntime {
  client: SdlClient;
  budgetMs: number;
  intervalMs: number;
  maxResults: number;
}

// Per-request context. Lifetime = one MCP tool call.
export interface ToolContext {
  client: PurpleClient;
  // Client on the separate write token (PURPLE_CONSOLE_WRITE_TOKEN); null when
  // that secret is unset, so write tools fail closed instead of using `client`.
  writeClient: PurpleClient | null;
  // PURPLE_ENABLE_EXCLUSION_TOOLS; create_path_exclusion fails closed when false.
  exclusionToolsEnabled: boolean;
  sdl: SdlRuntime;
  endpoints: PurpleEndpoints;
  purpleAi: PurpleAiConfig;
  cursorSigner: CursorSigner;
  // Optional account-id scoping carried on the user's KV record (SDL/Purple AI).
  accountIdsDefault: string[] | null;
  requestId: string;
  rayId: string | null;
  userId: string;
  scopes: ReadonlySet<string>;
}

export interface ToolResult {
  data: unknown;
  next_cursor?: string | null;
}

export type ToolFn = (ctx: ToolContext, args: Record<string, unknown>) => Promise<string>;

export async function runTool(
  endpoint: string,
  inner: () => Promise<ToolResult>,
): Promise<string> {
  const correlation_id = newCorrelationId();
  try {
    const result = await inner();
    return safeBuildEnvelope({
      data: result.data,
      next_cursor: result.next_cursor ?? null,
      api_endpoint_called: endpoint,
      correlation_id,
    });
  } catch (e) {
    if (isPurpleMcpError(e)) {
      return buildErrorEnvelope({ error: e, api_endpoint_called: endpoint, correlation_id });
    }
    const msg = e instanceof Error ? e.message : String(e);
    return buildErrorEnvelope({
      error: {
        code: "upstream",
        http_status: null,
        upstream_errors: [],
        retry_after_s: null,
        hint: null,
        message: `Unhandled error: ${msg}`,
      },
      api_endpoint_called: endpoint,
      correlation_id,
    });
  }
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

export function requireString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new ValidationError(`${name} must be a non-empty string.`);
  }
  return value;
}

export function optionalString(value: unknown, name: string): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") throw new ValidationError(`${name} must be a string if provided.`);
  return value;
}

export function optionalInt(value: unknown, name: string, fallback: number): number {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new ValidationError(`${name} must be an integer.`);
  }
  return value;
}

// Clamp an integer into [min, max] with a default. Used for `first`/`limit`.
export function boundedInt(
  value: unknown,
  name: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const n = optionalInt(value, name, fallback);
  if (n < min || n > max) {
    throw new ValidationError(`${name} must be between ${min} and ${max}.`);
  }
  return n;
}

export function optionalBool(value: unknown, name: string, fallback: boolean): boolean {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== "boolean") throw new ValidationError(`${name} must be a boolean.`);
  return value;
}

export function optionalRecord(value: unknown, name: string): Record<string, unknown> | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new ValidationError(`${name} must be an object if provided.`);
  }
  return value as Record<string, unknown>;
}

export function optionalStringArray(value: unknown, name: string): string[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
    throw new ValidationError(`${name} must be an array of strings.`);
  }
  return value;
}

// Parse a JSON filter string (tools accept filters as a JSON string, matching
// the Python `filters: str | None` signature). Returns undefined when absent.
export function parseJsonFilters(value: unknown, name: string): unknown {
  const s = optionalString(value, name);
  if (s === undefined || s.trim() === "") return undefined;
  try {
    return JSON.parse(s);
  } catch {
    throw new ValidationError(`${name} must be a valid JSON string.`, {
      hint: 'Example: {"severity":["HIGH","CRITICAL"]}',
    });
  }
}

export function reExportPurpleMcpError(): typeof PurpleMcpError {
  return PurpleMcpError;
}
