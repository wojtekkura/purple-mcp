// Minimal stateless MCP Streamable HTTP transport. Port of cf-mcp's mcp.ts.
//
// Per MCP 2025-06 spec: client POSTs a JSON-RPC 2.0 message to /mcp; we reply
// with a JSON-RPC response (Content-Type: application/json). Only the
// JSON-response path is supported — sufficient for tool invocation. No sessions,
// no Durable Objects, no SSE.

import { newCorrelationId } from "./envelope.js";

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: unknown;
}

export interface JsonRpcSuccessResponse<T = unknown> {
  jsonrpc: "2.0";
  id: string | number | null;
  result: T;
}

export interface JsonRpcErrorResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  error: { code: number; message: string; data?: unknown };
}

export type JsonRpcResponse = JsonRpcSuccessResponse | JsonRpcErrorResponse;

export const RPC_PARSE_ERROR = -32700;
export const RPC_INVALID_REQUEST = -32600;
export const RPC_METHOD_NOT_FOUND = -32601;
export const RPC_INVALID_PARAMS = -32602;
export const RPC_INTERNAL_ERROR = -32603;
export const RPC_FORBIDDEN = -32001;

export interface ToolDescriptor {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

// A handler returns the JSON envelope string (the tool's wire payload). We wrap
// that into MCP's `content: [{type:'text', text:...}]` shape.
export type ToolHandler<C> = (ctx: C, args: Record<string, unknown>) => Promise<string>;

export interface ToolRegistry<C> {
  descriptors: ToolDescriptor[];
  handlers: Map<string, ToolHandler<C>>;
}

export const SERVER_INFO = {
  name: "purple-mcp",
  version: "0.1.0",
} as const;

export const PROTOCOL_VERSION = "2025-06-18";

export function rpcResult<T>(id: JsonRpcRequest["id"], result: T): JsonRpcSuccessResponse<T> {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

export function rpcError(
  id: JsonRpcRequest["id"],
  code: number,
  message: string,
  data?: unknown,
): JsonRpcErrorResponse {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data !== undefined ? { data } : {}) } };
}

export interface ToolCallResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

export function wrapEnvelope(envelopeJson: string): ToolCallResult {
  return { content: [{ type: "text", text: envelopeJson }] };
}

// Pre-dispatch errors (auth, scope) rendered as MCP isError=true tool results
// when reached via tools/call, in the purple envelope shape.
export function wrapErrorAsToolResult(
  message: string,
  details?: { code?: string; correlation_id?: string },
): ToolCallResult {
  const payload = {
    data: null,
    next_cursor: null,
    cache_meta: { hit: false, age_s: 0, ttl_s: 0 },
    api_endpoint_called: "<mcp dispatch>",
    correlation_id: details?.correlation_id ?? newCorrelationId(),
    error: {
      code: details?.code ?? "denied",
      http_status: null,
      upstream_errors: [],
      retry_after_s: null,
      hint: null,
      message,
    },
  };
  return { content: [{ type: "text", text: JSON.stringify(payload) }], isError: true };
}

// Dispatch a single JSON-RPC request. Caller is responsible for auth + audit;
// this is pure protocol routing + tool invocation.
export async function dispatchRpc<C>(
  req: JsonRpcRequest,
  registry: ToolRegistry<C>,
  ctxFactory: () => Promise<C> | C,
  hooks?: {
    onToolCall?: (name: string, args: Record<string, unknown>, ctx: C) => Promise<void> | void;
    onToolResult?: (name: string, ctx: C, isError: boolean) => Promise<void> | void;
  },
): Promise<JsonRpcResponse> {
  const { id, method, params } = req;

  if (method === "initialize") {
    return rpcResult(id, {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: { listChanged: false } },
      serverInfo: SERVER_INFO,
    });
  }

  if (method === "notifications/initialized") {
    return rpcResult(id ?? null, {});
  }

  if (method === "ping") {
    return rpcResult(id, {});
  }

  if (method === "tools/list") {
    return rpcResult(id, { tools: registry.descriptors });
  }

  if (method === "tools/call") {
    const p = (params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
    const name = p.name;
    const args = (p.arguments ?? {}) as Record<string, unknown>;
    if (!name || typeof name !== "string") {
      return rpcError(id, RPC_INVALID_PARAMS, "tools/call requires a `name`");
    }
    const handler = registry.handlers.get(name);
    if (!handler) {
      return rpcError(id, RPC_METHOD_NOT_FOUND, `unknown tool: ${name}`);
    }
    const ctx = await ctxFactory();
    await hooks?.onToolCall?.(name, args, ctx);
    try {
      const envelopeJson = await handler(ctx, args);
      const isError = envelopeJson.includes('"error":{');
      await hooks?.onToolResult?.(name, ctx, isError);
      return rpcResult(id, wrapEnvelope(envelopeJson));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      await hooks?.onToolResult?.(name, ctx, true);
      return rpcResult(id, wrapErrorAsToolResult(`Tool ${name} threw: ${msg}`));
    }
  }

  return rpcError(id, RPC_METHOD_NOT_FOUND, `unknown method: ${method}`);
}
