// Worker entry — Streamable HTTP MCP server with per-user bearer auth, scope
// gate, D1 audit, and fire-and-forget SIEM webhook. Port of cf-mcp's index.ts.

import { allowedIps, exclusionToolsEnabled, type Env } from "./env.js";
import {
  AuthedUser,
  assertIpAllowed,
  assertToolScope,
  authenticate,
  buildToolContext,
  extractMeta,
  RequestMeta,
} from "./auth.js";
import { handleAdmin } from "./admin/tokens.js";
import { resolveSecrets, type ResolvedSecrets } from "./secrets.js";
import { EXCLUSION_WRITE_TOOLS, TOOL_DESCRIPTORS, TOOL_HANDLERS } from "./tools/index.js";
import {
  dispatchRpc,
  JsonRpcRequest,
  rpcError,
  rpcResult,
  RPC_FORBIDDEN,
  RPC_INVALID_REQUEST,
  RPC_METHOD_NOT_FOUND,
  RPC_PARSE_ERROR,
  ToolDescriptor,
  ToolHandler,
  ToolRegistry,
  wrapErrorAsToolResult,
} from "./mcp.js";
import { isPurpleMcpError } from "./errors.js";
import {
  AuditEntry,
  newAuditEntry,
  postSiem,
  setDenied,
  setOutcome,
  writeAudit,
} from "./audit.js";
import { TOOL_SCOPES } from "./scopes.js";

// Hard cap on JSON-RPC batch size — defends against a single authenticated POST
// fanning out hundreds of tool calls.
const MAX_BATCH_SIZE = 25;

// Compile-time invariants: keep scopes.ts and tools/index.ts in sync.
{
  for (const tool of Object.keys(TOOL_SCOPES)) {
    if (!(tool in TOOL_HANDLERS)) throw new Error(`scopes.ts references missing tool: ${tool}`);
  }
  for (const tool of Object.keys(TOOL_HANDLERS)) {
    if (!(tool in TOOL_SCOPES)) throw new Error(`tool ${tool} has no scope mapping`);
  }
}

function buildRegistry(exclude: ReadonlySet<string>): ToolRegistry<unknown> {
  return {
    descriptors: TOOL_DESCRIPTORS.filter((d) => !exclude.has(d.name)) as ToolDescriptor[],
    handlers: new Map<string, ToolHandler<unknown>>(
      Object.entries(TOOL_HANDLERS)
        .filter(([name]) => !exclude.has(name))
        .map(([name, fn]) => [name, fn as unknown as ToolHandler<unknown>]),
    ),
  };
}

const DISABLED_EXCLUSION_TOOLS: ReadonlySet<string> = new Set(EXCLUSION_WRITE_TOOLS);
const REGISTRY = buildRegistry(new Set());
// Served while PURPLE_ENABLE_EXCLUSION_TOOLS is off: create_path_exclusion is neither
// listed nor callable (exclusions go through the SOAR integration for now).
const REGISTRY_WITHOUT_EXCLUSION_WRITES = buildRegistry(DISABLED_EXCLUSION_TOOLS);

function registryFor(env: Env): ToolRegistry<unknown> {
  return exclusionToolsEnabled(env) ? REGISTRY : REGISTRY_WITHOUT_EXCLUSION_WRITES;
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "GET" && url.pathname === "/health") {
      return new Response(
        JSON.stringify({ ok: true, name: "purple-mcp", tools: registryFor(env).descriptors.length }),
        { headers: { "content-type": "application/json" } },
      );
    }

    if (url.pathname.startsWith("/admin/") || url.pathname === "/mcp") {
      let secrets: ResolvedSecrets;
      try {
        secrets = await resolveSecrets(env);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.warn(`secrets resolution failed: ${msg}`);
        return new Response(JSON.stringify({ error: "service-unavailable" }), {
          status: 503,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.pathname.startsWith("/admin/")) return await handleAdmin(req, env, secrets);
      return await handleMcp(req, env, ctx, secrets);
    }

    return new Response("not found", { status: 404 });
  },
};

async function handleMcp(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  secrets: ResolvedSecrets,
): Promise<Response> {
  if (req.method !== "POST") {
    return new Response("method not allowed", { status: 405, headers: { allow: "POST" } });
  }

  const meta = extractMeta(req);
  const startMs = Date.now();

  try {
    assertIpAllowed(allowedIps(env), meta.ip);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const entry = preAuthEntry(meta);
    setDenied(entry, "auth", msg, startMs);
    ctx.waitUntil(persistAudit(env, secrets, entry));
    return jsonRpcResponse(rpcError(null, RPC_FORBIDDEN, msg), 403);
  }

  let user: AuthedUser;
  try {
    user = await authenticate(req, env);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const code = isPurpleMcpError(e) ? e.code : "auth";
    const entry = preAuthEntry(meta);
    setDenied(entry, code, msg, startMs);
    ctx.waitUntil(persistAudit(env, secrets, entry));
    return jsonRpcResponse(rpcError(null, RPC_FORBIDDEN, msg), 401);
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonRpcResponse(rpcError(null, RPC_PARSE_ERROR, "request body is not valid JSON"));
  }

  const requests: JsonRpcRequest[] = Array.isArray(body)
    ? (body as JsonRpcRequest[])
    : [body as JsonRpcRequest];

  if (requests.length > MAX_BATCH_SIZE) {
    return jsonRpcResponse(
      rpcError(null, RPC_INVALID_REQUEST, `batch too large: ${requests.length} > ${MAX_BATCH_SIZE}`),
      413,
    );
  }

  const toolCtx = await buildToolContext(user, env, meta, secrets);

  const responses = await Promise.all(
    requests.map((r) => dispatchOne(r, user, env, secrets, meta, ctx, toolCtx, startMs)),
  );

  const out = Array.isArray(body) ? responses : responses[0];
  return jsonRpcResponse(out);
}

async function dispatchOne(
  r: JsonRpcRequest,
  user: AuthedUser,
  env: Env,
  secrets: ResolvedSecrets,
  meta: RequestMeta,
  execCtx: ExecutionContext,
  toolCtx: unknown,
  startMs: number,
): Promise<unknown> {
  const registry = registryFor(env);
  if (r.method !== "tools/call") {
    return await dispatchRpc(r, registry, () => toolCtx);
  }

  const params = (r.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
  const toolName = typeof params.name === "string" ? params.name : "<missing>";
  const args = (params.arguments ?? {}) as Record<string, unknown>;
  const entry = newAuditEntry({
    userId: user.record.userId,
    tool: toolName,
    input: args,
    ip: meta.ip,
    requestId: meta.requestId,
    rayId: meta.rayId,
  });

  if (!(toolName in TOOL_HANDLERS)) {
    setDenied(entry, "not_found", `unknown tool: ${toolName}`, startMs);
    execCtx.waitUntil(persistAudit(env, secrets, entry));
    return rpcError(r.id ?? null, RPC_METHOD_NOT_FOUND, `unknown tool: ${toolName}`);
  }

  if (!registry.handlers.has(toolName)) {
    const msg = `${toolName} is disabled on this server (PURPLE_ENABLE_EXCLUSION_TOOLS is off); exclusions are applied through the SOAR integration.`;
    setDenied(entry, "denied", msg, startMs);
    execCtx.waitUntil(persistAudit(env, secrets, entry));
    return rpcResult(r.id ?? null, wrapErrorAsToolResult(msg, { code: "denied" }));
  }

  try {
    assertToolScope(user, toolName);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const code = isPurpleMcpError(e) ? e.code : "denied";
    setDenied(entry, code, msg, startMs);
    execCtx.waitUntil(persistAudit(env, secrets, entry));
    return rpcResult(r.id ?? null, wrapErrorAsToolResult(msg, { code }));
  }

  const dispatchStart = Date.now();
  const resp = await dispatchRpc(r, registry, () => toolCtx);

  let envelopeJson = "";
  if ("result" in resp) {
    const result = resp.result as { content?: Array<{ text?: string }> };
    envelopeJson = result.content?.[0]?.text ?? "";
  }
  setOutcome(entry, envelopeJson, dispatchStart);
  execCtx.waitUntil(persistAudit(env, secrets, entry));

  return resp;
}

function preAuthEntry(meta: RequestMeta): AuditEntry {
  return newAuditEntry({
    userId: "unknown",
    tool: "<auth>",
    input: undefined,
    ip: meta.ip,
    requestId: meta.requestId,
    rayId: meta.rayId,
  });
}

async function persistAudit(env: Env, secrets: ResolvedSecrets, entry: AuditEntry): Promise<void> {
  try {
    await writeAudit(env, entry);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.warn(`audit D1 write failed for ${entry.id}: ${msg}`);
  }
  try {
    await postSiem(secrets.siemWebhookUrl, entry);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    console.warn(`SIEM webhook failed for ${entry.id}: ${msg}`);
  }
}

function jsonRpcResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export { REGISTRY };
