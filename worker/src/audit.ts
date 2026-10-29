// Per-call audit: synchronous D1 write (authoritative) + fire-and-forget SIEM
// webhook (best-effort) via ctx.waitUntil. Port of cf-mcp's audit.ts. The D1 row
// is the source of truth; webhook failures are logged but never block the call.

import type { Env } from "./env.js";

export type AuditResult = "success" | "error" | "denied";

export interface AuditEntry {
  id: string;
  timestamp: string;
  user_id: string;
  tool: string;
  input_json: string | null;
  result: AuditResult;
  error_code: string | null;
  error_msg: string | null;
  ip: string | null;
  request_id: string | null;
  ray_id: string | null;
  latency_ms: number | null;
}

// Keys stripped from the audit input_json before persisting, regardless of tool.
const SECRET_KEYS = new Set([
  "authorization",
  "bearer",
  "token",
  "console_token",
  "consoletoken",
  "team_token",
  "teamtoken",
  "api_token",
  "api_key",
  "secret",
  "password",
  "value",
  "secret_text",
]);

const MAX_INPUT_BYTES = 4096;
const MAX_ERROR_MSG_BYTES = 1024;

export function sanitizeInput(args: unknown): string {
  const scrubbed = scrub(args, 0);
  let s = JSON.stringify(scrubbed);
  if (s.length > MAX_INPUT_BYTES) s = s.slice(0, MAX_INPUT_BYTES - 13) + '","TRUNCATED"';
  return s;
}

function scrub(value: unknown, depth: number): unknown {
  if (depth > 8) return "<depth-limit>";
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.map((v) => scrub(v, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEYS.has(k.toLowerCase())) out[k] = "<redacted>";
      else out[k] = scrub(v, depth + 1);
    }
    return out;
  }
  return String(value);
}

export function newAuditEntry(init: {
  userId: string;
  tool: string;
  input: unknown;
  ip: string | null;
  requestId: string | null;
  rayId: string | null;
}): AuditEntry {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    user_id: init.userId,
    tool: init.tool,
    input_json: init.input === undefined ? null : sanitizeInput(init.input),
    result: "success",
    error_code: null,
    error_msg: null,
    ip: init.ip,
    request_id: init.requestId,
    ray_id: init.rayId,
    latency_ms: null,
  };
}

export function setOutcome(entry: AuditEntry, envelopeJson: string, startMs: number): void {
  entry.latency_ms = Math.max(0, Date.now() - startMs);
  try {
    const env = JSON.parse(envelopeJson) as { error: { code: string; message?: string } | null };
    if (env.error) {
      entry.result = "error";
      entry.error_code = env.error.code;
      const msg = (env.error.message ?? "").toString();
      entry.error_msg = msg.length > MAX_ERROR_MSG_BYTES ? msg.slice(0, MAX_ERROR_MSG_BYTES) : msg;
    } else {
      entry.result = "success";
    }
  } catch {
    entry.result = "error";
    entry.error_code = "upstream";
    entry.error_msg = "envelope not parseable";
  }
}

export function setDenied(entry: AuditEntry, code: string, msg: string, startMs: number): void {
  entry.latency_ms = Math.max(0, Date.now() - startMs);
  entry.result = "denied";
  entry.error_code = code;
  entry.error_msg = msg.length > MAX_ERROR_MSG_BYTES ? msg.slice(0, MAX_ERROR_MSG_BYTES) : msg;
}

export async function writeAudit(env: Env, e: AuditEntry): Promise<void> {
  await env.AUDIT_DB.prepare(
    `INSERT INTO audit_log
       (id, timestamp, user_id, tool, input_json, result,
        error_code, error_msg, ip, request_id, ray_id, latency_ms)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
  )
    .bind(
      e.id,
      e.timestamp,
      e.user_id,
      e.tool,
      e.input_json,
      e.result,
      e.error_code,
      e.error_msg,
      e.ip,
      e.request_id,
      e.ray_id,
      e.latency_ms,
    )
    .run();
}

// Fire the SIEM webhook. One JSON event per audit row plus `source: "purple-mcp"`
// for SIEM routing. Single retry on transport/5xx; D1 has the authoritative copy.
export async function postSiem(siemUrl: string, e: AuditEntry): Promise<void> {
  if (!siemUrl) return;
  const body = JSON.stringify({ source: "purple-mcp", ...e });
  const init: RequestInit = {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  };
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(siemUrl, init);
      if (res.status < 500) {
        if (res.status >= 400) {
          console.warn(`SIEM webhook returned ${res.status} for audit ${e.id}`);
        }
        return;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`SIEM webhook transport error (attempt ${attempt + 1}): ${msg}`);
    }
  }
  console.warn(`SIEM webhook failed twice for audit ${e.id}; D1 still has the row`);
}
