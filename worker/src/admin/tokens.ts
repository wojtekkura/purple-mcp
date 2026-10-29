// Admin surface — issue, list, revoke per-user MCP bearers. Port of cf-mcp's
// admin/tokens.ts. Bearer: PURPLE_MCP_ADMIN_KEY (disjoint from user MCP tokens).
//
// Issue flow (no per-user upstream token — one shared console token for all):
//   1. Admin POSTs {userId, name, scopes, accountIds?}.
//   2. We mint a fresh MCP token (32 bytes, base64url), hash it, write the user
//      record to KV under `token:<hash>`.
//   3. Return the MCP token to the caller ONCE — we store only its hash.

import type { Env } from "./../env.js";
import { constantTimeEqual, sha256Hex } from "./../crypto.js";
import { ALL_SCOPES } from "./../scopes.js";
import type { UserRecord } from "./../auth.js";
import type { ResolvedSecrets } from "./../secrets.js";

const KEY_PREFIX = "token:";
const USER_INDEX_KEY = (userId: string) => `userid:${userId}`;

interface IssueRequest {
  userId: string;
  name?: string;
  scopes: string[];
  accountIds?: string[];
}

export async function handleAdmin(
  req: Request,
  env: Env,
  secrets: ResolvedSecrets,
): Promise<Response> {
  if (!checkAdminAuth(req, secrets)) return json({ error: "unauthorized" }, 401);

  const url = new URL(req.url);
  const segments = url.pathname.split("/").filter(Boolean); // ['admin','tokens', ...]
  if (segments.length < 2 || segments[0] !== "admin" || segments[1] !== "tokens") {
    return json({ error: "not found" }, 404);
  }

  if (segments.length === 2) {
    if (req.method === "POST") return await issueToken(req, env);
    if (req.method === "GET") return await listTokens(env);
    return json({ error: "method not allowed" }, 405);
  }
  if (segments.length === 3 && req.method === "DELETE") {
    return await revokeToken(decodeURIComponent(segments[2]!), env);
  }
  return json({ error: "not found" }, 404);
}

function checkAdminAuth(req: Request, secrets: ResolvedSecrets): boolean {
  const h = req.headers.get("authorization");
  if (!h) return false;
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  if (!m) return false;
  return constantTimeEqual(m[1]!.trim(), secrets.adminKey);
}

async function issueToken(req: Request, env: Env): Promise<Response> {
  let body: IssueRequest;
  try {
    body = (await req.json()) as IssueRequest;
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }
  const err = validateIssueBody(body);
  if (err) return json({ error: err }, 400);

  const raw = crypto.getRandomValues(new Uint8Array(32));
  const mcpToken = "pml_" + base64Url(raw);
  const bearerHash = await sha256Hex(mcpToken);

  // One active bearer per userId: rotate by overwriting the prior record.
  const prevHash = await env.TOKENS_KV.get(USER_INDEX_KEY(body.userId));
  if (prevHash) await env.TOKENS_KV.delete(`${KEY_PREFIX}${prevHash}`);

  const record: UserRecord = {
    userId: body.userId,
    name: body.name,
    scopes: body.scopes,
    accountIds: (body.accountIds ?? []).map((s) => s.trim()).filter(Boolean),
    createdAt: new Date().toISOString(),
  };
  await env.TOKENS_KV.put(`${KEY_PREFIX}${bearerHash}`, JSON.stringify(record));
  await env.TOKENS_KV.put(USER_INDEX_KEY(body.userId), bearerHash);

  return json(
    {
      userId: body.userId,
      scopes: body.scopes,
      mcp_token: mcpToken,
      note: "store this securely; it is not recoverable",
      bearer_hash: bearerHash,
    },
    201,
  );
}

async function listTokens(env: Env): Promise<Response> {
  const out: UserRecord[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.TOKENS_KV.list({ prefix: KEY_PREFIX, cursor });
    for (const k of page.keys) {
      const raw = await env.TOKENS_KV.get(k.name);
      if (!raw) continue;
      try {
        out.push(JSON.parse(raw) as UserRecord);
      } catch {
        /* skip corrupt record */
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return json({ users: out, count: out.length });
}

async function revokeToken(userId: string, env: Env): Promise<Response> {
  const hash = await env.TOKENS_KV.get(USER_INDEX_KEY(userId));
  if (!hash) return json({ error: "not found" }, 404);
  await env.TOKENS_KV.delete(`${KEY_PREFIX}${hash}`);
  await env.TOKENS_KV.delete(USER_INDEX_KEY(userId));
  return json({ revoked: userId });
}

function validateIssueBody(b: unknown): string | null {
  if (!b || typeof b !== "object" || Array.isArray(b)) return "body must be an object";
  const r = b as Record<string, unknown>;
  if (typeof r.userId !== "string" || !r.userId.trim()) return "userId required";
  if (!Array.isArray(r.scopes) || !r.scopes.every((s) => typeof s === "string")) {
    return "scopes must be string[]";
  }
  const allowedSet: ReadonlySet<string> = new Set(ALL_SCOPES);
  const bad = (r.scopes as string[]).filter((s) => !allowedSet.has(s));
  if (bad.length) return `unknown scopes: ${bad.join(", ")} (allowed: ${ALL_SCOPES.join(", ")})`;
  if (r.accountIds !== undefined) {
    if (!Array.isArray(r.accountIds) || !r.accountIds.every((s) => typeof s === "string")) {
      return "accountIds must be string[] if provided";
    }
  }
  if (r.name !== undefined && typeof r.name !== "string") return "name must be a string if provided";
  return null;
}

function base64Url(buf: Uint8Array): string {
  let s = "";
  for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}
