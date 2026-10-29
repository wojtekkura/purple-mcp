// Bearer auth + KV lookup + scope gate + per-call ToolContext. Port of cf-mcp's
// auth.ts.
//
//   1. Hash the bearer -> look up KV.
//   2. 401 if not found.
//   3. Map the tool name to a required scope; deny if missing.
//   4. Hand the tool a ToolContext that uses the ONE shared console token from
//      Secrets Store (vt-mcp / cf-mcp pattern).
//
// We don't store per-user upstream tokens. Per-user attribution lives in our own
// D1 audit log; SentinelOne attributes every call to the shared token's principal.

import {
  type Env,
  exclusionToolsEnabled,
  isProduction,
  sdlMaxQueryResults,
  sdlPollBudgetMs,
  sdlPollIntervalMs,
} from "./env.js";
import { AuthError, DeniedError } from "./errors.js";
import { sha256Hex } from "./crypto.js";
import { TOOL_SCOPES, ScopeName, hasScope } from "./scopes.js";
import { PurpleClient } from "./http-client.js";
import { SdlClient } from "./sdl/client.js";
import { createCursorSigner } from "./cursor.js";
import { ToolContext, PurpleEndpoints, PurpleAiConfig } from "./tool-base.js";
import type { ResolvedSecrets } from "./secrets.js";

// What we store at `token:<sha256(bearer)>` in KV. No upstream token here — it
// lives in Secrets Store, shared by all users.
export interface UserRecord {
  userId: string;
  name?: string;
  scopes: string[];           // ScopeName values; stored as string[] for forward compat
  accountIds?: string[] | null; // optional SDL/Purple AI account-id scoping
  createdAt: string;          // ISO-8601
  lastUsed?: string;          // updated opportunistically; non-load-bearing
}

export interface AuthedUser {
  bearerHash: string;
  record: UserRecord;
  scopes: Set<string>;
}

export interface RequestMeta {
  requestId: string;
  rayId: string | null;
  ip: string | null;
}

export function extractMeta(req: Request): RequestMeta {
  const requestId = req.headers.get("x-request-id") ?? crypto.randomUUID();
  const rayId = req.headers.get("cf-ray");
  const ip = req.headers.get("cf-connecting-ip");
  return { requestId, rayId, ip };
}

function extractBearer(req: Request): string | null {
  const h = req.headers.get("authorization");
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  return m ? m[1]!.trim() : null;
}

export async function authenticate(req: Request, env: Env): Promise<AuthedUser> {
  const bearer = extractBearer(req);
  if (!bearer) throw new AuthError("Unauthorized.", { http_status: 401 });

  const bearerHash = await sha256Hex(bearer);
  const raw = await env.TOKENS_KV.get(`token:${bearerHash}`);
  if (!raw) {
    // Same message as the missing-bearer branch so an attacker can't enumerate.
    throw new AuthError("Unauthorized.", { http_status: 401 });
  }
  let record: UserRecord;
  try {
    record = JSON.parse(raw) as UserRecord;
  } catch {
    throw new AuthError("Corrupted user record in KV.", { http_status: 500 });
  }
  return { bearerHash, record, scopes: new Set(record.scopes) };
}

// Enforce the scope gate. Throws DeniedError if the user lacks the scope.
export function assertToolScope(user: AuthedUser, tool: string): void {
  const required: ScopeName | undefined = TOOL_SCOPES[tool];
  if (!required) return; // unknown tool -> dispatcher surfaces method_not_found
  if (!hasScope(user.scopes, required)) {
    throw new DeniedError(`Missing scope ${required} for tool ${tool}.`, {
      hint: `Grant the user the ${required} scope on their KV record.`,
    });
  }
}

function buildEndpoints(env: Env): PurpleEndpoints {
  return {
    consoleGraphql: env.PURPLE_CONSOLE_GRAPHQL_ENDPOINT,
    alertsGraphql: env.PURPLE_ALERTS_GRAPHQL_ENDPOINT,
    misconfigurationsGraphql: env.PURPLE_MISCONFIGURATIONS_GRAPHQL_ENDPOINT,
    vulnerabilitiesGraphql: env.PURPLE_VULNERABILITIES_GRAPHQL_ENDPOINT,
    inventoryRest: env.PURPLE_INVENTORY_RESTAPI_ENDPOINT,
  };
}

function buildPurpleAi(env: Env, secrets: ResolvedSecrets, requestId: string): PurpleAiConfig {
  return {
    accountId: env.PURPLE_AI_ACCOUNT_ID ?? "0",
    teamToken: secrets.teamToken,
    // The Python source mints a per-process UUID session; per-request is fine
    // for the stateless Worker and keeps Purple AI conversations isolated.
    sessionId: requestId,
    emailAddress: env.PURPLE_AI_EMAIL_ADDRESS ?? "",
    consoleVersion: env.PURPLE_AI_CONSOLE_VERSION ?? "S",
  };
}

// Build the ToolContext after auth + scope gate have passed.
export async function buildToolContext(
  user: AuthedUser,
  env: Env,
  meta: RequestMeta,
  secrets: ResolvedSecrets,
): Promise<ToolContext> {
  const baseUrl = env.PURPLE_CONSOLE_BASE_URL;
  const client = new PurpleClient({
    baseUrl,
    consoleToken: secrets.consoleToken,
    userId: user.record.userId,
  });
  const writeClient = secrets.consoleWriteToken
    ? new PurpleClient({
        baseUrl,
        consoleToken: secrets.consoleWriteToken,
        userId: user.record.userId,
      })
    : null;
  const sdlClient = new SdlClient({
    consoleBaseUrl: baseUrl,
    consoleToken: secrets.consoleToken,
    userId: user.record.userId,
  });
  const cursorSigner = await createCursorSigner(secrets.cursorHmac);

  // Production hardening parity: the Python SDL layer refuses TLS bypass in prod.
  // The Worker never bypasses TLS (fetch always verifies), so this is a no-op
  // guard kept for symmetry / future-proofing.
  void isProduction(env);

  return {
    client,
    writeClient,
    exclusionToolsEnabled: exclusionToolsEnabled(env),
    sdl: {
      client: sdlClient,
      budgetMs: sdlPollBudgetMs(env),
      intervalMs: sdlPollIntervalMs(env),
      maxResults: sdlMaxQueryResults(env),
    },
    endpoints: buildEndpoints(env),
    purpleAi: buildPurpleAi(env, secrets, meta.requestId),
    cursorSigner,
    accountIdsDefault: user.record.accountIds ?? null,
    requestId: meta.requestId,
    rayId: meta.rayId,
    userId: user.record.userId,
    scopes: user.scopes,
  };
}

// Optional IP allowlist (CF-Connecting-IP). Empty list = off.
export function assertIpAllowed(allowed: readonly string[], ip: string | null): void {
  if (allowed.length === 0) return;
  if (!ip || !allowed.includes(ip)) {
    throw new AuthError(`Caller IP ${ip ?? "<unknown>"} is not in the allowlist.`, {
      http_status: 403,
    });
  }
}
