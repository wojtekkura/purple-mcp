// Worker bindings, surfaced as a single typed env object.
//
// Local dev: wrangler injects [vars] and `secrets_store_secrets` bindings
// declared in wrangler.toml. Tests inject plain strings via vitest-pool-workers.
//
// Every secret field is typed as `SecretsStoreSecret` ({ get(): Promise<string> }).
// resolveSecrets() (src/secrets.ts) reads them once per request and exposes plain
// strings; it also tolerates plain-string overrides (for tests).

export interface Env {
  // KV: per-user MCP-bearer records, keyed by sha256(bearer).
  TOKENS_KV: KVNamespace;
  // D1: audit log.
  AUDIT_DB: D1Database;

  // --- Vars (wrangler.toml [vars]) — non-secret runtime knobs. ---
  PURPLE_CONSOLE_BASE_URL: string;                  // https://tenant.sentinelone.net (no trailing slash)
  PURPLE_CONSOLE_GRAPHQL_ENDPOINT: string;          // Purple AI GraphQL path
  PURPLE_ALERTS_GRAPHQL_ENDPOINT: string;           // Alerts / UAM GraphQL path
  PURPLE_MISCONFIGURATIONS_GRAPHQL_ENDPOINT: string;
  PURPLE_VULNERABILITIES_GRAPHQL_ENDPOINT: string;
  PURPLE_INVENTORY_RESTAPI_ENDPOINT: string;        // UAI REST path

  PURPLE_SDL_MAX_QUERY_RESULTS: string;             // int as string
  PURPLE_SDL_POLL_BUDGET_MS: string;                // int as string — per-request poll wall-clock budget
  PURPLE_SDL_POLL_INTERVAL_MS: string;              // int as string

  PURPLE_AI_ACCOUNT_ID: string;
  PURPLE_AI_EMAIL_ADDRESS: string;
  PURPLE_AI_CONSOLE_VERSION: string;

  PURPLE_ENV: string;                               // "production" | "development" | ...
  ALLOWED_IPS: string;                              // CSV of caller IPs; empty = no allowlist
  PURPLE_ENABLE_EXCLUSION_TOOLS?: string;           // "true" exposes create_path_exclusion; default off (SOAR applies exclusions)

  // --- Cloudflare Secrets Store bindings (read via resolveSecrets()). ---
  PURPLE_MCP_ADMIN_KEY: SecretsStoreSecret;         // admin bearer for /admin/*
  CURSOR_HMAC_KEY: SecretsStoreSecret;              // HMAC key for signed cursors
  PURPLE_CONSOLE_TOKEN: SecretsStoreSecret;         // ONE shared SentinelOne console API token
  PURPLE_AI_TEAM_TOKEN: SecretsStoreSecret;         // Purple AI team token (optional; "" = unset)
  SIEM_WEBHOOK_URL: SecretsStoreSecret;             // SIEM HTTP source URL (URL = credential; "" = off)
  PURPLE_CONSOLE_WRITE_TOKEN?: SecretsStoreSecret;  // S1 token with agent-upgrade rights (optional; unset = write tools fail closed)
}

export function purpleEnvName(env: Env): string {
  return (env.PURPLE_ENV ?? "production").trim().toLowerCase() || "production";
}

export function isProduction(env: Env): boolean {
  return purpleEnvName(env) === "production";
}

export function allowedIps(env: Env): readonly string[] {
  const raw = (env.ALLOWED_IPS ?? "").trim();
  if (!raw) return [];
  return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

// create_path_exclusion is off unless explicitly enabled: exclusions are applied
// through the Sumo Logic SOAR "Create Path Exclusion" action for now.
export function exclusionToolsEnabled(env: Env): boolean {
  return (env.PURPLE_ENABLE_EXCLUSION_TOOLS ?? "").trim().toLowerCase() === "true";
}

function intVar(raw: string | undefined, fallback: number): number {
  const n = parseInt((raw ?? "").trim(), 10);
  return Number.isFinite(n) ? n : fallback;
}

export function sdlMaxQueryResults(env: Env): number {
  return intVar(env.PURPLE_SDL_MAX_QUERY_RESULTS, 10_000);
}

export function sdlPollBudgetMs(env: Env): number {
  return intVar(env.PURPLE_SDL_POLL_BUDGET_MS, 22_000);
}

export function sdlPollIntervalMs(env: Env): number {
  return intVar(env.PURPLE_SDL_POLL_INTERVAL_MS, 1_000);
}
