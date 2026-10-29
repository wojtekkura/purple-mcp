// Resolve all Worker-bound secrets to plain strings, once per request.
//
// Production: each field on Env is a Cloudflare Secrets Store binding
// (`SecretsStoreSecret` — `{ get(): Promise<string> }`). The store is a
// separate, account-scoped product with its own access audit; rotating a
// secret happens in the dashboard / Secrets Store API and is picked up by
// every Worker that binds to it. No `wrangler secret put` on the Worker.
//
// Tests / dev: the same Env fields may be plain strings supplied by
// vitest-pool-workers. `resolveSecrets` accepts either shape.

import type { Env } from "./env.js";

export interface ResolvedSecrets {
  adminKey: string;        // PURPLE_MCP_ADMIN_KEY — admin bearer for /admin/*
  cursorHmac: string;      // CURSOR_HMAC_KEY      — HMAC key for signed cursors
  consoleToken: string;    // PURPLE_CONSOLE_TOKEN — the shared SentinelOne console token (all tool calls)
  teamToken: string;       // PURPLE_AI_TEAM_TOKEN — Purple AI team token ("" = unset)
  siemWebhookUrl: string;  // SIEM_WEBHOOK_URL     — "" means SIEM off
  consoleWriteToken: string; // PURPLE_CONSOLE_WRITE_TOKEN — S1 token allowed to upgrade agents ("" = write tools off)
}

type SecretLike = string | { get(): Promise<string> };

async function read(source: SecretLike, name: string): Promise<string> {
  if (typeof source === "string") return source;
  if (source && typeof (source as { get?: unknown }).get === "function") {
    try {
      return await source.get();
    } catch (e) {
      throw new Error(
        `Secret ${name} could not be read from Secrets Store: ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    }
  }
  throw new Error(
    `Secret ${name} is not configured — bind a Secrets Store secret or provide a string for tests.`,
  );
}

async function readOptional(source: SecretLike | undefined, name: string): Promise<string> {
  if (source === undefined || source === null) return "";
  if (typeof source === "string") return source;
  if (typeof (source as { get?: unknown }).get === "function") {
    try {
      return await source.get();
    } catch {
      console.warn(`Optional secret ${name} read failed; treating as unset.`);
      return "";
    }
  }
  return "";
}

export async function resolveSecrets(env: Env): Promise<ResolvedSecrets> {
  const [adminKey, cursorHmac, consoleToken, teamToken, siemWebhookUrl, consoleWriteToken] =
    await Promise.all([
      read(env.PURPLE_MCP_ADMIN_KEY as SecretLike, "PURPLE_MCP_ADMIN_KEY"),
      read(env.CURSOR_HMAC_KEY as SecretLike, "CURSOR_HMAC_KEY"),
      read(env.PURPLE_CONSOLE_TOKEN as SecretLike, "PURPLE_CONSOLE_TOKEN"),
      readOptional(env.PURPLE_AI_TEAM_TOKEN as SecretLike | undefined, "PURPLE_AI_TEAM_TOKEN"),
      readOptional(env.SIEM_WEBHOOK_URL as SecretLike | undefined, "SIEM_WEBHOOK_URL"),
      readOptional(
        env.PURPLE_CONSOLE_WRITE_TOKEN as SecretLike | undefined,
        "PURPLE_CONSOLE_WRITE_TOKEN",
      ),
    ]);
  return { adminKey, cursorHmac, consoleToken, teamToken, siemWebhookUrl, consoleWriteToken };
}
