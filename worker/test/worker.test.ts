// End-to-end test inside Miniflare: spin the Worker, seed KV with a user record,
// hit /health, /admin, /mcp. Tools that would call the real SentinelOne API
// aren't exercised here (envelope/cursor tests + the scope/auth paths cover the
// surface; live upstream coverage is in SMOKE.md).

import { beforeAll, describe, expect, it } from "vitest";
import { SELF, env } from "cloudflare:test";
import { sha256Hex } from "../src/crypto.js";
import type { UserRecord } from "../src/auth.js";

declare module "cloudflare:test" {
  interface ProvidedEnv {
    TOKENS_KV: KVNamespace;
    AUDIT_DB: D1Database;
    PURPLE_CONSOLE_BASE_URL: string;
    PURPLE_ENV: string;
    ALLOWED_IPS: string;
    PURPLE_MCP_ADMIN_KEY: string;
    CURSOR_HMAC_KEY: string;
    PURPLE_CONSOLE_TOKEN: string;
    PURPLE_AI_TEAM_TOKEN: string;
    SIEM_WEBHOOK_URL: string;
  }
}

async function seedUser(opts: {
  bearer: string;
  userId: string;
  scopes: string[];
  accountIds?: string[];
}): Promise<void> {
  const bearerHash = await sha256Hex(opts.bearer);
  const rec: UserRecord = {
    userId: opts.userId,
    scopes: opts.scopes,
    accountIds: opts.accountIds ?? [],
    createdAt: new Date().toISOString(),
  };
  await env.TOKENS_KV.put(`token:${bearerHash}`, JSON.stringify(rec));
  await env.TOKENS_KV.put(`userid:${opts.userId}`, bearerHash);
}

async function ensureAuditTable(): Promise<void> {
  await env.AUDIT_DB.exec(
    `CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, user_id TEXT NOT NULL,
      tool TEXT NOT NULL, input_json TEXT, result TEXT NOT NULL,
      error_code TEXT, error_msg TEXT, ip TEXT, request_id TEXT,
      ray_id TEXT, latency_ms INTEGER )`.replace(/\s+/g, " "),
  );
}

beforeAll(async () => {
  await ensureAuditTable();
});

describe("worker — health + admin + mcp", () => {
  it("GET /health returns ok and the served tool count (28; create_path_exclusion off)", async () => {
    const res = await SELF.fetch("https://example.com/health");
    expect(res.status).toBe(200);
    const j = (await res.json()) as Record<string, unknown>;
    expect(j.ok).toBe(true);
    expect(j.name).toBe("purple-mcp");
    expect(j.tools).toBe(28);
  });

  it("rejects /mcp without a bearer", async () => {
    const res = await SELF.fetch("https://example.com/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(401);
  });

  it("accepts /mcp tools/list with a seeded bearer", async () => {
    const bearer = "pml_test_list";
    await seedUser({ bearer, userId: "alice", scopes: ["alerts:read", "utils:any"] });
    const res = await SELF.fetch("https://example.com/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${bearer}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(200);
    const j = (await res.json()) as { result: { tools: Array<{ name: string }> } };
    const names = j.result.tools.map((t) => t.name);
    expect(names).toContain("get_alert");
    expect(names).toContain("powerquery");
    expect(names).toContain("initiate_investigation");
    expect(names).toContain("get_timestamp_range");
    expect(names).toContain("upgrade_agent");
    expect(names).toContain("list_path_exclusions");
    // PURPLE_ENABLE_EXCLUSION_TOOLS defaults to "false" in wrangler.toml
    expect(names).not.toContain("create_path_exclusion");
    expect(names.length).toBe(28);
  });

  it("refuses create_path_exclusion while the exclusion tools are disabled, even with the scope", async () => {
    const bearer = "pml_test_excl_disabled";
    await seedUser({ bearer, userId: "excluder", scopes: ["agents:read", "exclusions:write"] });
    const res = await SELF.fetch("https://example.com/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${bearer}` },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
          name: "create_path_exclusion",
          arguments: {
            endpoint: "31XZ173",
            path: "C:\\Vendor\\App\\",
            mode: "suppress",
            reason: "test",
            approved_by: "analyst",
            confirm: true,
          },
        },
      }),
    });
    const j = (await res.json()) as { result: { content: Array<{ text: string }>; isError: boolean } };
    expect(j.result.isError).toBe(true);
    const err = JSON.parse(j.result.content[0]!.text).error;
    expect(err.code).toBe("denied");
    expect(err.message).toContain("PURPLE_ENABLE_EXCLUSION_TOOLS");
  });

  it("admin accepts the exclusions:write scope", async () => {
    const res = await SELF.fetch("https://example.com/admin/tokens", {
      method: "POST",
      headers: { authorization: `Bearer ${env.PURPLE_MCP_ADMIN_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ userId: "excl-admin-test", scopes: ["agents:read", "exclusions:write"] }),
    });
    expect(res.status).toBe(201);
  });

  it("denies upgrade_agent to a user with agents:read but not agents:write", async () => {
    const bearer = "pml_test_agents_read";
    await seedUser({ bearer, userId: "reader", scopes: ["agents:read"] });
    const res = await SELF.fetch("https://example.com/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${bearer}` },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "upgrade_agent",
          arguments: { endpoint: "31XZ173", package_id: "p", confirm: true },
        },
      }),
    });
    const j = (await res.json()) as { result: { content: Array<{ text: string }>; isError: boolean } };
    expect(j.result.isError).toBe(true);
    const err = JSON.parse(j.result.content[0]!.text).error;
    expect(err.code).toBe("denied");
    expect(err.message).toContain("agents:write");
  });

  it("admin accepts the agents scopes when issuing a token", async () => {
    const res = await SELF.fetch("https://example.com/admin/tokens", {
      method: "POST",
      headers: { authorization: `Bearer ${env.PURPLE_MCP_ADMIN_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ userId: "upgrader", scopes: ["agents:read", "agents:write"] }),
    });
    expect(res.status).toBe(201);
  });

  it("denies a tool call when the user lacks the scope", async () => {
    const bearer = "pml_test_scope";
    await seedUser({ bearer, userId: "bob", scopes: ["utils:any"] });
    const res = await SELF.fetch("https://example.com/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${bearer}` },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "get_alert", arguments: { alert_id: "x" } },
      }),
    });
    expect(res.status).toBe(200);
    const j = (await res.json()) as { result: { content: Array<{ text: string }>; isError: boolean } };
    expect(j.result.isError).toBe(true);
    expect(JSON.parse(j.result.content[0]!.text).error.code).toBe("denied");
  });

  it("a pure utility tool runs without an upstream call", async () => {
    const bearer = "pml_test_utils";
    await seedUser({ bearer, userId: "carol", scopes: ["utils:any"] });
    const res = await SELF.fetch("https://example.com/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${bearer}` },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "iso_to_unix_timestamp", arguments: { iso_datetime: "2026-06-24T00:00:00Z" } },
      }),
    });
    expect(res.status).toBe(200);
    const envelope = JSON.parse(
      ((await res.json()) as { result: { content: Array<{ text: string }> } }).result.content[0]!.text,
    );
    expect(envelope.error).toBeNull();
    expect(envelope.data.unix_milliseconds).toBe(Date.parse("2026-06-24T00:00:00Z"));
  });

  it("get_timestamp_range defaults to a 24h window", async () => {
    const bearer = "pml_test_ts";
    await seedUser({ bearer, userId: "ts", scopes: ["utils:any"] });
    const res = await SELF.fetch("https://example.com/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${bearer}` },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: { name: "get_timestamp_range", arguments: { reference_time: "2026-06-24T00:00:00Z" } },
      }),
    });
    const envelope = JSON.parse(
      ((await res.json()) as { result: { content: Array<{ text: string }> } }).result.content[0]!.text,
    );
    expect(envelope.data.end_datetime.iso).toBe("2026-06-24T00:00:00.000Z");
    expect(envelope.data.start_datetime.iso).toBe("2026-06-23T00:00:00.000Z");
  });

  it("rejects a batch larger than the cap", async () => {
    const bearer = "pml_test_batch";
    await seedUser({ bearer, userId: "dave", scopes: ["utils:any"] });
    const batch = Array.from({ length: 30 }, (_, i) => ({ jsonrpc: "2.0", id: i, method: "tools/list" }));
    const res = await SELF.fetch("https://example.com/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${bearer}` },
      body: JSON.stringify(batch),
    });
    expect(res.status).toBe(413);
  });

  it("unknown tool produces a JSON-RPC method-not-found", async () => {
    const bearer = "pml_test_unknown";
    await seedUser({ bearer, userId: "erin", scopes: ["utils:any"] });
    const res = await SELF.fetch("https://example.com/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${bearer}` },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 99,
        method: "tools/call",
        params: { name: "does_not_exist", arguments: {} },
      }),
    });
    expect(res.status).toBe(200);
    const j = (await res.json()) as { error?: { code: number; message: string } };
    expect(j.error).toBeTruthy();
    expect(j.error!.message).toContain("unknown tool");
  });

  it("admin endpoint rejects without the admin key", async () => {
    const res = await SELF.fetch("https://example.com/admin/tokens", { method: "GET" });
    expect(res.status).toBe(401);
  });

  it("admin POST /tokens issues a new bearer", async () => {
    const res = await SELF.fetch("https://example.com/admin/tokens", {
      method: "POST",
      headers: { authorization: `Bearer ${env.PURPLE_MCP_ADMIN_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ userId: "frank", scopes: ["alerts:read", "sdl:read"] }),
    });
    expect(res.status).toBe(201);
    const j = (await res.json()) as { mcp_token: string; userId: string };
    expect(j.userId).toBe("frank");
    expect(j.mcp_token.startsWith("pml_")).toBe(true);
  });

  it("admin POST /tokens rejects unknown scopes", async () => {
    const res = await SELF.fetch("https://example.com/admin/tokens", {
      method: "POST",
      headers: { authorization: `Bearer ${env.PURPLE_MCP_ADMIN_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ userId: "bad", scopes: ["nope:read"] }),
    });
    expect(res.status).toBe(400);
  });
});
