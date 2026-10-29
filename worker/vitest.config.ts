import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.toml" },
        miniflare: {
          // Test-time bindings. Secrets Store bindings are supplied as plain
          // strings here; resolveSecrets() detects the shape at runtime.
          bindings: {
            CF_READ_ONLY: "true",
            PURPLE_CONSOLE_BASE_URL: "https://example.sentinelone.net",
            PURPLE_ENV: "production",
            ALLOWED_IPS: "",
            PURPLE_MCP_ADMIN_KEY: "test-admin-key",
            CURSOR_HMAC_KEY: "test-cursor-hmac-0000000000000000",
            PURPLE_CONSOLE_TOKEN: "test-console-token",
            PURPLE_AI_TEAM_TOKEN: "",
            SIEM_WEBHOOK_URL: "",
          },
        },
      },
    },
  },
});
