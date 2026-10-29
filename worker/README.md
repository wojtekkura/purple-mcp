# purple-mcp (Cloudflare Worker)

Remote SentinelOne / Purple AI MCP server for SOC investigation agents — a
Workers port of the Python [`purple-mcp`](../../purple-mcp), built on the same
architecture as [`cf-mcp`](../cf-mcp): per-user bearer auth, a D1 audit log, and
a fire-and-forget SIEM webhook.

## What it exposes (29 tools, 11 scopes; 28 served while exclusion writes are off)

| Domain | Scope | Tools |
|---|---|---|
| Alerts | `alerts:read` | `get_alert`, `list_alerts`, `search_alerts`, `get_alert_notes`, `get_alert_history` |
| Vulnerabilities | `vulnerabilities:read` | `get_vulnerability`, `list_vulnerabilities`, `search_vulnerabilities`, `get_vulnerability_notes`, `get_vulnerability_history` |
| Misconfigurations | `misconfigurations:read` | `get_misconfiguration`, `list_misconfigurations`, `search_misconfigurations`, `get_misconfiguration_notes`, `get_misconfiguration_history` |
| Inventory (REST) | `inventory:read` | `get_inventory_item`, `list_inventory_items`, `search_inventory_items` |
| Investigation | `investigation:read` | `initiate_investigation`, `get_storyline_events` |
| SDL PowerQuery | `sdl:read` | `powerquery` |
| Purple AI | `purpleai:read` | `purple_ai` |
| Utilities | `utils:any` | `get_timestamp_range`, `iso_to_unix_timestamp` |
| Agent upgrade (REST) | `agents:read` | `get_agent_upgrade_options`, `get_agent_upgrade_status` |
| Agent upgrade (REST) | `agents:write` | `upgrade_agent` — **changes console state** |
| Path exclusions (REST) | `agents:read` | `list_path_exclusions` |
| Path exclusions (REST) | `exclusions:write` | `create_path_exclusion` — **changes console state; disabled by default** |

Alerts / Vulnerabilities / Misconfigurations are **GraphQL**; Inventory and
agent upgrade are **REST**; PowerQuery / storyline run against the
**Singularity Data Lake (SDL)**.

### Remote agent upgrade (the one write tool)

`upgrade_agent` is analyst-confirmed by design. A call with `confirm=false`
(default) only returns a preview (current version → newest GA package for the
endpoint's OS/arch, plus `package_id`). After the analyst approves, a second
call with `confirm=true` and that `package_id` re-checks the agent and sends
`POST /agents/actions/update-software` **once** (no retry). The console then
notifies the agent, which installs on its next check-in; follow it with
`get_agent_upgrade_status`. The D1 audit row records who confirmed
(`user_id`) and what (`input_json`).

Two independent gates must both be open:

1. the caller's KV record has the `agents:write` scope, and
2. the Secrets Store secret `purple-console-write-token` (an S1 token whose role
   allows **Endpoints → Update/Upgrade software**) is bound as
   `PURPLE_CONSOLE_WRITE_TOKEN` — see the commented block in `wrangler.toml`.
   Without it the tool fails closed; it never uses `purple-console-token`.

### Path exclusions (disabled by default)

`list_path_exclusions` (read-only) returns the path exclusions that apply to an
endpoint's group, plus inherited site/account ones, for the agent's OS.

`create_path_exclusion` creates an S1 path exclusion on the endpoint's group
(default) or site, with the same preview → `confirm=true` flow, breadth guard
(no system/user roots, staging folders or LOLBins) and duplicate check as the
Sumo Logic SOAR *Create Path Exclusion* action. Approver, reference, endpoint and
reason go into the exclusion description; the POST is sent once (no retry).

Exclusions are applied through the SOAR integration for now, so this tool is
**hidden from `tools/list` and refused** unless `PURPLE_ENABLE_EXCLUSION_TOOLS =
"true"` in `wrangler.toml` `[vars]`. When enabled it also needs the
`exclusions:write` scope and the write-token secret (role with
**Exclusions → View/Create**), and fails closed without either.

## Architecture (mirrors cf-mcp)

- **Transport** — stateless Streamable-HTTP MCP. `POST /mcp` (JSON-RPC 2.0),
  `GET /health` (unauthenticated), `/admin/tokens` (admin plane). No SSE, no
  Durable Objects.
- **Auth** — caller sends a per-user MCP bearer; we `sha256` it and look up a
  user record in **KV** (`token:<hash>`). There is **one shared** SentinelOne
  console token in **Secrets Store** used for every upstream call (per-user
  attribution lives in the audit log, not in upstream tokens).
- **Authorization** — a per-tool **scope gate** (`src/scopes.ts`) runs before
  dispatch; a compile-time invariant asserts every tool has a scope.
- **Storage** — **KV** for user records, **D1** (`purple_mcp_audit`) for the
  audit log, **Secrets Store** for the admin key, cursor-HMAC key, console
  token, Purple AI team token, and SIEM URL.
- **Logging** — one authoritative D1 row per call (`ctx.waitUntil`) plus a
  best-effort SIEM webhook (`source: "purple-mcp"`); secret keys are redacted
  from audited input; `correlation_id` / `ray_id` / `request_id` throughout.
- **Envelope** — uniform `{data, next_cursor, cache_meta, api_endpoint_called,
  correlation_id, error}` with an 80 KB ceiling and `clampToFitBytes`.

### SDL long-poll → resume cursor

The Python SDL handler polls a PowerQuery for up to ~5 minutes. Workers can't
hold a request open that long, so `powerquery` / `get_storyline_events` poll
within a bounded wall-clock budget (`PURPLE_SDL_POLL_BUDGET_MS`, default 22s). If
the query hasn't finished, the tool returns the rows fetched so far plus a signed
`next_cursor`; call the tool again with `cursor` set to resume from the last step
seen. **The SDL query expires ~30s after the last poll, so resume promptly.**

## Setup

```bash
npm install

# 1. Create KV + D1, paste the printed IDs into wrangler.toml.
wrangler kv namespace create TOKENS_KV
wrangler kv namespace create TOKENS_KV --preview
wrangler d1 create purple_mcp_audit
npm run d1:migrate:remote   # and :local for dev

# 2. Create the Secrets Store secrets (see wrangler.toml header for the commands):
#    purple-mcp-admin-key, cursor-hmac-key, purple-console-token,
#    purple-ai-team-token (optional), siem-webhook-url (optional),
#    purple-console-write-token (optional; enables upgrade_agent).

# 3. Set PURPLE_CONSOLE_BASE_URL (+ endpoint vars) in wrangler.toml [vars].

npm run deploy
```

For local dev, drop the secret equivalents into `.dev.vars` (gitignored):

```ini
PURPLE_MCP_ADMIN_KEY=local-admin-key
CURSOR_HMAC_KEY=local-cursor-hmac-0000000000000000
PURPLE_CONSOLE_TOKEN=<your SentinelOne console token>
PURPLE_AI_TEAM_TOKEN=
SIEM_WEBHOOK_URL=
PURPLE_CONSOLE_WRITE_TOKEN=   # optional; S1 token allowed to upgrade agents
```

## Issue a per-user token

```bash
curl -s -X POST https://<worker>/admin/tokens \
  -H "authorization: Bearer $ADMIN_KEY" -H "content-type: application/json" \
  -d '{"userId":"analyst-1","scopes":["alerts:read","sdl:read","investigation:read","utils:any"]}'
# -> { "mcp_token": "pml_...", ... }   (shown once; only the hash is stored)
```

Optional per-user `accountIds` scopes SDL / Purple AI to specific account IDs.

## Development

```bash
npm run typecheck   # tsc --noEmit
npm test            # vitest (protocol + auth + envelope + cursor)
npm run dev         # wrangler dev on http://127.0.0.1:8787
```

Live upstream checks (real SentinelOne console) are in [SMOKE.md](SMOKE.md).

## Response envelope

```json
{
  "data": {...},
  "next_cursor": "psl1.<...>" ,
  "cache_meta": {"hit": false, "age_s": 0, "ttl_s": 0},
  "api_endpoint_called": "POST /alerts (SearchAlerts)",
  "correlation_id": "uuid",
  "error": null
}
```

On error, `data` is `null` and `error` carries
`{code, http_status, upstream_errors, retry_after_s, hint, message}` where
`code` ∈ `rate_limited | auth | not_found | validation | upstream |
response_too_large | denied`.
