# purple-mcp smoke test (real SentinelOne console)

Vitest covers the MCP protocol + auth + scope gate + envelope + cursor. This doc
covers the upstream surface (live HTTP to your SentinelOne console + SDL). Run it
once after deploying or after any change to `http-client.ts` / `sdl/*`.

## Prereqs

1. A SentinelOne console API token with read access to Alerts, XSPM
   (vulnerabilities + misconfigurations), Unified Asset Inventory, SDL
   PowerQuery, and (optionally) Purple AI.
2. `PURPLE_CONSOLE_BASE_URL` set in `wrangler.toml`, and the secrets created
   (see README + the wrangler.toml header).

## Boot locally

```bash
npm run dev    # http://127.0.0.1:8787
```

## 1. Health

```bash
curl -s http://127.0.0.1:8787/health | jq
# { "ok": true, "name": "purple-mcp", "tools": 24 }
```

## 2. Issue a token

```bash
ADMIN_KEY="local-admin-key"   # from .dev.vars
curl -s -X POST http://127.0.0.1:8787/admin/tokens \
  -H "authorization: Bearer ${ADMIN_KEY}" -H "content-type: application/json" \
  -d '{"userId":"smoke","scopes":["alerts:read","inventory:read","sdl:read","investigation:read","purpleai:read","utils:any"]}' \
  | jq -r .mcp_token
```

Copy the value into `$MCP_TOKEN`.

## 3. Tool catalog

```bash
curl -s -X POST http://127.0.0.1:8787/mcp \
  -H "authorization: Bearer ${MCP_TOKEN}" -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq '.result.tools | length'
# 24
```

## 4. A read tool (alerts)

```bash
curl -s -X POST http://127.0.0.1:8787/mcp \
  -H "authorization: Bearer ${MCP_TOKEN}" -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_alerts","arguments":{"first":3}}}' \
  | jq '.result.content[0].text | fromjson | {count: (.data.edges|length), err: .error}'
```

## 5. SDL PowerQuery + resume cursor

```bash
# Submit. If it doesn't finish in the poll budget, .data.complete=false and
# .next_cursor is set.
RESP=$(curl -s -X POST http://127.0.0.1:8787/mcp \
  -H "authorization: Bearer ${MCP_TOKEN}" -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"powerquery","arguments":{
        "query":"event.category = '"'"'dns'"'"' | columns event.time, dns.request | limit 100",
        "start_datetime":"24h","end_datetime":"now"}}}')
echo "$RESP" | jq '.result.content[0].text | fromjson | {complete:.data.complete, rows:.data.returned_count, next:.next_cursor}'

# If incomplete, resume PROMPTLY (SDL query TTL ~30s):
CUR=$(echo "$RESP" | jq -r '.result.content[0].text | fromjson | .next_cursor')
curl -s -X POST http://127.0.0.1:8787/mcp \
  -H "authorization: Bearer ${MCP_TOKEN}" -H "content-type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"powerquery\",\"arguments\":{\"cursor\":\"${CUR}\"}}}" \
  | jq '.result.content[0].text | fromjson | {complete:.data.complete, rows:.data.returned_count}'
```

## 6. Investigation orchestrator

```bash
curl -s -X POST http://127.0.0.1:8787/mcp \
  -H "authorization: Bearer ${MCP_TOKEN}" -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"initiate_investigation","arguments":{"alert_id":"<uuid-or-externalId>"}}}' \
  | jq '.result.content[0].text | fromjson | .data.summary'
# Then feed .data.summary.storyline_id into get_storyline_events.
```

## 7. Scope-gate denial

Issue a second token without `alerts:read`, call `get_alert`, expect
`{ isError: true, error.code: "denied" }`.

## 8. Audit trail

```bash
wrangler d1 execute purple_mcp_audit --local --command \
  "SELECT user_id, tool, result, error_code, latency_ms FROM audit_log ORDER BY timestamp DESC LIMIT 10;"
```

Each call above should appear as one row. If `SIEM_WEBHOOK_URL` is set, the same
rows arrive at your SIEM as `{ "source": "purple-mcp", ... }`.

## What this doesn't cover

- **Purple AI** — needs the team token configured; spot-check `purple_ai`
  manually.
- **Very large storylines** — `get_storyline_events` caps at `limit` and returns
  `match_count` (true total) + a resume cursor; verify the cap behavior against a
  busy endpoint.
