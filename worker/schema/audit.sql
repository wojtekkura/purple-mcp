-- Audit log for every MCP tool invocation.
-- One row per call (success, error, or denied). Authoritative copy;
-- SIEM webhook fan-out is fire-and-forget on top of this.
-- Identical shape to cf-mcp's audit_log so SOC tooling can query both uniformly.
CREATE TABLE IF NOT EXISTS audit_log (
  id          TEXT PRIMARY KEY,    -- uuid v4
  timestamp   TEXT NOT NULL,       -- ISO-8601 UTC, set at insert time
  user_id     TEXT NOT NULL,       -- 'unknown' for unauthenticated denies
  tool        TEXT NOT NULL,       -- MCP tool name, or '<auth>' for pre-dispatch denies
  input_json  TEXT,                -- sanitized; never contains the bearer or console token
  result      TEXT NOT NULL,       -- 'success' | 'error' | 'denied'
  error_code  TEXT,                -- envelope error.code when result='error'/'denied'
  error_msg   TEXT,                -- truncated message
  ip          TEXT,                -- CF-Connecting-IP
  request_id  TEXT,                -- X-Request-ID from caller (SOAR correlation)
  ray_id      TEXT,                -- cf-ray from Cloudflare edge
  latency_ms  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_tool ON audit_log(tool);
CREATE INDEX IF NOT EXISTS idx_time ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_request ON audit_log(request_id);
