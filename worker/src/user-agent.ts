// Port of cf_mcp/user_agent.py — a single User-Agent string for every upstream
// call, with the per-user id appended for server-side attribution (the Python
// source used `sentinelone/purple-mcp (version X)`).

export const SERVER_VERSION = "0.1.0";

export function getUserAgent(userId?: string): string {
  const base = `sentinelone/purple-mcp-worker (version ${SERVER_VERSION})`;
  return userId ? `${base} user=${userId}` : base;
}
