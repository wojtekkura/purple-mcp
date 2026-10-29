// Per-tool scope requirements. Authorization layer 1 (the MCP scope gate) checks
// the user's `scopes[]` against this map before dispatch. Layer 2 is the shared
// SentinelOne console token's own permissions (set at token creation in the S1
// console). Same model as cf-mcp's scopes.ts.
//
// Every scope is a *:read flavor (plus utils:any for the pure datetime helpers)
// except agents:write (remote agent upgrade) and exclusions:write (path
// exclusions). Those change console state; grant them to analysts deliberately.
// Write tools also need the separate PURPLE_CONSOLE_WRITE_TOKEN secret and fail
// closed without it; create_path_exclusion additionally needs
// PURPLE_ENABLE_EXCLUSION_TOOLS=true (off by default).

export type ScopeName =
  | "alerts:read"
  | "vulnerabilities:read"
  | "misconfigurations:read"
  | "inventory:read"
  | "investigation:read"
  | "sdl:read"
  | "purpleai:read"
  | "agents:read"
  | "agents:write"
  | "exclusions:write"
  | "utils:any";

export const ALL_SCOPES: readonly ScopeName[] = [
  "alerts:read",
  "vulnerabilities:read",
  "misconfigurations:read",
  "inventory:read",
  "investigation:read",
  "sdl:read",
  "purpleai:read",
  "agents:read",
  "agents:write",
  "exclusions:write",
  "utils:any",
];

// All 29 tools mapped to the scope they require.
export const TOOL_SCOPES: Readonly<Record<string, ScopeName>> = {
  // Alerts (5)
  get_alert:          "alerts:read",
  list_alerts:        "alerts:read",
  search_alerts:      "alerts:read",
  get_alert_notes:    "alerts:read",
  get_alert_history:  "alerts:read",

  // Vulnerabilities (5)
  get_vulnerability:          "vulnerabilities:read",
  list_vulnerabilities:       "vulnerabilities:read",
  search_vulnerabilities:     "vulnerabilities:read",
  get_vulnerability_notes:    "vulnerabilities:read",
  get_vulnerability_history:  "vulnerabilities:read",

  // Misconfigurations (5)
  get_misconfiguration:          "misconfigurations:read",
  list_misconfigurations:        "misconfigurations:read",
  search_misconfigurations:      "misconfigurations:read",
  get_misconfiguration_notes:    "misconfigurations:read",
  get_misconfiguration_history:  "misconfigurations:read",

  // Inventory (3)
  get_inventory_item:     "inventory:read",
  list_inventory_items:   "inventory:read",
  search_inventory_items: "inventory:read",

  // Investigation (2)
  initiate_investigation: "investigation:read",
  get_storyline_events:   "investigation:read",

  // SDL PowerQuery (1)
  powerquery: "sdl:read",

  // Purple AI (1)
  purple_ai: "purpleai:read",

  // Agent upgrade (3)
  get_agent_upgrade_options: "agents:read",
  get_agent_upgrade_status:  "agents:read",
  upgrade_agent:             "agents:write",

  // Path exclusions (2) — create_path_exclusion hidden unless PURPLE_ENABLE_EXCLUSION_TOOLS
  list_path_exclusions:  "agents:read",
  create_path_exclusion: "exclusions:write",

  // Utilities (2) — pure functions, no upstream call
  get_timestamp_range:   "utils:any",
  iso_to_unix_timestamp: "utils:any",
};

export function hasScope(userScopes: ReadonlySet<string>, required: ScopeName): boolean {
  return userScopes.has(required);
}
