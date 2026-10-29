// Flat tool registry. Mirrors cf-mcp's tools/index.ts — everything that
// dispatches off a tool name in one place so index.ts just imports
// TOOL_HANDLERS + TOOL_DESCRIPTORS. The compile-time invariants in src/index.ts
// assert this stays in sync with scopes.ts (all 29 tools mapped both ways).
// EXCLUSION_WRITE_TOOLS are dropped from the served registry unless
// PURPLE_ENABLE_EXCLUSION_TOOLS=true (see registryFor in src/index.ts).

import { ToolFn } from "../tool-base.js";
import type { ToolDescriptor } from "../mcp.js";

import { ALERTS_TOOLS, ALERTS_DESCRIPTORS } from "./alerts.js";
import { VULNERABILITIES_TOOLS, VULNERABILITIES_DESCRIPTORS } from "./vulnerabilities.js";
import { MISCONFIGURATIONS_TOOLS, MISCONFIGURATIONS_DESCRIPTORS } from "./misconfigurations.js";
import { INVENTORY_TOOLS, INVENTORY_DESCRIPTORS } from "./inventory.js";
import { INVESTIGATION_TOOLS, INVESTIGATION_DESCRIPTORS } from "./investigation.js";
import { SDL_TOOLS, SDL_DESCRIPTORS } from "./sdl.js";
import { PURPLE_AI_TOOLS, PURPLE_AI_DESCRIPTORS } from "./purple-ai.js";
import { UTILS_TOOLS, UTILS_DESCRIPTORS } from "./utils.js";
import { AGENTS_TOOLS, AGENTS_DESCRIPTORS } from "./agents.js";
import { EXCLUSIONS_TOOLS, EXCLUSIONS_DESCRIPTORS } from "./exclusions.js";

export { EXCLUSION_WRITE_TOOLS } from "./exclusions.js";

export const TOOL_HANDLERS: Readonly<Record<string, ToolFn>> = {
  ...ALERTS_TOOLS,
  ...VULNERABILITIES_TOOLS,
  ...MISCONFIGURATIONS_TOOLS,
  ...INVENTORY_TOOLS,
  ...INVESTIGATION_TOOLS,
  ...SDL_TOOLS,
  ...PURPLE_AI_TOOLS,
  ...UTILS_TOOLS,
  ...AGENTS_TOOLS,
  ...EXCLUSIONS_TOOLS,
};

export const TOOL_DESCRIPTORS: readonly ToolDescriptor[] = [
  ...ALERTS_DESCRIPTORS,
  ...VULNERABILITIES_DESCRIPTORS,
  ...MISCONFIGURATIONS_DESCRIPTORS,
  ...INVENTORY_DESCRIPTORS,
  ...INVESTIGATION_DESCRIPTORS,
  ...SDL_DESCRIPTORS,
  ...PURPLE_AI_DESCRIPTORS,
  ...UTILS_DESCRIPTORS,
  ...AGENTS_DESCRIPTORS,
  ...EXCLUSIONS_DESCRIPTORS,
];
