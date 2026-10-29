// Path exclusion tools: `list_path_exclusions` (agents:read) and
// `create_path_exclusion` (exclusions:write). Port of purple-mcp's
// tools/exclusions.py + libs/agents/exclusions.py; same rules as the Sumo Logic
// SOAR "Create Path Exclusion" action, so every delivery path refuses and warns
// about the same paths.
//
// create_path_exclusion is OFF unless PURPLE_ENABLE_EXCLUSION_TOOLS=true: index.ts
// hides it from tools/list and refuses the call, and the handler itself fails
// closed on ctx.exclusionToolsEnabled. Exclusions are applied through SOAR for now.
// When enabled it never acts on the first call: without confirm=true it returns a
// preview. With confirm=true it re-plans against the console and POSTs ONCE
// (noRetry) through ctx.writeClient. Approver, reference, endpoint and reason go
// into the exclusion description; the D1 audit row records the MCP user.
//
// Upstream (SentinelOne Management API v2.1, REST):
//   GET  /agents?computerName|uuids|ids
//   GET  /exclusions?type=path&groupIds|siteIds&osTypes&includeParents&value__contains&cursor
//   POST /exclusions  {filter:{groupIds|siteIds:[id]}, data:{type:"path", value, osType, pathExclusionType, mode, description}}

import { ToolDescriptor } from "../mcp.js";
import {
  ToolContext,
  ToolFn,
  ToolResult,
  optionalBool,
  optionalString,
  requireString,
  runTool,
} from "../tool-base.js";
import { DeniedError, ValidationError } from "../errors.js";
import { PurpleClient } from "../http-client.js";
import { dataArray, resolveAgent, str } from "./agents.js";

const API = "/web/api/v2.1";
const MAX_LISTED = 200;
const MAX_DESCRIPTION = 500;
const MAX_PATH_LENGTH = 1000;

type JsonObject = Record<string, unknown>;

// Legacy exclusion modes (data.mode) and their console names.
export const MODES: Readonly<Record<string, string>> = {
  suppress: "Suppress Alerts",
  disable_in_process_monitor: "Interoperability",
  disable_in_process_monitor_deep: "Interoperability - Extended",
  disable_all_monitors: "Performance Focus",
  disable_all_monitors_deep: "Performance Focus - Extended",
};
const WINDOWS_ONLY_MODES = new Set(["disable_in_process_monitor", "disable_in_process_monitor_deep"]);
const EXTENDED_MODES = new Set(["disable_all_monitors_deep"]);
const OS_TYPES = ["windows", "macos", "linux"] as const;
const PATH_TYPES = ["file", "folder", "subfolders"] as const;
const SCOPE_LEVELS = ["group", "site"] as const;

// Only system variables are expanded by the agent (4.6+); %USERPROFILE% etc. are not.
const WINDOWS_ENV_VARS = new Set([
  "programfiles", "programfiles(x86)", "programw6432", "systemdrive", "windir", "systemroot",
  "programdata", "allusersprofile", "public", "commonprogramfiles", "comspec", "homedrive",
]);

// Breadth guard. "?" = any single segment; a trailing "*" is a prefix match.
const WINDOWS_BLOCKED: readonly string[][] = [
  [], ["users"], ["users", "?"], ["users", "?", "appdata"], ["users", "?", "appdata", "local"],
  ["users", "?", "appdata", "roaming"], ["users", "?", "appdata", "locallow"],
  ["users", "?", "documents"], ["users", "?", "onedrive*"],
  ["program files"], ["program files (x86)"], ["programdata"], ["%programfiles%"],
  ["%programfiles(x86)%"], ["%programdata%"], ["%systemdrive%"], ["perflogs"], ["$recycle.bin"],
];
const WINDOWS_BLOCKED_PREFIXES: readonly string[][] = [["windows"], ["%windir%"], ["%systemroot%"]];
const POSIX_BLOCKED: readonly string[][] = [
  [], ["users"], ["users", "?"], ["users", "?", "library"], ["users", "?", "documents"],
  ["library"], ["applications"], ["private"], ["private", "var"], ["var"], ["usr"], ["usr", "bin"],
  ["usr", "sbin"], ["usr", "local"], ["usr", "local", "bin"], ["usr", "lib"], ["bin"], ["sbin"],
  ["lib"], ["opt"], ["opt", "homebrew"], ["opt", "homebrew", "bin"], ["volumes"], ["home"],
  ["home", "?"], ["etc"], ["root"], ["dev"], ["proc"], ["snap"],
];
const POSIX_BLOCKED_PREFIXES: readonly string[][] = [["system"], ["private", "etc"], ["boot"]];
// Malware staging locations: never excluded, wherever they appear.
const STAGING_SEGMENTS = new Set(["temp", "tmp", "downloads", "desktop", "inetcache", "$recycle.bin"]);
// Script hosts / LOLBins: excluding them blinds the agent to most attacks.
const BLOCKED_FILES = new Set([
  "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
  "regsvr32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "schtasks.exe",
  "explorer.exe", "svchost.exe", "lsass.exe", "conhost.exe", "osascript", "bash", "sh", "zsh", "dash",
  "curl", "wget", "launchctl", "sudo",
]);
const INTERPRETERS = new Set([
  "python.exe", "pythonw.exe", "node.exe", "java.exe", "javaw.exe", "python", "python3", "node",
  "java", "perl", "ruby", "php",
]);

export type ExclusionStatus = "ready" | "rejected" | "already_exists" | "already_covered";

export interface ExclusionPlan {
  status: ExclusionStatus;
  agent_id: string;
  computer_name: string | null;
  path: string;
  os_type: string;
  path_type: string;
  mode: string;
  mode_name: string | null;
  scope_level: string;
  scope_id: string | null;
  scope_name: string | null;
  description: string;
  problems: string[];
  warnings: string[];
  existing: JsonObject[];
  covering: JsonObject[];
}

// ---------------------------------------------------------------------------
// Pure decision logic (exported for tests)
// ---------------------------------------------------------------------------

// Lower-cased segments without drive/volume prefix and trailing separator or "*".
export function segments(path: string, osType: string): string[] {
  let value = path.trim().toLowerCase();
  let parts: string[];
  if (osType === "windows") {
    value = value.replace(/^\\device\\harddiskvolume\d+/, "").replace(/^[a-z*?]:/, "");
    parts = value.split("\\");
  } else {
    parts = value.split("/");
  }
  parts = parts.filter((p) => p !== "");
  while (parts.length > 0 && parts[parts.length - 1] === "*") parts.pop();
  return parts;
}

export function segmentsMatch(pattern: readonly string[], segs: readonly string[]): boolean {
  if (pattern.length !== segs.length) return false;
  return pattern.every((pat, i) => {
    const seg = segs[i]!;
    if (pat === "?") return true;
    if (pat.endsWith("*") && seg.startsWith(pat.slice(0, -1))) return true;
    return pat === seg;
  });
}

// A trailing separator or "*" means sub-folders; otherwise a single file.
export function defaultPathType(path: string): string {
  const p = path.trimEnd();
  return /(\\|\/|\\\*|\/\*)$/.test(p) ? "subfolders" : "file";
}

function modeProblems(mode: string, osType: string, allowExtended: boolean): string[] {
  if (!(mode in MODES)) return [`Unsupported mode "${mode}". Allowed: ${Object.keys(MODES).join(", ")}.`];
  const problems: string[] = [];
  if (WINDOWS_ONLY_MODES.has(mode) && osType !== "windows") {
    problems.push(`${MODES[mode]} (${mode}) is only available on Windows.`);
  }
  if (EXTENDED_MODES.has(mode) && !allowExtended) {
    problems.push(`${MODES[mode]} also stops monitoring of child processes; set allow_extended=true to use it.`);
  }
  return problems;
}

function syntaxProblems(path: string, osType: string): string[] {
  const problems: string[] = [];
  if (path.length > MAX_PATH_LENGTH) problems.push(`Path is longer than ${MAX_PATH_LENGTH} characters.`);
  if (/[\r\n\t"<>|]/.test(path)) problems.push('Path contains a newline, tab or one of " < > |.');
  if (path.includes("**")) problems.push('"**" is not a valid S1 wildcard.');
  if (osType !== "windows") {
    if (!path.startsWith("/")) problems.push(`${osType} paths must be absolute (start with /).`);
    if (path.includes("\\")) problems.push(`${osType} paths use forward slashes.`);
    return problems;
  }
  if (path.includes("/")) problems.push("Windows paths use backslashes.");
  for (const m of path.matchAll(/%([^%]+)%/g)) {
    if (!WINDOWS_ENV_VARS.has(m[1]!.toLowerCase())) {
      problems.push(`%${m[1]}% is not supported; only system environment variables are.`);
    }
  }
  if (/^[*?]:/.test(path)) {
    problems.push("The drive letter cannot be a wildcard; drop the drive to match every drive.");
  }
  return problems;
}

function breadthProblems(path: string, segs: string[], osType: string): string[] {
  const problems: string[] = [];
  const [blocked, prefixes] =
    osType === "windows" ? [WINDOWS_BLOCKED, WINDOWS_BLOCKED_PREFIXES] : [POSIX_BLOCKED, POSIX_BLOCKED_PREFIXES];
  if (segs.length > 0 && segs[0]!.includes("*")) {
    problems.push("Wildcard in the first folder level would match whole drives/volumes.");
  }
  if (blocked.some((p) => segmentsMatch(p, segs))) {
    problems.push(
      `"${path}" is a system-wide or per-user root folder; excluding it removes visibility for too much. ` +
        "Exclude the specific application folder instead.",
    );
  }
  if (prefixes.some((p) => segmentsMatch(p, segs.slice(0, p.length)))) {
    problems.push("Operating system folders cannot be excluded through this tool.");
  }
  const staging = segs.find((s) => STAGING_SEGMENTS.has(s));
  if (staging) problems.push(`Path goes through "${staging}", a common malware staging location.`);
  const name = segs[segs.length - 1];
  if (name && BLOCKED_FILES.has(name)) {
    problems.push(`"${name}" is a script host / LOLBin; excluding it blinds the agent to most attacks.`);
  }
  return problems;
}

function warningsFor(path: string, segs: string[], osType: string, mode: string, pathType: string): string[] {
  const warnings: string[] = [];
  const name = segs[segs.length - 1] ?? "";
  if (osType === "windows" && /%[^%]+%/.test(path)) warnings.push("Environment variables need agent 4.6 or later.");
  if (INTERPRETERS.has(name)) {
    warnings.push(`"${name}" is an interpreter: everything it runs loses monitoring. Prefer excluding the script folder.`);
  }
  if (pathType !== "file" && segs.filter((s) => !s.includes("*")).length <= 2) {
    warnings.push(`Broad folder (${segs.length} level(s) deep) with sub-folders included.`);
  }
  if (path.replace(/[*\\/]+$/, "").includes("*") || path.includes("?")) {
    warnings.push("Wildcards widen the match beyond a single folder.");
  }
  if (pathType === "file" && !/\.[a-z0-9]{1,6}$/.test(name)) {
    warnings.push(
      "No trailing separator and no file extension: this is treated as a single FILE. " +
        "End the path with \\ or / to exclude a folder.",
    );
  }
  if (mode.startsWith("disable_all_monitors")) {
    warnings.push(
      "Performance Focus turns off most behavioral monitoring for this path, and it applies after the process or endpoint restarts.",
    );
  } else if (mode.startsWith("disable_in_process_monitor")) {
    warnings.push(
      "Interoperability stops in-process monitoring (DLL injection) for this path; applies after the process restarts.",
    );
  }
  return warnings;
}

// Returns [problems, warnings]; any problem means the exclusion must be refused.
export function validateExclusion(
  path: string,
  osType: string,
  mode: string,
  pathType: string,
  allowExtended = false,
): [string[], string[]] {
  const segs = segments(path, osType);
  return [
    [...modeProblems(mode, osType, allowExtended), ...syntaxProblems(path, osType), ...breadthProblems(path, segs, osType)],
    warningsFor(path, segs, osType, mode, pathType),
  ];
}

// Split existing exclusions into exact matches and sub-folder exclusions covering `path`.
export function findExisting(rows: JsonObject[], path: string, osType: string): [JsonObject[], JsonObject[]] {
  const target = segments(path, osType);
  const exact: JsonObject[] = [];
  const covering: JsonObject[] = [];
  for (const row of rows) {
    const other = segments(str(row.value) ?? "", osType);
    if (other.join("/") === target.join("/")) {
      exact.push(row);
    } else if (row.pathExclusionType === "subfolders" && other.length > 0 && segmentsMatch(other, target.slice(0, other.length))) {
      covering.push(row);
    }
  }
  return [exact, covering];
}

export function buildDescription(approvedBy: string, reason: string, computerName: string | null, reference: string | null): string {
  let text = `[MCP] Approved by: ${approvedBy} | Ref: ${reference || "-"} | Endpoint: ${computerName || "-"} | Reason: ${reason}`;
  text = text.replace(/\s+/g, " ").trim();
  return text.length > MAX_DESCRIPTION ? `${text.slice(0, MAX_DESCRIPTION - 3)}...` : text;
}

function exclusionSummary(row: JsonObject): JsonObject {
  return {
    id: row.id ?? null,
    value: row.value ?? null,
    os_type: row.osType ?? null,
    mode: row.mode ?? null,
    path_exclusion_type: row.pathExclusionType ?? null,
    scope: row.scopeName ?? null,
    scope_path: row.scopePath ?? null,
    description: row.description ?? null,
    created_by: row.userName ?? null,
    created_at: row.createdAt ?? null,
  };
}

export function requestBody(plan: ExclusionPlan): JsonObject {
  return {
    filter: { [plan.scope_level === "group" ? "groupIds" : "siteIds"]: [plan.scope_id] },
    data: {
      type: "path",
      value: plan.path,
      osType: plan.os_type,
      pathExclusionType: plan.path_type,
      mode: plan.mode,
      description: plan.description,
    },
  };
}

// ---------------------------------------------------------------------------
// Upstream helpers
// ---------------------------------------------------------------------------

async function listExclusions(
  client: PurpleClient,
  opts: { groupId?: string | null; siteId?: string | null; osType?: string | null; valueContains?: string; includeParents?: boolean; maxItems?: number },
): Promise<JsonObject[]> {
  const maxItems = opts.maxItems ?? 1000;
  const params: Record<string, string | number> = { type: "path", limit: Math.min(maxItems, 1000) };
  if (opts.groupId) params.groupIds = opts.groupId;
  else if (opts.siteId) params.siteIds = opts.siteId;
  else throw new ValidationError("A group or site is required to list exclusions.");
  if (opts.osType) params.osTypes = opts.osType;
  if (opts.valueContains) params.value__contains = opts.valueContains;
  if (opts.includeParents ?? true) params.includeParents = "true";

  const rows: JsonObject[] = [];
  while (rows.length < maxItems) {
    const body = await client.requestJson({ method: "GET", path: `${API}/exclusions`, params });
    rows.push(...dataArray(body));
    const pagination = body["pagination"];
    const cursor =
      pagination && typeof pagination === "object" ? (pagination as JsonObject).nextCursor : null;
    if (!cursor) break;
    params.cursor = String(cursor);
  }
  return rows.slice(0, maxItems);
}

function choice<T extends string>(value: string | undefined, allowed: readonly T[], name: string): T | undefined {
  const v = value?.trim().toLowerCase();
  if (!v) return undefined;
  if (!(allowed as readonly string[]).includes(v)) {
    throw new ValidationError(`${name} must be one of ${allowed.join(", ")}.`);
  }
  return v as T;
}

interface PlanArgs {
  endpoint: string;
  path: string;
  mode: string;
  reason: string;
  approvedBy: string;
  scopeLevel?: string;
  pathType?: string;
  osType?: string;
  reference?: string;
  allowExtended: boolean;
}

function readArgs(args: Record<string, unknown>): PlanArgs {
  return {
    endpoint: requireString(args.endpoint, "endpoint"),
    path: requireString(args.path, "path").trim(),
    mode: requireString(args.mode, "mode").trim(),
    reason: requireString(args.reason, "reason").trim(),
    approvedBy: requireString(args.approved_by, "approved_by").trim(),
    scopeLevel: optionalString(args.scope_level, "scope_level"),
    pathType: optionalString(args.path_type, "path_type"),
    osType: optionalString(args.os_type, "os_type"),
    reference: optionalString(args.reference, "reference")?.trim() || undefined,
    allowExtended: optionalBool(args.allow_extended, "allow_extended", false),
  };
}

async function buildPlan(client: PurpleClient, a: PlanArgs): Promise<ExclusionPlan> {
  const level = choice(a.scopeLevel, SCOPE_LEVELS, "scope_level") ?? "group";
  const agent = await resolveAgent(client, a.endpoint);
  const agentOs = (str(agent.osType) ?? "").toLowerCase();
  const osType = choice(a.osType, OS_TYPES, "os_type") ?? agentOs;
  if (!(OS_TYPES as readonly string[]).includes(osType)) {
    throw new ValidationError(`Unsupported agent OS type '${osType}'.`);
  }
  const pathType = choice(a.pathType, PATH_TYPES, "path_type") ?? defaultPathType(a.path);
  const scopeId = str(level === "group" ? agent.groupId : agent.siteId);
  const scopeName = str(level === "group" ? agent.groupName : agent.siteName);

  const [problems, warnings] = validateExclusion(a.path, osType, a.mode, pathType, a.allowExtended);
  if (agent.isDecommissioned === true || agent.isUninstalled === true) problems.push("Agent is decommissioned/uninstalled.");
  if (!scopeId) problems.push(`Agent has no ${level} ID.`);
  if (level === "site") warnings.push(`Site scope: applies to every ${osType} agent in site '${scopeName}'.`);
  if (osType !== agentOs) warnings.push(`OS type ${osType} differs from the agent OS (${str(agent.osType)}).`);

  let status: ExclusionStatus = problems.length > 0 ? "rejected" : "ready";
  let exact: JsonObject[] = [];
  let covering: JsonObject[] = [];
  if (status === "ready") {
    const rows = await listExclusions(client, {
      groupId: level === "group" ? scopeId : null,
      siteId: level === "site" ? scopeId : null,
      osType,
    });
    [exact, covering] = findExisting(rows, a.path, osType);
    if (exact.length > 0) status = "already_exists";
    else if (covering.some((r) => r.mode === a.mode)) status = "already_covered";
  }

  return {
    status,
    agent_id: String(agent.id),
    computer_name: str(agent.computerName),
    path: a.path,
    os_type: osType,
    path_type: pathType,
    mode: a.mode,
    mode_name: MODES[a.mode] ?? null,
    scope_level: level,
    scope_id: scopeId,
    scope_name: scopeName,
    description: buildDescription(a.approvedBy, a.reason, str(agent.computerName), a.reference ?? null),
    problems,
    warnings,
    existing: exact.map(exclusionSummary),
    covering: covering.map(exclusionSummary).slice(0, 10),
  };
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

const list_path_exclusions: ToolFn = (ctx, args) =>
  runTool("GET /agents + /exclusions", async (): Promise<ToolResult> => {
    const endpoint = requireString(args.endpoint, "endpoint");
    const valueContains = optionalString(args.value_contains, "value_contains")?.trim() || undefined;
    const includeParents = optionalBool(args.include_parents, "include_parents", true);
    const agent = await resolveAgent(ctx.client, endpoint);
    const rows = await listExclusions(ctx.client, {
      groupId: str(agent.groupId),
      siteId: str(agent.siteId),
      osType: str(agent.osType),
      valueContains,
      includeParents,
      maxItems: MAX_LISTED,
    });
    return {
      data: {
        agent_id: agent.id ?? null,
        computer_name: agent.computerName ?? null,
        os_type: agent.osType ?? null,
        group: agent.groupName ?? null,
        site: agent.siteName ?? null,
        count: rows.length,
        exclusions: rows.map(exclusionSummary),
      },
    };
  });

function assertExclusionWritesEnabled(ctx: ToolContext): void {
  if (!ctx.exclusionToolsEnabled) {
    throw new DeniedError("Path exclusions are not enabled on this server.", {
      hint: "Exclusions are applied through the Sumo Logic SOAR 'Create Path Exclusion' action. Set PURPLE_ENABLE_EXCLUSION_TOOLS=true to enable this tool.",
    });
  }
}

const create_path_exclusion: ToolFn = (ctx, args) =>
  runTool("POST /exclusions", async (): Promise<ToolResult> => {
    assertExclusionWritesEnabled(ctx);
    const planArgs = readArgs(args);
    const confirm = optionalBool(args.confirm, "confirm", false);
    const plan = await buildPlan(ctx.client, planArgs);

    if (!confirm) {
      return {
        data: {
          mode: "preview",
          plan,
          ...(plan.status === "ready"
            ? {
                next_step:
                  "Show this preview, including every warning, to the analyst. Only after they approve, " +
                  "call create_path_exclusion again with the same arguments and confirm=true.",
              }
            : {}),
        },
      };
    }

    if (plan.status !== "ready") return { data: { mode: "not_executed", reason: plan.status, plan } };

    if (!ctx.writeClient) {
      throw new DeniedError("Console write token is not configured on this server.", {
        hint: "Create the Secrets Store secret purple-console-write-token (an S1 token with Exclusions View/Create) and bind it as PURPLE_CONSOLE_WRITE_TOKEN.",
      });
    }

    const body = await ctx.writeClient.requestJson({
      method: "POST",
      path: `${API}/exclusions`,
      jsonBody: requestBody(plan),
      noRetry: true,
    });
    const created = dataArray(body)[0] ?? ((body["data"] as JsonObject | undefined) ?? {});

    return {
      data: {
        mode: "executed",
        confirmed_by: ctx.userId,
        exclusion: exclusionSummary(created),
        plan,
        next_step: "Verify with list_path_exclusions; the mode applies after the process restarts.",
      },
    };
  });

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const EXCLUSIONS_TOOLS: Record<string, ToolFn> = {
  list_path_exclusions,
  create_path_exclusion,
};

// Tools hidden from tools/list and refused unless PURPLE_ENABLE_EXCLUSION_TOOLS=true.
export const EXCLUSION_WRITE_TOOLS: readonly string[] = ["create_path_exclusion"];

const ENDPOINT_PROP = {
  type: "string",
  description: "Computer name (e.g. 31XZ173), 32-char agent UUID, or numeric agent ID.",
};

export const EXCLUSIONS_DESCRIPTORS: ToolDescriptor[] = [
  {
    name: "list_path_exclusions",
    description:
      "Read-only. List the SentinelOne path exclusions that apply to an endpoint: those on its group plus, by default, those inherited from its site and account, for the agent's OS. Returns value, mode, scope, description, created_by, created_at (max 200).",
    inputSchema: {
      type: "object",
      properties: {
        endpoint: ENDPOINT_PROP,
        value_contains: { type: "string", description: "Only exclusions whose path contains this text." },
        include_parents: { type: "boolean", default: true, description: "Include site and account exclusions." },
      },
      required: ["endpoint"],
      additionalProperties: false,
    },
  },
  {
    name: "create_path_exclusion",
    description:
      "CHANGES CONSOLE STATE. Create a SentinelOne path exclusion scoped to an endpoint's group (default) or site. Two-step, analyst-confirmed: (1) call with confirm=false (default) to get a preview with scope, validation problems, risk warnings and duplicate check, and show it to the analyst including every warning; (2) only after the analyst explicitly approves, call again with the same arguments and confirm=true. Never set confirm=true on your own judgement or without the analyst's name in approved_by. Broad, system, staging and LOLBin paths are refused. Modes: disable_in_process_monitor (Interoperability, try first, Windows only), disable_in_process_monitor_deep, disable_all_monitors (Performance Focus), disable_all_monitors_deep (needs allow_extended), suppress.",
    inputSchema: {
      type: "object",
      properties: {
        endpoint: ENDPOINT_PROP,
        path: { type: "string", description: "Folder ending with \\ or / (sub-folders included), or a full file path." },
        mode: { type: "string", enum: Object.keys(MODES), description: "Exclusion mode." },
        reason: { type: "string", description: "Why the exclusion is needed (stored on the exclusion)." },
        approved_by: { type: "string", description: "Analyst who approved it (stored on the exclusion)." },
        scope_level: { type: "string", enum: [...SCOPE_LEVELS], default: "group", description: "group = the agent's group; site = every agent in the site." },
        path_type: { type: "string", enum: [...PATH_TYPES], description: "Default: subfolders when the path ends with a separator, otherwise file." },
        os_type: { type: "string", enum: [...OS_TYPES], description: "Default: the agent's OS." },
        reference: { type: "string", description: "Insight / incident ID for the audit trail." },
        allow_extended: { type: "boolean", default: false, description: "Required for disable_all_monitors_deep." },
        confirm: { type: "boolean", default: false, description: "Must be true to create. Set only after explicit analyst approval of the preview." },
      },
      required: ["endpoint", "path", "mode", "reason", "approved_by"],
      additionalProperties: false,
    },
  },
];
