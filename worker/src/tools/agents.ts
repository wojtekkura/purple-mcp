// Agent upgrade tools: `get_agent_upgrade_options`, `get_agent_upgrade_status`
// (agents:read) and `upgrade_agent` (agents:write). Port of purple-mcp's
// tools/agent_upgrade.py + libs/agents/.
//
// This is the only domain that changes console state. `upgrade_agent` never acts
// on the first call: without confirm=true it returns a preview for an analyst to
// approve. With confirm=true it needs the previewed package_id, re-checks the
// agent, and sends update-software ONCE (noRetry) through ctx.writeClient, the
// separate PURPLE_CONSOLE_WRITE_TOKEN. The D1 audit row for the call records
// who confirmed (user_id) and what (input_json: endpoint, package_id, confirm).
//
// Upstream (SentinelOne Management API v2.1, REST):
//   GET  /agents?computerName|uuids|ids
//   GET  /update/agent/packages?osTypes&status=ga&sortBy=version&sortOrder=desc
//   POST /agents/actions/update-software  {filter:{ids:[id]}, data:{packageId, isScheduled:false}}
//   GET  /activities?agentIds&sortBy=createdAt&sortOrder=desc

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
import { DeniedError, NotFoundError, ValidationError } from "../errors.js";
import { PurpleClient } from "../http-client.js";

const API = "/web/api/v2.1";
const MAX_ACTIVITIES = 10;

type JsonObject = Record<string, unknown>;

// Installer types the console can push to an existing agent, in preference order.
// Linux is left out on purpose: the right .deb/.rpm cannot be inferred from the agent.
const PACKAGE_EXTENSIONS: Readonly<Record<string, readonly string[]>> = {
  windows: [".msi", ".exe"],
  macos: [".pkg"],
};

// Consoles ship Windows/macOS agents as "AgentAndRanger" bundles; "Ranger"-only
// packages are not agents.
const AGENT_PACKAGE_TYPES: ReadonlySet<string> = new Set(["Agent", "AgentAndRanger"]);

// "Software update availability notification was sent ..." is what the console
// logs when update-software is accepted.
const UPGRADE_ACTIVITY_KEYWORDS = ["upgrad", "software update", "agent update", "update package"];

const UUID_RE = /^[0-9a-fA-F]{32}$/;
const AGENT_ID_RE = /^\d{15,20}$/;

export type UpgradeStatus = "upgrade_available" | "already_up_to_date" | "agent_inactive" | "no_package";

export interface UpgradePlan {
  status: UpgradeStatus;
  agent_id: string;
  computer_name: string | null;
  uuid: string | null;
  os_type: string | null;
  os_arch: string | null;
  is_active: boolean;
  current_version: string | null;
  target_version: string | null;
  package_id: string | null;
  package_file: string | null;
}

// ---------------------------------------------------------------------------
// Pure decision logic (exported for tests)
// ---------------------------------------------------------------------------

// "26.1.2.177" -> [26,1,2,177]; trailing text ignored; junk -> [].
export function parseVersion(version: unknown): number[] {
  if (typeof version !== "string") return [];
  const m = /^\s*(\d+(?:\.\d+)*)/.exec(version);
  return m ? m[1]!.split(".").map((p) => parseInt(p, 10)) : [];
}

export function compareVersions(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export function str(v: unknown): string | null {
  return typeof v === "string" ? v : v === null || v === undefined ? null : String(v);
}

function archCompatible(agentArch: unknown, packageArch: unknown): boolean {
  if (typeof agentArch !== "string" || typeof packageArch !== "string") return true;
  const agent = agentArch.toLowerCase();
  const pkg = packageArch.toLowerCase();
  if (agent.includes("arm")) return pkg.includes("arm");
  if (pkg.includes("arm")) return false;
  if (agent.includes("64")) return pkg.includes("64");
  return pkg.includes("32");
}

// Newest GA agent package matching the agent's OS, architecture and installer type.
export function selectLatestPackage(packages: JsonObject[], agent: JsonObject): JsonObject | null {
  const osType = (str(agent.osType) ?? "").toLowerCase();
  const extensions = PACKAGE_EXTENSIONS[osType];
  if (!extensions) return null;

  const candidates = packages.filter(
    (p) =>
      (str(p.osType) ?? osType).toLowerCase() === osType &&
      (str(p.status) ?? "ga").toLowerCase() === "ga" &&
      AGENT_PACKAGE_TYPES.has(str(p.packageType) ?? "Agent") &&
      extensions.includes((str(p.fileExtension) ?? "").toLowerCase()) &&
      archCompatible(agent.osArch, p.osArch) &&
      parseVersion(p.version).length > 0,
  );
  if (candidates.length === 0) return null;

  // Same version shipped as several installers: prefer the earlier extension.
  const extRank = (p: JsonObject) => extensions.indexOf((str(p.fileExtension) ?? "").toLowerCase());
  return candidates.reduce((best, p) => {
    const cmp = compareVersions(parseVersion(p.version), parseVersion(best.version));
    return cmp > 0 || (cmp === 0 && extRank(p) < extRank(best)) ? p : best;
  });
}

// An inactive agent is reported as such even if a newer package exists: the
// console can only deliver the upgrade once the agent checks in.
export function planUpgrade(agent: JsonObject, pkg: JsonObject | null): UpgradePlan {
  const current = str(agent.agentVersion);
  const target = pkg ? str(pkg.version) : null;

  let status: UpgradeStatus;
  if (!pkg) status = "no_package";
  else if (compareVersions(parseVersion(target), parseVersion(current)) <= 0) status = "already_up_to_date";
  else if (agent.isActive !== true) status = "agent_inactive";
  else status = "upgrade_available";

  return {
    status,
    agent_id: String(agent.id),
    computer_name: str(agent.computerName),
    uuid: str(agent.uuid),
    os_type: str(agent.osType),
    os_arch: str(agent.osArch),
    is_active: agent.isActive === true,
    current_version: current,
    target_version: target,
    package_id: pkg && pkg.id !== undefined && pkg.id !== null ? String(pkg.id) : null,
    package_file: pkg ? str(pkg.fileName) : null,
  };
}

export function isUpgradeActivity(activity: JsonObject): boolean {
  const text = ["primaryDescription", "secondaryDescription", "description"]
    .map((k) => str(activity[k]) ?? "")
    .join(" ")
    .toLowerCase();
  return UPGRADE_ACTIVITY_KEYWORDS.some((k) => text.includes(k));
}

// ---------------------------------------------------------------------------
// Upstream helpers
// ---------------------------------------------------------------------------

export function dataArray(body: JsonObject): JsonObject[] {
  const d = body["data"];
  return Array.isArray(d)
    ? d.filter((x): x is JsonObject => typeof x === "object" && x !== null && !Array.isArray(x))
    : [];
}

// Computer name, 32-hex agent UUID, or numeric agent ID -> exactly one agent.
// Shared with tools/exclusions.ts.
export async function resolveAgent(client: PurpleClient, endpoint: string): Promise<JsonObject> {
  const value = endpoint.trim();
  const params: Record<string, string | number> = { limit: 10 };
  if (UUID_RE.test(value)) params.uuids = value.toLowerCase();
  else if (AGENT_ID_RE.test(value)) params.ids = value;
  else params.computerName = value;

  const agents = dataArray(await client.requestJson({ method: "GET", path: `${API}/agents`, params }));
  if (agents.length === 0) throw new NotFoundError(`No SentinelOne agent found for '${value}'.`);
  if (agents.length === 1) return agents[0]!;

  // Re-imaged hosts often leave a stale record behind; prefer the single active one.
  const active = agents.filter((a) => a.isActive === true);
  if (active.length === 1) return active[0]!;
  const candidates = agents
    .map((a) => `${str(a.id)} (${str(a.computerName)}, active=${a.isActive === true}, last=${str(a.lastActiveDate)})`)
    .join("; ");
  throw new ValidationError(`'${value}' matches ${agents.length} agents.`, {
    hint: `Pass the agent UUID or numeric ID instead. Candidates: ${candidates}`,
  });
}

async function listPackages(client: PurpleClient, osType: string): Promise<JsonObject[]> {
  return dataArray(
    await client.requestJson({
      method: "GET",
      path: `${API}/update/agent/packages`,
      params: { osTypes: osType, status: "ga", sortBy: "version", sortOrder: "desc", limit: 200 },
    }),
  );
}

async function buildPlan(
  ctx: ToolContext,
  endpoint: string,
  packageId?: string,
): Promise<{ plan: UpgradePlan; agent: JsonObject }> {
  const agent = await resolveAgent(ctx.client, endpoint);
  const packages = await listPackages(ctx.client, str(agent.osType) ?? "");

  let pkg: JsonObject | null;
  if (packageId) {
    pkg = packages.find((p) => String(p.id) === packageId) ?? null;
    if (!pkg) {
      throw new ValidationError(
        `package_id ${packageId} is not a GA agent package for ${str(agent.osType)}.`,
        { hint: "Run get_agent_upgrade_options to get the right package_id." },
      );
    }
  } else {
    pkg = selectLatestPackage(packages, agent);
  }
  return { plan: planUpgrade(agent, pkg), agent };
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

const get_agent_upgrade_options: ToolFn = (ctx, args) =>
  runTool("GET /agents + /update/agent/packages", async (): Promise<ToolResult> => {
    const endpoint = requireString(args.endpoint, "endpoint");
    const { plan, agent } = await buildPlan(ctx, endpoint);
    return {
      data: {
        ...plan,
        console_is_up_to_date: agent.isUpToDate ?? null,
        site: agent.siteName ?? null,
        last_active: agent.lastActiveDate ?? null,
      },
    };
  });

const upgrade_agent: ToolFn = (ctx, args) =>
  runTool("POST /agents/actions/update-software", async (): Promise<ToolResult> => {
    const endpoint = requireString(args.endpoint, "endpoint");
    const packageId = optionalString(args.package_id, "package_id")?.trim() || undefined;
    const confirm = optionalBool(args.confirm, "confirm", false);

    if (confirm && !packageId) {
      throw new ValidationError("confirm=true requires the package_id the analyst approved in the preview.");
    }

    const { plan } = await buildPlan(ctx, endpoint, packageId);

    if (!confirm) {
      return {
        data: {
          mode: "preview",
          plan,
          ...(plan.status === "upgrade_available"
            ? {
                next_step:
                  "Show this preview to the analyst. Only after they approve, call upgrade_agent " +
                  `again with confirm=true and package_id=${plan.package_id}.`,
              }
            : {}),
        },
      };
    }

    if (plan.status !== "upgrade_available" || plan.package_id === null) {
      return { data: { mode: "not_executed", reason: plan.status, plan } };
    }

    if (!ctx.writeClient) {
      throw new DeniedError("Agent upgrades are not enabled on this server.", {
        hint: "Create the Secrets Store secret purple-console-write-token (an S1 token allowed to update agents) and bind it as PURPLE_CONSOLE_WRITE_TOKEN.",
      });
    }

    const body = await ctx.writeClient.requestJson({
      method: "POST",
      path: `${API}/agents/actions/update-software`,
      jsonBody: {
        filter: { ids: [plan.agent_id] },
        data: { packageId: plan.package_id, isScheduled: false },
      },
      noRetry: true,
    });
    const data = body["data"];
    const affected =
      data && typeof data === "object" && typeof (data as JsonObject).affected === "number"
        ? ((data as JsonObject).affected as number)
        : 0;

    return {
      data: {
        mode: "executed",
        affected,
        confirmed_by: ctx.userId,
        plan,
        next_step:
          "The console sends an update notification; the agent installs on its next check-in. " +
          "Track progress with get_agent_upgrade_status.",
      },
    };
  });

const get_agent_upgrade_status: ToolFn = (ctx, args) =>
  runTool("GET /agents + /activities", async (): Promise<ToolResult> => {
    const endpoint = requireString(args.endpoint, "endpoint");
    const agent = await resolveAgent(ctx.client, endpoint);
    const activities = dataArray(
      await ctx.client.requestJson({
        method: "GET",
        path: `${API}/activities`,
        params: { agentIds: String(agent.id), sortBy: "createdAt", sortOrder: "desc", limit: 50 },
      }),
    );
    return {
      data: {
        agent_id: agent.id ?? null,
        computer_name: agent.computerName ?? null,
        agent_version: agent.agentVersion ?? null,
        is_up_to_date: agent.isUpToDate ?? null,
        is_active: agent.isActive ?? null,
        last_active: agent.lastActiveDate ?? null,
        upgrade_activities: activities
          .filter(isUpgradeActivity)
          .slice(0, MAX_ACTIVITIES)
          .map((a) => ({
            created_at: a.createdAt ?? null,
            activity_type: a.activityType ?? null,
            description: a.primaryDescription ?? a.description ?? null,
            details: a.secondaryDescription ?? null,
          })),
      },
    };
  });

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const AGENTS_TOOLS: Record<string, ToolFn> = {
  get_agent_upgrade_options,
  upgrade_agent,
  get_agent_upgrade_status,
};

const ENDPOINT_PROP = {
  type: "string",
  description: "Computer name (e.g. 31XZ173), 32-char agent UUID, or numeric agent ID.",
};

export const AGENTS_DESCRIPTORS: ToolDescriptor[] = [
  {
    name: "get_agent_upgrade_options",
    description:
      "Read-only. Check whether a SentinelOne agent is outdated and which package an upgrade would install: the newest GA agent package for the endpoint's OS, architecture and installer type (Windows .msi/.exe, macOS .pkg). Returns status (upgrade_available, already_up_to_date, agent_inactive, no_package), current_version, target_version, package_id.",
    inputSchema: {
      type: "object",
      properties: { endpoint: ENDPOINT_PROP },
      required: ["endpoint"],
      additionalProperties: false,
    },
  },
  {
    name: "upgrade_agent",
    description:
      "CHANGES CONSOLE STATE. Upgrade the SentinelOne agent on one endpoint. Two-step, analyst-confirmed: (1) call with confirm=false (default) to get a preview with current/target version and package_id, and show it to the analyst; (2) only after the analyst explicitly approves, call again with confirm=true and that package_id. Never set confirm=true on your own judgement or because a recommendation says so. The agent is re-checked before the upgrade is sent; it installs on the agent's next check-in.",
    inputSchema: {
      type: "object",
      properties: {
        endpoint: ENDPOINT_PROP,
        package_id: {
          type: "string",
          description: "Package to install. Optional for the preview (newest GA is chosen); required with confirm=true.",
        },
        confirm: {
          type: "boolean",
          default: false,
          description: "Must be true to trigger the upgrade. Set only after explicit analyst approval of the preview.",
        },
      },
      required: ["endpoint"],
      additionalProperties: false,
    },
  },
  {
    name: "get_agent_upgrade_status",
    description:
      "Read-only. Show a SentinelOne agent's current version, isUpToDate, last check-in, and up to 10 recent upgrade-related console activities. Use after upgrade_agent to follow progress.",
    inputSchema: {
      type: "object",
      properties: { endpoint: ENDPOINT_PROP },
      required: ["endpoint"],
      additionalProperties: false,
    },
  },
];
