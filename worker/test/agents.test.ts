// Agent upgrade tools: pure decision logic + the analyst-confirmation gate,
// driven through PurpleClient with a mocked fetch (no real SentinelOne calls).

import { describe, expect, it } from "vitest";
import { PurpleClient } from "../src/http-client.js";
import type { ToolContext } from "../src/tool-base.js";
import {
  AGENTS_TOOLS,
  compareVersions,
  isUpgradeActivity,
  parseVersion,
  planUpgrade,
  selectLatestPackage,
} from "../src/tools/agents.js";

type Json = Record<string, unknown>;

const AGENT: Json = {
  id: "1890441504121661350",
  computerName: "31XZ173",
  uuid: "a8abe595b29c40c8a342f1f3a6952e80",
  osType: "windows",
  osArch: "64 bit",
  isActive: true,
  isUpToDate: false,
  agentVersion: "26.1.2.177",
  siteName: "Groupon, Inc.",
};

function pkg(id: string, version: string, extra: Json = {}): Json {
  return {
    id,
    version,
    status: "ga",
    packageType: "AgentAndRanger",
    osType: "windows",
    osArch: "64 bit",
    fileExtension: ".msi",
    fileName: `SentinelInstaller_windows_64bit_v${version}.msi`,
    ...extra,
  };
}

const PACKAGES = [pkg("old", "26.1.2.177"), pkg("new", "26.2.3.158"), pkg("arm", "26.2.3.158", { osArch: "ARM64" })];

interface Call {
  method: string;
  url: URL;
  body: unknown;
  token: string;
}

// Routes /agents, /update/agent/packages, /activities and update-software.
function fakeConsole(opts: { agents?: Json[]; packages?: Json[]; activities?: Json[]; updateStatus?: number }) {
  const calls: Call[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const headers = (init?.headers ?? {}) as Record<string, string>;
    calls.push({
      method: init?.method ?? "GET",
      url,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
      token: headers.authorization ?? "",
    });
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.pathname.endsWith("/agents")) return json(200, { data: opts.agents ?? [AGENT] });
    if (url.pathname.endsWith("/update/agent/packages")) return json(200, { data: opts.packages ?? PACKAGES });
    if (url.pathname.endsWith("/activities")) return json(200, { data: opts.activities ?? [] });
    if (url.pathname.endsWith("/agents/actions/update-software")) {
      const status = opts.updateStatus ?? 200;
      return json(status, status === 200 ? { data: { affected: 1 } } : { errors: [{ title: "boom" }] });
    }
    return json(404, {});
  };
  return { calls, fetchImpl };
}

function makeCtx(fetchImpl: typeof fetch, withWriteToken = true): ToolContext {
  const mk = (token: string) =>
    new PurpleClient({ baseUrl: "https://console.test", consoleToken: token, userId: "analyst-1", fetchImpl });
  return {
    client: mk("read-token"),
    writeClient: withWriteToken ? mk("write-token") : null,
    userId: "analyst-1",
  } as unknown as ToolContext;
}

async function call(ctx: ToolContext, tool: string, args: Json): Promise<{ data: any; error: any }> {
  return JSON.parse(await AGENTS_TOOLS[tool]!(ctx, args));
}

const updateCalls = (calls: Call[]) => calls.filter((c) => c.url.pathname.endsWith("update-software"));

describe("agent upgrade — decision logic", () => {
  it("parses and compares versions numerically", () => {
    expect(parseVersion("26.1.2.177")).toEqual([26, 1, 2, 177]);
    expect(parseVersion("24.1.4.6 EA")).toEqual([24, 1, 4, 6]);
    expect(parseVersion(null)).toEqual([]);
    expect(compareVersions(parseVersion("26.1.10.1"), parseVersion("26.1.9.300"))).toBeGreaterThan(0);
  });

  it("picks the newest matching GA package, accepting AgentAndRanger bundles", () => {
    const chosen = selectLatestPackage(
      [...PACKAGES, pkg("ranger", "27.0.0.1", { packageType: "Ranger" }), pkg("ea", "27.0.0.2", { status: "ea" })],
      AGENT,
    );
    expect(chosen?.id).toBe("new");
  });

  it("prefers .msi over .exe for the same version", () => {
    const chosen = selectLatestPackage(
      [pkg("exe", "26.2.3.158", { fileExtension: ".exe" }), pkg("msi", "26.2.3.158")],
      AGENT,
    );
    expect(chosen?.id).toBe("msi");
  });

  it("makes no automatic choice for linux", () => {
    expect(selectLatestPackage(PACKAGES, { ...AGENT, osType: "linux" })).toBeNull();
  });

  it("plans statuses", () => {
    expect(planUpgrade(AGENT, pkg("new", "26.2.3.158")).status).toBe("upgrade_available");
    expect(planUpgrade(AGENT, pkg("old", "26.1.2.177")).status).toBe("already_up_to_date");
    expect(planUpgrade({ ...AGENT, isActive: false }, pkg("new", "26.2.3.158")).status).toBe("agent_inactive");
    expect(planUpgrade(AGENT, null).status).toBe("no_package");
  });

  it("recognises the console's upgrade activity text", () => {
    expect(
      isUpgradeActivity({
        primaryDescription: "Software update availability notification was sent to 31XZ173 by SOAR Custom integration.",
      }),
    ).toBe(true);
    expect(isUpgradeActivity({ primaryDescription: "Agent 31XZ173 policy updated" })).toBe(false);
  });
});

describe("agent upgrade — tools", () => {
  it("options returns the plan for the newest GA package", async () => {
    const { fetchImpl } = fakeConsole({});
    const r = await call(makeCtx(fetchImpl), "get_agent_upgrade_options", { endpoint: "31XZ173" });
    expect(r.error).toBeNull();
    expect(r.data.status).toBe("upgrade_available");
    expect(r.data.package_id).toBe("new");
    expect(r.data.target_version).toBe("26.2.3.158");
  });

  it("preview never calls update-software", async () => {
    const { fetchImpl, calls } = fakeConsole({});
    const r = await call(makeCtx(fetchImpl), "upgrade_agent", { endpoint: "31XZ173" });
    expect(r.data.mode).toBe("preview");
    expect(r.data.next_step).toContain("confirm=true");
    expect(updateCalls(calls)).toHaveLength(0);
  });

  it("confirm without package_id is rejected before any upstream call", async () => {
    const { fetchImpl, calls } = fakeConsole({});
    const r = await call(makeCtx(fetchImpl), "upgrade_agent", { endpoint: "31XZ173", confirm: true });
    expect(r.error.code).toBe("validation");
    expect(calls).toHaveLength(0);
  });

  it("confirm sends one update-software on the write token", async () => {
    const { fetchImpl, calls } = fakeConsole({});
    const r = await call(makeCtx(fetchImpl), "upgrade_agent", {
      endpoint: "31XZ173",
      package_id: "new",
      confirm: true,
    });
    expect(r.error).toBeNull();
    expect(r.data.mode).toBe("executed");
    expect(r.data.affected).toBe(1);
    expect(r.data.confirmed_by).toBe("analyst-1");
    const [upd, ...rest] = updateCalls(calls);
    expect(rest).toHaveLength(0);
    expect(upd!.method).toBe("POST");
    expect(upd!.token).toBe("Bearer write-token");
    expect(upd!.body).toEqual({
      filter: { ids: ["1890441504121661350"] },
      data: { packageId: "new", isScheduled: false },
    });
  });

  it("confirm fails closed without a write token", async () => {
    const { fetchImpl, calls } = fakeConsole({});
    const r = await call(makeCtx(fetchImpl, false), "upgrade_agent", {
      endpoint: "31XZ173",
      package_id: "new",
      confirm: true,
    });
    expect(r.error.code).toBe("denied");
    expect(updateCalls(calls)).toHaveLength(0);
  });

  it("update-software is not retried on a 503", async () => {
    const { fetchImpl, calls } = fakeConsole({ updateStatus: 503 });
    const r = await call(makeCtx(fetchImpl), "upgrade_agent", {
      endpoint: "31XZ173",
      package_id: "new",
      confirm: true,
    });
    expect(r.error).not.toBeNull();
    expect(updateCalls(calls)).toHaveLength(1);
  });

  it("confirm is a no-op once the agent is already up to date", async () => {
    const { fetchImpl, calls } = fakeConsole({ agents: [{ ...AGENT, agentVersion: "26.2.3.158" }] });
    const r = await call(makeCtx(fetchImpl), "upgrade_agent", {
      endpoint: "31XZ173",
      package_id: "new",
      confirm: true,
    });
    expect(r.data.mode).toBe("not_executed");
    expect(r.data.reason).toBe("already_up_to_date");
    expect(updateCalls(calls)).toHaveLength(0);
  });

  it("confirm skips an inactive agent", async () => {
    const { fetchImpl, calls } = fakeConsole({ agents: [{ ...AGENT, isActive: false }] });
    const r = await call(makeCtx(fetchImpl), "upgrade_agent", {
      endpoint: "31XZ173",
      package_id: "new",
      confirm: true,
    });
    expect(r.data.reason).toBe("agent_inactive");
    expect(updateCalls(calls)).toHaveLength(0);
  });

  it("rejects a package_id that is not a GA package for the OS", async () => {
    const { fetchImpl } = fakeConsole({});
    const r = await call(makeCtx(fetchImpl), "upgrade_agent", {
      endpoint: "31XZ173",
      package_id: "nope",
      confirm: true,
    });
    expect(r.error.code).toBe("validation");
  });

  it("unknown endpoint -> not_found; several active matches -> validation", async () => {
    const none = fakeConsole({ agents: [] });
    expect((await call(makeCtx(none.fetchImpl), "get_agent_upgrade_options", { endpoint: "NOPE" })).error.code).toBe(
      "not_found",
    );
    const dup = fakeConsole({ agents: [AGENT, { ...AGENT, id: "999999999999999999" }] });
    const r = await call(makeCtx(dup.fetchImpl), "upgrade_agent", { endpoint: "31XZ173", package_id: "new", confirm: true });
    expect(r.error.code).toBe("validation");
    expect(updateCalls(dup.calls)).toHaveLength(0);
  });

  it("prefers the single active record when a stale duplicate exists", async () => {
    const { fetchImpl } = fakeConsole({ agents: [{ ...AGENT, id: "111111111111111111", isActive: false }, AGENT] });
    const r = await call(makeCtx(fetchImpl), "get_agent_upgrade_options", { endpoint: "31XZ173" });
    expect(r.data.agent_id).toBe("1890441504121661350");
  });

  it("routes UUIDs and numeric IDs to the right /agents filter", async () => {
    const { fetchImpl, calls } = fakeConsole({});
    const ctx = makeCtx(fetchImpl);
    await call(ctx, "get_agent_upgrade_options", { endpoint: "A8ABE595B29C40C8A342F1F3A6952E80" });
    await call(ctx, "get_agent_upgrade_options", { endpoint: "1890441504121661350" });
    const agentLookups = calls.filter((c) => c.url.pathname.endsWith("/agents"));
    expect(agentLookups[0]!.url.searchParams.get("uuids")).toBe("a8abe595b29c40c8a342f1f3a6952e80");
    expect(agentLookups[1]!.url.searchParams.get("ids")).toBe("1890441504121661350");
  });

  it("status lists only upgrade activities", async () => {
    const { fetchImpl } = fakeConsole({
      activities: [
        { createdAt: "t2", activityType: 5, primaryDescription: "Software update availability notification was sent to 31XZ173." },
        { createdAt: "t1", activityType: 65, primaryDescription: "fetch full report command" },
      ],
    });
    const r = await call(makeCtx(fetchImpl), "get_agent_upgrade_status", { endpoint: "31XZ173" });
    expect(r.data.agent_version).toBe("26.1.2.177");
    expect(r.data.upgrade_activities.map((a: Json) => a.created_at)).toEqual(["t2"]);
  });
});
