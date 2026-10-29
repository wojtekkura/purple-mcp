// Path exclusion tools: validation / breadth guard, duplicate detection, and the
// enable-flag + analyst-confirmation gate, driven through PurpleClient with a
// mocked fetch (no real SentinelOne calls).

import { describe, expect, it } from "vitest";
import { PurpleClient } from "../src/http-client.js";
import type { ToolContext } from "../src/tool-base.js";
import {
  EXCLUSIONS_TOOLS,
  buildDescription,
  defaultPathType,
  findExisting,
  validateExclusion,
} from "../src/tools/exclusions.js";

type Json = Record<string, unknown>;

const AGENT: Json = {
  id: "1890441504121661350",
  computerName: "31XZ173",
  osType: "windows",
  isActive: true,
  siteId: "200",
  siteName: "Groupon, Inc.",
  groupId: "300",
  groupName: "Default Group",
};

const ARGS: Json = {
  endpoint: "31XZ173",
  path: "C:\\Program Files\\Vendor\\App\\",
  mode: "disable_in_process_monitor",
  reason: "S1 CPU 95% while App rebuilds its cache",
  approved_by: "analyst@groupon.com",
  reference: "INSIGHT-1",
};

interface Call {
  method: string;
  url: URL;
  body: unknown;
  token: string;
}

// Routes /agents, GET /exclusions (paged by `pageSize`) and POST /exclusions.
function fakeConsole(opts: { agents?: Json[]; exclusions?: Json[]; postStatus?: number; pageSize?: number }) {
  const calls: Call[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, url, body, token: headers.authorization ?? "" });
    const json = (status: number, b: unknown) =>
      new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
    if (url.pathname.endsWith("/agents")) return json(200, { data: opts.agents ?? [AGENT] });
    if (url.pathname.endsWith("/exclusions") && method === "GET") {
      const rows = opts.exclusions ?? [];
      const size = opts.pageSize ?? 1000;
      const start = parseInt(url.searchParams.get("cursor") ?? "0", 10);
      const next = start + size < rows.length ? String(start + size) : null;
      return json(200, { data: rows.slice(start, start + size), pagination: { nextCursor: next } });
    }
    if (url.pathname.endsWith("/exclusions") && method === "POST") {
      const status = opts.postStatus ?? 200;
      return json(
        status,
        status === 200
          ? { data: [{ ...(body as Json).data as Json, id: "9001", scopeName: "group", userName: "svc" }] }
          : { errors: [{ title: "boom" }] },
      );
    }
    return json(404, {});
  };
  return { calls, fetchImpl };
}

function makeCtx(fetchImpl: typeof fetch, opts: { enabled?: boolean; writeToken?: boolean } = {}): ToolContext {
  const mk = (token: string) =>
    new PurpleClient({ baseUrl: "https://console.test", consoleToken: token, userId: "analyst-1", fetchImpl });
  return {
    client: mk("read-token"),
    writeClient: opts.writeToken === false ? null : mk("write-token"),
    exclusionToolsEnabled: opts.enabled ?? true,
    userId: "analyst-1",
  } as unknown as ToolContext;
}

async function call(ctx: ToolContext, tool: string, args: Json): Promise<{ data: any; error: any }> {
  return JSON.parse(await EXCLUSIONS_TOOLS[tool]!(ctx, args));
}

const posts = (calls: Call[]) => calls.filter((c) => c.method === "POST");

describe("path exclusions — validation", () => {
  it.each([
    ["C:\\", "windows"],
    ["C:\\Users\\*\\", "windows"],
    ["C:\\Users\\jdoe\\", "windows"],
    ["C:\\Users\\*\\AppData\\Local\\", "windows"],
    ["C:\\Users\\*\\AppData\\Local\\Temp\\App\\", "windows"],
    ["C:\\Windows\\System32\\", "windows"],
    ["C:\\Program Files\\", "windows"],
    ["%ProgramFiles%\\", "windows"],
    ["C:\\Users\\jdoe\\Downloads\\tool\\", "windows"],
    ["*\\Vendor\\", "windows"],
    ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "windows"],
    ["\\Program Files (x86)\\*", "windows"],
    ["C:\\Users\\jdoe\\OneDrive - Groupon\\", "windows"],
    ["/Users/*/", "macos"],
    ["/Users/*/Library/", "macos"],
    ["/System/Library/Foo/", "macos"],
    ["/private/tmp/x/", "macos"],
    ["/", "linux"],
  ])("refuses %s (%s)", (path, os) => {
    const [problems] = validateExclusion(path, os, "disable_all_monitors", "subfolders");
    expect(problems.length).toBeGreaterThan(0);
  });

  it.each([
    [{ path: "%USERPROFILE%\\App\\" }, "not supported"],
    [{ path: "C:/Program Files/Vendor/" }, "backslashes"],
    [{ path: "*:\\Vendor\\App\\" }, "drive letter"],
    [{ mode: "disable_all_monitors_deep" }, "allow_extended"],
    [{ mode: "yolo" }, "Unsupported mode"],
    [{ os: "macos", path: "/Applications/Vendor.app/" }, "only available on Windows"],
    [{ os: "linux", path: "opt/vendor/" }, "absolute"],
  ] as Array<[Record<string, string>, string]>)("rejects invalid input %j", (over, needle) => {
    const [problems] = validateExclusion(
      over.path ?? "C:\\Program Files\\Vendor\\App\\",
      over.os ?? "windows",
      over.mode ?? "disable_in_process_monitor",
      "subfolders",
    );
    expect(problems.some((p) => p.includes(needle))).toBe(true);
  });

  it("allows a specific app folder, with warnings", () => {
    const [problems, warnings] = validateExclusion(
      "%ProgramFiles%\\Vendor\\App\\Cache\\",
      "windows",
      "disable_all_monitors",
      "subfolders",
    );
    expect(problems).toEqual([]);
    expect(warnings.some((w) => w.includes("4.6"))).toBe(true);
    expect(warnings.some((w) => w.includes("Performance Focus"))).toBe(true);
  });

  it("infers path type and flags a bare folder name as a file", () => {
    expect(defaultPathType("C:\\Vendor\\App\\")).toBe("subfolders");
    expect(defaultPathType("C:\\Vendor\\App\\*")).toBe("subfolders");
    expect(defaultPathType("/opt/vendor/app")).toBe("file");
    const [, warnings] = validateExclusion("C:\\Vendor\\App", "windows", "suppress", "file");
    expect(warnings.some((w) => w.includes("single FILE"))).toBe(true);
  });

  it("finds exact (case/trailing-* insensitive) and covering exclusions", () => {
    const rows: Json[] = [
      { id: "1", value: "c:\\program files\\vendor\\app\\*", pathExclusionType: "subfolders" },
      { id: "2", value: "C:\\Program Files\\*\\", pathExclusionType: "subfolders" },
      { id: "3", value: "C:\\Program Files\\Vendor\\", pathExclusionType: "folder" },
      { id: "4", value: "C:\\Other\\", pathExclusionType: "subfolders" },
    ];
    const [exact, covering] = findExisting(rows, "C:\\Program Files\\Vendor\\App\\", "windows");
    expect(exact.map((r) => r.id)).toEqual(["1"]);
    expect(covering.map((r) => r.id)).toEqual(["2"]);
  });

  it("caps the audit description at 500 chars", () => {
    const text = buildDescription("analyst@groupon.com", "x".repeat(1000), "31XZ173", "INSIGHT-1");
    expect(text.startsWith("[MCP] Approved by: analyst@groupon.com | Ref: INSIGHT-1")).toBe(true);
    expect(text).toHaveLength(500);
  });
});

describe("path exclusions — tools", () => {
  it("is disabled unless PURPLE_ENABLE_EXCLUSION_TOOLS is on (even the preview)", async () => {
    const { fetchImpl, calls } = fakeConsole({});
    const r = await call(makeCtx(fetchImpl, { enabled: false }), "create_path_exclusion", { ...ARGS, confirm: true });
    expect(r.error.code).toBe("denied");
    expect(r.error.hint).toContain("SOAR");
    expect(calls).toHaveLength(0);
  });

  it("preview never POSTs and scopes to the agent's group", async () => {
    const { fetchImpl, calls } = fakeConsole({});
    const r = await call(makeCtx(fetchImpl), "create_path_exclusion", ARGS);
    expect(r.error).toBeNull();
    expect(r.data.mode).toBe("preview");
    expect(r.data.plan.status).toBe("ready");
    expect(r.data.plan.scope_id).toBe("300");
    expect(r.data.plan.path_type).toBe("subfolders");
    expect(r.data.plan.description).toContain("analyst@groupon.com");
    expect(r.data.next_step).toContain("confirm=true");
    const list = calls.find((c) => c.method === "GET" && c.url.pathname.endsWith("/exclusions"))!;
    expect(list.url.searchParams.get("groupIds")).toBe("300");
    expect(list.url.searchParams.get("includeParents")).toBe("true");
    expect(list.url.searchParams.get("osTypes")).toBe("windows");
    expect(posts(calls)).toHaveLength(0);
  });

  it("confirm POSTs once on the write token", async () => {
    const { fetchImpl, calls } = fakeConsole({});
    const r = await call(makeCtx(fetchImpl), "create_path_exclusion", { ...ARGS, confirm: true });
    expect(r.error).toBeNull();
    expect(r.data.mode).toBe("executed");
    expect(r.data.exclusion.id).toBe("9001");
    expect(r.data.confirmed_by).toBe("analyst-1");
    const [post, ...rest] = posts(calls);
    expect(rest).toHaveLength(0);
    expect(post!.token).toBe("Bearer write-token");
    expect(post!.body).toMatchObject({
      filter: { groupIds: ["300"] },
      data: { type: "path", value: ARGS.path, osType: "windows", pathExclusionType: "subfolders", mode: ARGS.mode },
    });
  });

  it("site scope uses siteIds and warns", async () => {
    const { fetchImpl, calls } = fakeConsole({});
    const r = await call(makeCtx(fetchImpl), "create_path_exclusion", { ...ARGS, scope_level: "site", confirm: true });
    expect(r.data.mode).toBe("executed");
    expect((posts(calls)[0]!.body as Json).filter).toEqual({ siteIds: ["200"] });
    expect(r.data.plan.warnings.some((w: string) => w.includes("Site scope"))).toBe(true);
  });

  it("fails closed without a write token", async () => {
    const { fetchImpl, calls } = fakeConsole({});
    const r = await call(makeCtx(fetchImpl, { writeToken: false }), "create_path_exclusion", { ...ARGS, confirm: true });
    expect(r.error.code).toBe("denied");
    expect(posts(calls)).toHaveLength(0);
  });

  it("does not retry the POST on a 503", async () => {
    const { fetchImpl, calls } = fakeConsole({ postStatus: 503 });
    const r = await call(makeCtx(fetchImpl), "create_path_exclusion", { ...ARGS, confirm: true });
    expect(r.error).not.toBeNull();
    expect(posts(calls)).toHaveLength(1);
  });

  it("refuses risky paths without a lookup or POST", async () => {
    const { fetchImpl, calls } = fakeConsole({});
    const r = await call(makeCtx(fetchImpl), "create_path_exclusion", {
      ...ARGS,
      path: "C:\\Users\\*\\AppData\\Local\\",
      confirm: true,
    });
    expect(r.data.mode).toBe("not_executed");
    expect(r.data.reason).toBe("rejected");
    expect(calls.filter((c) => c.url.pathname.endsWith("/exclusions"))).toHaveLength(0);
  });

  it("reports an existing exclusion on page 2 instead of duplicating it", async () => {
    const rows: Json[] = [
      { id: "1", value: "C:\\A\\", pathExclusionType: "subfolders" },
      { id: "2", value: "C:\\B\\", pathExclusionType: "subfolders" },
      { id: "77", value: "c:\\program files\\vendor\\app\\*", scopeName: "site" },
    ];
    const { fetchImpl, calls } = fakeConsole({ exclusions: rows, pageSize: 2 });
    const r = await call(makeCtx(fetchImpl), "create_path_exclusion", { ...ARGS, confirm: true });
    expect(r.data.reason).toBe("already_exists");
    expect(r.data.plan.existing[0].id).toBe("77");
    expect(posts(calls)).toHaveLength(0);
  });

  it("treats a same-mode parent sub-folder exclusion as already covering", async () => {
    const parent = { id: "78", value: "C:\\Program Files\\Vendor\\*", pathExclusionType: "subfolders", mode: ARGS.mode };
    const { fetchImpl, calls } = fakeConsole({ exclusions: [parent] });
    const r = await call(makeCtx(fetchImpl), "create_path_exclusion", { ...ARGS, confirm: true });
    expect(r.data.reason).toBe("already_covered");
    expect(posts(calls)).toHaveLength(0);
  });

  it.each(["reason", "approved_by", "path"])("requires %s", async (field) => {
    const { fetchImpl, calls } = fakeConsole({});
    const r = await call(makeCtx(fetchImpl), "create_path_exclusion", { ...ARGS, [field]: "  ", confirm: true });
    expect(r.error.code).toBe("validation");
    expect(calls).toHaveLength(0);
  });

  it("rejects decommissioned agents and unknown scope levels", async () => {
    const dec = fakeConsole({ agents: [{ ...AGENT, isDecommissioned: true }] });
    const r1 = await call(makeCtx(dec.fetchImpl), "create_path_exclusion", { ...ARGS, confirm: true });
    expect(r1.data.reason).toBe("rejected");
    const r2 = await call(makeCtx(fakeConsole({}).fetchImpl), "create_path_exclusion", { ...ARGS, scope_level: "account" });
    expect(r2.error.code).toBe("validation");
  });

  it("list_path_exclusions scopes to the agent's group, parents and OS", async () => {
    const rows = [{ id: "1", value: "C:\\A\\", mode: "suppress", scopeName: "site" }];
    const { fetchImpl, calls } = fakeConsole({ exclusions: rows });
    const r = await call(makeCtx(fetchImpl, { enabled: false }), "list_path_exclusions", {
      endpoint: "31XZ173",
      value_contains: "A",
    });
    expect(r.error).toBeNull();
    expect(r.data.count).toBe(1);
    expect(r.data.exclusions[0].scope).toBe("site");
    const list = calls.find((c) => c.url.pathname.endsWith("/exclusions"))!;
    expect(list.url.searchParams.get("groupIds")).toBe("300");
    expect(list.url.searchParams.get("value__contains")).toBe("A");
    expect(list.url.searchParams.get("osTypes")).toBe("windows");
  });
});
