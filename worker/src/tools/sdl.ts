// SDL PowerQuery tools: `powerquery` (general threat-hunting) and
// `get_storyline_events` (EDR process-tree reconstruction). Both use the
// bounded-sync poller; long queries return a signed `next_cursor` the agent
// echoes back to resume polling (see src/sdl/poller.ts).
//
// Ports of tools/sdl.py + libs/investigation/collector._fetch_storyline_events.

import { ToolDescriptor } from "../mcp.js";
import {
  ToolFn,
  ToolResult,
  boundedInt,
  optionalString,
  optionalStringArray,
  requireString,
  runTool,
} from "../tool-base.js";
import { ValidationError } from "../errors.js";
import { executePowerQuery, resumePowerQuery, SdlExecOutput, SdlPollOptions } from "../sdl/poller.js";
import { SdlPqAttributes } from "../sdl/types.js";

// Curated EDR projection — identical to the Python storyline query so an agent
// gets the exact columns it needs to rebuild a process tree without bloat.
const STORYLINE_COLUMNS =
  "event.time, event.type, event.category, " +
  "endpoint.name, endpoint.os, " +
  "src.process.name, src.process.cmdline, src.process.pid, src.process.user, " +
  "src.process.storyline.id, " +
  "tgt.process.name, tgt.process.cmdline, tgt.process.pid, " +
  "tgt.process.storyline.id, " +
  "tgt.file.path, tgt.file.sha256, " +
  "dns.request, url.address, " +
  "dst.ip.address, dst.port.number";

function pollOptions(ctx: Parameters<ToolFn>[0], maxResults?: number): SdlPollOptions {
  return {
    client: ctx.sdl.client,
    signer: ctx.cursorSigner,
    budgetMs: ctx.sdl.budgetMs,
    intervalMs: ctx.sdl.intervalMs,
    maxResults: maxResults ?? ctx.sdl.maxResults,
  };
}

// Shape the poller output into the tool's `data` block + envelope next_cursor.
function shape(out: SdlExecOutput, extra: Record<string, unknown> = {}): ToolResult {
  return {
    data: {
      ...extra,
      complete: out.complete,
      resumed: out.resumed,
      columns: out.columns.map((c) => c.name),
      column_types: out.columns.map((c) => ({ name: c.name, type: c.type })),
      rows: out.rows,
      returned_count: out.row_count,
      cumulative_count: out.cumulative_rows,
      match_count: out.match_count,
      steps_completed: out.steps_completed,
      total_steps: out.total_steps,
      truncated_at_limit: out.truncated_at_limit,
      partial_results_due_to_time_limit: out.partial_results_due_to_time_limit,
      omitted_events: out.omitted_events,
      discarded_array_items: out.discarded_array_items,
      warnings: out.warnings,
      poll_hint: out.next_cursor
        ? "Query did not finish within the poll budget. Call this tool again with `cursor` set to next_cursor to fetch more rows. Resume PROMPTLY — the SDL query expires ~30s after the last poll."
        : null,
    },
    next_cursor: out.next_cursor,
  };
}

const powerquery: ToolFn = (ctx, args) =>
  runTool("POST /sdl/v2/api/queries", async (): Promise<ToolResult> => {
    const cursor = optionalString(args.cursor, "cursor");
    if (cursor) {
      const out = await resumePowerQuery(pollOptions(ctx), cursor);
      return shape(out);
    }

    const query = requireString(args.query, "query");
    const startDatetime = requireString(args.start_datetime, "start_datetime");
    const endDatetime = requireString(args.end_datetime, "end_datetime");
    const resultType = (optionalString(args.result_type, "result_type") ?? "TABLE").toUpperCase();
    if (resultType !== "TABLE") {
      throw new ValidationError(`result_type '${resultType}' is not supported (only TABLE).`);
    }
    const frequency = (optionalString(args.frequency, "frequency") ?? "LOW").toUpperCase();
    if (frequency !== "LOW" && frequency !== "HIGH") {
      throw new ValidationError("frequency must be LOW or HIGH.");
    }
    const queryPriority = (optionalString(args.query_priority, "query_priority") ?? "LOW").toUpperCase();
    if (queryPriority !== "LOW" && queryPriority !== "HIGH") {
      throw new ValidationError("query_priority must be LOW or HIGH.");
    }
    const accountIds = optionalStringArray(args.account_ids, "account_ids") ?? ctx.accountIdsDefault ?? undefined;

    const pq: SdlPqAttributes = { query, resultType: "TABLE", frequency: frequency as "LOW" | "HIGH" };
    const out = await executePowerQuery(pollOptions(ctx), {
      startTime: startDatetime,
      endTime: endDatetime,
      pq,
      accountIds,
      queryPriority: queryPriority as "LOW" | "HIGH",
    });
    return shape(out, { query });
  });

const get_storyline_events: ToolFn = (ctx, args) =>
  runTool("POST /sdl/v2/api/queries (storyline)", async (): Promise<ToolResult> => {
    const cursor = optionalString(args.cursor, "cursor");
    if (cursor) {
      const out = await resumePowerQuery(pollOptions(ctx), cursor);
      return shape(out, { kind: "storyline" });
    }

    const storylineId = requireString(args.storyline_id, "storyline_id").trim();
    if (storylineId.includes("'")) {
      throw new ValidationError("storyline_id contains a single quote and cannot be safely quoted in PQ.");
    }
    const timeWindowHours = boundedInt(args.time_window_hours, "time_window_hours", 72, 1, 24 * 30);
    const limit = boundedInt(args.limit, "limit", 500, 1, 100_000);

    const endMs = Date.now();
    const startMs = endMs - timeWindowHours * 3_600_000;
    const startIso = new Date(startMs).toISOString();
    const endIso = new Date(endMs).toISOString();

    const query =
      `src.process.storyline.id='${storylineId}' ` +
      `OR tgt.process.storyline.id='${storylineId}' ` +
      `| columns ${STORYLINE_COLUMNS} ` +
      `| sort -event.time ` +
      `| limit ${limit}`;

    const pq: SdlPqAttributes = { query, resultType: "TABLE", frequency: "LOW" };
    const out = await executePowerQuery(pollOptions(ctx, limit), {
      startTime: startIso,
      endTime: endIso,
      pq,
      accountIds: ctx.accountIdsDefault ?? undefined,
      queryPriority: "LOW",
    });

    // Project rows into {fields: {col: value}} for ergonomic consumption,
    // matching the Python StorylineSection.events shape.
    const colNames = out.columns.map((c) => c.name);
    const events = out.rows.map((row) => {
      const fields: Record<string, unknown> = {};
      colNames.forEach((name, i) => { fields[name] = row[i]; });
      return { fields };
    });
    const shaped = shape(out, { kind: "storyline", storyline_id: storylineId, query, events });
    return shaped;
  });

export const SDL_TOOLS: Record<string, ToolFn> = {
  powerquery,
  get_storyline_events,
};

export const SDL_DESCRIPTORS: ToolDescriptor[] = [
  {
    name: "powerquery",
    description:
      "Run a SentinelOne Singularity Data Lake PowerQuery for threat hunting. Returns a TABLE result (columns + rows). Long queries poll within a bounded budget and return `next_cursor`; call again with `cursor` to resume (promptly — the SDL query expires ~30s after the last poll).",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "The PowerQuery to execute. Required unless `cursor` is set." },
        start_datetime: { type: "string", description: "Window start: ISO-8601, relative ('24h','7d'), or epoch (s/ms/ns). Required unless `cursor` is set." },
        end_datetime: { type: "string", description: "Window end: ISO-8601, relative, or epoch. Required unless `cursor` is set." },
        result_type: { type: "string", enum: ["TABLE"], default: "TABLE" },
        frequency: { type: "string", enum: ["LOW", "HIGH"], default: "LOW" },
        query_priority: { type: "string", enum: ["LOW", "HIGH"], default: "LOW" },
        account_ids: { type: "array", items: { type: "string" }, description: "Restrict the query to these account IDs." },
        cursor: { type: "string", description: "Resume token from a prior call's next_cursor. When set, all other args are ignored." },
      },
      additionalProperties: false,
    },
  },
  {
    name: "get_storyline_events",
    description:
      "Fetch SDL EDR events for a SentinelOne storyline (filtered on src/tgt process storyline.id) and return a curated process-tree projection. Pair with initiate_investigation's summary.storyline_id. Empty results are NORMAL for rule-based (non-EDR) detections. Long queries return `next_cursor` to resume.",
    inputSchema: {
      type: "object",
      properties: {
        storyline_id: { type: "string", description: "Storyline identifier. Required unless `cursor` is set." },
        time_window_hours: { type: "integer", minimum: 1, default: 72 },
        limit: { type: "integer", minimum: 1, default: 500 },
        cursor: { type: "string", description: "Resume token from a prior call's next_cursor." },
      },
      additionalProperties: false,
    },
  },
];
