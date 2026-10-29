// Bounded-sync SDL PowerQuery execution with resume cursors.
//
// Workers can't safely hold a request open for the SDL max (~5 min), so we poll
// only up to a wall-clock budget (PURPLE_SDL_POLL_BUDGET_MS). If the query
// finishes within the budget we return the full result. If not, we return the
// rows fetched so far plus a signed `next_cursor` carrying the SDL query id,
// forward tag, and last-step-seen; the agent calls the tool again with that
// cursor to resume polling from where we left off.
//
// IMPORTANT: the SDL query's server-side TTL is ~30s between pings, so a resume
// cursor must be used promptly. We surface that in the truncation hint.
//
// Incremental model (from libs/sdl/sdl_query_handler.py): each ping with
// `lastStepSeen=N` returns only the rows produced since step N; we advance
// lastStepSeen to `stepsCompleted` and the query is complete when
// lastStepSeen === totalSteps.

import { CursorSigner } from "../cursor.js";
import { ValidationError } from "../errors.js";
import { SdlClient } from "./client.js";
import { SdlColumn, SdlPqAttributes, SdlQueryResult } from "./types.js";

export interface SdlResumeState {
  v: 1;
  queryId: string;
  forwardTag: string;
  lastStepSeen: number;
  totalSteps: number;
  cumulativeRows: number; // total rows handed to the agent across all calls (for the global cap)
}

export interface SdlPollOptions {
  client: SdlClient;
  signer: CursorSigner;
  budgetMs: number;
  intervalMs: number;
  maxResults: number;
}

export interface SdlExecOutput {
  columns: SdlColumn[];
  rows: unknown[][];          // rows fetched during THIS call (the agent concatenates across calls)
  row_count: number;          // rows.length
  match_count: number;
  complete: boolean;
  steps_completed: number;
  total_steps: number;
  cumulative_rows: number;    // total rows across all calls so far
  truncated_at_limit: boolean;
  partial_results_due_to_time_limit: boolean;
  omitted_events: number | null;
  discarded_array_items: number | null;
  warnings: string[];
  next_cursor: string | null;
  resumed: boolean;
}

// Fresh execution: submit then poll within budget.
export async function executePowerQuery(
  opts: SdlPollOptions,
  args: {
    startTime: string;
    endTime: string;
    pq: SdlPqAttributes;
    tenant?: boolean;
    accountIds?: string[];
    queryPriority?: "LOW" | "HIGH";
  },
): Promise<SdlExecOutput> {
  const submitted = await opts.client.submit({
    startTime: args.startTime,
    endTime: args.endTime,
    pq: args.pq,
    tenant: args.tenant,
    accountIds: args.accountIds,
    queryPriority: args.queryPriority,
  });

  const first = submitted.result;
  if (first.error) {
    throw new ValidationError(`SDL rejected the query: ${first.error.message}`, {
      hint: "Check PowerQuery syntax and the time range.",
    });
  }
  if (!first.id) {
    throw new ValidationError("SDL submit returned no query id.", {
      hint: "The query was rejected before execution; verify syntax and time range.",
    });
  }

  const acc = new Accumulator(opts.maxResults);
  acc.absorbInitial(first);

  const state: SdlResumeState = {
    v: 1,
    queryId: first.id,
    forwardTag: submitted.forwardTag,
    lastStepSeen: first.stepsCompleted,
    totalSteps: first.totalSteps,
    cumulativeRows: acc.rows.length,
  };

  return await drain(opts, state, acc, /*resumed*/ false);
}

// Resume execution from a previously returned cursor.
export async function resumePowerQuery(
  opts: SdlPollOptions,
  cursor: string,
): Promise<SdlExecOutput> {
  const decoded = (await opts.signer.verify(cursor)) as Partial<SdlResumeState>;
  if (
    !decoded ||
    decoded.v !== 1 ||
    typeof decoded.queryId !== "string" ||
    typeof decoded.forwardTag !== "string" ||
    typeof decoded.lastStepSeen !== "number" ||
    typeof decoded.totalSteps !== "number"
  ) {
    throw new ValidationError("Cursor is not a valid SDL resume cursor.", {
      hint: "Pass the exact `next_cursor` from the previous powerquery call, or omit it to start a new query.",
    });
  }
  const state: SdlResumeState = {
    v: 1,
    queryId: decoded.queryId,
    forwardTag: decoded.forwardTag,
    lastStepSeen: decoded.lastStepSeen,
    totalSteps: decoded.totalSteps,
    cumulativeRows: typeof decoded.cumulativeRows === "number" ? decoded.cumulativeRows : 0,
  };
  const acc = new Accumulator(opts.maxResults, state.cumulativeRows);
  return await drain(opts, state, acc, /*resumed*/ true);
}

// Shared poll loop: ping until complete, budget exhausted, or global cap hit.
async function drain(
  opts: SdlPollOptions,
  state: SdlResumeState,
  acc: Accumulator,
  resumed: boolean,
): Promise<SdlExecOutput> {
  const start = Date.now();
  let complete = state.lastStepSeen >= state.totalSteps;

  while (!complete && !acc.atLimit) {
    if (Date.now() - start > opts.budgetMs) break;

    const resp = await opts.client.ping(state.queryId, state.forwardTag, state.lastStepSeen);
    if (resp.error) {
      throw new ValidationError(`SDL query errored mid-flight: ${resp.error.message}`);
    }
    state.totalSteps = resp.totalSteps;
    acc.absorb(resp);
    state.lastStepSeen = resp.stepsCompleted;
    complete = state.lastStepSeen >= state.totalSteps;

    if (!complete) await sleep(opts.intervalMs);
  }

  state.cumulativeRows = acc.cumulative;

  // Stop early if we hit the global row cap even if more steps remain.
  if (acc.atLimit) complete = complete || false; // keep as-is; truncated flag tells the story

  if (complete) {
    // Best-effort cleanup so the backend can free the query.
    await opts.client.deleteQuery(state.queryId, state.forwardTag);
  }

  const nextCursor = complete || acc.atLimit ? null : await opts.signer.sign(state);

  return {
    columns: acc.columns,
    rows: acc.rows,
    row_count: acc.rows.length,
    match_count: acc.matchCount,
    complete: complete || acc.atLimit,
    steps_completed: state.lastStepSeen,
    total_steps: state.totalSteps,
    cumulative_rows: acc.cumulative,
    truncated_at_limit: acc.atLimit,
    partial_results_due_to_time_limit: acc.partialTime,
    omitted_events: acc.omittedEvents,
    discarded_array_items: acc.discardedArrayItems,
    warnings: acc.warnings,
    next_cursor: nextCursor,
    resumed,
  };
}

// Accumulates only the rows fetched during the current call, while tracking the
// cumulative count across calls so the global max_query_results cap holds.
class Accumulator {
  columns: SdlColumn[] = [];
  rows: unknown[][] = [];
  matchCount = 0;
  warnings: string[] = [];
  partialTime = false;
  omittedEvents: number | null = null;
  discardedArrayItems: number | null = null;
  atLimit = false;
  cumulative: number;

  constructor(private readonly maxResults: number, priorCumulative = 0) {
    this.cumulative = priorCumulative;
    if (this.cumulative >= maxResults) this.atLimit = true;
  }

  absorbInitial(r: SdlQueryResult): void {
    this.absorb(r);
  }

  absorb(r: SdlQueryResult): void {
    const d = r.data;
    if (!d) return;
    if (d.columns.length) this.columns = d.columns;
    this.matchCount = d.matchCount;
    if (d.warnings.length) this.warnings = d.warnings;
    if (d.partialResultsDueToTimeLimit) this.partialTime = true;
    if (d.omittedEvents != null) this.omittedEvents = d.omittedEvents;
    if (d.discardedArrayItems != null) this.discardedArrayItems = d.discardedArrayItems;

    if (this.atLimit) return;
    const remaining = this.maxResults - this.cumulative;
    if (remaining <= 0) {
      this.atLimit = true;
      return;
    }
    const incoming = d.values;
    if (incoming.length > remaining) {
      this.rows.push(...incoming.slice(0, remaining));
      this.cumulative += remaining;
      this.atLimit = true;
    } else {
      this.rows.push(...incoming);
      this.cumulative += incoming.length;
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}
