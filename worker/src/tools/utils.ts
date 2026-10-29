// Pure datetime helper tools — no upstream call. Ports of purple-mcp's
// get_timestamp_range and iso_to_unix_timestamp (tools/purple_utils.py).

import { ToolDescriptor } from "../mcp.js";
import {
  ToolFn,
  ToolResult,
  optionalInt,
  optionalString,
  requireString,
  runTool,
} from "../tool-base.js";
import { ValidationError } from "../errors.js";

// Build {iso, nanoseconds} for an epoch-millis instant.
function stamp(ms: number): { iso: string; nanoseconds: string } {
  return {
    iso: new Date(ms).toISOString(),
    // ns as a string to avoid float precision loss for large epoch values.
    nanoseconds: (BigInt(Math.trunc(ms)) * 1_000_000n).toString(),
  };
}

// Subtract a calendar/clock offset from an epoch-millis instant (UTC-aware for
// months/years; fixed-length for days/hours/minutes/seconds).
function subtractOffset(
  ms: number,
  off: { years: number; months: number; days: number; hours: number; minutes: number; seconds: number },
): number {
  const d = new Date(ms);
  if (off.years || off.months) {
    d.setUTCFullYear(d.getUTCFullYear() - off.years);
    d.setUTCMonth(d.getUTCMonth() - off.months);
  }
  const fixedMs =
    (off.days * 86_400 + off.hours * 3_600 + off.minutes * 60 + off.seconds) * 1000;
  return d.getTime() - fixedMs;
}

const get_timestamp_range: ToolFn = (_ctx, args) =>
  runTool("<local: get_timestamp_range>", async (): Promise<ToolResult> => {
    const ref = optionalString(args.reference_time, "reference_time");
    let endMs: number;
    if (ref === undefined) {
      endMs = Date.now();
    } else {
      const parsed = Date.parse(ref);
      if (!Number.isFinite(parsed)) {
        throw new ValidationError("reference_time must be a parseable ISO-8601 datetime.", {
          hint: "Example: 2026-06-24T00:00:00Z",
        });
      }
      endMs = parsed;
    }

    const off = {
      years: nonNegInt(args.years, "years"),
      months: nonNegInt(args.months, "months"),
      days: nonNegInt(args.days, "days"),
      hours: nonNegInt(args.hours, "hours"),
      minutes: nonNegInt(args.minutes, "minutes"),
      seconds: nonNegInt(args.seconds, "seconds"),
    };
    const total = off.years + off.months + off.days + off.hours + off.minutes + off.seconds;
    const startMs = total === 0 ? subtractOffset(endMs, { ...off, hours: 24 }) : subtractOffset(endMs, off);

    return {
      data: {
        start_datetime: stamp(startMs),
        end_datetime: stamp(endMs),
        offset_applied: total === 0 ? { hours: 24, note: "defaulted to a 24h window" } : off,
      },
    };
  });

const iso_to_unix_timestamp: ToolFn = (_ctx, args) =>
  runTool("<local: iso_to_unix_timestamp>", async (): Promise<ToolResult> => {
    const iso = requireString(args.iso_datetime, "iso_datetime");
    const ms = Date.parse(iso);
    if (!Number.isFinite(ms)) {
      throw new ValidationError("iso_datetime must be a parseable ISO-8601 datetime.", {
        hint: "Example: 2026-06-24T12:34:56Z",
      });
    }
    return { data: { iso_datetime: iso, unix_milliseconds: ms, unix_seconds: Math.trunc(ms / 1000) } };
  });

function nonNegInt(value: unknown, name: string): number {
  const n = optionalInt(value, name, 0);
  if (n < 0) throw new ValidationError(`${name} must be >= 0.`);
  return n;
}

export const UTILS_TOOLS: Record<string, ToolFn> = {
  get_timestamp_range,
  iso_to_unix_timestamp,
};

export const UTILS_DESCRIPTORS: ToolDescriptor[] = [
  {
    name: "get_timestamp_range",
    description:
      "Compute a start/end time window for PowerQuery. Returns both ISO-8601 and nanosecond timestamps. Provide an offset (years/months/days/hours/minutes/seconds) measured back from reference_time (or now). With no offset, defaults to a 24h window.",
    inputSchema: {
      type: "object",
      properties: {
        reference_time: { type: "string", description: "ISO-8601 end of the window; defaults to now (UTC)." },
        years: { type: "integer", minimum: 0 },
        months: { type: "integer", minimum: 0 },
        days: { type: "integer", minimum: 0 },
        hours: { type: "integer", minimum: 0 },
        minutes: { type: "integer", minimum: 0 },
        seconds: { type: "integer", minimum: 0 },
      },
      additionalProperties: false,
    },
  },
  {
    name: "iso_to_unix_timestamp",
    description: "Convert an ISO-8601 datetime string to a UNIX timestamp (milliseconds and seconds).",
    inputSchema: {
      type: "object",
      required: ["iso_datetime"],
      properties: { iso_datetime: { type: "string", description: "ISO-8601 datetime, e.g. 2026-06-24T12:34:56Z" } },
      additionalProperties: false,
    },
  },
];
