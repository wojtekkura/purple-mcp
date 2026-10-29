// initiate_investigation — multi-API incident bundle for triage sub-agents.
// Port of tools/investigation.py + libs/investigation/collector.py (the `collect`
// path; storyline events are a separate tool, see tools/sdl.ts get_storyline_events).
//
// Flow:
//   1. Resolve alert_id (UUID passthrough, or externalId -> UUID via search).
//   2. Fetch the primary alert (anchors everything; NotFound -> error envelope).
//   3. Fan out concurrently (Promise.all): related alerts on the same endpoint
//      within the window, asset inventory, remediation (history + notes).
//   4. Assemble a bundle with per-section status (ok|empty|skipped|failed).

import { ToolDescriptor } from "../mcp.js";
import {
  ToolContext,
  ToolFn,
  ToolResult,
  boundedInt,
  requireString,
  runTool,
} from "../tool-base.js";
import { NotFoundError, ValidationError } from "../errors.js";
import { clampToFitBytes } from "../envelope.js";
import {
  fetchAlertById,
  fetchAlertHistoryRaw,
  fetchAlertNotesRaw,
  filterDatetimeRange,
  filterStringEqual,
  searchAlertsRaw,
} from "./alerts.js";
import { fetchInventoryItem } from "./inventory.js";

type SectionStatus = "ok" | "empty" | "skipped" | "failed";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function asObject(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

async function resolveAlertId(ctx: ToolContext, raw: string): Promise<string> {
  if (UUID_RE.test(raw)) return raw;
  // externalId resolution (collector._resolve_alert_id).
  const res = await searchAlertsRaw(ctx, [filterStringEqual("externalId", raw)], 2, "ALL");
  const ids = res.edges.map((e) => String((e.node as Record<string, unknown>).id ?? "")).filter(Boolean);
  if (ids.length === 0) {
    throw new NotFoundError(
      `No alert found with id or externalId=${JSON.stringify(raw)}.`,
      { hint: "UUIDs look like '019de8cc-…'; externalIds are long numeric strings." },
    );
  }
  if (ids.length > 1) {
    throw new ValidationError(
      `Ambiguous: ${ids.length} alerts share externalId=${JSON.stringify(raw)}. Pass the internal UUID instead.`,
    );
  }
  return ids[0]!;
}

const initiate_investigation: ToolFn = (ctx, args) =>
  runTool("POST /investigation (initiate_investigation)", async (): Promise<ToolResult> => {
    const rawAlertId = requireString(args.alert_id, "alert_id").trim();
    const timeWindowHours = boundedInt(args.time_window_hours, "time_window_hours", 72, 1, 24 * 30);
    const relatedLimit = boundedInt(args.related_alerts_limit, "related_alerts_limit", 50, 1, 100);
    const remediationLimit = boundedInt(args.remediation_history_limit, "remediation_history_limit", 50, 1, 100);

    const endMs = Date.now();
    const startMs = endMs - timeWindowHours * 3_600_000;
    const windowStartIso = new Date(startMs).toISOString();
    const windowEndIso = new Date(endMs).toISOString();
    const warnings: string[] = [];

    // ---- Phase 1: primary alert.
    const resolvedId = await resolveAlertId(ctx, rawAlertId);
    const primary = await fetchAlertById(ctx, resolvedId);
    if (primary === null) {
      throw new NotFoundError(`Primary alert ${resolvedId} not found.`, {
        hint: "Without the primary alert we have no asset_id to drive the other sections.",
      });
    }

    const asset = asObject(primary.asset);
    const assetId = asset ? (asset.id as string | undefined) ?? null : null;
    const storylineId = (primary.storylineId as string | undefined) ?? null;
    if (!assetId) {
      warnings.push("Primary alert has no asset.id; related-alerts and inventory sections were skipped.");
    }
    if (!storylineId) {
      warnings.push("Primary alert has no storylineId; get_storyline_events cannot be used for this incident.");
    }

    // ---- Phase 2: fan out (Promise.all; each section captures its own failure).
    const [relatedSection, inventorySection, remediationSection] = await Promise.all([
      fetchRelatedAlerts(ctx, assetId, resolvedId, startMs, endMs, relatedLimit),
      fetchAssetInventory(ctx, assetId),
      fetchRemediation(ctx, resolvedId, remediationLimit),
    ]);

    const summary = {
      alert_id: resolvedId,
      asset_id: assetId,
      asset_name: asset ? asset.name ?? null : null,
      asset_type: asset ? asset.type ?? null : null,
      storyline_id: storylineId,
      severity: primary.severity ?? null,
      status: primary.status ?? null,
      name: primary.name ?? null,
      detected_at: primary.detectedAt ?? null,
      classification: primary.classification ?? null,
      analyst_verdict: primary.analystVerdict ?? null,
      detection_source: primary.detectionSource ?? null,
      time_window_hours: timeWindowHours,
      time_window_start: windowStartIso,
      time_window_end: windowEndIso,
    };

    return {
      data: {
        schema_version: 2,
        summary,
        primary_alert: { status: "ok" as SectionStatus, alert: primary },
        related_alerts: relatedSection,
        asset_inventory: inventorySection,
        remediation: remediationSection,
        warnings,
      },
    };
  });

async function fetchRelatedAlerts(
  ctx: ToolContext,
  assetId: string | null,
  primaryAlertId: string,
  startMs: number,
  endMs: number,
  limit: number,
): Promise<Record<string, unknown>> {
  if (!assetId) return { status: "skipped" as SectionStatus };
  try {
    const res = await searchAlertsRaw(
      ctx,
      [filterStringEqual("assetId", assetId), filterDatetimeRange("createdAt", startMs, endMs)],
      limit,
      "ALL",
    );
    // Drop the primary alert so sub-agents don't double-count.
    const nodes = res.edges
      .map((e) => e.node)
      .filter((n) => String((n as Record<string, unknown>).id ?? "") !== primaryAlertId);
    if (nodes.length === 0) {
      return { status: "empty" as SectionStatus, total_count: res.totalCount, returned_count: 0, truncated: res.hasNextPage };
    }
    const { kept, truncated } = clampToFitBytes(nodes, (k) => ({
      status: "ok",
      total_count: res.totalCount,
      returned_count: k.length,
      truncated: res.hasNextPage,
      alerts: k,
    }));
    return {
      status: "ok" as SectionStatus,
      total_count: res.totalCount,
      returned_count: kept.length,
      truncated: res.hasNextPage || truncated > 0,
      dropped_to_fit: truncated,
      alerts: kept,
    };
  } catch (e) {
    return { status: "failed" as SectionStatus, error: e instanceof Error ? e.message : String(e) };
  }
}

async function fetchAssetInventory(ctx: ToolContext, assetId: string | null): Promise<Record<string, unknown>> {
  if (!assetId) return { status: "skipped" as SectionStatus };
  try {
    const item = await fetchInventoryItem(ctx, assetId);
    if (item === null) return { status: "empty" as SectionStatus, error: `Inventory item ${assetId} not found` };
    return { status: "ok" as SectionStatus, item };
  } catch (e) {
    return { status: "failed" as SectionStatus, error: e instanceof Error ? e.message : String(e) };
  }
}

async function fetchRemediation(
  ctx: ToolContext,
  alertId: string,
  historyLimit: number,
): Promise<Record<string, unknown>> {
  const [historyRes, notesRes] = await Promise.allSettled([
    fetchAlertHistoryRaw(ctx, alertId, historyLimit),
    fetchAlertNotesRaw(ctx, alertId),
  ]);

  let historyEvents: Record<string, unknown>[] = [];
  let historyTruncated = false;
  let historyError: string | null = null;
  if (historyRes.status === "fulfilled") {
    historyEvents = historyRes.value.edges.map((e) => e.node);
    historyTruncated = historyRes.value.hasNextPage;
  } else {
    historyError = String(historyRes.reason?.message ?? historyRes.reason);
  }

  let notes: Record<string, unknown>[] = [];
  let notesError: string | null = null;
  if (notesRes.status === "fulfilled") notes = notesRes.value;
  else notesError = String(notesRes.reason?.message ?? notesRes.reason);

  if (historyError && notesError) {
    return {
      status: "failed" as SectionStatus,
      history_error: historyError,
      notes_error: notesError,
      error: `history: ${historyError}; notes: ${notesError}`,
    };
  }
  if (historyEvents.length === 0 && notes.length === 0) {
    return {
      status: "empty" as SectionStatus,
      history_error: historyError,
      notes_error: notesError,
      history_truncated: historyTruncated,
    };
  }
  return {
    status: "ok" as SectionStatus,
    history_events: historyEvents,
    history_truncated: historyTruncated,
    notes,
    history_error: historyError,
    notes_error: notesError,
  };
}

export const INVESTIGATION_TOOLS: Record<string, ToolFn> = {
  initiate_investigation,
};

export const INVESTIGATION_DESCRIPTORS: ToolDescriptor[] = [
  {
    name: "initiate_investigation",
    description:
      "Assemble a SOAR-ready incident bundle for a SentinelOne alert: the primary alert, related alerts on the same endpoint within the time window, the asset inventory record, and remediation history + analyst notes. Accepts an internal alert UUID or a numeric externalId (auto-resolved). Storyline EDR events are intentionally excluded (they can be 100k+ rows) — use summary.storyline_id with get_storyline_events on demand.",
    inputSchema: {
      type: "object",
      required: ["alert_id"],
      properties: {
        alert_id: { type: "string", description: "Internal alert UUID or numeric externalId." },
        time_window_hours: { type: "integer", minimum: 1, default: 72, description: "Lookback for related alerts." },
        related_alerts_limit: { type: "integer", minimum: 1, maximum: 100, default: 50 },
        remediation_history_limit: { type: "integer", minimum: 1, maximum: 100, default: 50 },
      },
      additionalProperties: false,
    },
  },
];
