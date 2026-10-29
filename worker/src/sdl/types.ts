// Wire shapes for the SDL (Singularity Data Lake) Query API. Mirrors the Pydantic
// models in purple-mcp's libs/sdl/models.py (camelCase wire keys).

export type SdlQueryPriority = "LOW" | "HIGH";
export type SdlPqFrequency = "LOW" | "HIGH";
export type SdlPqResultType = "TABLE" | "PLOT";
export type PqColumnType = "NUMBER" | "PERCENTAGE" | "STRING" | "TIMESTAMP";

export interface SdlColumn {
  name: string;
  type: PqColumnType; // wire key may be `cellType` or `type`
  decimalPlaces?: number | null;
}

export interface SdlTableResultData {
  matchCount: number;
  values: unknown[][];
  columns: SdlColumn[];
  keyColumns?: number | null;
  omittedEvents?: number | null;
  partialResultsDueToTimeLimit?: boolean | null;
  discardedArrayItems?: number | null;
  warnings: string[];
}

export interface SdlErrorObject {
  message: string;
  details?: Record<string, unknown> | null;
}

// SDLQueryResult / SDLSubmitQueryResponse / SDLPingResponse share this shape.
export interface SdlQueryResult {
  id: string | null;
  stepsCompleted: number;
  totalSteps: number;
  resolvedTimeRange?: { start: number; end: number } | null;
  error?: SdlErrorObject | null;
  cpuUsage?: number;
  data?: SdlTableResultData | null;
}

export interface SdlPqAttributes {
  query: string;
  resultType: SdlPqResultType;
  frequency: SdlPqFrequency;
}

// Normalize the raw column array (which may use `cellType` or `type`).
export function normalizeColumns(raw: unknown): SdlColumn[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((c) => {
    const o = (c ?? {}) as Record<string, unknown>;
    return {
      name: String(o.name ?? ""),
      type: (o.cellType ?? o.type ?? "STRING") as PqColumnType,
      decimalPlaces: (o.decimalPlaces as number | null | undefined) ?? null,
    };
  });
}

// Parse a raw SDL query/ping/submit response into SdlQueryResult.
export function parseSdlResult(raw: Record<string, unknown>): SdlQueryResult {
  const dataRaw = raw["data"] as Record<string, unknown> | null | undefined;
  let data: SdlTableResultData | null = null;
  if (dataRaw && typeof dataRaw === "object") {
    data = {
      matchCount: Number(dataRaw["matchCount"] ?? 0),
      values: Array.isArray(dataRaw["values"]) ? (dataRaw["values"] as unknown[][]) : [],
      columns: normalizeColumns(dataRaw["columns"]),
      keyColumns: (dataRaw["keyColumns"] as number | null | undefined) ?? null,
      omittedEvents: (dataRaw["omittedEvents"] as number | null | undefined) ?? null,
      partialResultsDueToTimeLimit:
        (dataRaw["partialResultsDueToTimeLimit"] as boolean | null | undefined) ?? null,
      discardedArrayItems: (dataRaw["discardedArrayItems"] as number | null | undefined) ?? null,
      warnings: Array.isArray(dataRaw["warnings"]) ? (dataRaw["warnings"] as string[]) : [],
    };
  }
  return {
    id: (raw["id"] as string | null) ?? null,
    stepsCompleted: Number(raw["stepsCompleted"] ?? 0),
    totalSteps: Number(raw["totalSteps"] ?? 0),
    resolvedTimeRange: (raw["resolvedTimeRange"] as { start: number; end: number } | null) ?? null,
    error: (raw["error"] as SdlErrorObject | null) ?? null,
    cpuUsage: Number(raw["cpuUsage"] ?? 0),
    data,
  };
}
