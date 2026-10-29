// Unified Alerts Management (UAM) tools: get_alert, list_alerts, search_alerts,
// get_alert_notes, get_alert_history.
//
// Faithful port of purple-mcp's:
//   - tools/alerts.py            (the 5 MCP tool wrappers + docstrings + DoS caps)
//   - libs/alerts/client.py      (GraphQL query strings, field catalog, variables)
//   - libs/alerts/models.py      (FilterInput wire shape, ViewType, connection shapes)
//   - tools/fields_validation.py (fields-param length/count caps)
//
// All GraphQL goes through ctx.client.graphql(ctx.endpoints.alertsGraphql, ...),
// which returns the already-unwrapped `data` object. Relay-style connections are
// reduced to { edges, totalCount, hasNextPage }; next_cursor is the upstream
// opaque pageInfo.endCursor passed straight through (NOT signed).

import { ToolDescriptor } from "../mcp.js";
import {
  ToolContext,
  ToolFn,
  ToolResult,
  boundedInt,
  optionalString,
  parseJsonFilters,
  requireString,
  runTool,
} from "../tool-base.js";
import { clampToFitBytes } from "../envelope.js";
import { NotFoundError, ValidationError } from "../errors.js";

// ---------------------------------------------------------------------------
// DoS protection constants (alerts.py:30-34, fields_validation.py:6-8)
// ---------------------------------------------------------------------------

const MAX_FILTERS_COUNT = 50;
const MAX_FILTER_VALUES_COUNT = 100;
const MAX_FIELDS_COUNT = 50;
const MAX_FIELD_LENGTH = 1024;
const MAX_FIELDS_JSON_LENGTH = 8192;

// ViewType enum (models.py:28-34).
const VIEW_TYPES = ["ALL", "ASSIGNED_TO_ME", "UNASSIGNED", "MY_TEAM"] as const;
type ViewType = (typeof VIEW_TYPES)[number];

// ---------------------------------------------------------------------------
// GraphQL query strings (client.py). The Python uses string.Template with
// ${data_sources_field}, ${view_type_param}, ${view_type_arg}, ${node_fields}.
// The Worker always targets the full modern schema (no probe/fallback path), so
// we inline the "full schema" substitution: dataSources is always available and
// viewType is always supported. The node-field block is interpolated per call.
// ---------------------------------------------------------------------------

// GET_ALERT_QUERY_TEMPLATE (client.py:67-105) with ${data_sources_field} -> dataSources.
const GET_ALERT_QUERY = `
query GetAlert($alertId: ID!) {
    alert(id: $alertId) {
        id
        externalId
        severity
        status
        name
        description
        detectedAt
        firstSeenAt
        lastSeenAt
        analystVerdict
        classification
        confidenceLevel
        dataSources
        detectionSource {
            product
            vendor
        }
        asset {
            id
            name
            type
        }
        assignee {
            userId
            email
            fullName
        }
        noteExists
        result
        storylineId
        ticketId
    }
}
`;

// GET_ALERT_NOTES_QUERY_TEMPLATE (client.py:153-170). No template params.
const GET_ALERT_NOTES_QUERY = `
query GetAlertNotes($alertId: ID!) {
    alertNotes(alertId: $alertId) {
        data {
            id
            text
            createdAt
            author {
                userId
                email
            }
            alertId
        }
    }
}
`;

// GET_ALERT_HISTORY_QUERY_TEMPLATE (client.py:173-203). No template params.
const GET_ALERT_HISTORY_QUERY = `
query GetAlertHistory($alertId: ID!, $first: Int!, $after: String) {
    alertHistory(alertId: $alertId, first: $first, after: $after) {
        edges {
            node {
                createdAt
                eventText
                eventType
                reportUrl
                historyItemCreator {
                    __typename
                    ... on UserHistoryItemCreator {
                        userId
                        userType
                    }
                }
            }
            cursor
        }
        pageInfo {
            hasNextPage
            hasPreviousPage
            startCursor
            endCursor
        }
        totalCount
    }
}
`;

// Build LIST_ALERTS / SEARCH_ALERTS queries from the node-field block, mirroring
// LIST/SEARCH_ALERTS_QUERY_TEMPLATE (client.py:107-151). viewType is always
// wired in (full-schema parity). ${data_sources_field} is injected separately
// from ${node_fields} to avoid a duplicate dataSources selection (client.py:329).
function buildListAlertsQuery(nodeFields: string, dataSourcesField: string): string {
  return `
query ListAlerts($first: Int!, $after: String, $viewType: ViewType) {
    alerts(first: $first, after: $after, viewType: $viewType) {
        edges {
            node {
${nodeFields}
                ${dataSourcesField}
            }
            cursor
        }
        pageInfo {
            hasNextPage
            hasPreviousPage
            startCursor
            endCursor
        }
        totalCount
    }
}
`;
}

function buildSearchAlertsQuery(nodeFields: string, dataSourcesField: string): string {
  return `
query SearchAlerts($filters: [FilterInput!], $first: Int!, $after: String, $viewType: ViewType) {
    alerts(filters: $filters, first: $first, after: $after, viewType: $viewType) {
        edges {
            node {
${nodeFields}
                ${dataSourcesField}
            }
            cursor
        }
        pageInfo {
            hasNextPage
            hasPreviousPage
            startCursor
            endCursor
        }
        totalCount
    }
}
`;
}

// ---------------------------------------------------------------------------
// Field catalog (client.py:30-64). dataSources is NOT in defaults — it is
// injected via the ${data_sources_field} placeholder to avoid a GraphQL
// duplicate-field conflict. It IS an allowed custom field.
// ---------------------------------------------------------------------------

const DEFAULT_ALERT_FIELDS: string[] = [
  "id",
  "externalId",
  "severity",
  "status",
  "name",
  "description",
  "detectedAt",
  "firstSeenAt",
  "lastSeenAt",
  "analystVerdict",
  "classification",
  "confidenceLevel",
  "detectionSource { product vendor }",
  "asset { id name type }",
  "assignee { userId email fullName }",
  "noteExists",
  "result",
  "storylineId",
  "ticketId",
];

// dataSources is the only additional_allowed_field beyond the defaults
// (client.py:52-58). The set of selectable simple names = defaults + dataSources.
const ALLOWED_ALERT_FIELDS = new Set<string>([
  ...DEFAULT_ALERT_FIELDS,
  "dataSources",
]);

// Indent a field block to line up under `node {` in the query (cosmetic, matches
// the Python build_node_fields indentation depth).
function indentFields(fields: string[]): string {
  return fields.map((f) => `                ${f}`).join("\n");
}

// Mirror of _build_alert_field_params (client.py:329-360): returns the node-field
// block and whether dataSources should be injected via the separate placeholder.
// When fields is undefined -> all default fields + dataSources. When fields is
// provided -> dataSources is only included if explicitly listed, and is stripped
// from the node block.
function buildAlertFieldParams(fields: string[] | undefined): {
  nodeFields: string;
  dataSourcesField: string;
} {
  if (fields === undefined) {
    return { nodeFields: indentFields(DEFAULT_ALERT_FIELDS), dataSourcesField: "dataSources" };
  }
  const includeDataSources = fields.includes("dataSources");
  const selected = fields.filter((f) => f !== "dataSources");
  // Validate every requested name against the allowed catalog. The Python
  // build_node_fields enforces allowed-field membership; reproduce that.
  for (const f of selected) {
    if (!ALLOWED_ALERT_FIELDS.has(f)) {
      throw new ValidationError(`Unknown alert field requested: ${f}.`, {
        hint: `Allowed fields: ${[...ALLOWED_ALERT_FIELDS].join(", ")}.`,
      });
    }
  }
  return {
    nodeFields: indentFields(selected),
    dataSourcesField: includeDataSources ? "dataSources" : "",
  };
}

// ---------------------------------------------------------------------------
// Parameter parsing / validation helpers (alerts.py + fields_validation.py)
// ---------------------------------------------------------------------------

function parseViewType(value: unknown): ViewType {
  const s = optionalString(value, "view_type") ?? "ALL";
  if (!(VIEW_TYPES as readonly string[]).includes(s)) {
    throw new ValidationError(`view_type must be one of: ${VIEW_TYPES.join(", ")}.`);
  }
  return s as ViewType;
}

// Port of parse_fields_parameter (fields_validation.py:11-55). The `fields` arg
// is a JSON string; validate JSON-length, array-ness, count, element type, and
// per-field length.
function parseFieldsParameter(value: unknown): string[] | undefined {
  const raw = optionalString(value, "fields");
  if (raw === undefined) return undefined;
  if (raw.length > MAX_FIELDS_JSON_LENGTH) {
    throw new ValidationError(
      `Fields payload is too large: ${raw.length} characters. Maximum allowed: ${MAX_FIELDS_JSON_LENGTH}.`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ValidationError("Invalid JSON in fields parameter.", {
      hint: 'Example: ["id", "severity", "dataSources"]',
    });
  }
  if (!Array.isArray(parsed)) {
    throw new ValidationError("Fields must be an array of field names.");
  }
  if (parsed.length > MAX_FIELDS_COUNT) {
    throw new ValidationError(`Too many fields: ${parsed.length}. Maximum allowed: ${MAX_FIELDS_COUNT}.`);
  }
  parsed.forEach((item, index) => {
    if (typeof item !== "string") {
      throw new ValidationError(`All field names must be strings; element at index ${index} is not.`);
    }
    if (item.length > MAX_FIELD_LENGTH) {
      throw new ValidationError(
        `Field at index ${index} is too long: ${item.length} characters. Maximum allowed: ${MAX_FIELD_LENGTH}.`,
      );
    }
  });
  return parsed as string[];
}

// ---------------------------------------------------------------------------
// Filter parsing -> GraphQL FilterInput wire objects.
//
// The wire shape is exactly what FilterInput.model_dump(by_alias=True) produces
// (models.py:294-432). Each builder emits the camelCase aliases:
//   string_equals    -> { fieldId, isNegated, stringEqual: { value } }
//   string_in        -> { fieldId, isNegated, stringIn: { values } }
//   boolean_equals   -> { fieldId, isNegated, booleanEqual: { value } }
//   boolean_in       -> { fieldId, isNegated, booleanIn: { values } }
//   long_equals      -> { fieldId, isNegated, longEqual: { value } }
//   long_in          -> { fieldId, isNegated, longIn: { values } }
//   int_equals       -> { fieldId, isNegated, intEqual: { value } }
//   int_in           -> { fieldId, isNegated, intIn: { values } }
//   int_range        -> { fieldId, isNegated, intRange: { start, startInclusive, end, endInclusive } }
//   datetime_range   -> { fieldId, isNegated, dateTimeRange: { start, startInclusive, end, endInclusive } }
//   fulltext         -> { fieldId, isNegated, match: { values } }
// ---------------------------------------------------------------------------

// Reusable builders matching FilterInput.create_string_equal / create_datetime_range.

export function filterStringEqual(field: string, value: string): Record<string, unknown> {
  return { fieldId: field, isNegated: false, stringEqual: { value } };
}

export function filterDatetimeRange(
  field: string,
  startMs: number,
  endMs: number,
): Record<string, unknown> {
  return {
    fieldId: field,
    isNegated: false,
    dateTimeRange: {
      start: startMs,
      startInclusive: true,
      end: endMs,
      endInclusive: true,
    },
  };
}

// Reject nanosecond-scale timestamps (>13 digits), mirroring
// _validate_timestamp_milliseconds (alerts.py:667-696).
function validateTimestampMs(value: unknown, name: string): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n) || !Number.isInteger(n)) {
    throw new ValidationError(`datetime_range filter '${name}' must be an integer (milliseconds).`);
  }
  if (Math.abs(n) > 9_999_999_999_999) {
    throw new ValidationError(
      `datetime_range filter '${name}' value appears to be in nanoseconds (${n}). Use milliseconds; ` +
        "convert ISO-8601 with iso_to_unix_timestamp.",
    );
  }
  return n;
}

function checkValuesLen(values: unknown, filterType: string): unknown[] {
  if (!Array.isArray(values)) {
    throw new ValidationError(`${filterType} filter requires a 'values' array.`);
  }
  if (values.length > MAX_FILTER_VALUES_COUNT) {
    throw new ValidationError(
      `${filterType} filter has too many values: ${values.length}. Maximum allowed: ${MAX_FILTER_VALUES_COUNT}.`,
    );
  }
  return values;
}

// Convert one parsed filter object {fieldId, filterType, ...} into the GraphQL
// FilterInput wire shape. Port of _parse_new_filter_format + the three
// _create_*_filters helpers (alerts.py:613-753).
function buildFilterInput(filter: Record<string, unknown>): Record<string, unknown> {
  const fieldId = filter.fieldId;
  const filterType = filter.filterType;
  if (typeof fieldId !== "string" || typeof filterType !== "string") {
    throw new ValidationError(
      "Each filter must have 'fieldId' and 'filterType' keys. " +
        "Example: {\"fieldId\": \"severity\", \"filterType\": \"string_equals\", \"value\": \"HIGH\"}",
    );
  }
  const isNegated = filter.isNegated === true;
  const base = { fieldId, isNegated };

  switch (filterType) {
    case "string_equals": {
      if (!("value" in filter)) throw new ValidationError("string_equals filter requires 'value' key.");
      return { ...base, stringEqual: { value: filter.value } };
    }
    case "string_in": {
      const values = checkValuesLen(filter.values, "string_in");
      return { ...base, stringIn: { values } };
    }
    case "boolean_equals": {
      if (!("value" in filter)) throw new ValidationError("boolean_equals filter requires 'value' key.");
      return { ...base, booleanEqual: { value: filter.value } };
    }
    case "boolean_in": {
      const values = checkValuesLen(filter.values, "boolean_in");
      return { ...base, booleanIn: { values } };
    }
    case "long_equals": {
      if (!("value" in filter)) throw new ValidationError("long_equals filter requires 'value' key.");
      return { ...base, longEqual: { value: filter.value } };
    }
    case "long_in": {
      const values = checkValuesLen(filter.values, "long_in");
      return { ...base, longIn: { values } };
    }
    case "int_equals": {
      if (!("value" in filter)) throw new ValidationError("int_equals filter requires 'value' key.");
      return { ...base, intEqual: { value: filter.value } };
    }
    case "int_in": {
      const values = checkValuesLen(filter.values, "int_in");
      return { ...base, intIn: { values } };
    }
    case "int_range": {
      return {
        ...base,
        intRange: {
          start: "start" in filter ? filter.start : null,
          startInclusive: filter.startInclusive ?? true,
          end: "end" in filter ? filter.end : null,
          endInclusive: filter.endInclusive ?? true,
        },
      };
    }
    case "datetime_range": {
      const start = "start" in filter ? validateTimestampMs(filter.start, "start") : null;
      const end = "end" in filter ? validateTimestampMs(filter.end, "end") : null;
      return {
        ...base,
        dateTimeRange: {
          start,
          startInclusive: filter.startInclusive ?? true,
          end,
          endInclusive: filter.endInclusive ?? true,
        },
      };
    }
    case "fulltext": {
      const values = checkValuesLen(filter.values, "fulltext");
      return { ...base, match: { values } };
    }
    default:
      throw new ValidationError(`Unsupported filter type: ${filterType}.`);
  }
}

// Parse the `filters` JSON-string arg into a list of GraphQL FilterInput wire
// objects. Enforces the 50-filter cap (alerts.py:347-361). Returns undefined
// when no filters were supplied.
function parseFiltersArg(value: unknown): Record<string, unknown>[] | undefined {
  const parsed = parseJsonFilters(value, "filters");
  if (parsed === undefined) return undefined;
  if (!Array.isArray(parsed)) {
    throw new ValidationError("Filters must be an array of filter objects.");
  }
  if (parsed.length === 0) return undefined;
  if (parsed.length > MAX_FILTERS_COUNT) {
    throw new ValidationError(
      `Too many filters: ${parsed.length}. Maximum allowed: ${MAX_FILTERS_COUNT}.`,
    );
  }
  return parsed.map((f) => {
    if (typeof f !== "object" || f === null || Array.isArray(f)) {
      throw new ValidationError("Each filter must be an object.");
    }
    return buildFilterInput(f as Record<string, unknown>);
  });
}

// ---------------------------------------------------------------------------
// Connection extraction helpers
// ---------------------------------------------------------------------------

interface ConnectionPieces {
  edges: Array<{ node: Record<string, unknown> }>;
  totalCount: number;
  hasNextPage: boolean;
  endCursor: string | null;
}

function extractConnection(conn: unknown): ConnectionPieces {
  const c = (conn ?? {}) as Record<string, unknown>;
  const rawEdges = Array.isArray(c.edges) ? c.edges : [];
  const edges = rawEdges
    .map((e) => {
      const node = (e as Record<string, unknown> | null)?.node;
      return node && typeof node === "object"
        ? { node: node as Record<string, unknown> }
        : null;
    })
    .filter((e): e is { node: Record<string, unknown> } => e !== null);
  const pageInfo = (c.pageInfo ?? {}) as Record<string, unknown>;
  const totalCount = typeof c.totalCount === "number" ? c.totalCount : edges.length;
  const hasNextPage = pageInfo.hasNextPage === true;
  const endCursor = typeof pageInfo.endCursor === "string" ? pageInfo.endCursor : null;
  return { edges, totalCount, hasNextPage, endCursor };
}

// Shape a connection result into the tool's data block + next_cursor, clamping
// the edge array to the byte budget. The full connection metadata (totalCount,
// pagination flags, truncation count) lives alongside the clamped edges.
function shapeConnection(pieces: ConnectionPieces): ToolResult {
  const { kept, truncated } = clampToFitBytes(pieces.edges, (edges) => ({
    edges,
    totalCount: pieces.totalCount,
    pageInfo: { hasNextPage: pieces.hasNextPage, endCursor: pieces.endCursor },
  }));
  return {
    data: {
      edges: kept,
      totalCount: pieces.totalCount,
      pageInfo: {
        hasNextPage: pieces.hasNextPage,
        endCursor: pieces.endCursor,
      },
      truncated_count: truncated,
    },
    next_cursor: pieces.hasNextPage ? pieces.endCursor : null,
  };
}

// ---------------------------------------------------------------------------
// REQUIRED EXPORTS — reusable helpers for the investigation orchestrator.
// Pure functions: call GraphQL, return parsed JS objects (NOT envelopes).
// ---------------------------------------------------------------------------

// Returns the alert node object, or null if not found. id must be the internal UUID.
export async function fetchAlertById(
  ctx: ToolContext,
  id: string,
): Promise<Record<string, unknown> | null> {
  const data = await ctx.client.graphql(ctx.endpoints.alertsGraphql, GET_ALERT_QUERY, {
    alertId: id,
  });
  const alert = data.alert;
  if (!alert || typeof alert !== "object") return null;
  return alert as Record<string, unknown>;
}

// Generic search returning the raw connection pieces.
export async function searchAlertsRaw(
  ctx: ToolContext,
  filters: Record<string, unknown>[],
  first: number,
  viewType: string = "ALL",
): Promise<{ edges: Array<{ node: Record<string, unknown> }>; totalCount: number; hasNextPage: boolean }> {
  const { nodeFields, dataSourcesField } = buildAlertFieldParams(undefined);
  const query = buildSearchAlertsQuery(nodeFields, dataSourcesField);
  const data = await ctx.client.graphql(ctx.endpoints.alertsGraphql, query, {
    filters: filters.length > 0 ? filters : null,
    first,
    after: null,
    viewType,
  });
  const pieces = extractConnection(data.alerts);
  return { edges: pieces.edges, totalCount: pieces.totalCount, hasNextPage: pieces.hasNextPage };
}

export async function fetchAlertHistoryRaw(
  ctx: ToolContext,
  alertId: string,
  first: number,
): Promise<{ edges: Array<{ node: Record<string, unknown> }>; totalCount: number; hasNextPage: boolean }> {
  const data = await ctx.client.graphql(ctx.endpoints.alertsGraphql, GET_ALERT_HISTORY_QUERY, {
    alertId,
    first,
    after: null,
  });
  const pieces = extractConnection(data.alertHistory);
  return { edges: pieces.edges, totalCount: pieces.totalCount, hasNextPage: pieces.hasNextPage };
}

// alertNotes returns { data: [...] } (client.py:153-170, models.py:541-544),
// NOT a relay connection. Return the raw note objects.
export async function fetchAlertNotesRaw(
  ctx: ToolContext,
  alertId: string,
): Promise<Record<string, unknown>[]> {
  const data = await ctx.client.graphql(ctx.endpoints.alertsGraphql, GET_ALERT_NOTES_QUERY, {
    alertId,
  });
  const notes = (data.alertNotes ?? {}) as Record<string, unknown>;
  const list = Array.isArray(notes.data) ? notes.data : [];
  return list.filter(
    (n): n is Record<string, unknown> => typeof n === "object" && n !== null && !Array.isArray(n),
  );
}

// ---------------------------------------------------------------------------
// MCP tool functions
// ---------------------------------------------------------------------------

// get_alert (alerts.py:405-428). NotFoundError on a null node.
const get_alert: ToolFn = (ctx, args) =>
  runTool("POST /alerts (GetAlert)", async (): Promise<ToolResult> => {
    const alertId = requireString(args.alert_id, "alert_id").trim();
    const alert = await fetchAlertById(ctx, alertId);
    if (alert === null) {
      throw new NotFoundError(`Alert ${alertId} not found.`, {
        hint: "Verify the alert id (internal UUID) is correct and the token can access it.",
      });
    }
    return { data: alert };
  });

// list_alerts (alerts.py:431-482). Paginated; basic viewType filter only.
const list_alerts: ToolFn = (ctx, args) =>
  runTool("POST /alerts (ListAlerts)", async (): Promise<ToolResult> => {
    const first = boundedInt(args.first, "first", 10, 1, 100);
    const after = optionalString(args.after, "after");
    const viewType = parseViewType(args.view_type);
    const fields = parseFieldsParameter(args.fields);

    const { nodeFields, dataSourcesField } = buildAlertFieldParams(fields);
    const query = buildListAlertsQuery(nodeFields, dataSourcesField);

    const data = await ctx.client.graphql(ctx.endpoints.alertsGraphql, query, {
      first,
      after: after ?? null,
      viewType,
    });
    return shapeConnection(extractConnection(data.alerts));
  });

// search_alerts (alerts.py:543-610). Advanced filters + pagination.
const search_alerts: ToolFn = (ctx, args) =>
  runTool("POST /alerts (SearchAlerts)", async (): Promise<ToolResult> => {
    const first = boundedInt(args.first, "first", 10, 1, 100);
    const after = optionalString(args.after, "after");
    const viewType = parseViewType(args.view_type);
    const fields = parseFieldsParameter(args.fields);
    const filters = parseFiltersArg(args.filters);

    const { nodeFields, dataSourcesField } = buildAlertFieldParams(fields);
    const query = buildSearchAlertsQuery(nodeFields, dataSourcesField);

    const data = await ctx.client.graphql(ctx.endpoints.alertsGraphql, query, {
      filters: filters && filters.length > 0 ? filters : null,
      first,
      after: after ?? null,
      viewType,
    });
    return shapeConnection(extractConnection(data.alerts));
  });

// get_alert_notes (alerts.py:756-779). Returns the raw note list under `data`.
const get_alert_notes: ToolFn = (ctx, args) =>
  runTool("POST /alerts (GetAlertNotes)", async (): Promise<ToolResult> => {
    const alertId = requireString(args.alert_id, "alert_id").trim();
    const notes = await fetchAlertNotesRaw(ctx, alertId);
    const { kept, truncated } = clampToFitBytes(notes, (n) => ({ data: n }));
    return { data: { data: kept, truncated_count: truncated } };
  });

// get_alert_history (alerts.py:782-821). Paginated audit timeline.
const get_alert_history: ToolFn = (ctx, args) =>
  runTool("POST /alerts (GetAlertHistory)", async (): Promise<ToolResult> => {
    const alertId = requireString(args.alert_id, "alert_id").trim();
    const first = boundedInt(args.first, "first", 10, 1, 100);
    const after = optionalString(args.after, "after");

    const data = await ctx.client.graphql(ctx.endpoints.alertsGraphql, GET_ALERT_HISTORY_QUERY, {
      alertId,
      first,
      after: after ?? null,
    });
    return shapeConnection(extractConnection(data.alertHistory));
  });

// ---------------------------------------------------------------------------
// Registry exports
// ---------------------------------------------------------------------------

export const ALERTS_TOOLS: Record<string, ToolFn> = {
  get_alert,
  list_alerts,
  search_alerts,
  get_alert_notes,
  get_alert_history,
};

export const ALERTS_DESCRIPTORS: ToolDescriptor[] = [
  {
    name: "get_alert",
    description:
      "Get detailed information about a specific alert by ID. Returns comprehensive alert data: severity, status, timing, classification, associated asset, assignee, detection source, data sources, storyline/ticket ids, and analyst verdict. Use for incident investigation, triage, and enrichment.",
    inputSchema: {
      type: "object",
      required: ["alert_id"],
      properties: {
        alert_id: { type: "string", description: "The unique identifier (internal UUID) of the alert." },
      },
      additionalProperties: false,
    },
  },
  {
    name: "list_alerts",
    description:
      "List alerts with relay-style pagination and a basic assignment (view_type) filter. For advanced filtering by severity, status, or time range, use search_alerts. Returns edges, pageInfo, and totalCount. When paging to a position, pass fields='[\"id\"]' on intermediate pages to conserve context. dataSources is included by default but only when explicitly listed if `fields` is provided.",
    inputSchema: {
      type: "object",
      properties: {
        first: { type: "integer", minimum: 1, maximum: 100, default: 10, description: "Number of alerts (1-100)." },
        after: { type: "string", description: "Opaque pagination cursor (pageInfo.endCursor / next_cursor from a prior call)." },
        view_type: {
          type: "string",
          enum: ["ALL", "ASSIGNED_TO_ME", "UNASSIGNED", "MY_TEAM"],
          default: "ALL",
          description: "Assignment filter.",
        },
        fields: {
          type: "string",
          description: 'Optional JSON array of field names to return, e.g. \'["id","severity","dataSources"]\'. Omit for all default fields.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "search_alerts",
    description:
      "Search alerts using advanced filters. `filters` is a JSON array of filter objects, each with fieldId, filterType, and value/values (optional isNegated). Filter types: string_equals/string_in, boolean_equals/boolean_in, long_equals/long_in, int_equals/int_in/int_range, datetime_range (UNIX ms, UTC — use iso_to_unix_timestamp), fulltext. Max 50 filters, max 100 values each. For a 'how many' query set first=1 and read totalCount.",
    inputSchema: {
      type: "object",
      properties: {
        filters: {
          type: "string",
          description:
            'JSON array of filter objects. Example: \'[{"fieldId":"severity","filterType":"string_in","values":["CRITICAL","HIGH"]},{"fieldId":"createdAt","filterType":"datetime_range","start":1730289600000}]\'',
        },
        first: { type: "integer", minimum: 1, maximum: 100, default: 10, description: "Number of alerts (1-100)." },
        after: { type: "string", description: "Opaque pagination cursor." },
        view_type: {
          type: "string",
          enum: ["ALL", "ASSIGNED_TO_ME", "UNASSIGNED", "MY_TEAM"],
          default: "ALL",
          description: "Assignment filter.",
        },
        fields: {
          type: "string",
          description: 'Optional JSON array of field names to return. See list_alerts for available fields and dataSources behavior.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "get_alert_notes",
    description:
      "Get all analyst notes and comments attached to an alert. Each note includes id, text, createdAt, author, and alertId. Returns an empty list if none exist — check the alert's noteExists field first to avoid unnecessary calls.",
    inputSchema: {
      type: "object",
      required: ["alert_id"],
      properties: {
        alert_id: { type: "string", description: "The unique identifier of the alert." },
      },
      additionalProperties: false,
    },
  },
  {
    name: "get_alert_history",
    description:
      "Get the chronological audit history/timeline for an alert (status changes, assignments, severity changes, notes, escalations, integration actions). Relay-style paginated; returns edges with createdAt/eventText/eventType/reportUrl/historyItemCreator, plus pageInfo and totalCount.",
    inputSchema: {
      type: "object",
      required: ["alert_id"],
      properties: {
        alert_id: { type: "string", description: "The unique identifier of the alert." },
        first: { type: "integer", minimum: 1, maximum: 100, default: 10, description: "Number of history events (1-100)." },
        after: { type: "string", description: "Opaque pagination cursor." },
      },
      additionalProperties: false,
    },
  },
];
