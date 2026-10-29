// XSPM Misconfigurations domain. Ports purple-mcp's tools/misconfigurations.py +
// libs/misconfigurations/{client,templates,models}.py onto the Worker GraphQL
// surface. Five tools:
//   get_misconfiguration       -> single fetch (NotFoundError when absent)
//   list_misconfigurations     -> Relay pagination + view_type filter
//   search_misconfigurations   -> filters (JSON string) + view_type + pagination
//   get_misconfiguration_notes -> notes for one id
//   get_misconfiguration_history -> paginated audit history
//
// Every tool calls ctx.client.graphql(ctx.endpoints.misconfigurationsGraphql, ...)
// which returns the unwrapped `data` object and throws on GraphQL/HTTP errors.

import { ToolDescriptor } from "../mcp.js";
import {
  ToolFn,
  ToolResult,
  boundedInt,
  optionalString,
  parseJsonFilters,
  requireString,
  runTool,
} from "../tool-base.js";
import { NotFoundError, ValidationError } from "../errors.js";
import { clampToFitBytes } from "../envelope.js";

// ---------------------------------------------------------------------------
// DoS-protection caps (port of tools/misconfigurations.py + fields_validation.py)
// ---------------------------------------------------------------------------
const MAX_FILTERS_COUNT = 50;
const MAX_FILTER_VALUES_COUNT = 100;
const MAX_FIELDS_COUNT = 50;
const MAX_FIELD_LENGTH = 1024;
const MAX_FIELDS_JSON_LENGTH = 8192;

// View types (port of models.ViewType). ALL is the Python default.
const VIEW_TYPES = [
  "ALL",
  "CLOUD",
  "KUBERNETES",
  "IDENTITY",
  "INFRASTRUCTURE_AS_CODE",
  "ADMISSION_CONTROLLER",
  "OFFENSIVE_SECURITY",
  "SECRET_SCANNING",
] as const;

// ---------------------------------------------------------------------------
// Default node-field selection (port of templates.MISCONFIGURATION_FIELD_CATALOG
// default_fields, normalized to single-line GraphQL fragments).
// ---------------------------------------------------------------------------
const DEFAULT_NODE_FIELDS: string[] = [
  "id",
  "externalId",
  "name",
  "severity",
  "status",
  "detectedAt",
  "eventTime",
  "lastSeenAt",
  "environment",
  "product",
  "vendor",
  "asset { id externalId name type category subcategory privileged cloudInfo { accountId accountName providerName region } kubernetesInfo { cluster namespace } }",
  "scope { account { id name } site { id name } group { id name } }",
  "analystVerdict",
  "assignee { id email fullName }",
  "cnapp { policy { id version group } verifiedExploitable }",
  "complianceStandards",
  "dataClassificationCategories",
  "dataClassificationDataTypes",
  "enforcementAction",
  "evidence { fileName fileType iacFramework ipAddress port subdomain }",
  "exclusionPolicyId",
  "exploitId",
  "exposureReason",
  "findingType",
  "mitigable",
  "misconfigurationType",
  "mitreAttacks { techniqueId techniqueName techniqueUrl tacticName tacticUid }",
  "organization",
  "remediation { mitigable mitigationSteps }",
  "resourceUid",
  "admissionRequest { category resourceName resourceNamespace resourceType userName userUid userGroup }",
];

// 16-space indent to match the Python query builder layout (cosmetic).
const INDENT = " ".repeat(16);

// Resolve the node-field selection for a list/search query. When the caller
// supplies a `fields` JSON string we validate it (length/count/string-ness),
// always include `id`, and use it verbatim; otherwise the default catalog.
function resolveNodeFields(fieldsArg: unknown): string {
  const fields = parseFieldsParameter(fieldsArg);
  const list = fields ?? DEFAULT_NODE_FIELDS;
  const finalList =
    fields === null || fields === undefined
      ? list
      : list.includes("id")
        ? list
        : ["id", ...list];
  return finalList.map((f) => `${INDENT}${f}`).join("\n");
}

// Port of fields_validation.parse_fields_parameter. Returns undefined when the
// caller omitted `fields`, else a validated string[].
function parseFieldsParameter(value: unknown): string[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") {
    throw new ValidationError("fields must be a JSON string array if provided.");
  }
  if (value.length > MAX_FIELDS_JSON_LENGTH) {
    throw new ValidationError(
      `Fields payload is too large: ${value.length} characters. Maximum allowed: ${MAX_FIELDS_JSON_LENGTH}`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new ValidationError("Invalid JSON in fields parameter.", {
      hint: 'Example: ["id","severity","status","name"]',
    });
  }
  if (!Array.isArray(parsed)) {
    throw new ValidationError("Fields must be an array of field names.");
  }
  if (parsed.length > MAX_FIELDS_COUNT) {
    throw new ValidationError(`Too many fields: ${parsed.length}. Maximum allowed: ${MAX_FIELDS_COUNT}`);
  }
  parsed.forEach((item, index) => {
    if (typeof item !== "string") {
      throw new ValidationError(`All field names must be strings; element at index ${index} is not.`);
    }
    if (item.length > MAX_FIELD_LENGTH) {
      throw new ValidationError(
        `Field at index ${index} is too long: ${item.length} characters. Maximum allowed: ${MAX_FIELD_LENGTH}`,
      );
    }
  });
  return parsed as string[];
}

function parseViewType(value: unknown): string {
  const vt = optionalString(value, "view_type") ?? "ALL";
  if (!(VIEW_TYPES as readonly string[]).includes(vt)) {
    throw new ValidationError(`view_type must be one of: ${VIEW_TYPES.join(", ")}.`);
  }
  return vt;
}

// Validate a pagination cursor (port of _validate_cursor): non-empty string.
function parseCursor(value: unknown): string | undefined {
  const c = optionalString(value, "after");
  if (c === undefined) return undefined;
  if (c.trim() === "") throw new ValidationError("after cursor cannot be empty.");
  return c;
}

// ---------------------------------------------------------------------------
// Filter conversion (port of _convert_filters_to_input / _convert_filter_to_input).
// Translates the simplified {fieldId, filterType, value/values/start/end} form
// into the GraphQL FilterInput wire shape, e.g.
//   {fieldId, filterType: "string_equals", value: "X"}
//     -> {fieldId, isNegated, stringEqual: {value: "X"}}
// The wire object keys mirror models.FilterInput aliases exactly.
// ---------------------------------------------------------------------------

interface RawFilter {
  fieldId: string;
  filterType: string;
  isNegated?: boolean;
  value?: unknown;
  values?: unknown;
  start?: unknown;
  end?: unknown;
  startInclusive?: boolean;
  endInclusive?: boolean;
}

const NANOSECOND_GUARD = 9_999_999_999_999; // > 13 digits => likely nanoseconds

function toMillis(raw: unknown, bound: "start" | "end"): number {
  const n = typeof raw === "number" ? raw : Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n)) {
    throw new ValidationError(
      `datetime_range filter '${bound}' must be an integer (milliseconds), got: ${String(raw)}`,
    );
  }
  if (Math.abs(n) > NANOSECOND_GUARD) {
    throw new ValidationError(
      `datetime_range filter '${bound}' value appears to be in nanoseconds (${n}). ` +
        "Use milliseconds instead (see iso_to_unix_timestamp).",
    );
  }
  return n;
}

function buildRange(f: RawFilter, filterType: string): Record<string, unknown> {
  const range: Record<string, unknown> = {};
  if (f.start !== undefined) range.start = f.start;
  if (f.end !== undefined) range.end = f.end;
  if (f.startInclusive !== undefined) range.startInclusive = f.startInclusive;
  if (f.endInclusive !== undefined) range.endInclusive = f.endInclusive;
  if (range.start === undefined && range.end === undefined) {
    throw new ValidationError(`Filter type '${filterType}' requires at least 'start' or 'end' key.`);
  }
  return range;
}

function requireValue(f: RawFilter, filterType: string): unknown {
  if (f.value === undefined) {
    throw new ValidationError(`Filter type '${filterType}' requires 'value' key.`);
  }
  return f.value;
}

function requireValues(f: RawFilter, filterType: string): unknown {
  if (f.values === undefined) {
    throw new ValidationError(`Filter type '${filterType}' requires 'values' key.`);
  }
  return f.values;
}

function convertFilter(raw: unknown): Record<string, unknown> {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ValidationError("Each filter must be an object.");
  }
  const f = raw as RawFilter;
  if (typeof f.fieldId !== "string" || typeof f.filterType !== "string") {
    throw new ValidationError(
      "Each filter must have 'fieldId' and 'filterType' keys. " +
        "Example: {\"fieldId\":\"severity\",\"filterType\":\"string_equals\",\"value\":\"CRITICAL\"}",
    );
  }

  const filterType = f.filterType;
  const out: Record<string, unknown> = {
    fieldId: f.fieldId,
    isNegated: f.isNegated ?? false,
  };

  switch (filterType) {
    case "string_equals":
      out.stringEqual = { value: requireValue(f, filterType) };
      break;
    case "string_in":
      out.stringIn = { values: requireValues(f, filterType) };
      break;
    case "int_equals":
      out.intEqual = { value: requireValue(f, filterType) };
      break;
    case "int_in":
      out.intIn = { values: requireValues(f, filterType) };
      break;
    case "int_range":
      out.intRange = buildRange(f, filterType);
      break;
    case "long_equals":
      out.longEqual = { value: requireValue(f, filterType) };
      break;
    case "long_in":
      out.longIn = { values: requireValues(f, filterType) };
      break;
    case "long_range":
      out.longRange = buildRange(f, filterType);
      break;
    case "boolean_equals":
      out.booleanEqual = { value: requireValue(f, filterType) };
      break;
    case "boolean_in":
      out.booleanIn = { values: requireValues(f, filterType) };
      break;
    case "datetime_range": {
      const range: Record<string, unknown> = {};
      if (f.start !== undefined) range.start = toMillis(f.start, "start");
      if (f.end !== undefined) range.end = toMillis(f.end, "end");
      if (f.startInclusive !== undefined) range.startInclusive = f.startInclusive;
      if (f.endInclusive !== undefined) range.endInclusive = f.endInclusive;
      if (range.start === undefined && range.end === undefined) {
        throw new ValidationError(`Filter type '${filterType}' requires at least 'start' or 'end' key.`);
      }
      out.dateTimeRange = range;
      break;
    }
    case "fulltext":
      out.match = { values: requireValues(f, filterType) };
      break;
    case "fulltext_in":
      out.matchIn = { values: requireValues(f, filterType) };
      break;
    default:
      throw new ValidationError(
        `Unsupported filterType: '${filterType}'. Supported: string_equals, string_in, ` +
          "int_equals, int_in, int_range, long_equals, long_in, long_range, boolean_equals, " +
          "boolean_in, datetime_range, fulltext, fulltext_in.",
      );
  }
  return out;
}

// Parse the `filters` JSON string into FilterInput wire objects, enforcing the
// Python DoS caps (≤50 filters, ≤100 values each). Returns undefined when absent.
function parseFilters(filtersArg: unknown): Record<string, unknown>[] | undefined {
  const parsed = parseJsonFilters(filtersArg, "filters");
  if (parsed === undefined) return undefined;
  if (!Array.isArray(parsed)) {
    throw new ValidationError("filters must be an array of filter objects.");
  }
  if (parsed.length === 0) return undefined;
  if (parsed.length > MAX_FILTERS_COUNT) {
    throw new ValidationError(`Too many filters: ${parsed.length}. Maximum allowed: ${MAX_FILTERS_COUNT}`);
  }
  parsed.forEach((entry, i) => {
    if (entry && typeof entry === "object" && Array.isArray((entry as RawFilter).values)) {
      const vals = (entry as RawFilter).values as unknown[];
      if (vals.length > MAX_FILTER_VALUES_COUNT) {
        throw new ValidationError(
          `Filter ${i} has too many values: ${vals.length}. Maximum allowed: ${MAX_FILTER_VALUES_COUNT}`,
        );
      }
    }
  });
  return parsed.map(convertFilter);
}

// ---------------------------------------------------------------------------
// GraphQL query builders (port of templates.py).
// ---------------------------------------------------------------------------

const GET_MISCONFIGURATION_QUERY = `
query GetMisconfiguration($id: ID!) {
    misconfiguration(id: $id) {
        id
        externalId
        name
        description
        severity
        status
        detectedAt
        eventTime
        lastSeenAt
        environment
        product
        vendor
        asset {
            id externalId name type category subcategory domain agentUuid privileged criticality osType
            cloudInfo { accountId accountName providerName region resourceId resourceLink }
            kubernetesInfo { cluster clusterId namespace }
        }
        scope { account { id name } site { id name } group { id name } }
        scopeLevel
        analystVerdict
        assignee { id email fullName deleted }
        cnapp {
            policy { id name description version group }
            verifiedExploitable autoRemediation haConnectionId haTemplateId
        }
        compliance {
            standards requirements
            complianceStandards { title url }
            complianceReferences { title url }
            status
        }
        remediation { mitigable mitigationSteps references { title url } }
        failedRules { name description severity impact compliance recommendedAction enforcementSettings }
        findingData { properties { name value } exposureReason context }
        mitreAttacks { techniqueId techniqueName techniqueUrl tacticName tacticUid }
        dataClassificationCategories
        dataClassificationDataTypes
        enforcementAction
        evidence {
            fileName fileType fileUrl iacFramework ipAddress port subdomain commitedBy
            secret { type hash valid }
        }
        exclusionPolicyId
        exploitId
        exposureId
        misconfigurationType
        organization
        resourceUid
        selfLink
        admissionRequest { category resourceName resourceNamespace resourceType userName userUid userGroup }
    }
}
`;

function listQuery(nodeFields: string): string {
  return `
query ListMisconfigurations($first: Int!, $after: String, $viewType: ViewType) {
    misconfigurations(first: $first, after: $after, viewType: $viewType) {
        edges {
            node {
${nodeFields}
            }
            cursor
        }
        pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
        totalCount
    }
}
`;
}

function searchQuery(nodeFields: string): string {
  return `
query SearchMisconfigurations($filters: [FilterInput!], $first: Int!, $after: String, $viewType: ViewType) {
    misconfigurations(filters: $filters, first: $first, after: $after, viewType: $viewType) {
        edges {
            node {
${nodeFields}
            }
            cursor
        }
        pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
        totalCount
    }
}
`;
}

const GET_MISCONFIGURATION_NOTES_QUERY = `
query GetMisconfigurationNotes($misconfigurationId: ID!, $first: Int, $after: String) {
    misconfigurationNotes(misconfigurationId: $misconfigurationId, first: $first, after: $after) {
        edges {
            node {
                id
                misconfigurationId
                text
                author { id email fullName deleted }
                createdAt
                updatedAt
            }
            cursor
        }
        pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
        totalCount
    }
}
`;

const GET_MISCONFIGURATION_HISTORY_QUERY = `
query GetMisconfigurationHistory($misconfigurationId: ID!, $first: Int!, $after: String) {
    misconfigurationHistory(misconfigurationId: $misconfigurationId, first: $first, after: $after) {
        edges {
            node { eventType eventText createdAt }
            cursor
        }
        pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
        totalCount
    }
}
`;

// ---------------------------------------------------------------------------
// Connection shaping. Relay edges/pageInfo/totalCount with byte clamping over
// the edges array. next_cursor = endCursor when hasNextPage, else null.
// ---------------------------------------------------------------------------

interface PageInfo {
  hasNextPage?: boolean;
  hasPreviousPage?: boolean;
  startCursor?: string | null;
  endCursor?: string | null;
}

function shapeConnection(conn: unknown): ToolResult {
  const c = (conn ?? {}) as {
    edges?: unknown[];
    pageInfo?: PageInfo;
    totalCount?: number | null;
  };
  const edges = Array.isArray(c.edges) ? c.edges : [];
  const pageInfo: PageInfo = c.pageInfo ?? {
    hasNextPage: false,
    hasPreviousPage: false,
    startCursor: null,
    endCursor: null,
  };
  const totalCount = c.totalCount ?? null;

  const { kept, truncated } = clampToFitBytes(edges, (slice) => ({
    edges: slice,
    pageInfo,
    totalCount,
  }));

  const hasNext = pageInfo.hasNextPage === true;
  const nextCursor = hasNext ? (pageInfo.endCursor ?? null) : null;

  return {
    data: {
      edges: kept,
      pageInfo,
      totalCount,
      ...(truncated > 0 ? { truncated_edges: truncated } : {}),
    },
    next_cursor: nextCursor,
  };
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

const get_misconfiguration: ToolFn = (ctx, args) =>
  runTool("POST <misconfigurations graphql> (misconfiguration)", async (): Promise<ToolResult> => {
    const id = requireString(args.misconfiguration_id, "misconfiguration_id");
    const data = await ctx.client.graphql(ctx.endpoints.misconfigurationsGraphql, GET_MISCONFIGURATION_QUERY, {
      id,
    });
    const misc = data.misconfiguration;
    if (misc === null || misc === undefined) {
      throw new NotFoundError(`Misconfiguration ${id} was not found.`);
    }
    return { data: misc };
  });

const list_misconfigurations: ToolFn = (ctx, args) =>
  runTool("POST <misconfigurations graphql> (list)", async (): Promise<ToolResult> => {
    const first = boundedInt(args.first, "first", 10, 1, 100);
    const after = parseCursor(args.after);
    const viewType = parseViewType(args.view_type);
    const nodeFields = resolveNodeFields(args.fields);

    const variables: Record<string, unknown> = { first, viewType };
    if (after !== undefined) variables.after = after;

    const data = await ctx.client.graphql(
      ctx.endpoints.misconfigurationsGraphql,
      listQuery(nodeFields),
      variables,
    );
    return shapeConnection(data.misconfigurations);
  });

const search_misconfigurations: ToolFn = (ctx, args) =>
  runTool("POST <misconfigurations graphql> (search)", async (): Promise<ToolResult> => {
    const first = boundedInt(args.first, "first", 10, 1, 100);
    const after = parseCursor(args.after);
    const viewType = parseViewType(args.view_type);
    const filters = parseFilters(args.filters);
    const nodeFields = resolveNodeFields(args.fields);

    const variables: Record<string, unknown> = { first, viewType };
    if (after !== undefined) variables.after = after;
    if (filters !== undefined) variables.filters = filters;

    const data = await ctx.client.graphql(
      ctx.endpoints.misconfigurationsGraphql,
      searchQuery(nodeFields),
      variables,
    );
    return shapeConnection(data.misconfigurations);
  });

const get_misconfiguration_notes: ToolFn = (ctx, args) =>
  runTool("POST <misconfigurations graphql> (notes)", async (): Promise<ToolResult> => {
    const id = requireString(args.misconfiguration_id, "misconfiguration_id");
    const data = await ctx.client.graphql(
      ctx.endpoints.misconfigurationsGraphql,
      GET_MISCONFIGURATION_NOTES_QUERY,
      { misconfigurationId: id },
    );
    return shapeConnection(data.misconfigurationNotes);
  });

const get_misconfiguration_history: ToolFn = (ctx, args) =>
  runTool("POST <misconfigurations graphql> (history)", async (): Promise<ToolResult> => {
    const id = requireString(args.misconfiguration_id, "misconfiguration_id");
    const first = boundedInt(args.first, "first", 10, 1, 100);
    const after = parseCursor(args.after);

    const variables: Record<string, unknown> = { misconfigurationId: id, first };
    if (after !== undefined) variables.after = after;

    const data = await ctx.client.graphql(
      ctx.endpoints.misconfigurationsGraphql,
      GET_MISCONFIGURATION_HISTORY_QUERY,
      variables,
    );
    return shapeConnection(data.misconfigurationHistory);
  });

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

export const MISCONFIGURATIONS_TOOLS: Record<string, ToolFn> = {
  get_misconfiguration,
  list_misconfigurations,
  search_misconfigurations,
  get_misconfiguration_notes,
  get_misconfiguration_history,
};

const FIELDS_DESC =
  'Optional JSON string array of field names to return, e.g. \'["id","severity","status","name","detectedAt"]\'. ' +
  "Use minimal fields like '[\"id\"]' when paging. Nested objects (asset, scope, assignee, evidence, cnapp, " +
  "admissionRequest, remediation, mitreAttacks) and lists (complianceStandards, dataClassificationCategories, " +
  "dataClassificationDataTypes) are also valid. Omit for the full default selection.";

export const MISCONFIGURATIONS_DESCRIPTORS: ToolDescriptor[] = [
  {
    name: "get_misconfiguration",
    description:
      "Get detailed information about a specific XSPM misconfiguration by ID, including metadata, severity, " +
      "affected asset, compliance, remediation steps, failed rules, evidence, and MITRE ATT&CK mappings.",
    inputSchema: {
      type: "object",
      required: ["misconfiguration_id"],
      properties: {
        misconfiguration_id: { type: "string", description: "Unique identifier of the misconfiguration." },
      },
      additionalProperties: false,
    },
  },
  {
    name: "list_misconfigurations",
    description:
      "List misconfigurations with Relay pagination and an environment view filter. For advanced filtering by " +
      "severity, status, compliance, etc., use search_misconfigurations. Returns edges/pageInfo/totalCount; " +
      "next_cursor is pageInfo.endCursor when hasNextPage.",
    inputSchema: {
      type: "object",
      properties: {
        first: { type: "integer", minimum: 1, maximum: 100, default: 10, description: "Number to retrieve (1-100)." },
        after: { type: "string", description: "Pagination cursor (pageInfo.endCursor from a prior page)." },
        view_type: { type: "string", enum: [...VIEW_TYPES], default: "ALL", description: "Environment filter." },
        fields: { type: "string", description: FIELDS_DESC },
      },
      additionalProperties: false,
    },
  },
  {
    name: "search_misconfigurations",
    description:
      "Search misconfigurations using advanced filters. `filters` is a JSON string array of objects with fieldId, " +
      "filterType (string_equals, string_in, boolean_equals, boolean_in, datetime_range, fulltext, fulltext_in, " +
      "int_*/long_*), and value/values/start/end. Use flattened camelCase fieldIds (e.g. assetName, secretHash), not " +
      "nested paths. datetime_range uses UTC millisecond timestamps (see iso_to_unix_timestamp). Max 50 filters, 100 " +
      "values each. Returns edges/pageInfo/totalCount.",
    inputSchema: {
      type: "object",
      properties: {
        filters: {
          type: "string",
          description:
            'JSON array of filter objects, e.g. \'[{"fieldId":"severity","filterType":"string_equals","value":"CRITICAL"},' +
            '{"fieldId":"status","filterType":"string_in","values":["NEW","IN_PROGRESS"]}]\'.',
        },
        first: { type: "integer", minimum: 1, maximum: 100, default: 10, description: "Number to retrieve (1-100)." },
        after: { type: "string", description: "Pagination cursor." },
        view_type: { type: "string", enum: [...VIEW_TYPES], default: "ALL", description: "Environment filter." },
        fields: { type: "string", description: FIELDS_DESC },
      },
      additionalProperties: false,
    },
  },
  {
    name: "get_misconfiguration_notes",
    description:
      "Get all analyst notes and comments attached to a misconfiguration. Returns edges/pageInfo/totalCount; each " +
      "note has id, text, author, createdAt, updatedAt.",
    inputSchema: {
      type: "object",
      required: ["misconfiguration_id"],
      properties: {
        misconfiguration_id: { type: "string", description: "Unique identifier of the misconfiguration." },
      },
      additionalProperties: false,
    },
  },
  {
    name: "get_misconfiguration_history",
    description:
      "Get the paginated audit history/timeline for a misconfiguration (status changes, verdicts, assignments, " +
      "notes, workflow actions). Returns edges/pageInfo/totalCount; next_cursor resumes pagination.",
    inputSchema: {
      type: "object",
      required: ["misconfiguration_id"],
      properties: {
        misconfiguration_id: { type: "string", description: "Unique identifier of the misconfiguration." },
        first: { type: "integer", minimum: 1, maximum: 100, default: 10, description: "Number of events (1-100)." },
        after: { type: "string", description: "Pagination cursor." },
      },
      additionalProperties: false,
    },
  },
];
