// XSPM Vulnerabilities Management tools: get_vulnerability, list_vulnerabilities,
// search_vulnerabilities, get_vulnerability_notes, get_vulnerability_history.
//
// Port of purple-mcp's tools/vulnerabilities.py + libs/vulnerabilities/{client,
// templates,models}.py. Each tool POSTs a GraphQL query to
// ctx.endpoints.vulnerabilitiesGraphql via ctx.client.graphql(...) and relays the
// connection (edges[].node + pageInfo + totalCount) with byte-bounded clamping.
//
// Self-contained: does not import from alerts.ts (written concurrently).

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
// DoS protection limits (ported from tools/vulnerabilities.py +
// tools/fields_validation.py).
// ---------------------------------------------------------------------------
const MAX_FILTERS_COUNT = 50; // tools/vulnerabilities.py MAX_FILTERS_COUNT
const MAX_FILTER_VALUES_COUNT = 100; // tools/vulnerabilities.py MAX_FILTER_VALUES_COUNT
const MAX_FIELDS_COUNT = 50; // fields_validation.py MAX_FIELDS_COUNT
const MAX_FIELD_LENGTH = 1024; // fields_validation.py MAX_FIELD_LENGTH
const MAX_FIELDS_JSON_LENGTH = 8192; // fields_validation.py MAX_FIELDS_JSON_LENGTH

// `first` paging bound shared by list / search / history (Python: 1..100, default 10).
const FIRST_MIN = 1;
const FIRST_MAX = 100;
const FIRST_DEFAULT = 10;

// GraphQL field-selection indent used by build_node_fields (graphql_utils.INDENT).
const INDENT = " ".repeat(16);
const SIMPLE_FIELD_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

// ---------------------------------------------------------------------------
// Default node field selection (ported from templates.py
// VULNERABILITY_FIELD_CATALOG.default_fields, fragments normalized to one line).
// Used verbatim when the caller does not pass `fields`.
// ---------------------------------------------------------------------------
const DEFAULT_NODE_FIELDS: string[] = [
  "id",
  "name",
  "severity",
  "status",
  "detectedAt",
  "lastSeenAt",
  "product",
  "vendor",
  // _build_asset_fragment()
  "asset { id externalId name type category subcategory privileged " +
    "cloudInfo { accountId accountName providerName region } " +
    "kubernetesInfo { cluster namespace } }",
  // _build_scope_fragment()
  "scope { account { id name } site { id name } group { id name } }",
  // _build_cve_fragment()
  "cve { id nvdBaseScore riskScore publishedDate epssScore exploitMaturity exploitedInTheWild }",
  // _build_software_fragment()
  "software { name version fixVersion type vendor }",
  "analystVerdict",
  "assignee { id email fullName }",
  "exclusionPolicyId",
];

// Default node selection string, indented like the Python query templates.
const DEFAULT_NODE_FIELDS_STR = DEFAULT_NODE_FIELDS.map((f) => `${INDENT}${f}`).join("\n");

// ---------------------------------------------------------------------------
// GraphQL queries (ported from templates.py). The list/search node selection is
// templated so a `fields` override can be substituted; defaults to the catalog.
// ---------------------------------------------------------------------------
const GET_VULNERABILITY_QUERY = `
query GetVulnerability($id: ID!) {
    vulnerability(id: $id) {
        id
        externalId
        name
        severity
        status
        detectedAt
        lastSeenAt
        updatedAt
        product
        vendor
        asset {
            id
            externalId
            name
            type
            category
            subcategory
            domain
            agentUuid
            privileged
            criticality
            osType
            cloudInfo {
                accountId
                accountName
                providerName
                region
                resourceId
                resourceLink
            }
            kubernetesInfo {
                cluster
                clusterId
                namespace
            }
        }
        scope {
            account { id name }
            site { id name }
            group { id name }
        }
        scopeLevel
        cve {
            id
            description
            nvdBaseScore
            riskScore
            score
            publishedDate
            epssScore
            epssPercentile
            epssLastUpdatedDate
            exploitMaturity
            exploitedInTheWild
            kevAvailable
            remediationLevel
            reportConfidence
            s1BaseValues {
                attackVector
                attackComplexity
                privilegesRequired
                userInteractions
                scope
                confidentiality
                integrity
                availability
            }
            riskIndicators {
                severity
                values
            }
            mitreReferenceUrl
            nvdReferenceUrl
            timeline { date key }
        }
        software {
            name
            version
            fixVersion
            type
            vendor
        }
        findingData { context }
        paidScope
        remediationInsightsAvailable
        selfLink
        analystVerdict
        assignee { id email fullName deleted }
        exclusionPolicyId
    }
}
`;

// $node_fields is substituted with the (validated) node selection.
function listVulnerabilitiesQuery(nodeFields: string): string {
  return `
query ListVulnerabilities($first: Int!, $after: String) {
    vulnerabilities(first: $first, after: $after) {
        edges {
            node {
${nodeFields}
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

function searchVulnerabilitiesQuery(nodeFields: string): string {
  return `
query SearchVulnerabilities($filters: [FilterInput!], $first: Int!, $after: String) {
    vulnerabilities(filters: $filters, first: $first, after: $after) {
        edges {
            node {
${nodeFields}
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

const GET_VULNERABILITY_NOTES_QUERY = `
query GetVulnerabilityNotes($vulnerabilityId: ID!, $first: Int, $after: String) {
    vulnerabilityNotes(vulnerabilityId: $vulnerabilityId, first: $first, after: $after) {
        edges {
            node {
                id
                vulnerabilityId
                text
                author { id email fullName deleted }
                createdAt
                updatedAt
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

const GET_VULNERABILITY_HISTORY_QUERY = `
query GetVulnerabilityHistory($vulnerabilityId: ID!, $first: Int!, $after: String) {
    vulnerabilityHistory(vulnerabilityId: $vulnerabilityId, first: $first, after: $after) {
        edges {
            node {
                eventType
                eventText
                createdAt
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

// ---------------------------------------------------------------------------
// `fields` parsing / node-selection building.
// Ports fields_validation.parse_fields_parameter + a pragmatic subset of
// graphql_utils.build_node_fields (id auto-inject + injection guarding).
// ---------------------------------------------------------------------------

// Nested object names valid for a `fields` override, mapped to their default
// fragment (from DEFAULT_NODE_FIELDS). Mirrors catalog.get_nested_mappings().
const NESTED_MAPPINGS: Record<string, string> = (() => {
  const m: Record<string, string> = {};
  for (const f of DEFAULT_NODE_FIELDS) {
    const brace = f.indexOf("{");
    if (brace >= 0) m[f.slice(0, brace).trim()] = f;
  }
  return m;
})();

const ALLOWED_SIMPLE_FIELDS = new Set(
  DEFAULT_NODE_FIELDS.filter((f) => !f.includes("{")),
);

// Suspicious characters that could be used for GraphQL injection (graphql_utils).
const SUSPICIOUS = ["...", "@", "#", "(", ")", "[", "]", "$", "!"];

// Parse + validate the JSON `fields` string -> string[] | undefined (None).
// Mirrors fields_validation.parse_fields_parameter limits.
function parseFields(raw: unknown): string[] | undefined {
  const s = optionalString(raw, "fields");
  if (s === undefined) return undefined;
  if (s.length > MAX_FIELDS_JSON_LENGTH) {
    throw new ValidationError(
      `Fields payload is too large: ${s.length} characters. Maximum allowed: ${MAX_FIELDS_JSON_LENGTH}`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(s);
  } catch {
    throw new ValidationError("Invalid JSON in fields parameter.", {
      hint: 'Example: ["id", "severity", "status", "name"]',
    });
  }
  if (!Array.isArray(parsed)) {
    throw new ValidationError("Fields must be an array of field names.");
  }
  if (parsed.length > MAX_FIELDS_COUNT) {
    throw new ValidationError(
      `Too many fields: ${parsed.length}. Maximum allowed: ${MAX_FIELDS_COUNT}`,
    );
  }
  parsed.forEach((item, i) => {
    if (typeof item !== "string") {
      throw new ValidationError(`All field names must be strings; element at index ${i} is not.`);
    }
    if (item.length > MAX_FIELD_LENGTH) {
      throw new ValidationError(
        `Field at index ${i} is too long: ${item.length} characters. Maximum allowed: ${MAX_FIELD_LENGTH}`,
      );
    }
  });
  return parsed as string[];
}

// Validate one field against the allowlist + injection guard (graphql_utils
// _validate_field_name, simplified: simple names + known nested objects only).
function validateField(field: string): void {
  const f = field.trim();
  if (!f) throw new ValidationError("Empty field name is not allowed.");
  if (ALLOWED_SIMPLE_FIELDS.has(f)) return;
  if (f in NESTED_MAPPINGS) return;

  if (f.includes("{")) {
    const root = f.slice(0, f.indexOf("{")).trim();
    if (!(root in NESTED_MAPPINGS)) {
      throw new ValidationError(
        `Nested object '${root}' is not valid. Valid nested objects: ${Object.keys(NESTED_MAPPINGS).sort().join(", ")}`,
      );
    }
    // Require balanced braces for an explicit fragment.
    let depth = 0;
    for (const c of f) {
      if (c === "{") depth++;
      else if (c === "}") depth--;
      if (depth < 0) throw new ValidationError(`Nested field '${f}' has unbalanced braces.`);
    }
    if (depth !== 0) throw new ValidationError(`Nested field '${f}' has unbalanced braces.`);
    return;
  }

  for (const ch of SUSPICIOUS) {
    if (f.includes(ch)) {
      throw new ValidationError(
        `Field name '${f}' contains suspicious character '${ch}' that could be used for GraphQL injection.`,
      );
    }
  }
  if (SIMPLE_FIELD_RE.test(f)) {
    throw new ValidationError(`Field name '${f}' is not in the allowlist of valid fields.`);
  }
  throw new ValidationError(`Field name '${f}' has invalid format.`);
}

// Build the indented node-selection string. None -> default catalog selection;
// a list -> validated + id-ensured + nested-name auto-expansion (build_node_fields).
function buildNodeFields(fields: string[] | undefined): string {
  if (fields === undefined) return DEFAULT_NODE_FIELDS_STR;

  let fieldList = [...fields];
  if (fieldList.length === 0) fieldList = ["id"];
  if (!fieldList.includes("id")) fieldList = ["id", ...fieldList];

  const expanded: string[] = [];
  for (const field of fieldList) {
    validateField(field);
    if (field in NESTED_MAPPINGS) expanded.push(NESTED_MAPPINGS[field]!);
    else expanded.push(field);
  }
  return expanded.map((f) => `${INDENT}${f}`).join("\n");
}

// ---------------------------------------------------------------------------
// Filter conversion (ports _convert_filter_to_input + FilterInput wire shape).
// Input simplified filter -> nested GraphQL FilterInput object:
//   {"fieldId":"severity","filterType":"string_equals","value":"HIGH"}
//   -> {"fieldId":"severity","isNegated":false,"stringEqual":{"value":"HIGH"}}
// ---------------------------------------------------------------------------

interface RawFilter {
  fieldId?: unknown;
  filterType?: unknown;
  isNegated?: unknown;
  value?: unknown;
  values?: unknown;
  start?: unknown;
  end?: unknown;
  startInclusive?: unknown;
  endInclusive?: unknown;
}

const MAX_MS_TIMESTAMP = 9999999999999; // 13-digit guard (Python nanosecond check)

function requireValue(f: RawFilter, t: string): unknown {
  if (!("value" in f)) throw new ValidationError(`Filter type '${t}' requires 'value' key.`);
  return f.value;
}
function requireValues(f: RawFilter, t: string): unknown {
  if (!("values" in f)) throw new ValidationError(`Filter type '${t}' requires 'values' key.`);
  return f.values;
}

// Build a {start,end,startInclusive,endInclusive} range object (RangeFilter*Input
// wire shape uses startInclusive/endInclusive aliases; defaults omitted via
// exclude_none parity — only include keys explicitly provided / converted).
function buildRange(f: RawFilter, t: string, ts: boolean): Record<string, unknown> {
  const range: Record<string, unknown> = {};
  const conv = (raw: unknown, key: "start" | "end"): number => {
    const n = typeof raw === "number" ? raw : Number(raw);
    if (!Number.isInteger(n)) {
      throw new ValidationError(`${t} filter '${key}' must be an integer (milliseconds).`);
    }
    if (ts && Math.abs(n) > MAX_MS_TIMESTAMP) {
      throw new ValidationError(
        `${t} filter '${key}' value appears to be in nanoseconds (${n}). Use milliseconds instead.`,
      );
    }
    return n;
  };
  if ("start" in f) range.start = conv(f.start, "start");
  if ("end" in f) range.end = conv(f.end, "end");
  if ("startInclusive" in f) range.startInclusive = f.startInclusive;
  if ("endInclusive" in f) range.endInclusive = f.endInclusive;
  if (!("start" in range) && !("end" in range)) {
    throw new ValidationError(`Filter type '${t}' requires at least 'start' or 'end' key.`);
  }
  return range;
}

function convertFilter(raw: RawFilter): Record<string, unknown> {
  if (raw.fieldId === undefined || raw.filterType === undefined) {
    throw new ValidationError(
      "Each filter must have 'fieldId' and 'filterType' keys. " +
        "Example: {\"fieldId\":\"severity\",\"filterType\":\"string_equals\",\"value\":\"CRITICAL\"}",
    );
  }
  const t = String(raw.filterType);
  const out: Record<string, unknown> = {
    fieldId: raw.fieldId,
    isNegated: raw.isNegated ?? false,
  };

  switch (t) {
    case "string_equals":
      out.stringEqual = { value: requireValue(raw, t) };
      break;
    case "string_in":
      out.stringIn = { values: requireValues(raw, t) };
      break;
    case "int_equals":
      out.intEqual = { value: requireValue(raw, t) };
      break;
    case "int_in":
      out.intIn = { values: requireValues(raw, t) };
      break;
    case "int_range":
      out.intRange = buildRange(raw, t, false);
      break;
    case "long_equals":
      out.longEqual = { value: requireValue(raw, t) };
      break;
    case "long_in":
      out.longIn = { values: requireValues(raw, t) };
      break;
    case "long_range":
      out.longRange = buildRange(raw, t, false);
      break;
    case "boolean_equals":
      out.booleanEqual = { value: requireValue(raw, t) };
      break;
    case "boolean_in":
      out.booleanIn = { values: requireValues(raw, t) };
      break;
    case "datetime_range":
      out.dateTimeRange = buildRange(raw, t, true);
      break;
    case "fulltext":
      out.match = { values: requireValues(raw, t) };
      break;
    case "fulltext_in":
      out.matchIn = { values: requireValues(raw, t) };
      break;
    default:
      throw new ValidationError(
        `Unsupported filterType: '${t}'. Supported types: string_equals, string_in, int_equals, ` +
          "int_in, int_range, long_equals, long_in, long_range, boolean_equals, boolean_in, " +
          "datetime_range, fulltext, fulltext_in",
      );
  }
  return out;
}

// Parse + validate the `filters` JSON string into FilterInput wire objects.
function buildFilters(raw: unknown): Record<string, unknown>[] | undefined {
  const parsed = parseJsonFilters(raw, "filters");
  if (parsed === undefined) return undefined;
  if (!Array.isArray(parsed)) {
    throw new ValidationError("Filters must be an array of filter objects.");
  }
  if (parsed.length === 0) return undefined; // Python treats empty as no filters.
  if (parsed.length > MAX_FILTERS_COUNT) {
    throw new ValidationError(
      `Too many filters: ${parsed.length}. Maximum allowed: ${MAX_FILTERS_COUNT}`,
    );
  }
  return parsed.map((item, i) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new ValidationError(`Filter ${i} must be an object.`);
    }
    const f = item as RawFilter;
    if (Array.isArray(f.values) && f.values.length > MAX_FILTER_VALUES_COUNT) {
      throw new ValidationError(
        `Filter ${i} has too many values: ${f.values.length}. Maximum allowed: ${MAX_FILTER_VALUES_COUNT}`,
      );
    }
    try {
      return convertFilter(f);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new ValidationError(`Invalid filter format: ${msg}`);
    }
  });
}

// ---------------------------------------------------------------------------
// Connection relay helpers.
// ---------------------------------------------------------------------------

interface ConnectionShape {
  edges?: Array<{ node?: unknown; cursor?: unknown }>;
  pageInfo?: {
    hasNextPage?: unknown;
    hasPreviousPage?: unknown;
    startCursor?: unknown;
    endCursor?: unknown;
  };
  totalCount?: unknown;
}

// next_cursor = endCursor when hasNextPage else null (upstream-opaque passthrough).
function nextCursorOf(conn: ConnectionShape): string | null {
  const pi = conn.pageInfo ?? {};
  if (pi.hasNextPage === true && typeof pi.endCursor === "string") return pi.endCursor;
  return null;
}

// Relay a connection's nodes, byte-clamping the array so the envelope fits.
function relayConnection(conn: ConnectionShape): ToolResult {
  const edges = Array.isArray(conn.edges) ? conn.edges : [];
  const nodes = edges.map((e) => e?.node);
  const pageInfo = conn.pageInfo ?? {
    hasNextPage: false,
    hasPreviousPage: false,
    startCursor: null,
    endCursor: null,
  };
  const totalCount = conn.totalCount ?? null;

  const { kept, truncated } = clampToFitBytes(nodes, (k) => ({
    items: k,
    pageInfo,
    totalCount,
  }));

  return {
    data: {
      items: kept,
      pageInfo,
      totalCount,
      truncated,
    },
    next_cursor: nextCursorOf(conn),
  };
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

// get_vulnerability — single lookup; not-found -> NotFoundError.
const get_vulnerability: ToolFn = (ctx, args) =>
  runTool("POST <vulnerabilities graphql> (GetVulnerability)", async (): Promise<ToolResult> => {
    const vulnerabilityId = requireString(args.vulnerability_id, "vulnerability_id");
    const data = await ctx.client.graphql(ctx.endpoints.vulnerabilitiesGraphql, GET_VULNERABILITY_QUERY, {
      id: vulnerabilityId,
    });
    const vuln = data.vulnerability;
    if (vuln === null || vuln === undefined) {
      throw new NotFoundError(`Vulnerability ${vulnerabilityId} not found.`);
    }
    return { data: vuln };
  });

// list_vulnerabilities — paginated, no filters.
const list_vulnerabilities: ToolFn = (ctx, args) =>
  runTool("POST <vulnerabilities graphql> (ListVulnerabilities)", async (): Promise<ToolResult> => {
    const first = boundedInt(args.first, "first", FIRST_DEFAULT, FIRST_MIN, FIRST_MAX);
    const after = optionalString(args.after, "after");
    const fields = parseFields(args.fields);

    const query = listVulnerabilitiesQuery(buildNodeFields(fields));
    const variables: Record<string, unknown> = { first };
    if (after) variables.after = after;

    const data = await ctx.client.graphql(ctx.endpoints.vulnerabilitiesGraphql, query, variables);
    return relayConnection((data.vulnerabilities ?? {}) as ConnectionShape);
  });

// search_vulnerabilities — paginated, advanced filters (JSON string).
const search_vulnerabilities: ToolFn = (ctx, args) =>
  runTool("POST <vulnerabilities graphql> (SearchVulnerabilities)", async (): Promise<ToolResult> => {
    const first = boundedInt(args.first, "first", FIRST_DEFAULT, FIRST_MIN, FIRST_MAX);
    const after = optionalString(args.after, "after");
    const fields = parseFields(args.fields);
    const filters = buildFilters(args.filters);

    const query = searchVulnerabilitiesQuery(buildNodeFields(fields));
    const variables: Record<string, unknown> = { first };
    if (filters) variables.filters = filters;
    if (after) variables.after = after;

    const data = await ctx.client.graphql(ctx.endpoints.vulnerabilitiesGraphql, query, variables);
    return relayConnection((data.vulnerabilities ?? {}) as ConnectionShape);
  });

// get_vulnerability_notes — all notes for a vulnerability (single-page relay).
const get_vulnerability_notes: ToolFn = (ctx, args) =>
  runTool("POST <vulnerabilities graphql> (GetVulnerabilityNotes)", async (): Promise<ToolResult> => {
    const vulnerabilityId = requireString(args.vulnerability_id, "vulnerability_id");
    const data = await ctx.client.graphql(
      ctx.endpoints.vulnerabilitiesGraphql,
      GET_VULNERABILITY_NOTES_QUERY,
      { vulnerabilityId },
    );
    return relayConnection((data.vulnerabilityNotes ?? {}) as ConnectionShape);
  });

// get_vulnerability_history — paginated audit timeline.
const get_vulnerability_history: ToolFn = (ctx, args) =>
  runTool("POST <vulnerabilities graphql> (GetVulnerabilityHistory)", async (): Promise<ToolResult> => {
    const vulnerabilityId = requireString(args.vulnerability_id, "vulnerability_id");
    const first = boundedInt(args.first, "first", FIRST_DEFAULT, FIRST_MIN, FIRST_MAX);
    const after = optionalString(args.after, "after");

    const variables: Record<string, unknown> = { vulnerabilityId, first };
    if (after) variables.after = after;

    const data = await ctx.client.graphql(
      ctx.endpoints.vulnerabilitiesGraphql,
      GET_VULNERABILITY_HISTORY_QUERY,
      variables,
    );
    return relayConnection((data.vulnerabilityHistory ?? {}) as ConnectionShape);
  });

export const VULNERABILITIES_TOOLS: Record<string, ToolFn> = {
  get_vulnerability,
  list_vulnerabilities,
  search_vulnerabilities,
  get_vulnerability_notes,
  get_vulnerability_history,
};

// ---------------------------------------------------------------------------
// Descriptors (concise ports of the Python docstrings).
// ---------------------------------------------------------------------------

const FIELDS_DESC =
  "Optional JSON array string of field names to return; omit for the full default selection. " +
  'Use minimal fields (e.g. \'["id"]\') when paging. Simple fields: id, name, severity, status, ' +
  "detectedAt, lastSeenAt, product, vendor, analystVerdict, exclusionPolicyId. " +
  "Nested objects (auto-expanded): cve, software, asset, scope, assignee.";

export const VULNERABILITIES_DESCRIPTORS: ToolDescriptor[] = [
  {
    name: "get_vulnerability",
    description:
      "Get detailed information about a specific vulnerability by ID. Returns comprehensive data " +
      "including CVE details, affected asset, risk/EPSS scores, exploit maturity, KEV availability, " +
      "software, scope, analyst verdict, and remediation info.",
    inputSchema: {
      type: "object",
      required: ["vulnerability_id"],
      properties: {
        vulnerability_id: { type: "string", description: "The unique identifier of the vulnerability." },
      },
      additionalProperties: false,
    },
  },
  {
    name: "list_vulnerabilities",
    description:
      "List vulnerabilities with pagination. For advanced filtering by severity, CVE, asset type, etc., " +
      "use search_vulnerabilities instead. Returns items + pageInfo + totalCount; pass next_cursor as `after` " +
      "for the next page.",
    inputSchema: {
      type: "object",
      properties: {
        first: { type: "integer", minimum: FIRST_MIN, maximum: FIRST_MAX, default: FIRST_DEFAULT, description: "Number to retrieve (1-100)." },
        after: { type: "string", description: "Pagination cursor (endCursor from a previous response)." },
        fields: { type: "string", description: FIELDS_DESC },
      },
      additionalProperties: false,
    },
  },
  {
    name: "search_vulnerabilities",
    description:
      "Search vulnerabilities using advanced filters. `filters` is a JSON array string of objects, each with " +
      "fieldId (flattened camelCase, e.g. cveId, assetName), filterType (string_equals, string_in, " +
      "boolean_equals, boolean_in, datetime_range, fulltext, fulltext_in, int_*/long_*), and the matching " +
      "value/values/start/end keys; optional isNegated. The vulnerabilities API does NOT support INT filters " +
      "for most fields — prefer STRING/BOOLEAN. datetime_range uses UNIX milliseconds (UTC); convert with " +
      "iso_to_unix_timestamp. Max 50 filters, 100 values per filter.",
    inputSchema: {
      type: "object",
      properties: {
        filters: {
          type: "string",
          description:
            'JSON array of filter objects, e.g. \'[{"fieldId":"severity","filterType":"string_equals","value":"CRITICAL"},{"fieldId":"cveExploitedInTheWild","filterType":"boolean_equals","value":true}]\'.',
        },
        first: { type: "integer", minimum: FIRST_MIN, maximum: FIRST_MAX, default: FIRST_DEFAULT, description: "Number to retrieve (1-100)." },
        after: { type: "string", description: "Pagination cursor (endCursor from a previous response)." },
        fields: { type: "string", description: FIELDS_DESC },
      },
      additionalProperties: false,
    },
  },
  {
    name: "get_vulnerability_notes",
    description:
      "Get all analyst notes and comments associated with a vulnerability. Each note includes id, text, " +
      "author {id, email, fullName}, createdAt, and updatedAt. Typically ordered newest first.",
    inputSchema: {
      type: "object",
      required: ["vulnerability_id"],
      properties: {
        vulnerability_id: { type: "string", description: "The unique identifier of the vulnerability." },
      },
      additionalProperties: false,
    },
  },
  {
    name: "get_vulnerability_history",
    description:
      "Get the audit history/timeline for a vulnerability. Returns chronological events (eventType, eventText, " +
      "createdAt) such as CREATION, STATUS, ANALYST_VERDICT, USER_ASSIGNMENT, NOTES, WORKFLOW_ACTION. Paginated.",
    inputSchema: {
      type: "object",
      required: ["vulnerability_id"],
      properties: {
        vulnerability_id: { type: "string", description: "The unique identifier of the vulnerability." },
        first: { type: "integer", minimum: FIRST_MIN, maximum: FIRST_MAX, default: FIRST_DEFAULT, description: "Number of history events to retrieve (1-100)." },
        after: { type: "string", description: "Pagination cursor (endCursor from a previous response)." },
      },
      additionalProperties: false,
    },
  },
];
