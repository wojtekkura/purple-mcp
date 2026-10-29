// Unified Asset Inventory tools: `get_inventory_item`, `list_inventory_items`,
// `search_inventory_items`. Port of tools/inventory.py + libs/inventory/client.py.
//
// This domain is REST (not GraphQL). All calls go through
// ctx.client.requestJson({ method, path, params?, jsonBody? }). The inventory
// REST base path is ctx.endpoints.inventoryRest (e.g. /web/api/v2.1/xdr/assets).
//
// Upstream contract (libs/inventory/client.py _handle_response):
//   - list  -> GET  {base}            ?limit&skip      (surface => {base}/surface/<lower>)
//   - search-> POST {base}            body {"filter": {...filters, limit, skip}}
//   - response body: { data: InventoryItem[], pagination: { totalCount, limit, skip } }
// get_inventory_item is NOT a GET-by-id in Python: it issues a search with the
// {"id__in": [item_id]} filter, limit=1, and returns data[0] (or null).

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
import { NotFoundError, ValidationError } from "../errors.js";
import { clampToFitBytes } from "../envelope.js";

// DoS protection cap — matches MAX_LIMIT in tools/inventory.py.
const MAX_LIMIT = 1000;
const DEFAULT_LIMIT = 50;
const DEFAULT_SKIP = 0;

// Surface enum — libs/inventory/models.py Surface.
const SURFACES = ["ENDPOINT", "CLOUD", "IDENTITY", "NETWORK_DISCOVERY"] as const;
type Surface = (typeof SURFACES)[number];

type JsonObject = Record<string, unknown>;

// ---------------------------------------------------------------------------
// Upstream response shaping
// ---------------------------------------------------------------------------

interface PaginationInfo {
  total_count: number | null;
  limit: number | null;
  skip: number | null;
}

interface InventoryPage {
  items: JsonObject[];
  pagination: PaginationInfo | null;
}

// Extract { data, pagination } exactly as _handle_response does in the Python
// client (data defaults to [], pagination optional with camelCase totalCount).
function parsePage(body: JsonObject): InventoryPage {
  const rawData = body["data"];
  const items: JsonObject[] = Array.isArray(rawData)
    ? rawData.filter((it): it is JsonObject => typeof it === "object" && it !== null && !Array.isArray(it))
    : [];

  const rawPagination = body["pagination"];
  let pagination: PaginationInfo | null = null;
  if (rawPagination && typeof rawPagination === "object" && !Array.isArray(rawPagination)) {
    const p = rawPagination as JsonObject;
    pagination = {
      total_count: asIntOrNull(p["totalCount"]),
      limit: asIntOrNull(p["limit"]),
      skip: asIntOrNull(p["skip"]),
    };
  }
  return { items, pagination };
}

function asIntOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

// GET {base}{?/surface/<lower>}?limit&skip  — list_inventory in client.py.
async function listInventory(
  ctx: ToolContext,
  limit: number,
  skip: number,
  surface: Surface | undefined,
): Promise<InventoryPage> {
  // Surface-specific endpoint appends /surface/<lowercase> (client._get_surface_endpoint).
  const path = surface ? `${ctx.endpoints.inventoryRest}/surface/${surface.toLowerCase()}` : ctx.endpoints.inventoryRest;
  const body = await ctx.client.requestJson({
    method: "GET",
    path,
    params: { limit, skip },
  });
  return parsePage(body);
}

// POST {base} body {"filter": {...filters, limit, skip}} — search_inventory in client.py.
async function searchInventory(
  ctx: ToolContext,
  filters: JsonObject,
  limit: number,
  skip: number,
): Promise<InventoryPage> {
  const body = await ctx.client.requestJson({
    method: "POST",
    path: ctx.endpoints.inventoryRest,
    jsonBody: {
      filter: {
        ...filters,
        limit,
        skip,
      },
    },
  });
  return parsePage(body);
}

// Build the pagination block surfaced to the agent. Offset-based, opaque-free:
// when more results remain we hand back a `next_skip` hint (skip + limit).
function paginationBlock(
  pagination: PaginationInfo | null,
  limit: number,
  skip: number,
  returnedCount: number,
): JsonObject {
  const totalCount = pagination?.total_count ?? null;
  // More results exist if the API reports a total beyond what we've consumed,
  // or (absent a total) if the page came back full.
  const hasMore =
    totalCount !== null ? skip + returnedCount < totalCount : returnedCount >= limit;
  return {
    total_count: totalCount,
    limit: pagination?.limit ?? limit,
    skip: pagination?.skip ?? skip,
    returned_count: returnedCount,
    has_more: hasMore,
    next_skip: hasMore ? skip + limit : null,
  };
}

// Shape an inventory page into the tool `data` block with byte-clamped items.
function shapePage(page: InventoryPage, limit: number, skip: number): ToolResult {
  const { kept, truncated } = clampToFitBytes(page.items, (items) => items);
  return {
    data: {
      items: kept,
      count: kept.length,
      truncated,
      pagination: paginationBlock(page.pagination, limit, skip, page.items.length),
    },
  };
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

// get_inventory_item(item_id): search with {"id__in": [item_id]}, limit=1, and
// return data[0]. Not found -> NotFoundError (Python returns None -> we 404 the
// tool; the orchestrator export below returns null instead).
const get_inventory_item: ToolFn = (ctx, args) =>
  runTool("POST inventoryRest (id__in)", async (): Promise<ToolResult> => {
    const itemId = requireString(args.item_id, "item_id").trim();
    if (itemId === "") {
      throw new ValidationError("item_id cannot be empty.");
    }
    const page = await searchInventory(ctx, { id__in: [itemId] }, 1, 0);
    const item = page.items[0];
    if (!item) {
      throw new NotFoundError(`Inventory item '${itemId}' not found.`, {
        hint: "Verify the item id with list_inventory_items or search_inventory_items.",
      });
    }
    return { data: item };
  });

// list_inventory_items(limit=50, skip=0, surface?): offset pagination via GET
// query params; optional surface filter routed to the /surface/<lower> endpoint.
const list_inventory_items: ToolFn = (ctx, args) =>
  runTool("GET inventoryRest", async (): Promise<ToolResult> => {
    const limit = boundedInt(args.limit, "limit", DEFAULT_LIMIT, 1, MAX_LIMIT);
    const skip = boundedInt(args.skip, "skip", DEFAULT_SKIP, 0, Number.MAX_SAFE_INTEGER);

    let surface: Surface | undefined;
    const rawSurface = optionalString(args.surface, "surface");
    if (rawSurface !== undefined && rawSurface !== "") {
      if (!SURFACES.includes(rawSurface as Surface)) {
        throw new ValidationError(`surface must be one of: ${SURFACES.join(", ")}.`);
      }
      surface = rawSurface as Surface;
    }

    const page = await listInventory(ctx, limit, skip, surface);
    return shapePage(page, limit, skip);
  });

// search_inventory_items(filters?, limit=50, skip=0): POST with a JSON filter
// dict (REST format, camelCase fields), AND-combined. No surface support.
const search_inventory_items: ToolFn = (ctx, args) =>
  runTool("POST inventoryRest", async (): Promise<ToolResult> => {
    const limit = boundedInt(args.limit, "limit", DEFAULT_LIMIT, 1, MAX_LIMIT);
    const skip = boundedInt(args.skip, "skip", DEFAULT_SKIP, 0, Number.MAX_SAFE_INTEGER);

    let filters: JsonObject = {};
    const parsed = parseJsonFilters(args.filters, "filters");
    if (parsed !== undefined) {
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new ValidationError("filters must be a JSON object (dictionary).");
      }
      filters = parsed as JsonObject;
    }

    const page = await searchInventory(ctx, filters, limit, skip);
    return shapePage(page, limit, skip);
  });

// ---------------------------------------------------------------------------
// Orchestrator export
// ---------------------------------------------------------------------------

// Returns the inventory item object, or null if not found. Mirrors the Python
// client.get_inventory_item (search by {"id__in": [id]}, limit=1 -> data[0] | None).
// Catches the not-found case and returns null rather than throwing.
export async function fetchInventoryItem(
  ctx: ToolContext,
  id: string,
): Promise<Record<string, unknown> | null> {
  const trimmed = id.trim();
  if (trimmed === "") return null;
  const page = await searchInventory(ctx, { id__in: [trimmed] }, 1, 0);
  return page.items[0] ?? null;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const INVENTORY_TOOLS: Record<string, ToolFn> = {
  get_inventory_item,
  list_inventory_items,
  search_inventory_items,
};

export const INVENTORY_DESCRIPTORS: ToolDescriptor[] = [
  {
    name: "get_inventory_item",
    description:
      "Get detailed information about a specific SentinelOne managed asset by ID (computers, servers, workstations, cloud resources, network/identity entities). Returns the full inventory item object (asset details, metadata, cloud info, agent details, tags, notes). Errors with not_found if the id does not exist.",
    inputSchema: {
      type: "object",
      properties: {
        item_id: { type: "string", description: "The unique identifier of the inventory item." },
      },
      required: ["item_id"],
      additionalProperties: false,
    },
  },
  {
    name: "list_inventory_items",
    description:
      "List SentinelOne managed assets with offset pagination and an optional surface filter. Returns items + pagination (total_count, has_more, next_skip). Use `surface` for surface-specific browsing.",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "integer", minimum: 1, maximum: MAX_LIMIT, default: DEFAULT_LIMIT, description: "Number of items to retrieve (1-1000)." },
        skip: { type: "integer", minimum: 0, default: DEFAULT_SKIP, description: "Number of items to skip for pagination." },
        surface: {
          type: "string",
          enum: [...SURFACES],
          description:
            "Optional surface filter: ENDPOINT (agents/workstations/servers), CLOUD (AWS/Azure/GCP), IDENTITY (AD/Entra ID), NETWORK_DISCOVERY (Ranger).",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "search_inventory_items",
    description:
      "Search SentinelOne managed assets using REST API filters (JSON string, camelCase fields, AND-combined). Supports exact-match lists ({\"resourceType\":[\"Windows Server\"]}), __contains, __between date ranges, id__in, and __nin negation. For surface-specific filtering use list_inventory_items instead. Returns items + pagination.",
    inputSchema: {
      type: "object",
      properties: {
        filters: {
          type: "string",
          description:
            'JSON string of a filter dictionary (default {}). Examples: {"resourceType":["Windows Server","Linux Server"]}, {"name__contains":["prod"]}, {"lastActiveDt__between":{"from":"2024-01-01","to":"2024-12-31"}}, {"id__in":["uuid1"]}, {"assetStatus__nin":["Decommissioned"]}.',
        },
        limit: { type: "integer", minimum: 1, maximum: MAX_LIMIT, default: DEFAULT_LIMIT, description: "Number of items to retrieve (1-1000)." },
        skip: { type: "integer", minimum: 0, default: DEFAULT_SKIP, description: "Number of items to skip for pagination." },
      },
      additionalProperties: false,
    },
  },
];
