"""MCP tool for fetching EDR storyline events.

Split out from `initiate_investigation` because storylines on busy
endpoints can return hundreds of thousands of rows; bundling them into
the main triage envelope would push every payload past what most
sub-agents can ingest.

Typical workflow:

    bundle = await initiate_investigation(alert_id)
    storyline_id = bundle["summary"]["storyline_id"]
    if storyline_id:
        events = await get_storyline_events(storyline_id)

The library logic lives in `InvestigationCollector.fetch_storyline_events`
so this tool stays a thin MCP adapter that wires settings → config and
serializes the result.
"""

import logging
from textwrap import dedent
from typing import Final

from purple_mcp.config import get_settings
from purple_mcp.libs.investigation import (
    DEFAULT_STORYLINE_EVENT_LIMIT,
    DEFAULT_TIME_WINDOW_HOURS,
    InvestigationCollector,
    InvestigationConfig,
)
from purple_mcp.libs.sdl import SDL_API_PATH

logger = logging.getLogger(__name__)


GET_STORYLINE_EVENTS_DESCRIPTION: Final[str] = dedent(
    """
    Fetch SDL EDR events for a SentinelOne storyline.

    Runs a SentinelOne Singularity Data Lake PowerQuery filtered by
    `src.process.storyline.id` / `tgt.process.storyline.id` (the canonical
    EDR correlation fields) and returns a curated set of columns suitable
    for reconstructing a process tree:

        event.time, event.type, event.category,
        endpoint.name, endpoint.os,
        src.process.{name, cmdline, pid, user, storyline.id},
        tgt.process.{name, cmdline, pid, storyline.id},
        tgt.file.{path, sha256},
        dns.request, url.address,
        dst.ip.address, dst.port.number

    Designed to pair with `initiate_investigation`: that tool's response
    contains `summary.storyline_id` — pass it here when a sub-agent has
    decided it actually needs the EDR events.

    Args:
        storyline_id: The storyline identifier (e.g. `9A1F9530EF5DF7B6`
            or a UUID-style id). Get this from
            `initiate_investigation -> summary.storyline_id`.
        time_window_hours: Lookback window for the SDL query, in hours.
            Default 72.
        limit: Max rows to return. Default 500. Storylines on busy
            endpoints can have 100k+ events behind them — `match_count` in
            the response shows the true total even when `events` is
            limited.

    Returns:
        JSON document with this shape:

        {
          "status": "ok|empty|skipped|failed",
          "storyline_id": "<echoed back>",
          "query": "<the PowerQuery actually executed>",
          "columns": ["event.time", "event.type", ...],
          "match_count": 24,            // true total in window
          "returned_count": 24,         // capped at `limit`
          "truncated": false,           // hit the limit?
          "partial": false,             // SDL flagged partial results?
          "warnings": [],
          "events": [{"fields": {col: value, ...}}, ...],
          "error": null
        }

        Sub-agents should branch on `status` before consuming `events`.
        `events[i].fields` is a flat column→value dict so different
        consumers can pick the columns they care about.

    Common Use Cases:
        - Reconstructing a process tree for a malware investigation.
        - Pulling the command lines / network targets behind a behavioral
          alert.
        - Comparing src/tgt process pairs to identify lateral movement.

    Notes:
        - Empty results (`status="empty"`) are NORMAL on rule-based
          detections (e.g. STAR rules that fire from cloud telemetry
          rather than EDR events). Don't retry the same query expecting
          different rows.
        - The query is included in the response so a sub-agent can
          adapt it (different columns, different time-window, different
          field projection) and re-run via the lower-level `powerquery`
          tool if needed.

    Raises:
        ValueError: If storyline_id is empty or limits are out of range.
        RuntimeError: If settings are not configured or the SDL query
            fails outright.
    """
).strip()


def _build_investigation_config() -> InvestigationConfig:
    """Build an `InvestigationConfig` from the global app settings.

    Returns:
        InvestigationConfig populated from the cached `Settings` instance.

    Raises:
        RuntimeError: If application settings cannot be initialized.
    """
    try:
        settings = get_settings()
    except Exception as exc:
        raise RuntimeError(
            f"Settings not initialized. Please check your environment configuration. Error: {exc}"
        ) from exc

    return InvestigationConfig(
        auth_token=settings.graphql_service_token,
        console_base_url=settings.sentinelone_console_base_url,
        alerts_graphql_url=settings.alerts_graphql_url,
        inventory_api_endpoint=settings.sentinelone_inventory_restapi_endpoint,
        sdl_base_url=settings.sentinelone_console_base_url + SDL_API_PATH,
        environment=settings.environment,
    )


async def get_storyline_events(
    storyline_id: str,
    time_window_hours: int = DEFAULT_TIME_WINDOW_HOURS,
    limit: int = DEFAULT_STORYLINE_EVENT_LIMIT,
) -> str:
    """Fetch EDR events from SDL for a given storyline_id.

    Args:
        storyline_id: The storyline identifier.
        time_window_hours: Lookback window in hours (default 72).
        limit: Max rows to return (default 500).

    Returns:
        JSON-serialized `StorylineSection` with status/events/query/error.

    Raises:
        ValueError: If storyline_id is empty or limits are out of range.
        RuntimeError: If settings are not configured or the query fails.
    """
    if not storyline_id or not storyline_id.strip():
        raise ValueError("storyline_id cannot be empty")

    config = _build_investigation_config()
    collector = InvestigationCollector(config)

    try:
        section = await collector.fetch_storyline_events(
            storyline_id=storyline_id.strip(),
            time_window_hours=time_window_hours,
            limit=limit,
        )
    except ValueError:
        raise
    except Exception as exc:
        logger.exception(
            "Storyline fetch failed",
            extra={"storyline_id": storyline_id},
        )
        raise RuntimeError(f"Failed to fetch storyline events for {storyline_id}") from exc

    return section.model_dump_json(exclude_none=True, indent=2)
