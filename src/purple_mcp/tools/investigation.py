"""MCP tool that bundles a SentinelOne incident in a single call.

This tool wraps `InvestigationCollector.collect()` and returns the
**three-section** `IncidentBundle`:

    1. Related alerts on the same endpoint, last 72h
    2. Asset inventory record for the endpoint
    3. Remediation actions and analyst notes on the primary alert

Storyline events were intentionally split out: real storylines on busy
endpoints can produce hundreds of thousands of EDR rows. Bundling them
here would inflate every triage payload past what most sub-agents can
ingest, even when they don't need the storyline. They are now fetched
on-demand via the separate `get_storyline_events` tool, using
`summary.storyline_id` from this bundle.

The response is a stable, self-describing JSON envelope (`IncidentBundle`,
`schema_version: "2"`) that downstream specialist agents can dispatch on.
"""

import logging
from textwrap import dedent
from typing import Final

from purple_mcp.config import get_settings
from purple_mcp.libs.investigation import (
    DEFAULT_RELATED_ALERTS_LIMIT,
    DEFAULT_REMEDIATION_HISTORY_LIMIT,
    DEFAULT_TIME_WINDOW_HOURS,
    InvestigationCollector,
    InvestigationConfig,
    PrimaryAlertNotFoundError,
)
from purple_mcp.libs.sdl import SDL_API_PATH

logger = logging.getLogger(__name__)


INITIATE_INVESTIGATION_DESCRIPTION: Final[str] = dedent(
    """
    Initiate a SOAR-ready investigation bundle for a SentinelOne incident.

    Performs three concurrent data fetches and returns a structured JSON
    envelope that downstream specialist sub-agents can ingest as-is:

    1. **Related alerts** on the same endpoint within the lookback window
       (default 72 hours), excluding the primary alert.
    2. **Asset inventory** record for the endpoint (full InventoryItem,
       including agent/cloud/identity surface fields where present).
    3. **Remediation actions taken** — full alert audit history (status
       changes, assignments, mitigation events, integration actions) plus
       all analyst notes attached to the primary alert.

    NOTE: Storyline / EDR events are NOT included in this bundle. They can
    contain hundreds of thousands of rows on a busy endpoint, which would
    bloat every triage payload. Use the separate `get_storyline_events`
    tool with `summary.storyline_id` from this bundle when a sub-agent
    needs the EDR process tree.

    Args:
        alert_id: The primary alert / incident identifier. Either format
            is accepted:
              - Internal UUID (e.g. `019de8cc-6d14-7adc-993a-710e4123976a`).
              - External numeric id (e.g. `2470473633234860895`) — the kind
                analysts typically copy from a ticket / email / SIEM. The
                tool transparently resolves it via the Alerts GraphQL
                `externalId` filter before continuing.
            If the externalId resolves to multiple alerts the call fails
            with a clear error and the analyst must pass the UUID.
        time_window_hours: Lookback window applied to the related-alerts
            search. Default 72.
        related_alerts_limit: Max related alerts to return (1-100, default 50).
        remediation_history_limit: Max history events (1-100, default 50).

    Returns:
        JSON document with this shape:

        {
          "schema_version": "2",
          "summary": {
            "alert_id", "asset_id", "asset_name", "asset_type",
            "storyline_id", "severity", "status", "name", "detected_at",
            "classification", "analyst_verdict",
            "detection_product", "detection_vendor",
            "time_window_hours", "time_window_start", "time_window_end"
          },
          "primary_alert":   { "status", "alert", "error" },
          "related_alerts":  { "status", "total_count", "returned_count",
                               "truncated", "alerts", "error" },
          "asset_inventory": { "status", "item", "error" },
          "remediation":     { "status", "history_events", "history_truncated",
                               "notes", "history_error", "notes_error", "error" },
          "warnings": [...]
        }

        Each `status` field is one of: "ok", "empty", "skipped", "failed".
        Sub-agents should branch on status before consuming `alert/item`.

        `summary.storyline_id` is the input you pass to
        `get_storyline_events` to fetch the EDR process-tree rows.

    Failure model:
        - If the primary alert cannot be located, the tool raises
          RuntimeError (no useful bundle is possible without it).
        - Every other section is isolated: one failed section does NOT
          fail the call. The section's `status` is set to "failed" and
          its `error` field carries the message.

    Common Use Cases:
        - SOAR triage where a specialist analyst sub-agent needs a
          complete one-shot picture of an incident.
        - Pre-flight context gathering before deeper investigation.
        - Bulk hand-off from a queue worker to a downstream LLM agent.

    Raises:
        ValueError: If alert_id is empty or any limit is out of range.
        RuntimeError: If the primary alert cannot be retrieved.
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


async def initiate_investigation(
    alert_id: str,
    time_window_hours: int = DEFAULT_TIME_WINDOW_HOURS,
    related_alerts_limit: int = DEFAULT_RELATED_ALERTS_LIMIT,
    remediation_history_limit: int = DEFAULT_REMEDIATION_HISTORY_LIMIT,
) -> str:
    """Bundle related alerts, asset inventory, and remediation for an alert.

    Storylines are intentionally NOT bundled here — fetch them via the
    separate `get_storyline_events` tool when needed.

    Args:
        alert_id: The primary alert identifier. Accepts EITHER the internal
            UUID (e.g. `019de8cc-6d14-7adc-993a-710e4123976a`) OR the
            numeric externalId (e.g. `2470473633234860895`) — externalIds
            are resolved automatically via the Alerts GraphQL `externalId`
            filter.
        time_window_hours: Lookback window for the related-alerts search
            (default 72).
        related_alerts_limit: Max related alerts (1-100, default 50).
        remediation_history_limit: Max history events (1-100, default 50).

    Returns:
        JSON-serialized `IncidentBundle` (schema_version=2) with
        per-section status/payload/error.

    Raises:
        ValueError: If alert_id is empty or any limit is out of range.
        RuntimeError: If the primary alert cannot be retrieved or settings
            are not configured.
    """
    if not alert_id or not alert_id.strip():
        raise ValueError("alert_id cannot be empty")

    config = _build_investigation_config()
    collector = InvestigationCollector(config)

    try:
        bundle = await collector.collect(
            alert_id=alert_id.strip(),
            time_window_hours=time_window_hours,
            related_alerts_limit=related_alerts_limit,
            remediation_history_limit=remediation_history_limit,
        )
    except PrimaryAlertNotFoundError as exc:
        logger.warning("Primary alert not found", extra={"alert_id": alert_id})
        raise RuntimeError(str(exc)) from exc
    except ValueError:
        raise
    except Exception as exc:
        logger.exception("Investigation collection failed", extra={"alert_id": alert_id})
        raise RuntimeError(f"Failed to initiate investigation for alert {alert_id}") from exc

    return bundle.model_dump_json(exclude_none=True, indent=2)
