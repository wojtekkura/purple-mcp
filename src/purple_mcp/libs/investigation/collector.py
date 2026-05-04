"""Orchestrator that bundles a SentinelOne incident for downstream sub-agents.

`InvestigationCollector.collect()` performs three triage fetches in one
call (storyline events are explicitly NOT included — see below):

1. Related alerts on the same endpoint, last 72h (Alerts GraphQL)
2. Asset inventory record for the endpoint (Inventory REST)
3. Remediation actions and analyst notes on the primary alert (Alerts GraphQL)

The primary alert is fetched first (we need its `asset.id` to fan out the
other calls and we surface its `storyline_id` in the summary). After
that, the three subordinate fetches run concurrently with
`asyncio.gather(return_exceptions=True)` so a failure in one section
never blocks the others — the bundle is always returned with per-section
status, error string, and payload.

The storyline fetch is intentionally NOT bundled into `collect()`. Real
storylines on busy endpoints can return hundreds of thousands of EDR
events (one live test saw `match_count=172_820` from a single
storyline), which makes the bundle multi-megabyte and dominates the
sub-agent's context. Instead, `fetch_storyline_events()` is exposed as a
separate public method and surfaced as its own MCP tool
(`get_storyline_events`); a downstream sub-agent calls it on-demand with
its own limits/time-window using `summary.storyline_id` from the bundle.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone

from purple_mcp.libs.alerts import AlertsClient, AlertsConfig, FilterInput, ViewType
from purple_mcp.libs.alerts.models import Alert, AlertHistoryEvent, AlertNote
from purple_mcp.libs.inventory import (
    InventoryClient,
    InventoryConfig,
    InventoryItem,
    InventoryNotFoundError,
)
from purple_mcp.libs.investigation.config import InvestigationConfig
from purple_mcp.libs.investigation.exceptions import PrimaryAlertNotFoundError
from purple_mcp.libs.investigation.models import (
    AssetInventorySection,
    IncidentBundle,
    IncidentSummary,
    PrimaryAlertSection,
    RelatedAlertsSection,
    RemediationSection,
    SectionStatus,
    StorylineEvent,
    StorylineSection,
)
from purple_mcp.libs.sdl import (
    SDLPowerQueryHandler,
    SDLPQFrequency,
    SDLPQResultType,
    SDLQueryPriority,
    SDLTableResultData,
    create_sdl_settings,
)

logger = logging.getLogger(__name__)


DEFAULT_TIME_WINDOW_HOURS: int = 72
DEFAULT_RELATED_ALERTS_LIMIT: int = 50

# Default total cap on remediation history events. Bumped from 50 (the
# original single-page default) to 200 now that `_fetch_remediation`
# auto-paginates: most alerts have well under 50 events, but a heavily
# triaged incident (multiple analysts, multi-integration tickets,
# repeated mitigation attempts) can easily produce 100+ history rows
# and we want the bundle to capture every action by default.
DEFAULT_REMEDIATION_HISTORY_LIMIT: int = 200

# Per-API-call page size for the alert-history pagination loop. The S1
# Alerts GraphQL caps `first` at 100, so this is the largest single
# page we can request.
DEFAULT_HISTORY_PAGE_SIZE: int = 100

DEFAULT_STORYLINE_EVENT_LIMIT: int = 500
DEFAULT_STORYLINE_POLL_TIMEOUT_MS: int = 120_000


class InvestigationCollector:
    """Orchestrates a multi-API incident bundle for triage sub-agents."""

    def __init__(self, config: InvestigationConfig) -> None:
        """Initialize the collector with its composite configuration.

        Args:
            config: Investigation orchestrator configuration carrying the
                shared auth token plus per-API URLs/endpoints.
        """
        self.config = config

    async def collect(
        self,
        alert_id: str,
        time_window_hours: int = DEFAULT_TIME_WINDOW_HOURS,
        related_alerts_limit: int = DEFAULT_RELATED_ALERTS_LIMIT,
        remediation_history_limit: int = DEFAULT_REMEDIATION_HISTORY_LIMIT,
    ) -> IncidentBundle:
        """Collect the three-section investigation bundle for an alert.

        Sections:
            1. related_alerts   — other alerts on the same endpoint, last `time_window_hours`
            2. asset_inventory  — InventoryItem for the endpoint
            3. remediation      — EVERY alert-history audit event (auto-paginated)
                                  + every analyst note. Mitigation actions
                                  (kill / quarantine / rollback / network
                                  isolate / ticket events / status changes /
                                  verdict updates) all surface here as
                                  `history_events` rows. `history_truncated`
                                  is True only if we hit `remediation_history_limit`
                                  before exhausting the API — otherwise every
                                  action ever recorded on the alert is in
                                  the bundle.

        Storyline events are NOT included here; call `fetch_storyline_events()`
        (or the `get_storyline_events` MCP tool) on demand using
        `summary.storyline_id` from the returned bundle.

        Args:
            alert_id: The unique identifier of the primary alert (incident).
                Accepts either the internal UUID or a numeric externalId
                (the latter is auto-resolved via the Alerts GraphQL
                `externalId` filter).
            time_window_hours: Lookback window applied to the related-alerts
                search. Defaults to 72.
            related_alerts_limit: Max number of related alerts to return.
            remediation_history_limit: HARD CAP on total history events
                fetched across pagination. Default 200. The collector
                pages the alert-history endpoint until it either runs
                out of events (every action captured) or hits this cap.
                Bump this if a heavily-investigated alert truncates.

        Returns:
            A populated `IncidentBundle` with per-section status, payload,
            and error fields.

        Raises:
            PrimaryAlertNotFoundError: If the primary alert cannot be located.
                Without it we have no asset_id to drive the other fetches,
                so collection cannot proceed.
            ValueError: If any limit/window argument is out of range.
        """
        if time_window_hours <= 0:
            raise ValueError("time_window_hours must be positive")
        if related_alerts_limit <= 0 or related_alerts_limit > 100:
            raise ValueError("related_alerts_limit must be between 1 and 100")
        if remediation_history_limit <= 0 or remediation_history_limit > 1000:
            raise ValueError("remediation_history_limit must be between 1 and 1000")

        alert_id = alert_id.strip()
        if not alert_id:
            raise ValueError("alert_id cannot be empty")

        # Compute the lookback window once so every section uses the same edges
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=time_window_hours)
        window_start_iso = start_time.isoformat().replace("+00:00", "Z")
        window_end_iso = end_time.isoformat().replace("+00:00", "Z")

        warnings: list[str] = []

        # ---- Phase 1: fetch the primary alert (everything else depends on it)
        alerts_client = self._build_alerts_client()
        primary_section, primary_alert = await self._fetch_primary_alert(alerts_client, alert_id)
        if primary_alert is None:
            raise PrimaryAlertNotFoundError(
                f"Primary alert {alert_id} not found",
                details=primary_section.error,
            )

        asset_id = primary_alert.asset.id if primary_alert.asset else None
        storyline_id = primary_alert.storyline_id

        if not asset_id:
            warnings.append(
                "Primary alert has no asset.id; related-alerts and inventory "
                "sections will be skipped."
            )
        if not storyline_id:
            warnings.append(
                "Primary alert has no storyline_id; the bundle will not include "
                "a storyline_id for the get_storyline_events tool."
            )

        # ---- Phase 2: fan out the three subordinate fetches concurrently
        import asyncio

        # IMPORTANT: use the resolved UUID (`primary_alert.id`), not the raw
        # `alert_id` input — the analyst may have passed an externalId that
        # was transparently resolved by `_fetch_primary_alert`. Downstream
        # GraphQL queries require the UUID, and the related-alerts dedup
        # compares against UUID `node.id`s.
        resolved_alert_id = primary_alert.id

        related_task = asyncio.create_task(
            self._fetch_related_alerts(
                alerts_client=alerts_client,
                asset_id=asset_id,
                primary_alert_id=resolved_alert_id,
                window_start=start_time,
                window_end=end_time,
                limit=related_alerts_limit,
            )
        )
        inventory_task = asyncio.create_task(
            self._fetch_asset_inventory(asset_id=asset_id),
        )
        remediation_task = asyncio.create_task(
            self._fetch_remediation(
                alerts_client=alerts_client,
                alert_id=resolved_alert_id,
                history_total_cap=remediation_history_limit,
            )
        )

        related_section, inventory_section, remediation_section = await asyncio.gather(
            related_task,
            inventory_task,
            remediation_task,
        )

        summary = IncidentSummary(
            alert_id=primary_alert.id,
            asset_id=asset_id,
            asset_name=primary_alert.asset.name if primary_alert.asset else None,
            asset_type=primary_alert.asset.type if primary_alert.asset else None,
            storyline_id=storyline_id,
            severity=primary_alert.severity.value if primary_alert.severity else None,
            status=primary_alert.status.value if primary_alert.status else None,
            name=primary_alert.name,
            detected_at=primary_alert.detected_at,
            classification=primary_alert.classification,
            analyst_verdict=(
                primary_alert.analyst_verdict.value if primary_alert.analyst_verdict else None
            ),
            detection_product=(
                primary_alert.detection_source.product if primary_alert.detection_source else None
            ),
            detection_vendor=(
                primary_alert.detection_source.vendor if primary_alert.detection_source else None
            ),
            time_window_hours=time_window_hours,
            time_window_start=window_start_iso,
            time_window_end=window_end_iso,
        )

        return IncidentBundle(
            summary=summary,
            primary_alert=primary_section,
            related_alerts=related_section,
            asset_inventory=inventory_section,
            remediation=remediation_section,
            warnings=warnings,
        )

    # ------------------------------------------------------------------ helpers

    def _build_alerts_client(self) -> AlertsClient:
        """Build a fresh AlertsClient from the orchestrator config."""
        return AlertsClient(
            AlertsConfig(
                graphql_url=self.config.alerts_graphql_url,
                auth_token=self.config.auth_token,
            )
        )

    def _build_inventory_client(self) -> InventoryClient:
        """Build a fresh InventoryClient from the orchestrator config."""
        return InventoryClient(
            InventoryConfig(
                base_url=self.config.console_base_url,
                api_endpoint=self.config.inventory_api_endpoint,
                api_token=self.config.auth_token,
            )
        )

    @staticmethod
    def _looks_like_uuid(value: str) -> bool:
        """Return True if `value` parses as a standard UUID.

        S1's Unified Alerts Management `alert(id: ID!)` query expects the
        internal UUID. Analysts often paste an `externalId` instead — a
        long numeric string that looks like `2470473633234860895`. We use
        this check to decide whether to call `get_alert` directly or to
        resolve via `search_alerts(externalId=...)` first.
        """
        try:
            uuid.UUID(value)
        except (ValueError, AttributeError, TypeError):
            return False
        return True

    async def _resolve_alert_id(
        self, alerts_client: AlertsClient, raw_alert_id: str
    ) -> tuple[str | None, str | None]:
        """Resolve an analyst-supplied alert reference to its internal UUID.

        Returns:
            (resolved_uuid, error_message). If the input is already a UUID
            we return it unchanged. Otherwise we search by `externalId`:
            a unique match returns its UUID; zero or multiple matches
            return None plus a human-readable error.
        """
        if self._looks_like_uuid(raw_alert_id):
            return raw_alert_id, None

        logger.info(
            "Alert id is not a UUID; resolving via externalId",
            extra={"raw_alert_id": raw_alert_id},
        )

        filters = [FilterInput.create_string_equal("externalId", raw_alert_id)]
        try:
            connection = await alerts_client.search_alerts(
                filters=filters, first=2, view_type=ViewType.ALL
            )
        except Exception as exc:
            return None, (f"Failed to look up alert by externalId={raw_alert_id!r}: {exc}")

        matches = [edge.node.id for edge in connection.edges]
        if not matches:
            return None, (
                f"No alert found with id or externalId={raw_alert_id!r}. "
                "Verify the value (UUIDs look like '019de8cc-…'; externalIds "
                "are long numeric strings)."
            )
        if len(matches) > 1:
            return None, (
                f"Ambiguous: {len(matches)} alerts share externalId={raw_alert_id!r}. "
                "Pass the internal UUID instead."
            )

        resolved = matches[0]
        logger.info(
            "Resolved externalId to UUID",
            extra={"raw_alert_id": raw_alert_id, "resolved_uuid": resolved},
        )
        return resolved, None

    async def _fetch_primary_alert(
        self, alerts_client: AlertsClient, alert_id: str
    ) -> tuple[PrimaryAlertSection, Alert | None]:
        """Fetch the alert that anchors the investigation.

        Accepts either the internal UUID or a numeric `externalId` — the
        latter is auto-resolved via `search_alerts(externalId=…)` so an
        analyst can paste the value straight from a ticket/email/SIEM
        without having to re-look-up the UUID.

        Returns:
            Tuple of (section, alert_or_None). The section captures status
            and error so the caller can surface it even on failure; the
            alert is returned alongside so phase 2 can derive asset_id /
            storyline_id without re-parsing.
        """
        resolved_id, resolve_error = await self._resolve_alert_id(alerts_client, alert_id)
        if resolved_id is None:
            return (
                PrimaryAlertSection(status=SectionStatus.FAILED, error=resolve_error),
                None,
            )

        try:
            alert = await alerts_client.get_alert(resolved_id)
        except Exception as exc:
            logger.exception("Failed to fetch primary alert", extra={"alert_id": resolved_id})
            return (
                PrimaryAlertSection(status=SectionStatus.FAILED, error=str(exc)),
                None,
            )

        if alert is None:
            return (
                PrimaryAlertSection(
                    status=SectionStatus.EMPTY,
                    error=f"Alert {resolved_id} returned no record",
                ),
                None,
            )

        return PrimaryAlertSection(status=SectionStatus.OK, alert=alert), alert

    async def _fetch_related_alerts(
        self,
        alerts_client: AlertsClient,
        asset_id: str | None,
        primary_alert_id: str,
        window_start: datetime,
        window_end: datetime,
        limit: int,
    ) -> RelatedAlertsSection:
        """Fetch other alerts on the same endpoint within the lookback window."""
        if not asset_id:
            return RelatedAlertsSection(status=SectionStatus.SKIPPED)

        start_ms = int(window_start.timestamp() * 1000)
        end_ms = int(window_end.timestamp() * 1000)

        # The Alerts GraphQL doesn't expose `asset.id` as a top-level filter
        # field directly; the well-known field for endpoint correlation is
        # `assetId`. (We also tried `asset.id` historically but it 400s on
        # current schemas — `assetId` is the flattened name.)
        filters = [
            FilterInput.create_string_equal("assetId", asset_id),
            FilterInput.create_datetime_range("createdAt", start_ms, end_ms),
        ]

        try:
            connection = await alerts_client.search_alerts(
                filters=filters,
                first=limit,
                view_type=ViewType.ALL,
            )
        except Exception as exc:
            logger.exception(
                "Failed to fetch related alerts",
                extra={"asset_id": asset_id, "alert_id": primary_alert_id},
            )
            return RelatedAlertsSection(status=SectionStatus.FAILED, error=str(exc))

        # Drop the primary alert from the related set so sub-agents don't double-count
        alerts = [edge.node for edge in connection.edges if edge.node.id != primary_alert_id]
        truncated = (
            connection.page_info.has_next_page if connection.page_info is not None else False
        )

        if not alerts:
            return RelatedAlertsSection(
                status=SectionStatus.EMPTY,
                total_count=connection.total_count,
                returned_count=0,
                truncated=truncated,
            )

        return RelatedAlertsSection(
            status=SectionStatus.OK,
            total_count=connection.total_count,
            returned_count=len(alerts),
            truncated=truncated,
            alerts=alerts,
        )

    async def _fetch_asset_inventory(self, asset_id: str | None) -> AssetInventorySection:
        """Fetch the asset inventory record for the endpoint."""
        if not asset_id:
            return AssetInventorySection(status=SectionStatus.SKIPPED)

        try:
            async with self._build_inventory_client() as client:
                item: InventoryItem | None = await client.get_inventory_item(asset_id)
        except InventoryNotFoundError:
            return AssetInventorySection(
                status=SectionStatus.EMPTY,
                error=f"Inventory item {asset_id} not found",
            )
        except Exception as exc:
            logger.exception("Failed to fetch asset inventory", extra={"asset_id": asset_id})
            return AssetInventorySection(status=SectionStatus.FAILED, error=str(exc))

        if item is None:
            return AssetInventorySection(status=SectionStatus.EMPTY)

        return AssetInventorySection(status=SectionStatus.OK, item=item)

    async def _fetch_remediation(
        self,
        alerts_client: AlertsClient,
        alert_id: str,
        history_total_cap: int,
        history_page_size: int = DEFAULT_HISTORY_PAGE_SIZE,
    ) -> RemediationSection:
        """Fetch ALL alert history events plus analyst notes.

        History pagination is exhaustive — we walk the connection until
        `pageInfo.hasNextPage=false` or we hit `history_total_cap`,
        whichever comes first. This guarantees that every remediation
        action recorded on the alert (mitigation events, ticket updates,
        analyst verdict changes, integration callbacks, …) is included,
        not just the first page returned by the API.

        Pagination strategy:
            - Notes are launched concurrently and awaited after the
              history loop completes (notes don't paginate in this API).
            - History is paged sequentially using the connection's
              `endCursor` (cursor pagination is sequential by design;
              parallel page requests against the same cursor stream
              would race).
            - Each page asks for `min(history_page_size, remaining_cap)`
              rows, so we never fetch more than `history_total_cap` total.
            - `history_truncated` is True only if we hit the cap AND
              there were more events available (i.e. we actually
              dropped data); a clean exhaust sets it to False.

        Either side of the gather can fail independently and the section
        will still return whatever succeeded.
        """
        import asyncio

        # Notes don't paginate — fire it off and pick it up at the end.
        notes_task = asyncio.create_task(alerts_client.get_alert_notes(alert_id=alert_id))

        history_events: list[AlertHistoryEvent] = []
        history_truncated = False
        history_error: str | None = None
        history_pages_fetched = 0

        cursor: str | None = None
        try:
            while True:
                remaining = history_total_cap - len(history_events)
                if remaining <= 0:
                    # We hit the cap. Whether or not the API has more
                    # is signaled by the most recent page's hasNextPage,
                    # already captured below before we'd reach this branch.
                    break

                page_size = max(1, min(history_page_size, remaining))
                connection = await alerts_client.get_alert_history(
                    alert_id=alert_id, first=page_size, after=cursor
                )
                history_pages_fetched += 1
                history_events.extend(edge.node for edge in connection.edges)

                page_info = connection.page_info
                if page_info is None or not page_info.has_next_page:
                    # Exhausted — every recorded action is now in our list.
                    break
                if not page_info.end_cursor:
                    # Defensive: the API claims there's more but didn't
                    # give us a cursor. Treat as truncated and stop.
                    history_truncated = True
                    break

                if len(history_events) >= history_total_cap:
                    # Hit the cap exactly. The API still says more
                    # exists (we just checked has_next_page=true), so
                    # mark truncated and stop.
                    history_truncated = True
                    break

                cursor = page_info.end_cursor
        except Exception as exc:
            history_error = str(exc)
            logger.warning(
                "Failed to fetch alert history",
                extra={
                    "alert_id": alert_id,
                    "error": history_error,
                    "pages_fetched": history_pages_fetched,
                    "events_so_far": len(history_events),
                },
            )

        # Now collect notes.
        notes: list[AlertNote] = []
        notes_error: str | None = None
        try:
            notes_response = await notes_task
            notes = list(notes_response.data)
        except Exception as exc:
            notes_error = str(exc)
            logger.warning(
                "Failed to fetch alert notes",
                extra={"alert_id": alert_id, "error": notes_error},
            )

        if history_error and notes_error:
            return RemediationSection(
                status=SectionStatus.FAILED,
                history_error=history_error,
                notes_error=notes_error,
                error=f"history: {history_error}; notes: {notes_error}",
            )

        if not history_events and not notes:
            return RemediationSection(
                status=SectionStatus.EMPTY,
                history_error=history_error,
                notes_error=notes_error,
                history_truncated=history_truncated,
            )

        return RemediationSection(
            status=SectionStatus.OK,
            history_events=history_events,
            history_truncated=history_truncated,
            notes=notes,
            history_error=history_error,
            notes_error=notes_error,
        )

    async def fetch_storyline_events(
        self,
        storyline_id: str,
        time_window_hours: int = DEFAULT_TIME_WINDOW_HOURS,
        limit: int = DEFAULT_STORYLINE_EVENT_LIMIT,
    ) -> StorylineSection:
        """Public API: fetch SDL events for a storyline_id.

        This is intentionally separate from `collect()` because storyline
        events on busy endpoints can run into the hundreds of thousands of
        rows; bundling them into the main investigation envelope would
        bloat the per-call payload past what most sub-agents can ingest.
        Use this when a sub-agent has decided it actually needs the EDR
        process tree for the alert.

        Args:
            storyline_id: The storyline identifier from
                `IncidentBundle.summary.storyline_id`.
            time_window_hours: Lookback window for the SDL query (default 72).
            limit: Max rows to return (default 500).

        Returns:
            `StorylineSection` with status, projected events, and the
            generated PowerQuery (so the sub-agent can adapt it).

        Raises:
            ValueError: If `storyline_id` is empty or limits are out of range.
        """
        if not storyline_id or not storyline_id.strip():
            raise ValueError("storyline_id cannot be empty")
        if time_window_hours <= 0:
            raise ValueError("time_window_hours must be positive")
        if limit <= 0:
            raise ValueError("limit must be positive")

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=time_window_hours)
        return await self._fetch_storyline_events(
            storyline_id=storyline_id.strip(),
            window_start=start_time,
            window_end=end_time,
            limit=limit,
        )

    async def _fetch_storyline_events(
        self,
        storyline_id: str | None,
        window_start: datetime,
        window_end: datetime,
        limit: int,
    ) -> StorylineSection:
        """Run a PowerQuery for EDR events tied to the storyline.

        Empirically, on S1's SDL the cross-event correlation field is the
        per-process attribute `src.process.storyline.id` (and the symmetric
        `tgt.process.storyline.id` on parent/target sides). The flat
        `storylineId` column is exposed by the schema but is not populated
        for EDR events on the consoles we tested, so filtering on it returns
        zero rows.

        We also project a curated set of columns rather than pulling every
        attribute. This keeps the response size predictable and gives a
        downstream sub-agent the exact fields it needs to reconstruct a
        process tree (timestamp, src + tgt process identifiers, file/dns
        targets, command-line) without paying for unused columns.
        """
        if not storyline_id:
            return StorylineSection(status=SectionStatus.SKIPPED)

        # Single-quoted literal — storyline IDs are alphanumeric so this is
        # safe; we still avoid building strings that contain a quote char.
        if "'" in storyline_id:
            return StorylineSection(
                status=SectionStatus.FAILED,
                storyline_id=storyline_id,
                error="storyline_id contains a single quote and cannot be safely quoted in PQ",
            )

        # Curated projection: enough to rebuild a process tree without bloat
        projected_columns = (
            "event.time, event.type, event.category, "
            "endpoint.name, endpoint.os, "
            "src.process.name, src.process.cmdline, src.process.pid, src.process.user, "
            "src.process.storyline.id, "
            "tgt.process.name, tgt.process.cmdline, tgt.process.pid, "
            "tgt.process.storyline.id, "
            "tgt.file.path, tgt.file.sha256, "
            "dns.request, url.address, "
            "dst.ip.address, dst.port.number"
        )

        query = (
            f"src.process.storyline.id='{storyline_id}' "
            f"OR tgt.process.storyline.id='{storyline_id}' "
            f"| columns {projected_columns} "
            f"| sort -event.time "
            f"| limit {limit}"
        )

        sdl_settings = create_sdl_settings(
            auth_token=self.config.auth_token,
            base_url=self.config.sdl_base_url,
            default_poll_timeout_ms=DEFAULT_STORYLINE_POLL_TIMEOUT_MS,
            http_timeout=60,
            environment=self.config.environment,
            max_query_results=limit,
        )

        handler = SDLPowerQueryHandler(
            auth_token=sdl_settings.auth_token,
            base_url=sdl_settings.base_url,
            settings=sdl_settings,
        )

        try:
            try:
                await handler.submit_powerquery(
                    start_time=window_start,
                    end_time=window_end,
                    query=query,
                    result_type=SDLPQResultType.TABLE,
                    frequency=SDLPQFrequency.LOW,
                    query_priority=SDLQueryPriority.LOW,
                )
                results: SDLTableResultData | None = await handler.poll_until_complete()
            except Exception as exc:
                logger.exception(
                    "Storyline PowerQuery failed",
                    extra={"storyline_id": storyline_id},
                )
                return StorylineSection(
                    status=SectionStatus.FAILED,
                    storyline_id=storyline_id,
                    query=query,
                    error=str(exc),
                )

            if results is None or not results.values:
                return StorylineSection(
                    status=SectionStatus.EMPTY,
                    storyline_id=storyline_id,
                    query=query,
                )

            column_names = [col.name for col in results.columns]
            events = [
                StorylineEvent(fields=dict(zip(column_names, row, strict=False)))
                for row in results.values
            ]
            return StorylineSection(
                status=SectionStatus.OK,
                storyline_id=storyline_id,
                query=query,
                columns=column_names,
                match_count=int(results.match_count or 0),
                returned_count=len(events),
                truncated=results.truncated_at_limit,
                partial=handler.is_result_partial(),
                warnings=list(results.warnings),
                events=events,
            )

        finally:
            # Mirror the cleanup pattern from tools/sdl.py: best-effort delete
            # the query and close the HTTP client to avoid resource leaks.
            try:
                if (
                    handler.query_submitted
                    and handler.query_id
                    and not handler.sdl_query_client.is_closed()
                    and not handler.is_query_completed()
                ):
                    await handler.delete_query()
            except Exception:
                logger.exception("Failed to delete storyline query during cleanup")

            try:
                if not handler.sdl_query_client.is_closed():
                    await handler.sdl_query_client.close()
            except Exception:
                logger.exception("Failed to close SDL query client during cleanup")
