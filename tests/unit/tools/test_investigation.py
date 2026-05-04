"""Unit tests for the initiate_investigation tool.

Covers the orchestrator's branching: happy path, missing-asset fallback,
per-section failure isolation, and the externalId → UUID resolution path.
Live API calls are mocked at the client level so the test exercises the
section assembly logic without touching the network.

Storyline events are NOT bundled by `initiate_investigation` anymore —
they live behind the separate `get_storyline_events` tool, which has
its own test module.
"""

import json
from collections.abc import Callable
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from purple_mcp.libs.alerts.models import (
    Alert,
    AlertConnection,
    AlertEdge,
    AlertHistoryConnection,
    AlertHistoryEdge,
    AlertHistoryEvent,
    AlertNote,
    GetAlertNotesResponse,
    PageInfo,
    Severity,
    Status,
)
from purple_mcp.libs.inventory.models import InventoryItem
from purple_mcp.libs.investigation import PrimaryAlertNotFoundError
from purple_mcp.tools import investigation as investigation_tool

# Use real UUID-format strings so the collector's `_looks_like_uuid` check
# resolves them via `get_alert` directly (i.e. the happy path) rather than
# falling into the externalId search branch.
PRIMARY_UUID = "00000000-0000-0000-0000-000000000001"
RELATED_UUID = "00000000-0000-0000-0000-000000000002"


def _make_alert(
    alert_id: str = PRIMARY_UUID,
    asset_id: str | None = "asset-1",
    storyline_id: str | None = "story-1",
) -> Alert:
    """Build a minimal Alert with the fields the collector reads."""
    return Alert.model_validate(
        {
            "id": alert_id,
            "severity": Severity.HIGH,
            "status": Status.NEW,
            "name": "Test Alert",
            "detectedAt": "2026-05-01T12:00:00Z",
            "classification": "Malware",
            "asset": (
                {"id": asset_id, "name": "HOST-1", "type": "endpoint"} if asset_id else None
            ),
            "storylineId": storyline_id,
            "detectionSource": {"product": "EDR", "vendor": "SentinelOne"},
        }
    )


def _empty_page_info() -> PageInfo:
    """PageInfo for an exhausted connection."""
    return PageInfo(hasNextPage=False, hasPreviousPage=False)


@pytest.fixture
def mock_alerts_client_factory() -> MagicMock:
    """Factory fixture: returns an AlertsClient mock with default responses.

    Tests override individual methods after grabbing the mock.
    """
    client = MagicMock()
    client.get_alert = AsyncMock(return_value=_make_alert())
    client.search_alerts = AsyncMock(
        return_value=AlertConnection(
            edges=[
                AlertEdge(node=_make_alert(alert_id=RELATED_UUID), cursor="c1"),
                # The primary alert ID should be filtered out by the collector
                AlertEdge(node=_make_alert(alert_id=PRIMARY_UUID), cursor="c2"),
            ],
            pageInfo=_empty_page_info(),
            totalCount=2,
        )
    )
    client.get_alert_history = AsyncMock(
        return_value=AlertHistoryConnection(
            edges=[
                AlertHistoryEdge(
                    node=AlertHistoryEvent(
                        createdAt="2026-05-01T13:00:00Z",
                        eventText="Mitigation kill",
                        eventType="mitigation",
                    ),
                    cursor="h1",
                )
            ],
            pageInfo=_empty_page_info(),
            totalCount=1,
        )
    )
    client.get_alert_notes = AsyncMock(
        return_value=GetAlertNotesResponse(
            data=[
                AlertNote(
                    id="note-1",
                    text="Confirmed TP",
                    createdAt="2026-05-01T14:00:00Z",
                    alertId=PRIMARY_UUID,
                )
            ]
        )
    )
    return client


@pytest.fixture
def mock_inventory_client_factory() -> MagicMock:
    """Factory: returns an async-context-managed InventoryClient mock."""
    client = MagicMock()
    client.get_inventory_item = AsyncMock(return_value=InventoryItem(id="asset-1", name="HOST-1"))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


# ---------------------------------------------------------- happy path / branches


@pytest.mark.asyncio
async def test_initiate_investigation_happy_path(
    mock_settings: Callable[..., MagicMock],
    mock_alerts_client_factory: MagicMock,
    mock_inventory_client_factory: MagicMock,
) -> None:
    """All three sections should populate when every API responds normally."""
    with (
        patch(
            "purple_mcp.tools.investigation.get_settings",
            return_value=mock_settings(),
        ),
        patch(
            "purple_mcp.libs.investigation.collector.AlertsClient",
            return_value=mock_alerts_client_factory,
        ),
        patch(
            "purple_mcp.libs.investigation.collector.InventoryClient",
            return_value=mock_inventory_client_factory,
        ),
    ):
        result = await investigation_tool.initiate_investigation(PRIMARY_UUID)

    bundle = json.loads(result)

    assert bundle["schema_version"] == "2"
    # Storyline section is no longer part of the bundle envelope
    assert "storyline" not in bundle
    # …but storyline_id IS surfaced in the summary so the analyst can
    # hand it to `get_storyline_events`.
    assert bundle["summary"]["storyline_id"] == "story-1"

    assert bundle["summary"]["alert_id"] == PRIMARY_UUID
    assert bundle["summary"]["asset_id"] == "asset-1"
    assert bundle["summary"]["time_window_hours"] == 72

    assert bundle["primary_alert"]["status"] == "ok"
    assert bundle["primary_alert"]["alert"]["id"] == PRIMARY_UUID

    # The collector strips the primary alert from related results
    assert bundle["related_alerts"]["status"] == "ok"
    assert bundle["related_alerts"]["returned_count"] == 1
    assert bundle["related_alerts"]["alerts"][0]["id"] == RELATED_UUID

    assert bundle["asset_inventory"]["status"] == "ok"
    assert bundle["asset_inventory"]["item"]["id"] == "asset-1"

    assert bundle["remediation"]["status"] == "ok"
    assert len(bundle["remediation"]["history_events"]) == 1
    assert len(bundle["remediation"]["notes"]) == 1


@pytest.mark.asyncio
async def test_initiate_investigation_skips_when_asset_missing(
    mock_settings: Callable[..., MagicMock],
    mock_alerts_client_factory: MagicMock,
    mock_inventory_client_factory: MagicMock,
) -> None:
    """No asset.id → related_alerts and asset_inventory must skip cleanly."""
    mock_alerts_client_factory.get_alert = AsyncMock(
        return_value=_make_alert(asset_id=None, storyline_id="story-1")
    )

    with (
        patch(
            "purple_mcp.tools.investigation.get_settings",
            return_value=mock_settings(),
        ),
        patch(
            "purple_mcp.libs.investigation.collector.AlertsClient",
            return_value=mock_alerts_client_factory,
        ),
        patch(
            "purple_mcp.libs.investigation.collector.InventoryClient",
            return_value=mock_inventory_client_factory,
        ),
    ):
        result = await investigation_tool.initiate_investigation(PRIMARY_UUID)

    bundle = json.loads(result)
    assert bundle["related_alerts"]["status"] == "skipped"
    assert bundle["asset_inventory"]["status"] == "skipped"
    # Remediation does NOT depend on asset_id, so it should still run.
    assert bundle["remediation"]["status"] == "ok"
    # Warning should call out the skip reason
    assert any("asset.id" in w for w in bundle["warnings"])


@pytest.mark.asyncio
async def test_initiate_investigation_remediation_failure_isolated(
    mock_settings: Callable[..., MagicMock],
    mock_alerts_client_factory: MagicMock,
    mock_inventory_client_factory: MagicMock,
) -> None:
    """A remediation fetch failure must NOT take down the rest of the bundle."""
    mock_alerts_client_factory.get_alert_history = AsyncMock(
        side_effect=RuntimeError("history: 500"),
    )
    mock_alerts_client_factory.get_alert_notes = AsyncMock(
        side_effect=RuntimeError("notes: 500"),
    )

    with (
        patch(
            "purple_mcp.tools.investigation.get_settings",
            return_value=mock_settings(),
        ),
        patch(
            "purple_mcp.libs.investigation.collector.AlertsClient",
            return_value=mock_alerts_client_factory,
        ),
        patch(
            "purple_mcp.libs.investigation.collector.InventoryClient",
            return_value=mock_inventory_client_factory,
        ),
    ):
        result = await investigation_tool.initiate_investigation(PRIMARY_UUID)

    bundle = json.loads(result)
    assert bundle["primary_alert"]["status"] == "ok"
    assert bundle["related_alerts"]["status"] == "ok"
    assert bundle["asset_inventory"]["status"] == "ok"
    assert bundle["remediation"]["status"] == "failed"
    assert "history: 500" in bundle["remediation"]["error"]


@pytest.mark.asyncio
async def test_initiate_investigation_primary_missing_raises(
    mock_settings: Callable[..., MagicMock],
    mock_alerts_client_factory: MagicMock,
    mock_inventory_client_factory: MagicMock,
) -> None:
    """If the primary alert is not found, the call must raise (not return)."""
    mock_alerts_client_factory.get_alert = AsyncMock(return_value=None)

    with (
        patch(
            "purple_mcp.tools.investigation.get_settings",
            return_value=mock_settings(),
        ),
        patch(
            "purple_mcp.libs.investigation.collector.AlertsClient",
            return_value=mock_alerts_client_factory,
        ),
        patch(
            "purple_mcp.libs.investigation.collector.InventoryClient",
            return_value=mock_inventory_client_factory,
        ),
        pytest.raises(RuntimeError) as exc_info,
    ):
        await investigation_tool.initiate_investigation(PRIMARY_UUID)

    # The tool wraps PrimaryAlertNotFoundError in RuntimeError; the underlying
    # cause should still be available.
    assert isinstance(exc_info.value.__cause__, PrimaryAlertNotFoundError)


@pytest.mark.asyncio
async def test_initiate_investigation_validates_inputs(
    mock_settings: Callable[..., MagicMock],
) -> None:
    """Empty alert_id and out-of-range limits should raise ValueError early.

    These checks fire BEFORE any client construction, so we don't need to
    mock the alerts/inventory clients here.
    """
    with patch(
        "purple_mcp.tools.investigation.get_settings",
        return_value=mock_settings(),
    ):
        with pytest.raises(ValueError):
            await investigation_tool.initiate_investigation("")
        with pytest.raises(ValueError):
            await investigation_tool.initiate_investigation(PRIMARY_UUID, related_alerts_limit=0)
        with pytest.raises(ValueError):
            await investigation_tool.initiate_investigation(PRIMARY_UUID, time_window_hours=-1)


# ---------------------------------------------------- externalId resolver path


@pytest.mark.asyncio
async def test_initiate_investigation_resolves_external_id(
    mock_settings: Callable[..., MagicMock],
    mock_alerts_client_factory: MagicMock,
    mock_inventory_client_factory: MagicMock,
) -> None:
    """A numeric externalId input should resolve to its UUID via search_alerts."""
    external_id = "2470473633234860895"

    # First search_alerts call (resolver) returns exactly one alert; the
    # second call (related-alerts fan-out) returns its own response. We
    # chain the side_effect so each invocation gets the right response in
    # order.
    resolver_response = AlertConnection(
        edges=[AlertEdge(node=_make_alert(alert_id=PRIMARY_UUID), cursor="r1")],
        pageInfo=_empty_page_info(),
        totalCount=1,
    )
    related_response = AlertConnection(
        edges=[AlertEdge(node=_make_alert(alert_id=RELATED_UUID), cursor="c1")],
        pageInfo=_empty_page_info(),
        totalCount=1,
    )
    mock_alerts_client_factory.search_alerts = AsyncMock(
        side_effect=[resolver_response, related_response],
    )

    with (
        patch(
            "purple_mcp.tools.investigation.get_settings",
            return_value=mock_settings(),
        ),
        patch(
            "purple_mcp.libs.investigation.collector.AlertsClient",
            return_value=mock_alerts_client_factory,
        ),
        patch(
            "purple_mcp.libs.investigation.collector.InventoryClient",
            return_value=mock_inventory_client_factory,
        ),
    ):
        result = await investigation_tool.initiate_investigation(external_id)

    bundle = json.loads(result)
    # The bundle should be keyed by the resolved UUID, not the externalId
    assert bundle["summary"]["alert_id"] == PRIMARY_UUID
    assert bundle["primary_alert"]["status"] == "ok"
    # And get_alert must have been called with the resolved UUID, not the input
    mock_alerts_client_factory.get_alert.assert_called_once_with(PRIMARY_UUID)
    # First search_alerts call must have been the externalId resolver
    first_call = mock_alerts_client_factory.search_alerts.call_args_list[0]
    filters_passed = first_call.kwargs.get("filters") or first_call.args[0]
    assert any(getattr(f, "field_id", None) == "externalId" for f in filters_passed), (
        "Expected the resolver call to filter on `externalId`"
    )


@pytest.mark.asyncio
async def test_initiate_investigation_external_id_not_found(
    mock_settings: Callable[..., MagicMock],
    mock_alerts_client_factory: MagicMock,
    mock_inventory_client_factory: MagicMock,
) -> None:
    """A non-UUID input that resolves to zero matches must raise clearly."""
    mock_alerts_client_factory.search_alerts = AsyncMock(
        return_value=AlertConnection(
            edges=[],
            pageInfo=_empty_page_info(),
            totalCount=0,
        )
    )

    with (
        patch(
            "purple_mcp.tools.investigation.get_settings",
            return_value=mock_settings(),
        ),
        patch(
            "purple_mcp.libs.investigation.collector.AlertsClient",
            return_value=mock_alerts_client_factory,
        ),
        patch(
            "purple_mcp.libs.investigation.collector.InventoryClient",
            return_value=mock_inventory_client_factory,
        ),
        pytest.raises(RuntimeError) as exc_info,
    ):
        await investigation_tool.initiate_investigation("9999999999999999")

    assert isinstance(exc_info.value.__cause__, PrimaryAlertNotFoundError)
    assert "9999999999999999" in str(exc_info.value)


@pytest.mark.asyncio
async def test_initiate_investigation_external_id_ambiguous(
    mock_settings: Callable[..., MagicMock],
    mock_alerts_client_factory: MagicMock,
    mock_inventory_client_factory: MagicMock,
) -> None:
    """Multiple alerts sharing an externalId must surface as a clear error."""
    mock_alerts_client_factory.search_alerts = AsyncMock(
        return_value=AlertConnection(
            edges=[
                AlertEdge(node=_make_alert(alert_id=PRIMARY_UUID), cursor="r1"),
                AlertEdge(node=_make_alert(alert_id=RELATED_UUID), cursor="r2"),
            ],
            pageInfo=_empty_page_info(),
            totalCount=2,
        )
    )

    with (
        patch(
            "purple_mcp.tools.investigation.get_settings",
            return_value=mock_settings(),
        ),
        patch(
            "purple_mcp.libs.investigation.collector.AlertsClient",
            return_value=mock_alerts_client_factory,
        ),
        patch(
            "purple_mcp.libs.investigation.collector.InventoryClient",
            return_value=mock_inventory_client_factory,
        ),
        pytest.raises(RuntimeError) as exc_info,
    ):
        await investigation_tool.initiate_investigation("12345678901234567")

    assert "Ambiguous" in str(exc_info.value) or "ambiguous" in str(exc_info.value)
