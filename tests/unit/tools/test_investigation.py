"""Unit tests for the initiate_investigation tool.

Covers the orchestrator's branching: happy path, missing-asset/missing-storyline
fallbacks, and per-section failure isolation. Live API calls are mocked at the
client level so the test exercises the section assembly logic without touching
the network.
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
from purple_mcp.libs.sdl.enums import PQColumnType
from purple_mcp.libs.sdl.models import SDLTableResultData
from purple_mcp.tools import investigation as investigation_tool


def _make_alert(
    alert_id: str = "alert-primary",
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
def mock_alerts_client_factory() -> "AsyncMock":
    """Factory fixture: returns an AlertsClient mock with default responses.

    Tests override individual methods after grabbing the mock.
    """
    client = MagicMock()
    client.get_alert = AsyncMock(return_value=_make_alert())
    client.search_alerts = AsyncMock(
        return_value=AlertConnection(
            edges=[
                AlertEdge(node=_make_alert(alert_id="alert-related-1"), cursor="c1"),
                # The primary alert ID should be filtered out by the collector
                AlertEdge(node=_make_alert(alert_id="alert-primary"), cursor="c2"),
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
                    alertId="alert-primary",
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


@pytest.fixture
def mock_sdl_handler() -> MagicMock:
    """Factory: returns an SDLPowerQueryHandler mock with a single-row result."""
    handler = MagicMock()
    handler.submit_powerquery = AsyncMock()
    handler.poll_until_complete = AsyncMock(
        return_value=SDLTableResultData.model_validate(
            {
                "matchCount": 1,
                "values": [["1730000000000", "process_create", "/usr/bin/curl"]],
                "columns": [
                    {"name": "event.time", "type": PQColumnType.TIMESTAMP},
                    {"name": "event.type", "type": PQColumnType.STRING},
                    {"name": "src.process.name", "type": PQColumnType.STRING},
                ],
            }
        )
    )
    handler.is_result_partial = MagicMock(return_value=False)
    handler.query_submitted = False
    handler.query_id = None
    handler.is_query_completed = MagicMock(return_value=True)
    handler.delete_query = AsyncMock()
    sdl_query_client = MagicMock()
    sdl_query_client.is_closed = MagicMock(return_value=True)
    sdl_query_client.close = AsyncMock()
    handler.sdl_query_client = sdl_query_client
    return handler


@pytest.mark.asyncio
async def test_initiate_investigation_happy_path(
    mock_settings: Callable[..., MagicMock],
    mock_alerts_client_factory: MagicMock,
    mock_inventory_client_factory: MagicMock,
    mock_sdl_handler: MagicMock,
) -> None:
    """All four sections should populate when every API responds normally."""
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
        patch(
            "purple_mcp.libs.investigation.collector.SDLPowerQueryHandler",
            return_value=mock_sdl_handler,
        ),
    ):
        result = await investigation_tool.initiate_investigation("alert-primary")

    bundle = json.loads(result)

    assert bundle["schema_version"] == "1"
    assert bundle["summary"]["alert_id"] == "alert-primary"
    assert bundle["summary"]["asset_id"] == "asset-1"
    assert bundle["summary"]["storyline_id"] == "story-1"
    assert bundle["summary"]["time_window_hours"] == 72

    assert bundle["primary_alert"]["status"] == "ok"
    assert bundle["primary_alert"]["alert"]["id"] == "alert-primary"

    # The collector strips the primary alert from related results
    assert bundle["related_alerts"]["status"] == "ok"
    assert bundle["related_alerts"]["returned_count"] == 1
    assert bundle["related_alerts"]["alerts"][0]["id"] == "alert-related-1"

    assert bundle["asset_inventory"]["status"] == "ok"
    assert bundle["asset_inventory"]["item"]["id"] == "asset-1"

    assert bundle["remediation"]["status"] == "ok"
    assert len(bundle["remediation"]["history_events"]) == 1
    assert len(bundle["remediation"]["notes"]) == 1

    assert bundle["storyline"]["status"] == "ok"
    assert bundle["storyline"]["returned_count"] == 1
    assert bundle["storyline"]["events"][0]["fields"]["event.type"] == "process_create"


@pytest.mark.asyncio
async def test_initiate_investigation_skips_when_asset_missing(
    mock_settings: Callable[..., MagicMock],
    mock_alerts_client_factory: MagicMock,
    mock_inventory_client_factory: MagicMock,
    mock_sdl_handler: MagicMock,
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
        patch(
            "purple_mcp.libs.investigation.collector.SDLPowerQueryHandler",
            return_value=mock_sdl_handler,
        ),
    ):
        result = await investigation_tool.initiate_investigation("alert-primary")

    bundle = json.loads(result)
    assert bundle["related_alerts"]["status"] == "skipped"
    assert bundle["asset_inventory"]["status"] == "skipped"
    assert bundle["storyline"]["status"] == "ok"
    # Warning should call out the skip reason
    assert any("asset.id" in w for w in bundle["warnings"])


@pytest.mark.asyncio
async def test_initiate_investigation_storyline_failure_isolated(
    mock_settings: Callable[..., MagicMock],
    mock_alerts_client_factory: MagicMock,
    mock_inventory_client_factory: MagicMock,
    mock_sdl_handler: MagicMock,
) -> None:
    """A storyline PQ failure must NOT take down the rest of the bundle."""
    mock_sdl_handler.submit_powerquery = AsyncMock(
        side_effect=RuntimeError("SDL: Service unavailable"),
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
        patch(
            "purple_mcp.libs.investigation.collector.SDLPowerQueryHandler",
            return_value=mock_sdl_handler,
        ),
    ):
        result = await investigation_tool.initiate_investigation("alert-primary")

    bundle = json.loads(result)
    assert bundle["primary_alert"]["status"] == "ok"
    assert bundle["related_alerts"]["status"] == "ok"
    assert bundle["asset_inventory"]["status"] == "ok"
    assert bundle["remediation"]["status"] == "ok"
    assert bundle["storyline"]["status"] == "failed"
    assert "Service unavailable" in bundle["storyline"]["error"]


@pytest.mark.asyncio
async def test_initiate_investigation_primary_missing_raises(
    mock_settings: Callable[..., MagicMock],
    mock_alerts_client_factory: MagicMock,
    mock_inventory_client_factory: MagicMock,
    mock_sdl_handler: MagicMock,
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
        patch(
            "purple_mcp.libs.investigation.collector.SDLPowerQueryHandler",
            return_value=mock_sdl_handler,
        ),
        pytest.raises(RuntimeError) as exc_info,
    ):
        await investigation_tool.initiate_investigation("does-not-exist")

    # The tool wraps PrimaryAlertNotFoundError in RuntimeError; the underlying
    # cause should still be available.
    assert isinstance(exc_info.value.__cause__, PrimaryAlertNotFoundError)


@pytest.mark.asyncio
async def test_initiate_investigation_validates_inputs(
    mock_settings: Callable[..., MagicMock],
) -> None:
    """Empty alert_id and out-of-range limits should raise ValueError early."""
    with patch(
        "purple_mcp.tools.investigation.get_settings",
        return_value=mock_settings(),
    ):
        with pytest.raises(ValueError):
            await investigation_tool.initiate_investigation("")
        with pytest.raises(ValueError):
            await investigation_tool.initiate_investigation("a", related_alerts_limit=0)
        with pytest.raises(ValueError):
            await investigation_tool.initiate_investigation("a", time_window_hours=-1)
