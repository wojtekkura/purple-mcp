"""Unit tests for the agent upgrade tools, focused on the confirmation gate."""

import json
from collections.abc import Callable, Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from purple_mcp.tools import agent_upgrade as tool

AGENT: dict[str, Any] = {
    "id": "1234567890123456789",
    "computerName": "31XZ173",
    "uuid": "a8abe595b29c40c8a342f1f3a6952e80",
    "osType": "windows",
    "osArch": "64 bit",
    "isActive": True,
    "isUpToDate": False,
    "agentVersion": "26.1.2.177",
    "siteName": "Groupon, Inc.",
}
NEW_PACKAGE: dict[str, Any] = {
    "id": "pkg-new",
    "version": "26.2.1.50",
    "fileExtension": ".msi",
    "osType": "windows",
    "osArch": "64 bit",
    "status": "ga",
    "packageType": "Agent",
    "fileName": "SentinelInstaller_26.2.1.50.msi",
}


def _make_client(agents: list[dict[str, Any]], packages: list[dict[str, Any]]) -> MagicMock:
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.find_agents = AsyncMock(return_value=agents)
    client.list_update_packages = AsyncMock(return_value=packages)
    client.update_software = AsyncMock(return_value=1)
    client.list_activities = AsyncMock(return_value=[])
    return client


@pytest.fixture
def clients() -> Iterator[Callable[..., dict[str, MagicMock]]]:
    """Patch read and write clients; returns a configurator."""
    state: dict[str, MagicMock] = {}

    def configure(
        agents: list[dict[str, Any]] | None = None,
        packages: list[dict[str, Any]] | None = None,
    ) -> dict[str, MagicMock]:
        state["read"] = _make_client(
            [AGENT] if agents is None else agents,
            [NEW_PACKAGE] if packages is None else packages,
        )
        state["write"] = _make_client([], [])
        return state

    configure()

    def factory(*, write: bool = False) -> MagicMock:
        return state["write"] if write else state["read"]

    with patch.object(tool, "_get_agents_client", side_effect=factory):
        yield configure


@pytest.mark.asyncio
async def test_preview_never_writes(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """Without confirm, upgrade_agent returns a preview and never calls the write API."""
    state = clients()
    result = json.loads(await tool.upgrade_agent("31XZ173"))

    assert result["mode"] == "preview"
    assert result["plan"]["status"] == "upgrade_available"
    assert result["plan"]["package_id"] == "pkg-new"
    assert "confirm=true" in result["next_step"]
    state["write"].update_software.assert_not_called()


@pytest.mark.asyncio
async def test_confirm_requires_package_id(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """confirm=true without the approved package_id is rejected before any API call."""
    state = clients()
    with pytest.raises(ValueError, match="package_id"):
        await tool.upgrade_agent("31XZ173", confirm=True)
    state["write"].update_software.assert_not_called()


@pytest.mark.asyncio
async def test_confirm_executes_with_write_client(
    clients: Callable[..., dict[str, MagicMock]],
) -> None:
    """Confirmed upgrades go through the write-token client only."""
    state = clients()
    result = json.loads(await tool.upgrade_agent("31XZ173", package_id="pkg-new", confirm=True))

    assert result["mode"] == "executed"
    assert result["affected"] == 1
    state["write"].update_software.assert_awaited_once_with("1234567890123456789", "pkg-new")
    state["read"].update_software.assert_not_called()


@pytest.mark.asyncio
async def test_confirm_skips_when_already_up_to_date(
    clients: Callable[..., dict[str, MagicMock]],
) -> None:
    """A confirm that arrives after the agent already upgraded does nothing."""
    state = clients(agents=[{**AGENT, "agentVersion": "26.2.1.50"}])
    result = json.loads(await tool.upgrade_agent("31XZ173", package_id="pkg-new", confirm=True))

    assert result["mode"] == "not_executed"
    assert result["reason"] == "already_up_to_date"
    state["write"].update_software.assert_not_called()


@pytest.mark.asyncio
async def test_confirm_skips_inactive_agent(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """Inactive agents are not sent an upgrade."""
    state = clients(agents=[{**AGENT, "isActive": False}])
    result = json.loads(await tool.upgrade_agent("31XZ173", package_id="pkg-new", confirm=True))

    assert result["reason"] == "agent_inactive"
    state["write"].update_software.assert_not_called()


@pytest.mark.asyncio
async def test_unknown_package_id_rejected(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """Only GA packages for the agent's OS can be installed."""
    clients()
    with pytest.raises(ValueError, match="not a GA agent package"):
        await tool.upgrade_agent("31XZ173", package_id="pkg-other", confirm=True)


@pytest.mark.asyncio
async def test_not_found(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """Unknown endpoints return a not_found result instead of raising."""
    clients(agents=[])
    result = json.loads(await tool.get_agent_upgrade_options("NOPE"))
    assert result["status"] == "not_found"


@pytest.mark.asyncio
async def test_ambiguous_prefers_single_active(
    clients: Callable[..., dict[str, MagicMock]],
) -> None:
    """A stale duplicate record is ignored when exactly one agent is active."""
    stale = {**AGENT, "id": "999999999999999999", "isActive": False}
    clients(agents=[stale, AGENT])
    result = json.loads(await tool.get_agent_upgrade_options("31XZ173"))
    assert result["agent_id"] == "1234567890123456789"


@pytest.mark.asyncio
async def test_ambiguous_multiple_active(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """Several active matches block the upgrade and list the candidates."""
    state = clients(agents=[AGENT, {**AGENT, "id": "999999999999999999"}])
    result = json.loads(await tool.upgrade_agent("31XZ173", package_id="pkg-new", confirm=True))
    assert result["status"] == "ambiguous"
    assert len(result["candidates"]) == 2
    state["write"].update_software.assert_not_called()


@pytest.mark.asyncio
async def test_endpoint_routing(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """UUIDs and numeric IDs are looked up by the matching API filter."""
    state = clients()
    await tool.get_agent_upgrade_options("A8ABE595B29C40C8A342F1F3A6952E80")
    state["read"].find_agents.assert_awaited_with(uuid="a8abe595b29c40c8a342f1f3a6952e80")
    await tool.get_agent_upgrade_options("1234567890123456789")
    state["read"].find_agents.assert_awaited_with(agent_id="1234567890123456789")


@pytest.mark.asyncio
async def test_status_filters_upgrade_activities(
    clients: Callable[..., dict[str, MagicMock]],
) -> None:
    """Status keeps only upgrade-related activity rows."""
    state = clients()
    state["read"].list_activities = AsyncMock(
        return_value=[
            {"createdAt": "t2", "primaryDescription": "Agent 31XZ173 upgraded to 26.2.1.50"},
            {"createdAt": "t1", "primaryDescription": "User logged in"},
        ]
    )
    result = json.loads(await tool.get_agent_upgrade_status("31XZ173"))
    assert result["agent_version"] == "26.1.2.177"
    assert [a["created_at"] for a in result["upgrade_activities"]] == ["t2"]


def test_write_client_uses_write_token(mock_settings: Callable[..., MagicMock]) -> None:
    """The write client prefers the dedicated write token."""
    settings = mock_settings(graphql_service_token="read-tok", console_write_token="write-tok")
    with patch.object(tool, "get_settings", return_value=settings):
        assert tool._get_agents_client().config.api_token == "read-tok"
        assert tool._get_agents_client(write=True).config.api_token == "write-tok"


def test_write_client_falls_back_to_console_token(mock_settings: Callable[..., MagicMock]) -> None:
    """Without a write token, the console token is used."""
    settings = mock_settings(graphql_service_token="read-tok")
    settings.console_write_token = None
    with patch.object(tool, "get_settings", return_value=settings):
        assert tool._get_agents_client(write=True).config.api_token == "read-tok"
