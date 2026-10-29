"""Unit tests for the path exclusion tools, focused on the confirmation gate."""

import json
from collections.abc import Callable, Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from purple_mcp.tools import exclusions as tool

AGENT: dict[str, Any] = {
    "id": "1234567890123456789",
    "computerName": "31XZ173",
    "osType": "windows",
    "isActive": True,
    "siteId": "200",
    "siteName": "Groupon, Inc.",
    "groupId": "300",
    "groupName": "Default Group",
}
ARGS: dict[str, Any] = {
    "endpoint": "31XZ173",
    "path": "C:\\Program Files\\Vendor\\App\\",
    "mode": "disable_in_process_monitor",
    "reason": "S1 CPU 95% while App rebuilds its cache",
    "approved_by": "analyst@groupon.com",
    "reference": "INSIGHT-1",
}


def _make_client(agents: list[dict[str, Any]], exclusions: list[dict[str, Any]]) -> MagicMock:
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.find_agents = AsyncMock(return_value=agents)
    client.list_exclusions = AsyncMock(return_value=exclusions)
    client.create_exclusion = AsyncMock(
        return_value={"id": "9001", "value": ARGS["path"], "scopeName": "group"}
    )
    return client


@pytest.fixture
def clients() -> Iterator[Callable[..., dict[str, MagicMock]]]:
    """Patch read and write clients; returns a configurator."""
    state: dict[str, MagicMock] = {}

    def configure(
        agents: list[dict[str, Any]] | None = None,
        exclusions: list[dict[str, Any]] | None = None,
    ) -> dict[str, MagicMock]:
        state["read"] = _make_client([AGENT] if agents is None else agents, exclusions or [])
        state["write"] = _make_client([], [])
        return state

    configure()

    def factory(*, write: bool = False) -> MagicMock:
        return state["write"] if write else state["read"]

    with patch.object(tool, "_get_agents_client", side_effect=factory):
        yield configure


@pytest.mark.asyncio
async def test_preview_never_writes(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """Without confirm, create_path_exclusion returns a preview and never calls the write API."""
    state = clients()
    result = json.loads(await tool.create_path_exclusion(**ARGS))

    assert result["mode"] == "preview"
    plan = result["plan"]
    assert plan["status"] == "ready"
    assert plan["scope_level"] == "group" and plan["scope_id"] == "300"
    assert plan["path_type"] == "subfolders"
    assert "analyst@groupon.com" in plan["description"]
    assert "INSIGHT-1" in plan["description"]
    assert "confirm=true" in result["next_step"]
    state["read"].list_exclusions.assert_awaited_once_with(
        group_id="300", site_id=None, os_type="windows"
    )
    state["write"].create_exclusion.assert_not_called()


@pytest.mark.asyncio
async def test_confirm_creates_with_write_client(
    clients: Callable[..., dict[str, MagicMock]],
) -> None:
    """Confirmed creates go through the write-token client with the planned body."""
    state = clients()
    result = json.loads(await tool.create_path_exclusion(**ARGS, confirm=True))

    assert result["mode"] == "executed"
    assert result["exclusion"]["id"] == "9001"
    body = state["write"].create_exclusion.await_args.args[0]
    assert body["filter"] == {"groupIds": ["300"]}
    assert body["data"]["value"] == ARGS["path"]
    assert body["data"]["mode"] == "disable_in_process_monitor"
    assert body["data"]["osType"] == "windows"
    state["read"].create_exclusion.assert_not_called()


@pytest.mark.asyncio
async def test_site_scope(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """Site scope uses the agent's site and warns about the wider blast radius."""
    state = clients()
    result = json.loads(await tool.create_path_exclusion(**ARGS, scope_level="site", confirm=True))
    assert result["mode"] == "executed"
    assert state["write"].create_exclusion.await_args.args[0]["filter"] == {"siteIds": ["200"]}
    assert any("Site scope" in w for w in result["plan"]["warnings"])


@pytest.mark.asyncio
async def test_risky_path_not_executed(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """Rejected paths are never sent, even with confirm, and skip the duplicate lookup."""
    state = clients()
    args = {**ARGS, "path": "C:\\Users\\*\\AppData\\Local\\"}
    result = json.loads(await tool.create_path_exclusion(**args, confirm=True))

    assert result["mode"] == "not_executed"
    assert result["reason"] == "rejected"
    assert result["plan"]["problems"]
    state["read"].list_exclusions.assert_not_called()
    state["write"].create_exclusion.assert_not_called()


@pytest.mark.asyncio
async def test_existing_exclusion_not_duplicated(
    clients: Callable[..., dict[str, MagicMock]],
) -> None:
    """An exclusion that already exists (here on the site) is reported, not recreated."""
    existing = {"id": "77", "value": "c:\\program files\\vendor\\app\\*", "scopeName": "site"}
    state = clients(exclusions=[existing])
    result = json.loads(await tool.create_path_exclusion(**ARGS, confirm=True))

    assert result["reason"] == "already_exists"
    assert result["plan"]["existing"][0]["id"] == "77"
    state["write"].create_exclusion.assert_not_called()


@pytest.mark.asyncio
async def test_covering_exclusion_same_mode(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """A parent sub-folder exclusion with the same mode already covers the path."""
    parent = {
        "id": "78",
        "value": "C:\\Program Files\\Vendor\\*",
        "pathExclusionType": "subfolders",
        "mode": "disable_in_process_monitor",
    }
    state = clients(exclusions=[parent])
    result = json.loads(await tool.create_path_exclusion(**ARGS, confirm=True))
    assert result["reason"] == "already_covered"
    state["write"].create_exclusion.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["reason", "approved_by", "path"])
async def test_required_audit_fields(
    clients: Callable[..., dict[str, MagicMock]], field: str
) -> None:
    """Reason, approver and path are mandatory before anything is looked up."""
    state = clients()
    with pytest.raises(ValueError, match=field):
        await tool.create_path_exclusion(**{**ARGS, field: "  "}, confirm=True)
    state["read"].find_agents.assert_not_called()
    state["write"].create_exclusion.assert_not_called()


@pytest.mark.asyncio
async def test_invalid_scope_level(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """Only group and site scopes are supported."""
    clients()
    with pytest.raises(ValueError, match="scope_level"):
        await tool.create_path_exclusion(**ARGS, scope_level="account")


@pytest.mark.asyncio
async def test_decommissioned_agent_rejected(
    clients: Callable[..., dict[str, MagicMock]],
) -> None:
    """Exclusions are not scoped from a decommissioned agent record."""
    state = clients(agents=[{**AGENT, "isDecommissioned": True}])
    result = json.loads(await tool.create_path_exclusion(**ARGS, confirm=True))
    assert result["reason"] == "rejected"
    state["write"].create_exclusion.assert_not_called()


@pytest.mark.asyncio
async def test_ambiguous_endpoint(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """Several active agents with the same name block the create."""
    state = clients(agents=[AGENT, {**AGENT, "id": "999999999999999999"}])
    result = json.loads(await tool.create_path_exclusion(**ARGS, confirm=True))
    assert result["status"] == "ambiguous"
    state["write"].create_exclusion.assert_not_called()


@pytest.mark.asyncio
async def test_list_path_exclusions(clients: Callable[..., dict[str, MagicMock]]) -> None:
    """Listing scopes to the agent's group (with parents) and its OS."""
    rows = [{"id": "1", "value": "C:\\A\\", "mode": "suppress", "scopeName": "site"}]
    state = clients(exclusions=rows)
    result = json.loads(await tool.list_path_exclusions("31XZ173", value_contains="A"))

    assert result["count"] == 1
    assert result["exclusions"][0]["scope"] == "site"
    state["read"].list_exclusions.assert_awaited_once_with(
        group_id="300",
        site_id="200",
        os_type="windows",
        value_contains="A",
        include_parents=True,
        max_items=tool.MAX_LISTED,
    )
