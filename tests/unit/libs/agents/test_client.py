"""Unit tests for AgentsClient request shapes and error mapping."""

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from purple_mcp.libs.agents import (
    AgentsAPIError,
    AgentsAuthenticationError,
    AgentsClient,
    AgentsConfig,
)

Handler = Callable[[httpx.Request], httpx.Response]
CONFIG = AgentsConfig(base_url="https://console.test", api_token="tok")


@contextmanager
def mock_transport(handler: Handler) -> Iterator[None]:
    """Route every AsyncClient the agents client creates through ``handler``."""
    real_client = httpx.AsyncClient

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    with patch("purple_mcp.libs.agents.client.httpx.AsyncClient", side_effect=factory):
        yield


@pytest.mark.asyncio
async def test_find_agents_by_computer_name() -> None:
    """Computer-name lookup hits /agents with the ApiToken header."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": [{"id": "1", "computerName": "31XZ173"}]})

    with mock_transport(handler):
        async with AgentsClient(CONFIG) as client:
            agents = await client.find_agents(computer_name="31XZ173")

    assert agents == [{"id": "1", "computerName": "31XZ173"}]
    assert seen[0].url.path == "/web/api/v2.1/agents"
    assert seen[0].url.params["computerName"] == "31XZ173"
    assert seen[0].headers["Authorization"] == "ApiToken tok"


@pytest.mark.asyncio
async def test_find_agents_requires_a_selector() -> None:
    """Calling find_agents without any selector is a programming error."""
    with mock_transport(lambda r: httpx.Response(200, json={"data": []})):
        async with AgentsClient(CONFIG) as client:
            with pytest.raises(ValueError):
                await client.find_agents()


@pytest.mark.asyncio
async def test_list_update_packages_query() -> None:
    """Package listing asks for GA packages of the agent's OS."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": [{"id": "p1"}]})

    with mock_transport(handler):
        async with AgentsClient(CONFIG) as client:
            packages = await client.list_update_packages("windows")

    assert packages == [{"id": "p1"}]
    params = seen[0].url.params
    assert seen[0].url.path == "/web/api/v2.1/update/agent/packages"
    assert params["osTypes"] == "windows"
    assert params["status"] == "ga"


@pytest.mark.asyncio
async def test_update_software_body_and_affected() -> None:
    """update-software targets one agent ID with an immediate, unscheduled package push."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": {"affected": 1}})

    with mock_transport(handler):
        async with AgentsClient(CONFIG) as client:
            affected = await client.update_software("123", "pkg-9")

    assert affected == 1
    assert seen[0].method == "POST"
    assert seen[0].url.path == "/web/api/v2.1/agents/actions/update-software"
    assert json.loads(seen[0].content) == {
        "filter": {"ids": ["123"]},
        "data": {"packageId": "pkg-9", "isScheduled": False},
    }


@pytest.mark.asyncio
async def test_update_software_is_not_retried() -> None:
    """A failed upgrade POST is sent exactly once, never retried."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={"errors": ["busy"]})

    with mock_transport(handler):
        async with AgentsClient(CONFIG) as client:
            with pytest.raises(AgentsAPIError):
                await client.update_software("123", "pkg-9")

    assert calls == 1


@pytest.mark.asyncio
async def test_forbidden_maps_to_authentication_error() -> None:
    """A token without upgrade permission surfaces as an authentication error."""
    with mock_transport(lambda r: httpx.Response(403, json={"errors": ["no permission"]})):
        async with AgentsClient(CONFIG) as client:
            with pytest.raises(AgentsAuthenticationError):
                await client.update_software("123", "pkg-9")


@pytest.mark.asyncio
async def test_api_error_includes_status() -> None:
    """Other 4xx responses become AgentsAPIError carrying the HTTP status."""
    with mock_transport(lambda r: httpx.Response(400, json={"errors": [{"title": "bad"}]})):
        async with AgentsClient(CONFIG) as client:
            with pytest.raises(AgentsAPIError, match="HTTP 400"):
                await client.find_agents(agent_id="1")
