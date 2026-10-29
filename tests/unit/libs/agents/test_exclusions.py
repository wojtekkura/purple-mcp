"""Unit tests for path exclusion validation, duplicate detection and client calls."""

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from purple_mcp.libs.agents import (
    AgentsAPIError,
    AgentsClient,
    AgentsConfig,
    build_description,
    default_path_type,
    find_existing,
    validate_exclusion,
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


@pytest.mark.parametrize(
    ("path", "os_type"),
    [
        ("C:\\", "windows"),
        ("C:\\Users\\*\\", "windows"),
        ("C:\\Users\\jdoe\\", "windows"),
        ("C:\\Users\\*\\AppData\\Local\\", "windows"),
        ("C:\\Users\\*\\AppData\\Local\\Temp\\App\\", "windows"),
        ("C:\\Windows\\System32\\", "windows"),
        ("C:\\Program Files\\", "windows"),
        ("%ProgramFiles%\\", "windows"),
        ("C:\\Users\\jdoe\\Downloads\\tool\\", "windows"),
        ("*\\Vendor\\", "windows"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "windows"),
        ("\\Program Files (x86)\\*", "windows"),
        ("C:\\Users\\jdoe\\OneDrive - Groupon\\", "windows"),
        ("/Users/*/", "macos"),
        ("/Users/*/Library/", "macos"),
        ("/System/Library/Foo/", "macos"),
        ("/private/tmp/x/", "macos"),
        ("/", "linux"),
    ],
)
def test_broad_and_risky_paths_rejected(path: str, os_type: str) -> None:
    """System roots, user roots, staging folders and LOLBins are refused."""
    problems, _ = validate_exclusion(path, os_type, "disable_all_monitors", "subfolders")
    assert problems, path


@pytest.mark.parametrize(
    ("kwargs", "needle"),
    [
        ({"path": "%USERPROFILE%\\App\\"}, "not supported"),
        ({"path": "C:/Program Files/Vendor/"}, "backslashes"),
        ({"path": "*:\\Vendor\\App\\"}, "drive letter"),
        ({"mode": "disable_all_monitors_deep"}, "allow_extended"),
        ({"mode": "yolo"}, "Unsupported mode"),
        ({"os_type": "macos", "path": "/Applications/Vendor.app/"}, "only available on Windows"),
        ({"os_type": "linux", "path": "opt/vendor/"}, "absolute"),
    ],
)
def test_invalid_input_rejected(kwargs: dict[str, str], needle: str) -> None:
    """Unsupported syntax, modes and OS/mode combinations are refused with a reason."""
    problems, _ = validate_exclusion(
        path=kwargs.get("path", "C:\\Program Files\\Vendor\\App\\"),
        os_type=kwargs.get("os_type", "windows"),
        mode=kwargs.get("mode", "disable_in_process_monitor"),
        path_type="subfolders",
    )
    assert any(needle in p for p in problems), problems


def test_specific_app_folder_allowed_with_warnings() -> None:
    """An application folder passes; Performance Focus and env vars produce warnings."""
    problems, warnings = validate_exclusion(
        "%ProgramFiles%\\Vendor\\App\\Cache\\", "windows", "disable_all_monitors", "subfolders"
    )
    assert problems == []
    assert any("4.6" in w for w in warnings)
    assert any("Performance Focus" in w for w in warnings)


def test_extended_mode_needs_opt_in() -> None:
    """Performance Focus - Extended is allowed only with allow_extended."""
    problems, _ = validate_exclusion(
        "C:\\Vendor\\App\\", "windows", "disable_all_monitors_deep", "subfolders", True
    )
    assert problems == []


def test_default_path_type_and_file_warning() -> None:
    """A trailing separator means sub-folders; a bare folder name is flagged as a file."""
    assert default_path_type("C:\\Vendor\\App\\") == "subfolders"
    assert default_path_type("C:\\Vendor\\App\\*") == "subfolders"
    assert default_path_type("/opt/vendor/app") == "file"
    _, warnings = validate_exclusion("C:\\Vendor\\App", "windows", "suppress", "file")
    assert any("single FILE" in w for w in warnings)


def test_find_existing_exact_and_covering() -> None:
    """Exact matches ignore case and trailing ``*``; sub-folder parents (with wildcards) cover."""
    rows = [
        {
            "id": "1",
            "value": "c:\\program files\\vendor\\app\\*",
            "pathExclusionType": "subfolders",
        },
        {"id": "2", "value": "C:\\Program Files\\*\\", "pathExclusionType": "subfolders"},
        {"id": "3", "value": "C:\\Program Files\\Vendor\\", "pathExclusionType": "folder"},
        {"id": "4", "value": "C:\\Other\\", "pathExclusionType": "subfolders"},
    ]
    exact, covering = find_existing(rows, "C:\\Program Files\\Vendor\\App\\", "windows")
    assert [r["id"] for r in exact] == ["1"]
    assert [r["id"] for r in covering] == ["2"]


def test_description_is_truncated() -> None:
    """The audit description carries approver, ref and reason, capped at 500 chars."""
    text = build_description("analyst@groupon.com", "x" * 1000, "31XZ173", "INSIGHT-1")
    assert text.startswith("[MCP] Approved by: analyst@groupon.com | Ref: INSIGHT-1")
    assert len(text) == 500 and text.endswith("...")


@pytest.mark.asyncio
async def test_list_exclusions_follows_cursor() -> None:
    """Listing sends scope/OS/parent filters and follows nextCursor."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if "cursor" in request.url.params:
            return httpx.Response(200, json={"data": [{"id": "2"}], "pagination": {}})
        return httpx.Response(
            200, json={"data": [{"id": "1"}], "pagination": {"nextCursor": "abc"}}
        )

    with mock_transport(handler):
        async with AgentsClient(CONFIG) as client:
            items = await client.list_exclusions(group_id="300", os_type="windows")

    assert [i["id"] for i in items] == ["1", "2"]
    params = seen[0].url.params
    assert seen[0].url.path == "/web/api/v2.1/exclusions"
    assert params["groupIds"] == "300"
    assert params["osTypes"] == "windows"
    assert params["includeParents"] == "true"
    assert params["type"] == "path"
    assert seen[1].url.params["cursor"] == "abc"


@pytest.mark.asyncio
async def test_list_exclusions_requires_scope() -> None:
    """A group or site is required so the console never lists the whole tenant."""
    with mock_transport(lambda r: httpx.Response(200, json={"data": []})):
        async with AgentsClient(CONFIG) as client:
            with pytest.raises(ValueError):
                await client.list_exclusions()


@pytest.mark.asyncio
async def test_create_exclusion_posts_once() -> None:
    """Create sends the body unchanged and returns the first created object."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": [{"id": "9001", "value": "C:\\A\\"}]})

    body = {"filter": {"groupIds": ["300"]}, "data": {"type": "path", "value": "C:\\A\\"}}
    with mock_transport(handler):
        async with AgentsClient(CONFIG) as client:
            created = await client.create_exclusion(body)

    assert created["id"] == "9001"
    assert len(seen) == 1
    assert seen[0].method == "POST"
    assert json.loads(seen[0].content) == body


@pytest.mark.asyncio
async def test_create_exclusion_not_retried_on_5xx() -> None:
    """A 503 on create surfaces as an error after a single attempt."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(503, json={"errors": [{"title": "busy"}]})

    with mock_transport(handler):
        async with AgentsClient(CONFIG) as client:
            with pytest.raises(AgentsAPIError):
                await client.create_exclusion({"filter": {}, "data": {}})

    assert len(calls) == 1
