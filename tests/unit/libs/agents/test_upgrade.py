"""Unit tests for agent upgrade decision logic."""

import pytest

from purple_mcp.libs.agents import (
    ApiObject,
    is_upgrade_activity,
    parse_version,
    plan_upgrade,
    select_latest_package,
)

WINDOWS_AGENT: ApiObject = {
    "id": "1234567890123456789",
    "computerName": "31XZ173",
    "uuid": "a8abe595b29c40c8a342f1f3a6952e80",
    "osType": "windows",
    "osArch": "64 bit",
    "isActive": True,
    "agentVersion": "26.1.2.177",
}


def _pkg(
    pkg_id: str, version: str, ext: str = ".msi", arch: str = "64 bit", **extra: str
) -> ApiObject:
    return {
        "id": pkg_id,
        "version": version,
        "fileExtension": ext,
        "osType": "windows",
        "osArch": arch,
        "status": "ga",
        "packageType": "Agent",
        "fileName": f"SentinelInstaller_{version}{ext}",
        **extra,
    }


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("26.1.2.177", (26, 1, 2, 177)),
        ("24.1.4.6 EA", (24, 1, 4, 6)),
        ("", ()),
        (None, ()),
        ("n/a", ()),
    ],
)
def test_parse_version(raw: str | None, expected: tuple[int, ...]) -> None:
    """Dotted versions parse to int tuples; junk parses to an empty tuple."""
    assert parse_version(raw) == expected


def test_parse_version_orders_numerically() -> None:
    """Version parts compare as numbers, not strings."""
    assert parse_version("26.1.10.1") > parse_version("26.1.9.300")


def test_select_latest_package_picks_newest_matching() -> None:
    """Wrong arch, non-installer, non-GA and Ranger-only packages are skipped."""
    packages = [
        _pkg("1", "26.1.2.177"),
        _pkg("2", "26.2.1.50"),
        _pkg("3", "26.3.0.10", arch="ARM64"),
        _pkg("4", "26.4.0.1", ext=".zip"),
        _pkg("5", "26.5.0.1", status="ea"),
        _pkg("6", "26.6.0.1", packageType="Ranger"),
    ]
    chosen = select_latest_package(packages, WINDOWS_AGENT)
    assert chosen is not None
    assert chosen["id"] == "2"


def test_select_latest_package_accepts_agent_and_ranger_bundle() -> None:
    """Real consoles list Windows agents as AgentAndRanger bundles; those are upgrades too."""
    packages = [
        _pkg("old", "26.1.2.177", packageType="AgentAndRanger"),
        _pkg("new", "26.2.3.158", packageType="AgentAndRanger"),
    ]
    chosen = select_latest_package(packages, WINDOWS_AGENT)
    assert chosen is not None
    assert chosen["id"] == "new"


def test_select_latest_package_prefers_msi_for_same_version() -> None:
    """When one version ships as .msi and .exe, the .msi wins."""
    packages = [_pkg("exe", "26.2.1.50", ext=".exe"), _pkg("msi", "26.2.1.50", ext=".msi")]
    chosen = select_latest_package(packages, WINDOWS_AGENT)
    assert chosen is not None
    assert chosen["id"] == "msi"


def test_select_latest_package_accepts_dual_arch_package() -> None:
    """A 32/64 bit package installs on a 64 bit agent."""
    chosen = select_latest_package([_pkg("1", "26.2.1.50", arch="32/64 bit")], WINDOWS_AGENT)
    assert chosen is not None


def test_select_latest_package_unsupported_os() -> None:
    """Linux needs an explicit package, so no automatic choice is made."""
    linux_agent = {**WINDOWS_AGENT, "osType": "linux"}
    assert select_latest_package([_pkg("1", "26.2.1.50")], linux_agent) is None


def test_plan_upgrade_available() -> None:
    """A newer package for an active agent is an available upgrade."""
    plan = plan_upgrade(WINDOWS_AGENT, _pkg("2", "26.2.1.50"))
    assert plan.status == "upgrade_available"
    assert plan.package_id == "2"
    assert plan.current_version == "26.1.2.177"
    assert plan.target_version == "26.2.1.50"


def test_plan_upgrade_already_up_to_date() -> None:
    """Same version means nothing to do."""
    plan = plan_upgrade(WINDOWS_AGENT, _pkg("1", "26.1.2.177"))
    assert plan.status == "already_up_to_date"


def test_plan_upgrade_inactive_agent() -> None:
    """An inactive agent is reported instead of queuing an upgrade it cannot receive."""
    plan = plan_upgrade({**WINDOWS_AGENT, "isActive": False}, _pkg("2", "26.2.1.50"))
    assert plan.status == "agent_inactive"


def test_plan_upgrade_no_package() -> None:
    """No matching package yields no_package and no package ID."""
    plan = plan_upgrade(WINDOWS_AGENT, None)
    assert plan.status == "no_package"
    assert plan.package_id is None


@pytest.mark.parametrize(
    ("activity", "expected"),
    [
        ({"primaryDescription": "Agent 31XZ173 started upgrade to 26.2.1.50"}, True),
        ({"description": "Software update requested by user"}, True),
        ({"primaryDescription": "Agent 31XZ173 policy updated"}, False),
        ({}, False),
    ],
)
def test_is_upgrade_activity(activity: ApiObject, expected: bool) -> None:
    """Only upgrade-related activity rows are kept."""
    assert is_upgrade_activity(activity) is expected
