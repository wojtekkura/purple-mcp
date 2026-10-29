"""Pure decision logic for remote agent upgrades: version parsing and package selection."""

import re
from dataclasses import asdict, dataclass
from typing import Final, Literal

from purple_mcp.libs.agents.client import ApiObject

# Installer types the console can push to an existing agent, in order of preference.
# Linux is left out on purpose: the right .deb/.rpm cannot be inferred from the agent record.
PACKAGE_EXTENSIONS: Final[dict[str, tuple[str, ...]]] = {
    "windows": (".msi", ".exe"),
    "macos": (".pkg",),
}

# Consoles ship Windows/macOS agents as "AgentAndRanger" bundles; "Ranger"-only packages are not agents.
AGENT_PACKAGE_TYPES: Final[frozenset[str]] = frozenset({"Agent", "AgentAndRanger"})

_UPGRADE_ACTIVITY_KEYWORDS: Final[tuple[str, ...]] = (
    "upgrad",
    "software update",
    "agent update",
    "update package",
)

UpgradeStatus = Literal["upgrade_available", "already_up_to_date", "agent_inactive", "no_package"]


def parse_version(version: str | None) -> tuple[int, ...]:
    """Parse a dotted agent version such as ``26.1.2.177`` into a comparable tuple.

    Non-numeric suffixes (e.g. ``24.1.4.6 EA``) are ignored. Unparseable input yields ``()``.
    """
    if not version:
        return ()
    match = re.match(r"\s*(\d+(?:\.\d+)*)", version)
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def _arch_compatible(agent_arch: str | None, package_arch: str | None) -> bool:
    """Return whether a package built for ``package_arch`` can install on ``agent_arch``."""
    if not agent_arch or not package_arch:
        return True
    agent = agent_arch.lower()
    package = package_arch.lower()
    if "arm" in agent:
        return "arm" in package
    if "arm" in package:
        return False
    if "64" in agent:
        return "64" in package
    return "32" in package


def select_latest_package(packages: list[ApiObject], agent: ApiObject) -> ApiObject | None:
    """Pick the newest GA agent package that fits the agent's OS, architecture and installer type."""
    os_type = str(agent.get("osType") or "").lower()
    extensions = PACKAGE_EXTENSIONS.get(os_type)
    if not extensions:
        return None

    candidates = [
        pkg
        for pkg in packages
        if str(pkg.get("osType") or os_type).lower() == os_type
        and str(pkg.get("status") or "ga").lower() == "ga"
        and str(pkg.get("packageType") or "Agent") in AGENT_PACKAGE_TYPES
        and str(pkg.get("fileExtension") or "").lower() in extensions
        and _arch_compatible(agent.get("osArch"), pkg.get("osArch"))
        and parse_version(pkg.get("version"))
    ]
    if not candidates:
        return None

    return max(
        candidates,
        key=lambda pkg: (
            parse_version(pkg.get("version")),
            # Same version shipped as several installers: prefer the earlier extension.
            -extensions.index(str(pkg.get("fileExtension")).lower()),
        ),
    )


@dataclass(frozen=True)
class UpgradePlan:
    """What an upgrade of one agent would do, before anything is triggered."""

    status: UpgradeStatus
    agent_id: str
    computer_name: str | None
    uuid: str | None
    os_type: str | None
    os_arch: str | None
    is_active: bool
    current_version: str | None
    target_version: str | None
    package_id: str | None
    package_file: str | None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable view of the plan."""
        return asdict(self)


def plan_upgrade(agent: ApiObject, package: ApiObject | None) -> UpgradePlan:
    """Decide whether ``agent`` should move to ``package``.

    An inactive agent is reported as such even if a newer package exists, because the
    console can only deliver the upgrade once the agent checks in.
    """
    current = agent.get("agentVersion")
    target = package.get("version") if package else None

    status: UpgradeStatus
    if package is None:
        status = "no_package"
    elif parse_version(target) <= parse_version(current):
        status = "already_up_to_date"
    elif not agent.get("isActive"):
        status = "agent_inactive"
    else:
        status = "upgrade_available"

    return UpgradePlan(
        status=status,
        agent_id=str(agent.get("id")),
        computer_name=agent.get("computerName"),
        uuid=agent.get("uuid"),
        os_type=agent.get("osType"),
        os_arch=agent.get("osArch"),
        is_active=bool(agent.get("isActive")),
        current_version=current,
        target_version=target,
        package_id=str(package["id"]) if package and package.get("id") is not None else None,
        package_file=package.get("fileName") if package else None,
    )


def is_upgrade_activity(activity: ApiObject) -> bool:
    """Return whether a console activity row is about an agent software upgrade."""
    text = " ".join(
        str(activity.get(field) or "")
        for field in ("primaryDescription", "secondaryDescription", "description")
    ).lower()
    return any(keyword in text for keyword in _UPGRADE_ACTIVITY_KEYWORDS)
