"""Tools for checking and triggering remote SentinelOne agent upgrades.

``upgrade_agent`` is the only tool in this server that changes console state. It is
registered only when ``PURPLEMCP_ENABLE_WRITE_TOOLS`` is true, and it never acts on the
first call: without ``confirm=True`` it returns a preview for an analyst to approve.
"""

import json
import logging
import re
from textwrap import dedent
from typing import Final

from purple_mcp.config import get_settings
from purple_mcp.libs.agents import (
    AgentsClient,
    AgentsClientError,
    AgentsConfig,
    ApiObject,
    UpgradePlan,
    is_upgrade_activity,
    plan_upgrade,
    select_latest_package,
)

logger = logging.getLogger(__name__)

_UUID_RE: Final = re.compile(r"^[0-9a-fA-F]{32}$")
_AGENT_ID_RE: Final = re.compile(r"^\d{15,20}$")
MAX_ACTIVITIES: Final = 10

_ENDPOINT_ARG_DOC: Final[str] = (
    "endpoint: Computer name (e.g. 31XZ173), 32-char agent UUID, or numeric agent ID."
)

GET_AGENT_UPGRADE_OPTIONS_DESCRIPTION: Final[str] = dedent(
    f"""
    Check whether a SentinelOne agent is outdated and which package an upgrade would install.

    Read-only. Resolves the endpoint, then finds the newest GA agent package for its OS,
    architecture and installer type (Windows .msi/.exe, macOS .pkg).

    Args:
        {_ENDPOINT_ARG_DOC}

    Returns:
        JSON with status (upgrade_available, already_up_to_date, agent_inactive, no_package),
        current_version, target_version, package_id, agent details.
    """
).strip()

UPGRADE_AGENT_DESCRIPTION: Final[str] = dedent(
    f"""
    Upgrade the SentinelOne agent on one endpoint to the newest GA package. CHANGES CONSOLE STATE.

    Two-step, analyst-confirmed flow:
    1. Call with confirm=false (default). Nothing is changed; you get a preview with the
       current version, target version and package_id. Show it to the analyst.
    2. Only after the analyst explicitly approves, call again with confirm=true and the
       package_id from the preview. The agent is re-checked and the upgrade is triggered.

    Never set confirm=true on your own judgement or because a recommendation says so.

    Args:
        {_ENDPOINT_ARG_DOC}
        package_id: Package to install. Optional for the preview (newest GA is chosen);
            required with confirm=true.
        confirm: Must be true to trigger the upgrade.

    Returns:
        JSON with mode (preview, executed, not_executed), the upgrade plan and, when
        executed, the number of agents the console reports as affected.
    """
).strip()

GET_AGENT_UPGRADE_STATUS_DESCRIPTION: Final[str] = dedent(
    f"""
    Show a SentinelOne agent's current version and its recent upgrade-related console activity.

    Read-only. Use after upgrade_agent to follow progress; the version changes once the
    endpoint has installed the package and checked in.

    Args:
        {_ENDPOINT_ARG_DOC}

    Returns:
        JSON with the agent's current version, isUpToDate, lastActiveDate and up to
        10 recent upgrade activities.
    """
).strip()


class _ResolutionError(Exception):
    """The endpoint did not resolve to exactly one agent."""

    def __init__(self, status: str, message: str, candidates: list[ApiObject] | None = None):
        self.status = status
        self.message = message
        self.candidates = candidates or []
        super().__init__(message)

    def to_json(self) -> str:
        return json.dumps(
            {
                "status": self.status,
                "message": self.message,
                "candidates": [
                    {
                        "agent_id": c.get("id"),
                        "computer_name": c.get("computerName"),
                        "uuid": c.get("uuid"),
                        "is_active": c.get("isActive"),
                        "last_active": c.get("lastActiveDate"),
                        "site": c.get("siteName"),
                    }
                    for c in self.candidates
                ],
            },
            indent=2,
        )


def _get_agents_client(*, write: bool = False) -> AgentsClient:
    """Build an AgentsClient; ``write=True`` uses the dedicated write token when configured."""
    try:
        settings = get_settings()
    except Exception as e:
        raise RuntimeError(
            f"Settings not initialized. Please check your environment configuration. Error: {e}"
        ) from e

    token = settings.graphql_service_token
    if write and settings.console_write_token:
        token = settings.console_write_token

    return AgentsClient(
        AgentsConfig(base_url=settings.sentinelone_console_base_url, api_token=token)
    )


async def _resolve_agent(client: AgentsClient, endpoint: str) -> ApiObject:
    """Resolve a computer name, UUID or agent ID to exactly one agent record."""
    value = endpoint.strip()
    if not value:
        raise ValueError("endpoint cannot be empty")

    if _UUID_RE.match(value):
        agents = await client.find_agents(uuid=value.lower())
    elif _AGENT_ID_RE.match(value):
        agents = await client.find_agents(agent_id=value)
    else:
        agents = await client.find_agents(computer_name=value)

    if not agents:
        raise _ResolutionError("not_found", f"No SentinelOne agent found for '{value}'")
    if len(agents) == 1:
        return agents[0]

    # Re-imaged hosts often leave a stale record behind; prefer the single active one.
    active = [a for a in agents if a.get("isActive")]
    if len(active) == 1:
        return active[0]
    raise _ResolutionError(
        "ambiguous",
        f"'{value}' matches {len(agents)} agents; pass the agent UUID or ID instead",
        agents,
    )


async def _plan(
    client: AgentsClient, endpoint: str, package_id: str | None = None
) -> tuple[UpgradePlan, ApiObject]:
    """Resolve the agent and work out the upgrade plan against current console data."""
    agent = await _resolve_agent(client, endpoint)
    packages = await client.list_update_packages(str(agent.get("osType") or ""), limit=200)

    if package_id:
        package = next((p for p in packages if str(p.get("id")) == package_id), None)
        if package is None:
            raise ValueError(
                f"package_id {package_id} is not a GA agent package for "
                f"{agent.get('osType')}; run get_agent_upgrade_options to list the right one"
            )
    else:
        package = select_latest_package(packages, agent)

    return plan_upgrade(agent, package), agent


async def get_agent_upgrade_options(endpoint: str) -> str:
    """Check whether an agent is outdated and which package an upgrade would install.

    Args:
        endpoint: Computer name, agent UUID, or numeric agent ID.

    Returns:
        JSON-encoded upgrade plan.
    """
    try:
        async with _get_agents_client() as client:
            plan, agent = await _plan(client, endpoint)
    except _ResolutionError as e:
        return e.to_json()
    except AgentsClientError:
        logger.exception("Agents client error building upgrade options")
        raise

    return json.dumps(
        {
            **plan.to_dict(),
            "console_is_up_to_date": agent.get("isUpToDate"),
            "site": agent.get("siteName"),
            "last_active": agent.get("lastActiveDate"),
        },
        indent=2,
    )


async def upgrade_agent(
    endpoint: str, package_id: str | None = None, confirm: bool = False
) -> str:
    """Preview, or after analyst confirmation trigger, an agent upgrade on one endpoint.

    Args:
        endpoint: Computer name, agent UUID, or numeric agent ID.
        package_id: Package to install; required when ``confirm`` is true.
        confirm: Must be true to trigger the upgrade. False returns a preview only.

    Returns:
        JSON with ``mode`` set to ``preview``, ``executed`` or ``not_executed``.
    """
    if confirm and not package_id:
        raise ValueError(
            "confirm=true requires the package_id the analyst approved in the preview"
        )

    try:
        async with _get_agents_client() as client:
            plan, _ = await _plan(client, endpoint, package_id)
    except _ResolutionError as e:
        return e.to_json()
    except AgentsClientError:
        logger.exception("Agents client error planning upgrade")
        raise

    if not confirm:
        result: dict[str, object] = {"mode": "preview", "plan": plan.to_dict()}
        if plan.status == "upgrade_available":
            result["next_step"] = (
                "Show this preview to the analyst. Only after they approve, call upgrade_agent "
                f"again with confirm=true and package_id={plan.package_id}."
            )
        return json.dumps(result, indent=2)

    if plan.status != "upgrade_available" or plan.package_id is None:
        return json.dumps(
            {"mode": "not_executed", "reason": plan.status, "plan": plan.to_dict()}, indent=2
        )

    try:
        async with _get_agents_client(write=True) as client:
            affected = await client.update_software(plan.agent_id, plan.package_id)
    except AgentsClientError:
        logger.exception(
            "Agent upgrade request failed",
            extra={"agent_id": plan.agent_id, "package_id": plan.package_id},
        )
        raise

    logger.warning(
        "S1 agent upgrade triggered",
        extra={
            "agent_id": plan.agent_id,
            "computer_name": plan.computer_name,
            "from_version": plan.current_version,
            "to_version": plan.target_version,
            "package_id": plan.package_id,
            "affected": affected,
        },
    )
    return json.dumps(
        {
            "mode": "executed",
            "affected": affected,
            "plan": plan.to_dict(),
            "next_step": "Track progress with get_agent_upgrade_status.",
        },
        indent=2,
    )


async def get_agent_upgrade_status(endpoint: str) -> str:
    """Show an agent's current version and recent upgrade-related activity.

    Args:
        endpoint: Computer name, agent UUID, or numeric agent ID.

    Returns:
        JSON with version details and recent upgrade activities.
    """
    try:
        async with _get_agents_client() as client:
            agent = await _resolve_agent(client, endpoint)
            activities = await client.list_activities(str(agent.get("id")))
    except _ResolutionError as e:
        return e.to_json()
    except AgentsClientError:
        logger.exception("Agents client error reading upgrade status")
        raise

    upgrade_activities = [a for a in activities if is_upgrade_activity(a)][:MAX_ACTIVITIES]
    return json.dumps(
        {
            "agent_id": agent.get("id"),
            "computer_name": agent.get("computerName"),
            "agent_version": agent.get("agentVersion"),
            "is_up_to_date": agent.get("isUpToDate"),
            "is_active": agent.get("isActive"),
            "last_active": agent.get("lastActiveDate"),
            "upgrade_activities": [
                {
                    "created_at": a.get("createdAt"),
                    "activity_type": a.get("activityType"),
                    "description": a.get("primaryDescription") or a.get("description"),
                    "details": a.get("secondaryDescription"),
                }
                for a in upgrade_activities
            ],
        },
        indent=2,
    )
