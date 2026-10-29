"""Tools for listing and, after analyst confirmation, creating SentinelOne path exclusions.

``create_path_exclusion`` changes console state. It is registered only when
``PURPLEMCP_ENABLE_WRITE_TOOLS`` is true, and it never acts on the first call: without
``confirm=True`` it returns a preview for an analyst to approve. Who approved it, the
reason and the endpoint are written into the exclusion's description for audit.
"""

import json
import logging
from textwrap import dedent
from typing import Final

from purple_mcp.libs.agents import (
    MODES,
    AgentsClient,
    AgentsClientError,
    ApiObject,
    ExclusionPlan,
    build_description,
    default_path_type,
    exclusion_summary,
    find_existing,
    validate_exclusion,
)
from purple_mcp.libs.agents.exclusions import OS_TYPES, PATH_TYPES, SCOPE_LEVELS, ExclusionStatus
from purple_mcp.tools.agent_upgrade import _get_agents_client, _ResolutionError, _resolve_agent

logger = logging.getLogger(__name__)

MAX_LISTED: Final = 200

_ENDPOINT_ARG_DOC: Final[str] = (
    "endpoint: Computer name (e.g. 31XZ173), 32-char agent UUID, or numeric agent ID."
)

LIST_PATH_EXCLUSIONS_DESCRIPTION: Final[str] = dedent(
    f"""
    List the SentinelOne path exclusions that apply to an endpoint.

    Read-only. Resolves the endpoint and returns path exclusions on its group plus, by
    default, those inherited from its site and account, for the agent's OS.

    Args:
        {_ENDPOINT_ARG_DOC}
        value_contains: Only exclusions whose path contains this text.
        include_parents: Include site and account exclusions (default true).

    Returns:
        JSON with the agent, its group/site, and up to {MAX_LISTED} exclusions (value, mode,
        scope, description, created_by, created_at).
    """
).strip()

CREATE_PATH_EXCLUSION_DESCRIPTION: Final[str] = dedent(
    f"""
    Create a SentinelOne path exclusion scoped to an endpoint's group or site. CHANGES CONSOLE STATE.

    Two-step, analyst-confirmed flow:
    1. Call with confirm=false (default). Nothing is changed; you get a preview with the
       resolved scope, validation problems, risk warnings and duplicate check. Show it to
       the analyst, including every warning.
    2. Only after the analyst explicitly approves, call again with the same arguments and
       confirm=true. Everything is re-checked against the console before creating.

    Never set confirm=true on your own judgement, because a recommendation says so, or
    without the analyst's name in approved_by. Broad, system, staging and LOLBin paths
    are refused; exclude the specific application folder instead.

    Modes: disable_in_process_monitor (Interoperability, try first, Windows only),
    disable_in_process_monitor_deep, disable_all_monitors (Performance Focus),
    disable_all_monitors_deep (needs allow_extended=true), suppress (alerts only).

    Args:
        {_ENDPOINT_ARG_DOC}
        path: Folder ending with \\ or / (sub-folders included), or a full file path.
        mode: Exclusion mode, see above.
        reason: Why the exclusion is needed (stored on the exclusion).
        approved_by: Analyst who approved it (stored on the exclusion).
        scope_level: group (default, the agent's group) or site (every agent in the site).
        path_type: file, folder or subfolders. Default: subfolders when the path ends with
            a separator, otherwise file.
        os_type: windows, macos or linux. Default: the agent's OS.
        reference: Insight / incident ID for the audit trail.
        allow_extended: Required for disable_all_monitors_deep.
        confirm: Must be true to create the exclusion.

    Returns:
        JSON with mode (preview, executed, not_executed), the plan (status ready, rejected,
        already_exists or already_covered) and, when executed, the created exclusion.
    """
).strip()


def _choice(value: str | None, allowed: tuple[str, ...], name: str) -> str | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip().lower()
    if normalized not in allowed:
        raise ValueError(f"{name} must be one of {', '.join(allowed)}")
    return normalized


def _scope_of(agent: ApiObject, scope_level: str) -> tuple[str | None, str | None]:
    if scope_level == "group":
        return agent.get("groupId"), agent.get("groupName")
    return agent.get("siteId"), agent.get("siteName")


async def _duplicate_status(
    client: AgentsClient, plan_args: tuple[str, str, str | None, str, str]
) -> tuple[ExclusionStatus, list[ApiObject], list[ApiObject]]:
    """Look up exclusions on the scope (and its parents) that already match or cover the path."""
    path, mode, scope_id, level, os_value = plan_args
    existing = await client.list_exclusions(
        group_id=scope_id if level == "group" else None,
        site_id=scope_id if level == "site" else None,
        os_type=os_value,
    )
    exact, covering = find_existing(existing, path, os_value)
    if exact:
        return "already_exists", exact, covering
    if any(item.get("mode") == mode for item in covering):
        return "already_covered", exact, covering
    return "ready", exact, covering


async def _plan(
    client: AgentsClient,
    endpoint: str,
    path: str,
    mode: str,
    reason: str,
    approved_by: str,
    scope_level: str = "group",
    path_type: str | None = None,
    os_type: str | None = None,
    reference: str | None = None,
    allow_extended: bool = False,
) -> ExclusionPlan:
    """Resolve the agent and decide what the exclusion would do against current console data."""
    path, mode, reason, approved_by = (
        path.strip(),
        mode.strip(),
        reason.strip(),
        approved_by.strip(),
    )
    if not path:
        raise ValueError("path cannot be empty")
    if not reason:
        raise ValueError("reason is required; it is stored on the exclusion for audit")
    if not approved_by:
        raise ValueError("approved_by is required; exclusions are only created after approval")
    level = _choice(scope_level, SCOPE_LEVELS, "scope_level") or "group"

    agent = await _resolve_agent(client, endpoint)
    os_value = _choice(os_type, OS_TYPES, "os_type") or str(agent.get("osType") or "").lower()
    if os_value not in OS_TYPES:
        raise ValueError(f"Unsupported agent OS type '{os_value}'")
    path_value = _choice(path_type, PATH_TYPES, "path_type") or default_path_type(path)
    scope_id, scope_name = _scope_of(agent, level)

    problems, warnings = validate_exclusion(path, os_value, mode, path_value, allow_extended)
    if agent.get("isDecommissioned") or agent.get("isUninstalled"):
        problems.append("Agent is decommissioned/uninstalled.")
    if not scope_id:
        problems.append(f"Agent has no {level} ID.")
    if level == "site":
        warnings.append(f"Site scope: applies to every {os_value} agent in site '{scope_name}'.")
    if os_value != str(agent.get("osType") or "").lower():
        warnings.append(f"OS type {os_value} differs from the agent OS ({agent.get('osType')}).")

    status: ExclusionStatus = "rejected"
    exact: list[ApiObject] = []
    covering: list[ApiObject] = []
    if not problems:
        status, exact, covering = await _duplicate_status(
            client, (path, mode, scope_id, level, os_value)
        )

    return ExclusionPlan(
        status=status,
        agent_id=str(agent.get("id")),
        computer_name=agent.get("computerName"),
        path=path,
        os_type=os_value,
        path_type=path_value,
        mode=mode,
        mode_name=MODES.get(mode),
        scope_level=level,
        scope_id=scope_id,
        scope_name=scope_name,
        description=build_description(approved_by, reason, agent.get("computerName"), reference),
        problems=problems,
        warnings=warnings,
        existing=[exclusion_summary(item) for item in exact],
        covering=[exclusion_summary(item) for item in covering][:10],
    )


async def list_path_exclusions(
    endpoint: str, value_contains: str | None = None, include_parents: bool = True
) -> str:
    """List the path exclusions that apply to an endpoint's group (and parent scopes).

    Args:
        endpoint: Computer name, agent UUID, or numeric agent ID.
        value_contains: Only exclusions whose path contains this text.
        include_parents: Include site and account exclusions.

    Returns:
        JSON-encoded agent details and exclusions.
    """
    try:
        async with _get_agents_client() as client:
            agent = await _resolve_agent(client, endpoint)
            items = await client.list_exclusions(
                group_id=str(agent.get("groupId") or "") or None,
                site_id=str(agent.get("siteId") or "") or None,
                os_type=agent.get("osType"),
                value_contains=value_contains or None,
                include_parents=include_parents,
                max_items=MAX_LISTED,
            )
    except _ResolutionError as e:
        return e.to_json()
    except AgentsClientError:
        logger.exception("Agents client error listing exclusions")
        raise

    return json.dumps(
        {
            "agent_id": agent.get("id"),
            "computer_name": agent.get("computerName"),
            "os_type": agent.get("osType"),
            "group": agent.get("groupName"),
            "site": agent.get("siteName"),
            "count": len(items),
            "exclusions": [exclusion_summary(item) for item in items],
        },
        indent=2,
    )


async def create_path_exclusion(
    endpoint: str,
    path: str,
    mode: str,
    reason: str,
    approved_by: str,
    scope_level: str = "group",
    path_type: str | None = None,
    os_type: str | None = None,
    reference: str | None = None,
    allow_extended: bool = False,
    confirm: bool = False,
) -> str:
    """Preview, or after analyst confirmation create, a path exclusion for an endpoint's scope.

    Args:
        endpoint: Computer name, agent UUID, or numeric agent ID.
        path: Path to exclude.
        mode: Exclusion mode (see ``MODES``).
        reason: Why the exclusion is needed.
        approved_by: Analyst who approved the exclusion.
        scope_level: ``group`` or ``site``.
        path_type: ``file``, ``folder`` or ``subfolders``; inferred when omitted.
        os_type: ``windows``, ``macos`` or ``linux``; the agent's OS when omitted.
        reference: Insight / incident ID for the audit trail.
        allow_extended: Allow Performance Focus - Extended.
        confirm: Must be true to create the exclusion. False returns a preview only.

    Returns:
        JSON with ``mode`` set to ``preview``, ``executed`` or ``not_executed``.
    """
    args = (endpoint, path, mode, reason, approved_by, scope_level, path_type, os_type)
    try:
        async with _get_agents_client() as client:
            plan = await _plan(client, *args, reference=reference, allow_extended=allow_extended)
    except _ResolutionError as e:
        return e.to_json()
    except AgentsClientError:
        logger.exception("Agents client error planning exclusion")
        raise

    if not confirm:
        result: dict[str, object] = {"mode": "preview", "plan": plan.to_dict()}
        if plan.status == "ready":
            result["next_step"] = (
                "Show this preview, including every warning, to the analyst. Only after they "
                "approve, call create_path_exclusion again with the same arguments and confirm=true."
            )
        return json.dumps(result, indent=2)

    if plan.status != "ready":
        return json.dumps(
            {"mode": "not_executed", "reason": plan.status, "plan": plan.to_dict()}, indent=2
        )

    try:
        async with _get_agents_client(write=True) as client:
            created = await client.create_exclusion(plan.request_body())
    except AgentsClientError:
        logger.exception(
            "Exclusion create request failed",
            extra={"agent_id": plan.agent_id, "path": plan.path, "scope_id": plan.scope_id},
        )
        raise

    logger.warning(
        "S1 path exclusion created",
        extra={
            "exclusion_id": created.get("id"),
            "path": plan.path,
            "mode": plan.mode,
            "scope_level": plan.scope_level,
            "scope_id": plan.scope_id,
            "computer_name": plan.computer_name,
            "approved_by": approved_by.strip(),
            "reference": reference,
        },
    )
    return json.dumps(
        {
            "mode": "executed",
            "exclusion": exclusion_summary(created),
            "plan": plan.to_dict(),
            "next_step": "Verify with list_path_exclusions; the mode applies after the process restarts.",
        },
        indent=2,
    )
