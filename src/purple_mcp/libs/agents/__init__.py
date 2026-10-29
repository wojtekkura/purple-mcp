"""SentinelOne Management API library for agent lookups, remote upgrades and path exclusions."""

from purple_mcp.libs.agents.client import AgentsClient, ApiObject
from purple_mcp.libs.agents.config import AgentsConfig
from purple_mcp.libs.agents.exceptions import (
    AgentsAPIError,
    AgentsAuthenticationError,
    AgentsClientError,
    AgentsError,
    AgentsNetworkError,
    AgentsTransientError,
)
from purple_mcp.libs.agents.exclusions import (
    MODES,
    ExclusionPlan,
    build_description,
    default_path_type,
    exclusion_summary,
    find_existing,
    validate_exclusion,
)
from purple_mcp.libs.agents.upgrade import (
    UpgradePlan,
    is_upgrade_activity,
    parse_version,
    plan_upgrade,
    select_latest_package,
)

__all__ = [
    "MODES",
    "AgentsAPIError",
    "AgentsAuthenticationError",
    "AgentsClient",
    "AgentsClientError",
    "AgentsConfig",
    "AgentsError",
    "AgentsNetworkError",
    "AgentsTransientError",
    "ApiObject",
    "ExclusionPlan",
    "UpgradePlan",
    "build_description",
    "default_path_type",
    "exclusion_summary",
    "find_existing",
    "is_upgrade_activity",
    "parse_version",
    "plan_upgrade",
    "select_latest_package",
    "validate_exclusion",
]
