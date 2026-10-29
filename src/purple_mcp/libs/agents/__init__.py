"""SentinelOne Management API library for agent lookups and remote agent upgrades."""

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
from purple_mcp.libs.agents.upgrade import (
    UpgradePlan,
    is_upgrade_activity,
    parse_version,
    plan_upgrade,
    select_latest_package,
)

__all__ = [
    "AgentsAPIError",
    "AgentsAuthenticationError",
    "AgentsClient",
    "AgentsClientError",
    "AgentsConfig",
    "AgentsError",
    "AgentsNetworkError",
    "AgentsTransientError",
    "ApiObject",
    "UpgradePlan",
    "is_upgrade_activity",
    "parse_version",
    "plan_upgrade",
    "select_latest_package",
]
