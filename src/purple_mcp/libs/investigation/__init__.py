"""Investigation orchestration library.

Combines results from the alerts, inventory, and SDL libraries into a single
incident bundle that downstream sub-agents can ingest in one shot.
"""

from purple_mcp.libs.investigation.collector import (
    DEFAULT_RELATED_ALERTS_LIMIT,
    DEFAULT_REMEDIATION_HISTORY_LIMIT,
    DEFAULT_STORYLINE_EVENT_LIMIT,
    DEFAULT_TIME_WINDOW_HOURS,
    InvestigationCollector,
)
from purple_mcp.libs.investigation.config import InvestigationConfig
from purple_mcp.libs.investigation.exceptions import InvestigationError, PrimaryAlertNotFoundError
from purple_mcp.libs.investigation.models import (
    AssetInventorySection,
    IncidentBundle,
    IncidentSummary,
    PrimaryAlertSection,
    RelatedAlertsSection,
    RemediationSection,
    SectionStatus,
    StorylineEvent,
    StorylineSection,
)

__all__ = [
    "DEFAULT_RELATED_ALERTS_LIMIT",
    "DEFAULT_REMEDIATION_HISTORY_LIMIT",
    "DEFAULT_STORYLINE_EVENT_LIMIT",
    "DEFAULT_TIME_WINDOW_HOURS",
    "AssetInventorySection",
    "IncidentBundle",
    "IncidentSummary",
    "InvestigationCollector",
    "InvestigationConfig",
    "InvestigationError",
    "PrimaryAlertNotFoundError",
    "PrimaryAlertSection",
    "RelatedAlertsSection",
    "RemediationSection",
    "SectionStatus",
    "StorylineEvent",
    "StorylineSection",
]
