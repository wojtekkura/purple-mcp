"""Pydantic models for the investigation bundle.

These models are deliberately flat and self-describing so that downstream
sub-agents (alerts, inventory, storyline analyzers, etc.) can pick the
section they care about without having to walk a deeply nested tree.
"""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from purple_mcp.libs.alerts.models import Alert, AlertHistoryEvent, AlertNote
from purple_mcp.libs.inventory.models import InventoryItem


class SectionStatus(str, Enum):
    """Per-section fetch status.

    A bundle can be returned even if individual sections fail; sub-agents
    inspect the status to decide whether to use, skip, or retry the data.
    """

    OK = "ok"
    EMPTY = "empty"
    SKIPPED = "skipped"
    FAILED = "failed"


class IncidentSummary(BaseModel):
    """Top-level summary of the incident.

    All fields a sub-agent needs to triage at a glance, without having to
    open `primary_alert`. Anything here is also present in `primary_alert`,
    but flattened and de-aliased for ingestion convenience.
    """

    alert_id: str
    asset_id: str | None = None
    asset_name: str | None = None
    asset_type: str | None = None
    storyline_id: str | None = None
    severity: str | None = None
    status: str | None = None
    name: str | None = None
    detected_at: str | None = None
    classification: str | None = None
    analyst_verdict: str | None = None
    detection_product: str | None = None
    detection_vendor: str | None = None
    time_window_hours: int = Field(
        ...,
        description="Lookback window applied to related-alerts and storyline searches, in hours.",
    )
    time_window_start: str = Field(..., description="ISO-8601 start of the lookback window (UTC).")
    time_window_end: str = Field(..., description="ISO-8601 end of the lookback window (UTC).")


class PrimaryAlertSection(BaseModel):
    """The alert that anchors the investigation."""

    status: SectionStatus
    alert: Alert | None = None
    error: str | None = None


class RelatedAlertsSection(BaseModel):
    """Other alerts on the same endpoint within the lookback window.

    The primary alert is excluded by ID so sub-agents don't double-count it.
    """

    status: SectionStatus
    total_count: int | None = None
    returned_count: int = 0
    truncated: bool = False
    alerts: list[Alert] = Field(default_factory=list)
    error: str | None = None


class AssetInventorySection(BaseModel):
    """Asset inventory record for the endpoint.

    Returns the full `InventoryItem` (which already supports `extra="allow"`
    for vendor-specific fields), so sub-agents have everything available.
    """

    status: SectionStatus
    item: InventoryItem | None = None
    error: str | None = None


class RemediationSection(BaseModel):
    """Remediation actions and analyst notes attached to the primary alert.

    `history_events` is the audit log of what's been done (status changes,
    assignments, mitigation actions, etc.). `notes` is free-text analyst
    commentary. Both can be useful to a remediation sub-agent so we expose
    them together.
    """

    status: SectionStatus
    history_events: list[AlertHistoryEvent] = Field(default_factory=list)
    history_truncated: bool = False
    notes: list[AlertNote] = Field(default_factory=list)
    history_error: str | None = None
    notes_error: str | None = None
    error: str | None = None


class StorylineEvent(BaseModel):
    """A single SDL row from the storyline query, normalized to a dict.

    Storyline schemas vary across console versions; rather than hand-pick
    fields that may not exist, we capture the row as a column→value dict
    so the storyline sub-agent can apply its own selectors.
    """

    model_config = ConfigDict(extra="allow")

    fields: dict[str, JsonValue] = Field(default_factory=dict)


class StorylineSection(BaseModel):
    """SDL events that share the storyline_id of the primary alert."""

    status: SectionStatus
    storyline_id: str | None = None
    query: str | None = None
    columns: list[str] = Field(default_factory=list)
    match_count: int = 0
    returned_count: int = 0
    truncated: bool = False
    partial: bool = False
    warnings: list[str] = Field(default_factory=list)
    events: list[StorylineEvent] = Field(default_factory=list)
    error: str | None = None


class IncidentBundle(BaseModel):
    """Top-level bundle returned by `initiate_investigation`.

    Designed to be passed verbatim to a sub-agent: `summary` has the quick
    triage facts, then each section has its own status + payload + error.
    A sub-agent can dispatch on `summary.severity` and `summary.asset_type`,
    then walk into the section it specializes in.

    Schema version 2 dropped the `storyline` section from the bundle —
    storylines often contain hundreds of thousands of events, so they are
    now fetched on demand via the separate `get_storyline_events` tool
    using `summary.storyline_id`. Sub-agents that need raw EDR events
    should call that tool with appropriate limits/time-window.
    """

    schema_version: Literal["2"] = "2"
    summary: IncidentSummary
    primary_alert: PrimaryAlertSection
    related_alerts: RelatedAlertsSection
    asset_inventory: AssetInventorySection
    remediation: RemediationSection
    warnings: list[str] = Field(
        default_factory=list,
        description="Soft warnings emitted during collection (e.g., missing asset_id "
        "preventing related-alerts/inventory lookups). Hard failures live in "
        "section.error.",
    )
