"""Live smoke-test for `initiate_investigation` against a real S1 console.

Pulls the console token from the WCM keyring and the base URL from the
existing Claude Desktop config (or env), picks the most recent alert, and
runs the tool end-to-end. Designed to be invoked manually via:

    uv run python scripts/live_test_investigation.py
"""
# ruff: noqa: INP001  # standalone manual smoke-test, not a package member

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

import keyring

from purple_mcp.config import ENV_PREFIX, get_settings
from purple_mcp.libs.alerts import AlertsClient, AlertsConfig, ViewType
from purple_mcp.tools.investigation import initiate_investigation
from purple_mcp.tools.storyline import get_storyline_events

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("live_test")


KEYRING_SERVICE = "purple-mcp"
KEYRING_KEY = "PURPLEMCP_CONSOLE_TOKEN"
DEFAULT_BASE_URL = "https://usea1-008.sentinelone.net"


def _bootstrap_env() -> None:
    """Populate the env vars Settings needs from WCM + a sane default base URL."""
    if not os.environ.get(f"{ENV_PREFIX}CONSOLE_TOKEN"):
        token = keyring.get_password(KEYRING_SERVICE, KEYRING_KEY)
        if not token:
            sys.exit(
                f"No token found in WCM under service={KEYRING_SERVICE!r} "
                f"user={KEYRING_KEY!r}. Run `cmdkey` or `purple-mcp store-token` first."
            )
        os.environ[f"{ENV_PREFIX}CONSOLE_TOKEN"] = token
    if not os.environ.get(f"{ENV_PREFIX}CONSOLE_BASE_URL"):
        os.environ[f"{ENV_PREFIX}CONSOLE_BASE_URL"] = DEFAULT_BASE_URL
    # Use development env so SDL TLS validation is permissive on a dev console
    os.environ.setdefault(f"{ENV_PREFIX}ENV", "development")


async def _pick_alert() -> tuple[str, str | None, str | None]:
    """Pick the most recent alert that has BOTH an asset_id and a storyline_id.

    Falls back to the first alert with at least an asset_id, and finally to
    just the first alert returned. We need both to exercise every section.
    """
    settings = get_settings()
    client = AlertsClient(
        AlertsConfig(
            graphql_url=settings.alerts_graphql_url,
            auth_token=settings.graphql_service_token,
        )
    )
    page = await client.list_alerts(first=50, view_type=ViewType.ALL)

    if not page.edges:
        sys.exit("No alerts returned from this console. Cannot run live test.")

    # Pass 1: alert with both asset and storyline
    for edge in page.edges:
        a = edge.node
        if a.asset and a.asset.id and a.storyline_id:
            return a.id, a.asset.id, a.storyline_id

    # Pass 2: alert with at least asset
    for edge in page.edges:
        a = edge.node
        if a.asset and a.asset.id:
            return a.id, a.asset.id, a.storyline_id

    a = page.edges[0].node
    return a.id, a.asset.id if a.asset else None, a.storyline_id


def _summarize(bundle_json: str) -> None:
    """Print a one-page summary of the bundle for human review."""
    bundle = json.loads(bundle_json)
    summary = bundle["summary"]
    print()
    print("=" * 78)
    print("INVESTIGATION BUNDLE")
    print("=" * 78)
    print(f"  alert_id:     {summary['alert_id']}")
    print(f"  asset_id:     {summary.get('asset_id')}")
    print(f"  asset_name:   {summary.get('asset_name')}")
    print(f"  storyline_id: {summary.get('storyline_id')}")
    print(f"  severity:     {summary.get('severity')}")
    print(f"  status:       {summary.get('status')}")
    print(f"  detected_at:  {summary.get('detected_at')}")
    print(
        f"  window:       {summary['time_window_hours']}h "
        f"({summary['time_window_start']} -> {summary['time_window_end']})"
    )
    print()
    print(f"  primary_alert  : {bundle['primary_alert']['status']}")

    related = bundle["related_alerts"]
    print(
        f"  related_alerts : {related['status']} "
        f"(returned={related.get('returned_count', 0)}, "
        f"total={related.get('total_count')}, "
        f"truncated={related.get('truncated', False)})"
    )
    if related.get("error"):
        print(f"     ERROR: {related['error']}")

    inventory = bundle["asset_inventory"]
    inv_msg = inventory["status"]
    if inventory.get("item"):
        os_field = inventory["item"].get("os") or inventory["item"].get("osFamily")
        inv_msg += f" (name={inventory['item'].get('name')}, os={os_field})"
    print(f"  asset_inventory: {inv_msg}")
    if inventory.get("error"):
        print(f"     ERROR: {inventory['error']}")

    rem = bundle["remediation"]
    print(
        f"  remediation    : {rem['status']} "
        f"(history={len(rem.get('history_events', []))}, "
        f"notes={len(rem.get('notes', []))})"
    )
    if rem.get("error"):
        print(f"     ERROR: {rem['error']}")

    if bundle.get("warnings"):
        print()
        print("  warnings:")
        for w in bundle["warnings"]:
            print(f"     - {w}")
    print("=" * 78)
    print(f"\nBundle JSON length: {len(bundle_json)} bytes")


def _summarize_storyline(section_json: str) -> None:
    """Print a one-line summary of the storyline section (separate tool)."""
    section = json.loads(section_json)
    print()
    print("=" * 78)
    print("STORYLINE EVENTS  (separate tool: get_storyline_events)")
    print("=" * 78)
    print(f"  status        : {section['status']}")
    print(f"  storyline_id  : {section.get('storyline_id')}")
    print(
        f"  returned/match: {section.get('returned_count', 0)} / "
        f"{section.get('match_count', 0)}"
    )
    print(f"  truncated     : {section.get('truncated', False)}")
    if section.get("error"):
        print(f"  ERROR         : {section['error']}")
    if section.get("query"):
        print(f"  query         : {section['query']}")
    print("=" * 78)
    print(f"\nStoryline JSON length: {len(section_json)} bytes")


async def main() -> None:
    """Entry point: bootstrap env, pick or use a forced alert, run, summarize."""
    _bootstrap_env()

    # Allow the caller to force a specific alert id; otherwise auto-pick.
    forced = os.environ.get("PURPLEMCP_LIVE_TEST_ALERT_ID")
    if forced:
        alert_id = forced
        logger.info("Using forced alert id %s", alert_id)
    else:
        logger.info("Picking a candidate alert...")
        alert_id, asset_id, storyline_id = await _pick_alert()
        logger.info(
            "Selected alert: id=%s asset_id=%s storyline_id=%s",
            alert_id,
            asset_id,
            storyline_id,
        )

    logger.info("Running initiate_investigation(%s)...", alert_id)
    bundle_json = await initiate_investigation(alert_id)

    # Persist the bundle BEFORE printing so any print/encoding error
    # doesn't lose the result. Users can override the path via
    # PURPLEMCP_LIVE_TEST_OUT.
    out_path = Path(os.environ.get("PURPLEMCP_LIVE_TEST_OUT", "bundle.json"))
    with out_path.open("w", encoding="utf-8") as f:
        f.write(bundle_json)
    logger.info("Wrote full bundle to %s", out_path)

    _summarize(bundle_json)

    # Follow-up: call the separate get_storyline_events tool with the
    # storyline_id surfaced in the bundle summary. Skip cleanly if the
    # bundle didn't carry one (e.g. STAR alerts on cloud telemetry).
    bundle = json.loads(bundle_json)
    storyline_id = bundle["summary"].get("storyline_id")
    if not storyline_id:
        logger.info("Bundle has no storyline_id; skipping storyline fetch.")
        return

    logger.info("Running get_storyline_events(%s)...", storyline_id)
    storyline_json = await get_storyline_events(storyline_id, limit=200)

    storyline_path = out_path.with_name(f"{out_path.stem}_storyline.json")
    with storyline_path.open("w", encoding="utf-8") as f:
        f.write(storyline_json)
    logger.info("Wrote storyline to %s", storyline_path)

    _summarize_storyline(storyline_json)


if __name__ == "__main__":
    asyncio.run(main())
