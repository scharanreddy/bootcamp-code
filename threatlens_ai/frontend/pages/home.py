from __future__ import annotations

from datetime import date, datetime
from typing import Any

import pandas as pd
import streamlit as st

from threatlens_ai.frontend.api_client import APIClientError, ThreatLensAPIClient
from threatlens_ai.frontend.components import render_error, render_kev_cards, render_kev_table, render_metric_cards

_HOME_FEED_LIMIT = 50
_RECENT_WINDOW_DAYS = 7
_TREND_WINDOW_DAYS = 14
_CRITICAL_CARD_COUNT = 5


def render(client: ThreatLensAPIClient) -> None:
    """Render the Home page: latest CISA KEV, recent critical CVEs, and threat statistics."""
    st.title("Threat Intelligence Overview")
    st.caption("A real-time snapshot of known exploited vulnerabilities tracked by CISA.")

    try:
        items = client.get_latest_threats(limit=_HOME_FEED_LIMIT)
    except APIClientError as error:
        render_error(str(error))
        return

    if not items:
        st.info("No CISA KEV data is currently available.")
        return

    _render_statistics(items)
    st.divider()

    left, right = st.columns([1.4, 1], gap="large")
    with left:
        st.subheader("Latest CISA KEV")
        render_kev_table(items[:10], height=420)
    with right:
        st.subheader("Recent Critical CVEs")
        st.caption("Ransomware-linked entries first, backfilled with the most recently added.")
        render_kev_cards(_select_critical(items))


def _render_statistics(items: list[dict[str, Any]]) -> None:
    st.subheader("Threat Statistics")

    ransomware_count = sum(1 for item in items if _is_ransomware_linked(item))
    recent_count = _count_recent(items, days=_RECENT_WINDOW_DAYS)
    unique_vendors = len({item.get("vendor") for item in items if item.get("vendor")})

    render_metric_cards(
        [
            ("Tracked (latest batch)", str(len(items)), None),
            ("Ransomware-Linked", str(ransomware_count), None),
            ("Unique Vendors", str(unique_vendors), None),
            (f"Added in Last {_RECENT_WINDOW_DAYS} Days", str(recent_count), None),
        ]
    )

    trend = _entries_added_by_day(items, days=_TREND_WINDOW_DAYS)
    if trend:
        chart_frame = pd.DataFrame({"Date Added": list(trend.keys()), "New Entries": list(trend.values())})
        st.bar_chart(chart_frame.set_index("Date Added"), height=220)


def _is_ransomware_linked(item: dict[str, Any]) -> bool:
    return (item.get("known_ransomware_campaign_use") or "").strip().lower() == "known"


def _select_critical(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prioritize ransomware-linked entries, backfilled with the most recent entries."""
    ransomware_linked = [item for item in items if _is_ransomware_linked(item)]
    if len(ransomware_linked) >= _CRITICAL_CARD_COUNT:
        return ransomware_linked[:_CRITICAL_CARD_COUNT]

    seen_cves = {item.get("cve") for item in ransomware_linked}
    backfill = [item for item in items if item.get("cve") not in seen_cves]
    return (ransomware_linked + backfill)[:_CRITICAL_CARD_COUNT]


def _count_recent(items: list[dict[str, Any]], *, days: int) -> int:
    threshold = datetime.now().date().toordinal() - days
    count = 0
    for item in items:
        added_at = _parse_date(item.get("date_added"))
        if added_at is not None and added_at.toordinal() >= threshold:
            count += 1
    return count


def _entries_added_by_day(items: list[dict[str, Any]], *, days: int) -> dict[str, int]:
    threshold = datetime.now().date().toordinal() - days
    counts: dict[str, int] = {}
    for item in items:
        added_at = _parse_date(item.get("date_added"))
        if added_at is None or added_at.toordinal() < threshold:
            continue
        key = added_at.isoformat()
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).date()
    except ValueError:
        return None
