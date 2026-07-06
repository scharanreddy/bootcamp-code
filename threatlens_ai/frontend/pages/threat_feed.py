from __future__ import annotations

from typing import Any

import streamlit as st

from threatlens_ai.frontend.api_client import APIClientError, ThreatLensAPIClient
from threatlens_ai.frontend.components import render_error, render_kev_table

_FEED_LIMIT_OPTIONS = [20, 50, 100, 200]


def render(client: ThreatLensAPIClient) -> None:
    """Render the Threat Feed page: a searchable, filterable CISA KEV browser."""
    st.title("Threat Feed")
    st.caption("Browse the CISA Known Exploited Vulnerabilities (KEV) catalog.")

    controls_left, controls_right = st.columns([2, 1])
    with controls_left:
        search = st.text_input(
            "Search by CVE, vendor, or product", placeholder="e.g. CVE-2026, Microsoft, Exchange"
        )
    with controls_right:
        limit = st.selectbox("Entries to load", _FEED_LIMIT_OPTIONS, index=1)

    try:
        items = client.get_latest_threats(limit=limit)
    except APIClientError as error:
        render_error(str(error))
        return

    if not items:
        st.info("No CISA KEV data is currently available.")
        return

    filter_left, filter_right = st.columns(2)
    with filter_left:
        severities = sorted({(item.get("severity") or "Unknown").title() for item in items})
        selected_severities = st.multiselect("Filter by severity", severities, default=severities)
    with filter_right:
        ransomware_options = sorted(
            {(item.get("known_ransomware_campaign_use") or "Unknown").title() for item in items}
        )
        selected_ransomware = st.multiselect(
            "Filter by ransomware campaign use", ransomware_options, default=ransomware_options
        )

    filtered = _filter_items(
        items, search=search, severities=selected_severities, ransomware_use=selected_ransomware
    )

    st.caption(f"Showing {len(filtered)} of {len(items)} loaded entries.")
    if not filtered:
        st.info("No entries match the current filters.")
        return

    render_kev_table(filtered, height=560)


def _filter_items(
    items: list[dict[str, Any]],
    *,
    search: str,
    severities: list[str],
    ransomware_use: list[str],
) -> list[dict[str, Any]]:
    query = search.strip().lower()
    results: list[dict[str, Any]] = []
    for item in items:
        severity_label = (item.get("severity") or "Unknown").title()
        if severity_label not in severities:
            continue
        ransomware_label = (item.get("known_ransomware_campaign_use") or "Unknown").title()
        if ransomware_label not in ransomware_use:
            continue
        if query:
            haystack = " ".join(
                str(item.get(field) or "") for field in ("cve", "vendor", "product", "description")
            ).lower()
            if query not in haystack:
                continue
        results.append(item)
    return results
