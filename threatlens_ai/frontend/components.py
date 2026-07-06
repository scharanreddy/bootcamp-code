from __future__ import annotations

import html
from typing import Any

import pandas as pd
import streamlit as st

from threatlens_ai.frontend.theme import ransomware_badge, severity_badge


def render_error(message: str) -> None:
    """Render a user-facing error message."""
    st.error(f"⚠️ {message}")


_FRAME_COLUMNS = ["CVE", "Vendor", "Product", "Severity", "Ransomware Use", "Date Added", "Description"]


def kev_items_to_frame(items: list[dict[str, Any]]) -> pd.DataFrame:
    """Convert CISA KEV entries into a display-ready DataFrame."""
    if not items:
        return pd.DataFrame(columns=_FRAME_COLUMNS)

    return pd.DataFrame(
        [
            {
                "CVE": item.get("cve"),
                "Vendor": item.get("vendor") or "—",
                "Product": item.get("product") or "—",
                "Severity": (item.get("severity") or "Unknown").title(),
                "Ransomware Use": item.get("known_ransomware_campaign_use") or "Unknown",
                "Date Added": item.get("date_added") or "—",
                "Description": item.get("description") or "",
            }
            for item in items
        ]
    )


def render_kev_table(items: list[dict[str, Any]], *, height: int | None = None) -> None:
    """Render CISA KEV entries as a sortable table."""
    frame = kev_items_to_frame(items)
    st.dataframe(frame, hide_index=True, height=height)


def render_kev_cards(items: list[dict[str, Any]]) -> None:
    """Render CISA KEV entries as compact cards, flagging ransomware-linked CVEs."""
    for item in items:
        is_ransomware_linked = (item.get("known_ransomware_campaign_use") or "").strip().lower() == "known"
        badge = ransomware_badge() if is_ransomware_linked else severity_badge(item.get("severity"))
        cve = html.escape(item.get("cve") or "Unknown CVE")
        vendor = html.escape(item.get("vendor") or "Unknown vendor")
        product = html.escape(item.get("product") or "Unknown product")
        description = html.escape(item.get("description") or "No description available.")
        date_added = html.escape(item.get("date_added") or "Unknown date")

        st.markdown(
            f"""
            <div class="tl-card">
                <div class="tl-card-header">
                    <span class="tl-card-title">{cve}</span>
                    {badge}
                </div>
                <div class="tl-card-subtitle">{vendor} · {product}</div>
                <div class="tl-card-body">{description}</div>
                <div class="tl-card-footer">Added {date_added}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_metric_cards(metrics: list[tuple[str, str, str | None]]) -> None:
    """Render a row of st.metric cards from (label, value, delta) tuples."""
    columns = st.columns(len(metrics))
    for column, (label, value, delta) in zip(columns, metrics):
        column.metric(label, value, delta)


def render_bullets(items: list[str] | None) -> None:
    """Render a list of strings as Markdown bullets, or a placeholder if empty."""
    if not items:
        st.write("—")
        return
    for item in items:
        st.markdown(f"- {item}")
