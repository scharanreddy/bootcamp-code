from __future__ import annotations

import html
from typing import Any

import pandas as pd
import streamlit as st

from threatlens_ai.frontend.theme import ransomware_badge, severity_badge, severity_colors


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


def _dataframe(frame: pd.DataFrame, height: int | None) -> None:
    """Render a DataFrame, passing height only when set (Streamlit rejects height=None)."""
    if height is None:
        st.dataframe(frame, hide_index=True)
    else:
        st.dataframe(frame, hide_index=True, height=height)


def render_kev_table(items: list[dict[str, Any]], *, height: int | None = None) -> None:
    """Render CISA KEV entries as a sortable table."""
    _dataframe(kev_items_to_frame(items), height)


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


_SBOM_COLUMNS = ["Component", "Version", "Supplier", "Type", "Package URL"]


def sbom_components_to_frame(components: list[dict[str, Any]] | None) -> pd.DataFrame:
    """Convert SBOM components into a display-ready DataFrame."""
    if not components:
        return pd.DataFrame(columns=_SBOM_COLUMNS)

    return pd.DataFrame(
        [
            {
                "Component": component.get("software_name") or "—",
                "Version": component.get("version") or "—",
                "Supplier": component.get("supplier") or "—",
                "Type": (component.get("component_type") or "—").title(),
                "Package URL": component.get("package_url") or "—",
            }
            for component in components
        ]
    )


def render_component_table(components: list[dict[str, Any]] | None, *, height: int | None = None) -> None:
    """Render SBOM components as a sortable table."""
    _dataframe(sbom_components_to_frame(components), height)


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


def render_cvss_panel(cvss: dict[str, Any] | None) -> None:
    """Render a CVSS score panel with base score, severity, version, and vector."""
    if not cvss or cvss.get("base_score") is None:
        st.info("No CVSS score is published for this CVE.")
        return

    base_score = cvss.get("base_score")
    severity = cvss.get("severity")
    version = cvss.get("version") or "—"
    vector = cvss.get("vector_string")

    background, _text = severity_colors(severity)
    badge = severity_badge(severity)
    vector_html = (
        f'<div class="tl-cvss-vector">{html.escape(vector)}</div>' if vector else ""
    )
    st.markdown(
        f"""
        <div class="tl-cvss">
            <div class="tl-cvss-score" style="color:{background};">
                <span class="num">{html.escape(str(base_score))}</span>
                <span class="max">/ 10</span>
            </div>
            <div class="tl-cvss-meta">
                <div>{badge} &nbsp; <span style="opacity:0.7;">CVSS v{html.escape(str(version))}</span></div>
                {vector_html}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_timeline(events: list[dict[str, str]]) -> None:
    """Render a chronological vertical timeline from (date, label, description) events."""
    if not events:
        st.write("—")
        return

    items = "".join(
        f"""
        <div class="tl-timeline-item">
            <div class="tl-timeline-date">{html.escape(event.get("date", ""))}</div>
            <div class="tl-timeline-label">{html.escape(event.get("label", ""))}</div>
            <div class="tl-timeline-desc">{html.escape(event.get("description", ""))}</div>
        </div>
        """
        for event in events
    )
    st.markdown(f'<div class="tl-timeline">{items}</div>', unsafe_allow_html=True)


def render_chips(items: list[str] | None, *, icon: str = "") -> None:
    """Render a list of short labels as inline pill "chips", or a placeholder if empty."""
    if not items:
        st.write("—")
        return
    prefix = f"{html.escape(icon)} " if icon else ""
    chips = "".join(
        f'<span class="tl-chip">{prefix}{html.escape(str(item))}</span>' for item in items
    )
    st.markdown(f'<div class="tl-chips">{chips}</div>', unsafe_allow_html=True)


def render_trace_step(icon: str, title: str, detail: str) -> None:
    """Render a single agent-execution trace step (icon + title + detail)."""
    st.markdown(
        f"""
        <div class="tl-trace-item">
            <div class="tl-trace-icon">{html.escape(icon)}</div>
            <div>
                <div class="tl-trace-title">{html.escape(title)}</div>
                <div class="tl-trace-detail">{html.escape(detail)}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
