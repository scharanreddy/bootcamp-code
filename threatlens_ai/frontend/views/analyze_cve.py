from __future__ import annotations

import re
from typing import Any

import streamlit as st

from threatlens_ai.frontend import data
from threatlens_ai.frontend.api_client import APIClientError, ThreatLensAPIClient
from threatlens_ai.frontend.components import (
    render_bullets,
    render_cvss_panel,
    render_error,
    render_metric_cards,
    render_timeline,
    render_trace_step,
)
from threatlens_ai.frontend.theme import severity_badge

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# (source key in merged intelligence, human label) for building the threat timeline.
_TIMELINE_SOURCES: list[tuple[str, str, str]] = [
    ("published_date", "Published to NVD", "The vulnerability record was published by the NVD."),
    ("last_modified_date", "Last modified in NVD", "The NVD record was most recently updated."),
]


def render(client: ThreatLensAPIClient) -> None:
    """Render the Analyze CVE page: run the Threat Intelligence Agent for one CVE."""
    st.title("🔍 Analyze CVE")
    st.caption("Run the Threat Intelligence Agent against merged CISA KEV and NVD data.")

    with st.form("analyze_cve_form"):
        cve = st.text_input("CVE Identifier", placeholder="CVE-2026-1234")
        submitted = st.form_submit_button("Analyze", type="primary")

    if not submitted:
        return

    cve = cve.strip().upper()
    if not _CVE_PATTERN.fullmatch(cve):
        render_error("Enter a CVE using the format CVE-YYYY-NNNN.")
        return

    result = _run_agent(client, cve)
    if result is None:
        return

    _render_result(result)


def _run_agent(client: ThreatLensAPIClient, cve: str) -> dict[str, Any] | None:
    """Invoke the backend while surfacing the agent's pipeline as live progress."""
    with st.status(f"Running Threat Intelligence Agent on {cve}…", expanded=True) as status:
        st.write("📥 Querying the CISA KEV catalog…")
        st.write("📥 Enriching with NVD vulnerability data…")
        st.write("🧠 Merging sources and generating the report…")
        try:
            result = data.analyze_cve(client, cve)
        except APIClientError as error:
            status.update(label=f"Analysis failed for {cve}", state="error")
            render_error(str(error))
            return None
        status.update(label=f"Analysis complete for {cve}", state="complete", expanded=False)
    return result


def _render_result(result: dict[str, Any]) -> None:
    intel = result["threat_intelligence"]
    merged = intel.get("merged_intelligence") or {}
    cvss = merged.get("cvss") or {}

    header_col, badge_col = st.columns([3, 1])
    with header_col:
        st.subheader(intel["cve"])
        vendor_product = " · ".join(
            part for part in (merged.get("vendor"), merged.get("product")) if part
        )
        if vendor_product:
            st.caption(vendor_product)
    with badge_col:
        st.markdown(severity_badge(merged.get("severity")), unsafe_allow_html=True)

    render_metric_cards(
        [
            ("CVSS Score", _as_text(cvss.get("base_score")), None),
            ("Known Exploited", "Yes" if merged.get("is_known_exploited") else "No", None),
            ("Model", intel.get("model") or "—", None),
            ("Execution Time", f"{result.get('execution_time_seconds', 0):.2f}s", None),
        ]
    )

    _render_execution_trace(result, merged)

    st.markdown("#### Executive Summary")
    st.write(intel.get("executive_summary") or "—")

    st.markdown("#### Technical Summary")
    st.write(intel.get("technical_summary") or "—")

    col_cvss, col_timeline = st.columns(2)
    with col_cvss:
        st.markdown("#### CVSS")
        render_cvss_panel(cvss)
    with col_timeline:
        st.markdown("#### Threat Timeline")
        render_timeline(build_timeline_events(merged))

    col_impact, col_scenario = st.columns(2)
    with col_impact:
        st.markdown("#### Business Impact")
        st.write(intel.get("business_impact") or "—")
    with col_scenario:
        st.markdown("#### Likely Attack Scenario")
        st.write(intel.get("likely_attack_scenario") or "—")

    st.markdown("#### Recommendations")
    render_bullets(intel.get("immediate_recommendations"))

    with st.expander("Raw merged intelligence (CISA KEV + NVD)"):
        st.json(merged)


def _render_execution_trace(result: dict[str, Any], merged: dict[str, Any]) -> None:
    """Show a verified, per-step trace of what the Threat Intelligence Agent did."""
    with st.expander("Agent execution trace", expanded=False):
        cisa = merged.get("cisa_kev") or {}
        if merged.get("is_known_exploited"):
            date_added = cisa.get("date_added")
            cisa_detail = "Listed as a Known Exploited Vulnerability"
            if date_added:
                cisa_detail += f" (added {date_added})"
        else:
            cisa_detail = "Not present in the CISA KEV catalog"
        render_trace_step("✅", "CISA KEV lookup", cisa_detail)

        nvd = merged.get("nvd") or {}
        cvss = merged.get("cvss") or {}
        references = nvd.get("references") or []
        products = nvd.get("affected_products") or []
        if cvss.get("base_score") is not None:
            nvd_detail = (
                f"CVSS v{cvss.get('version', '?')} {cvss.get('base_score')} · "
                f"{len(references)} references · {len(products)} affected products"
            )
        else:
            nvd_detail = f"{len(references)} references · {len(products)} affected products"
        render_trace_step("✅", "NVD enrichment", nvd_detail)

        render_trace_step("✅", "Intelligence merge", "Consolidated CISA KEV and NVD sources")

        model = result["threat_intelligence"].get("model") or "the configured model"
        exec_time = result.get("execution_time_seconds", 0)
        render_trace_step(
            "✅", "AI report generation", f"Generated by {model} in {exec_time:.2f}s"
        )


def build_timeline_events(merged: dict[str, Any]) -> list[dict[str, str]]:
    """Build a chronologically sorted list of timeline events from merged intelligence.

    Pure function (no Streamlit) so it can be unit tested. Events with no usable
    date are dropped; remaining events are sorted oldest-first by date string.
    """
    events: list[dict[str, str]] = []

    for key, label, description in _TIMELINE_SOURCES:
        formatted = _format_date(merged.get(key))
        if formatted:
            events.append({"date": formatted, "label": label, "description": description})

    cisa = merged.get("cisa_kev") or {}
    cisa_date = _format_date(cisa.get("date_added"))
    if cisa_date:
        events.append(
            {
                "date": cisa_date,
                "label": "Added to CISA KEV",
                "description": "CISA confirmed active exploitation and mandated remediation.",
            }
        )

    events.sort(key=lambda event: event["date"])
    return events


def _format_date(value: Any) -> str | None:
    """Normalize an ISO timestamp or date string to a YYYY-MM-DD display value."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:10]


def _as_text(value: Any) -> str:
    """Render a metric value, falling back to a placeholder when missing."""
    return "N/A" if value is None else str(value)
