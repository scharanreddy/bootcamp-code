from __future__ import annotations

import re
from typing import Any

import streamlit as st

from threatlens_ai.frontend.api_client import APIClientError, ThreatLensAPIClient
from threatlens_ai.frontend.components import render_bullets, render_error
from threatlens_ai.frontend.theme import severity_badge

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def render(client: ThreatLensAPIClient) -> None:
    """Render the Analyze CVE page: run the Threat Intelligence Agent for one CVE."""
    st.title("Analyze CVE")
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

    with st.spinner(f"Analyzing {cve}..."):
        try:
            result = client.analyze_cve(cve)
        except APIClientError as error:
            render_error(str(error))
            return

    _render_result(result)


def _render_result(result: dict[str, Any]) -> None:
    intel = result["threat_intelligence"]
    merged = intel.get("merged_intelligence") or {}
    cvss = merged.get("cvss") or {}

    header_col, badge_col = st.columns([3, 1])
    with header_col:
        st.subheader(intel["cve"])
    with badge_col:
        st.markdown(severity_badge(merged.get("severity")), unsafe_allow_html=True)

    metric_cols = st.columns(4)
    metric_cols[0].metric("CVSS Score", cvss.get("base_score", "N/A"))
    metric_cols[1].metric("Known Exploited", "Yes" if merged.get("is_known_exploited") else "No")
    metric_cols[2].metric("Model", intel.get("model", "—"))
    metric_cols[3].metric("Execution Time", f"{result.get('execution_time_seconds', 0):.2f}s")

    st.markdown("#### Executive Summary")
    st.write(intel.get("executive_summary") or "—")

    st.markdown("#### Technical Summary")
    st.write(intel.get("technical_summary") or "—")

    col_impact, col_scenario = st.columns(2)
    with col_impact:
        st.markdown("#### Business Impact")
        st.write(intel.get("business_impact") or "—")
    with col_scenario:
        st.markdown("#### Likely Attack Scenario")
        st.write(intel.get("likely_attack_scenario") or "—")

    st.markdown("#### Immediate Recommendations")
    render_bullets(intel.get("immediate_recommendations"))

    with st.expander("Raw merged intelligence (CISA KEV + NVD)"):
        st.json(merged)
