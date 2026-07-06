from __future__ import annotations

from typing import Any

import streamlit as st

from threatlens_ai.frontend.api_client import APIClientError, ThreatLensAPIClient
from threatlens_ai.frontend.components import render_bullets, render_error
from threatlens_ai.frontend.constants import INDUSTRIES


def render(client: ThreatLensAPIClient) -> None:
    """Render the Industry Intelligence page: an industry-specific security briefing."""
    st.title("Industry Intelligence")
    st.caption("Generate an executive security briefing tailored to a specific industry.")

    with st.form("industry_intelligence_form"):
        industry = st.selectbox("Industry", INDUSTRIES)
        submitted = st.form_submit_button("Generate Report", type="primary")

    if not submitted:
        return

    with st.spinner(f"Generating report for {industry}..."):
        try:
            report = client.get_industry_report(industry)
        except APIClientError as error:
            render_error(str(error))
            return

    _render_report(report)


def _render_report(report: dict[str, Any]) -> None:
    st.subheader(report.get("industry", "Industry"))
    st.write(report.get("executive_summary") or "—")

    col_threats, col_risks = st.columns(2)
    with col_threats:
        st.markdown("#### Top Threats")
        render_bullets(report.get("top_threats"))
    with col_risks:
        st.markdown("#### Current Risks")
        render_bullets(report.get("current_risks"))

    col_controls, col_impact = st.columns(2)
    with col_controls:
        st.markdown("#### Recommended Controls")
        render_bullets(report.get("recommended_controls"))
    with col_impact:
        st.markdown("#### Business Impact")
        render_bullets(report.get("business_impact"))
