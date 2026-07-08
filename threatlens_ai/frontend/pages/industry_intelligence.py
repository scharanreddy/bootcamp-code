from __future__ import annotations

from typing import Any

import streamlit as st

from threatlens_ai.frontend import data
from threatlens_ai.frontend.api_client import APIClientError, ThreatLensAPIClient
from threatlens_ai.frontend.components import (
    render_bullets,
    render_chips,
    render_error,
    render_metric_cards,
)
from threatlens_ai.frontend.constants import INDUSTRY_INTELLIGENCE_OPTIONS


def render(client: ThreatLensAPIClient) -> None:
    """Render the Industry Intelligence page: an industry-specific security briefing."""
    st.title("🏭 Industry Intelligence")
    st.caption("Generate an executive security briefing tailored to a specific industry.")

    with st.form("industry_intelligence_form"):
        industry = st.selectbox("Industry", INDUSTRY_INTELLIGENCE_OPTIONS)
        submitted = st.form_submit_button("Generate Briefing", type="primary")

    if not submitted:
        return

    report = _run_agent(client, industry)
    if report is None:
        return

    _render_report(report)


def _run_agent(client: ThreatLensAPIClient, industry: str) -> dict[str, Any] | None:
    """Invoke the backend while surfacing the agent's progress."""
    with st.status(f"Running Industry Intelligence Agent for {industry}…", expanded=True) as status:
        st.write("📚 Loading the industry threat profile…")
        st.write("🧠 Compiling the executive security briefing…")
        try:
            report = data.industry_report(client, industry)
        except APIClientError as error:
            status.update(label=f"Briefing failed for {industry}", state="error")
            render_error(str(error))
            return None
        status.update(label=f"Briefing ready for {industry}", state="complete", expanded=False)
    return report


def _render_report(report: dict[str, Any]) -> None:
    st.subheader(report.get("industry", "Industry"))

    top_threats = report.get("top_threats") or []
    attack_patterns = report.get("common_attack_types") or []
    controls = report.get("recommended_controls") or []
    render_metric_cards(
        [
            ("Top Threats", str(len(top_threats)), None),
            ("Attack Patterns", str(len(attack_patterns)), None),
            ("Recommended Controls", str(len(controls)), None),
        ]
    )

    st.markdown("#### 📋 Executive Briefing")
    with st.container(border=True):
        st.write(report.get("executive_summary") or "—")

    col_threats, col_patterns = st.columns(2)
    with col_threats:
        st.markdown("#### ⚠️ Top Threats")
        render_chips(top_threats)
    with col_patterns:
        st.markdown("#### 🎯 Attack Patterns")
        render_chips(attack_patterns)

    col_controls, col_priorities = st.columns(2)
    with col_controls:
        st.markdown("#### 🛡️ Recommended Controls")
        render_bullets(controls)
    with col_priorities:
        st.markdown("#### 💼 Business Priorities")
        render_bullets(report.get("business_impact"))

    with st.expander("Full report data"):
        st.json(report)
