from __future__ import annotations

import re
from typing import Any

import streamlit as st

from threatlens_ai.frontend.api_client import APIClientError, ThreatLensAPIClient
from threatlens_ai.frontend.components import render_error
from threatlens_ai.frontend.constants import INDUSTRIES

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_NO_INDUSTRY = "None"


def render(client: ThreatLensAPIClient) -> None:
    """Render the Reports page: the full Advisor Agent output as a downloadable Markdown report."""
    st.title("Reports")
    st.caption("Generate a full security advisory synthesizing threat, industry, and exposure context.")

    uploaded_file = st.file_uploader(
        "Attach a CycloneDX SBOM (optional)", type=["json", "xml"], key="reports_sbom_uploader"
    )

    with st.form("reports_form"):
        cve = st.text_input("CVE Identifier", placeholder="CVE-2026-1234")
        industry = st.selectbox("Industry (optional)", [_NO_INDUSTRY, *INDUSTRIES])
        submitted = st.form_submit_button("Generate Advisory Report", type="primary")

    if not submitted:
        return

    cve = cve.strip().upper()
    if not _CVE_PATTERN.fullmatch(cve):
        render_error("Enter a CVE using the format CVE-YYYY-NNNN.")
        return

    sbom_text = uploaded_file.getvalue().decode("utf-8") if uploaded_file is not None else None
    industry_value = None if industry == _NO_INDUSTRY else industry

    with st.spinner("Running the full orchestration pipeline..."):
        try:
            result = client.orchestrate(cve=cve, industry=industry_value, sbom=sbom_text)
        except APIClientError as error:
            render_error(str(error))
            return

    _render_report(result, cve=cve)


def _render_report(result: dict[str, Any], *, cve: str) -> None:
    risk = result.get("risk_assessment") or {}
    advisory = result.get("advisory") or {}

    cols = st.columns(3)
    cols[0].metric("Priority", str(risk.get("priority", "—")).title())
    cols[1].metric("Overall Risk", f"{risk.get('overall_risk', 0):.1f}/10" if risk else "—")
    cols[2].metric("Confidence", f"{risk.get('confidence', 0):.0f}%" if risk else "—")

    st.divider()

    markdown_text = advisory.get("markdown", "")
    st.markdown(markdown_text)

    st.download_button(
        "Download Report (.md)",
        data=markdown_text,
        file_name=f"{cve}-advisory-report.md",
        mime="text/markdown",
    )
