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
    """Render the SBOM Analysis page: exposure and risk assessment from an uploaded SBOM."""
    st.title("SBOM Analysis")
    st.caption(
        "Upload a CycloneDX SBOM to assess exposure and combine it with a CVE for a risk assessment."
    )

    uploaded_file = st.file_uploader("Upload CycloneDX SBOM", type=["json", "xml"])

    with st.form("sbom_analysis_form"):
        cve = st.text_input("Related CVE", placeholder="CVE-2026-1234")
        industry = st.selectbox("Industry (optional)", [_NO_INDUSTRY, *INDUSTRIES])
        submitted = st.form_submit_button("Run Exposure & Risk Analysis", type="primary")

    if not submitted:
        return

    if uploaded_file is None:
        render_error("Upload a CycloneDX SBOM (JSON or XML) before running the analysis.")
        return

    cve = cve.strip().upper()
    if not _CVE_PATTERN.fullmatch(cve):
        render_error("Enter a CVE using the format CVE-YYYY-NNNN.")
        return

    sbom_text = uploaded_file.getvalue().decode("utf-8")
    industry_value = None if industry == _NO_INDUSTRY else industry

    with st.spinner("Analyzing exposure and risk..."):
        try:
            result = client.orchestrate(cve=cve, industry=industry_value, sbom=sbom_text)
        except APIClientError as error:
            render_error(str(error))
            return

    st.session_state["last_orchestration"] = result
    _render_result(result)


def _render_result(result: dict[str, Any]) -> None:
    exposure = result.get("exposure_analysis")
    risk = result.get("risk_assessment")

    if exposure is None:
        st.warning("The backend did not return an exposure analysis for this SBOM.")
    else:
        st.subheader("Exposure Profile")
        cols = st.columns(4)
        cols[0].metric("Exposed Assets", exposure.get("exposed_assets", 0))
        cols[1].metric("Public Services", exposure.get("public_services", 0))
        cols[2].metric("Third-Party Exposure", "Yes" if exposure.get("third_party_exposure") else "No")
        cols[3].metric("Data Sensitivity", str(exposure.get("data_sensitivity", "—")).title())

    if risk is not None:
        st.subheader("Risk Assessment")
        cols = st.columns(4)
        cols[0].metric("Overall Risk", f"{risk.get('overall_risk', 0):.1f}/10")
        cols[1].metric("Priority", str(risk.get("priority", "—")).title())
        cols[2].metric("Business Impact", f"{risk.get('business_impact', 0):.1f}/10")
        cols[3].metric("Confidence", f"{risk.get('confidence', 0):.0f}%")

        with st.expander("Risk score breakdown"):
            st.json(risk.get("breakdown", {}))

    st.info("Head to the Reports page to generate the full advisory using this CVE and SBOM context.")
