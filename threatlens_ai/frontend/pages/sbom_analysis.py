from __future__ import annotations

from typing import Any

import streamlit as st

from threatlens_ai.frontend import data
from threatlens_ai.frontend.api_client import APIClientError, ThreatLensAPIClient
from threatlens_ai.frontend.components import (
    render_bullets,
    render_chips,
    render_component_table,
    render_error,
    render_metric_cards,
)
from threatlens_ai.frontend.theme import severity_badge


def render(client: ThreatLensAPIClient) -> None:
    """Render the SBOM Analysis page: component and exposure analysis from a CycloneDX SBOM."""
    st.title("📦 SBOM Analysis")
    st.caption("Upload a CycloneDX SBOM to enumerate components and assess exposure.")

    uploaded_file = st.file_uploader("Upload CycloneDX SBOM (JSON or XML)", type=["json", "xml"])
    analyze = st.button("Analyze", type="primary", disabled=uploaded_file is None)

    if uploaded_file is None:
        st.info("No exposure analysis performed.")
        return

    if not analyze:
        return

    try:
        sbom_text = uploaded_file.getvalue().decode("utf-8")
    except UnicodeDecodeError:
        render_error("The uploaded file is not valid UTF-8 text.")
        return

    result = _run_analysis(client, sbom_text)
    if result is None:
        return

    _render_result(result)


def _run_analysis(client: ThreatLensAPIClient, sbom_text: str) -> dict[str, Any] | None:
    """Invoke the backend while surfacing the analysis progress."""
    with st.status("Analyzing SBOM…", expanded=True) as status:
        st.write("📦 Parsing CycloneDX components…")
        st.write("🧠 Deriving the exposure profile…")
        try:
            result = data.analyze_sbom(client, sbom_text)
        except APIClientError as error:
            status.update(label="SBOM analysis failed", state="error")
            render_error(str(error))
            return None
        status.update(label="SBOM analysis complete", state="complete", expanded=False)
    return result


def _render_result(result: dict[str, Any]) -> None:
    exposure = result.get("exposure_analysis") or {}

    render_metric_cards(
        [
            ("Components", str(result.get("component_count", 0)), None),
            ("Applications", str(result.get("application_count", 0)), None),
            ("Public Services", str(exposure.get("public_services", 0)), None),
            ("Internet Exposed", "Yes" if exposure.get("internet_exposed") else "No", None),
        ]
    )

    st.markdown("#### 🧩 Affected Components")
    render_component_table(result.get("components"))

    st.markdown("#### 🖥️ Applications")
    applications = result.get("applications") or []
    if applications:
        render_chips(
            [_component_label(app) for app in applications],
            icon="🖥️",
        )
    else:
        st.write("No application-type components found in this SBOM.")

    st.markdown("#### ⚠️ Risk")
    _render_risk(exposure)

    st.markdown("#### ✅ Recommendations")
    render_bullets(result.get("recommendations"))

    with st.expander("Raw analysis data"):
        st.json(result)


def _render_risk(exposure: dict[str, Any]) -> None:
    """Render the exposure-derived risk profile."""
    if not exposure:
        st.write("—")
        return

    col_assets, col_third_party, col_sensitivity = st.columns(3)
    col_assets.metric("Exposed Assets", exposure.get("exposed_assets", 0))
    col_third_party.metric(
        "Third-Party Exposure", "Yes" if exposure.get("third_party_exposure") else "No"
    )
    with col_sensitivity:
        st.caption("Data Sensitivity")
        st.markdown(severity_badge(exposure.get("data_sensitivity")), unsafe_allow_html=True)


def _component_label(component: dict[str, Any]) -> str:
    """Build a compact 'name vX.Y' label for an application component."""
    name = component.get("software_name") or "Unknown"
    version = component.get("version")
    return f"{name} v{version}" if version else name
