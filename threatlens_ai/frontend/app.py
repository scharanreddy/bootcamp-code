from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is importable no matter how this script is launched
# (`streamlit run …/app.py`, a container without an editable install, etc.).
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import streamlit as st

from threatlens_ai.frontend import data
from threatlens_ai.frontend.api_client import APIClientError, ThreatLensAPIClient
from threatlens_ai.frontend.constants import (
    NAV_ANALYZE_CVE,
    NAV_HOME,
    NAV_INDUSTRY_INTELLIGENCE,
    NAV_PAGES,
    NAV_REPORTS,
    NAV_SBOM_ANALYSIS,
    NAV_THREAT_FEED,
)
from threatlens_ai.frontend.theme import apply_theme
from threatlens_ai.frontend.views import (
    analyze_cve,
    home,
    industry_intelligence,
    reports,
    sbom_analysis,
    threat_feed,
)

_PAGE_RENDERERS = {
    NAV_HOME: home.render,
    NAV_THREAT_FEED: threat_feed.render,
    NAV_ANALYZE_CVE: analyze_cve.render,
    NAV_INDUSTRY_INTELLIGENCE: industry_intelligence.render,
    NAV_SBOM_ANALYSIS: sbom_analysis.render,
    NAV_REPORTS: reports.render,
}


@st.cache_resource
def _get_client() -> ThreatLensAPIClient:
    return ThreatLensAPIClient()


def _render_sidebar(client: ThreatLensAPIClient) -> str:
    with st.sidebar:
        st.markdown("## 🛡️ ThreatLens AI")
        st.caption("AI-powered threat intelligence")
        st.divider()
        page = st.radio("Navigation", NAV_PAGES, label_visibility="collapsed")
        st.divider()
        _render_backend_status(client)
    return page


def _render_backend_status(client: ThreatLensAPIClient) -> None:
    try:
        data.health(client)
    except APIClientError:
        st.markdown("🔴 **Backend offline**")
        st.caption(f"Could not reach {client.base_url}")
    else:
        st.markdown("🟢 **Backend online**")
        st.caption(client.base_url)


def _render_footer() -> None:
    st.divider()
    st.caption(
        "🛡️ ThreatLens AI · Data sourced from CISA KEV and NVD · "
        "For authorized security use only."
    )


def main() -> None:
    """Streamlit app entrypoint."""
    st.set_page_config(
        page_title="ThreatLens AI",
        page_icon="🛡️",
        layout="wide",
        menu_items={"about": "ThreatLens AI — AI-powered threat intelligence platform."},
    )
    apply_theme()

    client = _get_client()
    page = _render_sidebar(client)

    render_page = _PAGE_RENDERERS[page]
    try:
        render_page(client)
    except APIClientError as error:
        # Defensive: pages handle this themselves, but never leak a raw traceback.
        st.error(f"⚠️ {error}")
    except Exception as error:  # noqa: BLE001 - top-level UI guard
        st.error("⚠️ Something went wrong while rendering this page. Please try again.")
        with st.expander("Technical details"):
            st.exception(error)

    _render_footer()


if __name__ == "__main__":
    main()
