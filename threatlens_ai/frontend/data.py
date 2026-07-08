from __future__ import annotations

from typing import Any

import streamlit as st

from threatlens_ai.frontend.api_client import ThreatLensAPIClient

# The backend already caches the CISA catalog; a short frontend TTL avoids re-fetching
# on every Streamlit rerun (navigation, widget changes) while staying reasonably fresh.
_HEALTH_TTL = 15
_THREATS_TTL = 300
# Analyses are deterministic for a given input (and the advisory path is an expensive
# LLM call), so cache them longer and key on their inputs.
_ANALYSIS_TTL = 900

# NOTE: the leading underscore on `_client` tells Streamlit's cache not to hash it,
# so the singleton client is reused without breaking cache keys.


@st.cache_data(ttl=_HEALTH_TTL, show_spinner=False)
def health(_client: ThreatLensAPIClient) -> dict[str, Any]:
    """Cached backend health check."""
    return _client.health()


@st.cache_data(ttl=_THREATS_TTL, show_spinner=False)
def latest_threats(_client: ThreatLensAPIClient, limit: int = 20) -> list[dict[str, Any]]:
    """Cached CISA KEV feed."""
    return _client.get_latest_threats(limit=limit)


@st.cache_data(ttl=_ANALYSIS_TTL, show_spinner=False)
def analyze_cve(_client: ThreatLensAPIClient, cve: str) -> dict[str, Any]:
    """Cached Threat Intelligence Agent analysis for a CVE."""
    return _client.analyze_cve(cve)


@st.cache_data(ttl=_ANALYSIS_TTL, show_spinner=False)
def industry_report(_client: ThreatLensAPIClient, industry: str) -> dict[str, Any]:
    """Cached Industry Intelligence Agent report."""
    return _client.get_industry_report(industry)


@st.cache_data(ttl=_ANALYSIS_TTL, show_spinner=False)
def analyze_sbom(_client: ThreatLensAPIClient, sbom: str) -> dict[str, Any]:
    """Cached SBOM exposure analysis."""
    return _client.analyze_sbom(sbom)


@st.cache_data(ttl=_ANALYSIS_TTL, show_spinner=False)
def orchestrate(
    _client: ThreatLensAPIClient,
    cve: str,
    industry: str | None = None,
    sbom: str | None = None,
) -> dict[str, Any]:
    """Cached full orchestration pipeline run."""
    return _client.orchestrate(cve=cve, industry=industry, sbom=sbom)
