from __future__ import annotations

import html

import streamlit as st

# (background, text) colors per severity, layered on top of .streamlit/config.toml's dark theme.
SEVERITY_STYLES: dict[str, tuple[str, str]] = {
    "critical": ("#EF4444", "#FFFFFF"),
    "high": ("#F97316", "#111827"),
    "medium": ("#FBBF24", "#111827"),
    "low": ("#22C55E", "#111827"),
}
_DEFAULT_SEVERITY_STYLE = ("#64748B", "#FFFFFF")

_CUSTOM_CSS = """
<style>
#MainMenu, footer {visibility: hidden;}

[data-testid="stSidebar"] {
    border-right: 1px solid rgba(148, 163, 184, 0.15);
}

[data-testid="stSidebar"] [data-testid="stRadio"] label {
    font-size: 0.95rem;
    padding: 0.35rem 0;
}

[data-testid="stMetric"] {
    background: rgba(148, 163, 184, 0.08);
    border: 1px solid rgba(148, 163, 184, 0.15);
    border-radius: 0.75rem;
    padding: 1rem 1rem 0.75rem 1rem;
}

[data-testid="stMetricLabel"] {
    font-weight: 600;
    opacity: 0.85;
}

.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button {
    border-radius: 0.6rem;
    font-weight: 600;
}

.tl-badge {
    display: inline-block;
    padding: 0.2rem 0.7rem;
    border-radius: 999px;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.02em;
    white-space: nowrap;
}

.tl-card {
    background: rgba(148, 163, 184, 0.06);
    border: 1px solid rgba(148, 163, 184, 0.15);
    border-radius: 0.85rem;
    padding: 1rem 1.15rem;
    margin-bottom: 0.85rem;
}

.tl-card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
}

.tl-card-title {
    font-weight: 700;
    font-size: 1rem;
    font-family: monospace;
}

.tl-card-subtitle {
    opacity: 0.75;
    font-size: 0.85rem;
    margin-top: 0.15rem;
}

.tl-card-body {
    margin-top: 0.5rem;
    font-size: 0.9rem;
    line-height: 1.4;
}

.tl-card-footer {
    margin-top: 0.6rem;
    font-size: 0.75rem;
    opacity: 0.6;
}
</style>
"""


def apply_theme() -> None:
    """Inject ThreatLens AI's custom styling on top of the base Streamlit theme."""
    st.markdown(_CUSTOM_CSS, unsafe_allow_html=True)


def severity_badge(severity: str | None) -> str:
    """Render a colored HTML pill badge for a severity label."""
    label = html.escape((severity or "Unknown").title())
    background, color = SEVERITY_STYLES.get(
        (severity or "").strip().lower(), _DEFAULT_SEVERITY_STYLE
    )
    return f'<span class="tl-badge" style="background:{background};color:{color};">{label}</span>'


def ransomware_badge() -> str:
    """Render a badge flagging CVEs CISA has observed in ransomware campaigns."""
    return '<span class="tl-badge" style="background:#DC2626;color:#FFFFFF;">🔥 Ransomware-Linked</span>'
