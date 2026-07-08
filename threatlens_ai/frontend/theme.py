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

/* Animations */
@keyframes tl-fade-in {
    from { opacity: 0; transform: translateY(6px); }
    to { opacity: 1; transform: translateY(0); }
}
@keyframes tl-fade-in-soft {
    from { opacity: 0; }
    to { opacity: 1; }
}

/* Fade the main content in on each rerun for a smoother feel. */
[data-testid="stMain"] .block-container {
    animation: tl-fade-in-soft 0.4s ease-out;
    padding-top: 2.5rem;
    max-width: 1200px;
}

h1, h2, h3 { letter-spacing: -0.01em; }

[data-testid="stSidebar"] {
    border-right: 1px solid rgba(148, 163, 184, 0.15);
    background: linear-gradient(180deg, rgba(20, 28, 47, 0.6), rgba(11, 18, 32, 0.6));
}

[data-testid="stSidebar"] [data-testid="stRadio"] label {
    font-size: 0.95rem;
    padding: 0.4rem 0.5rem;
    border-radius: 0.5rem;
    transition: background 0.15s ease;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
    background: rgba(56, 189, 248, 0.1);
}

[data-testid="stMetric"] {
    background: rgba(148, 163, 184, 0.08);
    border: 1px solid rgba(148, 163, 184, 0.15);
    border-radius: 0.75rem;
    padding: 1rem 1rem 0.75rem 1rem;
    animation: tl-fade-in 0.45s ease-out both;
    transition: border-color 0.2s ease, transform 0.2s ease;
}
[data-testid="stMetric"]:hover {
    border-color: rgba(56, 189, 248, 0.45);
    transform: translateY(-2px);
}

[data-testid="stMetricLabel"] {
    font-weight: 600;
    opacity: 0.85;
}

.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button {
    border-radius: 0.6rem;
    font-weight: 600;
    transition: transform 0.12s ease, box-shadow 0.2s ease, filter 0.2s ease;
}
.stButton > button:hover, .stDownloadButton > button:hover, .stFormSubmitButton > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 18px rgba(56, 189, 248, 0.18);
    filter: brightness(1.05);
}

[data-testid="stDataFrame"] {
    border-radius: 0.75rem;
    overflow: hidden;
    border: 1px solid rgba(148, 163, 184, 0.15);
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
    animation: tl-fade-in 0.45s ease-out both;
    transition: border-color 0.2s ease, transform 0.2s ease;
}
.tl-card:hover {
    border-color: rgba(56, 189, 248, 0.4);
    transform: translateY(-2px);
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

/* CVSS panel */
.tl-cvss {
    display: flex;
    align-items: center;
    gap: 1.4rem;
    background: rgba(148, 163, 184, 0.06);
    border: 1px solid rgba(148, 163, 184, 0.15);
    border-radius: 0.85rem;
    padding: 1.1rem 1.35rem;
}
.tl-cvss-score {
    display: flex;
    align-items: baseline;
    gap: 0.15rem;
    font-weight: 800;
    line-height: 1;
}
.tl-cvss-score .num { font-size: 2.5rem; }
.tl-cvss-score .max { font-size: 1rem; opacity: 0.55; }
.tl-cvss-meta { display: flex; flex-direction: column; gap: 0.35rem; min-width: 0; }
.tl-cvss-vector {
    font-family: monospace;
    font-size: 0.82rem;
    opacity: 0.85;
    word-break: break-all;
}

/* Vertical timeline */
.tl-timeline {
    position: relative;
    margin: 0.25rem 0 0.5rem 0;
    padding-left: 1.5rem;
    border-left: 2px solid rgba(148, 163, 184, 0.25);
}
.tl-timeline-item { position: relative; padding: 0 0 1.15rem 0.4rem; }
.tl-timeline-item:last-child { padding-bottom: 0.15rem; }
.tl-timeline-item::before {
    content: "";
    position: absolute;
    left: -1.97rem;
    top: 0.2rem;
    width: 0.72rem;
    height: 0.72rem;
    border-radius: 999px;
    background: #60A5FA;
    box-shadow: 0 0 0 3px rgba(96, 165, 250, 0.18);
}
.tl-timeline-date { font-weight: 700; font-size: 0.82rem; color: #93C5FD; font-family: monospace; }
.tl-timeline-label { font-weight: 600; font-size: 0.92rem; margin-top: 0.1rem; }
.tl-timeline-desc { opacity: 0.7; font-size: 0.82rem; margin-top: 0.1rem; }

/* Inline chips (threats, attack patterns) */
.tl-chips { display: flex; flex-wrap: wrap; gap: 0.45rem; margin: 0.15rem 0 0.35rem 0; }
.tl-chip {
    display: inline-block;
    padding: 0.3rem 0.75rem;
    border-radius: 999px;
    font-size: 0.82rem;
    font-weight: 600;
    background: rgba(96, 165, 250, 0.12);
    border: 1px solid rgba(96, 165, 250, 0.3);
    color: #BFDBFE;
    white-space: nowrap;
    transition: background 0.15s ease, transform 0.15s ease;
}
.tl-chip:hover {
    background: rgba(96, 165, 250, 0.22);
    transform: translateY(-1px);
}

/* Agent execution trace */
.tl-trace-item {
    display: flex;
    gap: 0.65rem;
    align-items: flex-start;
    padding: 0.55rem 0.85rem;
    border: 1px solid rgba(148, 163, 184, 0.15);
    border-radius: 0.6rem;
    background: rgba(148, 163, 184, 0.05);
    margin-bottom: 0.5rem;
}
.tl-trace-icon { font-size: 1.05rem; line-height: 1.3; }
.tl-trace-title { font-weight: 600; font-size: 0.9rem; }
.tl-trace-detail { opacity: 0.72; font-size: 0.82rem; margin-top: 0.1rem; }
</style>
"""


def apply_theme() -> None:
    """Inject ThreatLens AI's custom styling on top of the base Streamlit theme."""
    st.markdown(_CUSTOM_CSS, unsafe_allow_html=True)


def severity_colors(severity: str | None) -> tuple[str, str]:
    """Return the (background, text) color pair for a severity label."""
    return SEVERITY_STYLES.get((severity or "").strip().lower(), _DEFAULT_SEVERITY_STYLE)


def severity_badge(severity: str | None) -> str:
    """Render a colored HTML pill badge for a severity label."""
    label = html.escape((severity or "Unknown").title())
    background, color = severity_colors(severity)
    return f'<span class="tl-badge" style="background:{background};color:{color};">{label}</span>'


def ransomware_badge() -> str:
    """Render a badge flagging CVEs CISA has observed in ransomware campaigns."""
    return '<span class="tl-badge" style="background:#DC2626;color:#FFFFFF;">🔥 Ransomware-Linked</span>'
