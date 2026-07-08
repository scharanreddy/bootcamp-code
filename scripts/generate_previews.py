"""Generate themed SVG UI previews of the ThreatLens AI dashboard pages.

Run from the repo root:  python scripts/generate_previews.py

These are faithful vector mockups (not live browser captures) rendered with the
exact palette from .streamlit/config.toml, used for the README gallery.
"""
from __future__ import annotations

from pathlib import Path

OUT_DIR = Path(__file__).resolve().parents[1] / "docs" / "screenshots"

W, H = 1160, 720
SIDEBAR_W = 232
CONTENT_X = SIDEBAR_W + 28

# Palette (mirrors .streamlit/config.toml and theme.py).
BG = "#0B1220"
PANEL = "#141C2F"
CARD = "#1B2438"
BORDER = "#2A3550"
TEXT = "#E5E9F0"
MUTED = "#93A1BD"
SKY = "#38BDF8"
CRIT = "#EF4444"
HIGH = "#F97316"
MED = "#FBBF24"
LOW = "#22C55E"
CHIP_BG = "#16304A"
CHIP_BORDER = "#2C5A85"
CHIP_TEXT = "#BFDBFE"

FONT = "Segoe UI, system-ui, -apple-system, sans-serif"
MONO = "SFMono-Regular, Menlo, monospace"

NAV = [
    ("🏠", "Home"),
    ("📡", "Threat Feed"),
    ("🔍", "Analyze CVE"),
    ("🏭", "Industry Intelligence"),
    ("📦", "SBOM Analysis"),
    ("📄", "Reports"),
]


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def rect(x, y, w, h, *, rx=0, fill="none", stroke="none", sw=1, opacity=1.0) -> str:
    s = f'stroke="{stroke}" stroke-width="{sw}"' if stroke != "none" else ""
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" {s} opacity="{opacity}"/>'


def text(x, y, s, *, size=14, fill=TEXT, weight=400, anchor="start", family=FONT, opacity=1.0) -> str:
    return (
        f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
        f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}" opacity="{opacity}">{esc(s)}</text>'
    )


def badge(x, y, label, fill, tfill="#0B1220", w=None) -> str:
    w = w if w is not None else 22 + len(label) * 8
    return (
        rect(x, y, w, 24, rx=12, fill=fill)
        + text(x + w / 2, y + 16, label, size=12, fill=tfill, weight=700, anchor="middle")
    )


def chip(x, y, label) -> str:
    w = 20 + len(label) * 7.6
    return (
        rect(x, y, w, 28, rx=14, fill=CHIP_BG, stroke=CHIP_BORDER)
        + text(x + w / 2, y + 18, label, size=12.5, fill=CHIP_TEXT, weight=600, anchor="middle")
    ), w


def sidebar(active: int) -> str:
    out = [rect(0, 0, SIDEBAR_W, H, fill=PANEL)]
    out.append(rect(SIDEBAR_W - 1, 0, 1, H, fill=BORDER))
    out.append(text(24, 46, "🛡️ ThreatLens AI", size=19, weight=700))
    out.append(text(24, 70, "AI-powered threat intelligence", size=12, fill=MUTED))
    out.append(rect(24, 88, SIDEBAR_W - 48, 1, fill=BORDER))
    y = 116
    for i, (icon, label) in enumerate(NAV):
        if i == active:
            out.append(rect(16, y - 20, SIDEBAR_W - 32, 34, rx=8, fill=SKY, opacity=0.16))
            out.append(rect(16, y - 20, 3, 34, rx=2, fill=SKY))
        out.append(text(30, y, f"{icon}  {label}", size=14.5,
                        fill=TEXT if i == active else MUTED, weight=600 if i == active else 400))
        y += 46
    out.append(rect(24, H - 70, SIDEBAR_W - 48, 1, fill=BORDER))
    out.append(f'<circle cx="30" cy="{H - 40}" r="5" fill="{LOW}"/>')
    out.append(text(44, H - 35, "Backend online", size=12.5, fill=TEXT, weight=600))
    return "".join(out)


def header(title: str, subtitle: str) -> str:
    return (
        text(CONTENT_X, 58, title, size=28, weight=700)
        + text(CONTENT_X, 84, subtitle, size=13.5, fill=MUTED)
    )


def metric_cards(y: int, cards: list[tuple[str, str]], *, cols: int | None = None) -> str:
    cols = cols or len(cards)
    gap = 16
    total = W - CONTENT_X - 28
    cw = (total - gap * (cols - 1)) / cols
    out = []
    for i, (label, value) in enumerate(cards):
        x = CONTENT_X + i * (cw + gap)
        out.append(rect(x, y, cw, 78, rx=12, fill=CARD, stroke=BORDER))
        out.append(text(x + 16, y + 26, label, size=12, fill=MUTED, weight=600))
        out.append(text(x + 16, y + 58, value, size=26, weight=700))
    return "".join(out)


def panel(x, y, w, h, title=None) -> str:
    out = [rect(x, y, w, h, rx=12, fill=CARD, stroke=BORDER)]
    if title:
        out.append(text(x + 18, y + 28, title, size=14.5, weight=700))
    return "".join(out)


def svg(body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" font-family="{FONT}">'
        f'{rect(0, 0, W, H, fill=BG)}{body}</svg>\n'
    )


def _rows(x, y, w, rows: list[list[str]], headers: list[str], widths: list[float]) -> str:
    out = [text(x + 14 + sum(widths[:i]) * w, y, h, size=12, fill=MUTED, weight=700)
           for i, h in enumerate(headers)]
    ry = y + 14
    for row in rows:
        ry += 34
        out.append(rect(x, ry - 22, w, 1, fill=BORDER, opacity=0.6))
        for i, cell in enumerate(row):
            cx = x + 14 + sum(widths[:i]) * w
            fill = TEXT
            fam = MONO if i == 0 else FONT
            out.append(text(cx, ry, cell, size=12.5, fill=fill, family=fam))
    return "".join(out)


def page_home() -> str:
    b = [sidebar(0), header("Threat Intelligence Overview",
                            "A real-time snapshot of known exploited vulnerabilities tracked by CISA.")]
    b.append(text(CONTENT_X, 122, "Threat Statistics", size=15, weight=700))
    b.append(metric_cards(136, [
        ("Tracked (latest batch)", "50"),
        ("Ransomware-Linked", "12"),
        ("Unique Vendors", "31"),
        ("Added in Last 7 Days", "8"),
    ]))
    # left table
    tx, ty, tw = CONTENT_X, 250, 540
    b.append(panel(tx, ty, tw, 400, "Latest CISA KEV"))
    b.append(_rows(tx, ty + 62, tw,
                   rows=[
                       ["CVE-2024-3400", "Palo Alto", "Critical"],
                       ["CVE-2024-1709", "ConnectWise", "Critical"],
                       ["CVE-2023-4966", "Citrix", "High"],
                       ["CVE-2024-21887", "Ivanti", "High"],
                       ["CVE-2023-34362", "Progress", "Critical"],
                       ["CVE-2024-1086", "Linux", "High"],
                   ],
                   headers=["CVE", "Vendor", "Severity"],
                   widths=[0.42, 0.36, 0.22]))
    # right cards
    rx = tx + tw + 20
    rw = W - rx - 28
    b.append(text(rx, ty - 8, "Recent Critical CVEs", size=15, weight=700))
    for i, (cve, vendor, tag, color, tag_text) in enumerate([
        ("CVE-2024-3400", "Palo Alto · PAN-OS", "🔥 Ransomware", CRIT, "#fff"),
        ("CVE-2024-1709", "ConnectWise · ScreenConnect", "Critical", CRIT, "#fff"),
        ("CVE-2023-4966", "Citrix · NetScaler", "High", HIGH, "#111827"),
    ]):
        cy = ty + i * 128
        b.append(rect(rx, cy, rw, 112, rx=12, fill=CARD, stroke=BORDER))
        b.append(text(rx + 16, cy + 30, cve, size=14, weight=700, family=MONO))
        b.append(badge(rx + rw - (30 + len(tag) * 8) - 14, cy + 14, tag, color, tag_text))
        b.append(text(rx + 16, cy + 54, vendor, size=12, fill=MUTED))
        b.append(text(rx + 16, cy + 82, "Actively exploited; apply vendor fix", size=12, fill=TEXT, opacity=0.85))
    return svg("".join(b))


def page_analyze() -> str:
    b = [sidebar(2), header("🔍 Analyze CVE",
                            "Run the Threat Intelligence Agent against merged CISA KEV and NVD data.")]
    # input
    b.append(rect(CONTENT_X, 108, 560, 40, rx=8, fill=PANEL, stroke=BORDER))
    b.append(text(CONTENT_X + 14, 133, "CVE-2024-3400", size=14, family=MONO))
    b.append(rect(CONTENT_X + 576, 108, 120, 40, rx=8, fill=SKY))
    b.append(text(CONTENT_X + 636, 133, "Analyze", size=14, weight=700, fill="#06263a", anchor="middle"))
    b.append(metric_cards(168, [
        ("CVSS Score", "9.8"),
        ("Known Exploited", "Yes"),
        ("Model", "gpt-5.5"),
        ("Execution Time", "1.24s"),
    ]))
    # exec summary
    b.append(text(CONTENT_X, 286, "Executive Summary", size=15, weight=700))
    for i, line in enumerate([
        "CVE-2024-3400 is a critical, actively exploited command-injection flaw in",
        "GlobalProtect (PAN-OS). Unauthenticated RCE on internet-facing firewalls;",
        "CISA KEV-listed. Patch on an emergency timeline.",
    ]):
        b.append(text(CONTENT_X, 312 + i * 22, line, size=13.5, fill=TEXT, opacity=0.9))
    # CVSS panel + timeline
    py = 400
    b.append(panel(CONTENT_X, py, 430, 150, "CVSS"))
    b.append(text(CONTENT_X + 24, py + 96, "9.8", size=48, weight=800, fill=CRIT))
    b.append(text(CONTENT_X + 110, py + 96, "/ 10", size=18, fill=MUTED))
    b.append(badge(CONTENT_X + 24, py + 112, "Critical", CRIT, "#fff"))
    b.append(text(CONTENT_X + 130, py + 128, "CVSS v3.1  AV:N/AC:L/PR:N/UI:N", size=11.5, fill=MUTED, family=MONO))
    # timeline
    tx = CONTENT_X + 460
    tw = W - tx - 28
    b.append(panel(tx, py, tw, 150, "Threat Timeline"))
    events = [("2024-04-12", "Published to NVD"), ("2024-04-12", "Added to CISA KEV"), ("2024-04-16", "Last modified")]
    b.append(rect(tx + 24, py + 52, 2, 74, fill=BORDER))
    for i, (d, label) in enumerate(events):
        ey = py + 60 + i * 30
        b.append(f'<circle cx="{tx + 25}" cy="{ey}" r="5" fill="{SKY}"/>')
        b.append(text(tx + 42, ey - 2, d, size=11.5, fill="#93C5FD", weight=700, family=MONO))
        b.append(text(tx + 140, ey - 2, label, size=12.5, fill=TEXT))
    b.append(text(CONTENT_X, py + 190, "Recommendations", size=15, weight=700))
    for i, r in enumerate(["Apply the PAN-OS hotfix to all affected firewalls",
                           "Hunt for IoCs in GlobalProtect logs"]):
        b.append(text(CONTENT_X, py + 216 + i * 22, f"•  {r}", size=13, fill=TEXT, opacity=0.9))
    return svg("".join(b))


def page_industry() -> str:
    b = [sidebar(3), header("🏭 Industry Intelligence",
                            "Generate an executive security briefing tailored to a specific industry.")]
    b.append(rect(CONTENT_X, 108, 360, 40, rx=8, fill=PANEL, stroke=BORDER))
    b.append(text(CONTENT_X + 14, 133, "Financial Services", size=14))
    b.append(text(CONTENT_X + 330, 133, "▾", size=14, fill=MUTED))
    b.append(metric_cards(168, [("Top Threats", "4"), ("Attack Patterns", "4"), ("Recommended Controls", "4")]))
    # briefing box
    by = 272
    b.append(text(CONTENT_X, by, "📋 Executive Briefing", size=15, weight=700))
    b.append(panel(CONTENT_X, by + 12, W - CONTENT_X - 28, 92))
    for i, line in enumerate([
        "Financial Services organizations should prioritize protection of core banking",
        "systems, trading platforms, and customer financial records. Key themes are fraud,",
        "ransomware, and insider threats — align controls to transaction integrity and IAM.",
    ]):
        b.append(text(CONTENT_X + 18, by + 40 + i * 22, line, size=13, fill=TEXT, opacity=0.9))
    # chips
    b.append(text(CONTENT_X, by + 142, "⚠️ Top Threats", size=14.5, weight=700))
    x = CONTENT_X
    for label in ["Fraud", "Ransomware", "Insider threats", "Advanced persistent threats"]:
        c, w = chip(x, by + 154, label)
        b.append(c)
        x += w + 10
    b.append(text(CONTENT_X, by + 210, "🎯 Attack Patterns", size=14.5, weight=700))
    x = CONTENT_X
    for label in ["Phishing", "Credential theft", "Business email compromise", "Malware"]:
        c, w = chip(x, by + 222, label)
        b.append(c)
        x += w + 10
    b.append(text(CONTENT_X, by + 284, "🛡️ Recommended Controls", size=14.5, weight=700))
    for i, r in enumerate(["Strengthen identity and access controls", "Protect transaction integrity"]):
        b.append(text(CONTENT_X, by + 310 + i * 22, f"•  {r}", size=13, fill=TEXT, opacity=0.9))
    return svg("".join(b))


def page_sbom() -> str:
    b = [sidebar(4), header("📦 SBOM Analysis",
                            "Upload a CycloneDX SBOM to enumerate components and assess exposure.")]
    b.append(rect(CONTENT_X, 108, W - CONTENT_X - 28, 46, rx=8, fill=PANEL, stroke=BORDER, sw=1))
    b.append(text(CONTENT_X + 16, 136, "📄  payments-app-sbom.json", size=13.5, fill=TEXT))
    b.append(text(W - 44 - 60, 136, "Browse", size=13, fill=SKY, weight=600, anchor="start"))
    b.append(metric_cards(172, [("Components", "4"), ("Applications", "1"), ("Public Services", "2"), ("Internet Exposed", "Yes")]))
    # components table
    tx, ty, tw = CONTENT_X, 288, W - CONTENT_X - 28
    b.append(text(tx, ty, "🧩 Affected Components", size=15, weight=700))
    b.append(panel(tx, ty + 12, tw, 190))
    b.append(_rows(tx, ty + 52, tw,
                   rows=[
                       ["payments-web", "4.1.0", "Acme", "Application"],
                       ["auth-service", "2.3.1", "Acme", "Service"],
                       ["openssl", "3.0.11", "OpenSSL", "Library"],
                       ["log4j-core", "2.17.1", "Apache", "Library"],
                   ],
                   headers=["Component", "Version", "Supplier", "Type"],
                   widths=[0.34, 0.18, 0.28, 0.20]))
    # risk row + recs
    ry = ty + 226
    b.append(text(tx, ry, "⚠️ Risk", size=15, weight=700))
    b.append(rect(tx, ry + 14, 200, 60, rx=10, fill=CARD, stroke=BORDER))
    b.append(text(tx + 16, ry + 38, "Exposed Assets", size=11.5, fill=MUTED))
    b.append(text(tx + 16, ry + 62, "4", size=20, weight=700))
    b.append(rect(tx + 216, ry + 14, 240, 60, rx=10, fill=CARD, stroke=BORDER))
    b.append(text(tx + 232, ry + 38, "Third-Party Exposure", size=11.5, fill=MUTED))
    b.append(text(tx + 232, ry + 62, "Yes", size=20, weight=700))
    b.append(rect(tx + 472, ry + 14, 220, 60, rx=10, fill=CARD, stroke=BORDER))
    b.append(text(tx + 488, ry + 38, "Data Sensitivity", size=11.5, fill=MUTED))
    b.append(badge(tx + 488, ry + 48, "Medium", MED, "#111827"))
    return svg("".join(b))


PAGES = {
    "home.svg": page_home,
    "analyze-cve.svg": page_analyze,
    "industry-intelligence.svg": page_industry,
    "sbom-analysis.svg": page_sbom,
}


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, builder in PAGES.items():
        (OUT_DIR / name).write_text(builder(), encoding="utf-8")
        print(f"wrote docs/screenshots/{name}")


if __name__ == "__main__":
    main()
