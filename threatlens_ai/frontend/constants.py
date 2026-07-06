from __future__ import annotations

# Must match the industry names in app/data/industries.json.
INDUSTRIES: list[str] = [
    "Retail",
    "Financial Services",
    "Healthcare",
    "Government",
    "Manufacturing",
    "Education",
    "Technology",
    "Telecommunications",
]

NAV_HOME = "🏠 Home"
NAV_THREAT_FEED = "📡 Threat Feed"
NAV_ANALYZE_CVE = "🔍 Analyze CVE"
NAV_INDUSTRY_INTELLIGENCE = "🏭 Industry Intelligence"
NAV_SBOM_ANALYSIS = "📦 SBOM Analysis"
NAV_REPORTS = "📄 Reports"

NAV_PAGES: list[str] = [
    NAV_HOME,
    NAV_THREAT_FEED,
    NAV_ANALYZE_CVE,
    NAV_INDUSTRY_INTELLIGENCE,
    NAV_SBOM_ANALYSIS,
    NAV_REPORTS,
]
