"""Generate example reports from ThreatLens AI's real code paths.

Run from the repo root:  python scripts/generate_examples.py

The Advisor markdown is produced by the real ``MarkdownAdvisoryRenderer`` (the
narrative content is representative, since we do not call OpenAI here). The
industry briefing and SBOM analysis are produced by the real deterministic
agents/services, so they reflect exactly what the app renders.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Ensure the repo root is importable when run as `python scripts/generate_examples.py`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# The backend config validates these at import time; set placeholders so the
# example generator runs without real credentials (no network calls are made).
os.environ.setdefault("OPENAI_API_KEY", "example-not-used")
os.environ.setdefault("NVD_API_KEY", "example-not-used")

from threatlens_ai.agent.advisor_agent import (  # noqa: E402
    AdvisoryReport,
    DetectionOpportunity,
    ImmediateAction,
    MarkdownAdvisoryRenderer,
    TechnicalRecommendation,
)
from threatlens_ai.agent.industry_intelligence import IndustryIntelligenceAgent  # noqa: E402
from threatlens_ai.backend.services.sbom_service import SBOMAnalysisService  # noqa: E402

EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "docs" / "examples"

SAMPLE_SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"type": "application", "name": "payments-web", "version": "4.1.0", "supplier": {"name": "Acme"}},
            {"type": "service", "name": "auth-service", "version": "2.3.1", "supplier": {"name": "Acme"}},
            {"type": "library", "name": "openssl", "version": "3.0.11", "supplier": {"name": "OpenSSL"}},
            {"type": "library", "name": "log4j-core", "version": "2.17.1", "supplier": {"name": "Apache"}},
        ],
    },
    indent=2,
)


def _write(name: str, content: str) -> None:
    path = EXAMPLES_DIR / name
    path.write_text(content, encoding="utf-8")
    print(f"wrote {path.relative_to(EXAMPLES_DIR.parents[1])}")


def generate_advisory() -> None:
    report = AdvisoryReport(
        executive_summary=(
            "CVE-2024-3400 is a critical, actively exploited command-injection vulnerability "
            "in the GlobalProtect feature of PAN-OS. Unauthenticated attackers can achieve "
            "remote code execution on internet-facing firewalls. Given confirmed exploitation "
            "and CISA KEV listing, patch on an emergency timeline."
        ),
        immediate_actions=[
            ImmediateAction(priority="Critical", action="Apply the PAN-OS hotfix to all affected firewalls", owner="Network Security"),
            ImmediateAction(priority="Critical", action="Hunt for indicators of compromise in GlobalProtect logs", owner="SOC"),
            ImmediateAction(priority="High", action="Rotate credentials and API keys exposed to affected devices", owner="IT Operations"),
        ],
        technical_recommendations=[
            TechnicalRecommendation(recommendation="Disable device telemetry until patched where hotfix is unavailable", rationale="Removes the exploitation precondition on unpatched versions."),
            TechnicalRecommendation(recommendation="Restrict management interface exposure to a trusted jump host", rationale="Reduces the attack surface for the unauthenticated vector."),
        ],
        detection_opportunities=[
            DetectionOpportunity(detection_type="IDS/IPS signature", data_source="Perimeter network traffic", logic="Alert on crafted GlobalProtect requests matching the known exploit pattern."),
            DetectionOpportunity(detection_type="EDR alert", data_source="Firewall shell/telemetry logs", logic="Alert on unexpected child processes spawned by the GlobalProtect service."),
        ],
        long_term_improvements=[
            "Establish an emergency patch SLA for internet-facing security appliances.",
            "Implement continuous external attack-surface monitoring.",
            "Adopt configuration hardening baselines for perimeter devices.",
        ],
    )
    markdown = MarkdownAdvisoryRenderer().render(report)
    _write("advisory-report-CVE-2024-3400.md", markdown)


def generate_industry_briefing() -> None:
    report = IndustryIntelligenceAgent().generate_report("Financial Services")

    def section(title: str, items: list[str]) -> str:
        body = "\n".join(f"- {item}" for item in items)
        return f"## {title}\n\n{body}\n"

    md = (
        f"# Industry Security Briefing — {report['industry']}\n\n"
        f"## Executive Briefing\n\n{report['executive_summary']}\n\n"
        + section("Top Threats", report["top_threats"])
        + "\n"
        + section("APT Threat Actors", report["apt_threat_actors"])
        + "\n"
        + section("Attack Patterns", report["common_attack_types"])
        + "\n"
        + section("Recommended Controls", report["recommended_controls"])
        + "\n"
        + section("Business Priorities", report["business_impact"])
    )
    _write("industry-briefing-financial-services.md", md)


def generate_sbom_analysis() -> None:
    result = SBOMAnalysisService().analyze(SAMPLE_SBOM)
    _write("sbom-analysis-sample.json", json.dumps(result, indent=2) + "\n")


def main() -> None:
    EXAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    generate_advisory()
    generate_industry_briefing()
    generate_sbom_analysis()


if __name__ == "__main__":
    main()
