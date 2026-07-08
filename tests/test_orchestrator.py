import unittest

from app.services.risk import ExposureAnalysis, RiskAssessment, RiskBreakdown
from threatlens_ai.agent.orchestrator import LangGraphOrchestrator


def make_threat_report(cve: str = "CVE-2026-0001") -> dict:
    return {
        "cve": cve,
        "model": "stub-model",
        "merged_intelligence": {
            "cve": cve,
            "is_known_exploited": True,
            "severity": "CRITICAL",
            "cvss": {"version": "3.1", "base_score": 9.8, "severity": "CRITICAL"},
            "description": "Stub vulnerability description.",
        },
        "executive_summary": "Stub executive summary.",
        "technical_summary": "Stub technical summary.",
        "business_impact": "Stub business impact.",
        "likely_attack_scenario": "Stub attack scenario.",
        "immediate_recommendations": ["Patch immediately"],
    }


def make_industry_report(industry: str) -> dict:
    return {
        "industry": industry,
        "executive_summary": "Stub industry summary.",
        "top_threats": ["Phishing"],
        "current_risks": ["Exposure of customer data"],
        "recommended_controls": ["MFA"],
        "business_impact": ["Regulatory exposure"],
    }


class StubThreatAgent:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[str] = []
        self.error = error

    def generate_report(self, cve: str) -> dict:
        self.calls.append(cve)
        if self.error:
            raise self.error
        return make_threat_report(cve)


class StubIndustryAgent:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def generate_report(self, industry: str) -> dict:
        self.calls.append(industry)
        return make_industry_report(industry)


class StubExposureAgent:
    def __init__(self) -> None:
        self.calls: list[object] = []

    def analyze(self, sbom: object) -> ExposureAnalysis:
        self.calls.append(sbom)
        return ExposureAnalysis(
            internet_exposed=True,
            public_services=2,
            exposed_assets=5,
            third_party_exposure=True,
            data_sensitivity="high",
        )


class StubRiskAgent:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def assess(self, threat_intelligence, industry_intelligence, exposure_analysis=None) -> RiskAssessment:
        self.calls.append((threat_intelligence, industry_intelligence, exposure_analysis))
        return RiskAssessment(
            overall_risk=9.1,
            priority="critical",
            business_impact=9.0,
            confidence=90.0,
            description="Stub risk description.",
            breakdown=RiskBreakdown(
                threat_score=9.0,
                exposure_score=8.0,
                industry_multiplier=1.2,
                business_impact=9.0,
                confidence=90.0,
            ),
        )


class StubAdvisorAgent:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def generate_advisory(self, threat_intelligence, risk_assessment=None, industry_intelligence=None) -> dict:
        self.calls.append((threat_intelligence, risk_assessment, industry_intelligence))
        return {
            "report": {
                "executive_summary": "Stub advisory summary.",
                "immediate_actions": [],
                "technical_recommendations": [],
                "detection_opportunities": [],
                "long_term_improvements": [],
            },
            "markdown": "# Security Advisory Report",
        }


def build_orchestrator() -> tuple[LangGraphOrchestrator, dict[str, object]]:
    agents = {
        "threat": StubThreatAgent(),
        "industry": StubIndustryAgent(),
        "exposure": StubExposureAgent(),
        "risk": StubRiskAgent(),
        "advisor": StubAdvisorAgent(),
    }
    orchestrator = LangGraphOrchestrator(
        threat_agent=agents["threat"],
        industry_agent=agents["industry"],
        exposure_agent=agents["exposure"],
        risk_agent=agents["risk"],
        advisor_agent=agents["advisor"],
    )
    return orchestrator, agents


class TestLangGraphOrchestrator(unittest.TestCase):
    def test_run_without_sbom_skips_exposure_agent(self) -> None:
        orchestrator, agents = build_orchestrator()

        final_state = orchestrator.run(cve="CVE-2026-0001", industry="Technology")

        self.assertEqual(agents["exposure"].calls, [])
        self.assertIsNone(final_state.get("exposure_analysis"))
        self.assertEqual(len(agents["risk"].calls), 1)
        self.assertIsNone(agents["risk"].calls[0][2])
        self.assertEqual(final_state["advisory"]["markdown"], "# Security Advisory Report")

    def test_run_with_sbom_invokes_exposure_agent(self) -> None:
        orchestrator, agents = build_orchestrator()
        sbom = {"components": [{"name": "openssl", "version": "3.0.0", "type": "library"}]}

        final_state = orchestrator.run(cve="CVE-2026-0001", industry="Technology", sbom=sbom)

        self.assertEqual(agents["exposure"].calls, [sbom])
        self.assertIsNotNone(final_state["exposure_analysis"])
        self.assertEqual(len(agents["risk"].calls), 1)
        self.assertIsNotNone(agents["risk"].calls[0][2])

    def test_run_without_industry_skips_industry_agent(self) -> None:
        orchestrator, agents = build_orchestrator()

        final_state = orchestrator.run(cve="CVE-2026-0001")

        self.assertEqual(agents["industry"].calls, [])
        self.assertIsNone(final_state["industry_intelligence"])
        # Risk Agent still runs with a fallback industry context.
        self.assertEqual(len(agents["risk"].calls), 1)

    def test_run_propagates_threat_agent_errors(self) -> None:
        agents = {
            "threat": StubThreatAgent(error=RuntimeError("nvd is down")),
            "industry": StubIndustryAgent(),
            "exposure": StubExposureAgent(),
            "risk": StubRiskAgent(),
            "advisor": StubAdvisorAgent(),
        }
        orchestrator = LangGraphOrchestrator(
            threat_agent=agents["threat"],
            industry_agent=agents["industry"],
            exposure_agent=agents["exposure"],
            risk_agent=agents["risk"],
            advisor_agent=agents["advisor"],
        )

        with self.assertRaises(RuntimeError):
            orchestrator.run(cve="CVE-2026-0001")

        self.assertEqual(agents["industry"].calls, [])


if __name__ == "__main__":
    unittest.main()
