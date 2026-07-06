import unittest

from app.services.risk import (
    ExposureAnalysis,
    IndustryIntelligence,
    RiskAgent,
    ThreatIntelligence,
)


class TestRiskAgent(unittest.TestCase):
    def setUp(self) -> None:
        self.agent = RiskAgent()

    def test_assess_returns_structured_json(self) -> None:
        threat = ThreatIntelligence(
            summary="Credential stuffing campaign targeting cloud assets.",
            severity="high",
            exploitability=8,
            prevalence=7,
            confidence=80,
        )
        industry = IndustryIntelligence(
            industry="Technology",
            revenue_sensitivity="high",
            regulatory_pressure="medium",
        )
        exposure = ExposureAnalysis(
            internet_exposed=True,
            public_services=3,
            exposed_assets=4,
            third_party_exposure=True,
            data_sensitivity="high",
        )

        assessment = self.agent.assess(threat, industry, exposure)

        self.assertEqual(assessment.priority, "critical")
        self.assertGreaterEqual(assessment.overall_risk, 8.0)
        self.assertGreaterEqual(assessment.business_impact, 8.0)
        self.assertGreaterEqual(assessment.confidence, 70.0)
        self.assertEqual(assessment.breakdown.threat_score, 7.55)
        self.assertEqual(assessment.breakdown.industry_multiplier, 1.35)

    def test_assess_defaults_exposure(self) -> None:
        threat = ThreatIntelligence(
            summary="Phishing campaign against employees.",
            severity="medium",
            exploitability=5,
            prevalence=5,
            confidence=60,
        )
        industry = IndustryIntelligence(
            industry="Retail",
            revenue_sensitivity="medium",
            regulatory_pressure="low",
        )

        assessment = self.agent.assess(threat, industry)

        self.assertEqual(assessment.priority, "medium")
        self.assertLess(assessment.overall_risk, 8.0)
        self.assertGreaterEqual(assessment.confidence, 60.0)
        self.assertEqual(assessment.breakdown.exposure_score, 0.0)

    def test_assess_handles_unknown_industry(self) -> None:
        threat = ThreatIntelligence(
            summary="New supply-chain threat observed.",
            severity="high",
            exploitability=9,
            prevalence=6,
            confidence=75,
        )
        industry = IndustryIntelligence(
            industry="Space Exploration",
            revenue_sensitivity="high",
            regulatory_pressure="high",
        )
        exposure = ExposureAnalysis(
            internet_exposed=False,
            public_services=1,
            exposed_assets=1,
            third_party_exposure=False,
            data_sensitivity="medium",
        )

        assessment = self.agent.assess(threat, industry, exposure)

        self.assertEqual(assessment.priority, "critical")
        self.assertGreater(assessment.breakdown.industry_multiplier, 1.0)


if __name__ == "__main__":
    unittest.main()
