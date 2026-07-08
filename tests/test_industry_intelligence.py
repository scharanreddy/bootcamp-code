import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from threatlens_ai.agent.industry_intelligence import IndustryIntelligenceAgent
from threatlens_ai.backend.api.dependencies import get_industry_intelligence_agent
from threatlens_ai.backend.api.routes import router
from threatlens_ai.frontend.constants import INDUSTRY_INTELLIGENCE_OPTIONS

REQUIRED_INDUSTRIES = ["Retail", "Healthcare", "Government", "Financial Services", "Technology"]


def make_client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_industry_intelligence_agent] = IndustryIntelligenceAgent
    return TestClient(app)


class TestIndustryReportExposesAttackPatterns(unittest.TestCase):
    def test_route_returns_common_attack_types(self) -> None:
        response = make_client().post("/industry/report", json={"industry": "Healthcare"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("common_attack_types", body)
        self.assertTrue(body["common_attack_types"], "attack patterns should not be empty")

    def test_agent_output_matches_all_five_display_sections(self) -> None:
        report = IndustryIntelligenceAgent().generate_report("Financial Services")

        # Executive Briefing, Top Threats, Attack Patterns, Recommended Controls, Business Priorities
        self.assertTrue(report["executive_summary"])
        self.assertTrue(report["top_threats"])
        self.assertTrue(report["common_attack_types"])
        self.assertTrue(report["recommended_controls"])
        self.assertTrue(report["business_impact"])


class TestIndustryIntelligencePageOptions(unittest.TestCase):
    def test_page_offers_exactly_the_requested_industries(self) -> None:
        self.assertEqual(INDUSTRY_INTELLIGENCE_OPTIONS, REQUIRED_INDUSTRIES)


if __name__ == "__main__":
    unittest.main()
