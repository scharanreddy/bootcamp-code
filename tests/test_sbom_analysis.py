import json
import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services.cyclonedx import parse_cyclonedx
from app.services.risk import ExposureAnalysis
from threatlens_ai.agent.exposure_agent import recommend_from_exposure
from threatlens_ai.backend.api.routes import router
from threatlens_ai.backend.services.sbom_service import SBOMAnalysisService

SAMPLE_SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "application",
                "name": "web-portal",
                "version": "3.2.1",
                "supplier": {"name": "Acme"},
                "purl": "pkg:generic/web-portal@3.2.1",
            },
            {
                "type": "library",
                "name": "openssl",
                "version": "3.0.0",
                "supplier": {"name": "OpenSSL Foundation"},
            },
            {"type": "service", "name": "auth-svc", "version": "1.0.0", "supplier": {"name": "Acme"}},
        ],
    }
)


class TestSBOMAnalysisService(unittest.TestCase):
    def setUp(self) -> None:
        self.service = SBOMAnalysisService()

    def test_analyze_enumerates_components_and_applications(self) -> None:
        result = self.service.analyze(SAMPLE_SBOM)

        self.assertEqual(result["component_count"], 3)
        self.assertEqual(result["application_count"], 1)
        self.assertEqual(result["applications"][0]["software_name"], "web-portal")
        self.assertTrue(result["recommendations"])
        self.assertIn("exposure_analysis", result)

    def test_analyze_derives_exposure_profile(self) -> None:
        exposure = self.service.analyze(SAMPLE_SBOM)["exposure_analysis"]

        self.assertEqual(exposure["exposed_assets"], 3)
        self.assertEqual(exposure["public_services"], 2)  # application + service
        self.assertTrue(exposure["third_party_exposure"])


class TestRecommendFromExposure(unittest.TestCase):
    def test_empty_sbom_returns_validation_hint(self) -> None:
        exposure = ExposureAnalysis()
        recommendations = recommend_from_exposure([], exposure)

        self.assertEqual(len(recommendations), 1)
        self.assertIn("no components", recommendations[0])

    def test_internet_and_third_party_exposure_add_recommendations(self) -> None:
        components = parse_cyclonedx(SAMPLE_SBOM)
        exposure = ExposureAnalysis(
            internet_exposed=True,
            public_services=2,
            exposed_assets=3,
            third_party_exposure=True,
            data_sensitivity="high",
        )

        recommendations = recommend_from_exposure(components, exposure)
        joined = " ".join(recommendations)

        self.assertIn("internet-facing", joined)
        self.assertIn("third-party", joined)
        self.assertIn("data sensitivity", joined)


class TestSBOMRoutes(unittest.TestCase):
    def setUp(self) -> None:
        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)

    def test_analyze_endpoint_returns_full_analysis(self) -> None:
        response = self.client.post("/sbom/analyze", json={"sbom": SAMPLE_SBOM})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["component_count"], 3)
        self.assertEqual(body["application_count"], 1)

    def test_invalid_sbom_returns_422(self) -> None:
        response = self.client.post("/sbom/analyze", json={"sbom": "not json or xml"})

        self.assertEqual(response.status_code, 422)
        self.assertIn("CycloneDX", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
