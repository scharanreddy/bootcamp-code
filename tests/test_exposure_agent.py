import unittest

from threatlens_ai.agent.exposure_agent import ExposureAgent, ExposureAgentError

SAMPLE_SBOM = {
    "components": [
        {"name": "app-gateway", "version": "1.0.0", "type": "application", "supplier": {"name": "Acme"}},
        {"name": "auth-service", "version": "2.1.0", "type": "service", "supplier": {"name": "Acme"}},
        {"name": "openssl", "version": "3.0.0", "type": "library", "supplier": {"name": "OpenSSL Foundation"}},
    ]
}


class TestExposureAgent(unittest.TestCase):
    def setUp(self) -> None:
        self.agent = ExposureAgent()

    def test_analyze_derives_exposure_from_sbom_components(self) -> None:
        exposure = self.agent.analyze(SAMPLE_SBOM)

        self.assertEqual(exposure.exposed_assets, 3)
        self.assertEqual(exposure.public_services, 2)
        self.assertTrue(exposure.third_party_exposure)
        self.assertTrue(exposure.internet_exposed)
        self.assertEqual(exposure.data_sensitivity, "low")

    def test_analyze_handles_empty_sbom(self) -> None:
        exposure = self.agent.analyze({"components": []})

        self.assertEqual(exposure.exposed_assets, 0)
        self.assertFalse(exposure.internet_exposed)
        self.assertFalse(exposure.third_party_exposure)

    def test_analyze_flags_single_supplier_as_no_third_party_exposure(self) -> None:
        sbom = {
            "components": [
                {"name": "internal-lib", "version": "1.0.0", "type": "library", "supplier": {"name": "Acme"}},
            ]
        }

        exposure = self.agent.analyze(sbom)

        self.assertFalse(exposure.third_party_exposure)

    def test_analyze_raises_on_invalid_payload(self) -> None:
        with self.assertRaises(ExposureAgentError):
            self.agent.analyze("not json or xml")


if __name__ == "__main__":
    unittest.main()
