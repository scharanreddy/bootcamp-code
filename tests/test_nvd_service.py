import os
import unittest
from unittest.mock import patch

import httpx

os.environ.setdefault("OPENAI_API_KEY", "test-openai")
os.environ.setdefault("NVD_API_KEY", "test-nvd")

from app.services.nvd import NVDService, NVDServiceError


# Mirrors the real NVD 2.0 response shape: published/lastModified/configurations
# are nested under `cve`, configurations is a list, and the CPE is under `criteria`.
SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-1234",
                "published": "2026-07-01T12:00Z",
                "lastModified": "2026-07-02T12:00Z",
                "descriptions": [
                    {"lang": "en", "value": "Example description."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 7.5,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseSeverity": "HIGH",
                            },
                        }
                    ]
                },
                "references": [
                    {"url": "https://example.com", "description": "Vendor advisory"}
                ],
                "weaknesses": [
                    {"description": [{"value": "CWE-79", "lang": "en"}]}
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:examplecorp:exampleproduct:1.0:*:*:*:*:*:*:*",
                                        "vulnerable": True,
                                    }
                                ]
                            }
                        ]
                    }
                ],
            },
        }
    ]
}


def make_response(status_code: int, json_data: dict[str, object]) -> httpx.Response:
    request = httpx.Request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    return httpx.Response(status_code, json=json_data, request=request)


class TestNVDService(unittest.TestCase):
    def setUp(self) -> None:
        self.service = NVDService(api_key="test-api-key", max_retries=2, backoff_seconds=0.0)

    def test_get_cve_returns_normalized_model(self) -> None:
        with patch("app.services.nvd.httpx.Client.get") as mocked_get:
            mocked_get.return_value = make_response(200, SAMPLE_NVD_RESPONSE)
            vulnerability = self.service.get_cve("CVE-2026-1234")

        self.assertEqual(vulnerability.cve_id, "CVE-2026-1234")
        self.assertEqual(vulnerability.description, "Example description.")
        self.assertEqual(vulnerability.cvss.base_score, 7.5)
        self.assertEqual(vulnerability.cvss.severity, "HIGH")
        self.assertEqual(vulnerability.cvss.vector_string, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(vulnerability.references[0].url, "https://example.com")
        self.assertEqual(vulnerability.affected_products[0].cpe_uri, "cpe:2.3:a:examplecorp:exampleproduct:1.0:*:*:*:*:*:*:*")
        self.assertEqual(vulnerability.cwe, ["CWE-79"])
        self.assertEqual(vulnerability.published_date, "2026-07-01T12:00Z")
        self.assertEqual(vulnerability.last_modified_date, "2026-07-02T12:00Z")

    def test_get_cve_retries_and_succeeds(self) -> None:
        with patch("app.services.nvd.httpx.Client.get") as mocked_get:
            mocked_get.side_effect = [
                httpx.HTTPStatusError(
                    "error",
                    request=httpx.Request("GET", "https://api.nvd.nist.gov/vuln/v2"),
                    response=make_response(503, {}),
                ),
                make_response(200, SAMPLE_NVD_RESPONSE),
            ]
            vulnerability = self.service.get_cve("CVE-2026-1234")

        self.assertEqual(vulnerability.cve_id, "CVE-2026-1234")
        self.assertEqual(mocked_get.call_count, 2)

    def test_get_cve_raises_if_not_found(self) -> None:
        with patch("app.services.nvd.httpx.Client.get") as mocked_get:
            mocked_get.return_value = make_response(200, {"vulnerabilities": []})
            with self.assertRaises(NVDServiceError):
                self.service.get_cve("CVE-2026-9999")

    def test_get_cve_raises_after_retries(self) -> None:
        with patch("app.services.nvd.httpx.Client.get") as mocked_get:
            mocked_get.side_effect = httpx.RequestError("connection failed", request=httpx.Request("GET", "https://api.nvd.nist.gov/vuln/v2"))
            with self.assertRaises(NVDServiceError):
                self.service.get_cve("CVE-2026-1234")
            self.assertEqual(mocked_get.call_count, 2)


if __name__ == "__main__":
    unittest.main()
