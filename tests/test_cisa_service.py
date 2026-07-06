import time
import unittest
from unittest.mock import patch

import httpx

from app.services.cisa import CISAService, CISAServiceError


SAMPLE_CATALOG = {
    "catalog": {
        "lastModified": "2026-07-06T00:00:00Z",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "ExampleCorp",
                "product": "ExampleProduct",
                "vulnerabilityName": "Example vulnerability",
                "dateAdded": "2026-07-06",
                "shortDescription": "Example description.",
                "requiredAction": "Apply patch.",
                "notes": "Example note.",
            },
            {
                "cveID": "CVE-2026-0002",
                "vendorProject": "ExampleCorp",
                "product": "ExampleProduct",
                "vulnerabilityName": "Second example vulnerability",
                "dateAdded": "2026-07-07",
                "shortDescription": "Second description.",
                "requiredAction": "Update software.",
                "notes": "Second note.",
            },
        ],
    }
}


def make_response(status_code: int, json_data: dict[str, object]) -> httpx.Response:
    request = httpx.Request("GET", "https://example.com/kev.json")
    return httpx.Response(status_code, json=json_data, request=request)


class TestCISAService(unittest.TestCase):
    def setUp(self) -> None:
        self.service = CISAService(catalog_url="https://example.com/kev.json", cache_ttl=1)

    def test_get_catalog_returns_catalog(self) -> None:
        with patch("app.services.cisa.httpx.Client.get") as mocked_get:
            mocked_get.return_value = make_response(200, SAMPLE_CATALOG)
            catalog = self.service.get_catalog()

        self.assertEqual(len(catalog.catalog.vulnerabilities), 2)
        self.assertEqual(catalog.catalog.vulnerabilities[0].cve_id, "CVE-2026-0001")

    def test_find_cve_returns_matching_item(self) -> None:
        with patch("app.services.cisa.httpx.Client.get") as mocked_get:
            mocked_get.return_value = make_response(200, SAMPLE_CATALOG)
            item = self.service.find_cve("cve-2026-0002")

        self.assertIsNotNone(item)
        self.assertEqual(item.cve_id, "CVE-2026-0002")
        self.assertEqual(item.required_action, "Update software.")

    def test_find_cve_returns_none_for_missing_item(self) -> None:
        with patch("app.services.cisa.httpx.Client.get") as mocked_get:
            mocked_get.return_value = make_response(200, SAMPLE_CATALOG)
            item = self.service.find_cve("CVE-2026-9999")

        self.assertIsNone(item)

    def test_get_latest_returns_most_recent_items(self) -> None:
        with patch("app.services.cisa.httpx.Client.get") as mocked_get:
            mocked_get.return_value = make_response(200, SAMPLE_CATALOG)
            latest = self.service.get_latest(limit=1)

        self.assertEqual(len(latest), 1)
        self.assertEqual(latest[0].cve_id, "CVE-2026-0002")

    def test_get_catalog_uses_cached_data(self) -> None:
        with patch("app.services.cisa.httpx.Client.get") as mocked_get:
            mocked_get.return_value = make_response(200, SAMPLE_CATALOG)
            first = self.service.get_catalog()
            mocked_get.reset_mock()
            second = self.service.get_catalog()

        mocked_get.assert_not_called()
        self.assertIs(second, first)

    def test_get_catalog_returns_cached_data_on_network_failure(self) -> None:
        with patch("app.services.cisa.httpx.Client.get") as mocked_get:
            mocked_get.side_effect = [
                make_response(200, SAMPLE_CATALOG),
                httpx.HTTPError("network failure"),
            ]
            first = self.service.get_catalog()
            self.service._cache_expiry = time.monotonic() - 1
            second = self.service.get_catalog()

        self.assertIs(second, first)

    def test_get_catalog_raises_error_when_no_cache_and_network_fails(self) -> None:
        service = CISAService(catalog_url="https://example.com/kev.json", cache_ttl=1)
        with patch("app.services.cisa.httpx.Client.get") as mocked_get:
            mocked_get.side_effect = httpx.HTTPError("network failure")
            with self.assertRaises(CISAServiceError):
                service.get_catalog()


if __name__ == "__main__":
    unittest.main()
