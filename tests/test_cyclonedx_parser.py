import tempfile
import unittest
from pathlib import Path

from app.services.cyclonedx import (
    CycloneDXParseError,
    parse_cyclonedx,
    parse_cyclonedx_file,
)


class TestCycloneDXParser(unittest.TestCase):
    def test_parse_json_components(self) -> None:
        payload = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "type": "library",
                    "name": "fastapi",
                    "version": "0.115.0",
                    "supplier": {"name": "FastAPI"},
                    "purl": "pkg:pypi/fastapi@0.115.0",
                },
                {
                    "type": "library",
                    "name": "httpx",
                    "version": "0.28.1",
                    "supplier": "Encode",
                    "purl": "pkg:pypi/httpx@0.28.1",
                },
            ],
        }

        components = parse_cyclonedx(payload)

        self.assertEqual(len(components), 2)
        self.assertEqual(components[0].software_name, "fastapi")
        self.assertEqual(components[0].version, "0.115.0")
        self.assertEqual(components[0].supplier, "FastAPI")
        self.assertEqual(components[0].package_url, "pkg:pypi/fastapi@0.115.0")
        self.assertEqual(components[1].supplier, "Encode")

    def test_parse_xml_components_with_namespace(self) -> None:
        payload = """<?xml version="1.0" encoding="UTF-8"?>
        <bom xmlns="http://cyclonedx.org/schema/bom/1.5" bomFormat="CycloneDX" specVersion="1.5">
          <components>
            <component type="library">
              <supplier>
                <name>Python Packaging Authority</name>
              </supplier>
              <name>pip</name>
              <version>25.0</version>
              <purl>pkg:pypi/pip@25.0</purl>
            </component>
          </components>
        </bom>
        """

        components = parse_cyclonedx(payload)

        self.assertEqual(len(components), 1)
        self.assertEqual(components[0].software_name, "pip")
        self.assertEqual(components[0].version, "25.0")
        self.assertEqual(components[0].supplier, "Python Packaging Authority")
        self.assertEqual(components[0].package_url, "pkg:pypi/pip@25.0")

    def test_missing_optional_fields_return_none(self) -> None:
        components = parse_cyclonedx(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {
                        "name": "internal-service",
                    }
                ],
            }
        )

        self.assertEqual(components[0].software_name, "internal-service")
        self.assertIsNone(components[0].version)
        self.assertIsNone(components[0].supplier)
        self.assertIsNone(components[0].package_url)

    def test_parse_file(self) -> None:
        payload = '{"bomFormat": "CycloneDX", "components": [{"name": "uvicorn", "version": "0.35.0"}]}'

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bom.json"
            path.write_text(payload, encoding="utf-8")

            components = parse_cyclonedx_file(path)

        self.assertEqual(len(components), 1)
        self.assertEqual(components[0].software_name, "uvicorn")
        self.assertEqual(components[0].version, "0.35.0")

    def test_invalid_payload_raises_parse_error(self) -> None:
        with self.assertRaises(CycloneDXParseError):
            parse_cyclonedx("not-json-or-xml")

    def test_non_list_json_components_raises_parse_error(self) -> None:
        with self.assertRaises(CycloneDXParseError):
            parse_cyclonedx({"bomFormat": "CycloneDX", "components": {"name": "bad"}})


if __name__ == "__main__":
    unittest.main()
