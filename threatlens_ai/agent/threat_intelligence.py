from __future__ import annotations

import json
import re
from typing import Any

from app.config import settings
from app.services.cisa import CISAService, CISAServiceError, CVEItem
from app.services.nvd import NVDService, NVDServiceError, NVDVulnerability
from app.utils.logger import get_logger

logger = get_logger(__name__)

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class ThreatIntelligenceAgentError(RuntimeError):
    """Raised when threat intelligence report generation fails."""


class InvalidCVEError(ValueError):
    """Raised when a CVE identifier is malformed."""


class ThreatIntelligenceAgent:
    """Agent that merges CISA KEV and NVD data, then generates a report with OpenAI."""

    def __init__(
        self,
        cisa_service: CISAService,
        nvd_service: NVDService,
        model: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.cisa_service = cisa_service
        self.nvd_service = nvd_service
        self.model = model or settings.openai_model
        self.api_key = api_key or settings.openai_api_key

    def generate_report(self, cve: str) -> dict[str, Any]:
        """Generate a structured threat intelligence report for a CVE."""
        cve_id = self._normalize_cve(cve)
        logger.debug("Generating threat intelligence report for %s.", cve_id)

        cisa_item = self._get_cisa_item(cve_id)
        nvd_item = self._get_nvd_item(cve_id)
        merged_intelligence = self._merge_intelligence(cve_id, cisa_item, nvd_item)
        generated_report = self._generate_with_openai(merged_intelligence)

        return {
            "cve": cve_id,
            "model": self.model,
            "merged_intelligence": merged_intelligence,
            **generated_report,
        }

    def _get_cisa_item(self, cve_id: str) -> CVEItem | None:
        try:
            return self.cisa_service.find_cve(cve_id)
        except CISAServiceError:
            raise
        except Exception as error:
            raise ThreatIntelligenceAgentError("Unexpected CISA KEV lookup failure") from error

    def _get_nvd_item(self, cve_id: str) -> NVDVulnerability:
        try:
            return self.nvd_service.get_cve(cve_id)
        except NVDServiceError:
            raise
        except Exception as error:
            raise ThreatIntelligenceAgentError("Unexpected NVD lookup failure") from error

    def _merge_intelligence(
        self,
        cve_id: str,
        cisa_item: CVEItem | None,
        nvd_item: NVDVulnerability,
    ) -> dict[str, Any]:
        affected_products = [
            product.model_dump(mode="json")
            for product in nvd_item.affected_products
        ]
        references = [
            reference.model_dump(mode="json")
            for reference in nvd_item.references
        ]

        return {
            "cve": cve_id,
            "is_known_exploited": cisa_item is not None,
            "vendor": cisa_item.vendor_project if cisa_item else self._first_value(affected_products, "vendor"),
            "product": cisa_item.product if cisa_item else self._first_value(affected_products, "product"),
            "severity": nvd_item.cvss.severity if nvd_item.cvss else cisa_item.severity if cisa_item else None,
            "cvss": nvd_item.cvss.model_dump(mode="json") if nvd_item.cvss else None,
            "description": nvd_item.description or (cisa_item.short_description if cisa_item else None),
            "published_date": nvd_item.published_date,
            "last_modified_date": nvd_item.last_modified_date,
            "cisa_kev": self._serialize_cisa_item(cisa_item),
            "nvd": {
                "cwe": nvd_item.cwe,
                "affected_products": affected_products,
                "references": references,
            },
        }

    def _generate_with_openai(self, merged_intelligence: dict[str, Any]) -> dict[str, Any]:
        try:
            from openai import OpenAI
        except ImportError as error:
            raise ThreatIntelligenceAgentError(
                "OpenAI SDK is not installed. Install dependencies from requirements.txt."
            ) from error

        client = OpenAI(api_key=self.api_key)
        prompt = (
            "Generate a concise threat intelligence report from the merged CVE data. "
            "Use only the facts in the supplied JSON. If a field is missing, avoid inventing specifics. "
            "Return JSON matching the schema exactly."
        )

        try:
            response = client.responses.create(
                model=self.model,
                input=[
                    {
                        "role": "system",
                        "content": "You are a senior cyber threat intelligence analyst.",
                    },
                    {
                        "role": "user",
                        "content": f"{prompt}\n\nMerged CVE data:\n{json.dumps(merged_intelligence)}",
                    },
                ],
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "threat_intelligence_report",
                        "schema": self._report_schema(),
                        "strict": True,
                    }
                },
            )
        except Exception as error:
            raise ThreatIntelligenceAgentError("OpenAI report generation failed") from error

        return self._parse_openai_json(response)

    @staticmethod
    def _parse_openai_json(response: Any) -> dict[str, Any]:
        output_text = getattr(response, "output_text", None)
        if not output_text:
            output_text = ThreatIntelligenceAgent._extract_output_text(response)

        if not output_text:
            raise ThreatIntelligenceAgentError("OpenAI response did not include report JSON")

        try:
            parsed = json.loads(output_text)
        except json.JSONDecodeError as error:
            raise ThreatIntelligenceAgentError("OpenAI response was not valid JSON") from error

        if not isinstance(parsed, dict):
            raise ThreatIntelligenceAgentError("OpenAI response JSON was not an object")
        return parsed

    @staticmethod
    def _extract_output_text(response: Any) -> str | None:
        output = getattr(response, "output", None)
        if not output:
            return None

        chunks: list[str] = []
        for item in output:
            for content in getattr(item, "content", []) or []:
                text = getattr(content, "text", None)
                if text:
                    chunks.append(text)
        return "\n".join(chunks) if chunks else None

    @staticmethod
    def _report_schema() -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "executive_summary": {"type": "string"},
                "technical_summary": {"type": "string"},
                "business_impact": {"type": "string"},
                "likely_attack_scenario": {"type": "string"},
                "immediate_recommendations": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": [
                "executive_summary",
                "technical_summary",
                "business_impact",
                "likely_attack_scenario",
                "immediate_recommendations",
            ],
        }

    @staticmethod
    def _normalize_cve(cve: str) -> str:
        cve_id = cve.strip().upper()
        if not CVE_PATTERN.fullmatch(cve_id):
            raise InvalidCVEError("CVE must use the format CVE-YYYY-NNNN.")
        return cve_id

    @staticmethod
    def _serialize_cisa_item(cisa_item: CVEItem | None) -> dict[str, Any] | None:
        if cisa_item is None:
            return None
        return {
            "vendor": cisa_item.vendor_project,
            "product": cisa_item.product,
            "vulnerability_name": cisa_item.vulnerability_name,
            "date_added": cisa_item.date_added,
            "description": cisa_item.short_description,
            "required_action": cisa_item.required_action,
            "notes": cisa_item.notes,
        }

    @staticmethod
    def _first_value(items: list[dict[str, Any]], key: str) -> str | None:
        for item in items:
            value = item.get(key)
            if value:
                return str(value)
        return None
