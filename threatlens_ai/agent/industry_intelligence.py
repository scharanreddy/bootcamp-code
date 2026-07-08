from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.utils.logger import get_logger

logger = get_logger(__name__)

INDUSTRY_DATA_PATH = Path(__file__).resolve().parents[2] / "app" / "data" / "industries.json"


class IndustryNotFoundError(ValueError):
    """Raised when requested industry intelligence is not available."""


class IndustryIntelligenceAgent:
    """Agent for generating industry-specific security reports."""

    def __init__(self, data_path: Path = INDUSTRY_DATA_PATH) -> None:
        self.data_path = data_path
        self._industries: dict[str, dict[str, Any]] | None = None

    def generate_report(self, industry: str) -> dict[str, Any]:
        """Generate an executive security report for the requested industry."""
        industry_data = self._find_industry(industry)
        name = industry_data["name"]
        critical_assets = industry_data["critical_assets"]
        common_threats = industry_data["common_threats"]
        security_priorities = industry_data["security_priorities"]
        common_attack_types = industry_data["common_attack_types"]

        logger.debug("Generating industry intelligence report for %s.", name)
        return {
            "industry": name,
            "executive_summary": (
                f"{name} organizations should prioritize protection of "
                f"{self._join_items(critical_assets[:3])}. The most relevant threat themes are "
                f"{self._join_items(common_threats[:3])}, requiring controls aligned to "
                f"{self._join_items(security_priorities[:3])}."
            ),
            "top_threats": common_threats,
            "current_risks": [
                f"Exposure of {asset.lower()} could disrupt operations or expose sensitive data."
                for asset in critical_assets
            ],
            "recommended_controls": security_priorities,
            "business_impact": [
                "Operational disruption and service downtime",
                "Regulatory, contractual, or compliance exposure",
                "Loss of customer, citizen, patient, or partner trust",
                "Financial impact from incident response, fraud, recovery, and remediation",
            ],
            "common_attack_types": common_attack_types,
        }

    def _find_industry(self, industry: str) -> dict[str, Any]:
        industries = self._load_industries()
        normalized = industry.strip().lower()
        if not normalized:
            raise IndustryNotFoundError("Industry is required.")

        try:
            return industries[normalized]
        except KeyError as error:
            raise IndustryNotFoundError(f"Industry '{industry}' is not supported.") from error

    def _load_industries(self) -> dict[str, dict[str, Any]]:
        if self._industries is not None:
            return self._industries

        with self.data_path.open(encoding="utf-8") as data_file:
            payload = json.load(data_file)

        industries = payload.get("industries", [])
        self._industries = {
            item["name"].strip().lower(): item
            for item in industries
            if isinstance(item, dict) and item.get("name")
        }
        return self._industries

    @staticmethod
    def _join_items(items: list[str]) -> str:
        if not items:
            return "the most critical business assets"
        if len(items) == 1:
            return items[0]
        return f"{', '.join(items[:-1])}, and {items[-1]}"
