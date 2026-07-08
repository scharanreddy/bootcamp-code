from __future__ import annotations

from typing import Any

from app.services.cyclonedx import CycloneDXComponent, parse_cyclonedx
from app.utils.logger import get_logger
from threatlens_ai.agent.exposure_agent import ExposureAgent, recommend_from_exposure

logger = get_logger(__name__)

_APPLICATION_TYPE = "application"


class SBOMAnalysisService:
    """Composes SBOM parsing, exposure analysis, and recommendations.

    Keeps the API route thin: it parses the CycloneDX document once and hands the
    resulting components to the injected Exposure Agent, then derives remediation
    recommendations from the exposure profile.
    """

    def __init__(self, exposure_agent: ExposureAgent | None = None) -> None:
        self.exposure_agent = exposure_agent or ExposureAgent()

    def analyze(self, sbom_content: str) -> dict[str, Any]:
        """Analyze a raw CycloneDX SBOM document.

        Raises:
            CycloneDXParseError: if the SBOM cannot be parsed.
        """
        components = parse_cyclonedx(sbom_content)
        exposure = self.exposure_agent.analyze_components(components)
        applications = [
            component
            for component in components
            if (component.component_type or "").strip().lower() == _APPLICATION_TYPE
        ]
        recommendations = recommend_from_exposure(components, exposure)

        logger.info(
            "Analyzed SBOM with %d components (%d applications).",
            len(components),
            len(applications),
        )
        return {
            "component_count": len(components),
            "application_count": len(applications),
            "components": [self._component_dict(component) for component in components],
            "applications": [self._component_dict(component) for component in applications],
            "exposure_analysis": exposure.model_dump(mode="json"),
            "recommendations": recommendations,
        }

    @staticmethod
    def _component_dict(component: CycloneDXComponent) -> dict[str, Any]:
        return component.model_dump(mode="json")
