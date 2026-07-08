from __future__ import annotations

from typing import Any

from app.services.cyclonedx import CycloneDXComponent, CycloneDXParseError, parse_cyclonedx
from app.services.risk import ExposureAnalysis
from app.utils.logger import get_logger

logger = get_logger(__name__)

SBOMPayload = str | bytes | dict[str, Any]

_INTERNET_FACING_TYPES = {"application", "service", "container"}
_LOW_ASSET_THRESHOLD = 5
_HIGH_ASSET_THRESHOLD = 25


class ExposureAgentError(RuntimeError):
    """Raised when SBOM-based exposure analysis fails."""


class ExposureAgent:
    """Agent that derives an exposure profile from an SBOM (CycloneDX) document.

    The heuristics here are intentionally simple: component count is used as a
    proxy for attack surface, distinct suppliers as a proxy for third-party
    exposure, and component type as a proxy for internet-facing services.
    """

    def analyze(self, sbom: SBOMPayload) -> ExposureAnalysis:
        """Parse an SBOM payload and derive an exposure analysis from it."""
        try:
            components = parse_cyclonedx(sbom)
        except CycloneDXParseError as error:
            raise ExposureAgentError("Failed to parse SBOM for exposure analysis") from error

        return self.analyze_components(components)

    def analyze_components(self, components: list[CycloneDXComponent]) -> ExposureAnalysis:
        """Derive an exposure analysis from already-parsed CycloneDX components."""
        exposure = self._derive_exposure(components)
        logger.debug(
            "Derived exposure analysis from %d SBOM components: %s",
            len(components),
            exposure.model_dump(mode="json"),
        )
        return exposure

    @staticmethod
    def _derive_exposure(components: list[CycloneDXComponent]) -> ExposureAnalysis:
        exposed_assets = len(components)
        suppliers = {c.supplier for c in components if c.supplier}
        third_party_exposure = len(suppliers) > 1
        public_services = sum(
            1
            for component in components
            if (component.component_type or "").lower() in _INTERNET_FACING_TYPES
        )

        if exposed_assets > _HIGH_ASSET_THRESHOLD:
            data_sensitivity = "high"
        elif exposed_assets > _LOW_ASSET_THRESHOLD:
            data_sensitivity = "medium"
        else:
            data_sensitivity = "low"

        return ExposureAnalysis(
            internet_exposed=public_services > 0,
            public_services=public_services,
            exposed_assets=exposed_assets,
            third_party_exposure=third_party_exposure,
            data_sensitivity=data_sensitivity,
        )


def recommend_from_exposure(
    components: list[CycloneDXComponent],
    exposure: ExposureAnalysis,
) -> list[str]:
    """Derive deterministic, exposure-driven remediation recommendations.

    Pure function (no I/O) so it is straightforward to unit test.
    """
    if not components:
        return [
            "The SBOM contained no components; verify it is a valid CycloneDX document "
            "before relying on this analysis."
        ]

    recommendations = [
        "Cross-reference each component and version against CISA KEV and the NVD to "
        "identify known exploited vulnerabilities."
    ]

    if exposure.internet_exposed or exposure.public_services:
        recommendations.append(
            f"Place the {exposure.public_services} internet-facing service(s) behind a "
            "gateway or WAF and minimize their public attack surface."
        )
    if exposure.third_party_exposure:
        recommendations.append(
            "Review third-party and supplier components for provenance, maintenance "
            "status, and supply-chain risk."
        )
    if exposure.data_sensitivity in {"high", "critical"}:
        recommendations.append(
            "Apply stricter change control and monitoring given the high data "
            "sensitivity of the affected systems."
        )

    recommendations.append(
        f"Establish a patch-management cadence to keep the {exposure.exposed_assets} "
        "tracked component(s) current."
    )
    return recommendations
