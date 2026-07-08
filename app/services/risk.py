from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, root_validator, validator

from app.utils.logger import get_logger

logger = get_logger(__name__)

INDUSTRY_DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "industries.json"

SEVERITY_WEIGHTS = {
    "low": 2.5,
    "medium": 5.0,
    "high": 7.5,
    "critical": 9.5,
}

SENSITIVITY_WEIGHTS = {
    "low": 0.8,
    "medium": 1.0,
    "high": 1.2,
    "critical": 1.4,
}

PRIORITY_THRESHOLDS = [
    (8.0, "critical"),
    (6.0, "high"),
    (4.0, "medium"),
    (0.0, "low"),
]

DEFAULT_INDUSTRY_MULTIPLIERS = {
    "financial services": 1.3,
    "healthcare": 1.25,
    "government": 1.25,
    "technology": 1.2,
    "telecommunications": 1.2,
    "manufacturing": 1.15,
    "retail": 1.1,
    "education": 1.1,
}


def _load_industry_data() -> dict[str, dict[str, object]]:
    """Load industry intelligence from the local JSON dataset."""
    try:
        with INDUSTRY_DATA_PATH.open("r", encoding="utf-8") as stream:
            payload = json.load(stream)
            return {
                entry["name"].lower(): entry
                for entry in payload.get("industries", [])
                if "name" in entry
            }
    except FileNotFoundError:
        logger.warning("Industry intelligence dataset missing; using defaults.")
        return {}
    except json.JSONDecodeError as error:
        logger.warning("Could not parse industry intelligence dataset: %s", error)
        return {}


INDUSTRY_DATA = _load_industry_data()


class ThreatIntelligence(BaseModel):
    """Threat intelligence input for risk scoring."""

    summary: str = Field(..., description="Short summary of the threat intelligence.")
    severity: Literal["low", "medium", "high", "critical"] = Field(
        "medium", description="Severity of the threat intelligence." 
    )
    exploitability: int = Field(
        5,
        ge=1,
        le=10,
        description="Exploitability score from 1 (lowest) to 10 (highest).",
    )
    prevalence: int = Field(
        5,
        ge=1,
        le=10,
        description="Estimated prevalence or exploitation trend score.",
    )
    confidence: int = Field(
        70,
        ge=0,
        le=100,
        description="Confidence level in the threat intelligence as a percentage.",
    )

    @validator("summary")
    def summary_must_not_be_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("summary must not be empty")
        return value


class IndustryIntelligence(BaseModel):
    """Industry intelligence input for scoring risk."""

    industry: str = Field(..., description="Industry sector affected by the threat.")
    revenue_sensitivity: Literal["low", "medium", "high"] = Field(
        "medium",
        description="Estimated sensitivity to revenue or profitability impact.",
    )
    regulatory_pressure: Literal["low", "medium", "high"] = Field(
        "medium",
        description="Regulatory or compliance pressure for this industry.",
    )

    @validator("industry")
    def industry_must_not_be_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("industry must not be empty")
        return value


class ExposureAnalysis(BaseModel):
    """Optional exposure analysis input for risk scoring."""

    internet_exposed: bool = Field(
        False,
        description="Whether the impacted asset is directly exposed to the internet.",
    )
    public_services: int = Field(
        0,
        ge=0,
        description="Number of externally facing services or interfaces.",
    )
    exposed_assets: int = Field(
        0,
        ge=0,
        description="Number of exposed assets that could be impacted.",
    )
    third_party_exposure: bool = Field(
        False,
        description="Whether third-party integrations increase the exposure.",
    )
    data_sensitivity: Literal["low", "medium", "high", "critical"] = Field(
        "medium",
        description="Sensitivity of the data or systems affected.",
    )


class RiskBreakdown(BaseModel):
    """Detailed numeric breakdown of the risk assessment."""

    threat_score: float
    exposure_score: float
    industry_multiplier: float
    business_impact: float
    confidence: float


class RiskAssessment(BaseModel):
    """Structured risk assessment result."""

    overall_risk: float
    priority: Literal["low", "medium", "high", "critical"]
    business_impact: float
    confidence: float
    description: str
    breakdown: RiskBreakdown

    class Config:
        extra = "ignore"


class RiskAgent:
    """Deterministic risk assessment agent for ThreatLens AI."""

    def __init__(self) -> None:
        self.industry_data = INDUSTRY_DATA

    def assess(
        self,
        threat_intelligence: ThreatIntelligence,
        industry_intelligence: IndustryIntelligence,
        exposure_analysis: ExposureAnalysis | None = None,
    ) -> RiskAssessment:
        """Calculate an overall risk assessment from the provided inputs."""
        exposure_analysis = exposure_analysis or ExposureAnalysis()

        threat_score = self._calculate_threat_score(threat_intelligence)
        exposure_score = self._calculate_exposure_score(exposure_analysis)
        industry_multiplier = self._calculate_industry_multiplier(industry_intelligence)
        business_impact = self._calculate_business_impact(
            threat_score, industry_multiplier, exposure_analysis
        )
        overall_risk = self._calculate_overall_risk(
            threat_score, exposure_score, industry_multiplier
        )
        confidence = self._calculate_confidence(threat_intelligence, industry_intelligence, exposure_analysis)
        priority = self._derive_priority(overall_risk)

        description = (
            "Overall risk is calculated from threat severity, exploitability, exposure, "
            "and the industry context. Confidence is based on the input quality and "
            "the completeness of threat and industry intelligence."
        )

        return RiskAssessment(
            overall_risk=round(overall_risk, 2),
            priority=priority,
            business_impact=round(business_impact, 2),
            confidence=round(confidence, 1),
            description=description,
            breakdown=RiskBreakdown(
                threat_score=round(threat_score, 2),
                exposure_score=round(exposure_score, 2),
                industry_multiplier=round(industry_multiplier, 2),
                business_impact=round(business_impact, 2),
                confidence=round(confidence, 1),
            ),
        )

    def _calculate_threat_score(self, threat_intelligence: ThreatIntelligence) -> float:
        severity_component = SEVERITY_WEIGHTS[threat_intelligence.severity]
        exploitability_component = threat_intelligence.exploitability
        prevalence_component = threat_intelligence.prevalence
        score = (
            severity_component * 0.5
            + exploitability_component * 0.3
            + prevalence_component * 0.2
        )
        logger.debug("Threat score components: severity=%s, exploitability=%s, prevalence=%s", severity_component, exploitability_component, prevalence_component)
        return min(10.0, score)

    def _calculate_exposure_score(self, exposure: ExposureAnalysis) -> float:
        sensitivity_weight = SENSITIVITY_WEIGHTS[exposure.data_sensitivity]
        score = 0.0
        if exposure.internet_exposed:
            score += 2.0
        score += min(5.0, exposure.public_services * 0.5)
        score += min(5.0, exposure.exposed_assets * 0.5)
        if exposure.third_party_exposure:
            score += 1.5
        score *= sensitivity_weight
        logger.debug("Exposure score components: internet_exposed=%s, public_services=%s, exposed_assets=%s, third_party_exposure=%s, sensitivity=%s", exposure.internet_exposed, exposure.public_services, exposure.exposed_assets, exposure.third_party_exposure, exposure.data_sensitivity)
        return min(10.0, score)

    def _calculate_industry_multiplier(self, industry_intelligence: IndustryIntelligence) -> float:
        base_multiplier = DEFAULT_INDUSTRY_MULTIPLIERS.get(industry_intelligence.industry.lower(), 1.0)
        regulatory_weight = {"low": 0.0, "medium": 0.05, "high": 0.1}[industry_intelligence.regulatory_pressure]
        revenue_weight = {"low": 0.0, "medium": 0.05, "high": 0.1}[industry_intelligence.revenue_sensitivity]
        multiplier = base_multiplier + regulatory_weight + revenue_weight
        logger.debug("Industry multiplier for %s: base=%s, regulatory=%s, revenue=%s", industry_intelligence.industry, base_multiplier, regulatory_weight, revenue_weight)
        return min(2.0, multiplier)

    def _calculate_business_impact(
        self,
        threat_score: float,
        industry_multiplier: float,
        exposure_analysis: ExposureAnalysis,
    ) -> float:
        sensitivity_weight = SENSITIVITY_WEIGHTS[exposure_analysis.data_sensitivity]
        impact = threat_score * industry_multiplier * (0.8 + 0.05 * sensitivity_weight)
        logger.debug("Business impact calculation: threat_score=%s, industry_multiplier=%s, sensitivity=%s", threat_score, industry_multiplier, sensitivity_weight)
        return min(10.0, impact)

    def _calculate_overall_risk(
        self,
        threat_score: float,
        exposure_score: float,
        industry_multiplier: float,
    ) -> float:
        risk = threat_score * (1.0 + exposure_score / 15.0) * industry_multiplier
        logger.debug("Overall risk calculation: threat_score=%s, exposure_score=%s, industry_multiplier=%s", threat_score, exposure_score, industry_multiplier)
        return min(10.0, risk)

    def _calculate_confidence(
        self,
        threat_intelligence: ThreatIntelligence,
        industry_intelligence: IndustryIntelligence,
        exposure_analysis: ExposureAnalysis,
    ) -> float:
        completeness = 0
        completeness += 1 if threat_intelligence.summary else 0
        completeness += 1 if threat_intelligence.severity else 0
        completeness += 1 if threat_intelligence.exploitability else 0
        completeness += 1 if threat_intelligence.prevalence else 0
        completeness += 1 if industry_intelligence.industry else 0
        completeness += 1 if exposure_analysis.data_sensitivity else 0
        confidence = threat_intelligence.confidence * 0.7 + (completeness / 6.0) * 30.0
        logger.debug("Confidence calculation: base=%s, completeness=%s", threat_intelligence.confidence, completeness)
        return min(100.0, max(20.0, confidence))

    def _derive_priority(self, overall_risk: float) -> Literal["low", "medium", "high", "critical"]:
        for threshold, priority in PRIORITY_THRESHOLDS:
            if overall_risk >= threshold:
                return priority
        return "low"
