from typing import Any

from pydantic import BaseModel, Field


class ServiceInfoResponse(BaseModel):
    """Response model for the service root endpoint."""

    service: str = Field(..., description="Name of the service")
    status: str = Field(..., description="Current service status")


class HealthResponse(BaseModel):
    """Response model for the health endpoint."""

    status: str = Field(..., description="Health status of the service")
    service: str = Field(..., description="Name of the service")


class VersionResponse(BaseModel):
    """Response model for the version endpoint."""

    service: str = Field(..., description="Name of the service")
    version: str = Field(..., description="Resolved service version")


class PlaceholderResponse(BaseModel):
    """Response model for the placeholder endpoint."""

    message: str = Field(..., description="Descriptive placeholder message")


class LatestThreatResponse(BaseModel):
    """Response model for a latest CISA KEV threat entry."""

    cve: str = Field(..., description="CVE identifier")
    vendor: str | None = Field(None, description="Affected vendor or project")
    product: str | None = Field(None, description="Affected product")
    severity: str | None = Field(None, description="Severity when available")
    date_added: str | None = Field(None, description="Date the entry was added to CISA KEV")
    due_date: str | None = Field(None, description="CISA-mandated remediation due date")
    description: str | None = Field(None, description="CISA vulnerability description")
    known_ransomware_campaign_use: str | None = Field(
        None, description="Whether CISA has observed this CVE used in ransomware campaigns"
    )


class IndustryReportRequest(BaseModel):
    """Request model for an industry intelligence report."""

    industry: str = Field(..., min_length=1, description="Industry name")


class IndustryReportResponse(BaseModel):
    """Response model for an industry intelligence report."""

    industry: str = Field(..., description="Matched industry name")
    executive_summary: str = Field(..., description="Executive-level security summary")
    top_threats: list[str] = Field(..., description="Top threats for the industry")
    current_risks: list[str] = Field(..., description="Current risks for the industry")
    recommended_controls: list[str] = Field(..., description="Recommended security controls")
    business_impact: list[str] = Field(..., description="Likely business impact areas")
    common_attack_types: list[str] = Field(
        default_factory=list, description="Common attack patterns observed in the industry"
    )
    apt_threat_actors: list[str] = Field(
        default_factory=list, description="APT groups known to target the industry"
    )


class ThreatIntelligenceReportRequest(BaseModel):
    """Request model for a CVE threat intelligence report."""

    cve: str = Field(..., min_length=13, description="CVE identifier, for example CVE-2026-1234")


class ThreatIntelligenceReportResponse(BaseModel):
    """Structured CVE threat intelligence report."""

    cve: str = Field(..., description="Normalized CVE identifier")
    model: str = Field(..., description="OpenAI model used to generate the report")
    merged_intelligence: dict[str, Any] = Field(..., description="Merged CISA KEV and NVD source data")
    executive_summary: str = Field(..., description="Executive summary")
    technical_summary: str = Field(..., description="Technical summary")
    business_impact: str = Field(..., description="Business impact")
    likely_attack_scenario: str = Field(..., description="Likely attack scenario")
    immediate_recommendations: list[str] = Field(..., description="Immediate recommendations")


class CVEAnalyzeResponse(BaseModel):
    """Response model for CVE analysis."""

    execution_time_seconds: float = Field(..., description="Total endpoint execution time in seconds")
    threat_intelligence: ThreatIntelligenceReportResponse = Field(
        ...,
        description="Threat Intelligence Agent output",
    )


class AdvisorReportRequest(BaseModel):
    """Request model for an advisory report."""

    cve: str = Field(..., min_length=13, description="CVE identifier, for example CVE-2026-1234")
    industry: str | None = Field(None, description="Optional industry name for added context")


class ImmediateActionResponse(BaseModel):
    """Response model for a single immediate action item."""

    priority: str = Field(..., description="Priority: Critical, High, Medium, or Low")
    action: str = Field(..., description="Concrete action to take immediately")
    owner: str = Field(..., description="Team or role responsible for the action")


class TechnicalRecommendationResponse(BaseModel):
    """Response model for a single technical recommendation."""

    recommendation: str = Field(..., description="Technical recommendation")
    rationale: str = Field(..., description="Why this recommendation matters")


class DetectionOpportunityResponse(BaseModel):
    """Response model for a single detection engineering opportunity."""

    detection_type: str = Field(..., description="Type of detection, e.g. SIEM rule, EDR alert")
    data_source: str = Field(..., description="Log or telemetry source needed")
    logic: str = Field(..., description="Detection logic or indicator to alert on")


class AdvisoryReportResponse(BaseModel):
    """Structured advisory report content."""

    executive_summary: str = Field(..., description="Executive summary")
    immediate_actions: list[ImmediateActionResponse] = Field(..., description="Immediate actions")
    technical_recommendations: list[TechnicalRecommendationResponse] = Field(
        ..., description="Technical recommendations"
    )
    detection_opportunities: list[DetectionOpportunityResponse] = Field(
        ..., description="Detection opportunities"
    )
    long_term_improvements: list[str] = Field(..., description="Long-term improvements")


class AdvisorReportResponse(BaseModel):
    """Response model for an advisory report."""

    report: AdvisoryReportResponse = Field(..., description="Structured advisory report")
    markdown: str = Field(..., description="Advisory report rendered as Markdown")


class OrchestrationRequest(BaseModel):
    """Request model for the full LangGraph orchestration pipeline."""

    cve: str = Field(..., min_length=13, description="CVE identifier, for example CVE-2026-1234")
    industry: str | None = Field(None, description="Optional industry name for added context")
    sbom: str | None = Field(
        None,
        description=(
            "Optional CycloneDX SBOM document (JSON or XML) as raw text. When supplied, the "
            "Exposure Agent runs before the Risk Agent."
        ),
    )


class OrchestrationResponse(BaseModel):
    """Response model for the full LangGraph orchestration pipeline."""

    cve: str = Field(..., description="Normalized CVE identifier")
    threat_intelligence: ThreatIntelligenceReportResponse = Field(
        ..., description="Threat Intelligence Agent output"
    )
    industry_intelligence: IndustryReportResponse | None = Field(
        None, description="Industry Intelligence Agent output, when an industry was supplied"
    )
    exposure_analysis: dict[str, Any] | None = Field(
        None, description="Exposure Agent output, present only when an SBOM was supplied"
    )
    risk_assessment: dict[str, Any] | None = Field(None, description="Risk Agent output")
    advisory: AdvisorReportResponse = Field(..., description="Advisor Agent output")


class SBOMAnalysisRequest(BaseModel):
    """Request model for SBOM exposure analysis."""

    sbom: str = Field(..., min_length=1, description="Raw CycloneDX SBOM document (JSON or XML)")


class SBOMComponentResponse(BaseModel):
    """A single normalized software component from a CycloneDX SBOM."""

    software_name: str | None = Field(None, description="Component or application name")
    version: str | None = Field(None, description="Component version")
    supplier: str | None = Field(None, description="Component supplier")
    package_url: str | None = Field(None, description="Package URL (purl)")
    component_type: str | None = Field(None, description="CycloneDX component type")


class SBOMAnalysisResponse(BaseModel):
    """Response model for SBOM exposure analysis."""

    component_count: int = Field(..., description="Total number of components in the SBOM")
    application_count: int = Field(..., description="Number of application-type components")
    components: list[SBOMComponentResponse] = Field(..., description="All affected components")
    applications: list[SBOMComponentResponse] = Field(
        ..., description="Application-type components"
    )
    exposure_analysis: dict[str, Any] = Field(..., description="Exposure Agent risk profile")
    recommendations: list[str] = Field(..., description="Exposure-driven recommendations")
