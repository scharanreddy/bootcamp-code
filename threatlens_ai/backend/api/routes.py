import time
from importlib.metadata import PackageNotFoundError, version as package_version

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.services.cisa import CISAService, CISAServiceError
from app.services.cyclonedx import CycloneDXParseError
from app.services.nvd import NVDServiceError
from threatlens_ai.agent.advisor_agent import AdvisorAgent, AdvisorAgentError
from threatlens_ai.agent.exposure_agent import ExposureAgentError
from threatlens_ai.agent.industry_intelligence import (
    IndustryIntelligenceAgent,
    IndustryNotFoundError,
)
from threatlens_ai.agent.orchestrator import LangGraphOrchestrator
from threatlens_ai.agent.threat_intelligence import (
    InvalidCVEError,
    ThreatIntelligenceAgent,
    ThreatIntelligenceAgentError,
)
from threatlens_ai.backend.api.dependencies import (
    get_advisor_agent,
    get_cisa_service,
    get_industry_intelligence_agent,
    get_orchestrator,
    get_sbom_service,
    get_threat_intelligence_agent,
    get_threat_service,
    ThreatServiceProtocol,
)
from threatlens_ai.backend.api.schemas import (
    AdvisorReportRequest,
    AdvisorReportResponse,
    CVEAnalyzeResponse,
    HealthResponse,
    IndustryReportRequest,
    IndustryReportResponse,
    LatestThreatResponse,
    OrchestrationRequest,
    OrchestrationResponse,
    PlaceholderResponse,
    SBOMAnalysisRequest,
    SBOMAnalysisResponse,
    ServiceInfoResponse,
    ThreatIntelligenceReportRequest,
    ThreatIntelligenceReportResponse,
    VersionResponse,
)
from threatlens_ai.backend.services.sbom_service import SBOMAnalysisService

router = APIRouter()


def _get_service_version() -> str:
    """Return the currently installed ThreatLens AI package version."""
    try:
        return package_version("threatlens-ai")
    except PackageNotFoundError:
        return "0.1.0"


@router.get(
    "/",
    response_model=ServiceInfoResponse,
    summary="ThreatLens AI root",
    description="Return basic information about the ThreatLens AI backend service.",
)
def root() -> ServiceInfoResponse:
    """Root endpoint for service metadata."""
    return ServiceInfoResponse(service="ThreatLens AI", status="running")


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Return the current health status of the ThreatLens AI backend.",
)
def health_check() -> HealthResponse:
    """Health check endpoint for the backend service."""
    return HealthResponse(status="ok", service="ThreatLens AI")


@router.get(
    "/version",
    response_model=VersionResponse,
    summary="Service version",
    description="Return the current version of the ThreatLens AI backend.",
)
def version() -> VersionResponse:
    """Version endpoint for the backend service."""
    return VersionResponse(service="ThreatLens AI", version=_get_service_version())


@router.get(
    "/placeholder",
    response_model=PlaceholderResponse,
    summary="Placeholder endpoint",
    description="Return a placeholder message from the backend service.",
)
def placeholder_endpoint(
    threat_service: ThreatServiceProtocol = Depends(get_threat_service),
) -> PlaceholderResponse:
    """Placeholder endpoint that delegates to the threat service."""
    return PlaceholderResponse(message=threat_service.placeholder_message())


@router.get(
    "/threats/latest",
    response_model=list[LatestThreatResponse],
    summary="Latest CISA KEV threats",
    description="Return the newest known exploited vulnerability entries from CISA KEV.",
)
def latest_threats(
    limit: int = Query(20, ge=1, le=200, description="Number of entries to return"),
    cisa_service: CISAService = Depends(get_cisa_service),
) -> list[LatestThreatResponse]:
    """Return the latest CISA KEV entries."""
    try:
        latest = cisa_service.get_latest(limit=limit)
    except CISAServiceError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to load CISA KEV catalog.",
        ) from error

    return [
        LatestThreatResponse(
            cve=item.cve_id,
            vendor=item.vendor_project,
            product=item.product,
            severity=item.severity,
            date_added=item.date_added,
            due_date=item.due_date,
            description=item.short_description,
            known_ransomware_campaign_use=item.known_ransomware_campaign_use,
        )
        for item in latest
    ]


@router.post(
    "/industry/report",
    response_model=IndustryReportResponse,
    summary="Industry intelligence report",
    description="Generate an industry-specific security report using the Industry Intelligence Agent.",
)
def industry_report(
    request: IndustryReportRequest,
    industry_agent: IndustryIntelligenceAgent = Depends(get_industry_intelligence_agent),
) -> IndustryReportResponse:
    """Generate a security report for the requested industry."""
    try:
        report = industry_agent.generate_report(request.industry)
    except IndustryNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error

    return IndustryReportResponse.model_validate(report)


def _generate_threat_intelligence_report(
    cve: str,
    threat_agent: ThreatIntelligenceAgent,
) -> ThreatIntelligenceReportResponse:
    """Generate a threat intelligence report and map known failures to HTTP errors."""
    try:
        report = threat_agent.generate_report(cve)
    except InvalidCVEError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        ) from error
    except CISAServiceError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to load CISA KEV data.",
        ) from error
    except NVDServiceError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to load NVD data.",
        ) from error
    except ThreatIntelligenceAgentError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(error),
        ) from error

    return ThreatIntelligenceReportResponse.model_validate(report)


@router.post(
    "/threat-intelligence/report",
    response_model=ThreatIntelligenceReportResponse,
    summary="Threat intelligence report",
    description="Generate a structured CVE report using merged CISA KEV and NVD data with GPT-5.5.",
)
def threat_intelligence_report(
    request: ThreatIntelligenceReportRequest,
    threat_agent: ThreatIntelligenceAgent = Depends(get_threat_intelligence_agent),
) -> ThreatIntelligenceReportResponse:
    """Generate a structured threat intelligence report for a CVE."""
    return _generate_threat_intelligence_report(request.cve, threat_agent)


@router.post(
    "/cve/analyze",
    response_model=CVEAnalyzeResponse,
    summary="Analyze CVE",
    description="Analyze a CVE with the Threat Intelligence Agent and include execution time.",
)
def analyze_cve(
    request: ThreatIntelligenceReportRequest,
    threat_agent: ThreatIntelligenceAgent = Depends(get_threat_intelligence_agent),
) -> CVEAnalyzeResponse:
    """Analyze a CVE and include endpoint execution time."""
    started_at = time.perf_counter()
    threat_intelligence = _generate_threat_intelligence_report(request.cve, threat_agent)
    execution_time = time.perf_counter() - started_at

    return CVEAnalyzeResponse(
        execution_time_seconds=round(execution_time, 6),
        threat_intelligence=threat_intelligence,
    )


@router.post(
    "/advisor/report",
    response_model=AdvisorReportResponse,
    summary="Advisory report",
    description=(
        "Generate a Markdown security advisory for a CVE, covering executive summary, "
        "immediate actions, technical recommendations, detection opportunities, and "
        "long-term improvements."
    ),
)
def advisor_report(
    request: AdvisorReportRequest,
    threat_agent: ThreatIntelligenceAgent = Depends(get_threat_intelligence_agent),
    industry_agent: IndustryIntelligenceAgent = Depends(get_industry_intelligence_agent),
    advisor_agent: AdvisorAgent = Depends(get_advisor_agent),
) -> AdvisorReportResponse:
    """Generate an advisory report synthesizing threat and, optionally, industry context."""
    threat_intelligence = _generate_threat_intelligence_report(request.cve, threat_agent)

    industry_intelligence = None
    if request.industry:
        try:
            industry_intelligence = industry_agent.generate_report(request.industry)
        except IndustryNotFoundError as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(error),
            ) from error

    try:
        result = advisor_agent.generate_advisory(
            threat_intelligence=threat_intelligence.model_dump(mode="json"),
            industry_intelligence=industry_intelligence,
        )
    except AdvisorAgentError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(error),
        ) from error

    return AdvisorReportResponse.model_validate(result)


@router.post(
    "/orchestrate/report",
    response_model=OrchestrationResponse,
    summary="Full orchestrated advisory",
    description=(
        "Run the full ThreatLens AI LangGraph pipeline: Threat Intelligence -> Industry "
        "Intelligence -> (conditionally, if an SBOM is supplied) Exposure -> Risk -> Advisor, "
        "and return the combined results."
    ),
)
def orchestrate_report(
    request: OrchestrationRequest,
    orchestrator: LangGraphOrchestrator = Depends(get_orchestrator),
) -> OrchestrationResponse:
    """Run the full LangGraph orchestration pipeline and map failures to HTTP errors."""
    try:
        final_state = orchestrator.run(
            cve=request.cve,
            industry=request.industry,
            sbom=request.sbom,
        )
    except InvalidCVEError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        ) from error
    except IndustryNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error
    except (
        CISAServiceError,
        NVDServiceError,
        ThreatIntelligenceAgentError,
        ExposureAgentError,
        AdvisorAgentError,
    ) as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(error),
        ) from error

    return OrchestrationResponse.model_validate(final_state)


@router.post(
    "/sbom/analyze",
    response_model=SBOMAnalysisResponse,
    summary="Analyze a CycloneDX SBOM",
    description=(
        "Parse a CycloneDX SBOM, enumerate its components and applications, and derive "
        "an exposure profile and remediation recommendations via the Exposure Agent."
    ),
)
def analyze_sbom(
    request: SBOMAnalysisRequest,
    sbom_service: SBOMAnalysisService = Depends(get_sbom_service),
) -> SBOMAnalysisResponse:
    """Analyze an uploaded CycloneDX SBOM and map parsing failures to HTTP errors."""
    try:
        result = sbom_service.analyze(request.sbom)
    except CycloneDXParseError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        ) from error
    except ExposureAgentError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        ) from error

    return SBOMAnalysisResponse.model_validate(result)
