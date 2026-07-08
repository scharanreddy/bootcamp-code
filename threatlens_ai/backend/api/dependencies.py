from app.services.cisa import CISAService
from app.services.nvd import NVDService
from app.services.risk import RiskAgent
from threatlens_ai.agent.advisor_agent import AdvisorAgent, OpenAIAdvisoryReportGenerator
from threatlens_ai.agent.exposure_agent import ExposureAgent
from threatlens_ai.agent.industry_intelligence import IndustryIntelligenceAgent
from threatlens_ai.agent.orchestrator import LangGraphOrchestrator
from threatlens_ai.agent.threat_intelligence import ThreatIntelligenceAgent
from threatlens_ai.backend.services.interfaces import ThreatServiceProtocol
from threatlens_ai.backend.services.sbom_service import SBOMAnalysisService
from threatlens_ai.backend.services.threat_service import ThreatService

_cisa_service = CISAService()
_nvd_service = NVDService()
_industry_intelligence_agent = IndustryIntelligenceAgent()
_threat_intelligence_agent = ThreatIntelligenceAgent(_cisa_service, _nvd_service)
_advisor_agent = AdvisorAgent(OpenAIAdvisoryReportGenerator())
_exposure_agent = ExposureAgent()
_risk_agent = RiskAgent()
_sbom_service = SBOMAnalysisService(_exposure_agent)
_orchestrator = LangGraphOrchestrator(
    threat_agent=_threat_intelligence_agent,
    industry_agent=_industry_intelligence_agent,
    exposure_agent=_exposure_agent,
    risk_agent=_risk_agent,
    advisor_agent=_advisor_agent,
)


def get_threat_service() -> ThreatServiceProtocol:
    """Provide a concrete threat service implementation for dependency injection."""
    return ThreatService()


def get_cisa_service() -> CISAService:
    """Provide a cached CISA KEV service implementation for dependency injection."""
    return _cisa_service


def get_industry_intelligence_agent() -> IndustryIntelligenceAgent:
    """Provide the industry intelligence agent for dependency injection."""
    return _industry_intelligence_agent


def get_nvd_service() -> NVDService:
    """Provide a cached NVD service implementation for dependency injection."""
    return _nvd_service


def get_threat_intelligence_agent() -> ThreatIntelligenceAgent:
    """Provide the threat intelligence agent for dependency injection."""
    return _threat_intelligence_agent


def get_advisor_agent() -> AdvisorAgent:
    """Provide the advisor agent for dependency injection."""
    return _advisor_agent


def get_exposure_agent() -> ExposureAgent:
    """Provide the exposure agent for dependency injection."""
    return _exposure_agent


def get_risk_agent() -> RiskAgent:
    """Provide the risk agent for dependency injection."""
    return _risk_agent


def get_orchestrator() -> LangGraphOrchestrator:
    """Provide the LangGraph orchestrator for dependency injection."""
    return _orchestrator


def get_sbom_service() -> SBOMAnalysisService:
    """Provide the SBOM analysis service for dependency injection."""
    return _sbom_service
