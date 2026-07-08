from __future__ import annotations

import time
from typing import Any, Literal, NotRequired, Protocol, TypedDict

from langgraph.graph import END, START, StateGraph

from app.services.risk import ExposureAnalysis, IndustryIntelligence, RiskAssessment, ThreatIntelligence
from app.utils.logger import get_logger
from threatlens_ai.agent.exposure_agent import SBOMPayload

logger = get_logger(__name__)

_SEVERITY_ALIASES = {
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
}


def _normalize_severity(value: str | None) -> Literal["low", "medium", "high", "critical"]:
    """Map an upstream severity label onto the scale the Risk Agent expects."""
    if not value:
        return "medium"
    return _SEVERITY_ALIASES.get(value.strip().lower(), "medium")


def _score_to_scale(base_score: float | None) -> int:
    """Map a 0-10 CVSS base score onto the 1-10 exploitability scale."""
    if base_score is None:
        return 5
    return max(1, min(10, round(base_score)))


class ThreatIntelligenceProvider(Protocol):
    """Abstraction for the Threat Intelligence Agent step."""

    def generate_report(self, cve: str) -> dict[str, Any]:
        ...


class IndustryIntelligenceProvider(Protocol):
    """Abstraction for the Industry Intelligence Agent step."""

    def generate_report(self, industry: str) -> dict[str, Any]:
        ...


class ExposureProvider(Protocol):
    """Abstraction for the Exposure Agent step."""

    def analyze(self, sbom: SBOMPayload) -> ExposureAnalysis:
        ...


class RiskProvider(Protocol):
    """Abstraction for the Risk Agent step."""

    def assess(
        self,
        threat_intelligence: ThreatIntelligence,
        industry_intelligence: IndustryIntelligence,
        exposure_analysis: ExposureAnalysis | None = None,
    ) -> RiskAssessment:
        ...


class AdvisoryProvider(Protocol):
    """Abstraction for the Advisor Agent step."""

    def generate_advisory(
        self,
        threat_intelligence: dict[str, Any],
        risk_assessment: dict[str, Any] | None = None,
        industry_intelligence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ...


class OrchestratorState(TypedDict):
    """Typed state threaded through the ThreatLens AI LangGraph pipeline."""

    cve: str
    industry: NotRequired[str | None]
    sbom: NotRequired[SBOMPayload | None]
    threat_intelligence: NotRequired[dict[str, Any]]
    industry_intelligence: NotRequired[dict[str, Any] | None]
    exposure_analysis: NotRequired[dict[str, Any] | None]
    risk_assessment: NotRequired[dict[str, Any] | None]
    advisory: NotRequired[dict[str, Any]]


class LangGraphOrchestrator:
    """LangGraph-based orchestrator wiring the ThreatLens AI agent pipeline.

    Graph shape::

        START -> Threat Intelligence -> Industry Intelligence
              -> [SBOM uploaded?] -> Exposure -> Risk -> Advisor -> END
              -> [no SBOM]        ------------> Risk -> Advisor -> END
    """

    def __init__(
        self,
        threat_agent: ThreatIntelligenceProvider,
        industry_agent: IndustryIntelligenceProvider,
        exposure_agent: ExposureProvider,
        risk_agent: RiskProvider,
        advisor_agent: AdvisoryProvider,
    ) -> None:
        self.threat_agent = threat_agent
        self.industry_agent = industry_agent
        self.exposure_agent = exposure_agent
        self.risk_agent = risk_agent
        self.advisor_agent = advisor_agent
        self._graph = self._build_graph()

    def run(
        self,
        cve: str,
        industry: str | None = None,
        sbom: SBOMPayload | None = None,
    ) -> OrchestratorState:
        """Run the full orchestration pipeline for a CVE and return the final state."""
        initial_state: OrchestratorState = {"cve": cve, "industry": industry, "sbom": sbom}
        logger.info("Starting ThreatLens AI orchestration for %s.", cve)
        started_at = time.perf_counter()
        final_state = self._graph.invoke(initial_state)
        logger.info(
            "Completed ThreatLens AI orchestration for %s in %.3fs.",
            cve,
            time.perf_counter() - started_at,
        )
        return final_state

    def _build_graph(self) -> Any:
        graph = StateGraph(OrchestratorState)
        graph.add_node("threat_intelligence", self._traced("threat_intelligence", self._run_threat_intelligence))
        graph.add_node("industry_intelligence", self._traced("industry_intelligence", self._run_industry_intelligence))
        graph.add_node("exposure_agent", self._traced("exposure_agent", self._run_exposure))
        graph.add_node("risk_agent", self._traced("risk_agent", self._run_risk))
        graph.add_node("advisor_agent", self._traced("advisor_agent", self._run_advisor))

        graph.add_edge(START, "threat_intelligence")
        graph.add_edge("threat_intelligence", "industry_intelligence")
        graph.add_conditional_edges(
            "industry_intelligence",
            self._route_after_industry,
            {"exposure_agent": "exposure_agent", "risk_agent": "risk_agent"},
        )
        graph.add_edge("exposure_agent", "risk_agent")
        graph.add_edge("risk_agent", "advisor_agent")
        graph.add_edge("advisor_agent", END)

        return graph.compile()

    @staticmethod
    def _traced(name: str, func: Any) -> Any:
        """Wrap a node function with entry/exit/duration/error logging."""

        def wrapped(state: OrchestratorState) -> dict[str, Any]:
            started_at = time.perf_counter()
            logger.info("Starting node '%s'.", name)
            try:
                result = func(state)
            except Exception as error:
                logger.error(
                    "Node '%s' failed after %.3fs: %s",
                    name,
                    time.perf_counter() - started_at,
                    error,
                )
                raise
            logger.info("Completed node '%s' in %.3fs.", name, time.perf_counter() - started_at)
            return result

        return wrapped

    def _run_threat_intelligence(self, state: OrchestratorState) -> dict[str, Any]:
        report = self.threat_agent.generate_report(state["cve"])
        return {"threat_intelligence": report}

    def _run_industry_intelligence(self, state: OrchestratorState) -> dict[str, Any]:
        industry = state.get("industry")
        if not industry:
            logger.debug("No industry supplied; skipping Industry Intelligence Agent.")
            return {"industry_intelligence": None}

        report = self.industry_agent.generate_report(industry)
        return {"industry_intelligence": report}

    @staticmethod
    def _route_after_industry(state: OrchestratorState) -> str:
        """Conditional edge: only run the Exposure Agent when an SBOM was supplied."""
        if state.get("sbom"):
            logger.debug("SBOM supplied; routing to Exposure Agent.")
            return "exposure_agent"
        logger.debug("No SBOM supplied; routing directly to Risk Agent.")
        return "risk_agent"

    def _run_exposure(self, state: OrchestratorState) -> dict[str, Any]:
        sbom = state["sbom"]
        exposure = self.exposure_agent.analyze(sbom)
        return {"exposure_analysis": exposure.model_dump(mode="json")}

    def _run_risk(self, state: OrchestratorState) -> dict[str, Any]:
        threat_input = self._build_threat_intelligence_input(state["threat_intelligence"])
        industry_input = self._build_industry_intelligence_input(
            state.get("industry_intelligence"), state.get("industry")
        )
        exposure_input = self._build_exposure_input(state.get("exposure_analysis"))

        assessment = self.risk_agent.assess(threat_input, industry_input, exposure_input)
        return {"risk_assessment": assessment.model_dump(mode="json")}

    def _run_advisor(self, state: OrchestratorState) -> dict[str, Any]:
        result = self.advisor_agent.generate_advisory(
            threat_intelligence=state["threat_intelligence"],
            risk_assessment=state.get("risk_assessment"),
            industry_intelligence=state.get("industry_intelligence"),
        )
        return {"advisory": result}

    @staticmethod
    def _build_threat_intelligence_input(report: dict[str, Any]) -> ThreatIntelligence:
        merged = report.get("merged_intelligence") or {}
        cvss = merged.get("cvss") or {}
        is_known_exploited = bool(merged.get("is_known_exploited"))

        severity = _normalize_severity(merged.get("severity") or cvss.get("severity"))
        exploitability = 9 if is_known_exploited else _score_to_scale(cvss.get("base_score"))
        prevalence = 8 if is_known_exploited else 5
        confidence = 85 if is_known_exploited else 60
        summary = (
            report.get("executive_summary")
            or merged.get("description")
            or f"Vulnerability {merged.get('cve') or report.get('cve') or ''}".strip()
            or "No summary available."
        )

        return ThreatIntelligence(
            summary=summary,
            severity=severity,
            exploitability=exploitability,
            prevalence=prevalence,
            confidence=confidence,
        )

    @staticmethod
    def _build_industry_intelligence_input(
        industry_report: dict[str, Any] | None,
        industry_name: str | None,
    ) -> IndustryIntelligence:
        name = industry_name or (industry_report or {}).get("industry") or "Unspecified"
        return IndustryIntelligence(industry=name)

    @staticmethod
    def _build_exposure_input(exposure: dict[str, Any] | None) -> ExposureAnalysis | None:
        if not exposure:
            return None
        return ExposureAnalysis.model_validate(exposure)
