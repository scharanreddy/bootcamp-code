from fastapi import FastAPI
from fastapi.testclient import TestClient

from threatlens_ai.agent.advisor_agent import AdvisorAgentError
from threatlens_ai.agent.industry_intelligence import IndustryNotFoundError
from threatlens_ai.agent.threat_intelligence import InvalidCVEError
from threatlens_ai.backend.api.dependencies import get_orchestrator
from threatlens_ai.backend.api.routes import router

FULL_STATE = {
    "cve": "CVE-2026-0001",
    "industry": "Technology",
    "sbom": None,
    "threat_intelligence": {
        "cve": "CVE-2026-0001",
        "model": "stub-model",
        "merged_intelligence": {"cve": "CVE-2026-0001", "is_known_exploited": True},
        "executive_summary": "Executive summary.",
        "technical_summary": "Technical summary.",
        "business_impact": "Business impact.",
        "likely_attack_scenario": "Attack scenario.",
        "immediate_recommendations": ["Patch now"],
    },
    "industry_intelligence": {
        "industry": "Technology",
        "executive_summary": "Industry summary.",
        "top_threats": ["Phishing"],
        "current_risks": ["Data exposure"],
        "recommended_controls": ["MFA"],
        "business_impact": ["Regulatory exposure"],
    },
    "exposure_analysis": None,
    "risk_assessment": {
        "overall_risk": 9.0,
        "priority": "critical",
        "business_impact": 9.0,
        "confidence": 90.0,
        "description": "Risk description.",
        "breakdown": {
            "threat_score": 9.0,
            "exposure_score": 8.0,
            "industry_multiplier": 1.2,
            "business_impact": 9.0,
            "confidence": 90.0,
        },
    },
    "advisory": {
        "report": {
            "executive_summary": "Advisory summary.",
            "immediate_actions": [{"priority": "Critical", "action": "Patch", "owner": "IT"}],
            "technical_recommendations": [
                {"recommendation": "Deploy patch", "rationale": "Closes the exploit"}
            ],
            "detection_opportunities": [
                {"detection_type": "EDR alert", "data_source": "Endpoint telemetry", "logic": "Alert on exploit chain"}
            ],
            "long_term_improvements": ["Faster patch cadence"],
        },
        "markdown": "# Security Advisory Report",
    },
}


class StubOrchestrator:
    def __init__(self, state: dict | None = None, error: Exception | None = None) -> None:
        self.state = state or FULL_STATE
        self.error = error
        self.calls: list[dict] = []

    def run(self, cve: str, industry: str | None = None, sbom: object | None = None) -> dict:
        self.calls.append({"cve": cve, "industry": industry, "sbom": sbom})
        if self.error:
            raise self.error
        return self.state


def make_client(stub: StubOrchestrator) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_orchestrator] = lambda: stub
    return TestClient(app)


def test_orchestrate_report_returns_combined_results() -> None:
    stub = StubOrchestrator()
    client = make_client(stub)

    response = client.post("/orchestrate/report", json={"cve": "CVE-2026-0001", "industry": "Technology"})

    assert response.status_code == 200
    body = response.json()
    assert body["cve"] == "CVE-2026-0001"
    assert body["advisory"]["markdown"] == "# Security Advisory Report"
    assert body["risk_assessment"]["priority"] == "critical"
    assert stub.calls == [{"cve": "CVE-2026-0001", "industry": "Technology", "sbom": None}]


def test_orchestrate_report_maps_invalid_cve_to_422() -> None:
    stub = StubOrchestrator(error=InvalidCVEError("CVE must use the format CVE-YYYY-NNNN."))
    client = make_client(stub)

    response = client.post("/orchestrate/report", json={"cve": "CVE-2026-0001"})

    assert response.status_code == 422
    assert response.json() == {"detail": "CVE must use the format CVE-YYYY-NNNN."}


def test_orchestrate_report_maps_industry_not_found_to_404() -> None:
    stub = StubOrchestrator(error=IndustryNotFoundError("Industry 'Nope' is not supported."))
    client = make_client(stub)

    response = client.post("/orchestrate/report", json={"cve": "CVE-2026-0001", "industry": "Nope"})

    assert response.status_code == 404
    assert response.json() == {"detail": "Industry 'Nope' is not supported."}


def test_orchestrate_report_maps_advisor_failure_to_502() -> None:
    stub = StubOrchestrator(error=AdvisorAgentError("OpenAI advisory report generation failed"))
    client = make_client(stub)

    response = client.post("/orchestrate/report", json={"cve": "CVE-2026-0001"})

    assert response.status_code == 502
    assert response.json() == {"detail": "OpenAI advisory report generation failed"}
