from __future__ import annotations

from typing import Any

import httpx

from threatlens_ai.frontend.config import settings


class APIClientError(RuntimeError):
    """Raised when a request to the ThreatLens AI backend fails."""


class ThreatLensAPIClient:
    """Thin HTTP client for the ThreatLens AI FastAPI backend.

    Keeps all network concerns (base URL, timeouts, error normalization) in
    one place so Streamlit pages depend on a simple, mockable interface
    instead of scattering httpx calls throughout the UI layer.
    """

    def __init__(self, base_url: str | None = None, timeout: float | None = None) -> None:
        self.base_url = (base_url or settings.api_base_url).rstrip("/")
        self.timeout = timeout if timeout is not None else settings.request_timeout

    def health(self) -> dict[str, Any]:
        """Check backend health."""
        return self._get("/health")

    def get_latest_threats(self, limit: int = 20) -> list[dict[str, Any]]:
        """Fetch the latest CISA KEV entries."""
        return self._get("/threats/latest", params={"limit": limit})

    def analyze_cve(self, cve: str) -> dict[str, Any]:
        """Run the Threat Intelligence Agent for a single CVE."""
        return self._post("/cve/analyze", json={"cve": cve})

    def get_industry_report(self, industry: str) -> dict[str, Any]:
        """Generate an Industry Intelligence Agent report."""
        return self._post("/industry/report", json={"industry": industry})

    def get_advisor_report(self, cve: str, industry: str | None = None) -> dict[str, Any]:
        """Generate an Advisor Agent report for a CVE."""
        return self._post("/advisor/report", json={"cve": cve, "industry": industry})

    def orchestrate(
        self,
        cve: str,
        industry: str | None = None,
        sbom: str | None = None,
    ) -> dict[str, Any]:
        """Run the full LangGraph orchestration pipeline."""
        return self._post(
            "/orchestrate/report",
            json={"cve": cve, "industry": industry, "sbom": sbom},
        )

    def analyze_sbom(self, sbom: str) -> dict[str, Any]:
        """Analyze a CycloneDX SBOM for components and exposure."""
        return self._post("/sbom/analyze", json={"sbom": sbom})

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self._request("GET", path, params=params)

    def _post(self, path: str, json: dict[str, Any]) -> Any:
        return self._request("POST", path, json=json)

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = f"{self.base_url}{path}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.request(method, url, **kwargs)
        except httpx.TimeoutException as error:
            raise APIClientError(
                f"The backend did not respond within {self.timeout:.0f}s. "
                "The analysis may be taking longer than usual — please try again."
            ) from error
        except httpx.RequestError as error:
            raise APIClientError(
                f"Could not reach the ThreatLens AI backend at {self.base_url}. "
                "Is the backend running?"
            ) from error

        if response.is_error:
            raise APIClientError(self._extract_error_detail(response))

        try:
            return response.json()
        except ValueError as error:
            raise APIClientError(
                "The backend returned an unexpected (non-JSON) response."
            ) from error

    @staticmethod
    def _extract_error_detail(response: httpx.Response) -> str:
        try:
            payload = response.json()
        except ValueError:
            return f"Backend request failed with status {response.status_code}."
        detail = payload.get("detail") if isinstance(payload, dict) else None
        return detail or f"Backend request failed with status {response.status_code}."
