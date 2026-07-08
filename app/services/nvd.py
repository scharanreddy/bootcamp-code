from __future__ import annotations

import re
import time
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

NVD_API_URL = "https://api.nvd.nist.gov/vuln/v2"
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_SECONDS = 1.0


class NVDServiceError(RuntimeError):
    """Raised when the NVD API request or response processing fails."""


class NVDReference(BaseModel):
    """Normalized reference information from the NVD API."""

    url: str
    description: str | None = None

    model_config = ConfigDict(extra="ignore")


class AffectedProduct(BaseModel):
    """Normalized affected product information from the NVD API."""

    cpe_uri: str
    vendor: str | None = None
    product: str | None = None
    version: str | None = None

    model_config = ConfigDict(extra="ignore")


class CVSSMetrics(BaseModel):
    """Normalized CVSS score information from the NVD API."""

    version: str
    base_score: float | None = None
    vector_string: str | None = None
    severity: str | None = None

    model_config = ConfigDict(extra="ignore")


class NVDVulnerability(BaseModel):
    """Normalized vulnerability information returned from NVD."""

    cve_id: str
    description: str | None = None
    cvss: CVSSMetrics | None = None
    references: list[NVDReference] = Field(default_factory=list)
    affected_products: list[AffectedProduct] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    published_date: str | None = None
    last_modified_date: str | None = None

    model_config = ConfigDict(extra="ignore")


def _parse_cpe(cpe_uri: str) -> tuple[str | None, str | None, str | None]:
    """Extract vendor, product, and version from a CPE 2.3 URI."""
    if not cpe_uri.startswith("cpe:2.3:"):
        return None, None, None

    parts = cpe_uri.split(":")
    if len(parts) < 7:
        return None, None, None

    _, _, _, vendor, product, version = parts[:6]
    return vendor or None, product or None, version or None


def _extract_references(reference_data: list[dict[str, Any]]) -> list[NVDReference]:
    """Normalize reference entries from the NVD API payload."""
    results: list[NVDReference] = []
    for entry in reference_data:
        url = entry.get("url")
        if not url:
            continue

        description = entry.get("description") or entry.get("name")
        results.append(NVDReference(url=url, description=description))

    return results


def _extract_affected_products(configurations: dict[str, Any] | None) -> list[AffectedProduct]:
    """Extract affected product CPEs from the NVD API configuration tree."""
    if not configurations:
        return []

    products: list[AffectedProduct] = []
    nodes = configurations.get("nodes", [])
    for node in nodes:
        for match in node.get("cpeMatch", []):
            cpe_uri = match.get("cpe23Uri") or match.get("cpe22Uri")
            if not cpe_uri:
                continue

            vendor, product, version = _parse_cpe(cpe_uri)
            products.append(
                AffectedProduct(
                    cpe_uri=cpe_uri,
                    vendor=vendor,
                    product=product,
                    version=version,
                )
            )
        for child in node.get("children", []):
            products.extend(_extract_affected_products({"nodes": [child]}))

    return products


def _extract_cwes(weaknesses: list[dict[str, Any]] | None) -> list[str]:
    """Collect CWE identifiers from the NVD vulnerability payload."""
    if not weaknesses:
        return []

    cwes: list[str] = []
    for entry in weaknesses:
        for description in entry.get("description", []):
            value = description.get("value")
            if value and value.startswith("CWE-"):
                cwes.append(value)
    return cwes


def _extract_description(cve_payload: dict[str, Any] | None) -> str | None:
    """Return the primary English vulnerability description."""
    if not cve_payload:
        return None

    for entry in cve_payload.get("descriptions", []):
        if entry.get("lang") == "en" and entry.get("value"):
            return entry["value"]

    return None


def _extract_cvss(cve_payload: dict[str, Any] | None) -> CVSSMetrics | None:
    """Return normalized CVSS metrics from the NVD payload."""
    if not cve_payload:
        return None

    metrics = cve_payload.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV3", "cvssMetricV2"):
        metric_list = metrics.get(key)
        if not metric_list:
            continue

        metric = metric_list[0]
        score_data = metric.get("cvssData") or metric.get("cvssV3") or metric.get("cvssV2")
        if not score_data:
            continue

        return CVSSMetrics(
            version=score_data.get("version", key),
            base_score=score_data.get("baseScore"),
            vector_string=score_data.get("vectorString") or score_data.get("vectorV3"),
            severity=metric.get("baseSeverity") or score_data.get("severity"),
        )

    return None


class NVDService:
    """Service for retrieving normalized vulnerability details from the NVD API."""

    def __init__(
        self,
        api_key: str | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
        base_url: str = NVD_API_URL,
    ) -> None:
        self.api_key = api_key or settings.nvd_api_key
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.base_url = base_url

    def get_cve(self, cve_id: str) -> NVDVulnerability:
        """Retrieve normalized vulnerability details for the requested CVE."""
        cve_id = cve_id.strip().upper()
        logger.debug("Requesting NVD details for CVE %s", cve_id)
        payload = self._request(params={"cveId": cve_id})

        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            raise NVDServiceError(f"CVE {cve_id} not found in NVD")

        vulnerability = vulnerabilities[0]
        cve_payload = vulnerability.get("cve", {})

        return NVDVulnerability(
            cve_id=cve_payload.get("id", cve_id),
            description=_extract_description(cve_payload),
            cvss=_extract_cvss(cve_payload),
            references=_extract_references(cve_payload.get("references", [])),
            affected_products=_extract_affected_products(vulnerability.get("configurations")),
            cwe=_extract_cwes(cve_payload.get("weaknesses", [])),
            published_date=vulnerability.get("published") or vulnerability.get("publishedDate"),
            last_modified_date=vulnerability.get("lastModified"),
        )

    def _request(self, params: dict[str, str]) -> dict[str, Any]:
        """Perform an HTTP request to the NVD API with retries and backoff."""
        headers = {"apiKey": self.api_key} if self.api_key else {}

        for attempt in range(1, self.max_retries + 1):
            try:
                with httpx.Client(timeout=10.0) as client:
                    response = client.get(self.base_url, params=params, headers=headers)
                    response.raise_for_status()
                    return response.json()
            except httpx.HTTPStatusError as error:
                status = error.response.status_code
                logger.warning(
                    "NVD API returned %s for %s, attempt %d/%d",
                    status,
                    params,
                    attempt,
                    self.max_retries,
                )
                if attempt == self.max_retries or status not in {429, 500, 502, 503, 504}:
                    raise NVDServiceError("NVD API returned an error") from error
                self._backoff(attempt, error.response)
            except httpx.RequestError as error:
                logger.warning(
                    "NVD request failed for %s, attempt %d/%d: %s",
                    params,
                    attempt,
                    self.max_retries,
                    error,
                )
                if attempt == self.max_retries:
                    raise NVDServiceError("Failed to connect to NVD API") from error
                self._backoff(attempt)
        raise NVDServiceError("NVD API request failed after retries")

    def _backoff(self, attempt: int, response: httpx.Response | None = None) -> None:
        """Sleep between retries, honoring Retry-After if provided."""
        retry_after = None
        if response is not None:
            retry_after = response.headers.get("Retry-After")

        delay = self.backoff_seconds * (2 ** (attempt - 1))
        if retry_after:
            try:
                retry_after_value = float(retry_after)
                delay = max(delay, retry_after_value)
            except ValueError:
                pass

        logger.debug("Sleeping %.1f seconds before retrying NVD request.", delay)
        time.sleep(delay)
