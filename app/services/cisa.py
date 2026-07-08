from __future__ import annotations

import time
from typing import TYPE_CHECKING

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.utils.logger import get_logger

if TYPE_CHECKING:
    from httpx import Response

logger = get_logger(__name__)

CISA_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
CACHE_TTL_SECONDS = 30 * 60


class CISAServiceError(RuntimeError):
    """Raised when the CISA catalog cannot be loaded or parsed."""


class CVEItem(BaseModel):
    """Pydantic model for a single CISA known exploited vulnerability entry."""

    cve_id: str = Field(..., alias="cveID")
    vendor_project: str | None = Field(None, alias="vendorProject")
    product: str | None = Field(None, alias="product")
    severity: str | None = None
    vulnerability_name: str | None = Field(None, alias="vulnerabilityName")
    date_added: str | None = Field(None, alias="dateAdded")
    due_date: str | None = Field(None, alias="dueDate")
    short_description: str | None = Field(None, alias="shortDescription")
    required_action: str | None = Field(None, alias="requiredAction")
    known_ransomware_campaign_use: str | None = Field(None, alias="knownRansomwareCampaignUse")
    notes: str | None = None

    model_config = ConfigDict(extra="ignore")


class CISACatalog(BaseModel):
    """Pydantic model for the CISA catalog payload."""

    last_modified: str | None = Field(None, alias="lastModified")
    version: str | None = Field(None, alias="version")
    vulnerabilities: list[CVEItem] = Field(default_factory=list, alias="vulnerabilities")

    model_config = ConfigDict(extra="ignore")


class CISAExploitCatalog(BaseModel):
    """Top-level CISA catalog model."""

    catalog: CISACatalog

    model_config = ConfigDict(extra="ignore")

    @model_validator(mode="before")
    @classmethod
    def normalize_catalog_payload(cls, data: object) -> object:
        """Support both wrapped test payloads and CISA's top-level feed shape."""
        if isinstance(data, dict) and "catalog" not in data:
            return {
                "catalog": {
                    "lastModified": data.get("lastModified") or data.get("dateReleased"),
                    "version": data.get("version") or data.get("catalogVersion"),
                    "vulnerabilities": data.get("vulnerabilities", []),
                }
            }
        return data


class CISAService:
    """Service responsible for downloading and caching the CISA KEV catalog."""

    def __init__(
        self,
        catalog_url: str = CISA_CATALOG_URL,
        cache_ttl: int = CACHE_TTL_SECONDS,
    ) -> None:
        self.catalog_url = catalog_url
        self.cache_ttl = cache_ttl
        self._catalog: CISAExploitCatalog | None = None
        self._cache_expiry: float = 0.0

    def get_catalog(self) -> CISAExploitCatalog:
        """Return the CISA KEV catalog, using cached results when available."""
        now = time.monotonic()
        if self._catalog is not None and now < self._cache_expiry:
            logger.debug("Returning CISA catalog from cache.")
            return self._catalog

        try:
            self._catalog = self._fetch_catalog()
            self._cache_expiry = now + self.cache_ttl
            logger.info(
                "Loaded CISA catalog with %d vulnerabilities.",
                len(self._catalog.catalog.vulnerabilities),
            )
            return self._catalog
        except httpx.HTTPError as error:
            logger.warning("CISA catalog download failed: %s", error)
            if self._catalog is not None:
                logger.info("Returning stale CISA catalog from cache due to network failure.")
                return self._catalog
            raise CISAServiceError("Failed to download CISA catalog") from error
        except ValueError as error:
            logger.error("Failed to parse CISA catalog: %s", error)
            raise CISAServiceError("Invalid CISA catalog format") from error

    def _fetch_catalog(self) -> CISAExploitCatalog:
        """Download and parse the CISA catalog JSON data."""
        logger.debug("Fetching CISA catalog from %s", self.catalog_url)
        with httpx.Client(timeout=10.0) as client:
            response = client.get(self.catalog_url)
            response.raise_for_status()
            payload = response.json()

        if not isinstance(payload, dict):
            raise ValueError("CISA catalog payload is not a JSON object")

        return CISAExploitCatalog.model_validate(payload)

    def find_cve(self, cve_id: str) -> CVEItem | None:
        """Find a CVE entry by its CVE ID in the loaded CISA catalog."""
        catalog = self.get_catalog()
        normalized_id = cve_id.strip().upper()
        for item in catalog.catalog.vulnerabilities:
            if item.cve_id.upper() == normalized_id:
                logger.debug("Found CVE %s in catalog.", normalized_id)
                return item

        logger.debug("CVE %s was not found in the catalog.", normalized_id)
        return None

    def get_latest(self, limit: int = 10) -> list[CVEItem]:
        """Return the most recently added CVE entries from the catalog."""
        vulnerabilities = self.get_catalog().catalog.vulnerabilities
        latest = sorted(
            vulnerabilities,
            key=lambda item: item.date_added or "",
            reverse=True,
        )[:limit]
        logger.debug("Returning %d latest CVE entries.", len(latest))
        return latest
