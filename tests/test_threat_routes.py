from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services.cisa import CISAServiceError, CVEItem
from threatlens_ai.backend.api.dependencies import get_cisa_service
from threatlens_ai.backend.api.routes import router


class StubCISAService:
    def __init__(self, items: list[CVEItem] | None = None, error: Exception | None = None) -> None:
        self.items = items or []
        self.error = error
        self.limit: int | None = None

    def get_latest(self, limit: int = 10) -> list[CVEItem]:
        self.limit = limit
        if self.error:
            raise self.error
        return self.items


def make_client(stub: StubCISAService) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_cisa_service] = lambda: stub
    return TestClient(app)


def test_latest_threats_returns_cisa_kev_items() -> None:
    stub = StubCISAService(
        items=[
            CVEItem.model_validate(
                {
                    "cveID": "CVE-2026-0001",
                    "vendorProject": "ExampleCorp",
                    "product": "ExampleProduct",
                    "severity": "Critical",
                    "dateAdded": "2026-07-06",
                    "dueDate": "2026-07-27",
                    "shortDescription": "Example description.",
                    "knownRansomwareCampaignUse": "Known",
                }
            )
        ]
    )
    client = make_client(stub)

    response = client.get("/threats/latest")

    assert response.status_code == 200
    assert stub.limit == 20
    assert response.json() == [
        {
            "cve": "CVE-2026-0001",
            "vendor": "ExampleCorp",
            "product": "ExampleProduct",
            "severity": "Critical",
            "date_added": "2026-07-06",
            "due_date": "2026-07-27",
            "description": "Example description.",
            "known_ransomware_campaign_use": "Known",
        }
    ]


def test_latest_threats_returns_bad_gateway_when_cisa_fails() -> None:
    client = make_client(StubCISAService(error=CISAServiceError("failed")))

    response = client.get("/threats/latest")

    assert response.status_code == 502
    assert response.json() == {"detail": "Unable to load CISA KEV catalog."}
