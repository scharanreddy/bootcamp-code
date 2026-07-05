from pydantic import BaseModel


class ThreatData(BaseModel):
    """Placeholder model for threat analysis payloads."""

    source: str | None = None
    details: str | None = None
