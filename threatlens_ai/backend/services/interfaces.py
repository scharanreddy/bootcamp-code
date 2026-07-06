from typing import Protocol

from threatlens_ai.models.threat import ThreatData


class ThreatServiceProtocol(Protocol):
    """Protocol for threat service implementations."""

    def analyze(self, data: ThreatData) -> dict[str, str]:
        """Analyze threat data and return a result payload."""
        ...

    def placeholder_message(self) -> str:
        """Return a placeholder response message."""
        ...
