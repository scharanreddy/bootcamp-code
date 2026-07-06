from __future__ import annotations

import os

DEFAULT_API_BASE_URL = "http://localhost:8000"
DEFAULT_TIMEOUT_SECONDS = 30.0


class FrontendSettings:
    """Frontend-only settings, resolved independently of backend secrets.

    The backend's Settings model requires OPENAI_API_KEY and NVD_API_KEY, but
    the Streamlit process only needs to know where the API lives, so it reads
    its own small set of environment variables instead of importing app.config.
    """

    def __init__(self) -> None:
        self.api_base_url = os.environ.get("API_BASE_URL", DEFAULT_API_BASE_URL).rstrip("/")
        self.request_timeout = float(
            os.environ.get("API_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
        )


settings = FrontendSettings()
