from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError

ROOT_DIR = Path(__file__).resolve().parents[1]
DOTENV_PATH = ROOT_DIR / ".env"

load_dotenv(dotenv_path=DOTENV_PATH, override=False)


class ConfigurationError(RuntimeError):
    """Raised when required ThreatLens AI configuration is missing or invalid."""


class Settings(BaseModel):
    """Application settings loaded from environment variables."""

    openai_api_key: str = Field(...)
    openai_model: str = Field("gpt-5.5")
    nvd_api_key: str = Field(...)
    fastapi_host: str = Field("0.0.0.0")
    fastapi_port: int = Field(8000)
    environment: str = Field("production")

    def validate(self) -> None:
        """Validate the current settings instance."""
        try:
            self.model_validate(self.model_dump())
        except ValidationError as error:
            raise ConfigurationError(
                "ThreatLens AI configuration is invalid. "
                "Please verify OPENAI_API_KEY and NVD_API_KEY are set."
            ) from error


def load_settings() -> Settings:
    """Create the settings object and raise a descriptive error if invalid."""
    config_values = {
        "openai_api_key": os.environ.get("OPENAI_API_KEY"),
        "openai_model": os.environ.get("OPENAI_MODEL", "gpt-5.5"),
        "nvd_api_key": os.environ.get("NVD_API_KEY"),
        "fastapi_host": os.environ.get("FASTAPI_HOST", "0.0.0.0"),
        "fastapi_port": int(os.environ.get("FASTAPI_PORT", 8000)),
        "environment": os.environ.get("ENVIRONMENT", "production"),
    }
    try:
        return Settings.model_validate(config_values)
    except ValidationError as error:
        raise ConfigurationError(
            "Failed to load ThreatLens AI settings. "
            "Required environment variables are missing or invalid."
        ) from error


settings = load_settings()
