from pydantic import BaseSettings


class Settings(BaseSettings):
    fastapi_host: str = "0.0.0.0"
    fastapi_port: int = 8000
    environment: str = "production"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
