from fastapi import FastAPI

from .api.routes import router
from .core.config import settings

app = FastAPI(title="ThreatLens AI Backend")
app.include_router(router)

@app.on_event("startup")
async def startup_event() -> None:
    """Validate application configuration on startup."""
    settings.validate()
    # TODO: initialize database, caches, or agent orchestration hooks
    return None
