from fastapi import FastAPI

from .api.routes import router
from .core.config import settings

app = FastAPI(title="ThreatLens AI Backend")
app.include_router(router, prefix="/api")

@app.on_event("startup")
async def startup_event() -> None:
    """Startup hook placeholder."""
    # TODO: initialize database, caches, or agent orchestration hooks
    return None

@app.get("/health")
def health_check() -> dict[str, str]:
    """Simple health check endpoint."""
    return {"status": "ok", "service": "ThreatLens AI"}
