from fastapi import APIRouter

router = APIRouter()

@router.get("/placeholder")
def placeholder_endpoint() -> dict[str, str]:
    """Placeholder endpoint for backend routes."""
    return {"message": "This is a placeholder route for ThreatLens AI."}
