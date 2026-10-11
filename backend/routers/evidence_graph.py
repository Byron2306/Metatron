from fastapi import APIRouter, Depends, HTTPException

try:
    from routers.dependencies import get_current_user, get_db
except Exception:
    from backend.routers.dependencies import get_current_user, get_db

try:
    from services.evidence_graph import build_technique_evidence_graph
except Exception:
    from backend.services.evidence_graph import build_technique_evidence_graph


router = APIRouter(prefix="/evidence-graph", tags=["Evidence Graph"])


@router.get("/techniques/{technique_id}")
async def get_technique_evidence_graph(
    technique_id: str,
    current_user: dict = Depends(get_current_user),
):
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    return await build_technique_evidence_graph(db, technique_id)
