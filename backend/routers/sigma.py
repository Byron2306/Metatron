from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Any, Dict

from .dependencies import get_current_user, check_permission
from sigma_engine import sigma_engine

router = APIRouter(prefix="/sigma", tags=["Sigma"])


class SigmaEventRequest(BaseModel):
    event: Dict[str, Any]
    max_matches: int = 25


@router.get("/status")
async def sigma_status(current_user: dict = Depends(get_current_user)):
    return sigma_engine.get_status()


@router.post("/reload")
async def sigma_reload(current_user: dict = Depends(check_permission("write"))):
    result = sigma_engine.reload_rules()
    return {
        "message": "Sigma rules reloaded",
        "loaded": result.get("loaded", 0),
        "errors": result.get("errors", []),
        "status": sigma_engine.get_status(),
    }


@router.get("/rules")
async def sigma_rules(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    query: str = Query("", max_length=120),
    current_user: dict = Depends(get_current_user),
):
    return sigma_engine.list_rules(limit=limit, offset=offset, query=query)


@router.get("/coverage")
async def sigma_coverage(current_user: dict = Depends(get_current_user)):
    return sigma_engine.coverage_summary()


@router.post("/evaluate")
async def sigma_evaluate(payload: SigmaEventRequest, current_user: dict = Depends(get_current_user)):
    return sigma_engine.evaluate_event(payload.event, max_matches=payload.max_matches)
