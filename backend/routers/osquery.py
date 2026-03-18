from typing import Dict, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from .dependencies import get_current_user, check_permission, get_db
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
from osquery_fleet import osquery_fleet

router = APIRouter(prefix="/osquery", tags=["Osquery Fleet"])


class LiveQueryRequest(BaseModel):
    sql: str = Field(..., min_length=1, max_length=4000)
    selected: Dict[str, Any] = Field(default_factory=dict)


@router.get("/status")
async def osquery_status(current_user: dict = Depends(get_current_user)):
    return osquery_fleet.get_status()


@router.get("/stats")
async def osquery_stats(current_user: dict = Depends(get_current_user)):
    return osquery_fleet.get_stats()


@router.get("/results")
async def osquery_results(
    limit: int = Query(100, ge=1, le=500),
    current_user: dict = Depends(get_current_user),
):
    return osquery_fleet.get_results(limit=limit)


@router.get("/queries")
async def osquery_queries(
    limit: int = Query(50, ge=1, le=200),
    query: str = Query("", max_length=120),
    current_user: dict = Depends(get_current_user),
):
    return osquery_fleet.list_queries(limit=limit, query=query)


@router.get("/hosts")
async def osquery_hosts(
    limit: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
):
    return osquery_fleet.list_hosts(limit=limit)


@router.post("/live-query")
async def osquery_live_query(
    payload: LiveQueryRequest,
    current_user: dict = Depends(check_permission("write")),
):
    result = osquery_fleet.run_live_query(payload.sql, selected=payload.selected)
    await emit_world_event(get_db(), event_type="osquery_live_query_executed", entity_refs=[], payload={"actor": current_user.get("id"), "sql": payload.sql[:120], "selected_count": len(payload.selected)}, trigger_triune=False)
    return result
