from fastapi import APIRouter, Depends, HTTPException
from routers.dependencies import get_db
from services.world_model import WorldEntity, WorldEdge, WorldModelService
from typing import Dict, Any

router = APIRouter(prefix="/ingest", tags=["World Ingest"])


def _entity_from_payload(payload: Dict[str, Any]) -> WorldEntity:
    try:
        return WorldEntity(**payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


def _edge_from_payload(payload: Dict[str, Any]) -> WorldEdge:
    try:
        return WorldEdge(**payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/entity")
async def ingest_entity(payload: Dict[str, Any], db=Depends(get_db)):
    """Generic entity ingestion endpoint.  Body should match WorldEntity model."""
    wm = WorldModelService(db)
    entity = _entity_from_payload(payload)
    await wm.upsert_entity(entity)
    # after upsert, recalc risk
    if hasattr(wm, "calculate_risk"):
        await wm.calculate_risk(entity.id)
    return {"status": "ok", "id": entity.id}

@router.post("/edge")
async def ingest_edge(payload: Dict[str, Any], db=Depends(get_db)):
    """Create relationship between two entities."""
    wm = WorldModelService(db)
    edge = _edge_from_payload(payload)
    await wm.add_edge(edge)
    return {"status": "ok"}

@router.post("/detection")
async def ingest_detection(payload: Dict[str, Any], db=Depends(get_db)):
    """Ingest a detection hit and update entity attributes accordingly."""
    wm = WorldModelService(db)
    eid = payload.get("entity_id")
    if not eid:
        raise HTTPException(status_code=400, detail="entity_id required")
    # append detection record to entity attributes
    await wm.entities.update_one({"id": eid}, {"$push": {"attributes.detections": payload}}, upsert=True)
    if hasattr(wm, "calculate_risk"):
        await wm.calculate_risk(eid)
    return {"status": "ok"}

@router.post("/alert")
async def ingest_alert(payload: Dict[str, Any], db=Depends(get_db)):
    """Ingest an alert and create/update the corresponding entity."""
    wm = WorldModelService(db)
    eid = payload.get("entity_id") or payload.get("id")
    if not eid:
        raise HTTPException(status_code=400, detail="entity_id or id required")
    # treat alert as entity record
    ent = WorldEntity(id=eid, type=payload.get("type", "alert"), attributes=payload)
    await wm.upsert_entity(ent)
    if hasattr(wm, "calculate_risk"):
        await wm.calculate_risk(eid)
    return {"status": "ok"}

@router.post("/policy-violation")
async def ingest_policy_violation(payload: Dict[str, Any], db=Depends(get_db)):
    wm = WorldModelService(db)
    eid = payload.get("entity_id")
    if not eid:
        raise HTTPException(status_code=400, detail="entity_id required")
    await wm.entities.update_one({"id": eid}, {"$set": {"attributes.policy_violation": True}}, upsert=True)
    if hasattr(wm, "calculate_risk"):
        await wm.calculate_risk(eid)
    return {"status": "ok"}

@router.post("/token-event")
async def ingest_token_event(payload: Dict[str, Any], db=Depends(get_db)):
    wm = WorldModelService(db)
    eid = payload.get("token_id")
    if not eid:
        raise HTTPException(status_code=400, detail="token_id required")
    await wm.entities.update_one({"id": eid}, {"$push": {"attributes.token_events": payload}}, upsert=True)
    if hasattr(wm, "calculate_risk"):
        await wm.calculate_risk(eid)
    return {"status": "ok"}
