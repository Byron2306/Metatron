from celery_app import celery_app
from services.world_model import WorldModelService, WorldEntity, WorldEdge
from typing import Dict, Any

@celery_app.task(name="backend.tasks.world_ingest.ingest_entity")
async def ingest_entity_task(db_config: Dict[str, Any], payload: Dict[str, Any]):
    # db_config could be connection settings; for now we assume app-level Mongo client accessible
    from backend.server import db as global_db
    wm = WorldModelService(global_db)
    entity = WorldEntity(**payload)
    await wm.upsert_entity(entity)
    return {"status": "ok", "id": entity.id}

@celery_app.task(name="backend.tasks.world_ingest.ingest_edge")
async def ingest_edge_task(db_config: Dict[str, Any], payload: Dict[str, Any]):
    from backend.server import db as global_db
    wm = WorldModelService(global_db)
    edge = WorldEdge(**payload)
    await wm.add_edge(edge)
    return {"status": "ok"}

@celery_app.task(name="backend.tasks.world_ingest.ingest_detection")
async def ingest_detection_task(db_config: Dict[str, Any], payload: Dict[str, Any]):
    from backend.server import db as global_db
    wm = WorldModelService(global_db)
    eid = payload.get("entity_id")
    if eid:
        await wm.entities.update_one({"id": eid}, {"$push": {"attributes.detections": payload}}, upsert=True)
        if hasattr(wm, "calculate_risk"):
            await wm.calculate_risk(eid)
    return {"status": "ok"}

@celery_app.task(name="backend.tasks.world_ingest.ingest_alert")
async def ingest_alert_task(db_config: Dict[str, Any], payload: Dict[str, Any]):
    from backend.server import db as global_db
    wm = WorldModelService(global_db)
    eid = payload.get("entity_id") or payload.get("id")
    if eid:
        ent = WorldEntity(id=eid, type=payload.get("type", "alert"), attributes=payload)
        await wm.upsert_entity(ent)
        if hasattr(wm, "calculate_risk"):
            await wm.calculate_risk(eid)
    return {"status": "ok"}

@celery_app.task(name="backend.tasks.world_ingest.ingest_policy_violation")
async def ingest_policy_violation_task(db_config: Dict[str, Any], payload: Dict[str, Any]):
    from backend.server import db as global_db
    wm = WorldModelService(global_db)
    eid = payload.get("entity_id")
    if eid:
        await wm.entities.update_one({"id": eid}, {"$set": {"attributes.policy_violation": True}}, upsert=True)
        if hasattr(wm, "calculate_risk"):
            await wm.calculate_risk(eid)
    return {"status": "ok"}

@celery_app.task(name="backend.tasks.world_ingest.ingest_token_event")
async def ingest_token_event_task(db_config: Dict[str, Any], payload: Dict[str, Any]):
    from backend.server import db as global_db
    wm = WorldModelService(global_db)
    eid = payload.get("token_id")
    if eid:
        await wm.entities.update_one({"id": eid}, {"$push": {"attributes.token_events": payload}}, upsert=True)
        if hasattr(wm, "calculate_risk"):
            await wm.calculate_risk(eid)
    return {"status": "ok"}
