"""
Alerts Router
"""
from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime, timezone
from typing import Optional
import uuid

from .dependencies import (
    AlertCreate, AlertResponse, get_current_user, get_db
)
from services.world_events import emit_world_event

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.post("", response_model=AlertResponse)
async def create_alert(alert_data: AlertCreate, current_user: dict = Depends(get_current_user)):
    db = get_db()
    alert_id = str(uuid.uuid4())
    alert_doc = {
        "id": alert_id,
        "title": alert_data.title,
        "type": alert_data.type,
        "severity": alert_data.severity,
        "threat_id": alert_data.threat_id,
        "message": alert_data.message,
        "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.alerts.insert_one(alert_doc)

    from services.world_model import WorldModelService, WorldEntity
    wm = WorldModelService(db)
    await wm.upsert_entity(WorldEntity(id=alert_id, type="alert", attributes=alert_doc))
    await emit_world_event(db, event_type="alert_created", entity_refs=[alert_id], payload=alert_doc)
    return AlertResponse(**alert_doc)


@router.get("")
async def get_alerts(status: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    db = get_db()
    query = {}
    if status:
        query["status"] = status
    alerts = await db.alerts.find(query, {"_id": 0}).sort([("created_at", -1), ("timestamp", -1)]).to_list(100)

    normalized_alerts = []
    for a in alerts:
        normalized_alerts.append({
            "id": a.get("id") or str(uuid.uuid4()),
            "title": a.get("title") or a.get("event_type") or a.get("message", "Alert")[:50],
            "type": a.get("type", "unknown"),
            "severity": a.get("severity", "medium"),
            "threat_id": a.get("threat_id"),
            "message": a.get("message", ""),
            "status": a.get("status", "new"),
            "created_at": a.get("created_at") or a.get("timestamp") or datetime.now(timezone.utc).isoformat()
        })

    return {"alerts": normalized_alerts, "count": len(normalized_alerts)}


@router.patch("/{alert_id}/status")
async def update_alert_status(alert_id: str, status: str, current_user: dict = Depends(get_current_user)):
    db = get_db()
    if status not in ["new", "acknowledged", "resolved"]:
        raise HTTPException(status_code=400, detail="Invalid status")

    result = await db.alerts.update_one({"id": alert_id}, {"$set": {"status": status}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Alert not found")

    await emit_world_event(
        db,
        event_type="alert_status_updated",
        entity_refs=[alert_id],
        payload={"status": status, "updated_by": current_user.get("id")},
    )
    return {"message": "Alert status updated", "status": status}
