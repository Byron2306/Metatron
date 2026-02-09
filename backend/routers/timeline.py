"""
Threat Timeline Router
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional

from .dependencies import get_current_user, get_db

# Import timeline services
from threat_timeline import timeline_builder

router = APIRouter(prefix="/timeline", tags=["Timeline"])

@router.get("/{threat_id}")
async def get_threat_timeline(threat_id: str, current_user: dict = Depends(get_current_user)):
    """Get complete timeline for a threat"""
    db = get_db()
    
    # Check if threat exists
    threat = await db.threats.find_one({"id": threat_id}, {"_id": 0})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    # Build timeline
    timeline = await timeline_builder.build_timeline(threat_id, threat)
    return timeline.to_dict()

@router.get("/{threat_id}/export")
async def export_threat_timeline(threat_id: str, format: str = "json", current_user: dict = Depends(get_current_user)):
    """Export timeline in specified format"""
    db = get_db()
    
    threat = await db.threats.find_one({"id": threat_id}, {"_id": 0})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    timeline = await timeline_builder.build_timeline(threat_id, threat)
    
    if format == "json":
        return timeline.to_dict()
    elif format == "markdown":
        return {"content": timeline.to_markdown()}
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

# Alternative route for listing recent timelines
timelines_router = APIRouter(prefix="/timelines", tags=["Timeline"])

@timelines_router.get("/recent")
async def get_recent_timelines(limit: int = 10, current_user: dict = Depends(get_current_user)):
    """Get recent threat timelines"""
    db = get_db()
    threats = await db.threats.find({}, {"_id": 0}).sort("created_at", -1).to_list(limit)
    
    timelines = []
    for threat in threats:
        timeline = await timeline_builder.build_timeline(threat["id"], threat)
        timelines.append({
            "threat_id": threat["id"],
            "threat_name": threat["name"],
            "severity": threat["severity"],
            "status": threat["status"],
            "event_count": len(timeline.events),
            "created_at": threat["created_at"]
        })
    
    return timelines
