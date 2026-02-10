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
    
    # Build timeline (only takes threat_id)
    timeline = await timeline_builder.build_timeline(threat_id)
    if not timeline:
        raise HTTPException(status_code=404, detail="Could not build timeline")
    
    from dataclasses import asdict
    return asdict(timeline)

@router.get("/{threat_id}/export")
async def export_threat_timeline(threat_id: str, format: str = "json", current_user: dict = Depends(get_current_user)):
    """Export timeline in specified format"""
    db = get_db()
    
    threat = await db.threats.find_one({"id": threat_id}, {"_id": 0})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    timeline = await timeline_builder.build_timeline(threat_id)
    if not timeline:
        raise HTTPException(status_code=404, detail="Could not build timeline")
    
    from dataclasses import asdict
    if format == "json":
        return asdict(timeline)
    elif format == "markdown":
        return {"content": timeline_builder._to_markdown(timeline)}
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

# Alternative route for listing recent timelines
timelines_router = APIRouter(prefix="/timelines", tags=["Timeline"])

@timelines_router.get("/recent")
async def get_recent_timelines(limit: int = 10, current_user: dict = Depends(get_current_user)):
    """Get recent threat timelines"""
    # Use the class method that handles this properly
    timelines = await timeline_builder.get_recent_timelines(limit)
    return {"timelines": timelines, "count": len(timelines)}
