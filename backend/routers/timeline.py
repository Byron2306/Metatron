"""
Threat Timeline Router
"""
from dataclasses import asdict
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from .dependencies import get_current_user, get_db, check_permission

# world model ingestion helpers
from services.world_model import WorldModelService, WorldEntity, WorldEdge
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
try:
    from services.telemetry_chain import tamper_evident_telemetry
except Exception:
    from backend.services.telemetry_chain import tamper_evident_telemetry

# Import timeline services
from threat_timeline import timeline_builder, ReportType

router = APIRouter(prefix="/timeline", tags=["Timeline"])


def _record_timeline_audit(
    *,
    principal: str,
    action: str,
    targets: List[str],
    result: str,
    result_details: Optional[str] = None,
    constraints: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        tamper_evident_telemetry.set_db(get_db())
        tamper_evident_telemetry.record_action(
            principal=principal,
            principal_trust_state="trusted",
            action=action,
            targets=targets,
            constraints=constraints or {},
            result=result,
            result_details=result_details,
        )
    except Exception:
        pass


class ArtifactRegisterRequest(BaseModel):
    artifact_type: str
    name: str
    description: str
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None


class ArtifactCustodyUpdateRequest(BaseModel):
    action: str
    notes: Optional[str] = ""


@router.get("/correlate/all")
async def correlate_all_timelines(
    preload_limit: int = Query(25, ge=2, le=200),
    current_user: dict = Depends(check_permission("read")),
):
    """Correlate incidents across recent timelines."""
    _ = current_user
    db = get_db()

    # Prime correlator with recent incidents so correlation works after restart.
    recent = await db.threats.find({}, {"_id": 0, "id": 1}).sort("created_at", -1).limit(preload_limit).to_list(preload_limit)
    for item in recent:
        tid = item.get("id")
        if tid:
            await timeline_builder.build_timeline(tid, full_analysis=True)

    result = timeline_builder.correlate_all_incidents()
    result["preloaded_timelines"] = len(recent)
    return result


@router.get("/{threat_id}/related-incidents")
async def get_related_incidents(
    threat_id: str,
    current_user: dict = Depends(check_permission("read")),
):
    """Get incidents correlated to the provided threat timeline."""
    _ = current_user
    db = get_db()
    threat = await db.threats.find_one({"id": threat_id}, {"_id": 0, "id": 1})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    await timeline_builder.build_timeline(threat_id, full_analysis=True)
    related = timeline_builder.find_related_incidents(threat_id)
    return {
        "threat_id": threat_id,
        "related_incidents": related,
        "count": len(related),
    }


@router.get("/{threat_id}/report")
async def get_timeline_report(
    threat_id: str,
    type: str = Query("technical"),
    current_user: dict = Depends(check_permission("read")),
):
    """Generate enterprise incident report for a threat timeline."""
    actor = (current_user or {}).get("email") or (current_user or {}).get("id") or "unknown"
    db = get_db()
    threat = await db.threats.find_one({"id": threat_id}, {"_id": 0, "id": 1})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    try:
        report_type = ReportType(type.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"Unsupported report type: {type}",
                "supported": [rt.value for rt in ReportType],
            },
        )

    timeline = await timeline_builder.build_timeline(threat_id, full_analysis=True)
    if not timeline:
        raise HTTPException(status_code=404, detail="Could not build timeline")

    report = timeline_builder.generate_report(timeline, report_type=report_type)
    await emit_world_event(
        get_db(),
        event_type="timeline_report_generated",
        entity_refs=[threat_id],
        payload={"report_type": report_type.value, "actor": actor},
        trigger_triune=False,
    )
    _record_timeline_audit(
        principal=f"operator:{actor}",
        action="timeline_generate_report",
        targets=[threat_id],
        result="success",
        constraints={"report_type": report_type.value},
    )
    return {
        "threat_id": threat_id,
        "report_type": report_type.value,
        "report": report,
    }


@router.post("/artifacts/register")
async def register_timeline_artifact(
    request: ArtifactRegisterRequest,
    current_user: dict = Depends(check_permission("write")),
):
    """Register a forensic artifact for timeline evidence workflows."""
    actor = current_user.get("email") or current_user.get("name") or "unknown"
    artifact = timeline_builder.register_artifact(
        artifact_type=request.artifact_type,
        name=request.name,
        description=request.description,
        collected_by=actor,
        hash_md5=request.hash_md5,
        hash_sha256=request.hash_sha256,
    )
    # ingest artifact into world model so Metatron can see it
    try:
        db = get_db()
        wm = WorldModelService(db)
        await wm.upsert_entity(WorldEntity(
            id=artifact.artifact_id,
            type="file",  # use existing EntityType
            attributes=asdict(artifact),
        ))
        await emit_world_event(db, event_type="timeline_artifact_registered", entity_refs=[artifact.artifact_id], payload=asdict(artifact), trigger_triune=False)
    except Exception:
        # ingestion is best-effort
        logger.warning("Failed to ingest timeline artifact into world model")

    return {
        "status": "registered",
        "artifact": asdict(artifact),
    }


@router.post("/artifacts/{artifact_id}/custody")
async def update_artifact_custody(
    artifact_id: str,
    request: ArtifactCustodyUpdateRequest,
    current_user: dict = Depends(check_permission("write")),
):
    """Append chain-of-custody entry for an artifact."""
    actor = current_user.get("email") or current_user.get("name") or "unknown"
    ok = timeline_builder.update_artifact_custody(
        artifact_id=artifact_id,
        action=request.action,
        actor=actor,
        notes=request.notes or "",
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Artifact not found")

    artifact = timeline_builder.get_artifact(artifact_id)
    # create an edge in world model representing the custody update
    try:
        db = get_db()
        wm = WorldModelService(db)
        await wm.add_edge(WorldEdge(source=artifact_id, target=actor, relation="custody_update"))
        await emit_world_event(db, event_type="timeline_custody_updated", entity_refs=[artifact_id, actor], payload={"action": request.action, "notes": request.notes or ""}, trigger_triune=False)
    except Exception:
        logger.warning("Failed to record custody edge in world model")

    return {
        "status": "updated",
        "artifact_id": artifact_id,
        "artifact": artifact,
    }


@router.get("/artifacts/{artifact_id}/custody-report")
async def get_artifact_custody_report(
    artifact_id: str,
    current_user: dict = Depends(check_permission("read")),
):
    """Export chain-of-custody report for a forensic artifact."""
    actor = (current_user or {}).get("email") or (current_user or {}).get("id") or "unknown"
    report = timeline_builder.export_custody_report(artifact_id)
    if not report:
        raise HTTPException(status_code=404, detail="Artifact not found")
    await emit_world_event(
        get_db(),
        event_type="timeline_custody_report_exported",
        entity_refs=[artifact_id],
        payload={"actor": actor},
        trigger_triune=False,
    )
    _record_timeline_audit(
        principal=f"operator:{actor}",
        action="timeline_export_custody_report",
        targets=[artifact_id],
        result="success",
    )

    return {
        "artifact_id": artifact_id,
        "report_markdown": report,
    }

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
    actor = (current_user or {}).get("email") or (current_user or {}).get("id") or "unknown"
    await emit_world_event(
        get_db(),
        event_type="timeline_export_requested",
        entity_refs=[threat_id],
        payload={"format": format, "actor": actor},
        trigger_triune=False,
    )
    _record_timeline_audit(
        principal=f"operator:{actor}",
        action="timeline_export_requested",
        targets=[threat_id],
        result="success",
        constraints={"format": format},
    )
    if format == "json":
        return asdict(timeline)
    elif format == "markdown":
        return {"markdown": timeline_builder._to_markdown(timeline)}
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
