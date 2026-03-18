"""
Sandbox Analysis Router - Dynamic malware analysis
"""
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, BackgroundTasks
from typing import Optional, List
from pydantic import BaseModel

from .dependencies import get_current_user, check_permission, get_db
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
try:
    from services.outbound_gate import OutboundGateService
except Exception:
    from backend.services.outbound_gate import OutboundGateService
from sandbox_analysis import sandbox_service, SandboxService

router = APIRouter(prefix="/sandbox", tags=["Sandbox Analysis"])


class SubmitURLRequest(BaseModel):
    url: str
    tags: Optional[List[str]] = None


class SubmitHashRequest(BaseModel):
    sample_hash: str
    sample_name: str
    tags: Optional[List[str]] = None


@router.get("/stats")
async def get_sandbox_stats(current_user: dict = Depends(get_current_user)):
    """Get sandbox analysis statistics"""
    return sandbox_service.get_stats()


@router.get("/analyses")
async def get_analyses(
    limit: int = 50,
    status: Optional[str] = None,
    verdict: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get list of sandbox analyses"""
    analyses = sandbox_service.get_analyses(
        limit=limit,
        status=status,
        verdict=verdict
    )
    return {"analyses": analyses, "count": len(analyses)}


@router.get("/analyses/{analysis_id}")
async def get_analysis(analysis_id: str, current_user: dict = Depends(get_current_user)):
    """Get detailed analysis results"""
    analysis = sandbox_service.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis


@router.post("/submit/file")
async def submit_file_for_analysis(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    tags: Optional[str] = None,
    current_user: dict = Depends(check_permission("write"))
):
    """Queue file submission through outbound governance."""
    gate = OutboundGateService(get_db())
    actor = current_user.get("email", current_user.get("id", "unknown"))
    tag_list = tags.split(",") if tags else []
    gated = await gate.gate_action(
        action_type="tool_execution",
        actor=actor,
        payload={"sandbox_action": "submit_file", "file_name": file.filename, "tags": tag_list},
        impact_level="high",
        subject_id=file.filename,
        entity_refs=[file.filename],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="sandbox_file_submission_gated",
        entity_refs=[file.filename, gated.get("queue_id"), gated.get("decision_id")],
        payload={"actor": current_user.get("id")},
        trigger_triune=True,
    )
    return {
        "status": "queued_for_triune_approval",
        "file_name": file.filename,
        "queue_id": gated.get("queue_id"),
        "decision_id": gated.get("decision_id"),
    }


@router.post("/submit/url")
async def submit_url_for_analysis(
    request: SubmitURLRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(check_permission("write"))
):
    """Queue URL submission through outbound governance."""
    gate = OutboundGateService(get_db())
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gated = await gate.gate_action(
        action_type="tool_execution",
        actor=actor,
        payload={"sandbox_action": "submit_url", "url": request.url, "tags": request.tags or []},
        impact_level="high",
        subject_id=request.url,
        entity_refs=[request.url],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="sandbox_url_submission_gated",
        entity_refs=[request.url, gated.get("queue_id"), gated.get("decision_id")],
        payload={"actor": current_user.get("id")},
        trigger_triune=True,
    )
    return {
        "status": "queued_for_triune_approval",
        "url": request.url,
        "queue_id": gated.get("queue_id"),
        "decision_id": gated.get("decision_id"),
    }


@router.post("/analyses/{analysis_id}/rerun")
async def rerun_analysis(
    analysis_id: str,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(check_permission("write"))
):
    """Queue analysis re-run through outbound governance."""
    analysis = sandbox_service.get_analysis(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    gate = OutboundGateService(get_db())
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gated = await gate.gate_action(
        action_type="tool_execution",
        actor=actor,
        payload={"sandbox_action": "rerun_analysis", "analysis_id": analysis_id},
        impact_level="high",
        subject_id=analysis_id,
        entity_refs=[analysis_id],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="sandbox_analysis_rerun_gated",
        entity_refs=[analysis_id, gated.get("queue_id"), gated.get("decision_id")],
        payload={"actor": current_user.get("id")},
        trigger_triune=True,
    )
    return {"message": "Analysis queued for triune approval", "status": "queued_for_triune_approval", "analysis_id": analysis_id, "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}


@router.get("/signatures")
async def get_signatures(current_user: dict = Depends(get_current_user)):
    """Get available malware signatures"""
    return {
        "signatures": sandbox_service.signatures,
        "count": len(sandbox_service.signatures)
    }


@router.get("/queue")
async def get_queue_status(current_user: dict = Depends(get_current_user)):
    """Get sandbox queue status"""
    return {
        "queue_length": len(sandbox_service.queue),
        "running": sandbox_service.running_count,
        "max_concurrent": sandbox_service.max_concurrent,
        "vm_pool": sandbox_service.vm_pool,
        "queued_ids": sandbox_service.queue[:10]  # First 10
    }
