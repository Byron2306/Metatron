from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio

from .dependencies import (
    check_permission,
    get_current_user,
    get_optional_current_user,
    has_permission,
    optional_machine_token,
    get_db,
)
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
try:
    from services.outbound_gate import OutboundGateService
except Exception:
    from backend.services.outbound_gate import OutboundGateService
from integrations_manager import run_amass, ingest_indicators_direct, get_job, list_jobs
from integrations_manager import run_velociraptor, ingest_host_logs
from integrations_manager import run_purplesharp
verify_integrations_machine_token = optional_machine_token(
    env_keys=["INTEGRATION_API_KEY", "SWARM_AGENT_TOKEN"],
    header_names=["x-internal-token", "x-agent-token"],
    subject="integrations internal",
)

router = APIRouter(prefix="/integrations", tags=["Integrations"])

class AmassRequest(BaseModel):
    domain: str

class IngestItem(BaseModel):
    type: Optional[str] = None
    value: str
    confidence: Optional[int] = 50
    threat_level: Optional[str] = "medium"
    description: Optional[str] = ""
    tags: Optional[List[str]] = []
    references: Optional[List[str]] = []

class DirectIngestRequest(BaseModel):
    source: str
    indicators: List[IngestItem]

@router.post("/amass/run")
async def start_amass(req: AmassRequest, user: dict = Depends(check_permission("write"))):
    """Queue Amass execution through outbound governance."""
    actor = user.get("email", user.get("id", "unknown"))
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="tool_execution",
        actor=actor,
        payload={"tool": "amass", "domain": req.domain},
        impact_level="high",
        subject_id=req.domain,
        entity_refs=[req.domain],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="integration_amass_gated",
        entity_refs=[req.domain, gated.get("queue_id"), gated.get("decision_id")],
        payload={"actor": user.get("id")},
        trigger_triune=True,
    )
    return {"status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}

@router.get("/jobs")
async def get_jobs(user: dict = Depends(get_current_user)):
    return list_jobs()

@router.get("/jobs/{job_id}")
async def get_job_status(job_id: str, user: dict = Depends(get_current_user)):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='job not found')
    return job

@router.post("/ingest/direct")
async def direct_ingest(
    req: DirectIngestRequest,
    request: Request,
    machine_auth: Optional[dict] = Depends(verify_integrations_machine_token),
    user: Optional[dict] = Depends(get_optional_current_user),
):
    """Allow direct ingest either via authenticated user OR internal token header for M2M calls.

    Internal clients (workers/agents) should send header `X-Internal-Token` with value
    set in `INTEGRATION_API_KEY` env var.
    """
    internal = machine_auth is not None
    if not internal:
        if user is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        if not has_permission(user, "write"):
            raise HTTPException(status_code=403, detail="Permission denied. Required: write")

    items = [i.dict() for i in req.indicators]
    job = await ingest_indicators_direct(req.source, items)
    actor = "machine" if internal else user.get("id")
    await emit_world_event(get_db(), event_type="integration_direct_ingest", entity_refs=[job["id"], req.source], payload={"indicator_count": len(items), "internal": internal, "actor": actor}, trigger_triune=False)
    return {"job_id": job['id'], "status": job['status'], "result": job.get('result')}


class VelociraptorRequest(BaseModel):
    collection_name: Optional[str] = None


@router.post('/velociraptor/run')
async def start_velociraptor(req: VelociraptorRequest, user: dict = Depends(check_permission('write'))):
    """Queue Velociraptor execution through outbound governance."""
    actor = user.get("email", user.get("id", "unknown"))
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="tool_execution",
        actor=actor,
        payload={"tool": "velociraptor", "collection_name": req.collection_name},
        impact_level="critical",
        subject_id=req.collection_name,
        entity_refs=[req.collection_name or "velociraptor_default"],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="integration_velociraptor_gated",
        entity_refs=[gated.get("queue_id"), gated.get("decision_id")],
        payload={"collection_name": req.collection_name, "actor": user.get("id")},
        trigger_triune=True,
    )
    return {"status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}


class PurpleSharpRequest(BaseModel):
    target: Optional[str] = None
    options: Optional[Dict[str, Any]] = None


@router.post('/purplesharp/run')
async def start_purplesharp(req: PurpleSharpRequest, user: dict = Depends(check_permission('write'))):
    actor = user.get("email", user.get("id", "unknown"))
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="tool_execution",
        actor=actor,
        payload={"tool": "purplesharp", "target": req.target, "options": req.options or {}},
        impact_level="critical",
        subject_id=req.target,
        entity_refs=[req.target or "purplesharp_default"],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="integration_purplesharp_gated",
        entity_refs=[gated.get("queue_id"), gated.get("decision_id")],
        payload={"target": req.target, "actor": user.get("id")},
        trigger_triune=True,
    )
    return {"status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}


class HostLogIngestRequest(BaseModel):
    source: str
    raw: str


@router.post('/ingest/host')
async def ingest_host(
    req: HostLogIngestRequest,
    machine_auth: Optional[dict] = Depends(verify_integrations_machine_token),
    user: Optional[dict] = Depends(get_optional_current_user),
):
    """Ingest raw host telemetry (Sysmon/Auditd) text and extract indicators."""
    internal = machine_auth is not None
    if not internal:
        if user is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        if not has_permission(user, "write"):
            raise HTTPException(status_code=403, detail="Permission denied. Required: write")
    job = await ingest_host_logs(req.source, req.raw)
    actor = "machine" if internal else user.get("id")
    await emit_world_event(get_db(), event_type="integration_host_ingest", entity_refs=[job["id"], req.source], payload={"raw_size": len(req.raw), "actor": actor}, trigger_triune=False)
    return {"job_id": job['id'], "status": job['status'], "result": job.get('result')}


@router.get('/artifacts/{job_id}')
async def list_artifacts(job_id: str, request: Request, user: dict = Depends(get_current_user)):
    """List artifact filenames for a job (if available)."""
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='job not found')
    result = job.get('result') or {}
    artifacts = result.get('artifacts') or []
    artifact_dir = result.get('artifact_dir')
    return {"artifacts": artifacts, "artifact_dir": artifact_dir}


@router.get('/artifact/{job_id}/{filename}')
async def get_artifact(job_id: str, filename: str, request: Request, user: dict = Depends(get_current_user)):
    """Download a specific artifact file for a job.
    Note: artifact paths are trusted only when running in controlled environment.
    """
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='job not found')
    result = job.get('result') or {}
    artifact_dir = result.get('artifact_dir')
    if not artifact_dir:
        raise HTTPException(status_code=404, detail='no artifacts for this job')
    # Prevent path traversal
    safe_base = os.path.abspath(artifact_dir)
    candidate = os.path.abspath(os.path.join(safe_base, filename))
    if not candidate.startswith(safe_base):
        raise HTTPException(status_code=400, detail='invalid filename')
    if not os.path.exists(candidate):
        raise HTTPException(status_code=404, detail='file not found')
    return FileResponse(candidate, filename=filename)
