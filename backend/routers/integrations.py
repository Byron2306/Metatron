from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio

from .dependencies import check_permission, get_current_user, get_db
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
from integrations_manager import run_amass, ingest_indicators_direct, get_job, list_jobs
from integrations_manager import run_velociraptor, ingest_host_logs
from integrations_manager import run_purplesharp
import os

# Internal token for machine-to-machine calls (Celery, unified_agent)
INTERNAL_TOKEN = os.environ.get('INTEGRATION_API_KEY', '').strip()

# Allow internal token bypass for ingestion calls
INTERNAL_TOKEN = os.environ.get('INTEGRATION_API_KEY', '')

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
    """Start Amass enumeration on the server; returns job id."""
    # Kick off background task
    task = asyncio.create_task(run_amass(req.domain))
    # task will register job internally and update
    # We don't have immediate job id from run_amass (it creates one), but run_amass returns job dict when complete
    # To provide job id immediately, run_amass creates a job entry first. We'll wait a tick for it to appear.
    await asyncio.sleep(0.1)
    jobs = list_jobs()
    # Find most recent job for amass/domain
    matches = [j for j in jobs if j.get('tool') == 'amass' and j.get('params', {}).get('domain') == req.domain]
    if not matches:
        raise HTTPException(status_code=500, detail='Failed to start amass job')
    job = sorted(matches, key=lambda x: x.get('created_at'), reverse=True)[0]
    await emit_world_event(get_db(), event_type="integration_amass_started", entity_refs=[job["id"], req.domain], payload={"actor": user.get("id")}, trigger_triune=False)
    return {"job_id": job['id'], "status": job['status']}

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
async def direct_ingest(req: DirectIngestRequest, request: Request, user: dict = Depends(check_permission("write"))):
    """Allow direct ingest either via authenticated user OR internal token header for M2M calls.

    Internal clients (workers/agents) should send header `X-Internal-Token` with value
    set in `INTEGRATION_API_KEY` env var.
    """
    # Accept internal token without normal auth
    internal = False
    hdr = request.headers.get('x-internal-token') or request.headers.get('X-Internal-Token')
    if hdr and INTERNAL_TOKEN and hdr.strip() == INTERNAL_TOKEN:
        internal = True

    if not internal:
        # permission dependency already enforced by caller via Depends; if it's present, proceed
        # (the dependency will raise if not allowed)
        pass

    items = [i.dict() for i in req.indicators]
    job = await ingest_indicators_direct(req.source, items)
    await emit_world_event(get_db(), event_type="integration_direct_ingest", entity_refs=[job["id"], req.source], payload={"indicator_count": len(items), "internal": internal, "actor": user.get("id") if isinstance(user, dict) else None}, trigger_triune=False)
    return {"job_id": job['id'], "status": job['status'], "result": job.get('result')}


class VelociraptorRequest(BaseModel):
    collection_name: Optional[str] = None


@router.post('/velociraptor/run')
async def start_velociraptor(req: VelociraptorRequest, user: dict = Depends(check_permission('write'))):
    """Start a Velociraptor collection on the server (enqueues Celery task)."""
    job = await run_velociraptor(req.collection_name)
    await emit_world_event(get_db(), event_type="integration_velociraptor_started", entity_refs=[job["id"]], payload={"collection_name": req.collection_name, "actor": user.get("id")}, trigger_triune=False)
    return {"job_id": job['id'], "status": job.get('status')}


class PurpleSharpRequest(BaseModel):
    target: Optional[str] = None
    options: Optional[Dict[str, Any]] = None


@router.post('/purplesharp/run')
async def start_purplesharp(req: PurpleSharpRequest, user: dict = Depends(check_permission('write'))):
    job = await run_purplesharp(req.target, req.options)
    await emit_world_event(get_db(), event_type="integration_purplesharp_started", entity_refs=[job["id"]], payload={"target": req.target, "actor": user.get("id")}, trigger_triune=False)
    return {"job_id": job['id'], "status": job.get('status')}


class HostLogIngestRequest(BaseModel):
    source: str
    raw: str


@router.post('/ingest/host')
async def ingest_host(req: HostLogIngestRequest, user: dict = Depends(check_permission('write'))):
    """Ingest raw host telemetry (Sysmon/Auditd) text and extract indicators."""
    job = await ingest_host_logs(req.source, req.raw)
    await emit_world_event(get_db(), event_type="integration_host_ingest", entity_refs=[job["id"], req.source], payload={"raw_size": len(req.raw), "actor": user.get("id")}, trigger_triune=False)
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
