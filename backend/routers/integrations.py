from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import os

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
from integrations_manager import (
    ingest_indicators_direct,
    run_runtime_tool,
    get_job_async,
    list_jobs_async,
    SUPPORTED_RUNTIME_TOOLS,
)
from integrations_manager import ingest_host_logs
verify_integrations_machine_token = optional_machine_token(
    env_keys=["INTEGRATION_API_KEY", "SWARM_AGENT_TOKEN"],
    header_names=["x-internal-token", "x-agent-token"],
    subject="integrations internal",
)

router = APIRouter(prefix="/integrations", tags=["Integrations"])

class AmassRequest(BaseModel):
    domain: str
    runtime_target: Optional[str] = "server"
    agent_id: Optional[str] = None

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

class RuntimeLaunchRequest(BaseModel):
    tool: str
    params: Optional[Dict[str, Any]] = None
    runtime_target: Optional[str] = "server"
    agent_id: Optional[str] = None


class ToolRunRequest(BaseModel):
    params: Optional[Dict[str, Any]] = None
    runtime_target: Optional[str] = "server"
    agent_id: Optional[str] = None


def _runtime_job_response(job: Dict[str, Any]) -> Dict[str, Any]:
    result = job.get("result") if isinstance(job, dict) else {}
    result = result if isinstance(result, dict) else {}
    return {
        "status": job.get("status"),
        "job_id": job.get("id"),
        "tool": job.get("tool"),
        "runtime_target": (job.get("params") or {}).get("runtime_target") or result.get("runtime_target") or "server",
        "agent_id": result.get("agent_id") or (job.get("params") or {}).get("agent_id"),
        "command_id": result.get("command_id"),
        "queue_id": result.get("queue_id"),
        "decision_id": result.get("decision_id"),
        "result": result,
    }


async def _start_tool_runtime(
    *,
    tool: str,
    params: Dict[str, Any],
    runtime_target: str,
    agent_id: Optional[str],
    user: Dict[str, Any],
) -> Dict[str, Any]:
    job = await run_runtime_tool(
        tool=tool,
        params=params or {},
        runtime_target=runtime_target or "server",
        agent_id=agent_id,
        actor=user.get("email", user.get("id", "unknown")),
        governance_context={
            "approved": True,
            "decision_id": f"integration-{tool}-direct",
            "queue_id": f"integration-{tool}-direct",
        },
    )
    await emit_world_event(
        get_db(),
        event_type=f"integration_{tool}_runtime_requested",
        entity_refs=[tool, job.get("id"), (job.get("result") or {}).get("queue_id")],
        payload={
            "tool": tool,
            "actor": user.get("id"),
            "runtime_target": runtime_target or "server",
            "agent_id": agent_id,
        },
        trigger_triune=False,
    )
    return _runtime_job_response(job)

@router.post("/amass/run")
async def start_amass(req: AmassRequest, user: dict = Depends(check_permission("write"))):
    """Run Amass on server or queue it for unified-agent runtime."""
    return await _start_tool_runtime(
        tool="amass",
        params={"domain": req.domain},
        runtime_target=req.runtime_target or "server",
        agent_id=req.agent_id,
        user=user,
    )

@router.get("/jobs")
async def get_jobs(user: dict = Depends(get_current_user)):
    return await list_jobs_async()

@router.get("/jobs/{job_id}")
async def get_job_status(job_id: str, user: dict = Depends(get_current_user)):
    job = await get_job_async(job_id)
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
    runtime_target: Optional[str] = "server"
    agent_id: Optional[str] = None


@router.post('/velociraptor/run')
async def start_velociraptor(req: VelociraptorRequest, user: dict = Depends(check_permission('write'))):
    return await _start_tool_runtime(
        tool="velociraptor",
        params={"collection_name": req.collection_name},
        runtime_target=req.runtime_target or "server",
        agent_id=req.agent_id,
        user=user,
    )


class PurpleSharpRequest(BaseModel):
    target: Optional[str] = None
    options: Optional[Dict[str, Any]] = None
    runtime_target: Optional[str] = "server"
    agent_id: Optional[str] = None


@router.post('/purplesharp/run')
async def start_purplesharp(req: PurpleSharpRequest, user: dict = Depends(check_permission('write'))):
    return await _start_tool_runtime(
        tool="purplesharp",
        params={"target": req.target, "options": req.options or {}},
        runtime_target=req.runtime_target or "server",
        agent_id=req.agent_id,
        user=user,
    )


@router.post('/arkime/run')
async def start_arkime(req: ToolRunRequest, user: dict = Depends(check_permission("write"))):
    return await _start_tool_runtime(
        tool="arkime",
        params=req.params or {},
        runtime_target=req.runtime_target or "server",
        agent_id=req.agent_id,
        user=user,
    )


@router.post('/bloodhound/run')
async def start_bloodhound(req: ToolRunRequest, user: dict = Depends(check_permission("write"))):
    return await _start_tool_runtime(
        tool="bloodhound",
        params=req.params or {},
        runtime_target=req.runtime_target or "server",
        agent_id=req.agent_id,
        user=user,
    )


@router.post('/spiderfoot/run')
async def start_spiderfoot(req: ToolRunRequest, user: dict = Depends(check_permission("write"))):
    return await _start_tool_runtime(
        tool="spiderfoot",
        params=req.params or {},
        runtime_target=req.runtime_target or "server",
        agent_id=req.agent_id,
        user=user,
    )


@router.post('/sigma/run')
async def start_sigma(req: ToolRunRequest, user: dict = Depends(check_permission("write"))):
    return await _start_tool_runtime(
        tool="sigma",
        params=req.params or {},
        runtime_target=req.runtime_target or "server",
        agent_id=req.agent_id,
        user=user,
    )


@router.post('/atomic/run')
async def start_atomic(req: ToolRunRequest, user: dict = Depends(check_permission("write"))):
    return await _start_tool_runtime(
        tool="atomic",
        params=req.params or {},
        runtime_target=req.runtime_target or "server",
        agent_id=req.agent_id,
        user=user,
    )


class HostLogIngestRequest(BaseModel):
    source: str
    raw: str


@router.get("/runtime/tools")
async def runtime_supported_tools(user: dict = Depends(get_current_user)):
    return {"tools": sorted(SUPPORTED_RUNTIME_TOOLS)}


@router.post("/runtime/run")
async def start_runtime_launch(payload: RuntimeLaunchRequest, user: dict = Depends(check_permission("write"))):
    tool = str(payload.tool or "").strip().lower()
    if tool not in SUPPORTED_RUNTIME_TOOLS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported tool '{payload.tool}'. Supported: {sorted(SUPPORTED_RUNTIME_TOOLS)}",
        )
    return await _start_tool_runtime(
        tool=tool,
        params=payload.params or {},
        runtime_target=payload.runtime_target or "server",
        agent_id=payload.agent_id,
        user=user,
    )


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
    job = await get_job_async(job_id)
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
    job = await get_job_async(job_id)
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
