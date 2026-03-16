import asyncio
import json
import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import os
import re

from routers.dependencies import get_db

_scheduler_task = None
_scheduler_config = {}

from runtime_paths import ensure_data_dir
from threat_intel import threat_intel
try:
    from services.governance_context import assert_governance_context
except Exception:
    from backend.services.governance_context import assert_governance_context

try:
    from services.world_events import emit_world_event
except Exception:  # pragma: no cover
    try:
        from backend.services.world_events import emit_world_event
    except Exception:  # pragma: no cover
        emit_world_event = None

logger = logging.getLogger(__name__)

# Directory for temporary integration outputs
INTEGRATIONS_DIR = ensure_data_dir("integrations")
INTEGRATIONS_DIR.mkdir(parents=True, exist_ok=True)

_jobs: Dict[str, Dict[str, Any]] = {}
SUPPORTED_RUNTIME_TOOLS = {
    "amass",
    "arkime",
    "bloodhound",
    "spiderfoot",
    "velociraptor",
    "purplesharp",
    "sigma",
    "atomic",
}


def _db_collection():
    db = get_db()
    if db is None:
        return None
    return db.integrations_jobs


def _json_safe(value: Any) -> Any:
    """Recursively make integration job payloads JSON-safe."""
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, inner in value.items():
            if key == "_id":
                # Do not leak database-specific identifiers in API payloads.
                continue
            out[key] = _json_safe(inner)
        return out
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    # Handle bson.ObjectId without importing bson as hard dependency.
    if value.__class__.__name__ == "ObjectId":
        return str(value)
    return value


async def _emit_integration_event(event_type: str, entity_refs: List[str] = None, payload: Dict[str, Any] = None, trigger_triune: bool = False):
    db = get_db()
    if db is None or emit_world_event is None:
        return
    try:
        await emit_world_event(
            db,
            event_type=event_type,
            entity_refs=entity_refs or [],
            payload=payload or {},
            trigger_triune=trigger_triune,
        )
    except Exception:
        logger.debug("integration world event emission failed", exc_info=True)

async def _new_job(tool: str, params: Dict[str, Any]):
    job_id = str(uuid.uuid4())
    job_doc = {
        "id": job_id,
        "tool": tool,
        "params": params,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "result": None,
    }
    # insert into DB if available
    col = _db_collection()
    if col is not None:
        await col.insert_one(dict(job_doc))
    # also keep in-memory copy for quick listing
    _jobs[job_id] = dict(job_doc)
    await _emit_integration_event(
        "integration_job_created_service",
        entity_refs=[job_id],
        payload={"tool": tool},
        trigger_triune=False,
    )
    return job_id


async def _persist_job(job_id: str, **fields: Any) -> Dict[str, Any]:
    """Persist integration job updates in memory + DB."""
    now = datetime.utcnow().isoformat()
    fields = dict(fields or {})
    fields.setdefault("updated_at", now)
    if job_id not in _jobs:
        _jobs[job_id] = {"id": job_id}
    _jobs[job_id].update(fields)
    col = _db_collection()
    if col is not None:
        try:
            await col.update_one({"id": job_id}, {"$set": fields})
        except Exception:
            logger.debug("Failed to persist integration job update", exc_info=True)
    return _jobs.get(job_id, {"id": job_id, **fields})


async def _extract_indicators_from_json_file(path: str, source: str) -> List[Dict[str, Any]]:
    """Best-effort parser for Arkime/BloodHound/SpiderFoot exported JSON."""
    indicators: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return indicators

    def add_ioc(ioc_type: str, value: Any):
        raw = str(value or "").strip()
        if not raw:
            return
        indicators.append({"type": ioc_type, "value": raw, "confidence": 60})

    def walk(obj: Any):
        if isinstance(obj, dict):
            for key, value in obj.items():
                low = str(key).lower()
                if isinstance(value, (str, int, float)):
                    text = str(value).strip()
                    if not text:
                        continue
                    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", text):
                        add_ioc("ip", text)
                    elif "@" in text and "." in text:
                        add_ioc("email", text)
                    elif "." in text and len(text) > 3 and " " not in text:
                        add_ioc("domain", text)
                if low in {"srcip", "dstip", "ip", "sourceip", "destinationip", "lastlogonip"}:
                    if isinstance(value, list):
                        for entry in value:
                            add_ioc("ip", entry)
                    else:
                        add_ioc("ip", value)
                elif low in {"host", "hosts", "hostname", "domain", "domains", "name", "samaccountname"}:
                    if isinstance(value, list):
                        for entry in value:
                            add_ioc("domain", entry)
                    else:
                        add_ioc("domain", value)
                elif low in {"userprincipalname", "email"}:
                    if isinstance(value, list):
                        for entry in value:
                            add_ioc("email", entry)
                    else:
                        add_ioc("email", value)
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for item in indicators:
        key = f"{item.get('type')}:{str(item.get('value') or '').lower()}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _agent_command_for_tool(tool: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a bounded integration_runtime command payload for unified_agent.
    unified_agent executes this command type with a strict tool allowlist.
    """
    return {
        "command_type": "integration_runtime",
        "parameters": {
            "tool": tool,
            "params": params or {},
        },
    }


async def _queue_unified_agent_runtime(
    *,
    job_id: str,
    tool: str,
    params: Dict[str, Any],
    actor: str,
    agent_id: str,
) -> Dict[str, Any]:
    """Queue integration runtime command for a unified agent through governed dispatch."""
    try:
        from services.governed_dispatch import GovernedDispatchService
    except Exception:
        from backend.services.governed_dispatch import GovernedDispatchService

    db = get_db()
    if db is None:
        await _persist_job(job_id, status="failed", result={"error": "database_unavailable"})
        return _jobs.get(job_id, {"id": job_id, "status": "failed"})

    command_id = f"integration-{uuid.uuid4().hex[:10]}"
    now = datetime.utcnow().isoformat()
    command = _agent_command_for_tool(tool, params)
    command_doc = {
        "command_id": command_id,
        "agent_id": agent_id,
        "type": "command",
        "command_type": command["command_type"],
        "parameters": command["parameters"],
        "priority": "high",
        "status": "gated_pending_approval",
        "created_at": now,
        "updated_at": now,
        "created_by": actor or "integration_runtime",
        "issued_by": actor or "integration_runtime",
        "state_version": 1,
        "state_transition_log": [
            {
                "from_status": None,
                "to_status": "gated_pending_approval",
                "actor": actor or "integration_runtime",
                "reason": "integration runtime queued for approval",
                "timestamp": now,
                "metadata": {"tool": tool},
            }
        ],
    }
    dispatch = GovernedDispatchService(db)
    queued = await dispatch.queue_gated_agent_command(
        action_type="agent_command",
        actor=actor or "integration_runtime",
        agent_id=agent_id,
        command_doc=command_doc,
        impact_level="high",
        entity_refs=[agent_id, command_id, job_id, tool],
        requires_triune=True,
    )
    gate = queued.get("queued", {})
    result = {
        "runtime_target": "unified_agent",
        "agent_id": agent_id,
        "command_id": command_id,
        "queue_id": gate.get("queue_id"),
        "decision_id": gate.get("decision_id"),
        "command_type": command["command_type"],
    }
    await _persist_job(job_id, status="queued_for_triune_approval", result=result)
    return _jobs.get(job_id, {"id": job_id, "status": "queued_for_triune_approval"})


async def _sync_agent_command_state(job: Dict[str, Any]) -> Dict[str, Any]:
    """Hydrate integration job state from unified agent command status."""
    try:
        result = job.get("result") or {}
        command_id = result.get("command_id")
        if not command_id:
            return job
        db = get_db()
        if db is None:
            return job
        cmd = await db.agent_commands.find_one({"command_id": command_id}, {"_id": 0})
        if not cmd:
            return job
        cmd_status = str(cmd.get("status") or "").lower()
        mapped_status = job.get("status")
        if cmd_status in {"completed"}:
            mapped_status = "completed"
        elif cmd_status in {"failed", "error", "cancelled", "unknown_command"}:
            mapped_status = "failed"
        elif cmd_status in {"delivered", "pending", "queued", "gated_pending_approval"}:
            mapped_status = "running" if cmd_status in {"pending", "delivered"} else "queued_for_triune_approval"
        updated_result = dict(result)
        updated_result["agent_command_status"] = cmd_status
        if cmd.get("result") is not None:
            updated_result["agent_result"] = cmd.get("result")
        if mapped_status != job.get("status") or updated_result != result:
            await _persist_job(job.get("id"), status=mapped_status, result=updated_result)
            return _jobs.get(job.get("id"), job)
    except Exception:
        logger.debug("Failed to sync integration job from agent command", exc_info=True)
    return job


async def _run_subprocess(cmd: List[str], cwd: Path = None, timeout: int = 3600):
    logger.info("Running command: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode, stdout.decode(errors='ignore'), stderr.decode(errors='ignore')


async def run_amass(
    domain: str,
    governance_context: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Run Amass via Docker on the server, parse JSON-lines output and ingest domains."""
    assert_governance_context(governance_context, action="integrations.run_amass")
    params = {"domain": domain}
    job_id = await _new_job("amass", params)
    # update status to running in DB and memory
    _jobs[job_id]["status"] = "running"
    _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
    col = _db_collection()
    if col is not None:
        await col.update_one({"id": job_id}, {"$set": {"status": "running", "updated_at": datetime.utcnow().isoformat()}})

    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    outname = f"amass_{domain}_{ts}.json"
    outpath = INTEGRATIONS_DIR / outname

    # Docker amass command writes JSON-lines to mounted folder
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{INTEGRATIONS_DIR}:/data",
        "caffix/amass:latest",
        "enum",
        "-d",
        domain,
        "-oJ",
        f"/data/{outname}",
    ]

    try:
        rc, out, err = await _run_subprocess(cmd)
        if rc != 0:
            _jobs[job_id]["status"] = "failed"
            _jobs[job_id]["result"] = {"rc": rc, "stderr": err}
            _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
            col = _db_collection()
            if col is not None:
                await col.update_one({"id": job_id}, {"$set": {"status": "failed", "result": _jobs[job_id]["result"], "updated_at": _jobs[job_id]["updated_at"]}})
            return _jobs[job_id]

        # Parse JSON-lines
        indicators = []
        if outpath.exists():
            with open(outpath, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line=line.strip()
                    if not line: continue
                    try:
                        j = json.loads(line)
                        name = j.get('name') or j.get('host')
                        if name:
                            indicators.append({'type':'domain','value':name, 'confidence':50})
                    except Exception:
                        continue

        # Ingest into threat intel
        if indicators:
            res = await threat_intel.ingest_indicators('amass', indicators)
        else:
            res = {"ingested": 0}

        _jobs[job_id]["status"] = "completed"
        _jobs[job_id]["result"] = res
        await _emit_integration_event(
            "integration_job_completed_service",
            entity_refs=[job_id],
            payload={"tool": "amass", "ingested": res.get("ingested", 0) if isinstance(res, dict) else None},
            trigger_triune=False,
        )
        _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
        col = _db_collection()
        if col is not None:
            await col.update_one({"id": job_id}, {"$set": {"status": "completed", "result": res, "updated_at": _jobs[job_id]["updated_at"]}})
        return _jobs[job_id]
    except Exception as e:
        logger.exception("Amass run failed")
        _jobs[job_id]["status"] = "failed"
        _jobs[job_id]["result"] = {"error": str(e)}
        await _emit_integration_event(
            "integration_job_failed_service",
            entity_refs=[job_id],
            payload={"tool": "amass", "error": str(e)},
            trigger_triune=False,
        )
        _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
        return _jobs[job_id]


async def ingest_indicators_direct(source: str, indicators: List[Dict[str, Any]]):
    """Convenience wrapper to ingest programmatically provided indicators."""
    job_id = await _new_job("ingest", {"source": source, "count": len(indicators)})
    _jobs[job_id]["status"] = "running"
    _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
    col = _db_collection()
    if col is not None:
        await col.update_one({"id": job_id}, {"$set": {"status": "running", "updated_at": _jobs[job_id]["updated_at"]}})
    try:
        res = await threat_intel.ingest_indicators(source, indicators)
        _jobs[job_id]["status"] = "completed"
        _jobs[job_id]["result"] = res
        _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
        col = _db_collection()
        if col is not None:
            await col.update_one({"id": job_id}, {"$set": {"status": "completed", "result": res, "updated_at": _jobs[job_id]["updated_at"]}})
        return _jobs[job_id]
    except Exception as e:
        logger.exception("Direct ingest failed")
        _jobs[job_id]["status"] = "failed"
        _jobs[job_id]["result"] = {"error": str(e)}
        _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
        return _jobs[job_id]


async def get_job_async(job_id: str):
    # in-memory first
    if job_id in _jobs:
        return _json_safe(await _sync_agent_command_state(_jobs[job_id]))
    db = get_db()
    if db is None:
        return None
    try:
        doc = await db.integrations_jobs.find_one({"id": job_id}, {"_id": 0})
        if not doc:
            return None
        merged = dict(doc)
        if job_id in _jobs:
            merged.update(_jobs[job_id])
        hydrated = await _sync_agent_command_state(merged)
        _jobs[job_id] = dict(hydrated)
        return _json_safe(hydrated)
    except Exception:
        logger.debug("Failed reading integration job from DB", exc_info=True)
        return None


def get_job(job_id: str):
    """Synchronous compatibility wrapper (prefer get_job_async)."""
    if job_id in _jobs:
        return _json_safe(_jobs[job_id])
    return None


async def list_jobs_async(limit: int = 200):
    jobs_map: Dict[str, Dict[str, Any]] = {}
    db = get_db()
    if db is not None:
        try:
            docs = await db.integrations_jobs.find({}, {"_id": 0}).sort("updated_at", -1).limit(limit).to_list(length=limit)
            for doc in docs:
                jid = str(doc.get("id") or "")
                if jid:
                    jobs_map[jid] = dict(doc)
        except Exception:
            logger.debug("Failed listing integration jobs from DB", exc_info=True)
    for jid, job in _jobs.items():
        jobs_map[jid] = dict({**jobs_map.get(jid, {}), **job})

    hydrated: List[Dict[str, Any]] = []
    for job in jobs_map.values():
        hydrated.append(await _sync_agent_command_state(job))

    hydrated.sort(key=lambda item: str(item.get("updated_at") or item.get("created_at") or ""), reverse=True)
    return [_json_safe(job) for job in hydrated[:limit]]


def list_jobs():
    """Synchronous compatibility wrapper (prefer list_jobs_async)."""
    return [_json_safe(job) for job in sorted(_jobs.values(), key=lambda j: str(j.get("updated_at") or ""), reverse=True)]


async def _scheduler_loop():
    """Simple scheduler loop that runs configured tasks periodically.
    Configuration via environment variables:
      - AMASS_SCHEDULE_HOURS (int, optional)
      - AMASS_DOMAINS (comma-separated domains)
    """
    logger.info("Integrations scheduler started")
    try:
        while True:
            try:
                hours = int(os.environ.get('AMASS_SCHEDULE_HOURS', '0'))
                domains = os.environ.get('AMASS_DOMAINS', '').split(',') if os.environ.get('AMASS_DOMAINS') else []
                allow_ungated_scheduler = str(os.environ.get("ALLOW_UNGATED_INTEGRATION_SCHEDULER", "false")).lower() in {"1", "true", "yes", "on"}
                if hours > 0 and domains:
                    if not allow_ungated_scheduler:
                        logger.warning(
                            "Skipping scheduled integration execution because it is not outbound-gated. "
                            "Set ALLOW_UNGATED_INTEGRATION_SCHEDULER=true only for controlled environments."
                        )
                        await asyncio.sleep(max(3600, hours * 3600))
                        continue
                    for d in [x.strip() for x in domains if x.strip()]:
                        logger.info(f"Scheduler: launching amass for {d}")
                        await run_amass(
                            d,
                            governance_context={
                                "approved": True,
                                "decision_id": "scheduler-ungated-allowlist",
                                "queue_id": "scheduler",
                            },
                        )
                # Sleep for hours (default 1 hour if not set to 0)
                sleep_for = max(3600, hours * 3600) if hours > 0 else 3600
            except Exception as e:
                logger.error(f"Scheduler iteration error: {e}")
                sleep_for = 3600

            await asyncio.sleep(sleep_for)
    except asyncio.CancelledError:
        logger.info("Integrations scheduler stopped")


def start_scheduler():
    global _scheduler_task
    if _scheduler_task is None:
        _scheduler_task = asyncio.create_task(_scheduler_loop())
        logger.info("Integrations scheduler task created")
    else:
        logger.info("Integrations scheduler already running")


async def run_velociraptor(
    collection_name: str = None,
    governance_context: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Run Velociraptor collector using Docker for a quick host collection and export results.

    This is a lightweight wrapper that launches a Velociraptor docker command to perform a collection
    and writes the artifacts into the integrations dir. Requires Velociraptor image or local binary.
    """
    assert_governance_context(governance_context, action="integrations.run_velociraptor")
    params = {"collection": collection_name}
    job_id = await _new_job("velociraptor", params)
    _jobs[job_id]["status"] = "pending"
    _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
    col = _db_collection()
    if col is not None:
        await col.update_one({"id": job_id}, {"$set": {"status": "pending", "updated_at": _jobs[job_id]["updated_at"]}})

    # Enqueue Celery task to perform the collection (worker will update the DB)
    try:
        # import here to avoid requiring Celery at module import time
        from celery_app import celery_app
        # send task by name
        celery_app.send_task('backend.tasks.integrations_tasks.run_velociraptor_task', args=[job_id, collection_name])
    except Exception:
        logger.exception('Failed to enqueue velociraptor task')
        _jobs[job_id]["status"] = "failed"
        _jobs[job_id]["result"] = {"error": "failed_to_enqueue_velociraptor_task"}
        _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
        if col is not None:
            await col.update_one(
                {"id": job_id},
                {"$set": {"status": "failed", "result": _jobs[job_id]["result"], "updated_at": _jobs[job_id]["updated_at"]}},
            )
        return _jobs[job_id]

    # Return job metadata (worker will update status later)
    return _jobs[job_id]


async def run_purplesharp(
    target: str = None,
    options: Dict[str, Any] = None,
    governance_context: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Run PurpleSharp scaffold locally and ingest extracted indicators."""
    assert_governance_context(governance_context, action="integrations.run_purplesharp")
    params = {"target": target, "options": options or {}}
    job_id = await _new_job("purplesharp", params)
    await _persist_job(job_id, status="running")
    script = Path(__file__).resolve().parent.parent / "unified_agent" / "integrations" / "purplesharp" / "run_purplesharp.sh"
    if not script.exists():
        await _persist_job(job_id, status="failed", result={"error": f"missing_script:{script}"})
        return _jobs[job_id]
    env = dict(os.environ)
    env["OUTDIR"] = str(INTEGRATIONS_DIR)
    try:
        proc = await asyncio.create_subprocess_exec(
            "bash",
            str(script),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        out = (stdout.decode(errors="ignore") or "").strip()
        err = (stderr.decode(errors="ignore") or "").strip()
        if proc.returncode != 0:
            await _persist_job(job_id, status="failed", result={"rc": proc.returncode, "stderr": err})
            return _jobs[job_id]
        outfile = out.splitlines()[-1].strip() if out else ""
        indicators = []
        if outfile and Path(outfile).exists():
            indicators = await _extract_indicators_from_json_file(outfile, "purplesharp")
        ingested = await threat_intel.ingest_indicators("purplesharp", indicators) if indicators else {"ingested": 0}
        await _persist_job(
            job_id,
            status="completed",
            result={
                "ingested": ingested.get("ingested", 0) if isinstance(ingested, dict) else 0,
                "artifact_dir": str(INTEGRATIONS_DIR),
                "artifacts": [Path(outfile).name] if outfile else [],
                "stdout": out[-4000:],
                "stderr": err[-2000:],
            },
        )
        return _jobs[job_id]
    except Exception as exc:
        await _persist_job(job_id, status="failed", result={"error": str(exc)})
        return _jobs[job_id]


async def _run_docker_service(
    *,
    tool: str,
    image: str,
    container_name: str,
    ports: List[str],
    env_vars: Dict[str, str] = None,
) -> Dict[str, Any]:
    job_id = await _new_job(tool, {"image": image, "container_name": container_name, "ports": ports})
    await _persist_job(job_id, status="running")
    cmd = ["docker", "run", "-d", "--rm", "--name", container_name]
    for port in ports:
        cmd.extend(["-p", port])
    for key, value in (env_vars or {}).items():
        cmd.extend(["-e", f"{key}={value}"])
    cmd.append(image)
    try:
        rc, out, err = await _run_subprocess(cmd, timeout=240)
        if rc != 0:
            # Common case: service already running / port in use. Surface as ready_with_warning.
            if "port is already allocated" in (err or "").lower() or "is already in use by container" in (err or "").lower():
                await _persist_job(
                    job_id,
                    status="completed",
                    result={"ready": True, "warning": err[:1000], "container_name": container_name, "ports": ports},
                )
                return _jobs[job_id]
            await _persist_job(job_id, status="failed", result={"rc": rc, "stderr": err[:2000]})
            return _jobs[job_id]
        await _persist_job(
            job_id,
            status="completed",
            result={
                "ready": True,
                "container_id": out.strip(),
                "container_name": container_name,
                "ports": ports,
            },
        )
        return _jobs[job_id]
    except Exception as exc:
        await _persist_job(job_id, status="failed", result={"error": str(exc)})
        return _jobs[job_id]


async def run_arkime(governance_context: Dict[str, Any] = None, params: Dict[str, Any] = None) -> Dict[str, Any]:
    assert_governance_context(governance_context, action="integrations.run_arkime")
    settings = params or {}
    input_file = str(settings.get("input_file") or "").strip()
    if input_file:
        job_id = await _new_job("arkime", {"input_file": input_file})
        await _persist_job(job_id, status="running")
        indicators = await _extract_indicators_from_json_file(input_file, "arkime")
        ingested = await threat_intel.ingest_indicators("arkime", indicators) if indicators else {"ingested": 0}
        await _persist_job(job_id, status="completed", result={"ingested": ingested.get("ingested", 0), "source_file": input_file})
        return _jobs[job_id]
    return await _run_docker_service(
        tool="arkime",
        image="quay.io/arkime/arkime:latest",
        container_name=f"arkime-{uuid.uuid4().hex[:6]}",
        ports=["8005:8005", "8006:8006"],
        env_vars={"ES_HOSTS": str(settings.get("es_url") or os.environ.get("ARKIME_ES_URL") or "http://host.docker.internal:9200")},
    )


async def run_bloodhound(governance_context: Dict[str, Any] = None, params: Dict[str, Any] = None) -> Dict[str, Any]:
    assert_governance_context(governance_context, action="integrations.run_bloodhound")
    settings = params or {}
    input_file = str(settings.get("input_file") or "").strip()
    if input_file:
        job_id = await _new_job("bloodhound", {"input_file": input_file})
        await _persist_job(job_id, status="running")
        indicators = await _extract_indicators_from_json_file(input_file, "bloodhound")
        ingested = await threat_intel.ingest_indicators("bloodhound", indicators) if indicators else {"ingested": 0}
        await _persist_job(job_id, status="completed", result={"ingested": ingested.get("ingested", 0), "source_file": input_file})
        return _jobs[job_id]
    image = str(settings.get("image") or "specterops/bloodhound:latest")
    return await _run_docker_service(
        tool="bloodhound",
        image=image,
        container_name=f"bloodhound-{uuid.uuid4().hex[:6]}",
        ports=["7474:7474", "7687:7687"],
    )


async def run_spiderfoot(governance_context: Dict[str, Any] = None, params: Dict[str, Any] = None) -> Dict[str, Any]:
    assert_governance_context(governance_context, action="integrations.run_spiderfoot")
    settings = params or {}
    input_file = str(settings.get("input_file") or "").strip()
    if input_file:
        job_id = await _new_job("spiderfoot", {"input_file": input_file})
        await _persist_job(job_id, status="running")
        indicators = await _extract_indicators_from_json_file(input_file, "spiderfoot")
        ingested = await threat_intel.ingest_indicators("spiderfoot", indicators) if indicators else {"ingested": 0}
        await _persist_job(job_id, status="completed", result={"ingested": ingested.get("ingested", 0), "source_file": input_file})
        return _jobs[job_id]
    return await _run_docker_service(
        tool="spiderfoot",
        image="spiderfoot/spiderfoot:latest",
        container_name=f"spiderfoot-{uuid.uuid4().hex[:6]}",
        ports=[f"{int(settings.get('port') or 5001)}:5001"],
    )


async def run_sigma(governance_context: Dict[str, Any] = None, params: Dict[str, Any] = None) -> Dict[str, Any]:
    assert_governance_context(governance_context, action="integrations.run_sigma")
    payload = params or {}
    action = str(payload.get("action") or "reload").lower().strip()
    job_id = await _new_job("sigma", {"action": action})
    await _persist_job(job_id, status="running")
    try:
        from sigma_engine import sigma_engine
        if action == "evaluate":
            event = payload.get("event") if isinstance(payload.get("event"), dict) else {}
            result = sigma_engine.evaluate_event(event, max_matches=int(payload.get("max_matches") or 25))
        elif action == "coverage":
            result = sigma_engine.coverage_summary()
        else:
            result = sigma_engine.reload_rules()
        await _persist_job(job_id, status="completed", result={"action": action, "result": result})
        return _jobs[job_id]
    except Exception as exc:
        await _persist_job(job_id, status="failed", result={"error": str(exc), "action": action})
        return _jobs[job_id]


async def run_atomic(governance_context: Dict[str, Any] = None, params: Dict[str, Any] = None) -> Dict[str, Any]:
    assert_governance_context(governance_context, action="integrations.run_atomic")
    payload = params or {}
    dry_run = bool(payload.get("dry_run", False))
    selected_job = str(payload.get("job_id") or "").strip()
    job_id = await _new_job("atomic", {"job_id": selected_job, "dry_run": dry_run})
    await _persist_job(job_id, status="running")
    try:
        import importlib

        atomic_module = importlib.import_module("atomic_validation")
        manager = getattr(atomic_module, "atomic_validation")
        manager.set_db(get_db())
        if not selected_job:
            all_jobs = manager.list_jobs() or []
            if not all_jobs:
                await _persist_job(job_id, status="failed", result={"error": "atomic_jobs_unavailable"})
                return _jobs[job_id]
            selected_job = str(all_jobs[0].get("job_id") or "")
        result = await asyncio.to_thread(manager.run_job, selected_job, dry_run)
        ok = bool(result.get("ok", False))
        await _persist_job(job_id, status="completed" if ok else "failed", result=result)
        return _jobs[job_id]
    except Exception as exc:
        await _persist_job(job_id, status="failed", result={"error": str(exc)})
        return _jobs[job_id]


async def run_runtime_tool(
    *,
    tool: str,
    params: Dict[str, Any] = None,
    runtime_target: str = "server",
    agent_id: str = None,
    actor: str = "integration_runtime",
    governance_context: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Unified runtime launcher for security integrations.
    runtime_target:
      - server: execute on backend runtime
      - unified_agent_local/unified_agent_remote: queue command to a unified agent
    """
    t = str(tool or "").strip().lower()
    if t not in SUPPORTED_RUNTIME_TOOLS:
        raise ValueError(f"Unsupported tool '{tool}'. Supported: {sorted(SUPPORTED_RUNTIME_TOOLS)}")
    rt = str(runtime_target or "server").strip().lower()
    payload = params or {}
    context = governance_context or {
        "approved": True,
        "decision_id": "integration-runtime-direct",
        "queue_id": "integration-runtime-direct",
    }
    if rt in {"unified_agent_local", "unified_agent_remote", "agent", "unified_agent"}:
        db = get_db()
        resolved_agent_id = str(agent_id or "").strip()
        if not resolved_agent_id and db is not None:
            agent = await db.unified_agents.find_one(
                {"status": {"$in": ["online", "healthy"]}},
                {"_id": 0, "agent_id": 1},
            )
            if not agent:
                agent = await db.unified_agents.find_one({}, {"_id": 0, "agent_id": 1})
            if agent:
                resolved_agent_id = str(agent.get("agent_id") or "").strip()
        if not resolved_agent_id:
            job_id = await _new_job(t, {"runtime_target": rt, "params": payload})
            await _persist_job(job_id, status="failed", result={"error": "no_unified_agent_available"})
            return _jobs[job_id]
        job_id = await _new_job(t, {"runtime_target": rt, "agent_id": resolved_agent_id, "params": payload})
        return await _queue_unified_agent_runtime(
            job_id=job_id,
            tool=t,
            params=payload,
            actor=actor,
            agent_id=resolved_agent_id,
        )

    if t == "amass":
        domain = str(payload.get("domain") or "").strip()
        if not domain:
            job_id = await _new_job("amass", {"runtime_target": rt, "params": payload})
            await _persist_job(job_id, status="failed", result={"error": "domain_required"})
            return _jobs[job_id]
        return await run_amass(domain, governance_context=context)
    if t == "velociraptor":
        return await run_velociraptor(collection_name=payload.get("collection_name"), governance_context=context)
    if t == "purplesharp":
        return await run_purplesharp(target=payload.get("target"), options=payload.get("options"), governance_context=context)
    if t == "arkime":
        return await run_arkime(governance_context=context, params=payload)
    if t == "bloodhound":
        return await run_bloodhound(governance_context=context, params=payload)
    if t == "spiderfoot":
        return await run_spiderfoot(governance_context=context, params=payload)
    if t == "sigma":
        return await run_sigma(governance_context=context, params=payload)
    if t == "atomic":
        return await run_atomic(governance_context=context, params=payload)
    raise ValueError(f"Unsupported tool '{tool}'")


async def ingest_host_logs(source: str, raw_text: str) -> Dict[str, Any]:
    """Parse Sysmon or auditd log text to extract IOCs and ingest them.

    This is a heuristic parser: extracts IPs, domains, file hashes, and common indicators.
    """
    job_id = await _new_job("host_ingest", {"source": source})
    _jobs[job_id]["status"] = "running"
    _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
    try:
        import re
        ips = set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", raw_text))
        domains = set(re.findall(r"\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})\b", raw_text))
        sha256s = set(re.findall(r"\b[a-fA-F0-9]{64}\b", raw_text))

        indicators = []
        for ip in ips:
            indicators.append({'type': 'ip', 'value': ip, 'confidence': 60})
        for d in domains:
            indicators.append({'type': 'domain', 'value': d, 'confidence': 50})
        for h in sha256s:
            indicators.append({'type': 'sha256', 'value': h, 'confidence': 60})

        res = await threat_intel.ingest_indicators(source, indicators)
        _jobs[job_id]["status"] = "completed"
        _jobs[job_id]["result"] = res
        _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
        return _jobs[job_id]
    except Exception as e:
        logger.exception("Host log ingest failed")
        _jobs[job_id]["status"] = "failed"
        _jobs[job_id]["result"] = {"error": str(e)}
        _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
        return _jobs[job_id]


def stop_scheduler():
    global _scheduler_task
    if _scheduler_task:
        _scheduler_task.cancel()
        _scheduler_task = None
