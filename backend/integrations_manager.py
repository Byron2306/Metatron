import asyncio
import json
import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import os

from routers.dependencies import get_db

_scheduler_task = None
_scheduler_config = {}

from runtime_paths import ensure_data_dir
from threat_intel import threat_intel

logger = logging.getLogger(__name__)

# Directory for temporary integration outputs
INTEGRATIONS_DIR = ensure_data_dir("integrations")
INTEGRATIONS_DIR.mkdir(parents=True, exist_ok=True)

_jobs: Dict[str, Dict[str, Any]] = {}


def _db_collection():
    db = get_db()
    if db is None:
        return None
    return db.integrations_jobs


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
        await col.insert_one(job_doc)
    # also keep in-memory copy for quick listing
    _jobs[job_id] = job_doc
    return job_id


async def _run_subprocess(cmd: str, cwd: Path = None, timeout: int = 3600):
    logger.info(f"Running: {cmd}")
    proc = await asyncio.create_subprocess_shell(
        cmd,
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


async def run_amass(domain: str) -> Dict[str, Any]:
    """Run Amass via Docker on the server, parse JSON-lines output and ingest domains."""
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
    cmd = f"docker run --rm -v {INTEGRATIONS_DIR}:/data caffix/amass:latest enum -d {domain} -oJ /data/{outname}"

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
        _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
        col = _db_collection()
        if col is not None:
            await col.update_one({"id": job_id}, {"$set": {"status": "completed", "result": res, "updated_at": _jobs[job_id]["updated_at"]}})
        return _jobs[job_id]
    except Exception as e:
        logger.exception("Amass run failed")
        _jobs[job_id]["status"] = "failed"
        _jobs[job_id]["result"] = {"error": str(e)}
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


def get_job(job_id: str):
    # attempt in-memory first
    if job_id in _jobs:
        return _jobs[job_id]
    # otherwise try DB (synchronous fallback not ideal but quick)
    try:
        db = get_db()
        if db is None:
            return None
        doc = asyncio.get_event_loop().run_until_complete(db.integrations_jobs.find_one({"id": job_id}, {"_id": 0}))
        return doc
    except Exception:
        return None


def list_jobs():
    # return in-memory snapshot combined with DB entries
    try:
        db = get_db()
        if db is None:
            return list(_jobs.values())
        docs = asyncio.get_event_loop().run_until_complete(db.integrations_jobs.find({}, {"_id": 0}).to_list(length=100))
        # merge: overlay _jobs entries by id
        jobs_map = {j['id']: j for j in docs}
        jobs_map.update(_jobs)
        return list(jobs_map.values())
    except Exception:
        return list(_jobs.values())


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
                if hours > 0 and domains:
                    for d in [x.strip() for x in domains if x.strip()]:
                        logger.info(f"Scheduler: launching amass for {d}")
                        await run_amass(d)
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


async def run_velociraptor(collection_name: str = None) -> Dict[str, Any]:
    """Run Velociraptor collector using Docker for a quick host collection and export results.

    This is a lightweight wrapper that launches a Velociraptor docker command to perform a collection
    and writes the artifacts into the integrations dir. Requires Velociraptor image or local binary.
    """
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
        logger.exception('Failed to enqueue velociraptor task; running inline')
        # fallback to inline execution
        _jobs[job_id]["status"] = "running"
        if col is not None:
            await col.update_one({"id": job_id}, {"$set": {"status": "running", "updated_at": datetime.utcnow().isoformat()}})
        # call inline
        try:
            rc = await _run_subprocess(cmd)
        except Exception as e:
            _jobs[job_id]["status"] = "failed"
            _jobs[job_id]["result"] = {"error": str(e)}
            _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
            if col is not None:
                await col.update_one({"id": job_id}, {"$set": {"status": "failed", "result": _jobs[job_id]["result"], "updated_at": _jobs[job_id]["updated_at"]}})
            return _jobs[job_id]

    # Return job metadata (worker will update status later)
    return _jobs[job_id]


async def run_purplesharp(target: str = None, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """Schedule a PurpleSharp emulation job (privilege escalation emulation).
    This creates a job record; execution can be handled by agents/unified_agent.
    """
    params = {"target": target, "options": options or {}}
    job_id = await _new_job("purplesharp", params)
    _jobs[job_id]["status"] = "scheduled"
    _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
    col = _db_collection()
    if col is not None:
        await col.update_one({"id": job_id}, {"$set": {"status": "scheduled", "updated_at": _jobs[job_id]["updated_at"]}})
    return _jobs[job_id]

    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    outdir = INTEGRATIONS_DIR / f"velociraptor_{ts}"
    outdir.mkdir(parents=True, exist_ok=True)

    # Try docker image first
    if collection_name:
        cli_cmd = f"velociraptor --config /config/config.yaml collect --collection {collection_name} --output /data/collection_{ts}.json"
    else:
        cli_cmd = f"velociraptor --config /config/config.yaml collect --output /data/collection_{ts}.json"

    cmd = f"docker run --rm -v {outdir}:/data veloci/velociraptor:latest {cli_cmd}"

    try:
        rc, out, err = await _run_subprocess(cmd)
        if rc != 0:
            _jobs[job_id]["status"] = "failed"
            _jobs[job_id]["result"] = {"rc": rc, "stderr": err}
            _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
            return _jobs[job_id]

        # If collection file exists, attempt to parse basic indicators (IPs, domains, hashes)
        collection_file = None
        for p in outdir.iterdir():
            if p.name.startswith('collection_') and p.suffix in ['.json', '.jsonl']:
                collection_file = p
                break

        indicators = []
        if collection_file and collection_file.exists():
            try:
                text = collection_file.read_text(encoding='utf-8')
                # simple extraction heuristics: look for ip addresses, domains, sha256
                import re
                ips = set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text))
                domains = set(re.findall(r"\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})\b", text))
                sha256s = set(re.findall(r"\b[a-fA-F0-9]{64}\b", text))
                for ip in ips:
                    indicators.append({'type': 'ip', 'value': ip, 'confidence': 60})
                for d in domains:
                    indicators.append({'type': 'domain', 'value': d, 'confidence': 50})
                for h in sha256s:
                    indicators.append({'type': 'sha256', 'value': h, 'confidence': 60})
            except Exception as e:
                logger.debug(f"Failed to parse velociraptor collection: {e}")

        # Ingest indicators if found
        if indicators:
            res = await threat_intel.ingest_indicators('velociraptor', indicators)
        else:
            res = {"ingested": 0}

        _jobs[job_id]["status"] = "completed"
        _jobs[job_id]["result"] = res
        _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
        return _jobs[job_id]
    except Exception as e:
        logger.exception("Velociraptor run failed")
        _jobs[job_id]["status"] = "failed"
        _jobs[job_id]["result"] = {"error": str(e)}
        _jobs[job_id]["updated_at"] = datetime.utcnow().isoformat()
        return _jobs[job_id]


async def ingest_host_logs(source: str, raw_text: str) -> Dict[str, Any]:
    """Parse Sysmon or auditd log text to extract IOCs and ingest them.

    This is a heuristic parser: extracts IPs, domains, file hashes, and common indicators.
    """
    job_id = _new_job("host_ingest", {"source": source})
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
