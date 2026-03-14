import os
import subprocess
import json
import re
from datetime import datetime
try:
    from celery.utils.log import get_task_logger
    from celery import shared_task
    logger = get_task_logger(__name__)
except Exception:
    # Celery not installed in lightweight test environments; provide fallbacks
    def get_task_logger(name):
        import logging as _logging
        return _logging.getLogger(name)

    def shared_task(**kwargs):
        # decorator passthrough that returns the function unchanged
        def _decorator(fn):
            return fn
        return _decorator

    logger = get_task_logger(__name__)

import requests

# Endpoint config for central ingestion API
API_URL = os.environ.get('API_URL', 'http://localhost:8001').rstrip('/')
INGEST_ENDPOINT = f"{API_URL}/api/integrations/ingest/direct"
INTERNAL_TOKEN = os.environ.get('INTEGRATION_API_KEY', '')


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3}, soft_time_limit=3600, time_limit=4000)
def run_velociraptor_task(self, job_id: str, collection_name: str = None):
    """Celery task to run Velociraptor collection and POST extracted indicators to central ingestion API."""
    # mark running via API / DB update handled by integrations_manager earlier

    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    integrations_dir = os.environ.get('INTEGRATIONS_DIR', '/tmp/integrations')
    outdir = os.path.join(integrations_dir, f"velociraptor_{ts}")
    os.makedirs(outdir, exist_ok=True)

    if collection_name:
        cli_cmd = f"velociraptor --config /config/config.yaml collect --collection {collection_name} --output /data/collection_{ts}.json"
    else:
        cli_cmd = f"velociraptor --config /config/config.yaml collect --output /data/collection_{ts}.json"

    cmd = f"docker run --rm -v {outdir}:/data veloci/velociraptor:latest {cli_cmd}"

    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3600)
    if proc.returncode != 0:
        logger.error(f"Velociraptor failed: {proc.stderr}")
        # raise to trigger retry
        raise RuntimeError(f"Velociraptor failed: {proc.stderr}")

    # find collection file
    collection_file = None
    artifacts = []
    for fn in os.listdir(outdir):
        artifacts.append(fn)
        if fn.startswith('collection_') and fn.endswith('.json'):
            collection_file = os.path.join(outdir, fn)
            break

    indicators = []
    if collection_file:
        indicators = extract_indicators_from_collection(collection_file)

    ingested = 0
    result = {'ingested': 0, 'artifacts': artifacts, 'artifact_dir': outdir}

    if indicators:
        # Post to central ingestion API
        try:
            headers = {'Content-Type': 'application/json'}
            if INTERNAL_TOKEN:
                headers['X-Internal-Token'] = INTERNAL_TOKEN
            payload = {'source': 'velociraptor', 'indicators': indicators}
            r = requests.post(INGEST_ENDPOINT, json=payload, headers=headers, timeout=30)
            if r.status_code == 200:
                j = r.json()
                ingested = j.get('result', {}).get('ingested', 0) if isinstance(j, dict) else 0
                result['ingested'] = ingested
            else:
                logger.error(f"Ingest API returned {r.status_code}: {r.text}")
        except Exception as e:
            logger.exception(f"Failed to POST indicators to ingestion API: {e}")

    # Update job document via direct DB (best-effort) if API not used by integrations_manager
    try:
        from pymongo import MongoClient
        MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
        DB_NAME = os.environ.get('DB_NAME', 'metatron')
        client = MongoClient(MONGO_URL)
        db = client[DB_NAME]
        db.integrations_jobs.update_one({"id": job_id}, {"$set": {"status": "completed", "result": result, "updated_at": datetime.utcnow().isoformat()}})
    except Exception:
        logger.exception('Failed to update job document in DB')

    logger.info(f"Velociraptor job {job_id} completed, ingested {ingested}")


def extract_indicators_from_collection(collection_file: str):
    """Extract IPs, domains, hashes from a collection file and optionally run Yara rules.
    Returns list of indicator dicts.
    """
    indicators = []
    try:
        text = open(collection_file, 'r', encoding='utf-8', errors='ignore').read()
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
        logger.exception(f"Failed to parse collection file: {e}")

    # Optional Yara rules
    yara_rules_dir = os.environ.get('YARA_RULES_DIR')
    if yara_rules_dir:
        # try yara-python first
        try:
            import yara
            rules = yara.compile(filepath=yara_rules_dir) if os.path.isfile(yara_rules_dir) else yara.compile(filepaths={})
            matches = rules.match(collection_file)
            for m in matches:
                indicators.append({'type': 'yara', 'value': m.rule, 'confidence': 80, 'tags': ['yara']})
        except Exception:
            # fallback to command-line yara
            try:
                yara_cmd = f"yara -r {yara_rules_dir} {collection_file}"
                yc = subprocess.run(yara_cmd, shell=True, capture_output=True, text=True, timeout=120)
                if yc.returncode == 0 and yc.stdout:
                    for line in yc.stdout.splitlines():
                        parts = line.strip().split()
                        if not parts:
                            continue
                        rule_name = parts[0]
                        indicators.append({'type': 'yara', 'value': rule_name, 'confidence': 80, 'tags': ['yara']})
            except Exception:
                logger.exception('Yara scan failed')

    return indicators
