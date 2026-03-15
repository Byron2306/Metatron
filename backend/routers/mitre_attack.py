from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
import re
from typing import Dict, List, Set

from fastapi import APIRouter, Depends

from .dependencies import get_current_user, get_db
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
from sigma_engine import sigma_engine
from osquery_fleet import osquery_fleet
import atomic_validation as atomic_validation_module

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])

ENTERPRISE_TECHNIQUE_TOTAL = 216

TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance"},
    {"id": "TA0042", "name": "Resource Development"},
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0003", "name": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement"},
    {"id": "TA0009", "name": "Collection"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0010", "name": "Exfiltration"},
    {"id": "TA0040", "name": "Impact"},
]

TECHNIQUE_TO_TACTIC = {
    "T1195": "TA0001",
    "T1199": "TA0001",
    "T1113": "TA0009",
    "T1123": "TA0009",
    "T1125": "TA0009",
    "T1530": "TA0010",
    "T1078.004": "TA0001",
    "T1528": "TA0006",
    "T1552.001": "TA0006",
    "T1552.005": "TA0006",
    "T1567.002": "TA0010",
    "T1059": "TA0002",
    "T1059.001": "TA0002",
    "T1059.003": "TA0002",
    "T1547": "TA0003",
    "T1547.001": "TA0003",
    "T1003": "TA0006",
    "T1003.001": "TA0006",
    "T1555": "TA0006",
    "T1041": "TA0010",
    "T1048": "TA0010",
    "T1562": "TA0005",
    "T1562.001": "TA0005",
    "T1027": "TA0005",
    "T1046": "TA0007",
    "T1018": "TA0007",
    "T1091": "TA0001",
    "T1200": "TA0001",
    "T1071": "TA0011",
    "T1095": "TA0011",
    "T1571": "TA0011",
    "T1568": "TA0011",
}

PRIORITY_GAPS = [
    {"technique": "T1195", "name": "Supply Chain Compromise"},
    {"technique": "T1199", "name": "Trusted Relationship"},
    {"technique": "T1113", "name": "Screen Capture"},
    {"technique": "T1123", "name": "Audio Capture"},
    {"technique": "T1125", "name": "Video Capture"},
    {"technique": "T1530", "name": "Data from Cloud Storage"},
    {"technique": "T1078.004", "name": "Valid Accounts: Cloud Accounts"},
    {"technique": "T1528", "name": "Steal Application Access Token"},
    {"technique": "T1552.001", "name": "Credentials in Files"},
    {"technique": "T1567.002", "name": "Exfiltration to Cloud Storage"},
]



ATTACK_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
ATTACK_TACTIC_RE = re.compile(r"\bTA\d{4}\b", re.IGNORECASE)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _scan_python_files_for_attack_ids(base_dirs: List[Path]) -> Dict[str, Dict]:
    """Sweep repository Python sources for MITRE ATT&CK technique references."""
    implemented: Dict[str, Dict] = {}
    for base in base_dirs:
        if not base.exists():
            continue
        for py_file in base.rglob('*.py'):
            try:
                text = py_file.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                continue

            tactic_hints = {m.group(0).upper() for m in ATTACK_TACTIC_RE.finditer(text)}
            for m in ATTACK_TECHNIQUE_RE.finditer(text):
                tech = _normalize_technique(m.group(0))
                if not tech:
                    continue
                rel_path = str(py_file.relative_to(_repo_root()))
                meta = implemented.setdefault(tech, {
                    'sources': set(),
                    'evidence_files': set(),
                    'tactic_hints': set(),
                })
                meta['sources'].add('code_sweep')
                meta['evidence_files'].add(rel_path)
                meta['tactic_hints'].update(tactic_hints)

    return implemented


@lru_cache(maxsize=1)
def _implemented_techniques_sweep() -> Dict[str, Dict]:
    root = _repo_root()
    base_dirs = [root / 'backend', root / 'unified_agent']
    return _scan_python_files_for_attack_ids(base_dirs)


def _merge_implemented_sweep(techniques: Dict[str, Dict]) -> Dict[str, Dict]:
    """Merge static implementation sweep into dynamic MITRE coverage map."""
    implemented = _implemented_techniques_sweep()
    for tech, details in implemented.items():
        techniques.setdefault(tech, {'score': 0, 'sources': set()})
        techniques[tech]['score'] = max(techniques[tech]['score'], 2)
        techniques[tech]['sources'].update(details.get('sources', set()))

    return implemented


def _normalize_technique(value: str) -> str:
    return (value or "").strip().upper()


def _parent_technique(technique: str) -> str:
    return technique.split(".")[0]


def _technique_tactic(technique: str, implemented_meta: Dict[str, Dict] = None) -> str:
    mapped = TECHNIQUE_TO_TACTIC.get(technique) or TECHNIQUE_TO_TACTIC.get(_parent_technique(technique))
    if mapped:
        return mapped
    if implemented_meta:
        hints = implemented_meta.get(technique, {}).get('tactic_hints', set())
        if len(hints) == 1:
            return next(iter(hints))
    return "unknown"


def _collect_sigma(techniques: Dict[str, Dict]):
    coverage = sigma_engine.coverage_summary()
    for row in coverage.get("techniques", []):
        t = _normalize_technique(row.get("technique", ""))
        if not t:
            continue
        techniques.setdefault(t, {"score": 0, "sources": set()})
        techniques[t]["score"] = max(techniques[t]["score"], 2)
        techniques[t]["sources"].add("sigma")


def _collect_osquery(techniques: Dict[str, Dict]):
    queries = osquery_fleet.list_queries(limit=200, query="").get("queries", [])
    for query in queries:
        for tt in query.get("attack_techniques", []):
            t = _normalize_technique(tt)
            if not t:
                continue
            techniques.setdefault(t, {"score": 0, "sources": set()})
            techniques[t]["score"] = max(techniques[t]["score"], 2)
            techniques[t]["sources"].add("osquery")


def _collect_zeek(techniques: Dict[str, Dict]):
    zeek_dir = Path("/var/log/zeek/current")
    if not zeek_dir.exists():
        return

    mapped = ["T1071", "T1095", "T1041", "T1048", "T1571", "T1568"]
    logs_present = any((zeek_dir / f"{log}.log").exists() for log in ["conn", "dns", "http", "ssl", "notice"])

    for t in mapped:
        techniques.setdefault(t, {"score": 0, "sources": set()})
        techniques[t]["score"] = max(techniques[t]["score"], 3 if logs_present else 2)
        techniques[t]["sources"].add("zeek")


def _collect_atomic(techniques: Dict[str, Dict]):
    manager = getattr(atomic_validation_module, "atomic_validation", None)
    if manager is None:
        return

    jobs = manager.list_jobs().get("jobs", [])
    for job in jobs:
        for tt in job.get("techniques", []):
            t = _normalize_technique(tt)
            if not t:
                continue
            techniques.setdefault(t, {"score": 0, "sources": set()})
            techniques[t]["score"] = max(techniques[t]["score"], 3)
            techniques[t]["sources"].add("atomic_job")

    runs = manager.list_runs(limit=300).get("runs", [])
    for run in runs:
        if run.get("status") != "success":
            continue
        for tt in run.get("techniques", []):
            t = _normalize_technique(tt)
            if not t:
                continue
            techniques.setdefault(t, {"score": 0, "sources": set()})
            techniques[t]["score"] = max(techniques[t]["score"], 4)
            techniques[t]["sources"].add("atomic_validated")


def _collect_threat_intel(techniques: Dict[str, Dict]):
    """Add techniques derived from ingested indicators in threat intel feeds.

    Each indicator stored earlier may have been annotated with technique IDs
    by ThreatIntelManager.ingest_indicators.  We call its stats API to get
    counts and update the coverage.
    """
    from threat_intel import threat_intel

    stats = threat_intel.get_stats()
    by_t = stats.get('by_technique', {})
    for t, count in by_t.items():
        tnorm = _normalize_technique(t)
        if not tnorm:
            continue
        techniques.setdefault(tnorm, {'score': 0, 'sources': set()})
        # telemetry-only baseline
        techniques[tnorm]['score'] = max(techniques[tnorm]['score'], 2)
        techniques[tnorm]['sources'].add('threat_intel')
        # bump score if many indicators exist
        if count and count > 5:
            techniques[tnorm]['score'] = max(techniques[tnorm]['score'], 3)


def _summarize_tactics(techniques: Dict[str, Dict], implemented_meta: Dict[str, Dict]) -> List[Dict]:
    index = {t["id"]: {"tactic_id": t["id"], "tactic_name": t["name"], "technique_count": 0, "score_gte3_count": 0} for t in TACTICS}

    for technique, meta in techniques.items():
        tactic = _technique_tactic(technique, implemented_meta)
        if tactic not in index:
            continue
        index[tactic]["technique_count"] += 1
        if meta["score"] >= 3:
            index[tactic]["score_gte3_count"] += 1

    return [index[t["id"]] for t in TACTICS]


def _score_distribution(techniques: Dict[str, Dict]) -> Dict[str, int]:
    buckets = {str(i): 0 for i in range(0, 6)}
    for meta in techniques.values():
        score = int(meta.get("score", 0))
        score = 0 if score < 0 else 5 if score > 5 else score
        buckets[str(score)] += 1

    covered = sum(v for k, v in buckets.items() if k != "0")
    buckets["0"] = max(ENTERPRISE_TECHNIQUE_TOTAL - covered, 0)
    return buckets


@router.get("/coverage")
async def mitre_coverage(current_user: dict = Depends(get_current_user)):
    techniques: Dict[str, Dict] = {}

    _collect_sigma(techniques)
    _collect_osquery(techniques)
    _collect_zeek(techniques)
    _collect_atomic(techniques)
    # include indicators ingested via integrations (Amass, Velociraptor, etc.)
    _collect_threat_intel(techniques)
    implemented_meta = _merge_implemented_sweep(techniques)

    ordered = []
    for technique in sorted(techniques.keys()):
        meta = techniques[technique]
        impl = implemented_meta.get(technique, {})
        ordered.append(
            {
                "technique": technique,
                "tactic": _technique_tactic(technique, implemented_meta),
                "score": int(meta["score"]),
                "sources": sorted(list(meta["sources"])),
                "implemented": technique in implemented_meta,
                "implemented_evidence_count": len(impl.get('evidence_files', set())),
            }
        )

    tactics = _summarize_tactics(techniques, implemented_meta)
    score_dist = _score_distribution(techniques)

    priority = []
    for gap in PRIORITY_GAPS:
        t = gap["technique"]
        score = techniques.get(t, {}).get("score", 0)
        priority.append({
            **gap,
            "score": score,
            "status": "covered" if score >= 3 else "partial" if score > 0 else "missing",
        })

    covered_gte3 = len([t for t in ordered if t["score"] >= 3])
    implemented_count = len(implemented_meta)
    implemented_covered_gte3 = len([t for t in ordered if t["score"] >= 3 and t["technique"] in implemented_meta])
    implemented_tactics = {
        _technique_tactic(t, implemented_meta)
        for t in implemented_meta.keys()
        if _technique_tactic(t, implemented_meta) != 'unknown'
    }

    checked_at = datetime.now(timezone.utc).isoformat()
    coverage_percent = round((covered_gte3 / ENTERPRISE_TECHNIQUE_TOTAL) * 100, 2)
    implemented_coverage_percent = round((implemented_covered_gte3 / implemented_count) * 100, 2) if implemented_count else 0.0
    await emit_world_event(get_db(), event_type="mitre_coverage_calculated", entity_refs=[], payload={"actor": current_user.get("id"), "observed_techniques": len(ordered), "covered_score_gte3": covered_gte3, "coverage_percent_gte3": coverage_percent, "implemented_techniques": implemented_count, "implemented_covered_score_gte3": implemented_covered_gte3, "implemented_coverage_percent_gte3": implemented_coverage_percent}, trigger_triune=False)
    return {
        "checked_at": checked_at,
        "enterprise_total_techniques": ENTERPRISE_TECHNIQUE_TOTAL,
        "observed_techniques": len(ordered),
        "implemented_techniques": implemented_count,
        "implemented_tactics": len(implemented_tactics),
        "covered_score_gte3": covered_gte3,
        "coverage_percent_gte3": coverage_percent,
        "implemented_covered_score_gte3": implemented_covered_gte3,
        "implemented_coverage_percent_gte3": implemented_coverage_percent,
        "score_distribution": score_dist,
        "tactics": tactics,
        "techniques": ordered,
        "priority_gaps": priority,
    }
