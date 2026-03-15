from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
import os
import re
from typing import Any, Dict, List, Set

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
ROADMAP_TARGET_TECHNIQUE_TOTAL = 639

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
    "T1195.002": "TA0001",
    "T1199": "TA0001",
    "T1113": "TA0009",
    "T1123": "TA0009",
    "T1125": "TA0009",
    "T1530": "TA0010",
    "T1078.004": "TA0001",
    "T1528": "TA0006",
    "T1552.001": "TA0006",
    "T1552.005": "TA0006",
    "T1553.006": "TA0005",
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


def _extract_attack_techniques(value: Any) -> Set[str]:
    """Recursively extract ATT&CK technique IDs from arbitrary payloads."""
    found: Set[str] = set()
    if value is None:
        return found
    if isinstance(value, str):
        for match in ATTACK_TECHNIQUE_RE.finditer(value):
            normalized = _normalize_technique(match.group(0))
            if normalized:
                found.add(normalized)
        return found
    if isinstance(value, dict):
        for inner in value.values():
            found.update(_extract_attack_techniques(inner))
        return found
    if isinstance(value, list):
        for inner in value:
            found.update(_extract_attack_techniques(inner))
        return found
    return found


async def _collect_audit_and_world_event_evidence(techniques: Dict[str, Dict], db: Any):
    """Collect ATT&CK evidence from telemetry/audit/event stores."""
    if db is None:
        return

    collection_sources = [
        ("world_events", "world_event_evidence"),
        ("audit_logs", "audit_log_evidence"),
        ("alerts", "alerts_evidence"),
        ("unified_alerts", "unified_alerts_evidence"),
        ("events_raw", "events_raw_evidence"),
        ("hunting_matches", "hunting_match_evidence"),
    ]

    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    for collection_name, source_tag in collection_sources:
        col = getattr(db, collection_name, None)
        if col is None:
            continue
        try:
            cursor = col.find({}, {"_id": 0})
            try:
                cursor = cursor.sort("timestamp", -1)
            except Exception:
                pass
            docs = await cursor.to_list(length=500)
        except Exception:
            docs = []
        for doc in docs:
            for technique in _extract_attack_techniques(doc):
                counts[technique] = counts.get(technique, 0) + 1
                source_map.setdefault(technique, set()).add(source_tag)

    for technique, seen_count in counts.items():
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        # Telemetry evidence means this technique is operationally observed.
        score = 3
        # Multiple sightings/sources promote confidence.
        if seen_count >= 3 or len(source_map.get(technique, set())) >= 2:
            score = 4
        techniques[technique]["score"] = max(techniques[technique]["score"], score)
        techniques[technique]["sources"].update(source_map.get(technique, set()))


async def _collect_celery_task_attack_metadata(techniques: Dict[str, Dict], db: Any):
    """Collect ATT&CK evidence from standardized Celery task metadata envelopes."""
    if db is None:
        return

    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    max_score: Dict[str, int] = {}

    source_specs = [
        ("world_events", {"source": {"$in": ["celery_app", "task.integrations"]}}, "celery_world_event"),
        ("integrations_jobs", {}, "celery_integration_job"),
    ]

    for collection_name, query, source_tag in source_specs:
        col = getattr(db, collection_name, None)
        if col is None:
            continue
        try:
            docs = await col.find(query, {"_id": 0}).to_list(length=800)
        except Exception:
            docs = []

        for doc in docs:
            candidates = [
                doc.get("attack_metadata"),
                (doc.get("payload") or {}).get("attack_metadata"),
                (doc.get("result") or {}).get("attack_metadata"),
            ]
            local_techniques: Set[str] = set()
            for candidate in candidates:
                local_techniques.update(_extract_attack_techniques(candidate))
            if not local_techniques:
                continue

            doc_score = 3
            status = str(doc.get("status", "")).lower()
            event_type = str(doc.get("event_type", "")).lower()
            if status == "completed" or event_type.endswith("completed") or event_type.endswith("failed"):
                doc_score = 4

            for technique in local_techniques:
                counts[technique] = counts.get(technique, 0) + 1
                source_map.setdefault(technique, set()).add(source_tag)
                max_score[technique] = max(max_score.get(technique, 0), doc_score)

    for technique, seen_count in counts.items():
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        score = max_score.get(technique, 3)
        if seen_count >= 3 or len(source_map.get(technique, set())) >= 2:
            score = max(score, 4)
        techniques[technique]["score"] = max(techniques[technique]["score"], score)
        techniques[technique]["sources"].update(source_map.get(technique, set()))


async def _collect_supply_chain(techniques: Dict[str, Dict], db: Any):
    """Collect supply-chain ATT&CK depth for T1195/T1195.002/T1553.006."""
    # Baseline: policy controls configured in runtime environment.
    supply_chain_baseline = {
        "TRIVY_ENABLED": ("T1195.002", "trivy_policy"),
        "COSIGN_VERIFY": ("T1553.006", "cosign_policy"),
    }
    for env_key, (technique, source) in supply_chain_baseline.items():
        default_value = "true" if env_key == "TRIVY_ENABLED" else "false"
        if str(os.environ.get(env_key, default_value)).lower() in {"1", "true", "yes", "on"}:
            techniques.setdefault(technique, {"score": 0, "sources": set()})
            # Trivy-backed image scanning is treated as high-fidelity detection
            # for software supply-chain compromise (first roadmap technique update).
            baseline_score = 3 if technique == "T1195.002" else 2
            techniques[technique]["score"] = max(techniques[technique]["score"], baseline_score)
            techniques[technique]["sources"].add(source)
            if technique == "T1195.002":
                techniques.setdefault("T1195", {"score": 0, "sources": set()})
                techniques["T1195"]["score"] = max(techniques["T1195"]["score"], 3)
                techniques["T1195"]["sources"].add("supply_chain_image_scanning")

    # Runtime evidence from container security manager (if available).
    try:
        from container_security import container_security  # lazy import
        stats = container_security.get_stats() if hasattr(container_security, "get_stats") else {}
        if int(stats.get("cached_scans", 0) or 0) > 0:
            techniques.setdefault("T1195.002", {"score": 0, "sources": set()})
            techniques["T1195.002"]["score"] = max(techniques["T1195.002"]["score"], 3)
            techniques["T1195.002"]["sources"].add("container_scan_cache")

        if int(stats.get("signing_cache", 0) or 0) > 0:
            for technique, source in [("T1553.006", "image_signing_cache"), ("T1195", "supply_chain_signing_observed")]:
                techniques.setdefault(technique, {"score": 0, "sources": set()})
                techniques[technique]["score"] = max(techniques[technique]["score"], 3)
                techniques[technique]["sources"].add(source)
    except Exception:
        pass

    if db is None:
        return

    # Persistent evidence from recorded container scans.
    try:
        scan_docs = await db.container_scans.find({}, {"_id": 0, "scan_status": 1, "critical_count": 1, "high_count": 1}).to_list(500)
    except Exception:
        scan_docs = []

    if scan_docs:
        techniques.setdefault("T1195.002", {"score": 0, "sources": set()})
        techniques["T1195.002"]["score"] = max(techniques["T1195.002"]["score"], 3)
        techniques["T1195.002"]["sources"].add("container_scan_history")

        risky_scans = sum(
            1
            for row in scan_docs
            if int(row.get("critical_count", 0) or 0) > 0 or int(row.get("high_count", 0) or 0) > 0
        )
        if risky_scans > 0:
            techniques.setdefault("T1195", {"score": 0, "sources": set()})
            techniques["T1195"]["score"] = max(techniques["T1195"]["score"], 3)
            techniques["T1195"]["sources"].add("supply_chain_risky_image_findings")


async def _collect_secure_boot(techniques: Dict[str, Dict]):
    """Collect ATT&CK depth from secure-boot / firmware integrity capability."""
    def _mark(technique_id: str, score: int, source: str):
        t = _normalize_technique(technique_id)
        if not t:
            return
        techniques.setdefault(t, {"score": 0, "sources": set()})
        techniques[t]["score"] = max(techniques[t]["score"], score)
        techniques[t]["sources"].add(source)

    # Capability-based baseline from implemented secure boot pipeline.
    for baseline in ["T1542.001", "T1542.003", "T1014", "T1495", "T1601", "T1553.006"]:
        _mark(baseline, 3, "secure_boot_pipeline")

    try:
        from secure_boot_verification import get_secure_boot_verifier
    except Exception:  # pragma: no cover
        try:
            from backend.secure_boot_verification import get_secure_boot_verifier
        except Exception:
            return

    try:
        verifier = get_secure_boot_verifier()
    except Exception:
        return
    if verifier is None:
        return

    # Hardened policy state (Secure Boot enabled) increases confidence for trust-controls coverage.
    try:
        status = await verifier.get_secure_boot_status()
        if bool(getattr(status, "secure_boot_enabled", False)):
            _mark("T1553.006", 4, "secure_boot_policy_enforced")
    except Exception:
        pass

    # Boot-chain verification can emit concrete ATT&CK techniques with high-fidelity evidence.
    try:
        chain = await verifier.verify_boot_chain()
        for technique in getattr(chain, "mitre_techniques", []) or []:
            _mark(technique, 4, "secure_boot_bootchain")
    except Exception:
        pass

    # Alerts and scan history indicate observed detections over time.
    try:
        alerts = await verifier.get_alerts(limit=200)
    except Exception:
        alerts = []
    for alert in alerts or []:
        _mark(getattr(alert, "mitre_technique", ""), 4, "secure_boot_alert")

    try:
        history = getattr(verifier, "scan_history", {}) or {}
    except Exception:
        history = {}
    if history:
        for scan in history.values():
            threats = ((scan or {}).get("result") or {}).get("threats") or []
            for threat in threats:
                _mark((threat or {}).get("mitre_technique", ""), 4, "secure_boot_scan_history")


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
    buckets["0"] = max(ROADMAP_TARGET_TECHNIQUE_TOTAL - covered, 0)
    return buckets


def _enterprise_parent_count(techniques: List[Dict[str, Any]], *, min_score: int = 0, require_operational: bool = False) -> int:
    """Count unique parent techniques for Enterprise denominator accuracy."""
    seen: Set[str] = set()
    for row in techniques:
        if int(row.get("score", 0)) < min_score:
            continue
        if require_operational and not bool(row.get("operational_evidence", False)):
            continue
        parent = _parent_technique(str(row.get("technique", "")))
        if parent:
            seen.add(parent)
    return len(seen)


@router.get("/coverage")
async def mitre_coverage(current_user: dict = Depends(get_current_user)):
    techniques: Dict[str, Dict] = {}
    db = get_db()

    _collect_sigma(techniques)
    _collect_osquery(techniques)
    _collect_zeek(techniques)
    _collect_atomic(techniques)
    # include indicators ingested via integrations (Amass, Velociraptor, etc.)
    _collect_threat_intel(techniques)
    # Technique update pass #3: evidence from canonical audit/event telemetry.
    await _collect_audit_and_world_event_evidence(techniques, db)
    # Technique update pass #4: Celery task ATT&CK metadata envelope evidence.
    await _collect_celery_task_attack_metadata(techniques, db)
    # Technique update pass #1: supply-chain compromise depth (T1195 family)
    await _collect_supply_chain(techniques, db)
    # Technique update pass #2: secure-boot and firmware integrity techniques
    await _collect_secure_boot(techniques)
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
                "operational_evidence": any(src != "code_sweep" for src in meta["sources"]),
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
    covered_gte2 = len([t for t in ordered if t["score"] >= 2])
    covered_gte4 = len([t for t in ordered if t["score"] >= 4])
    implemented_count = len(implemented_meta)
    operational_observed = len([t for t in ordered if t["operational_evidence"]])
    operational_covered_gte3 = len([t for t in ordered if t["score"] >= 3 and t["operational_evidence"]])
    implemented_covered_gte3 = len([t for t in ordered if t["score"] >= 3 and t["technique"] in implemented_meta])
    implemented_covered_gte2 = len([t for t in ordered if t["score"] >= 2 and t["technique"] in implemented_meta])
    implemented_tactics = {
        _technique_tactic(t, implemented_meta)
        for t in implemented_meta.keys()
        if _technique_tactic(t, implemented_meta) != 'unknown'
    }

    checked_at = datetime.now(timezone.utc).isoformat()
    enterprise_covered_parents_gte3 = _enterprise_parent_count(ordered, min_score=3)
    enterprise_covered_parents_gte2 = _enterprise_parent_count(ordered, min_score=2)
    enterprise_operational_parents = _enterprise_parent_count(ordered, min_score=0, require_operational=True)
    coverage_percent = round((enterprise_covered_parents_gte3 / ENTERPRISE_TECHNIQUE_TOTAL) * 100, 2)
    coverage_percent_gte2 = round((enterprise_covered_parents_gte2 / ENTERPRISE_TECHNIQUE_TOTAL) * 100, 2)
    operational_coverage_percent = round((enterprise_operational_parents / ENTERPRISE_TECHNIQUE_TOTAL) * 100, 2)
    implemented_coverage_percent = round((implemented_covered_gte3 / implemented_count) * 100, 2) if implemented_count else 0.0
    implemented_coverage_percent_gte2 = round((implemented_covered_gte2 / implemented_count) * 100, 2) if implemented_count else 0.0
    roadmap_coverage_percent = round((covered_gte3 / ROADMAP_TARGET_TECHNIQUE_TOTAL) * 100, 2)
    roadmap_coverage_percent_gte2 = round((covered_gte2 / ROADMAP_TARGET_TECHNIQUE_TOTAL) * 100, 2)
    roadmap_referenced_percent = round((implemented_count / ROADMAP_TARGET_TECHNIQUE_TOTAL) * 100, 2)
    await emit_world_event(
        db,
        event_type="mitre_coverage_calculated",
        entity_refs=[],
        payload={
            "actor": current_user.get("id"),
            "observed_techniques": len(ordered),
            "covered_score_gte2": covered_gte2,
            "covered_score_gte3": covered_gte3,
            "covered_score_gte4": covered_gte4,
            "operational_observed_techniques": operational_observed,
            "operational_covered_score_gte3": operational_covered_gte3,
            "enterprise_covered_parent_techniques_gte3": enterprise_covered_parents_gte3,
            "coverage_percent_gte3": coverage_percent,
            "coverage_percent_gte2": coverage_percent_gte2,
            "operational_coverage_percent": operational_coverage_percent,
            "implemented_techniques": implemented_count,
            "implemented_covered_score_gte2": implemented_covered_gte2,
            "implemented_covered_score_gte3": implemented_covered_gte3,
            "implemented_coverage_percent_gte3": implemented_coverage_percent,
            "implemented_coverage_percent_gte2": implemented_coverage_percent_gte2,
            "roadmap_target_techniques": ROADMAP_TARGET_TECHNIQUE_TOTAL,
            "roadmap_coverage_percent_gte2": roadmap_coverage_percent_gte2,
            "roadmap_coverage_percent_gte3": roadmap_coverage_percent,
            "roadmap_referenced_percent": roadmap_referenced_percent,
        },
        trigger_triune=False,
    )
    return {
        "checked_at": checked_at,
        "enterprise_total_techniques": ENTERPRISE_TECHNIQUE_TOTAL,
        "roadmap_target_techniques": ROADMAP_TARGET_TECHNIQUE_TOTAL,
        "observed_techniques": len(ordered),
        "covered_score_gte2": covered_gte2,
        "implemented_techniques": implemented_count,
        "operational_observed_techniques": operational_observed,
        "operational_covered_score_gte3": operational_covered_gte3,
        "implemented_tactics": len(implemented_tactics),
        "enterprise_covered_parent_techniques_gte2": enterprise_covered_parents_gte2,
        "enterprise_covered_parent_techniques_gte3": enterprise_covered_parents_gte3,
        "enterprise_operational_parent_techniques": enterprise_operational_parents,
        "covered_score_gte4": covered_gte4,
        "covered_score_gte3": covered_gte3,
        "coverage_percent_gte2": coverage_percent_gte2,
        "coverage_percent_gte3": coverage_percent,
        "operational_coverage_percent": operational_coverage_percent,
        "roadmap_coverage_percent_gte2": roadmap_coverage_percent_gte2,
        "roadmap_coverage_percent_gte3": roadmap_coverage_percent,
        "roadmap_referenced_percent": roadmap_referenced_percent,
        "implemented_covered_score_gte2": implemented_covered_gte2,
        "implemented_coverage_percent_gte2": implemented_coverage_percent_gte2,
        "implemented_covered_score_gte3": implemented_covered_gte3,
        "implemented_coverage_percent_gte3": implemented_coverage_percent,
        "score_distribution": score_dist,
        "tactics": tactics,
        "techniques": ordered,
        "priority_gaps": priority,
    }
