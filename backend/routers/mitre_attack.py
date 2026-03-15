from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from collections import deque
import os
import json
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
    "T1190": "TA0001",
    "T1133": "TA0001",
    "T1204": "TA0002",
    "T1486": "TA0040",
    "T1489": "TA0040",
    "T1566": "TA0001",
    "T1566.001": "TA0001",
    "T1566.002": "TA0001",
    "T1570": "TA0008",
    "T1105": "TA0011",
    "T1055": "TA0005",
    "T1078": "TA0001",
    "T1071.004": "TA0011",
    "T1490": "TA0040",
    "T1562.001": "TA0005",
    "T1003.006": "TA0006",
    "T1040": "TA0006",
    "T1069.002": "TA0007",
    "T1078.002": "TA0001",
    "T1087.002": "TA0007",
    "T1110.003": "TA0006",
    "T1134.005": "TA0004",
    "T1187": "TA0001",
    "T1207": "TA0005",
    "T1222.001": "TA0005",
    "T1484.001": "TA0004",
    "T1550.002": "TA0008",
    "T1550.003": "TA0008",
    "T1555.003": "TA0006",
    "T1555.004": "TA0006",
    "T1556.001": "TA0006",
    "T1556.006": "TA0006",
    "T1557.001": "TA0006",
    "T1558": "TA0006",
    "T1558.001": "TA0006",
    "T1558.003": "TA0006",
    "T1558.004": "TA0006",
    "T1543.003": "TA0003",
    "T1053.005": "TA0003",
    "T1112": "TA0005",
    "T1218": "TA0005",
    "T1564.001": "TA0005",
    "T1562.004": "TA0005",
    "T1036": "TA0005",
    "T1574": "TA0005",
    "T1021.002": "TA0008",
    "T1021.004": "TA0008",
    "T1070": "TA0005",
    "T1562.008": "TA0005",
    "T1553.002": "TA0005",
    "T1496": "TA0040",
    "T1059.007": "TA0002",
    "T1005": "TA0009",
    "T1119": "TA0009",
    "T1499": "TA0040",
    "T1588": "TA0042",
    "T1585": "TA0042",
    "T1047": "TA0002",
    "T1021.003": "TA0008",
    "T1021.006": "TA0008",
    "T1611": "TA0004",
    "T1610": "TA0002",
    "T1578": "TA0040",
    "T1565": "TA0040",
    "T1565.001": "TA0040",
    "T1203": "TA0002",
    "T1485": "TA0040",
    "T1552": "TA0006",
    "T1595.002": "TA0043",
    "T1592.002": "TA0043",
    "T1573": "TA0011",
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

MONITOR_TECHNIQUES: Dict[str, List[str]] = {
    "registry": ["T1547.001", "T1112"],
    "process_tree": ["T1055", "T1059"],
    "lolbin": ["T1218"],
    "code_signing": ["T1553.002"],
    "dns": ["T1071.004", "T1568"],
    "memory": ["T1055", "T1003.001"],
    "whitelist": ["T1204", "T1036"],
    "dlp": ["T1041", "T1567.002"],
    "vulnerability": ["T1190"],
    "amsi": ["T1059.001", "T1562.001"],
    "firewall": ["T1562.004"],
    "ransomware": ["T1486", "T1490"],
    "rootkit": ["T1014"],
    "kernel_security": ["T1562.001"],
    "self_protection": ["T1562.001"],
    "identity": ["T1003.001", "T1558", "T1078"],
    "auto_throttle": ["T1496"],
    "cli_telemetry": ["T1059", "T1218"],
    "hidden_file": ["T1564.001"],
    "alias_rename": ["T1036", "T1574"],
    "priv_escalation": ["T1068", "T1548"],
    "email_protection": ["T1566", "T1566.001"],
    "mobile_security": ["T1078", "T1021"],
    "webview2": ["T1189", "T1059.007"],
}

SOAR_TRIGGER_TECHNIQUES: Dict[str, List[str]] = {
    "threat_detected": ["T1190"],
    "malware_found": ["T1204", "T1105"],
    "ransomware_detected": ["T1486", "T1490"],
    "suspicious_process": ["T1055", "T1059"],
    "ioc_match": ["T1071"],
    "honeypot_triggered": ["T1595.001", "T1190"],
    "anomaly_detected": ["T1036"],
    "ai_behavior_detected": ["T1190", "T1059.001"],
    "autonomous_recon": ["T1595.001", "T1046"],
    "rapid_credential_access": ["T1003.001", "T1110.003"],
    "automated_lateral_movement": ["T1021", "T1570"],
    "ai_exfiltration_pattern": ["T1041", "T1048"],
    "deception_token_access": ["T1550.003", "T1552.001"],
    "goal_persistent_loop": ["T1053.005", "T1547.001"],
    "tool_chain_switching": ["T1218", "T1059"],
    "adaptive_attack_detected": ["T1190", "T1071"],
}

SOAR_ACTION_TECHNIQUES: Dict[str, List[str]] = {
    "block_ip": ["T1071"],
    "kill_process": ["T1055", "T1059"],
    "quarantine_file": ["T1204", "T1105"],
    "isolate_endpoint": ["T1021"],
    "collect_forensics": ["T1005", "T1046"],
    "disable_user": ["T1078"],
    "scan_endpoint": ["T1057", "T1082"],
    "update_firewall": ["T1562.004"],
    "throttle_cli": ["T1059"],
    "inject_latency": ["T1499"],
    "deploy_decoy": ["T1588"],
    "engage_tarpit": ["T1499"],
    "capture_triage_bundle": ["T1005", "T1119"],
    "capture_memory_snapshot": ["T1003.001"],
    "kill_process_tree": ["T1055"],
    "tag_session": ["T1071"],
    "rotate_credentials": ["T1078", "T1555"],
    "feed_disinformation": ["T1585"],
}

PURPLESHARP_KEYWORD_TECHNIQUES: Dict[str, List[str]] = {
    "mimikatz": ["T1003.001", "T1555"],
    "lsass": ["T1003.001"],
    "dcsync": ["T1003.006"],
    "kerberoast": ["T1558.003"],
    "asreproast": ["T1558.004"],
    "golden ticket": ["T1558.001"],
    "silver ticket": ["T1558"],
    "pass the hash": ["T1550.002"],
    "pass the ticket": ["T1550.003"],
    "wmic": ["T1047", "T1021.003"],
    "psexec": ["T1021.002"],
    "winrm": ["T1021.006"],
    "rdp": ["T1021.001"],
    "smb": ["T1021.002"],
    "service create": ["T1543.003"],
    "scheduled task": ["T1053.005"],
    "powershell": ["T1059.001"],
}

SIEM_KEYWORD_TECHNIQUES: Dict[str, List[str]] = {
    "c2": ["T1071", "T1095"],
    "command and control": ["T1071", "T1095"],
    "beacon": ["T1071", "T1095"],
    "exfil": ["T1041", "T1048"],
    "dns tunnel": ["T1071.004"],
    "scan": ["T1046", "T1595.001"],
    "brute force": ["T1110.003"],
    "credential": ["T1003.001", "T1555"],
    "malware": ["T1204", "T1105"],
}

EDR_KEYWORD_TECHNIQUES: Dict[str, List[str]] = {
    "malfind": ["T1055"],
    "injected": ["T1055"],
    "lsass": ["T1003.001"],
    "credential": ["T1003.001", "T1555"],
    "rootkit": ["T1014"],
    "deleted": ["T1070", "T1565.001"],
    "modified": ["T1565.001"],
    "permission": ["T1222.001"],
    "usb": ["T1091"],
    "process": ["T1057"],
}

YARA_KEYWORD_TECHNIQUES: Dict[str, List[str]] = {
    "mimikatz": ["T1003.001", "T1555"],
    "powershell": ["T1059.001"],
    "ransom": ["T1486", "T1490"],
    "webshell": ["T1505.003"],
    "credential": ["T1003.001", "T1555"],
    "malware": ["T1204", "T1105"],
    "inject": ["T1055"],
}

SURICATA_KEYWORD_TECHNIQUES: Dict[str, List[str]] = {
    "scan": ["T1046", "T1595.001"],
    "portscan": ["T1046", "T1595.001"],
    "dns": ["T1071.004"],
    "http": ["T1071.001"],
    "tls": ["T1573"],
    "c2": ["T1071", "T1095"],
    "command and control": ["T1071", "T1095"],
    "beacon": ["T1071", "T1095"],
    "exploit": ["T1190", "T1203"],
    "rce": ["T1190", "T1203"],
    "exfil": ["T1041", "T1048"],
}

FALCO_KEYWORD_TECHNIQUES: Dict[str, List[str]] = {
    "privileged": ["T1611"],
    "container escape": ["T1611"],
    "escape": ["T1611"],
    "ptrace": ["T1055"],
    "shell": ["T1059"],
    "sensitive mount": ["T1611"],
    "credential": ["T1552.001", "T1555"],
    "crypto-miner": ["T1496"],
    "k8s": ["T1610"],
}

TRIVY_KEYWORD_TECHNIQUES: Dict[str, List[str]] = {
    "rce": ["T1190", "T1203"],
    "remote code execution": ["T1190", "T1203"],
    "privilege escalation": ["T1068"],
    "credential": ["T1552.001", "T1552.005"],
    "secret": ["T1552.001", "T1552.005"],
    "deserialization": ["T1190"],
    "injection": ["T1190"],
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def _compose_text() -> str:
    root = _repo_root()
    chunks: List[str] = []
    for rel in ["docker-compose.yml", "docker-compose.prod.yml"]:
        path = root / rel
        if not path.exists():
            continue
        try:
            chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
    return "\n".join(chunks)


def _stack_service_declared(service_name: str) -> bool:
    text = _compose_text()
    if not text:
        return False
    pattern = rf"(?im)^\s*{re.escape(service_name)}\s*:"
    return re.search(pattern, text) is not None


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
    hunting_map = _load_threat_hunting_tactic_map()
    mapped = (
        TECHNIQUE_TO_TACTIC.get(technique)
        or TECHNIQUE_TO_TACTIC.get(_parent_technique(technique))
        or hunting_map.get(technique)
        or hunting_map.get(_parent_technique(technique))
    )
    if mapped:
        return mapped
    if implemented_meta:
        hints = implemented_meta.get(technique, {}).get('tactic_hints', set())
        if len(hints) == 1:
            return next(iter(hints))
    return "unknown"


@lru_cache(maxsize=1)
def _load_threat_hunting_tactic_map() -> Dict[str, str]:
    """Build technique->tactic map from threat hunting ruleset."""
    try:
        try:
            from services.threat_hunting import threat_hunting_engine
        except Exception:
            from backend.services.threat_hunting import threat_hunting_engine
    except Exception:
        return {}

    mapped: Dict[str, str] = {}
    rules = getattr(threat_hunting_engine, "rules", {}) or {}
    for rule in rules.values():
        technique = _normalize_technique(getattr(rule, "mitre_technique", ""))
        tactic = _normalize_technique(getattr(rule, "mitre_tactic", ""))
        if technique and tactic.startswith("TA"):
            mapped[technique] = tactic
    return mapped


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
            # Configured validation test exists for this technique.
            techniques[t]["score"] = max(techniques[t]["score"], 3)
            techniques[t]["sources"].add("atomic_job")

    runs = manager.list_runs(limit=300).get("runs", [])
    for run in runs:
        if run.get("status") != "success":
            continue
        executed = run.get("techniques_executed", []) or run.get("techniques", [])
        for tt in executed:
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
        # feed + enrichment baseline
        techniques[tnorm]['score'] = max(techniques[tnorm]['score'], 3)
        techniques[tnorm]['sources'].add('threat_intel')
        # bump score if many indicators exist
        if count and count > 5:
            techniques[tnorm]['score'] = max(techniques[tnorm]['score'], 3)
        if count and count > 100:
            techniques[tnorm]['score'] = max(techniques[tnorm]['score'], 4)


async def _collect_threat_intel_match_evidence(techniques: Dict[str, Dict], db: Any):
    """Collect operational ATT&CK evidence from threat-intel match/update telemetry."""
    if db is None:
        return

    match_sources = [
        ("threat_intel_matches", "threat_intel_match_evidence"),
        ("threat_intel_updates", "threat_intel_update_evidence"),
    ]

    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    for collection_name, source_tag in match_sources:
        col = getattr(db, collection_name, None)
        if col is None:
            continue
        try:
            docs = await col.find({}, {"_id": 0}).sort("timestamp", -1).to_list(length=800)
        except Exception:
            docs = []
        for doc in docs:
            local_techniques = set()
            local_techniques.update(_extract_attack_techniques(doc))
            indicator = doc.get("indicator") or {}
            local_techniques.update(_extract_attack_techniques(indicator))
            for technique in local_techniques:
                counts[technique] = counts.get(technique, 0) + 1
                source_map.setdefault(technique, set()).add(source_tag)

    for technique, seen_count in counts.items():
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        score = 3
        if seen_count >= 3 or len(source_map.get(technique, set())) >= 2:
            score = 4
        techniques[technique]["score"] = max(techniques[technique]["score"], score)
        techniques[technique]["sources"].update(source_map.get(technique, set()))


async def _collect_integration_job_evidence(techniques: Dict[str, Dict], db: Any):
    """Collect ATT&CK evidence from integration job lifecycle (Amass/Velociraptor/PurpleSharp)."""
    if db is None:
        return
    col = getattr(db, "integrations_jobs", None)
    if col is None:
        return

    tool_map: Dict[str, List[str]] = {
        "amass": ["T1590.002", "T1590.004", "T1595.001"],
        "velociraptor": ["T1053", "T1018", "T1083", "T1003"],
        "purplesharp": ["T1543", "T1021", "T1068", "T1059"],
    }

    try:
        docs = await col.find({}, {"_id": 0, "tool": 1, "status": 1, "result": 1}).to_list(length=800)
    except Exception:
        docs = []

    for doc in docs:
        tool = str(doc.get("tool") or "").strip().lower()
        status = str(doc.get("status") or "").strip().lower()
        mapped = tool_map.get(tool, [])
        extracted = _extract_attack_techniques(doc)
        local_techniques = set(_normalize_technique(t) for t in mapped) | extracted
        local_techniques = {t for t in local_techniques if t}
        if not local_techniques:
            continue

        score = 3
        if status in {"completed", "success"}:
            score = 4
        source = f"integration_job_{tool}" if tool else "integration_job_evidence"
        if score == 4:
            source = f"{source}_completed"

        for technique in local_techniques:
            techniques.setdefault(technique, {"score": 0, "sources": set()})
            techniques[technique]["score"] = max(techniques[technique]["score"], score)
            techniques[technique]["sources"].add(source)


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


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, bool):
            return int(value)
        return int(float(value))
    except Exception:
        return default


def _extract_keyword_techniques(value: Any, keyword_map: Dict[str, List[str]]) -> Set[str]:
    text = str(value or "").lower()
    if not text:
        return set()
    found: Set[str] = set()
    for keyword, techniques in keyword_map.items():
        if keyword in text:
            for technique in techniques:
                normalized = _normalize_technique(technique)
                if normalized:
                    found.add(normalized)
    return found


def _extract_monitor_entries(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    entries: Dict[str, Dict[str, Any]] = {}
    if not isinstance(doc, dict):
        return entries

    # Legacy/alternate shape: {"monitors": {"registry": {...}}}
    nested = doc.get("monitors")
    if isinstance(nested, dict):
        for name, payload in nested.items():
            if isinstance(payload, dict):
                entries[name] = payload

    for monitor_name in MONITOR_TECHNIQUES.keys():
        payload = doc.get(monitor_name)
        if isinstance(payload, dict):
            entries[monitor_name] = payload

    return entries


def _monitor_payload_has_signal(payload: Dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    if _safe_int(payload.get("threats_found")) > 0:
        return True

    # Ignore "volume-only" counters that don't imply suspicious behavior by themselves.
    volume_keys = {
        "processes_analyzed",
        "queries_analyzed",
        "software_checked",
        "scripts_scanned",
        "executables_checked",
        "files_scanned",
        "scan_count",
        "commands_captured",
        "total_processes",
        "last_run",
        "scan_duration_ms",
    }
    for key, value in payload.items():
        if key in volume_keys:
            continue
        if isinstance(value, bool) and value:
            return True
        if isinstance(value, (int, float)) and value > 0:
            return True
    return False


def _extract_ports(value: Any) -> List[int]:
    ports: List[int] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, int):
                ports.append(item)
            elif isinstance(item, str):
                parsed = _safe_int(item, default=-1)
                if parsed > 0:
                    ports.append(parsed)
            elif isinstance(item, dict):
                parsed = _safe_int(item.get("port"), default=-1)
                if parsed > 0:
                    ports.append(parsed)
    return ports


def _tail_lines(path: Path, limit: int = 500) -> List[str]:
    if not path.exists() or not path.is_file():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            return list(deque(fh, maxlen=max(1, limit)))
    except Exception:
        return []


def _mark_technique(
    techniques: Dict[str, Dict],
    technique: str,
    *,
    score: int,
    source: str,
) -> None:
    normalized = _normalize_technique(technique)
    if not normalized:
        return
    techniques.setdefault(normalized, {"score": 0, "sources": set()})
    techniques[normalized]["score"] = max(int(techniques[normalized]["score"]), int(score))
    techniques[normalized]["sources"].add(source)


def _merge_collector_scores(
    techniques: Dict[str, Dict],
    *,
    counts: Dict[str, int],
    source_map: Dict[str, Set[str]],
    max_score: Dict[str, int],
    promote_count: int = 3,
    promote_sources: int = 2,
) -> None:
    for technique, seen_count in counts.items():
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        score = max_score.get(technique, 3)
        if seen_count >= promote_count or len(source_map.get(technique, set())) >= promote_sources:
            score = max(score, 4)
        techniques[technique]["score"] = max(techniques[technique]["score"], score)
        techniques[technique]["sources"].update(source_map.get(technique, set()))


def _extract_semantic_attack_techniques(value: Any) -> Set[str]:
    """Infer ATT&CK techniques from operational text semantics."""
    text = str(value or "").lower()
    if not text:
        return set()

    keyword_map: Dict[str, List[str]] = {
        "phish": ["T1566", "T1566.001"],
        "spear phish": ["T1566.001"],
        "malware": ["T1204", "T1105"],
        "ransom": ["T1486", "T1489", "T1490"],
        "credential": ["T1003.001", "T1555", "T1078"],
        "lsass": ["T1003.001"],
        "lateral movement": ["T1021", "T1570"],
        "privilege escalation": ["T1068", "T1548"],
        "persistence": ["T1547.001", "T1053"],
        "powershell": ["T1059.001"],
        "command and control": ["T1071", "T1095"],
        "c2": ["T1071", "T1095"],
        "beacon": ["T1071", "T1095"],
        "dns tunnel": ["T1071.004"],
        "exfil": ["T1041", "T1048", "T1567.002"],
        "injection": ["T1055"],
        "rootkit": ["T1014"],
        "defense evasion": ["T1562.001"],
        "impair defenses": ["T1562.001"],
        "api exploit": ["T1190"],
        "public-facing": ["T1190"],
        "external remote": ["T1133"],
        "botnet": ["T1071", "T1095"],
        "ai agent": ["T1190", "T1059.001"],
    }

    found: Set[str] = set()
    for keyword, techniques in keyword_map.items():
        if keyword in text:
            for technique in techniques:
                normalized = _normalize_technique(technique)
                if normalized:
                    found.add(normalized)
    return found


@lru_cache(maxsize=1)
def _identity_detector_catalog() -> List[str]:
    """Extract ATT&CK techniques declared in identity protection detections."""
    identity_file = _repo_root() / "backend" / "identity_protection.py"
    if not identity_file.exists():
        return []
    try:
        text = identity_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    block_re = re.compile(r"mitre_techniques\s*=\s*\[(.*?)\]", re.IGNORECASE | re.DOTALL)
    techniques: Set[str] = set()
    for block in block_re.findall(text):
        techniques.update(_extract_attack_techniques(block))
    return sorted(techniques)


def _collect_identity_protection_catalog(techniques: Dict[str, Dict]):
    """Collect ATT&CK depth from identity protection detector coverage."""
    for technique in _identity_detector_catalog():
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        techniques[technique]["score"] = max(techniques[technique]["score"], 3)
        techniques[technique]["sources"].add("identity_detector_catalog")

    # Runtime detections from identity engine (if any) are promoted to score 4.
    try:
        try:
            from identity_protection import identity_protection_engine
        except Exception:
            from backend.identity_protection import identity_protection_engine
        coverage = identity_protection_engine.get_mitre_coverage()
    except Exception:
        coverage = {}

    for row in (coverage.get("techniques") or []):
        technique = _normalize_technique(str(row.get("technique_id") or ""))
        if not technique:
            continue
        count = int(row.get("detection_count") or 0)
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        if count > 0:
            techniques[technique]["score"] = max(techniques[technique]["score"], 4)
            techniques[technique]["sources"].add("identity_runtime_detected")


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


async def _collect_semantic_security_collections(techniques: Dict[str, Dict], db: Any):
    """Collect ATT&CK evidence from semantic security telemetry in non-indexed collections."""
    if db is None:
        return

    collection_sources = [
        ("alerts", "alerts_semantic"),
        ("unified_alerts", "unified_alerts_semantic"),
        ("critical_alerts", "critical_alerts_semantic"),
        ("agent_alerts", "agent_alerts_semantic"),
        ("response_history", "response_history_semantic"),
        ("response_actions", "response_actions_semantic"),
        ("container_runtime_events", "container_runtime_semantic"),
        ("deception_hits", "deception_hits_semantic"),
        ("honeypot_interactions", "honeypot_interactions_semantic"),
        ("ai_analyses", "ai_analyses_semantic"),
    ]

    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    max_score: Dict[str, int] = {}

    for collection_name, source_tag in collection_sources:
        col = getattr(db, collection_name, None)
        if col is None:
            continue
        try:
            docs = await col.find({}, {"_id": 0}).to_list(length=500)
        except Exception:
            docs = []

        for doc in docs:
            explicit = _extract_attack_techniques(doc)
            semantic = _extract_semantic_attack_techniques(doc)
            local_techniques = explicit | semantic
            if not local_techniques:
                continue

            text = str(doc).lower()
            score = 3
            if any(token in text for token in ["critical", "high", "blocked", "quarantine", "contained", "resolved", "confirmed"]):
                score = 4

            for technique in local_techniques:
                counts[technique] = counts.get(technique, 0) + 1
                source_map.setdefault(technique, set()).add(source_tag)
                max_score[technique] = max(max_score.get(technique, 0), score)

    for technique, seen_count in counts.items():
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        score = max_score.get(technique, 3)
        if seen_count >= 3 or len(source_map.get(technique, set())) >= 2:
            score = max(score, 4)
        techniques[technique]["score"] = max(techniques[technique]["score"], score)
        techniques[technique]["sources"].update(source_map.get(technique, set()))


def _collect_threat_hunting_ruleset(techniques: Dict[str, Dict]):
    """Collect ATT&CK depth from active threat hunting rules and live matches."""
    try:
        try:
            from services.threat_hunting import threat_hunting_engine
        except Exception:
            from backend.services.threat_hunting import threat_hunting_engine
    except Exception:
        return

    rules = getattr(threat_hunting_engine, "rules", {}) or {}
    for rule in rules.values():
        if not bool(getattr(rule, "enabled", True)):
            continue
        technique = _normalize_technique(getattr(rule, "mitre_technique", ""))
        if not technique:
            continue
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        techniques[technique]["score"] = max(techniques[technique]["score"], 3)
        techniques[technique]["sources"].add("threat_hunting_ruleset")
        severity = str(getattr(rule, "severity", "")).lower()
        if severity in {"critical", "high"}:
            techniques[technique]["score"] = max(techniques[technique]["score"], 4)
            techniques[technique]["sources"].add("threat_hunting_high_severity_rule")

    matches = getattr(threat_hunting_engine, "matches", []) or []
    for match in matches:
        technique = _normalize_technique(getattr(match, "mitre_technique", ""))
        if not technique:
            continue
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        techniques[technique]["score"] = max(techniques[technique]["score"], 4)
        techniques[technique]["sources"].add("threat_hunting_live_match")


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


async def _collect_threat_incident_evidence(techniques: Dict[str, Dict], db: Any):
    """Promote ATT&CK coverage from operational threat/incident records."""
    if db is None:
        return

    threat_type_map: Dict[str, List[str]] = {
        "ai_agent": ["T1190", "T1059.001", "T1071"],
        "ai_autonomous": ["T1190", "T1059.001", "T1071"],
        "botnet": ["T1071", "T1095", "T1041"],
        "malware": ["T1204", "T1059", "T1105"],
        "ransomware": ["T1486", "T1489", "T1485"],
        "phishing": ["T1566", "T1566.001", "T1566.002"],
        "intrusion": ["T1190", "T1133"],
        "ids_alert": ["T1046", "T1071"],
        "credential_theft": ["T1003.001", "T1555"],
        "lateral_movement": ["T1021", "T1570"],
        "exfiltration": ["T1041", "T1048", "T1567.002"],
        "persistence": ["T1547.001", "T1053"],
        "privilege_escalation": ["T1068", "T1548"],
        "c2_activity": ["T1071", "T1095"],
    }
    keyword_map: Dict[str, List[str]] = {
        "phish": ["T1566"],
        "ransom": ["T1486"],
        "credential": ["T1003.001"],
        "lateral": ["T1021"],
        "exfil": ["T1041"],
        "command and control": ["T1071"],
        "c2": ["T1071"],
        "powershell": ["T1059.001"],
        "botnet": ["T1095"],
    }

    try:
        threat_docs = await db.threats.find({}, {"_id": 0}).to_list(600)
    except Exception:
        threat_docs = []

    try:
        alert_docs = await db.alerts.find({}, {"_id": 0, "threat_id": 1}).to_list(1200)
    except Exception:
        alert_docs = []

    alert_counts: Dict[str, int] = {}
    for alert in alert_docs:
        threat_id = str(alert.get("threat_id") or "").strip()
        if threat_id:
            alert_counts[threat_id] = alert_counts.get(threat_id, 0) + 1

    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    max_score: Dict[str, int] = {}
    for threat in threat_docs:
        threat_id = str(threat.get("id") or "").strip()
        threat_type = str(threat.get("type") or "").strip().lower()
        severity = str(threat.get("severity") or "").strip().lower()
        status = str(threat.get("status") or "").strip().lower()

        techniques_for_threat: Set[str] = set()
        techniques_for_threat.update(_normalize_technique(t) for t in threat_type_map.get(threat_type, []))

        threat_text = " ".join(
            [
                str(threat.get("name") or ""),
                str(threat.get("description") or ""),
                " ".join([str(v) for v in (threat.get("indicators") or [])]),
            ]
        ).lower()
        for keyword, tlist in keyword_map.items():
            if keyword in threat_text:
                techniques_for_threat.update(_normalize_technique(t) for t in tlist)

        if not techniques_for_threat:
            continue

        alert_count = alert_counts.get(threat_id, 0)
        score = 3
        if alert_count >= 1 or severity in {"high", "critical"}:
            score = 4
        if status in {"contained", "resolved", "blocked"}:
            score = 4

        for technique in techniques_for_threat:
            if not technique:
                continue
            counts[technique] = counts.get(technique, 0) + 1
            source_map.setdefault(technique, set()).add("threat_incident_evidence")
            if alert_count > 0:
                source_map[technique].add("incident_alert_corroboration")
            max_score[technique] = max(max_score.get(technique, 0), score)

    for technique, seen_count in counts.items():
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        score = max_score.get(technique, 3)
        if seen_count >= 3:
            score = max(score, 4)
        techniques[technique]["score"] = max(techniques[technique]["score"], score)
        techniques[technique]["sources"].update(source_map.get(technique, set()))


async def _collect_cspm_findings_history(techniques: Dict[str, Dict], db: Any):
    """Collect ATT&CK evidence from CSPM findings and scan/check history."""
    findings_col = getattr(db, "cspm_findings", None) if db is not None else None
    scans_col = getattr(db, "cspm_scans", None) if db is not None else None

    try:
        findings = await findings_col.find({}, {"_id": 0}).to_list(length=2000) if findings_col is not None else []
    except Exception:
        findings = []

    try:
        scans = await scans_col.find({}, {"_id": 0, "status": 1}).to_list(length=600) if scans_col is not None else []
    except Exception:
        scans = []

    # CSPM can run fully in-memory; include runtime engine state as a fallback/source.
    try:
        try:
            from cspm_engine import get_cspm_engine
        except Exception:
            from backend.cspm_engine import get_cspm_engine
        engine = get_cspm_engine()
    except Exception:
        engine = None

    if engine is not None:
        try:
            for finding in (getattr(engine, "findings_db", {}) or {}).values():
                if hasattr(finding, "to_dict"):
                    findings.append(finding.to_dict())
                elif isinstance(finding, dict):
                    findings.append(finding)
        except Exception:
            pass
        try:
            scans.extend(
                {"status": str(getattr(scan, "status", ""))}
                for scan in (getattr(engine, "scan_history", []) or [])
            )
        except Exception:
            pass
        try:
            scanners = getattr(engine, "scanners", {}) or {}
            for scanner in scanners.values():
                for check in (getattr(scanner, "checks", {}) or {}).values():
                    for technique in (_extract_attack_techniques(getattr(check, "mitre_techniques", [])) or set()):
                        techniques.setdefault(technique, {"score": 0, "sources": set()})
                        techniques[technique]["score"] = max(techniques[technique]["score"], 3)
                        techniques[technique]["sources"].add("cspm_check_catalog")
        except Exception:
            pass

    completed_scans = sum(1 for row in scans if str(row.get("status") or "").lower() in {"completed", "done", "success"})

    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    max_score: Dict[str, int] = {}
    cspm_keyword_map: Dict[str, List[str]] = {
        "public access": ["T1190", "T1133"],
        "internet": ["T1190", "T1133"],
        "security group": ["T1046", "T1190"],
        "network": ["T1046", "T1016"],
        "storage": ["T1530", "T1567.002"],
        "bucket": ["T1530"],
        "identity": ["T1078", "T1078.004"],
        "access key": ["T1078.004", "T1552.005"],
        "credential": ["T1552.001", "T1552.005"],
        "cloudtrail": ["T1562.008", "T1070"],
        "logging": ["T1562.001", "T1070"],
        "kubernetes": ["T1611", "T1578"],
        "container": ["T1611"],
    }

    for finding in findings:
        local_techniques = _extract_attack_techniques(finding)
        for raw in finding.get("mitre_techniques") or []:
            normalized = _normalize_technique(str(raw))
            if normalized:
                local_techniques.add(normalized)
        finding_text = " ".join(
            [
                str(finding.get("title") or ""),
                str(finding.get("description") or ""),
                str(finding.get("category") or ""),
                str(finding.get("subcategory") or ""),
                str(finding.get("check_id") or ""),
                str(finding.get("check_title") or ""),
            ]
        )
        local_techniques.update(_extract_semantic_attack_techniques(finding_text))
        local_techniques.update(_extract_keyword_techniques(finding_text, cspm_keyword_map))
        if not local_techniques:
            continue

        severity = str(finding.get("severity") or "").lower().split(".")[-1].strip()
        status = str(finding.get("status") or "").lower().split(".")[-1].strip()
        transitions = finding.get("state_transition_log") or []
        evidence = finding.get("evidence") or {}

        score = 3
        if severity in {"high", "critical"} or status in {"resolved", "suppressed"}:
            score = 4
        if len(transitions) >= 2 or bool(evidence):
            score = max(score, 4)

        for technique in local_techniques:
            counts[technique] = counts.get(technique, 0) + 1
            tags = source_map.setdefault(technique, set())
            tags.add("cspm_findings")
            if severity:
                tags.add(f"cspm_{severity}")
            if status:
                tags.add(f"cspm_status_{status}")
            if len(transitions) >= 2:
                tags.add("cspm_finding_state_history")
            if evidence:
                tags.add("cspm_finding_evidence")
            max_score[technique] = max(max_score.get(technique, 0), score)

    for technique, seen_count in counts.items():
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        score = max_score.get(technique, 3)
        if seen_count >= 3 or completed_scans >= 3:
            score = max(score, 4)
            source_map.setdefault(technique, set()).add("cspm_scan_history")
        techniques[technique]["score"] = max(techniques[technique]["score"], score)
        techniques[technique]["sources"].update(source_map.get(technique, set()))


async def _collect_unified_monitor_telemetry_evidence(techniques: Dict[str, Dict], db: Any):
    """Collect ATT&CK evidence from unified agent monitor telemetry and summaries."""
    if db is None:
        return

    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    max_score: Dict[str, int] = {}

    async def ingest_monitor_docs(docs: List[Dict[str, Any]], source_tag: str, *, summary_key: str = "") -> None:
        for doc in docs:
            entries = _extract_monitor_entries(doc)
            if summary_key:
                summary = doc.get(summary_key)
                if isinstance(summary, dict):
                    for monitor_name, payload in summary.items():
                        if isinstance(payload, dict):
                            entries[monitor_name] = payload
            if not entries:
                continue
            for monitor_name, payload in entries.items():
                monitor_techniques = {
                    _normalize_technique(t)
                    for t in MONITOR_TECHNIQUES.get(monitor_name, [])
                    if _normalize_technique(t)
                }
                monitor_techniques.update(_extract_attack_techniques(payload))
                if not monitor_techniques:
                    continue
                score = 4 if _monitor_payload_has_signal(payload) else 3
                for technique in monitor_techniques:
                    counts[technique] = counts.get(technique, 0) + 1
                    source_map.setdefault(technique, set()).add(source_tag)
                    source_map[technique].add(f"monitor_{monitor_name}")
                    max_score[technique] = max(max_score.get(technique, 0), score)

    try:
        monitor_docs = await db.agent_monitor_telemetry.find({}, {"_id": 0}).to_list(length=1200)
    except Exception:
        monitor_docs = []
    await ingest_monitor_docs(monitor_docs, "unified_monitor_telemetry")

    try:
        unified_agents = await db.unified_agents.find({}, {"_id": 0, "monitors_summary": 1}).to_list(length=800)
    except Exception:
        unified_agents = []
    await ingest_monitor_docs(unified_agents, "unified_agents_monitor_summary", summary_key="monitors_summary")

    try:
        world_agents = await db.world_entities.find(
            {"type": "agent"},
            {"_id": 0, "attributes.monitor_summary": 1},
        ).to_list(length=800)
    except Exception:
        world_agents = []
    normalized_world_docs = []
    for row in world_agents:
        attrs = row.get("attributes") or {}
        normalized_world_docs.append({"monitor_summary": attrs.get("monitor_summary")})
    await ingest_monitor_docs(normalized_world_docs, "world_agent_monitor_projection", summary_key="monitor_summary")

    for technique, seen_count in counts.items():
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        score = max_score.get(technique, 3)
        if seen_count >= 3 or len(source_map.get(technique, set())) >= 3:
            score = max(score, 4)
        techniques[technique]["score"] = max(techniques[technique]["score"], score)
        techniques[technique]["sources"].update(source_map.get(technique, set()))


def _collect_soar_record_techniques(record: Dict[str, Any]) -> Set[str]:
    techniques = _extract_attack_techniques(record)
    trigger_tokens = [
        record.get("trigger"),
        record.get("trigger_type"),
        record.get("trigger_reason"),
        (record.get("trigger_event") or {}).get("trigger_type") if isinstance(record.get("trigger_event"), dict) else None,
    ]
    for token in trigger_tokens:
        norm = str(token or "").strip().lower()
        for mapped in SOAR_TRIGGER_TECHNIQUES.get(norm, []):
            t = _normalize_technique(mapped)
            if t:
                techniques.add(t)

    action_tokens: List[str] = []
    for step in record.get("steps") or []:
        if isinstance(step, dict):
            action_tokens.append(str(step.get("action") or ""))
    for action in action_tokens:
        norm = action.strip().lower()
        for mapped in SOAR_ACTION_TECHNIQUES.get(norm, []):
            t = _normalize_technique(mapped)
            if t:
                techniques.add(t)

    techniques.update(_extract_semantic_attack_techniques(record))
    return techniques


async def _collect_soar_execution_evidence(techniques: Dict[str, Dict], db: Any):
    """Collect ATT&CK evidence from SOAR playbook catalog + execution telemetry."""
    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    max_score: Dict[str, int] = {}

    def add_techniques(local: Set[str], source_tag: str, score: int) -> None:
        for technique in local:
            if not technique:
                continue
            counts[technique] = counts.get(technique, 0) + 1
            source_map.setdefault(technique, set()).add(source_tag)
            max_score[technique] = max(max_score.get(technique, 0), score)

    try:
        from soar_engine import soar_engine
    except Exception:
        soar_engine = None

    if soar_engine is not None:
        try:
            playbooks = soar_engine.get_playbooks() or []
        except Exception:
            playbooks = []
        for playbook in playbooks:
            local = _collect_soar_record_techniques(playbook if isinstance(playbook, dict) else {})
            if local:
                add_techniques(local, "soar_playbook_catalog", 3)

        try:
            memory_execs = soar_engine.get_executions(limit=500) or []
        except Exception:
            memory_execs = []
        for execution in memory_execs:
            local = _collect_soar_record_techniques(execution if isinstance(execution, dict) else {})
            if not local:
                continue
            status = str((execution or {}).get("status") or "").lower()
            score = 4 if status in {"completed", "commands_queued", "success", "executed", "partial"} else 3
            add_techniques(local, "soar_execution_memory", score)

    if db is not None:
        try:
            db_execs = await db.soar_executions.find({}, {"_id": 0}).to_list(length=1200)
        except Exception:
            db_execs = []
        for execution in db_execs:
            local = _collect_soar_record_techniques(execution)
            if not local:
                continue
            status = str(execution.get("status") or "").lower()
            score = 4 if status in {"completed", "commands_queued", "success", "executed", "partial"} else 3
            add_techniques(local, "soar_execution_db", score)

        try:
            world_events = await db.world_events.find(
                {"event_type": {"$in": ["soar_playbook_execution_gated", "soar_trigger_gated"]}},
                {"_id": 0, "event_type": 1, "payload": 1},
            ).to_list(length=600)
        except Exception:
            world_events = []
        for event in world_events:
            payload = event.get("payload") or {}
            local = _collect_soar_record_techniques(payload if isinstance(payload, dict) else {})
            if local:
                add_techniques(local, "soar_world_event", 3)

    for technique, seen_count in counts.items():
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        score = max_score.get(technique, 3)
        if seen_count >= 3 or len(source_map.get(technique, set())) >= 2:
            score = max(score, 4)
        techniques[technique]["score"] = max(techniques[technique]["score"], score)
        techniques[technique]["sources"].update(source_map.get(technique, set()))


def _network_techniques_from_ports(ports: List[int]) -> Set[str]:
    techniques: Set[str] = set()
    if not ports:
        return techniques
    techniques.add("T1046")
    techniques.add("T1016")
    port_set = set(ports)
    if 3389 in port_set:
        techniques.add("T1021.001")
    if 445 in port_set or 139 in port_set:
        techniques.add("T1021.002")
    if 22 in port_set:
        techniques.add("T1021.004")
    if 5985 in port_set or 5986 in port_set:
        techniques.add("T1021.006")
    if 53 in port_set:
        techniques.add("T1071.004")
    return techniques


async def _collect_network_scan_evidence(techniques: Dict[str, Dict], db: Any):
    """Collect ATT&CK evidence from network scans, discovered hosts/devices, and packet telemetry."""
    if db is None:
        return

    collection_specs = [
        ("network_scans", "network_scans"),
        ("discovered_hosts", "discovered_hosts"),
        ("discovered_devices", "discovered_devices"),
        ("network_scanners", "network_scanners"),
        ("suspicious_packets", "suspicious_packets"),
    ]

    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    max_score: Dict[str, int] = {}

    for collection_name, source_tag in collection_specs:
        col = getattr(db, collection_name, None)
        if col is None:
            continue
        try:
            docs = await col.find({}, {"_id": 0}).to_list(length=1200)
        except Exception:
            docs = []

        for doc in docs:
            local = _extract_attack_techniques(doc)
            local.update(_extract_semantic_attack_techniques(doc))

            if collection_name == "network_scanners":
                if _safe_int(doc.get("total_reports")) > 0:
                    local.update({"T1595.001", "T1046"})

            hosts = doc.get("hosts") if isinstance(doc.get("hosts"), list) else []
            if hosts:
                local.update({"T1595.001", "T1046", "T1016"})

            open_ports = _extract_ports(doc.get("open_ports"))
            if not open_ports and hosts:
                for host in hosts:
                    if isinstance(host, dict):
                        open_ports.extend(_extract_ports(host.get("open_ports")))
                        open_ports.extend(_extract_ports(host.get("ports")))
            local.update(_network_techniques_from_ports(open_ports))

            if not local:
                continue

            host_count = len(hosts)
            risk_score = _safe_int(doc.get("risk_score"))
            suspicious_score = max(
                _safe_int(doc.get("suspicious_count")),
                _safe_int(doc.get("threats_found")),
                _safe_int(doc.get("alerts")),
            )
            score = 3
            if risk_score >= 60 or suspicious_score > 0 or host_count >= 20 or len(set(open_ports)) >= 5:
                score = 4

            for technique in local:
                counts[technique] = counts.get(technique, 0) + 1
                source_map.setdefault(technique, set()).add(source_tag)
                max_score[technique] = max(max_score.get(technique, 0), score)

    for technique, seen_count in counts.items():
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        score = max_score.get(technique, 3)
        if seen_count >= 3 or len(source_map.get(technique, set())) >= 2:
            score = max(score, 4)
        techniques[technique]["score"] = max(techniques[technique]["score"], score)
        techniques[technique]["sources"].update(source_map.get(technique, set()))


async def _collect_purplesharp_execution_evidence(techniques: Dict[str, Dict], db: Any):
    """Collect ATT&CK evidence from PurpleSharp execution results (not only scheduling)."""
    if db is None:
        return

    col = getattr(db, "integrations_jobs", None)
    if col is None:
        return

    try:
        docs = await col.find({"tool": {"$regex": "^purplesharp$", "$options": "i"}}, {"_id": 0}).to_list(length=800)
    except Exception:
        docs = []

    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    max_score: Dict[str, int] = {}

    for doc in docs:
        status = str(doc.get("status") or "").strip().lower()
        result = doc.get("result") or {}
        params = doc.get("params") or {}
        local = _extract_attack_techniques(doc)
        local.update(_extract_keyword_techniques(result, PURPLESHARP_KEYWORD_TECHNIQUES))
        local.update(_extract_keyword_techniques(params, PURPLESHARP_KEYWORD_TECHNIQUES))

        artifact_dir = str((result or {}).get("artifact_dir") or "").strip()
        artifacts = (result or {}).get("artifacts") or []
        parsed_artifact = False
        if artifact_dir and isinstance(artifacts, list):
            base_dir = Path(artifact_dir)
            for name in artifacts[:8]:
                if not isinstance(name, str):
                    continue
                if not name.lower().endswith((".json", ".jsonl", ".txt", ".log")):
                    continue
                candidate = (base_dir / name).resolve()
                try:
                    if not candidate.exists() or not str(candidate).startswith(str(base_dir.resolve())):
                        continue
                    text = candidate.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                parsed_artifact = True
                local.update(_extract_attack_techniques(text))
                local.update(_extract_keyword_techniques(text, PURPLESHARP_KEYWORD_TECHNIQUES))

        if not local and status in {"completed", "success", "executed", "finished"}:
            local = {"T1059.001", "T1543.003", "T1021.002", "T1003.001"}

        if not local:
            continue

        if status in {"completed", "success", "executed", "finished"}:
            score = 4
        elif status in {"running", "in_progress", "processing"}:
            score = 3
        elif bool(result):
            score = 3
        else:
            continue

        for technique in local:
            counts[technique] = counts.get(technique, 0) + 1
            tags = source_map.setdefault(technique, set())
            tags.add("purplesharp_execution")
            if parsed_artifact:
                tags.add("purplesharp_artifact_parse")
            if status:
                tags.add(f"purplesharp_status_{status}")
            max_score[technique] = max(max_score.get(technique, 0), score)

    for technique, seen_count in counts.items():
        techniques.setdefault(technique, {"score": 0, "sources": set()})
        score = max_score.get(technique, 3)
        if seen_count >= 2:
            score = max(score, 4)
        techniques[technique]["score"] = max(techniques[technique]["score"], score)
        techniques[technique]["sources"].update(source_map.get(technique, set()))


async def _collect_siem_evidence(techniques: Dict[str, Dict], db: Any):
    """Collect ATT&CK evidence from SIEM integration state and SIEM event telemetry."""
    siem_enabled = False
    siem_type = "unknown"
    try:
        try:
            from services.siem import siem_service
        except Exception:
            from backend.services.siem import siem_service
        status = siem_service.get_status() if hasattr(siem_service, "get_status") else {}
        siem_enabled = bool((status or {}).get("enabled"))
        siem_type = str((status or {}).get("type") or "unknown").lower()
    except Exception:
        status = {}

    stack_siem_declared = _stack_service_declared("elasticsearch") or _stack_service_declared("kibana")
    if siem_enabled or stack_siem_declared:
        baseline_source = f"siem_configured_{siem_type}" if siem_enabled else "siem_stack_declared"
        baseline_score = 3 if siem_enabled else 2
        for technique in ["T1071", "T1041", "T1046"]:
            _mark_technique(techniques, technique, score=baseline_score, source=baseline_source)

    if db is None:
        return

    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    max_score: Dict[str, int] = {}
    try:
        docs = await db.world_events.find(
            {"event_type": {"$regex": r"^siem_", "$options": "i"}},
            {"_id": 0, "event_type": 1, "payload": 1, "timestamp": 1},
        ).to_list(length=800)
    except Exception:
        docs = []

    for doc in docs:
        payload = doc.get("payload") or {}
        local = _extract_attack_techniques(doc)
        local.update(_extract_semantic_attack_techniques(doc))
        local.update(_extract_keyword_techniques(doc, SIEM_KEYWORD_TECHNIQUES))
        if not local:
            # A SIEM log event still implies operational telemetry transport.
            local = {"T1071", "T1041"}

        severity = str(payload.get("severity") or payload.get("level") or "").lower()
        immediate = bool(payload.get("immediate"))
        score = 4 if severity in {"critical", "high", "error"} or immediate else 3

        for technique in local:
            counts[technique] = counts.get(technique, 0) + 1
            source_map.setdefault(technique, set()).add("siem_world_event")
            if severity:
                source_map[technique].add(f"siem_severity_{severity}")
            max_score[technique] = max(max_score.get(technique, 0), score)

    _merge_collector_scores(
        techniques,
        counts=counts,
        source_map=source_map,
        max_score=max_score,
        promote_count=2,
        promote_sources=2,
    )


async def _collect_edr_evidence(techniques: Dict[str, Dict], db: Any):
    """Collect ATT&CK evidence from EDR/FIM/memory telemetry and EDR world events."""
    try:
        try:
            from edr_service import edr_manager
        except Exception:
            from backend.edr_service import edr_manager
        edr_status = edr_manager.get_status() if hasattr(edr_manager, "get_status") else {}
    except Exception:
        edr_status = {}

    fim_status = (edr_status or {}).get("fim") or {}
    if bool(fim_status.get("enabled")):
        _mark_technique(techniques, "T1070", score=3, source="edr_fim_capability")
        _mark_technique(techniques, "T1565.001", score=3, source="edr_fim_capability")
    mem_status = (edr_status or {}).get("memory_forensics") or {}
    if bool(mem_status.get("volatility_installed")):
        _mark_technique(techniques, "T1055", score=3, source="edr_memory_capability")
        _mark_technique(techniques, "T1003.001", score=3, source="edr_memory_capability")
        _mark_technique(techniques, "T1014", score=3, source="edr_memory_capability")
    usb_status = (edr_status or {}).get("usb_control") or {}
    if bool(usb_status.get("enabled")):
        _mark_technique(techniques, "T1091", score=3, source="edr_usb_capability")

    if db is None:
        return

    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    max_score: Dict[str, int] = {}

    try:
        fim_docs = await db.fim_events.find({}, {"_id": 0}).to_list(length=1500)
    except Exception:
        fim_docs = []
    for event in fim_docs:
        local = _extract_attack_techniques(event)
        local.update(_extract_keyword_techniques(event, EDR_KEYWORD_TECHNIQUES))
        local.update(_extract_semantic_attack_techniques(event))
        event_type = str(event.get("event_type") or "").lower()
        if event_type == "deleted":
            local.update({"T1070", "T1565.001"})
        elif event_type == "modified":
            local.update({"T1565.001"})
        elif event_type == "permission_change":
            local.update({"T1222.001"})
        if not local:
            continue
        severity = str(event.get("severity") or "").lower()
        score = 4 if severity in {"critical", "high"} else 3
        for technique in local:
            counts[technique] = counts.get(technique, 0) + 1
            source_map.setdefault(technique, set()).add("edr_fim_events")
            max_score[technique] = max(max_score.get(technique, 0), score)

    try:
        mem_docs = await db.memory_analyses.find({}, {"_id": 0}).to_list(length=800)
    except Exception:
        mem_docs = []
    for analysis in mem_docs:
        local = _extract_attack_techniques(analysis)
        local.update(_extract_keyword_techniques(analysis, EDR_KEYWORD_TECHNIQUES))
        local.update(_extract_semantic_attack_techniques(analysis))
        findings = analysis.get("findings") or []
        if findings and not local:
            local.update({"T1055", "T1003.001"})
        if not local:
            continue
        status = str(analysis.get("status") or "").lower()
        score = 4 if status in {"completed", "success"} and len(findings) > 0 else 3
        for technique in local:
            counts[technique] = counts.get(technique, 0) + 1
            source_map.setdefault(technique, set()).add("edr_memory_analyses")
            max_score[technique] = max(max_score.get(technique, 0), score)

    try:
        edr_events = await db.world_events.find(
            {"event_type": {"$regex": r"^edr_", "$options": "i"}},
            {"_id": 0, "event_type": 1, "payload": 1},
        ).to_list(length=800)
    except Exception:
        edr_events = []
    for event in edr_events:
        local = _extract_attack_techniques(event)
        local.update(_extract_keyword_techniques(event, EDR_KEYWORD_TECHNIQUES))
        local.update(_extract_semantic_attack_techniques(event))
        event_type = str(event.get("event_type") or "").lower()
        if "fim" in event_type and not local:
            local.update({"T1070", "T1565.001"})
        elif "memory" in event_type and not local:
            local.update({"T1055", "T1003.001"})
        elif "usb" in event_type and not local:
            local.update({"T1091"})
        if not local:
            continue
        score = 4 if event_type.endswith("completed") or event_type.endswith("analyzed") else 3
        for technique in local:
            counts[technique] = counts.get(technique, 0) + 1
            source_map.setdefault(technique, set()).add("edr_world_event")
            max_score[technique] = max(max_score.get(technique, 0), score)

    _merge_collector_scores(
        techniques,
        counts=counts,
        source_map=source_map,
        max_score=max_score,
        promote_count=2,
        promote_sources=2,
    )


async def _collect_yara_evidence(techniques: Dict[str, Dict], db: Any):
    """Collect ATT&CK evidence from YARA rule catalog and YARA detections."""
    rule_dirs = [
        Path("/app/yara_rules"),
        Path("/etc/yara/rules"),
        Path("/var/lib/seraph-ai/yara_rules"),
    ]
    extra_rule_dir = str(os.environ.get("YARA_RULES_DIR") or "").strip()
    if extra_rule_dir:
        rule_dirs.append(Path(extra_rule_dir))
    rule_count = 0
    for directory in rule_dirs:
        try:
            if directory.exists():
                rule_count += sum(1 for _ in directory.glob("**/*.yar"))
                rule_count += sum(1 for _ in directory.glob("**/*.yara"))
        except Exception:
            continue
    requirements_has_yara = False
    try:
        requirements_path = _repo_root() / "backend" / "requirements.txt"
        if requirements_path.exists():
            requirements_has_yara = "yara-python" in requirements_path.read_text(encoding="utf-8", errors="ignore").lower()
    except Exception:
        requirements_has_yara = False
    if rule_count > 0:
        baseline_score = 3 if rule_count >= 20 else 2
        for technique in ["T1204", "T1105", "T1059"]:
            _mark_technique(techniques, technique, score=baseline_score, source="yara_rule_catalog")
    elif requirements_has_yara:
        for technique in ["T1204", "T1105"]:
            _mark_technique(techniques, technique, score=2, source="yara_engine_declared")

    if db is None:
        return

    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    max_score: Dict[str, int] = {}

    try:
        yara_events = await db.world_events.find(
            {"event_type": {"$regex": "yara", "$options": "i"}},
            {"_id": 0, "event_type": 1, "payload": 1},
        ).to_list(length=800)
    except Exception:
        yara_events = []
    for event in yara_events:
        local = _extract_attack_techniques(event)
        local.update(_extract_keyword_techniques(event, YARA_KEYWORD_TECHNIQUES))
        local.update(_extract_semantic_attack_techniques(event))
        if not local:
            local.update({"T1204", "T1105"})
        for technique in local:
            counts[technique] = counts.get(technique, 0) + 1
            source_map.setdefault(technique, set()).add("yara_world_event")
            max_score[technique] = max(max_score.get(technique, 0), 4)

    try:
        scan_docs = await db.agent_scan_results.find(
            {"scan_type": {"$regex": "yara", "$options": "i"}},
            {"_id": 0},
        ).to_list(length=800)
    except Exception:
        scan_docs = []
    for scan in scan_docs:
        local = _extract_attack_techniques(scan)
        local.update(_extract_keyword_techniques(scan, YARA_KEYWORD_TECHNIQUES))
        local.update(_extract_semantic_attack_techniques(scan))
        results = scan.get("results") or {}
        match_count = _safe_int(results.get("match_count")) + len(results.get("matches") or [])
        if match_count > 0 and not local:
            local.update({"T1204", "T1105"})
        if not local:
            continue
        score = 4 if match_count > 0 else 3
        for technique in local:
            counts[technique] = counts.get(technique, 0) + 1
            source_map.setdefault(technique, set()).add("yara_agent_scan")
            max_score[technique] = max(max_score.get(technique, 0), score)

    try:
        threat_docs = await db.threats.find({}, {"_id": 0, "description": 1, "indicators": 1}).to_list(length=600)
    except Exception:
        threat_docs = []
    for threat in threat_docs:
        text_blob = " ".join([str(threat.get("description") or ""), " ".join([str(x) for x in (threat.get("indicators") or [])])])
        if "yara" not in text_blob.lower():
            continue
        local = _extract_keyword_techniques(text_blob, YARA_KEYWORD_TECHNIQUES) | {"T1204", "T1105"}
        for technique in local:
            counts[technique] = counts.get(technique, 0) + 1
            source_map.setdefault(technique, set()).add("yara_threat_artifact")
            max_score[technique] = max(max_score.get(technique, 0), 4)

    _merge_collector_scores(
        techniques,
        counts=counts,
        source_map=source_map,
        max_score=max_score,
        promote_count=2,
        promote_sources=2,
    )


async def _collect_container_tooling_evidence(techniques: Dict[str, Dict], db: Any):
    """Collect ATT&CK evidence for Trivy/Falco/Suricata/container runtime telemetry."""
    trivy_enabled = str(os.environ.get("TRIVY_ENABLED", "true")).lower() in {"1", "true", "yes", "on"}
    falco_enabled = str(os.environ.get("FALCO_ENABLED", "true")).lower() in {"1", "true", "yes", "on"}
    suricata_paths_present = Path("/var/log/suricata/eve.json").exists() or Path("/var/log/suricata/stats.log").exists()
    trivy_declared = _stack_service_declared("trivy")
    falco_declared = _stack_service_declared("falco")
    suricata_declared = _stack_service_declared("suricata")
    if trivy_enabled:
        _mark_technique(techniques, "T1195.002", score=2, source="trivy_configured")
        _mark_technique(techniques, "T1190", score=2, source="trivy_configured")
    elif trivy_declared:
        _mark_technique(techniques, "T1195.002", score=2, source="trivy_stack_declared")
    if falco_enabled:
        _mark_technique(techniques, "T1611", score=3, source="falco_configured")
        _mark_technique(techniques, "T1055", score=3, source="falco_configured")
    elif falco_declared:
        _mark_technique(techniques, "T1611", score=2, source="falco_stack_declared")
    if suricata_paths_present:
        _mark_technique(techniques, "T1046", score=3, source="suricata_configured")
        _mark_technique(techniques, "T1071", score=3, source="suricata_configured")
    elif suricata_declared:
        _mark_technique(techniques, "T1046", score=2, source="suricata_stack_declared")

    counts: Dict[str, int] = {}
    source_map: Dict[str, Set[str]] = {}
    max_score: Dict[str, int] = {}

    # Suricata eve.json operational alerts
    eve_path = Path("/var/log/suricata/eve.json")
    for line in _tail_lines(eve_path, limit=700):
        try:
            evt = json.loads(line.strip())
        except Exception:
            continue
        if str(evt.get("event_type") or "").lower() != "alert":
            continue
        local = _extract_attack_techniques(evt)
        local.update(_extract_keyword_techniques(evt, SURICATA_KEYWORD_TECHNIQUES))
        local.update(_extract_semantic_attack_techniques(evt))
        if not local:
            local = {"T1071", "T1046"}
        for technique in local:
            counts[technique] = counts.get(technique, 0) + 1
            source_map.setdefault(technique, set()).add("suricata_eve_alert")
            max_score[technique] = max(max_score.get(technique, 0), 4)

    # Falco file-based alerts.
    falco_file = Path("/var/log/falco/falco_alerts.json")
    for line in _tail_lines(falco_file, limit=700):
        try:
            evt = json.loads(line.strip())
        except Exception:
            continue
        local = _extract_attack_techniques(evt)
        local.update(_extract_keyword_techniques(evt, FALCO_KEYWORD_TECHNIQUES))
        local.update(_extract_semantic_attack_techniques(evt))
        if not local:
            local = {"T1611", "T1059"}
        priority = str(evt.get("priority") or "").lower()
        score = 4 if priority in {"critical", "error", "warning"} else 3
        for technique in local:
            counts[technique] = counts.get(technique, 0) + 1
            source_map.setdefault(technique, set()).add("falco_alert_file")
            max_score[technique] = max(max_score.get(technique, 0), score)

    # Falco in-memory/runtime alerts from container manager.
    try:
        try:
            from container_security import container_security
        except Exception:
            from backend.container_security import container_security
    except Exception:
        container_security = None

    if container_security is not None:
        try:
            alerts = container_security.falco.get_alerts(limit=600) if hasattr(container_security, "falco") else []
        except Exception:
            alerts = []
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            local = _extract_attack_techniques(alert)
            local.update(_extract_keyword_techniques(alert, FALCO_KEYWORD_TECHNIQUES))
            local.update(_extract_semantic_attack_techniques(alert))
            if not local:
                local = {"T1611", "T1059"}
            severity = str(alert.get("priority") or "").lower()
            score = 4 if severity in {"critical", "error", "warning"} else 3
            for technique in local:
                counts[technique] = counts.get(technique, 0) + 1
                source_map.setdefault(technique, set()).add("falco_runtime_alert")
                max_score[technique] = max(max_score.get(technique, 0), score)

        try:
            attempts = container_security.falco.get_escape_attempts(limit=200) if hasattr(container_security, "falco") else []
        except Exception:
            attempts = []
        for attempt in attempts:
            local = _extract_attack_techniques(attempt) | {"T1611"}
            for technique in local:
                counts[technique] = counts.get(technique, 0) + 1
                source_map.setdefault(technique, set()).add("falco_escape_attempt")
                max_score[technique] = max(max_score.get(technique, 0), 4)

    if db is not None:
        # Trivy/container vulnerability scans
        try:
            scans = await db.container_scans.find({}, {"_id": 0}).to_list(length=1000)
        except Exception:
            scans = []
        for scan in scans:
            local = _extract_attack_techniques(scan)
            local.update(_extract_keyword_techniques(scan, TRIVY_KEYWORD_TECHNIQUES))
            local.update(_extract_semantic_attack_techniques(scan))
            critical = _safe_int(scan.get("critical_count"))
            high = _safe_int(scan.get("high_count"))
            total = _safe_int(scan.get("total_vulnerabilities"))
            if (critical > 0 or high > 0) and not local:
                local.update({"T1190", "T1068"})
            if not local:
                continue
            score = 4 if critical > 0 or high > 3 else 3
            if total <= 0:
                score = 3
            for technique in local:
                counts[technique] = counts.get(technique, 0) + 1
                source_map.setdefault(technique, set()).add("trivy_scan_evidence")
                max_score[technique] = max(max_score.get(technique, 0), score)

        # Alerts collection can include Falco callback and Suricata-derived alerts.
        try:
            alerts = await db.alerts.find({}, {"_id": 0, "title": 1, "message": 1, "severity": 1, "type": 1}).to_list(length=1200)
        except Exception:
            alerts = []
        for alert in alerts:
            text = " ".join([str(alert.get("title") or ""), str(alert.get("message") or ""), str(alert.get("type") or "")]).lower()
            if not any(token in text for token in ["falco", "suricata", "sid:", "container", "runtime", "trivy"]):
                continue
            local = _extract_keyword_techniques(alert, SURICATA_KEYWORD_TECHNIQUES)
            local.update(_extract_keyword_techniques(alert, FALCO_KEYWORD_TECHNIQUES))
            local.update(_extract_keyword_techniques(alert, TRIVY_KEYWORD_TECHNIQUES))
            local.update(_extract_semantic_attack_techniques(alert))
            if "falco" in text and not local:
                local.update({"T1611", "T1059"})
            if ("suricata" in text or "sid:" in text) and not local:
                local.update({"T1071", "T1046"})
            if "trivy" in text and not local:
                local.update({"T1190"})
            if not local:
                continue
            severity = str(alert.get("severity") or "").lower()
            score = 4 if severity in {"critical", "high", "error"} else 3
            source = "container_alert_tooling"
            if "falco" in text:
                source = "falco_alert_collection"
            elif "suricata" in text or "sid:" in text:
                source = "suricata_alert_collection"
            elif "trivy" in text:
                source = "trivy_alert_collection"
            for technique in local:
                counts[technique] = counts.get(technique, 0) + 1
                source_map.setdefault(technique, set()).add(source)
                max_score[technique] = max(max_score.get(technique, 0), score)

        # Additional container security benchmark records.
        try:
            cis_docs = await db.cis_benchmarks.find({}, {"_id": 0}).to_list(length=500)
        except Exception:
            cis_docs = []
        for doc in cis_docs:
            local = _extract_attack_techniques(doc)
            local.update(_extract_keyword_techniques(doc, FALCO_KEYWORD_TECHNIQUES))
            local.update(_extract_keyword_techniques(doc, TRIVY_KEYWORD_TECHNIQUES))
            status = str(doc.get("status") or "").upper()
            if status in {"FAIL", "WARN"} and not local:
                local.update({"T1611", "T1190"})
            if not local:
                continue
            score = 4 if status == "FAIL" else 3
            for technique in local:
                counts[technique] = counts.get(technique, 0) + 1
                source_map.setdefault(technique, set()).add("container_cis_benchmark")
                max_score[technique] = max(max_score.get(technique, 0), score)

    _merge_collector_scores(
        techniques,
        counts=counts,
        source_map=source_map,
        max_score=max_score,
        promote_count=2,
        promote_sources=2,
    )


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
    _collect_threat_hunting_ruleset(techniques)
    _collect_identity_protection_catalog(techniques)
    # include indicators ingested via integrations (Amass, Velociraptor, etc.)
    _collect_threat_intel(techniques)
    await _collect_siem_evidence(techniques, db)
    await _collect_edr_evidence(techniques, db)
    await _collect_yara_evidence(techniques, db)
    await _collect_container_tooling_evidence(techniques, db)
    await _collect_cspm_findings_history(techniques, db)
    await _collect_unified_monitor_telemetry_evidence(techniques, db)
    await _collect_soar_execution_evidence(techniques, db)
    await _collect_network_scan_evidence(techniques, db)
    await _collect_threat_intel_match_evidence(techniques, db)
    await _collect_integration_job_evidence(techniques, db)
    await _collect_purplesharp_execution_evidence(techniques, db)
    # Technique update pass #3: evidence from canonical audit/event telemetry.
    await _collect_audit_and_world_event_evidence(techniques, db)
    # Technique update pass #3b: semantic security telemetry collections.
    await _collect_semantic_security_collections(techniques, db)
    # Technique update pass #4: Celery task ATT&CK metadata envelope evidence.
    await _collect_celery_task_attack_metadata(techniques, db)
    # Technique update pass #5: operational threat incident evidence.
    await _collect_threat_incident_evidence(techniques, db)
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
