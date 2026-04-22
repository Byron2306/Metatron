import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query

from backend.mitre_catalog import load_mitre_catalog_totals

from .dependencies import get_current_user
try:
    from sigma_engine import sigma_engine
except Exception:
    from backend.sigma_engine import sigma_engine

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])
MITRE_COVERAGE_CACHE_TTL_SECONDS = max(
    30,
    int(os.environ.get("MITRE_COVERAGE_CACHE_TTL_SECONDS", "900") or 900),
)

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

_coverage_cache: Dict[str, Any] = {}
_coverage_cache_ts: float = 0.0


def _load_tvr_index() -> Dict[str, Any]:
    """Load the canonical TVR index from evidence_bundle.

    technique_index.json is the authoritative key set (691 techniques).
    coverage_summary.json provides updated tier/score data for techniques
    already in the index and takes priority on a per-technique basis.
    """
    import json
    from pathlib import Path

    evidence_root = Path(os.environ.get("EVIDENCE_BUNDLE_ROOT", "/var/lib/seraph-ai/evidence-bundle"))

    # Step 1: load technique_index.json as the authoritative key set
    merged: Dict[str, Any] = {}
    idx_path = evidence_root / "technique_index.json"
    if idx_path.exists():
        try:
            raw = json.loads(idx_path.read_text(encoding="utf-8"))
            techs = raw.get("techniques") or {}
            if isinstance(techs, dict):
                merged.update(techs)
        except Exception:
            pass

    # Step 2: override with coverage_summary.json data, but ONLY for techniques
    # already in the index — never add new techniques from coverage_summary
    cs_path = evidence_root / "coverage_summary.json"
    if cs_path.exists():
        try:
            raw = json.loads(cs_path.read_text(encoding="utf-8"))
            tech_list = raw.get("techniques") or []
            if isinstance(tech_list, list):
                for entry in tech_list:
                    tid = entry.get("technique_id")
                    if tid and tid in merged:
                        merged[tid] = entry
        except Exception:
            pass

    return merged


def _build_coverage_response(force_refresh: bool = False) -> Dict[str, Any]:
    global _coverage_cache, _coverage_cache_ts

    now = time.monotonic()
    if not force_refresh and _coverage_cache and (now - _coverage_cache_ts) < MITRE_COVERAGE_CACHE_TTL_SECONDS:
        return _coverage_cache

    # --- Canonical TVR source (evidence_bundle) ---
    tvr_index = _load_tvr_index()
    catalog_totals = load_mitre_catalog_totals()
    enterprise_total = int(catalog_totals.get("enterprise_technique_total") or 0)
    enterprise_parent_total = int(catalog_totals.get("enterprise_parent_total") or 0)
    roadmap_total = int(catalog_totals.get("roadmap_target_total") or enterprise_total or 0)

    # --- Sigma engine for tactic mapping and fallback scoring ---
    summary = sigma_engine.coverage_summary()
    unified = summary.get("unified_coverage") or {}
    sigma_rows = {row.get("technique"): row for row in (unified.get("techniques") or []) if row.get("technique")}

    # When TVR index is populated, it is the authoritative source — sigma supplements tactic
    # mapping only. Never let sigma add techniques that aren't in the TVR index.
    if tvr_index:
        all_technique_ids = set(tvr_index.keys())
    else:
        all_technique_ids = set(tvr_index.keys()) | set(sigma_rows.keys())

    techniques: List[Dict[str, Any]] = []
    for tid in sorted(all_technique_ids):
        tvr = tvr_index.get(tid) or {}
        sigma_row = sigma_rows.get(tid) or {}
        evidence = sigma_row.get("evidence") or {}

        # TVR score takes priority when a validated record exists
        if tvr:
            score = float(tvr.get("score", 0))
            tier = tvr.get("tier", "none")
            runs = int(tvr.get("repeated_runs", 0))
            reason = tvr.get("reason", "")
            sources = ["tvr_validated"] + (sigma_row.get("sources") or [])
        else:
            score = float(sigma_row.get("score", 0.0) or 0.0)
            tier = sigma_row.get("promotion_tier", "none")
            runs = int(evidence.get("atomic_validated_runs", 0) or 0)
            reason = ""
            sources = sigma_row.get("sources") or []

        operational = runs > 0 or int(evidence.get("osquery_telemetry_hits", 0) or 0) > 0

        techniques.append({
            "technique": tid,
            "id": tid,
            "score": score,
            "score_level": f"S{int(score)}" if score >= 1 else "S0",
            "tactic": sigma_row.get("tactic", ""),
            "tactics": sigma_row.get("tactics") or [],
            "implemented": score >= 1.0,
            "operational_evidence": operational,
            "implemented_evidence_count": runs,
            "sources": sources,
            "tvr_validated": bool(tvr),
            "tvr_runs": runs,
            "tvr_reason": reason,
            "evidence": evidence,
            "promotion_tier": tier,
        })

    covered_gte2 = sum(1 for t in techniques if t["score"] >= 2.0)
    covered_gte3 = sum(1 for t in techniques if t["score"] >= 3.0)
    covered_gte4 = sum(1 for t in techniques if t["score"] >= 4.0)
    covered_gte5 = sum(1 for t in techniques if t["score"] >= 5.0)
    covered_parent_gte3 = len({str(t["technique"]).split(".")[0] for t in techniques if t["score"] >= 3.0})
    covered_parent_gte4 = len({str(t["technique"]).split(".")[0] for t in techniques if t["score"] >= 4.0})
    covered_parent_gte5 = len({str(t["technique"]).split(".")[0] for t in techniques if t["score"] >= 5.0})
    operational_observed = sum(1 for t in techniques if t["operational_evidence"])

    total = len(techniques)

    result = {
        "techniques": techniques,
        "implemented_techniques": sum(1 for t in techniques if t["implemented"]),
        "operational_observed_techniques": operational_observed,
        "covered_score_gte2": covered_gte2,
        "covered_score_gte3": covered_gte3,
        "covered_score_gte4": covered_gte4,
        "covered_score_gte5": covered_gte5,
        "coverage_percent_gte2": round(covered_gte2 / enterprise_total * 100, 2) if enterprise_total else 0.0,
        "coverage_percent_gte3": round(covered_gte3 / enterprise_total * 100, 2) if enterprise_total else 0.0,
        "coverage_percent_gte4": round(covered_gte4 / enterprise_total * 100, 2) if enterprise_total else 0.0,
        "coverage_percent_gte5": round(covered_gte5 / enterprise_total * 100, 2) if enterprise_total else 0.0,
        "operational_coverage_percent": round(operational_observed / enterprise_total * 100, 2) if enterprise_total else 0.0,
        "enterprise_technique_total": enterprise_total,
        "enterprise_parent_total": enterprise_parent_total,
        "roadmap_target_techniques": roadmap_total,
        "roadmap_coverage_percent_gte3": round(covered_gte3 / roadmap_total * 100, 2) if roadmap_total else 0.0,
        "roadmap_coverage_percent_gte2": round(covered_gte2 / roadmap_total * 100, 2) if roadmap_total else 0.0,
        "roadmap_referenced_percent": round(total / roadmap_total * 100, 2) if roadmap_total else 0.0,
        "enterprise_covered_parent_techniques_gte3": covered_parent_gte3,
        "enterprise_covered_parent_techniques_gte4": covered_parent_gte4,
        "enterprise_covered_parent_techniques_gte5": covered_parent_gte5,
        "enterprise_parent_coverage_percent_gte3": round(covered_parent_gte3 / enterprise_parent_total * 100, 2) if enterprise_parent_total else 0.0,
        "enterprise_parent_coverage_percent_gte4": round(covered_parent_gte4 / enterprise_parent_total * 100, 2) if enterprise_parent_total else 0.0,
        "enterprise_parent_coverage_percent_gte5": round(covered_parent_gte5 / enterprise_parent_total * 100, 2) if enterprise_parent_total else 0.0,
        "gap_to_full_catalog_gte3": max(0, enterprise_total - covered_gte3),
        "gap_to_full_catalog_gte4": max(0, enterprise_total - covered_gte4),
        "gap_to_full_catalog_gte5": max(0, enterprise_total - covered_gte5),
        "gap_to_full_parent_gte3": max(0, enterprise_parent_total - covered_parent_gte3),
        "gap_to_full_parent_gte4": max(0, enterprise_parent_total - covered_parent_gte4),
        "gap_to_full_parent_gte5": max(0, enterprise_parent_total - covered_parent_gte5),
        "tvr_validated_count": len(tvr_index),
        "tvr_s5_count": covered_gte5,
        "tier_breakdown": {"platinum": covered_gte5, "gold": covered_gte4 - covered_gte5, "silver": covered_gte3 - covered_gte4, "bronze": covered_gte2 - covered_gte3, "none": total - covered_gte2},
        "telemetry_summary": unified.get("telemetry_summary") or {},
        "scoring_pass_trace": unified.get("scoring_pass_trace") or [],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "evidence_bundle_tvr+sigma_engine",
        "catalog_source": catalog_totals.get("catalog_path"),
    }

    _coverage_cache = result
    _coverage_cache_ts = now
    return result


@router.get("/coverage")
async def mitre_coverage(
    refresh: bool = Query(False),
    profile: str = Query("default"),
    current_user: dict = Depends(get_current_user),
):
    return _build_coverage_response(force_refresh=refresh)


@router.get("/tactics")
async def mitre_tactics(current_user: dict = Depends(get_current_user)):
    return {"tactics": TACTICS, "count": len(TACTICS)}


@router.get("/techniques")
async def mitre_techniques(
    tactic: str = Query("", max_length=10),
    current_user: dict = Depends(get_current_user),
):
    coverage = _build_coverage_response()
    techniques = coverage.get("techniques") or []
    if tactic:
        techniques = [t for t in techniques if tactic.upper() in str(t.get("tactics") or [])]
    return {"count": len(techniques), "techniques": techniques}
