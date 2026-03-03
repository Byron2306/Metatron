"""
Threat Hunting Router
=====================
API endpoints for MITRE ATT&CK-based automated threat hunting.
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from datetime import datetime, timezone

from .dependencies import get_current_user, check_permission, get_db

router = APIRouter(prefix="/hunting", tags=["Threat Hunting"])


class HuntRequest(BaseModel):
    telemetry: Dict[str, Any]


class RuleToggleRequest(BaseModel):
    enabled: bool


@router.get("/status")
async def get_hunting_status(current_user: dict = Depends(get_current_user)):
    """Get threat hunting engine status"""
    from services.threat_hunting import threat_hunting_engine
    
    return {
        "status": "operational",
        **threat_hunting_engine.get_stats()
    }


@router.get("/rules")
async def get_hunting_rules(
    tactic: Optional[str] = None,
    technique: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get all hunting rules"""
    from services.threat_hunting import threat_hunting_engine
    
    if tactic:
        rules = threat_hunting_engine.get_rules_by_tactic(tactic)
    elif technique:
        rules = threat_hunting_engine.get_rules_by_technique(technique)
    else:
        rules = list(threat_hunting_engine.rules.values())
    
    return {
        "rules": [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "mitre_technique": r.mitre_technique,
                "mitre_tactic": r.mitre_tactic,
                "severity": r.severity,
                "enabled": r.enabled,
                "data_sources": r.data_sources,
                "response_actions": r.response_actions
            }
            for r in rules
        ],
        "total": len(rules)
    }


@router.get("/rules/{rule_id}")
async def get_hunting_rule(
    rule_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a specific hunting rule"""
    from services.threat_hunting import threat_hunting_engine
    from dataclasses import asdict
    
    rule = threat_hunting_engine.rules.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    return asdict(rule)


@router.put("/rules/{rule_id}/toggle")
async def toggle_rule(
    rule_id: str,
    request: RuleToggleRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Enable or disable a hunting rule"""
    from services.threat_hunting import threat_hunting_engine
    
    rule = threat_hunting_engine.rules.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule.enabled = request.enabled
    
    return {"rule_id": rule_id, "enabled": rule.enabled}


@router.post("/hunt")
async def execute_hunt(
    request: HuntRequest,
    current_user: dict = Depends(get_current_user)
):
    """Execute threat hunting on provided telemetry"""
    from services.threat_hunting import threat_hunting_engine
    from dataclasses import asdict
    
    matches = threat_hunting_engine.hunt_all(request.telemetry)
    
    # Store matches in MongoDB
    db = get_db()
    if matches and db is not None:
        await db.hunting_matches.insert_many([asdict(m) for m in matches])
    
    return {
        "matches": [asdict(m) for m in matches],
        "total_matches": len(matches),
        "high_severity": len([m for m in matches if m.severity in ['critical', 'high']])
    }


@router.get("/matches")
async def get_recent_matches(
    severity: Optional[str] = None,
    technique: Optional[str] = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get recent hunting matches"""
    from services.threat_hunting import threat_hunting_engine
    from dataclasses import asdict
    
    # Get from in-memory first
    matches = threat_hunting_engine.matches[-limit:]
    
    if severity:
        matches = [m for m in matches if m.severity == severity]
    
    if technique:
        matches = [m for m in matches if m.mitre_technique == technique]
    
    return {
        "matches": [asdict(m) for m in matches],
        "total": len(matches)
    }


@router.get("/matches/high-severity")
async def get_high_severity_matches(
    current_user: dict = Depends(get_current_user)
):
    """Get critical and high severity matches"""
    from services.threat_hunting import threat_hunting_engine
    from dataclasses import asdict
    
    matches = threat_hunting_engine.get_high_severity_matches()
    
    return {
        "matches": [asdict(m) for m in matches[-50:]],
        "total": len(matches)
    }


@router.get("/tactics")
async def get_mitre_tactics(current_user: dict = Depends(get_current_user)):
    """Get covered MITRE ATT&CK tactics"""
    from services.threat_hunting import threat_hunting_engine
    
    tactics = {}
    for rule in threat_hunting_engine.rules.values():
        tactic = rule.mitre_tactic
        if tactic not in tactics:
            tactics[tactic] = {"tactic_id": tactic, "techniques": [], "rule_count": 0}
        tactics[tactic]["techniques"].append(rule.mitre_technique)
        tactics[tactic]["rule_count"] += 1
    
    # Deduplicate techniques
    for t in tactics.values():
        t["techniques"] = list(set(t["techniques"]))
    
    return {"tactics": list(tactics.values())}


@router.get("/techniques")
async def get_mitre_techniques(current_user: dict = Depends(get_current_user)):
    """Get all covered MITRE ATT&CK techniques"""
    from services.threat_hunting import threat_hunting_engine
    
    techniques = {}
    for rule in threat_hunting_engine.rules.values():
        tech = rule.mitre_technique
        if tech not in techniques:
            techniques[tech] = {
                "technique_id": tech,
                "name": rule.name,
                "tactic": rule.mitre_tactic,
                "severity": rule.severity,
                "rules": []
            }
        techniques[tech]["rules"].append(rule.rule_id)
    
    return {"techniques": list(techniques.values())}
