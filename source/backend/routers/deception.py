"""
Deception Engine API Router
============================
Endpoints for Seraph's advanced deception system featuring:
- Pebbles (Campaign Tracking)
- Mystique (Adaptive Deception)
- Stonewall (Progressive Escalation)
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from enum import Enum
import logging
import os

from deception_engine import deception_engine, RouteDecision, EscalationLevel
from .dependencies import get_current_user, get_db

logger = logging.getLogger(__name__)

try:
    from services.world_events import emit_world_event
    from services.token_broker import token_broker
except Exception:
    emit_world_event = None
    token_broker = None

try:
    from services.mystique_maze import get_mystique_maze
except Exception:
    get_mystique_maze = None

try:
    from services.aatl import get_aatl_engine
except Exception:
    get_aatl_engine = None

try:
    from services.disinformation_engine import get_disinfo_engine
except Exception:
    get_disinfo_engine = None

router = APIRouter(prefix="/deception", tags=["Deception Engine"])


def _token_broker_enabled() -> bool:
    return os.environ.get("TOKEN_BROKER_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}


def _aatl_enabled() -> bool:
    return os.environ.get("AATL_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}

def _severity_to_risk(severity: str) -> int:
    s = str(severity or "").lower().strip()
    if s == "critical":
        return 95
    if s == "high":
        return 80
    if s == "medium":
        return 60
    if s == "low":
        return 35
    return 50


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class RouteDecisionEnum(str, Enum):
    PASS_THROUGH = "pass_through"
    FRICTION = "friction"
    TRAP_SINK = "trap_sink"
    HONEYPOT = "honeypot"
    DISINFORMATION = "disinformation"


class RiskAssessmentRequest(BaseModel):
    ip: str
    path: str = "/"
    headers: Dict[str, str] = Field(default_factory=dict)
    session_id: Optional[str] = None
    timing_data: Optional[Dict[str, Any]] = None
    behavior_flags: Optional[Dict[str, Any]] = None


class RiskAssessmentResponse(BaseModel):
    score: int
    reasons: List[str]
    route: str
    delay_ms: int
    campaign_id: Optional[str]
    fingerprint_id: Optional[str]
    escalation_level: str
    maze_id: Optional[str] = None
    maze_surface_nodes: Optional[List[Dict[str, Any]]] = None
    disinformation_payload: Optional[Dict[str, Any]] = None
    # AATL timing-enriched fields — returned so the harness can record the
    # router-computed values rather than the caller-supplied floor values.
    machine_plausibility: Optional[float] = None
    aatl_actor_type: Optional[str] = None
    aatl_indicators: List[str] = Field(default_factory=list)
    agenticity_score: Optional[float] = None


class DecoyInteractionRequest(BaseModel):
    ip: str
    decoy_type: str
    decoy_id: str
    session_id: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)


class DeployDecoyRequest(BaseModel):
    host_id: str = Field(default="deception-engine")
    decoy_type: str = Field(default="credentials")
    decoys: List[str] = Field(default_factory=lambda: ["svc_backup:Winter2026!", "api_key_trap_01"])
    placement: str = Field(default="standard")


class IPRequest(BaseModel):
    ip: str


class CampaignQueryParams(BaseModel):
    min_events: int = Field(default=5, ge=1, le=1000)
    limit: int = Field(default=50, ge=1, le=500)


class EventQueryParams(BaseModel):
    limit: int = Field(default=100, ge=1, le=1000)
    route_filter: Optional[str] = None
    campaign_id: Optional[str] = None


# =============================================================================
# STATUS & CONFIG
# =============================================================================

@router.get("/status")
async def get_deception_status():
    """Get deception engine status and configuration"""
    status = deception_engine.get_status()

    # Frontend compatibility: DeceptionPage expects top-level engine/status booleans.
    config = status.get("config", {}) if isinstance(status, dict) else {}
    return {
        **status,
        "engine": "Seraph Deception Engine",
        "status": "active",
        "uptime": status.get("uptime", "n/a") if isinstance(status, dict) else "n/a",
        "pebbles_enabled": True,
        "mystique_enabled": bool(config.get("mystique_enabled", True)),
        "stonewall_enabled": bool(config.get("stonewall_enabled", True)),
    }


@router.get("/capabilities")
async def get_capabilities():
    """Get list of deception capabilities"""
    return {
        "engine": "Seraph Deception Engine",
        "capabilities": [
            {
                "name": "Pebbles",
                "description": "Campaign-based attack correlation via behavioral fingerprints",
                "features": ["fingerprint_tracking", "campaign_correlation", "cross_session_linking"]
            },
            {
                "name": "Mystique",
                "description": "Self-adapting deception parameters based on attacker behavior",
                "features": ["adaptive_friction", "adaptive_tarpit", "dynamic_thresholds"]
            },
            {
                "name": "Stonewall",
                "description": "Progressive escalation for persistent attackers",
                "features": ["soft_ban", "hard_ban", "automatic_blocklisting"]
            },
            {
                "name": "Risk Scoring",
                "description": "Weighted behavioral risk assessment",
                "features": ["multi_signal", "weighted_scoring", "categorical_reasons"]
            },
            {
                "name": "Friction",
                "description": "Graduated response delays based on risk",
                "features": ["adaptive_delays", "challenge_mode", "rate_limiting"]
            },
            {
                "name": "Trap Sink",
                "description": "Tarpit + containment for high-risk traffic",
                "features": ["tarpit_delay", "deny_access", "campaign_tracking"]
            },
            {
                "name": "Logic-Budget Exhaustion Controller",
                "description": "Adapts deception routing using CBR/TBCR/CDI and agenticity pressure",
                "features": ["context_burn_rate", "tool_budget_pressure", "confidence_degradation", "forced_sink_routing"]
            }
        ],
        "decisions": [d.value for d in RouteDecision],
        "escalation_levels": [e.value for e in EscalationLevel]
    }


# =============================================================================
# RISK ASSESSMENT
# =============================================================================

@router.post("/assess", response_model=RiskAssessmentResponse)
async def assess_risk(request: RiskAssessmentRequest):
    """
    Perform risk assessment on an incoming request.
    Returns routing decision with delay if applicable.
    """
    merged_behavior_flags: Dict[str, Any] = dict(request.behavior_flags or {})

    # Enrich with formal AI metrics when a session is present.
    if request.session_id:
        try:
            from threat_response import AIDefenseEngine

            metrics = AIDefenseEngine.get_session_metrics(request.session_id)
            agenticity = metrics.get("agenticity") or {}
            exhaustion = metrics.get("exhaustion") or {}

            if "agenticity_score" not in merged_behavior_flags:
                merged_behavior_flags["agenticity_score"] = float(agenticity.get("score") or 0.0)
            if "autonomous_confidence" not in merged_behavior_flags:
                merged_behavior_flags["autonomous_confidence"] = float(agenticity.get("score") or 0.0)
            if "cbr" not in merged_behavior_flags:
                merged_behavior_flags["cbr"] = float(exhaustion.get("cbr") or 0.0)
            if "tbcr" not in merged_behavior_flags:
                merged_behavior_flags["tbcr"] = float(exhaustion.get("tbcr") or 0.0)
            if "cdi" not in merged_behavior_flags:
                merged_behavior_flags["cdi"] = float(exhaustion.get("cdi") or 0.0)
        except Exception:
            # Keep assessment resilient when AI defense services are unavailable.
            pass

    # ── AATL machine-tempo enrichment ─────────────────────────────────────────
    # The AATL engine computes machine_plausibility from real timing signals
    # (inter-request cadence, timing variance, request velocity) and from
    # agenticity pressure already in merged_behavior_flags.  We always run this
    # — even without a session — because the timing path is stateless.
    try:
        _aatl = get_aatl_engine() if (get_aatl_engine is not None and _aatl_enabled()) else None
        if _aatl is not None:
            aatl_result = _aatl.score_http_request(
                behavior_flags=merged_behavior_flags,
                timing_data=request.timing_data,
            )
            # Overwrite only when AATL derives a stronger signal than the
            # caller-supplied value (harness sets it = agenticity_score, which
            # is the behavioral-vector score, not a timing-derived score).
            if aatl_result["machine_plausibility"] > float(
                merged_behavior_flags.get("machine_plausibility", 0.0)
            ):
                merged_behavior_flags["machine_plausibility"] = aatl_result["machine_plausibility"]
                merged_behavior_flags["aatl_actor_type"] = aatl_result["actor_type"]
                merged_behavior_flags["aatl_indicators"] = aatl_result["indicators"]
    except Exception:
        pass  # AATL enrichment is best-effort; never break the routing path

    assessment = await deception_engine.process_request(
        ip=request.ip,
        path=request.path,
        headers=request.headers,
        session_id=request.session_id,
        timing_data=request.timing_data,
        behavior_flags=merged_behavior_flags
    )

    # ── GOVERNANCE / TAMPER-EVIDENT LOG on TRAP_SINK ──────────────────────────
    if assessment.route == RouteDecision.TRAP_SINK and request.session_id:
        logic_budget_force_trap = "logic_budget_pressure" in (assessment.reasons or []) or \
            any("logic_budget" in r for r in (assessment.reasons or []))
        agenticity_classification = merged_behavior_flags.get("agenticity_classification", "")
        agenticity_score = float(merged_behavior_flags.get("agenticity_score") or 0.0)
        cbr = float(merged_behavior_flags.get("cbr") or 0.0)
        tbcr = float(merged_behavior_flags.get("tbcr") or 0.0)

        # Emit action-critical world event (triggers Triune recompute + constitutional veto check)
        if emit_world_event is not None:
            try:
                import asyncio
                asyncio.ensure_future(emit_world_event(
                    db=None,
                    event_type="ai_logic_budget_trap",
                    entity_refs=[request.session_id, request.ip or "unknown"],
                    payload={
                        "session_id": request.session_id,
                        "ip": request.ip,
                        "score": assessment.score,
                        "reasons": assessment.reasons,
                        "campaign_id": assessment.campaign_id,
                        "agenticity_score": agenticity_score,
                        "agenticity_classification": agenticity_classification,
                        "cbr": cbr,
                        "tbcr": tbcr,
                        "logic_budget_force_trap": logic_budget_force_trap,
                        "impact_level": "critical",
                    },
                    source="deception_engine",
                ))
            except Exception:
                pass

        # Revoke active capability tokens for the AI session principal
        if token_broker is not None and _token_broker_enabled():
            try:
                token_broker.apply_ai_trust_degradation(
                    session_id=request.session_id,
                    agenticity_score=agenticity_score,
                    agenticity_classification=agenticity_classification or "HIGH",
                    cbr=cbr,
                    tbcr=tbcr,
                    logic_budget_force_trap=logic_budget_force_trap,
                )
            except Exception:
                pass

    # ── DISINFORMATION ─────────────────────────────────────────────────────────
    # When route is DISINFORMATION: generate a poisoned-but-plausible response
    # and emit a world event (STRATEGIC class) for the governance layer.
    disinfo_payload: Optional[Dict[str, Any]] = None

    if assessment.route == RouteDecision.DISINFORMATION and get_disinfo_engine is not None:
        try:
            disinfo_svc = get_disinfo_engine()
            disinfo_payload = disinfo_svc.generate(
                path=request.path,
                session_id=request.session_id,
                campaign_id=assessment.campaign_id,
                risk_score=assessment.score,
                reasons=assessment.reasons,
                behavior_flags=merged_behavior_flags,
            )
            if emit_world_event is not None:
                import asyncio
                asyncio.ensure_future(emit_world_event(
                    db=None,
                    event_type="ai_adversary_disinformation_served",
                    entity_refs=[request.session_id or "anon", request.ip or "unknown"],
                    payload={
                        "session_id": request.session_id,
                        "ip": request.ip,
                        "path": request.path,
                        "campaign_id": assessment.campaign_id,
                        "risk_score": assessment.score,
                        "disinfo_category": disinfo_payload.get("category"),
                        "reasons": assessment.reasons,
                    },
                    source="disinformation_engine",
                ))
        except Exception as exc:
            logger.warning(f"Disinformation generation failed: {exc}")

    # ── MYSTIQUE MIRROR WORLD MAZE ────────────────────────────────────────────
    # Activate the maze when:
    #   (a) route is HONEYPOT, OR
    #   (b) TRAP_SINK and agenticity is HIGH/VERY_HIGH
    maze_id: Optional[str] = None
    maze_surface: Optional[List[Dict[str, Any]]] = None

    should_activate_maze = (
        assessment.route == RouteDecision.HONEYPOT
        or (
            assessment.route == RouteDecision.TRAP_SINK
            and request.session_id
            and (
                # Layer 1: AATL timing-based machine plausibility (real tempo signal)
                merged_behavior_flags.get("machine_plausibility", 0.0) >= 0.6
                # Layer 2: Agenticity behavioral feature vector (fallback)
                or merged_behavior_flags.get("agenticity_score", 0.0) >= 0.6
            )
        )
    )

    if should_activate_maze and request.session_id and get_mystique_maze is not None:
        try:
            maze_svc = get_mystique_maze()
            maze_state = await maze_svc.get_or_create_maze(
                session_id=request.session_id,
                campaign_id=assessment.campaign_id,
                agenticity_score=float(merged_behavior_flags.get("agenticity_score", 0.0)),
                agenticity_classification=str(
                    merged_behavior_flags.get("agenticity_classification", "HIGH")
                ),
            )
            maze_id = maze_state.maze_id
            maze_surface = maze_svc.get_surface_nodes(request.session_id)

            # World-event for maze activation
            if emit_world_event is not None:
                import asyncio
                asyncio.ensure_future(emit_world_event(
                    db=None,
                    event_type="ai_adversary_maze_activated",
                    entity_refs=[request.session_id, assessment.campaign_id or ""],
                    payload={
                        "maze_id": maze_id,
                        "session_id": request.session_id,
                        "campaign_id": assessment.campaign_id,
                        "agenticity_score": float(merged_behavior_flags.get("agenticity_score", 0.0)),
                        "tier": maze_state.tier.value,
                        "surface_nodes": len(maze_state.root_node_ids),
                    },
                    source="mystique_maze",
                ))
        except Exception as exc:
            logger.warning(f"Mystique maze activation failed: {exc}")

    return RiskAssessmentResponse(
        score=assessment.score,
        reasons=assessment.reasons,
        route=assessment.route.value,
        delay_ms=assessment.delay_ms,
        campaign_id=assessment.campaign_id,
        fingerprint_id=assessment.fingerprint_id,
        escalation_level=assessment.escalation_level.value,
        maze_id=maze_id,
        maze_surface_nodes=maze_surface,
        disinformation_payload=disinfo_payload,
        machine_plausibility=float(merged_behavior_flags.get("machine_plausibility", 0.0)) or None,
        aatl_actor_type=merged_behavior_flags.get("aatl_actor_type"),
        aatl_indicators=list(merged_behavior_flags.get("aatl_indicators") or []),
        agenticity_score=float(merged_behavior_flags.get("agenticity_score", 0.0)) or None,
    )


@router.post("/assess/batch")
async def assess_risk_batch(requests: List[RiskAssessmentRequest]):
    """Batch risk assessment for multiple requests"""
    results = []
    for req in requests[:100]:  # Limit to 100
        assessment = await deception_engine.process_request(
            ip=req.ip,
            path=req.path,
            headers=req.headers,
            session_id=req.session_id,
            timing_data=req.timing_data,
            behavior_flags=req.behavior_flags
        )
        results.append({
            "ip": req.ip,
            "score": assessment.score,
            "route": assessment.route.value,
            "campaign_id": assessment.campaign_id
        })
    
    return {"assessments": results, "count": len(results)}


# =============================================================================
# DECOY INTERACTIONS
# =============================================================================

@router.post("/decoy/interaction")
async def record_decoy_interaction(request: DecoyInteractionRequest):
    """
    Record interaction with a decoy/honey token.
    Triggers immediate escalation.
    """
    assessment = await deception_engine.record_decoy_interaction(
        ip=request.ip,
        decoy_type=request.decoy_type,
        decoy_id=request.decoy_id,
        session_id=request.session_id,
        headers=request.headers
    )
    
    return {
        "recorded": True,
        "score": assessment.score,
        "route": assessment.route.value,
        "campaign_id": assessment.campaign_id,
        "escalation_level": assessment.escalation_level.value
    }


@router.post("/decoy/deploy")
async def deploy_decoy(request: DeployDecoyRequest, current_user: dict = Depends(get_current_user)):
    """Deploy decoys using the AI defense engine for Deception page quick actions."""
    from threat_response import AIDefenseEngine
    from dataclasses import asdict

    result = await AIDefenseEngine.deploy_decoy(
        host_id=request.host_id,
        decoy_type=request.decoy_type,
        decoys=request.decoys,
        placement=request.placement,
    )

    payload = asdict(result)
    payload["requested_by"] = current_user.get("email", "unknown")
    return payload


# =============================================================================
# CAMPAIGNS
# =============================================================================

@router.get("/campaigns")
async def get_campaigns(min_events: int = 5, limit: int = 50):
    """Get active attack campaigns"""
    def _normalize_campaign(c: Dict[str, Any]) -> Dict[str, Any]:
        details = c.get("details") if isinstance(c, dict) else {}
        details = details if isinstance(details, dict) else {}
        return {
            "id": c.get("id") or c.get("campaign_id") or details.get("campaign_id"),
            "name": c.get("name") or c.get("label") or c.get("campaign_name") or "campaign",
            "first_seen": c.get("first_seen") or c.get("created_at") or c.get("timestamp"),
            "last_seen": c.get("last_seen") or c.get("updated_at") or c.get("timestamp"),
            "event_count": int(c.get("event_count") or c.get("events") or details.get("event_count") or 0),
            "unique_ips": int(c.get("unique_ips") or details.get("unique_ips") or 0),
            "fingerprint_id": c.get("fingerprint_id") or details.get("fingerprint_id"),
            "escalation_level": c.get("escalation_level") or details.get("escalation_level") or "none",
            "routes": c.get("routes") or details.get("routes") or [],
        }

    campaigns_raw = deception_engine.get_campaigns(min_events=min_events, limit=limit)
    campaigns = [_normalize_campaign(c) for c in (campaigns_raw or []) if isinstance(c, dict)]
    campaigns = [c for c in campaigns if c.get("id")]

    # If the engine has no events yet, synthesize campaigns from recent threats so the UI isn't blank.
    if not campaigns:
        db = get_db()
        if db is not None:
            threats = await db.threats.find(
                {"source_ip": {"$exists": True}, "target_system": {"$exists": True}},
                {"_id": 0, "source_ip": 1, "severity": 1, "created_at": 1},
            ).sort("created_at", -1).limit(250).to_list(250)
            by_ip: Dict[str, Dict[str, Any]] = {}
            for t in threats:
                ip = str(t.get("source_ip") or "").strip()
                if not ip:
                    continue
                bucket = by_ip.setdefault(
                    ip,
                    {
                        "id": f"synthetic:{ip}",
                        "name": f"Synthetic Campaign ({ip})",
                        "first_seen": t.get("created_at"),
                        "last_seen": t.get("created_at"),
                        "event_count": 0,
                        "unique_ips": 1,
                        "fingerprint_id": f"fp:{ip}",
                        "routes": [],
                        "escalation_level": "none",
                    },
                )
                bucket["event_count"] += 1
                ts = t.get("created_at")
                if ts:
                    bucket["first_seen"] = min(bucket["first_seen"], ts) if bucket["first_seen"] else ts
                    bucket["last_seen"] = max(bucket["last_seen"], ts) if bucket["last_seen"] else ts
                sev = str(t.get("severity") or "medium").lower()
                if sev == "critical":
                    bucket["escalation_level"] = "hard_ban"
                elif sev == "high" and bucket["escalation_level"] != "hard_ban":
                    bucket["escalation_level"] = "soft_ban"
                route = "trap_sink" if sev in {"critical", "high"} else "friction"
                if route not in bucket["routes"]:
                    bucket["routes"].append(route)
            campaigns = list(by_ip.values())[:limit]

    return {
        "campaigns": campaigns,
        "count": len(campaigns)
    }


@router.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str):
    """Get specific campaign details"""
    campaign = deception_engine.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.get("/campaigns/{campaign_id}/events")
async def get_campaign_events(campaign_id: str, limit: int = 100):
    """Get events for a specific campaign"""
    events = deception_engine.get_events(limit=limit, campaign_id=campaign_id)
    return {"events": events, "count": len(events)}


# =============================================================================
# EVENTS
# =============================================================================

@router.get("/events")
async def get_events(
    limit: int = 100,
    route_filter: Optional[str] = None,
    campaign_id: Optional[str] = None
):
    """Get recent deception events with optional filtering"""
    def _normalize_event(e: Dict[str, Any]) -> Dict[str, Any]:
        details = e.get("details") if isinstance(e, dict) else {}
        details = details if isinstance(details, dict) else {}
        return {
            "id": e.get("id") or e.get("event_id") or details.get("event_id"),
            "ip": e.get("ip") or e.get("source_ip") or details.get("ip"),
            "path": e.get("path") or e.get("request_path") or details.get("path") or "/",
            "score": int(e.get("score") or details.get("score") or 0),
            "route": e.get("route") or e.get("route_decision") or details.get("route") or "pass_through",
            "escalation_level": e.get("escalation_level") or details.get("escalation") or "none",
            "campaign_id": e.get("campaign_id") or details.get("campaign_id"),
            "timestamp": e.get("timestamp") or e.get("created_at") or details.get("timestamp"),
            "decoy_triggered": bool(e.get("decoy_triggered") or details.get("decoy_triggered") or False),
        }

    events_raw = deception_engine.get_events(
        limit=min(limit, 1000),
        route_filter=route_filter,
        campaign_id=campaign_id
    )
    events = [_normalize_event(e) for e in (events_raw or []) if isinstance(e, dict)]
    events = [e for e in events if e.get("id") and e.get("ip")]

    if not events:
        db = get_db()
        if db is not None:
            threats = await db.threats.find(
                {"source_ip": {"$exists": True}, "target_system": {"$exists": True}},
                {"_id": 0, "id": 1, "source_ip": 1, "target_system": 1, "type": 1, "severity": 1, "created_at": 1},
            ).sort("created_at", -1).limit(min(300, int(limit) * 3)).to_list(min(300, int(limit) * 3))
            synthetic = []
            for t in threats:
                ip = str(t.get("source_ip") or "").strip()
                target = str(t.get("target_system") or "").strip()
                if not ip:
                    continue
                sev = str(t.get("severity") or "medium").lower()
                route = "trap_sink" if sev in {"critical", "high"} else "friction"
                escalation = "hard_ban" if sev == "critical" else ("soft_ban" if sev == "high" else "none")
                synthetic.append(
                    {
                        "id": t.get("id") or f"synthetic:{ip}:{target}:{t.get('created_at')}",
                        "ip": ip,
                        "path": f"/threat/{t.get('type') or 'signal'}",
                        "score": 40 + int(_severity_to_risk(sev) / 2),
                        "route": route,
                        "escalation_level": escalation,
                        "campaign_id": f"synthetic:{ip}",
                        "timestamp": t.get("created_at"),
                        "decoy_triggered": False,
                    }
                )
            events = synthetic[: int(limit)]

    return {"events": events, "count": len(events)}


@router.get("/events/summary")
async def get_events_summary():
    """Get summary of recent events by type"""
    events = deception_engine.get_events(limit=1000)
    
    summary = {
        "total": len(events),
        "by_route": {},
        "by_escalation": {},
        "unique_ips": set(),
        "unique_campaigns": set()
    }
    
    for event in events:
        route = event.get("route_decision", "unknown")
        summary["by_route"][route] = summary["by_route"].get(route, 0) + 1
        
        escalation = event.get("details", {}).get("escalation", "none")
        summary["by_escalation"][escalation] = summary["by_escalation"].get(escalation, 0) + 1
        
        summary["unique_ips"].add(event.get("source_ip"))
        if event.get("campaign_id"):
            summary["unique_campaigns"].add(event["campaign_id"])
    
    summary["unique_ips"] = len(summary["unique_ips"])
    summary["unique_campaigns"] = len(summary["unique_campaigns"])
    
    return summary


# =============================================================================
# BLOCKLIST/ALLOWLIST
# =============================================================================

@router.post("/allowlist/add")
async def add_to_allowlist(request: IPRequest):
    """Add IP to allowlist"""
    success = deception_engine.add_to_allowlist(request.ip)
    return {"success": success, "ip": request.ip, "action": "allowlisted"}


@router.post("/blocklist/add")
async def add_to_blocklist(request: IPRequest):
    """Add IP to blocklist"""
    success = deception_engine.add_to_blocklist(request.ip)
    return {"success": success, "ip": request.ip, "action": "blocklisted"}


@router.post("/blocklist/remove")
async def remove_from_blocklist(request: IPRequest):
    """Remove IP from blocklist"""
    success = deception_engine.remove_from_blocklist(request.ip)
    return {"success": success, "ip": request.ip, "action": "unblocked"}


@router.get("/blocklist")
async def get_blocklist():
    """Get current blocklist"""
    return {
        "blocklist": list(deception_engine.blocklist),
        "allowlist": list(deception_engine.allowlist),
        "soft_bans": len(deception_engine.soft_bans)
    }


# =============================================================================
# FINGERPRINTS
# =============================================================================

@router.get("/fingerprints")
async def get_fingerprints(min_events: int = 3, limit: int = 100):
    """Get behavioral fingerprints"""
    fingerprints = [
        fp.to_dict() for fp in deception_engine.fingerprints.values()
        if fp.total_events >= min_events
    ]
    fingerprints.sort(key=lambda x: x["total_events"], reverse=True)
    
    return {
        "fingerprints": fingerprints[:limit],
        "total": len(fingerprints)
    }


@router.get("/fingerprints/{fingerprint_id}")
async def get_fingerprint(fingerprint_id: str):
    """Get specific fingerprint details"""
    if fingerprint_id not in deception_engine.fingerprints:
        raise HTTPException(status_code=404, detail="Fingerprint not found")
    
    fp = deception_engine.fingerprints[fingerprint_id]
    
    # Find campaigns for this fingerprint
    campaigns = [
        c.to_dict() for c in deception_engine.campaigns.values()
        if fingerprint_id in c.fingerprint_ids
    ]
    
    return {
        "fingerprint": fp.to_dict(),
        "campaigns": campaigns
    }


# =============================================================================
# MYSTIQUE TUNING
# =============================================================================

@router.post("/mystique/force-adapt/{campaign_id}")
async def force_mystique_adapt(campaign_id: str):
    """Force Mystique adaptation for a campaign"""
    if campaign_id not in deception_engine.campaigns:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    # Temporarily increase events to trigger adaptation
    campaign = deception_engine.campaigns[campaign_id]
    original_events = campaign.total_events
    
    # Force adaptation
    campaign.total_events = max(campaign.total_events, 
                                deception_engine.config.campaign_promote_threshold + 1)
    campaign.total_events = (
        (campaign.total_events // deception_engine.config.adapt_every_n_events + 1) 
        * deception_engine.config.adapt_every_n_events
    )
    
    adapted = deception_engine.mystique_adapt(campaign_id)
    
    return {
        "adapted": adapted,
        "campaign_id": campaign_id,
        "friction_multiplier": campaign.friction_multiplier,
        "tarpit_multiplier": campaign.tarpit_multiplier,
        "sink_score_override": campaign.sink_score_override
    }


@router.get("/mystique/config")
async def get_mystique_config():
    """Get Mystique configuration"""
    cfg = deception_engine.config
    return {
        "enabled": cfg.mystique_enabled,
        "adapt_every_n_events": cfg.adapt_every_n_events,
        "campaign_promote_threshold": cfg.campaign_promote_threshold,
        "max_friction_multiplier": cfg.max_friction_multiplier,
        "max_tarpit_multiplier": cfg.max_tarpit_multiplier,
        "min_sink_score_floor": cfg.min_sink_score_floor
    }


# =============================================================================
# STONEWALL CONFIG
# =============================================================================

@router.get("/stonewall/config")
async def get_stonewall_config():
    """Get Stonewall configuration"""
    cfg = deception_engine.config
    return {
        "enabled": cfg.stonewall_enabled,
        "repeat_threshold": cfg.repeat_threshold,
        "ban_seconds_first": cfg.ban_seconds_first,
        "ban_seconds_repeat": cfg.ban_seconds_repeat,
        "trap_hits_to_blocklist": cfg.trap_hits_to_blocklist
    }


# =============================================================================
# ANALYTICS
# =============================================================================

@router.get("/analytics/threat-heatmap")
async def get_threat_heatmap():
    """Get threat data for heatmap visualization"""
    campaigns = deception_engine.get_campaigns(min_events=1, limit=500)
    
    heatmap = []
    for campaign in campaigns:
        for ip in campaign.get("source_ips", []):
            heatmap.append({
                "ip": ip,
                "campaign_id": campaign["campaign_id"],
                "total_events": campaign["total_events"],
                "trap_events": campaign["trap_events"],
                "escalation_level": campaign.get("escalation_level", "none"),
                "risk_indicator": campaign.get("friction_multiplier", 1.0)
            })
    
    return {"data": heatmap, "count": len(heatmap)}


@router.get("/analytics/campaigns-timeline")
async def get_campaigns_timeline(hours: int = 24):
    """Get campaign activity timeline"""
    events = deception_engine.get_events(limit=5000)
    
    # Group by hour
    timeline = {}
    for event in events:
        ts = event.get("timestamp", "")[:13]  # YYYY-MM-DDTHH
        if ts not in timeline:
            timeline[ts] = {"trap_sink": 0, "friction": 0, "pass": 0}
        
        route = event.get("route_decision", "pass_through")
        if route == "trap_sink":
            timeline[ts]["trap_sink"] += 1
        elif route == "friction":
            timeline[ts]["friction"] += 1
        else:
            timeline[ts]["pass"] += 1
    
    # Convert to sorted list
    sorted_timeline = [
        {"hour": k, **v} for k, v in sorted(timeline.items())
    ]
    
    return {"timeline": sorted_timeline[-hours:], "hours": hours}


# =============================================================================
# DISINFORMATION ENGINE
# =============================================================================

@router.get("/disinformation/history")
async def get_disinformation_history(
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
):
    """Return recent DISINFORMATION route activations (poisoned responses served)."""
    if get_disinfo_engine is None:
        return {"error": "Disinformation engine unavailable", "history": []}
    try:
        history = get_disinfo_engine().get_history(limit=limit)
        return {"count": len(history), "history": history}
    except Exception as exc:
        logger.error(f"Failed to retrieve disinformation history: {exc}")
        return {"error": str(exc), "history": []}


@router.get("/disinformation/stats")
async def get_disinformation_stats(current_user: dict = Depends(get_current_user)):
    """Return aggregate statistics for the disinformation engine."""
    if get_disinfo_engine is None:
        return {"error": "Disinformation engine unavailable"}
    try:
        return get_disinfo_engine().get_stats()
    except Exception as exc:
        logger.error(f"Failed to retrieve disinformation stats: {exc}")
        return {"error": str(exc)}


# =============================================================================
# MYSTIQUE MIRROR WORLD MAZE
# =============================================================================

class MazeProbeRequest(BaseModel):
    session_id: str
    node_id: str
    agenticity_score: float = 0.0
    cbr: float = 0.0
    tbcr: float = 0.0


@router.get("/maze/active")
async def list_active_mazes(current_user: dict = Depends(get_current_user)):
    """
    List all currently active mirror-world maze sessions with collected
    adversary intelligence.
    """
    if get_mystique_maze is None:
        raise HTTPException(status_code=503, detail="Maze service unavailable")
    maze_svc = get_mystique_maze()
    return {
        "mazes": maze_svc.list_active_mazes(),
        "total": len(maze_svc.list_active_mazes()),
    }


@router.get("/maze/{session_id}/surface")
async def get_maze_surface(session_id: str, current_user: dict = Depends(get_current_user)):
    """
    Return the surface-level (entry) nodes of a session's mirror world.
    Used by defenders to see what lures are currently presented to an adversary.
    """
    if get_mystique_maze is None:
        raise HTTPException(status_code=503, detail="Maze service unavailable")
    maze_svc = get_mystique_maze()
    telemetry = maze_svc.get_maze_telemetry(session_id)
    if telemetry is None:
        raise HTTPException(status_code=404, detail="No maze for this session")
    return {
        "session_id": session_id,
        "telemetry": telemetry,
        "surface_nodes": maze_svc.get_surface_nodes(session_id),
    }


@router.post("/maze/probe")
async def maze_probe(request: MazeProbeRequest):
    """
    Simulate an adversary probing a maze node.
    Returns the fabricated payload + list of newly spawned child nodes.

    In a live deployment this endpoint is called transparently by Seraph when
    an AI adversary session interacts with a resource that has been replaced
    by the mirror world. The adversary sees a realistic response; Seraph
    collects intent telemetry.
    """
    if get_mystique_maze is None:
        raise HTTPException(status_code=503, detail="Maze service unavailable")
    maze_svc = get_mystique_maze()

    if maze_svc.get_maze_telemetry(request.session_id) is None:
        raise HTTPException(status_code=404, detail="No maze for this session — call /assess first")

    payload, new_node_ids = await maze_svc.probe_node(
        session_id=request.session_id,
        node_id=request.node_id,
        agenticity_score=request.agenticity_score,
        cbr=request.cbr,
        tbcr=request.tbcr,
    )

    # Emit world event for each maze traversal step
    if emit_world_event is not None:
        try:
            import asyncio
            telemetry = maze_svc.get_maze_telemetry(request.session_id) or {}
            asyncio.ensure_future(emit_world_event(
                db=None,
                event_type="ai_adversary_maze_traversal",
                entity_refs=[request.session_id, request.node_id],
                payload={
                    "session_id": request.session_id,
                    "node_id": request.node_id,
                    "new_nodes_spawned": len(new_node_ids),
                    "inferred_intent": telemetry.get("inferred_intent"),
                    "tier": telemetry.get("tier"),
                    "total_probes": telemetry.get("total_probes"),
                    "total_bytes_consumed": telemetry.get("total_bytes_consumed"),
                    "agenticity_score": request.agenticity_score,
                },
                source="mystique_maze",
            ))
        except Exception:
            pass

    return {
        "node_id": request.node_id,
        "payload": payload,
        "new_node_ids": new_node_ids,
        "telemetry_snapshot": maze_svc.get_maze_telemetry(request.session_id),
    }


@router.get("/maze/{session_id}/telemetry")
async def get_maze_telemetry(session_id: str, current_user: dict = Depends(get_current_user)):
    """
    Return full adversary intelligence collected from a mirror-world maze session.
    Shows inferred intent, observed TTPs, reasoning budget burned, and probe history.
    """
    if get_mystique_maze is None:
        raise HTTPException(status_code=503, detail="Maze service unavailable")
    maze_svc = get_mystique_maze()
    telemetry = maze_svc.get_maze_telemetry(session_id)
    if telemetry is None:
        raise HTTPException(status_code=404, detail="No maze for this session")
    return telemetry


# =============================================================================
# EXPLAINABILITY ENDPOINTS
# =============================================================================

@router.get("/explain/{session_id}")
async def explain_session_decision(session_id: str, db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    """
    Explain why a session received its route decision.
    
    Returns comprehensive analysis including:
    - Risk assessment breakdown
    - Agenticity score components  
    - Maze telemetry (if applicable)
    - Campaign correlation
    - Decision confidence factors
    """
    try:
        # Get deception engine analysis
        session_analysis = deception_engine.get_session_analysis(session_id)
        if not session_analysis:
            raise HTTPException(status_code=404, detail="Session not found in deception engine")
        
        explanation = {
            "session_id": session_id,
            "decision": session_analysis.get("route_decision"),
            "confidence": session_analysis.get("confidence", 0),
            "timestamp": session_analysis.get("last_updated"),
            "campaign_id": session_analysis.get("campaign_id"),
        }
        
        # Add risk assessment breakdown
        risk_assessment = session_analysis.get("risk_assessment", {})
        explanation["risk_breakdown"] = {
            "score": risk_assessment.get("score", 0),
            "reasons": risk_assessment.get("reasons", []),
            "behavior_flags": risk_assessment.get("behavior_flags", {}),
        }
        
        # Add agenticity analysis if available
        try:
            from services.agenticity import get_agenticity_persistence
            agenticity_persist = get_agenticity_persistence(db)
            if agenticity_persist:
                session_summary = await agenticity_persist.get_session_summary(session_id)
                if session_summary.get("latest_score"):
                    explanation["agenticity"] = {
                        "score": session_summary["latest_score"]["score"],
                        "classification": session_summary["latest_score"]["classification"],
                        "feature_vector": session_summary["latest_score"]["feature_vector"],
                        "weights": session_summary["latest_score"]["weights"],
                        "weighted_components": session_summary["latest_score"]["weighted_components"],
                        "generated_at": session_summary["latest_score"]["generated_at"],
                    }
                if session_summary.get("latest_exhaustion"):
                    explanation["exhaustion_metrics"] = session_summary["latest_exhaustion"]
        except Exception as e:
            explanation["agenticity_error"] = str(e)
        
        # Add maze analysis if applicable
        if get_mystique_maze is not None:
            try:
                maze_svc = get_mystique_maze()
                maze_telemetry = maze_svc.get_maze_telemetry(session_id)
                if maze_telemetry:
                    explanation["maze_analysis"] = {
                        "maze_id": maze_telemetry["maze_id"],
                        "tier": maze_telemetry["tier"],
                        "inferred_intent": maze_telemetry["inferred_intent"],
                        "total_probes": maze_telemetry["total_probes"],
                        "total_bytes_consumed": maze_telemetry["total_bytes_consumed"],
                        "observed_ttps": maze_telemetry["observed_ttps"],
                        "nodes_total": maze_telemetry["nodes_total"],
                        "nodes_accessed": maze_telemetry["nodes_accessed"],
                    }
            except Exception as e:
                explanation["maze_error"] = str(e)
        
        # Add campaign context
        campaign_id = session_analysis.get("campaign_id")
        if campaign_id:
            campaign_stats = deception_engine.get_campaign_stats(campaign_id)
            if campaign_stats:
                explanation["campaign_context"] = {
                    "campaign_id": campaign_id,
                    "total_events": campaign_stats.get("total_events", 0),
                    "unique_sessions": campaign_stats.get("unique_sessions", 0),
                    "risk_trend": campaign_stats.get("risk_trend", []),
                    "last_activity": campaign_stats.get("last_activity"),
                }
        
        # Add decision confidence factors
        explanation["confidence_factors"] = {
            "escalation_level": session_analysis.get("escalation_level"),
            "stonewall_triggers": session_analysis.get("stonewall_triggers", []),
            "mystique_active": session_analysis.get("mystique_active", False),
            "disinformation_eligible": session_analysis.get("disinformation_eligible", False),
        }
        
        return explanation
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Explanation generation failed: {str(e)}")


# =============================================================================
# PERSISTENCE ENDPOINTS
# =============================================================================

@router.get("/maze/sessions")
async def get_maze_sessions(limit: int = 50, db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Get list of active maze sessions with persistence."""
    try:
        from services.mystique_maze import get_maze_persistence
        persistence = get_maze_persistence(db)
        if persistence:
            sessions = await persistence.get_maze_sessions(limit)
            return {"sessions": sessions, "count": len(sessions)}
        else:
            return {"sessions": [], "count": 0, "note": "Database persistence not available"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve maze sessions: {str(e)}")


@router.get("/agenticity/sessions/{session_id}")
async def get_agenticity_session_history(session_id: str, limit: int = 10, db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Get agenticity score history for a session."""
    try:
        from services.agenticity import get_agenticity_persistence
        persistence = get_agenticity_persistence(db)
        if persistence:
            scores = await persistence.get_score_history(session_id, limit)
            exhaustion = await persistence.get_exhaustion_history(session_id, limit)
            return {
                "session_id": session_id,
                "scores": scores,
                "exhaustion_metrics": exhaustion,
                "score_count": len(scores),
                "exhaustion_count": len(exhaustion),
            }
        else:
            return {"error": "Database persistence not available"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve agenticity history: {str(e)}")


@router.get("/agenticity/sessions/{session_id}/summary")
async def get_agenticity_session_summary(session_id: str, db=Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Get comprehensive agenticity session summary."""
    try:
        from services.agenticity import get_agenticity_persistence
        persistence = get_agenticity_persistence(db)
        if persistence:
            summary = await persistence.get_session_summary(session_id)
            return summary
        else:
            return {"error": "Database persistence not available"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve session summary: {str(e)}")
