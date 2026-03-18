"""
Agent Command System - Bi-directional communication between server and agents
Commands require manual approval before execution
"""
from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from datetime import datetime, timezone
import uuid
import json
import asyncio

from .dependencies import get_db
from backend.services.governed_dispatch import GovernedDispatchService
from backend.services.governance_authority import GovernanceDecisionAuthority
from backend.services.governance_executor import GovernanceExecutorService
from backend.services.outbound_gate import OutboundGateService
from backend.services.polyphonic_governance import get_polyphonic_governance_service
from backend.services.notation_token import get_notation_token_service
from backend.services.harmonic_engine import get_harmonic_engine
from backend.services.vns import vns
from backend.services.vns_alerts import vns_alert_service
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
try:
    from .dependencies import (
        get_current_user,
        get_optional_current_user,
        check_permission,
        has_permission,
        optional_machine_token,
        logger,
        verify_websocket_machine_token,
    )
except Exception:
    def get_current_user(*args, **kwargs):
        return None

    def check_permission(required_permission: str):
        async def _checker(*a, **k):
            return None
        return _checker

    async def get_optional_current_user(*args, **kwargs):
        return None

    def has_permission(_user: Optional[dict], _required_permission: str) -> bool:
        return False

    def optional_machine_token(*args, **kwargs):
        async def _checker(*a, **k):
            return None
        return _checker

    import logging as _logging
    logger = _logging.getLogger(__name__)

    def verify_websocket_machine_token(*args, **kwargs):
        return {"auth": "ok"}

router = APIRouter(prefix="/agent-commands", tags=["Agent Commands"])
verify_agent_result_machine_token = optional_machine_token(
    env_keys=["AGENT_COMMANDS_TOKEN", "SWARM_AGENT_TOKEN", "INTEGRATION_API_KEY"],
    header_names=["x-agent-token", "x-internal-token"],
    subject="agent command reporter",
)

COMMAND_TERMINAL_STATUSES = {"completed", "failed", "rejected"}
CONNECTION_STATUSES = {"connected", "disconnected"}
AGENT_STATUS_SNAPSHOT_STATUSES = {"snapshot"}

# In-memory storage for connected agents and pending commands
connected_agents: Dict[str, WebSocket] = {}
pending_commands: Dict[str, Dict] = {}
command_results: Dict[str, Dict] = {}


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_epoch_ms(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(float(value))
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(float(text))
    except Exception:
        pass
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except Exception:
        return None


def _build_result_stage_harmonic_context(
    *,
    db: Any,
    command: Dict[str, Any],
    result_success: bool,
    stage: str,
) -> Dict[str, Any]:
    polyphonic_context = dict(command.get("polyphonic_context") or {})
    timestamp_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    dispatch_ms = _to_epoch_ms(
        command.get("dispatch_created_at_ms")
        or (polyphonic_context.get("harmonic_timeline") or {}).get("dispatch_created_at_ms")
    )
    tool_name = str(command.get("command_type") or command.get("tool") or "agent_command")
    target_domain = str(
        command.get("target_domain")
        or (command.get("parameters") or {}).get("target_domain")
        or "global"
    )
    harmonic_engine = get_harmonic_engine(db)
    observation = harmonic_engine.score_observation(
        actor_id=str(command.get("agent_id") or command.get("actor") or "agent"),
        tool_name=tool_name,
        target_domain=target_domain,
        environment="local",
        stage=stage,
        timestamp_ms=float(timestamp_ms),
        operation=str(command.get("command_type") or "agent_command"),
        context={"result_success": bool(result_success), "command_id": command.get("command_id")},
    )
    polyphonic_context["timing_features"] = observation.get("timing_features")
    polyphonic_context["harmonic_state"] = observation.get("harmonic_state")
    polyphonic_context["baseline_ref"] = observation.get("baseline_ref")
    history = list(polyphonic_context.get("harmonic_history") or [])
    history.append(
        {
            "stage": stage,
            "timestamp_ms": timestamp_ms,
            "harmonic_state": observation.get("harmonic_state"),
        }
    )
    polyphonic_context["harmonic_history"] = history[-30:]
    timeline = dict(polyphonic_context.get("harmonic_timeline") or {})
    if dispatch_ms is not None:
        timeline.setdefault("dispatch_created_at_ms", dispatch_ms)
        timeline["closure_lag_ms"] = max(0, timestamp_ms - dispatch_ms)
    timeline["audit_closed_at_ms"] = timestamp_ms
    polyphonic_context["harmonic_timeline"] = timeline
    try:
        if hasattr(vns, "update_domain_pulse"):
            pulse = vns.update_domain_pulse(
                domain=target_domain,
                timing_features=observation.get("timing_features") or {},
                harmonic_state=observation.get("harmonic_state") or {},
                timestamp_ms=timestamp_ms,
            )
            if (
                pulse
                and float(pulse.get("pulse_stability_index") or 1.0) < 0.45
                and hasattr(vns_alert_service, "alert_pulse_instability_by_domain")
            ):
                vns_alert_service.alert_pulse_instability_by_domain(pulse)
    except Exception:
        pass
    return polyphonic_context


def _transition_entry(
    from_status: Optional[str],
    to_status: str,
    actor: str,
    reason: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    entry = {
        "timestamp": _iso_now(),
        "from_status": from_status,
        "to_status": to_status,
        "actor": actor,
        "reason": reason,
    }
    if metadata:
        entry["metadata"] = metadata
    return entry


async def _guarded_command_transition(
    db,
    *,
    command_id: str,
    expected_statuses: List[str],
    next_status: str,
    actor: str,
    reason: str,
    expected_state_version: Optional[int] = None,
    extra_updates: Optional[Dict[str, Any]] = None,
    transition_metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    command = await db.agent_commands.find_one({"command_id": command_id}, {"_id": 0})
    if not command:
        return False

    from_status = str(command.get("status") or "").lower().strip()
    if from_status not in expected_statuses:
        return False

    resolved_version = expected_state_version
    if resolved_version is None:
        resolved_version = int(command.get("state_version") or 0)

    query: Dict[str, Any] = {
        "command_id": command_id,
        "status": {"$in": expected_statuses},
    }
    if resolved_version <= 0:
        query["$or"] = [{"state_version": {"$exists": False}}, {"state_version": 0}]
    else:
        query["state_version"] = resolved_version

    set_doc = {
        "status": next_status,
        "updated_at": _iso_now(),
    }
    if extra_updates:
        set_doc.update(extra_updates)

    transition = _transition_entry(
        from_status=from_status,
        to_status=next_status,
        actor=actor,
        reason=reason,
        metadata=transition_metadata,
    )

    update = {
        "$set": set_doc,
        "$inc": {"state_version": 1},
        "$push": {"state_transition_log": transition},
    }

    result = await db.agent_commands.update_one(query, update)
    return bool(getattr(result, "modified_count", 0))


async def _ensure_command_state_fields(
    db,
    *,
    command_id: str,
    actor: str,
    reason: str,
) -> Dict[str, Any]:
    command = await db.agent_commands.find_one({"command_id": command_id}, {"_id": 0})
    if not command:
        return {}

    if command.get("state_version") is not None and command.get("state_transition_log") is not None:
        return command

    current_status = str(command.get("status") or "pending_approval").lower().strip()
    bootstrap = {
        "state_version": int(command.get("state_version") or 1),
        "state_transition_log": command.get("state_transition_log")
        or [
            _transition_entry(
                from_status=None,
                to_status=current_status,
                actor=actor,
                reason=reason,
            )
        ],
    }
    await db.agent_commands.update_one({"command_id": command_id}, {"$set": bootstrap})
    return await db.agent_commands.find_one({"command_id": command_id}, {"_id": 0}) or {}


def _connection_transition_entry(
    from_status: Optional[str],
    to_status: str,
    actor: str,
    reason: str,
    session_id: Optional[str],
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    entry = {
        "timestamp": _iso_now(),
        "from_status": from_status,
        "to_status": to_status,
        "actor": actor,
        "reason": reason,
        "session_id": session_id,
    }
    if metadata:
        entry["metadata"] = metadata
    return entry


async def _ensure_connection_state_fields(
    db,
    *,
    agent_id: str,
    actor: str,
    reason: str,
) -> Dict[str, Any]:
    connection = await db.connected_agents.find_one({"agent_id": agent_id}, {"_id": 0})
    if not connection:
        return {}

    if (
        connection.get("connection_state_version") is not None
        and connection.get("connection_transition_log") is not None
    ):
        return connection

    current_status = str(connection.get("status") or "disconnected").lower().strip()
    if current_status not in CONNECTION_STATUSES:
        current_status = "disconnected"

    bootstrap = {
        "connection_state_version": int(connection.get("connection_state_version") or 1),
        "connection_transition_log": connection.get("connection_transition_log")
        or [
            _connection_transition_entry(
                from_status=None,
                to_status=current_status,
                actor=actor,
                reason=reason,
                session_id=connection.get("session_id"),
            )
        ],
        "updated_at": _iso_now(),
    }
    await db.connected_agents.update_one({"agent_id": agent_id}, {"$set": bootstrap})
    return await db.connected_agents.find_one({"agent_id": agent_id}, {"_id": 0}) or {}


async def _transition_connection_state(
    db,
    *,
    agent_id: str,
    expected_statuses: List[str],
    next_status: str,
    actor: str,
    reason: str,
    session_id: Optional[str],
    expected_state_version: Optional[int] = None,
    required_current_session_id: Optional[str] = None,
    extra_updates: Optional[Dict[str, Any]] = None,
    transition_metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    connection = await db.connected_agents.find_one({"agent_id": agent_id}, {"_id": 0})
    if not connection:
        return False

    from_status = str(connection.get("status") or "").lower().strip()
    if from_status not in expected_statuses:
        return False

    if required_current_session_id and connection.get("session_id") != required_current_session_id:
        return False

    resolved_version = expected_state_version
    if resolved_version is None:
        resolved_version = int(connection.get("connection_state_version") or 0)

    query: Dict[str, Any] = {
        "agent_id": agent_id,
        "status": {"$in": expected_statuses},
    }
    if required_current_session_id:
        query["session_id"] = required_current_session_id

    if resolved_version <= 0:
        query["$or"] = [
            {"connection_state_version": {"$exists": False}},
            {"connection_state_version": 0},
        ]
    else:
        query["connection_state_version"] = resolved_version

    set_doc = {
        "status": next_status,
        "session_id": session_id,
        "updated_at": _iso_now(),
    }
    if extra_updates:
        set_doc.update(extra_updates)

    transition = _connection_transition_entry(
        from_status=from_status,
        to_status=next_status,
        actor=actor,
        reason=reason,
        session_id=session_id,
        metadata=transition_metadata,
    )

    result = await db.connected_agents.update_one(
        query,
        {
            "$set": set_doc,
            "$inc": {"connection_state_version": 1},
            "$push": {"connection_transition_log": transition},
        },
    )
    return bool(getattr(result, "modified_count", 0))


async def _register_connected_session(
    db,
    *,
    agent_id: str,
    session_id: str,
) -> bool:
    now = _iso_now()
    existing = await db.connected_agents.find_one({"agent_id": agent_id}, {"_id": 0})
    if not existing:
        await db.connected_agents.update_one(
            {"agent_id": agent_id},
            {
                "$set": {
                    "agent_id": agent_id,
                    "connected_at": now,
                    "status": "connected",
                    "session_id": session_id,
                    "last_heartbeat": now,
                    "updated_at": now,
                    "connection_state_version": 1,
                    "connection_transition_log": [
                        _connection_transition_entry(
                            from_status=None,
                            to_status="connected",
                            actor="system:websocket",
                            reason="websocket session connected",
                            session_id=session_id,
                        )
                    ],
                }
            },
            upsert=True,
        )
        return True

    existing = await _ensure_connection_state_fields(
        db,
        agent_id=agent_id,
        actor="system:websocket",
        reason="bootstrap connection durability fields",
    )
    current_version = int(existing.get("connection_state_version") or 0)
    current_session = existing.get("session_id")

    return await _transition_connection_state(
        db,
        agent_id=agent_id,
        expected_statuses=["connected", "disconnected"],
        next_status="connected",
        actor="system:websocket",
        reason="websocket session connected",
        session_id=session_id,
        expected_state_version=current_version,
        extra_updates={
            "connected_at": now,
            "last_heartbeat": now,
            "disconnected_at": None,
        },
        transition_metadata={"previous_session_id": current_session},
    )


async def _mark_session_disconnected(
    db,
    *,
    agent_id: str,
    session_id: str,
) -> bool:
    existing = await _ensure_connection_state_fields(
        db,
        agent_id=agent_id,
        actor="system:websocket",
        reason="bootstrap connection durability fields",
    )
    if not existing:
        return False

    current_version = int(existing.get("connection_state_version") or 0)
    return await _transition_connection_state(
        db,
        agent_id=agent_id,
        expected_statuses=["connected"],
        next_status="disconnected",
        actor="system:websocket",
        reason="websocket session disconnected",
        session_id=session_id,
        required_current_session_id=session_id,
        expected_state_version=current_version,
        extra_updates={"disconnected_at": _iso_now()},
    )


async def _record_session_heartbeat(
    db,
    *,
    agent_id: str,
    session_id: str,
) -> bool:
    existing = await _ensure_connection_state_fields(
        db,
        agent_id=agent_id,
        actor="system:websocket",
        reason="bootstrap connection durability fields",
    )
    if not existing:
        return False

    current_version = int(existing.get("connection_state_version") or 0)
    return await _transition_connection_state(
        db,
        agent_id=agent_id,
        expected_statuses=["connected"],
        next_status="connected",
        actor="system:websocket",
        reason="websocket heartbeat",
        session_id=session_id,
        required_current_session_id=session_id,
        expected_state_version=current_version,
        extra_updates={"last_heartbeat": _iso_now()},
    )


def _agent_status_transition_entry(
    from_status: Optional[str],
    to_status: str,
    actor: str,
    reason: str,
    session_id: Optional[str],
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    entry = {
        "timestamp": _iso_now(),
        "from_status": from_status,
        "to_status": to_status,
        "actor": actor,
        "reason": reason,
        "session_id": session_id,
    }
    if metadata:
        entry["metadata"] = metadata
    return entry


async def _ensure_agent_status_state_fields(
    db,
    *,
    agent_id: str,
    actor: str,
    reason: str,
) -> Dict[str, Any]:
    status_doc = await db.agent_status.find_one({"agent_id": agent_id}, {"_id": 0})
    if not status_doc:
        return {}

    if (
        status_doc.get("state_version") is not None
        and status_doc.get("state_transition_log") is not None
    ):
        return status_doc

    current_status = str(status_doc.get("status") or "snapshot").lower().strip()
    if current_status not in AGENT_STATUS_SNAPSHOT_STATUSES:
        current_status = "snapshot"

    bootstrap = {
        "state_version": int(status_doc.get("state_version") or 1),
        "state_transition_log": status_doc.get("state_transition_log")
        or [
            _agent_status_transition_entry(
                from_status=None,
                to_status=current_status,
                actor=actor,
                reason=reason,
                session_id=status_doc.get("last_session_id"),
            )
        ],
        "status": current_status,
        "updated_at": _iso_now(),
    }
    await db.agent_status.update_one({"agent_id": agent_id}, {"$set": bootstrap})
    return await db.agent_status.find_one({"agent_id": agent_id}, {"_id": 0}) or {}


async def _record_agent_status_snapshot(
    db,
    *,
    agent_id: str,
    session_id: str,
    snapshot: Dict[str, Any],
) -> bool:
    now = _iso_now()
    existing = await db.agent_status.find_one({"agent_id": agent_id}, {"_id": 0})
    if not existing:
        bootstrap = {
            "agent_id": agent_id,
            "hostname": snapshot.get("hostname"),
            "os": snapshot.get("os"),
            "ip_address": snapshot.get("ip_address"),
            "security_status": snapshot.get("security_status") or {},
            "last_scan": snapshot.get("last_scan"),
            "last_session_id": session_id,
            "status": "snapshot",
            "updated_at": now,
            "state_version": 1,
            "state_transition_log": [
                _agent_status_transition_entry(
                    from_status=None,
                    to_status="snapshot",
                    actor="system:websocket",
                    reason="initial agent status snapshot",
                    session_id=session_id,
                )
            ],
        }
        await db.agent_status.update_one({"agent_id": agent_id}, {"$set": bootstrap}, upsert=True)
        return True

    existing = await _ensure_agent_status_state_fields(
        db,
        agent_id=agent_id,
        actor="system:websocket",
        reason="bootstrap agent status durability fields",
    )
    if not existing:
        return False

    current_session = existing.get("last_session_id")
    if current_session and current_session != session_id:
        return False

    current_status = str(existing.get("status") or "snapshot").lower().strip()
    if current_status not in AGENT_STATUS_SNAPSHOT_STATUSES:
        return False

    current_version = int(existing.get("state_version") or 0)
    query: Dict[str, Any] = {
        "agent_id": agent_id,
        "status": "snapshot",
    }
    if current_session:
        query["last_session_id"] = session_id
    if current_version <= 0:
        query["$or"] = [{"state_version": {"$exists": False}}, {"state_version": 0}]
    else:
        query["state_version"] = current_version

    result = await db.agent_status.update_one(
        query,
        {
            "$set": {
                "agent_id": agent_id,
                "hostname": snapshot.get("hostname"),
                "os": snapshot.get("os"),
                "ip_address": snapshot.get("ip_address"),
                "security_status": snapshot.get("security_status") or {},
                "last_scan": snapshot.get("last_scan"),
                "last_session_id": session_id,
                "status": "snapshot",
                "updated_at": now,
            },
            "$inc": {"state_version": 1},
            "$push": {
                "state_transition_log": _agent_status_transition_entry(
                    from_status=current_status,
                    to_status="snapshot",
                    actor="system:websocket",
                    reason="agent status snapshot update",
                    session_id=session_id,
                )
            },
        },
    )
    return bool(getattr(result, "modified_count", 0))


class CommandRequest(BaseModel):
    agent_id: str
    command_type: str  # block_ip, kill_process, quarantine_file, remediate, scan, etc.
    parameters: Dict[str, Any]
    priority: str = "medium"  # low, medium, high, critical


class CommandApproval(BaseModel):
    approved: bool
    notes: Optional[str] = None


class AICommandRecommendationRequest(BaseModel):
    objective: str
    agent_id: Optional[str] = None
    context: Dict[str, Any] = {}
    max_recommendations: int = 3


# Command types and their descriptions
COMMAND_TYPES = {
    "block_ip": {
        "name": "Block IP Address",
        "description": "Add IP to local firewall blocklist",
        "parameters": ["ip_address", "duration_hours"],
        "risk_level": "medium"
    },
    "kill_process": {
        "name": "Terminate Process",
        "description": "Kill a running process by PID or name",
        "parameters": ["pid", "process_name"],
        "risk_level": "high"
    },
    "quarantine_file": {
        "name": "Quarantine File",
        "description": "Move suspicious file to quarantine folder",
        "parameters": ["file_path"],
        "risk_level": "medium"
    },
    "delete_file": {
        "name": "Delete File",
        "description": "Permanently delete a malicious file",
        "parameters": ["file_path"],
        "risk_level": "critical"
    },
    "remove_persistence": {
        "name": "Remove Persistence",
        "description": "Remove registry/startup persistence mechanisms",
        "parameters": ["persistence_type", "path"],
        "risk_level": "high"
    },
    "block_user": {
        "name": "Block User Account",
        "description": "Disable a compromised user account",
        "parameters": ["username"],
        "risk_level": "high"
    },
    "collect_forensics": {
        "name": "Collect Forensic Data",
        "description": "Gather logs, memory dump, and artifacts",
        "parameters": ["collection_type"],
        "risk_level": "low"
    },
    "full_scan": {
        "name": "Run Full Security Scan",
        "description": "Execute comprehensive security scan",
        "parameters": ["scan_types"],
        "risk_level": "low"
    },
    "update_agent": {
        "name": "Update Agent",
        "description": "Download and apply agent updates",
        "parameters": [],
        "risk_level": "low"
    },
    "restart_service": {
        "name": "Restart Security Service",
        "description": "Restart the local security monitoring service",
        "parameters": ["service_name"],
        "risk_level": "medium"
    },
    "remediate_compliance": {
        "name": "Remediate Compliance Issue",
        "description": "Fix security compliance violations",
        "parameters": ["issue_type", "remediation_action"],
        "risk_level": "medium"
    },
    "trivy_scan": {
        "name": "Trivy Scan",
        "description": "Run Trivy vulnerability scan on filesystem/image/repository target",
        "parameters": ["mode", "target", "timeout"],
        "risk_level": "low"
    },
    "falco_status": {
        "name": "Falco Status",
        "description": "Collect Falco runtime status and version",
        "parameters": ["timeout"],
        "risk_level": "low"
    },
    "suricata_status": {
        "name": "Suricata Status",
        "description": "Collect Suricata IDS status and version",
        "parameters": ["timeout"],
        "risk_level": "low"
    },
    "volatility_status": {
        "name": "Volatility Status",
        "description": "Check Volatility availability and command health",
        "parameters": ["timeout"],
        "risk_level": "low"
    },
    "volatility_scan": {
        "name": "Volatility Memory Scan",
        "description": "Run Volatility plugin against a supplied memory image",
        "parameters": ["image_path", "plugin", "timeout"],
        "risk_level": "medium"
    }
}


@router.get("/types")
async def get_command_types(current_user: dict = Depends(get_current_user)):
    """Get available command types"""
    return {"command_types": COMMAND_TYPES}


@router.post("/recommend")
async def recommend_commands(
    request: AICommandRecommendationRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Recommend commands using Ollama-assisted reasoning with safe fallbacks."""
    from services.ai_reasoning import ai_reasoning

    allowed_types = list(COMMAND_TYPES.keys())
    objective = request.objective.strip()
    max_items = max(1, min(request.max_recommendations, 5))

    system_prompt = (
        "You are a SOC response planner. Return strict JSON only with schema: "
        "{\"recommended_commands\":[{\"command_type\":str,\"priority\":str,\"parameters\":object,\"rationale\":str}],\"notes\":str}. "
        f"Allowed command_type values: {allowed_types}."
    )
    prompt = (
        f"Objective: {objective}\n"
        f"Agent ID: {request.agent_id or 'unspecified'}\n"
        f"Context: {request.context}\n"
        f"Max recommendations: {max_items}"
    )

    method = "fallback"
    recommendations = []

    try:
        llm_result = await ai_reasoning.ollama_generate(prompt=prompt, system_prompt=system_prompt)
        if "error" not in llm_result:
            raw = (llm_result.get("response") or "").strip()
            # strip code fences if present
            raw = raw.replace("```json", "").replace("```", "").strip()
            parsed = json.loads(raw)
            for item in parsed.get("recommended_commands", []):
                command_type = item.get("command_type")
                if command_type in COMMAND_TYPES:
                    recommendations.append({
                        "command_type": command_type,
                        "priority": item.get("priority", "medium"),
                        "parameters": item.get("parameters", {}),
                        "rationale": item.get("rationale", "AI-recommended")
                    })
            if recommendations:
                method = "ollama"
    except Exception:
        # fall through to rule-based fallback
        pass

    if not recommendations:
        text = objective.lower()
        if "ransom" in text or "encrypt" in text:
            recommendations = [
                {"command_type": "kill_process", "priority": "critical", "parameters": {}, "rationale": "Contain suspected ransomware execution."},
                {"command_type": "collect_forensics", "priority": "high", "parameters": {"collection_type": "memory+logs"}, "rationale": "Preserve evidence before full remediation."}
            ]
        elif "ip" in text or "c2" in text or "beacon" in text:
            recommendations = [
                {"command_type": "block_ip", "priority": "high", "parameters": {}, "rationale": "Disrupt suspicious external communication."},
                {"command_type": "full_scan", "priority": "medium", "parameters": {"scan_types": ["network", "process"]}, "rationale": "Validate scope of compromise."}
            ]
        else:
            recommendations = [
                {"command_type": "full_scan", "priority": "medium", "parameters": {"scan_types": ["process", "file"]}, "rationale": "Baseline containment and verification."}
            ]
        method = "rule_based"

    return {
        "objective": objective,
        "agent_id": request.agent_id,
        "recommended_commands": recommendations[:max_items],
        "method": method
    }


@router.post("/create")
async def create_command(
    request: CommandRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Create a new command for an agent (requires approval)"""
    db = get_db()
    
    if request.command_type not in COMMAND_TYPES:
        raise HTTPException(status_code=400, detail=f"Unknown command type: {request.command_type}")
    
    command_id = str(uuid.uuid4())[:12]
    command = {
        "command_id": command_id,
        "agent_id": request.agent_id,
        "command_type": request.command_type,
        "command_name": COMMAND_TYPES[request.command_type]["name"],
        "parameters": request.parameters,
        "priority": request.priority,
        "risk_level": COMMAND_TYPES[request.command_type]["risk_level"],
        "status": "pending_approval",
        "created_by": current_user.get("email", current_user.get("id")),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "state_version": 1,
        "state_transition_log": [
            _transition_entry(
                from_status=None,
                to_status="pending_approval",
                actor=current_user.get("email", current_user.get("id")) or "unknown",
                reason="command created",
            )
        ],
        "approved_by": None,
        "approved_at": None,
        "executed_at": None,
        "result": None
    }
    polyphonic = get_polyphonic_governance_service()
    envelope = polyphonic.build_action_request_envelope(
        actor_id=str(current_user.get("email", current_user.get("id")) or "unknown"),
        actor_type="user",
        operation="agent_command_create",
        parameters=request.parameters or {},
        tool_name=request.command_type,
        resource_uris=[request.agent_id],
        context_refs={
            "request_id": command_id,
            "session_id": str(current_user.get("session_id") or ""),
        },
        policy_refs=[],
        evidence_hashes=[],
        target_domain="agent_control_zone",
    )
    envelope = polyphonic.attach_voice_profile(
        envelope,
        component_id="agent_commands_router",
        route="/agent-commands/create",
        tool_name=request.command_type,
        component_type="ingress",
    )
    command["polyphonic_context"] = polyphonic.serialize_polyphonic_context(envelope)
    
    dispatch = GovernedDispatchService(db)
    action_type = "cross_sector_hardening" if request.command_type in {"remediate_compliance", "remove_persistence"} else "agent_command"
    queued = await dispatch.queue_gated_agent_command(
        action_type=action_type,
        actor=current_user.get("email", current_user.get("id", "unknown")),
        agent_id=request.agent_id,
        command_doc=command,
        impact_level="critical" if command["risk_level"] in {"high", "critical"} else "high",
        entity_refs=[request.agent_id, command_id],
        requires_triune=True,
        route="/agent-commands/create",
        component_id="agent_commands_router",
    )
    gated = queued.get("queued", {})
    command = queued.get("command", command)

    pending_commands[command_id] = command.copy()
    await emit_world_event(
        db,
        event_type="agent_command_created",
        trigger_triune=True,
        entity_refs=[request.agent_id, command_id],
        payload={
            "command_type": request.command_type,
            "priority": request.priority,
            "queue_id": gated.get("queue_id"),
            "decision_id": gated.get("decision_id"),
            "polyphonic_context": command.get("polyphonic_context"),
            "voice_type": ((command.get("polyphonic_context") or {}).get("voice_profile") or {}).get("voice_type"),
            "capability_class": ((command.get("polyphonic_context") or {}).get("voice_profile") or {}).get("capability_class"),
        },
    )
    
    # Remove MongoDB _id before returning
    command.pop("_id", None)
    return {"command_id": command_id, "status": "gated_pending_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id"), "command": command}


@router.get("/pending")
async def get_pending_commands(current_user: dict = Depends(get_current_user)):
    """Get all commands pending approval"""
    db = get_db()
    commands = await db.agent_commands.find(
        {"status": {"$in": ["pending_approval", "gated_pending_approval"]}},
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    
    return {"commands": commands, "count": len(commands)}


@router.post("/{command_id}/approve")
async def approve_command(
    command_id: str,
    approval: CommandApproval,
    current_user: dict = Depends(check_permission("write"))
):
    """Approve or reject a pending command"""
    db = get_db()

    command = await _ensure_command_state_fields(
        db,
        command_id=command_id,
        actor=current_user.get("email", current_user.get("id")) or "unknown",
        reason="bootstrap legacy command durability fields",
    )
    if not command:
        raise HTTPException(status_code=404, detail="Command not found")

    if command["status"] not in {"pending_approval", "gated_pending_approval"}:
        raise HTTPException(status_code=400, detail=f"Command already {command['status']}")

    new_status = "approved" if approval.approved else "rejected"

    current_version = int(command.get("state_version") or 0)
    approved_by = current_user.get("email", current_user.get("id"))
    transitioned = await _guarded_command_transition(
        db,
        command_id=command_id,
        expected_statuses=["pending_approval", "gated_pending_approval"],
        next_status=new_status,
        actor=approved_by or "unknown",
        reason="manual command approval decision",
        expected_state_version=current_version,
        extra_updates={
            "approved_by": approved_by,
            "approved_at": _iso_now(),
            "approval_notes": approval.notes,
            "polyphonic_context": command.get("polyphonic_context") or {},
        },
        transition_metadata={"approved": bool(approval.approved)},
    )
    if not transitioned:
        raise HTTPException(status_code=409, detail="Command approval conflict; state changed concurrently")

    decision_id = command.get("decision_id") or (command.get("gate") or {}).get("decision_id")
    if not decision_id and approval.approved:
        # Legacy compatibility: bootstrap ungated commands into the canonical gate.
        gate = OutboundGateService(db)
        actor = approved_by or "unknown"
        action_type = (
            "cross_sector_hardening"
            if command.get("command_type") in {"remediate_compliance", "remove_persistence"}
            else "agent_command"
        )
        gated = await gate.gate_action(
            action_type=action_type,
            actor=actor,
            payload=command,
            impact_level="critical" if str(command.get("risk_level", "")).lower() in {"high", "critical"} else "high",
            subject_id=command.get("agent_id"),
            entity_refs=[command.get("agent_id"), command_id],
            requires_triune=True,
            polyphonic_context=command.get("polyphonic_context") or {},
        )
        await db.agent_commands.update_one(
            {"command_id": command_id},
            {
                "$set": {
                    "decision_id": gated.get("decision_id"),
                    "queue_id": gated.get("queue_id"),
                    "gate": {
                        "queue_id": gated.get("queue_id"),
                        "decision_id": gated.get("decision_id"),
                        "action_id": gated.get("action_id"),
                    },
                    "updated_at": _iso_now(),
                }
            },
        )
        decision_id = gated.get("decision_id")

    actor = approved_by or "unknown"
    authority = GovernanceDecisionAuthority(db)
    execution_summary = None
    if decision_id:
        if approval.approved:
            await authority.approve_decision(
                decision_id=decision_id,
                actor=actor,
                notes=approval.notes,
                execution_status="pending_executor",
                source="agent_commands_manual_approval",
            )
            execution_summary = await GovernanceExecutorService(db).process_approved_decisions(limit=100)
        else:
            await authority.deny_decision(
                decision_id=decision_id,
                actor=actor,
                reason=approval.notes,
                source="agent_commands_manual_approval",
            )
        await db.triune_decisions.update_one(
            {"decision_id": decision_id},
            {"$set": {"manual_override": True, "manual_override_actor": actor}},
        )

    await emit_world_event(
        db,
        event_type="agent_command_approval_decision",
        trigger_triune=False,
        entity_refs=[command.get("agent_id"), command_id],
        payload={
            "approved": bool(approval.approved),
            "notes": approval.notes,
            "actor": current_user.get("email", current_user.get("id")),
            "polyphonic_context": command.get("polyphonic_context") or {},
            "voice_type": ((command.get("polyphonic_context") or {}).get("voice_profile") or {}).get("voice_type"),
            "capability_class": ((command.get("polyphonic_context") or {}).get("voice_profile") or {}).get("capability_class"),
        },
    )
    
    return {
        "command_id": command_id,
        "status": new_status,
        "decision_id": decision_id,
        "execution_summary": execution_summary,
        "message": "Command decision recorded through canonical governance authority",
    }


@router.get("/history")
async def get_command_history(
    agent_id: Optional[str] = None,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get command execution history"""
    db = get_db()
    
    query = {}
    if agent_id:
        query["agent_id"] = agent_id
    
    commands = await db.agent_commands.find(query, {"_id": 0}).sort("created_at", -1).to_list(limit)
    
    return {"commands": commands, "count": len(commands)}


@router.post("/{command_id}/result")
async def report_command_result(
    command_id: str,
    result: Dict[str, Any],
    machine_auth: Optional[dict] = Depends(verify_agent_result_machine_token),
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """Agent reports command execution result"""
    db = get_db()
    actor = None
    if current_user is not None and has_permission(current_user, "write"):
        actor = current_user.get("email", current_user.get("id")) or "unknown"
    elif machine_auth is not None:
        actor = "agent:machine-token"
    else:
        if current_user is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        raise HTTPException(status_code=403, detail="Permission denied. Required: write or machine token")

    command = await _ensure_command_state_fields(
        db,
        command_id=command_id,
        actor=actor,
        reason="bootstrap legacy command durability fields",
    )
    if not command:
        raise HTTPException(status_code=404, detail="Command not found")

    status = str(command.get("status") or "").lower().strip()
    if status in COMMAND_TERMINAL_STATUSES:
        raise HTTPException(status_code=409, detail=f"Command already terminal (status={status})")

    next_status = "completed" if result.get("success") else "failed"
    current_version = int(command.get("state_version") or 0)
    updated_polyphonic_context = _build_result_stage_harmonic_context(
        db=db,
        command=command,
        result_success=bool(result.get("success")),
        stage="command_result_reported",
    )
    transitioned = await _guarded_command_transition(
        db,
        command_id=command_id,
        expected_statuses=["approved", "queued_for_pickup", "pending", "delivered", "sent_to_agent", "deploying", "running", "in_progress"],
        next_status=next_status,
        actor=actor or "agent:reported-result",
        reason="command result reported",
        expected_state_version=current_version,
        extra_updates={
            "executed_at": _iso_now(),
            "result": result,
            "polyphonic_context": updated_polyphonic_context,
        },
    )
    if not transitioned:
        raise HTTPException(status_code=409, detail="Command result conflict; state changed concurrently")
    
    command_results[command_id] = result
    notation_service = get_notation_token_service(db)
    notation_token_id = (
        (command.get("polyphonic_context") or {}).get("notation_token_id")
        or command.get("notation_token_id")
    )
    if notation_token_id:
        await notation_service.consume_notation_token(
            str(notation_token_id),
            outcome="completed" if bool(result.get("success")) else "failed",
        )
    await emit_world_event(
        db,
        event_type="agent_command_result_recorded",
        trigger_triune=False,
        entity_refs=[command.get("agent_id"), command_id],
        payload={
            "success": bool(result.get("success")),
            "result": result,
            "polyphonic_context": updated_polyphonic_context,
            "voice_type": ((updated_polyphonic_context.get("voice_profile") or {}).get("voice_type")),
            "capability_class": ((updated_polyphonic_context.get("voice_profile") or {}).get("capability_class")),
        },
    )

    return {"status": "recorded"}


@router.get("/agents/connected")
async def get_connected_agents(current_user: dict = Depends(get_current_user)):
    """Get list of currently connected agents"""
    return {
        "agents": list(connected_agents.keys()),
        "count": len(connected_agents)
    }


@router.websocket("/ws/{agent_id}")
async def agent_websocket(websocket: WebSocket, agent_id: str):
    """WebSocket connection for agent bi-directional communication"""
    verify_websocket_machine_token(
        websocket,
        env_keys=["SWARM_AGENT_TOKEN", "INTEGRATION_API_KEY", "AGENT_COMMANDS_WS_TOKEN"],
        header_names=["x-agent-token", "x-internal-token"],
        subject="agent commands websocket",
    )
    await websocket.accept()
    connection_session_id = str(uuid.uuid4())[:12]
    connected_agents[agent_id] = websocket
    
    db = get_db()

    registered = await _register_connected_session(
        db,
        agent_id=agent_id,
        session_id=connection_session_id,
    )
    if not registered:
        logger.warning("Connection registration conflict for agent %s; proceeding with in-memory session", agent_id)
    
    try:
        # Send any pending commands ready for delivery.
        pending = await db.agent_commands.find({
            "agent_id": agent_id,
            "status": {"$in": ["pending", "approved", "queued_for_pickup"]}
        }, {"_id": 0}).to_list(100)
        
        for cmd in pending:
            await websocket.send_json({
                "type": "command",
                "command_id": cmd["command_id"],
                "command_type": cmd["command_type"],
                "parameters": cmd["parameters"]
            })
            await _guarded_command_transition(
                db,
                command_id=cmd["command_id"],
                    expected_statuses=["pending", "approved", "queued_for_pickup"],
                next_status="sent_to_agent",
                actor="system:websocket-delivery",
                reason="command delivered on websocket connect",
                expected_state_version=int(cmd.get("state_version") or 0),
            )
        
        # Listen for messages from agent
        while True:
            data = await websocket.receive_json()
            
            if data.get("type") == "heartbeat":
                updated = await _record_session_heartbeat(
                    db,
                    agent_id=agent_id,
                    session_id=connection_session_id,
                )
                if not updated:
                    logger.debug(
                        "Skipped heartbeat transition for agent %s session %s (stale or already transitioned)",
                        agent_id,
                        connection_session_id,
                    )
            
            elif data.get("type") == "scan_result":
                # Agent sending scan results
                await db.agent_scan_results.insert_one({
                    "agent_id": agent_id,
                    "scan_type": data.get("scan_type"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "results": data.get("results", {})
                })
            
            elif data.get("type") == "alert":
                # Agent reporting an alert
                await db.agent_alerts.insert_one({
                    "agent_id": agent_id,
                    "alert_type": data.get("alert_type"),
                    "severity": data.get("severity", "medium"),
                    "message": data.get("message"),
                    "details": data.get("details", {}),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            
            elif data.get("type") == "command_result":
                # Agent reporting command execution result
                command_id = data.get("command_id")
                command = await _ensure_command_state_fields(
                    db,
                    command_id=command_id,
                    actor=f"agent:{agent_id}",
                    reason="bootstrap legacy command durability fields",
                )
                if command:
                    status = str(command.get("status") or "").lower().strip()
                    if status not in COMMAND_TERMINAL_STATUSES:
                        updated_polyphonic_context = _build_result_stage_harmonic_context(
                            db=db,
                            command=command,
                            result_success=bool(data.get("success")),
                            stage="command_result_websocket",
                        )
                        await _guarded_command_transition(
                            db,
                            command_id=command_id,
                            expected_statuses=["pending", "delivered", "approved", "queued_for_pickup", "sent_to_agent", "deploying", "running", "in_progress"],
                            next_status="completed" if data.get("success") else "failed",
                            actor=f"agent:{agent_id}",
                            reason="command result received via websocket",
                            expected_state_version=int(command.get("state_version") or 0),
                            extra_updates={
                                "executed_at": _iso_now(),
                                "result": data.get("result", {}),
                                "polyphonic_context": updated_polyphonic_context,
                            },
                        )
                        notation_service = get_notation_token_service(db)
                        notation_token_id = (
                            (command.get("polyphonic_context") or {}).get("notation_token_id")
                            or command.get("notation_token_id")
                        )
                        if notation_token_id:
                            await notation_service.consume_notation_token(
                                str(notation_token_id),
                                outcome="completed" if data.get("success") else "failed",
                            )
            
            elif data.get("type") == "status_update":
                # Agent sending status update
                updated = await _record_agent_status_snapshot(
                    db,
                    agent_id=agent_id,
                    session_id=connection_session_id,
                    snapshot={
                        "hostname": data.get("hostname"),
                        "os": data.get("os"),
                        "ip_address": data.get("ip_address"),
                        "security_status": data.get("security_status", {}),
                        "last_scan": data.get("last_scan"),
                    },
                )
                if not updated:
                    logger.debug(
                        "Skipped status snapshot for agent %s session %s (stale or conflict)",
                        agent_id,
                        connection_session_id,
                    )
                
    except WebSocketDisconnect:
        pass
    finally:
        if connected_agents.get(agent_id) is websocket:
            del connected_agents[agent_id]
        disconnected = await _mark_session_disconnected(
            db,
            agent_id=agent_id,
            session_id=connection_session_id,
        )
        if not disconnected:
            logger.debug(
                "Skipped disconnect transition for agent %s session %s (stale or already transitioned)",
                agent_id,
                connection_session_id,
            )


@router.get("/agents/status")
async def get_all_agent_status(current_user: dict = Depends(get_current_user)):
    """Get status of all registered agents"""
    db = get_db()
    
    agents = await db.agent_status.find({}, {"_id": 0}).to_list(100)
    connected = await db.connected_agents.find({}, {"_id": 0}).to_list(100)
    
    # Merge status
    connected_map = {a["agent_id"]: a for a in connected}
    for agent in agents:
        conn_info = connected_map.get(agent["agent_id"], {})
        agent["connected"] = conn_info.get("status") == "connected"
        agent["last_heartbeat"] = conn_info.get("last_heartbeat")
    
    return {"agents": agents, "count": len(agents)}


@router.get("/agents/{agent_id}/alerts")
async def get_agent_alerts(
    agent_id: str,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get alerts from a specific agent"""
    db = get_db()
    alerts = await db.agent_alerts.find(
        {"agent_id": agent_id},
        {"_id": 0}
    ).sort("timestamp", -1).to_list(limit)
    
    return {"alerts": alerts, "count": len(alerts)}


@router.get("/agents/{agent_id}/scan-results")
async def get_agent_scan_results(
    agent_id: str,
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    """Get scan results from a specific agent"""
    db = get_db()
    results = await db.agent_scan_results.find(
        {"agent_id": agent_id},
        {"_id": 0}
    ).sort("timestamp", -1).to_list(limit)
    
    return {"results": results, "count": len(results)}
