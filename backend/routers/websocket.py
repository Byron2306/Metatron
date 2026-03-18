"""
WebSocket Router - Real-time communication management
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any

from .dependencies import get_current_user, check_permission, get_db
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
try:
    from services.outbound_gate import OutboundGateService
except Exception:
    from backend.services.outbound_gate import OutboundGateService

# Import websocket services
from websocket_service import realtime_ws, WSMessageType, WSMessage

router = APIRouter(prefix="/websocket", tags=["WebSocket"])

@router.get("/stats")
async def get_websocket_stats(current_user: dict = Depends(get_current_user)):
    """Get WebSocket connection statistics"""
    return realtime_ws.get_stats()

@router.get("/agents")
async def get_connected_agents(current_user: dict = Depends(get_current_user)):
    """Get list of connected agents"""
    return realtime_ws.get_connected_agents()

@router.post("/command/{agent_id}")
async def send_command_to_agent(
    agent_id: str,
    command: Dict[str, Any],
    current_user: dict = Depends(check_permission("write")),
):
    """Queue a WebSocket command through mandatory outbound governance."""
    db = get_db()
    gate = OutboundGateService(db)
    actor = (current_user or {}).get("email") or (current_user or {}).get("id") or "unknown"
    gated = await gate.gate_action(
        action_type="agent_command",
        actor=actor,
        payload={
            "agent_id": agent_id,
            "command": command.get("command"),
            "params": command.get("params", {}),
            "transport": "websocket",
        },
        impact_level="high",
        subject_id=agent_id,
        entity_refs=[agent_id, str(command.get("command") or "")],
        requires_triune=True,
    )
    await emit_world_event(
        db,
        event_type="websocket_command_gated",
        entity_refs=[agent_id, gated.get("queue_id"), gated.get("decision_id")],
        payload={"command": command.get("command"), "actor": actor},
        trigger_triune=True,
    )
    return {
        "message": "Command queued for triune approval",
        "status": "queued_for_triune_approval",
        "agent_id": agent_id,
        "command": command.get("command"),
        "queue_id": gated.get("queue_id"),
        "decision_id": gated.get("decision_id"),
    }

@router.post("/scan/{agent_id}")
async def request_agent_scan(
    agent_id: str,
    scan_type: str = "full",
    current_user: dict = Depends(check_permission("write")),
):
    """Queue scan request through mandatory outbound governance."""
    db = get_db()
    gate = OutboundGateService(db)
    actor = (current_user or {}).get("email") or (current_user or {}).get("id") or "unknown"
    gated = await gate.gate_action(
        action_type="tool_execution",
        actor=actor,
        payload={
            "agent_id": agent_id,
            "command": "scan",
            "scan_type": scan_type,
            "transport": "websocket",
        },
        impact_level="high",
        subject_id=agent_id,
        entity_refs=[agent_id, scan_type],
        requires_triune=True,
    )
    await emit_world_event(
        db,
        event_type="websocket_scan_gated",
        entity_refs=[agent_id, gated.get("queue_id"), gated.get("decision_id")],
        payload={"scan_type": scan_type, "actor": actor},
        trigger_triune=True,
    )
    return {
        "message": "Scan request queued for triune approval",
        "status": "queued_for_triune_approval",
        "agent_id": agent_id,
        "scan_type": scan_type,
        "queue_id": gated.get("queue_id"),
        "decision_id": gated.get("decision_id"),
    }
