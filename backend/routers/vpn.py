"""
VPN Integration Router
"""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import PlainTextResponse
from typing import Optional
from pydantic import BaseModel

from .dependencies import get_current_user, check_permission, get_db
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
try:
    from services.outbound_gate import OutboundGateService
except Exception:
    from backend.services.outbound_gate import OutboundGateService

# Import VPN service
from vpn_integration import vpn_manager, VPNManager

router = APIRouter(prefix="/vpn", tags=["VPN"])

class AddPeerRequest(BaseModel):
    name: str


async def _queue_vpn_governed_action(
    *,
    action_type: str,
    actor: str,
    payload: dict,
    subject_id: Optional[str] = None,
    impact_level: str = "critical",
) -> dict:
    db = get_db()
    gate = OutboundGateService(db)
    refs = [subject_id] if subject_id else []
    gated = await gate.gate_action(
        action_type=action_type,
        actor=actor,
        payload=payload,
        impact_level=impact_level,
        subject_id=subject_id,
        entity_refs=refs,
        requires_triune=True,
    )
    await emit_world_event(
        db,
        event_type="vpn_action_gated",
        entity_refs=refs + [gated.get("queue_id"), gated.get("decision_id")],
        payload={"action_type": action_type, "actor": actor},
        trigger_triune=True,
    )
    return gated

@router.get("/status")
async def get_vpn_status(current_user: dict = Depends(get_current_user)):
    """Get VPN server status"""
    status = await vpn_manager.get_status()
    
    # Add server public key for display
    if vpn_manager.server.server_config:
        status["server"]["public_key"] = vpn_manager.server.server_config.public_key
    
    return status

@router.post("/initialize")
async def initialize_vpn(current_user: dict = Depends(check_permission("write"))):
    """Queue VPN initialization through outbound governance."""
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gated = await _queue_vpn_governed_action(
        action_type="vpn_initialize",
        actor=actor,
        payload={"operation": "initialize"},
        impact_level="high",
    )
    return {"status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}

@router.post("/start")
async def start_vpn(current_user: dict = Depends(check_permission("write"))):
    """Queue VPN start through outbound governance."""
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gated = await _queue_vpn_governed_action(
        action_type="vpn_start",
        actor=actor,
        payload={"operation": "start"},
        impact_level="critical",
    )
    return {"status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}

@router.post("/stop")
async def stop_vpn(current_user: dict = Depends(check_permission("write"))):
    """Queue VPN stop through outbound governance."""
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gated = await _queue_vpn_governed_action(
        action_type="vpn_stop",
        actor=actor,
        payload={"operation": "stop"},
        impact_level="critical",
    )
    return {"status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}

@router.get("/peers")
async def get_peers(current_user: dict = Depends(get_current_user)):
    """Get all VPN peers"""
    peers = vpn_manager.get_peers()
    return {"peers": peers, "count": len(peers)}

@router.post("/peers")
async def add_peer(request: AddPeerRequest, current_user: dict = Depends(check_permission("write"))):
    """Queue VPN peer creation through outbound governance."""
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gated = await _queue_vpn_governed_action(
        action_type="vpn_peer_add",
        actor=actor,
        payload={"peer_name": request.name},
        subject_id=request.name,
        impact_level="high",
    )
    return {
        "status": "queued_for_triune_approval",
        "peer_name": request.name,
        "queue_id": gated.get("queue_id"),
        "decision_id": gated.get("decision_id"),
    }

@router.get("/peers/{peer_id}/config")
async def get_peer_config(peer_id: str, current_user: dict = Depends(get_current_user)):
    """Get WireGuard configuration file for a peer"""
    config = vpn_manager.get_peer_config(peer_id)
    if not config:
        raise HTTPException(status_code=404, detail="Peer not found")
    return PlainTextResponse(content=config, media_type="text/plain")

@router.delete("/peers/{peer_id}")
async def remove_peer(peer_id: str, current_user: dict = Depends(check_permission("write"))):
    """Queue VPN peer removal through outbound governance."""
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gated = await _queue_vpn_governed_action(
        action_type="vpn_peer_remove",
        actor=actor,
        payload={"peer_id": peer_id},
        subject_id=peer_id,
        impact_level="critical",
    )
    return {
        "status": "queued_for_triune_approval",
        "peer_id": peer_id,
        "queue_id": gated.get("queue_id"),
        "decision_id": gated.get("decision_id"),
    }

@router.get("/kill-switch")
async def get_kill_switch_status(current_user: dict = Depends(get_current_user)):
    """Get kill switch status"""
    return vpn_manager.kill_switch.get_status()

@router.post("/kill-switch/enable")
async def enable_kill_switch(current_user: dict = Depends(check_permission("manage_users"))):
    """Queue kill switch enable through outbound governance."""
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gated = await _queue_vpn_governed_action(
        action_type="vpn_kill_switch_enable",
        actor=actor,
        payload={"operation": "kill_switch_enable"},
        impact_level="critical",
    )
    return {"status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}

@router.post("/kill-switch/disable")
async def disable_kill_switch(current_user: dict = Depends(check_permission("manage_users"))):
    """Queue kill switch disable through outbound governance."""
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gated = await _queue_vpn_governed_action(
        action_type="vpn_kill_switch_disable",
        actor=actor,
        payload={"operation": "kill_switch_disable"},
        impact_level="critical",
    )
    return {"status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}
