"""
Arda Fabric Router
==================
Exposes the Arda Fabric peer mesh and WireGuard transport verification layer.
Endpoints:
  GET  /api/fabric/peers              — list all known fabric peers
  POST /api/fabric/handshake/initiate — initiate TPM handshake with remote peer
  POST /api/fabric/handshake/verify   — verify handshake response
  GET  /api/fabric/peer/{node_id}     — get peer state and influence budget
  GET  /api/fabric/local-node         — get local node identity
  POST /api/fabric/summons            — broadcast sovereign summons across mesh
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Any, Dict, Optional

from .dependencies import get_current_user, check_permission

router = APIRouter(prefix="/fabric", tags=["Arda Fabric"])


class HandshakeInitRequest(BaseModel):
    remote_node_id: str


class HandshakeVerifyRequest(BaseModel):
    session_id: str
    secret_fire_packet: Dict[str, Any]


class SummonsRequest(BaseModel):
    payload: Dict[str, Any]


@router.get("/peers")
async def list_peers(current_user: dict = Depends(get_current_user)):
    """List all peers known to the Arda Fabric engine."""
    try:
        from services.arda_fabric import get_arda_fabric
        fabric = get_arda_fabric()
        peers = []
        for node_id, peer in fabric.known_peers.items():
            budget = peer.get("influence_budget")
            peers.append({
                "node_id": node_id,
                "wg_pubkey": peer.get("wg_pubkey", ""),
                "last_handshake": peer.get("last_handshake"),
                "is_peer_verified": peer.get("is_peer_verified", False),
                "constitutional_state": getattr(budget, "constitutional_state", "unknown") if budget else "unknown",
                "network_trust": getattr(budget, "network_trust", 0.0) if budget else 0.0,
            })
        return {"peers": peers, "count": len(peers)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/local-node")
async def get_local_node(current_user: dict = Depends(get_current_user)):
    """Get the local node's sovereign identity."""
    try:
        from services.arda_fabric import get_arda_fabric
        fabric = get_arda_fabric()
        node_id = await fabric.get_local_node_id()
        return {"node_id": node_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/handshake/initiate")
async def initiate_handshake(
    req: HandshakeInitRequest,
    current_user: dict = Depends(check_permission("write")),
):
    """Initiate a TPM-attested handshake with a remote peer."""
    try:
        from services.arda_fabric import get_arda_fabric
        fabric = get_arda_fabric()
        session_id = await fabric.initiate_handshake(req.remote_node_id)
        return {"session_id": session_id, "remote_node_id": req.remote_node_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/handshake/verify")
async def verify_handshake(
    req: HandshakeVerifyRequest,
    current_user: dict = Depends(check_permission("write")),
):
    """Verify a peer's handshake response (TPM quote + secret fire packet)."""
    try:
        from services.arda_fabric import get_arda_fabric
        fabric = get_arda_fabric()
        verified = await fabric.verify_handshake(req.session_id, req.secret_fire_packet)
        return {"verified": verified, "session_id": req.session_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/peer/{node_id}")
async def get_peer(node_id: str, current_user: dict = Depends(get_current_user)):
    """Get a specific peer's state and influence budget."""
    try:
        from services.arda_fabric import get_arda_fabric
        fabric = get_arda_fabric()
        peer = fabric.known_peers.get(node_id)
        if not peer:
            raise HTTPException(status_code=404, detail=f"Peer {node_id} not found")
        budget = peer.get("influence_budget")
        return {
            "node_id": node_id,
            "peer": {k: v for k, v in peer.items() if k != "influence_budget"},
            "constitutional_state": budget.model_dump() if hasattr(budget, "model_dump") else vars(budget) if budget else None,
            "transport_verified": peer.get("is_peer_verified", False),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/transport-lock/{node_id}")
async def check_transport_lock(node_id: str, current_user: dict = Depends(get_current_user)):
    """Check whether a peer has a verified WireGuard transport lock."""
    try:
        from services.outbound_gate import OutboundGateService
        gate = OutboundGateService(db=None)
        locked = gate.verify_transport_lock(node_id)
        return {"node_id": node_id, "transport_locked": locked}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/summons")
async def broadcast_summons(
    req: SummonsRequest,
    current_user: dict = Depends(check_permission("manage_users")),
):
    """Broadcast a sovereign summons across the fabric mesh."""
    try:
        from services.arda_fabric import get_arda_fabric
        fabric = get_arda_fabric()
        await fabric.broadcast_sovereign_summons(req.payload)
        return {"status": "dispatched"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
