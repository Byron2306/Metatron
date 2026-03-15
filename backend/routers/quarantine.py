"""
Quarantine Router
"""
from fastapi import APIRouter, HTTPException, Depends
from dataclasses import asdict

from .dependencies import get_current_user, get_db
try:
    from services.outbound_gate import OutboundGateService
except Exception:
    from backend.services.outbound_gate import OutboundGateService
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event

# Import quarantine service
from quarantine import (
    get_quarantine_summary, list_quarantined,
    get_quarantine_entry
)

router = APIRouter(prefix="/quarantine", tags=["Quarantine"])

@router.get("")
async def get_quarantine_list(current_user: dict = Depends(get_current_user)):
    """Get all quarantined files"""
    # list_quarantined is sync, not async
    entries = list_quarantined()
    # Convert dataclass entries to dicts
    return [asdict(e) for e in entries]

@router.get("/summary")
async def get_summary(current_user: dict = Depends(get_current_user)):
    """Get quarantine summary stats"""
    # get_quarantine_summary is sync, not async
    summary = get_quarantine_summary()
    return {
        "total_files": summary.get("total_entries", 0),
        "total_size": summary.get("storage", {}).get("total_size_bytes", 0),
        "by_status": summary.get("by_status", {}),
        "by_threat_type": summary.get("by_threat_type", {}),
        "storage": summary.get("storage", {})
    }

@router.get("/{entry_id}")
async def get_entry(entry_id: str, current_user: dict = Depends(get_current_user)):
    """Get specific quarantine entry"""
    # get_quarantine_entry is sync, not async
    entry = get_quarantine_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    return asdict(entry)

@router.post("/{entry_id}/restore")
async def restore_entry(entry_id: str, current_user: dict = Depends(get_current_user)):
    """Queue quarantine restore via mandatory outbound gate."""
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="quarantine_restore",
        actor=(current_user or {}).get("id", "unknown"),
        payload={"entry_id": entry_id},
        impact_level="high",
        subject_id=entry_id,
        entity_refs=[entry_id],
        requires_triune=True,
    )
    await emit_world_event(get_db(), event_type="quarantine_entry_restore_gated", entity_refs=[entry_id], payload={"actor": (current_user or {}).get("id"), "queue_id": gated.get("queue_id")}, trigger_triune=True)
    return {"success": True, "status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id"), "message": "Restore queued for approval"}


@router.delete("/{entry_id}")
async def delete_entry(entry_id: str, current_user: dict = Depends(get_current_user)):
    """Queue quarantine delete via mandatory outbound gate."""
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="quarantine_delete",
        actor=(current_user or {}).get("id", "unknown"),
        payload={"entry_id": entry_id},
        impact_level="critical",
        subject_id=entry_id,
        entity_refs=[entry_id],
        requires_triune=True,
    )
    await emit_world_event(get_db(), event_type="quarantine_entry_delete_gated", entity_refs=[entry_id], payload={"actor": (current_user or {}).get("id"), "queue_id": gated.get("queue_id")}, trigger_triune=True)
    return {"success": True, "status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id"), "message": "Delete queued for approval"}
