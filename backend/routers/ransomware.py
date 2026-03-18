"""
Ransomware Protection Router
Enhanced with deception engine integration for campaign tracking
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional, List
from pydantic import BaseModel

from .dependencies import get_current_user, check_permission, get_db
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event

# Import ransomware protection service
from ransomware_protection import ransomware_protection, RansomwareProtectionManager

router = APIRouter(prefix="/ransomware", tags=["Ransomware Protection"])

# Lazy loader for deception engine to avoid circular imports
_deception_engine = None
def get_deception_engine():
    global _deception_engine
    if _deception_engine is None:
        try:
            from deception_engine import deception_engine
            _deception_engine = deception_engine
        except ImportError:
            pass
    return _deception_engine

class DeployCanariesRequest(BaseModel):
    directories: Optional[List[str]] = None

class ProtectedFolderRequest(BaseModel):
    path: str
    allowed_processes: Optional[List[str]] = None

@router.get("/status")
async def get_ransomware_status(current_user: dict = Depends(get_current_user)):
    """Get ransomware protection status"""
    return ransomware_protection.get_status()

@router.post("/start")
async def start_protection(current_user: dict = Depends(check_permission("write"))):
    """Start ransomware protection"""
    ransomware_protection.start_protection()
    await emit_world_event(get_db(), event_type="ransomware_protection_started", entity_refs=[], payload={"actor": current_user.get("id")}, trigger_triune=False)
    return {"message": "Ransomware protection started", "status": ransomware_protection.get_status()}

@router.post("/stop")
async def stop_protection(current_user: dict = Depends(check_permission("write"))):
    """Stop ransomware protection"""
    ransomware_protection.stop_protection()
    await emit_world_event(get_db(), event_type="ransomware_protection_stopped", entity_refs=[], payload={"actor": current_user.get("id")}, trigger_triune=False)
    return {"message": "Ransomware protection stopped"}

@router.post("/canaries/deploy")
async def deploy_canaries(request: DeployCanariesRequest, current_user: dict = Depends(check_permission("write"))):
    """Deploy canary files to detect ransomware"""
    canaries = ransomware_protection.deploy_canaries(request.directories)
    await emit_world_event(get_db(), event_type="ransomware_canaries_deployed", entity_refs=canaries[:10], payload={"count": len(canaries), "actor": current_user.get("id")}, trigger_triune=False)
    return {
        "message": f"Deployed {len(canaries)} canary files",
        "canaries": canaries
    }

@router.get("/canaries")
async def get_canaries(current_user: dict = Depends(get_current_user)):
    """Get deployed canary files"""
    status = ransomware_protection.canary_manager.get_status()
    return status

@router.post("/canaries/check")
async def check_canaries(current_user: dict = Depends(get_current_user)):
    """Manually check canary files for modifications - notifies deception engine on triggers"""
    from dataclasses import asdict
    triggered = ransomware_protection.canary_manager.check_canaries()
    
    # Notify deception engine for each triggered canary
    deception = get_deception_engine()
    campaign_tracking = []
    if deception and triggered:
        import logging
        logger = logging.getLogger(__name__)
        for canary in triggered:
            try:
                # Record as decoy interaction - canary is a type of decoy
                assessment = await deception.record_decoy_interaction(
                    ip="local",  # Canary triggers are local process-based
                    decoy_type="canary",
                    decoy_id=canary.path,
                    headers={"canary_path": canary.path, "triggered_at": str(canary.last_check)}
                )
                campaign_tracking.append({
                    "canary_path": canary.path,
                    "campaign_id": assessment.campaign_id,
                    "escalation_level": assessment.escalation_level.value,
                    "risk_score": assessment.score
                })
            except Exception as e:
                logger.warning(f"Deception engine notification failed for canary {canary.path}: {e}")
    
    await emit_world_event(get_db(), event_type="ransomware_canaries_checked", entity_refs=[c.path for c in triggered[:10]], payload={"triggered_count": len(triggered), "actor": current_user.get("id")}, trigger_triune=False)
    return {
        "triggered_count": len(triggered),
        "triggered": [asdict(c) for c in triggered],
        "campaign_tracking": campaign_tracking if campaign_tracking else None
    }

@router.get("/protected-folders")
async def get_protected_folders(current_user: dict = Depends(get_current_user)):
    """Get protected folders list"""
    return ransomware_protection.get_protected_folders()

@router.post("/protected-folders")
async def add_protected_folder(request: ProtectedFolderRequest, current_user: dict = Depends(check_permission("write"))):
    """Add a folder to ransomware protection"""
    folder = ransomware_protection.add_protected_folder(request.path, request.allowed_processes)
    await emit_world_event(get_db(), event_type="ransomware_protected_folder_added", entity_refs=[request.path], payload={"actor": current_user.get("id")}, trigger_triune=False)
    return {"message": "Folder protected", "folder": folder}

@router.delete("/protected-folders")
async def remove_protected_folder(path: str, current_user: dict = Depends(check_permission("write"))):
    """Remove a folder from protection"""
    success = ransomware_protection.folder_manager.remove_protected_folder(path)
    if not success:
        raise HTTPException(status_code=404, detail="Folder not found")
    await emit_world_event(get_db(), event_type="ransomware_protected_folder_removed", entity_refs=[path], payload={"actor": current_user.get("id")}, trigger_triune=False)
    return {"message": "Folder removed from protection"}

@router.get("/behavioral/stats")
async def get_behavioral_stats(current_user: dict = Depends(get_current_user)):
    """Get behavioral detection statistics"""
    return ransomware_protection.behavior_detector.get_stats()
