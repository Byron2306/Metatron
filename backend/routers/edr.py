"""
EDR (Endpoint Detection & Response) Router
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional
from pydantic import BaseModel

from .dependencies import get_current_user, check_permission, get_db
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
try:
    from services.telemetry_chain import tamper_evident_telemetry
except Exception:
    from backend.services.telemetry_chain import tamper_evident_telemetry

# Import EDR service
from edr_service import edr_manager, EDRManager

router = APIRouter(prefix="/edr", tags=["EDR"])


def _record_edr_audit(action: str, principal: str, targets: list, result: str, constraints: Optional[dict] = None):
    try:
        tamper_evident_telemetry.set_db(get_db())
        tamper_evident_telemetry.record_action(
            principal=principal,
            principal_trust_state="trusted",
            action=action,
            targets=targets,
            constraints=constraints or {},
            result=result,
        )
    except Exception:
        pass

class MemoryAnalysisRequest(BaseModel):
    dump_path: str

class FIMPathRequest(BaseModel):
    path: str

class USBDeviceRequest(BaseModel):
    vendor_id: str
    product_id: str

@router.get("/status")
async def get_edr_status(current_user: dict = Depends(get_current_user)):
    """Get EDR system status"""
    return edr_manager.get_status()

# Process Tree endpoints
@router.get("/process-tree")
async def get_process_tree(current_user: dict = Depends(get_current_user)):
    """Get current process tree"""
    tree = await edr_manager.get_process_tree()
    return {"process_tree": tree, "count": len(tree)}

# File Integrity Monitoring endpoints
@router.get("/fim/status")
async def get_fim_status(current_user: dict = Depends(get_current_user)):
    """Get FIM status"""
    return edr_manager.fim.get_status()

@router.post("/fim/baseline")
async def create_fim_baseline(current_user: dict = Depends(check_permission("write"))):
    """Create FIM baseline"""
    result = await edr_manager.create_fim_baseline()
    await emit_world_event(get_db(), event_type="edr_fim_baseline_created", entity_refs=[], payload={"actor": current_user.get("id")}, trigger_triune=False)
    return result

@router.post("/fim/check")
async def check_file_integrity(current_user: dict = Depends(get_current_user)):
    """Check file integrity against baseline"""
    events = await edr_manager.check_file_integrity()
    await emit_world_event(get_db(), event_type="edr_fim_check_completed", entity_refs=[], payload={"violations": len(events)}, trigger_triune=False)
    return {
        "events": events,
        "count": len(events),
        "has_violations": len(events) > 0
    }

@router.post("/fim/monitor")
async def add_monitored_path(request: FIMPathRequest, current_user: dict = Depends(check_permission("write"))):
    """Add path to FIM monitoring"""
    edr_manager.fim.add_monitored_path(request.path)
    await emit_world_event(get_db(), event_type="edr_fim_monitored_path_added", entity_refs=[request.path], payload={"actor": current_user.get("id")}, trigger_triune=False)
    return {"message": f"Added {request.path} to monitoring"}

# USB Device Control endpoints
@router.get("/usb/devices")
async def get_usb_devices(current_user: dict = Depends(get_current_user)):
    """Get connected USB devices"""
    devices = await edr_manager.scan_usb_devices()
    return {"devices": devices, "count": len(devices)}

@router.get("/usb/status")
async def get_usb_status(current_user: dict = Depends(get_current_user)):
    """Get USB control status"""
    return edr_manager.usb_control.get_status()

@router.post("/usb/allow")
async def allow_usb_device(request: USBDeviceRequest, current_user: dict = Depends(check_permission("write"))):
    """Allow a USB device"""
    edr_manager.usb_control.allow_device(request.vendor_id, request.product_id)
    await emit_world_event(get_db(), event_type="edr_usb_allowlisted", entity_refs=[f"{request.vendor_id}:{request.product_id}"], payload={"actor": current_user.get("id")}, trigger_triune=False)
    return {"message": f"Device {request.vendor_id}:{request.product_id} allowed"}

@router.post("/usb/block")
async def block_usb_device(request: USBDeviceRequest, current_user: dict = Depends(check_permission("write"))):
    """Block a USB device"""
    edr_manager.usb_control.block_device(request.vendor_id, request.product_id)
    await emit_world_event(get_db(), event_type="edr_usb_blocklisted", entity_refs=[f"{request.vendor_id}:{request.product_id}"], payload={"actor": current_user.get("id")}, trigger_triune=False)
    return {"message": f"Device {request.vendor_id}:{request.product_id} blocked"}

# Memory Forensics endpoints
@router.get("/memory/status")
async def get_memory_forensics_status(current_user: dict = Depends(get_current_user)):
    """Get memory forensics status"""
    return edr_manager.memory_forensics.get_status()

@router.post("/memory/analyze")
async def analyze_memory_dump(request: MemoryAnalysisRequest, current_user: dict = Depends(check_permission("write"))):
    """Analyze a memory dump file"""
    result = await edr_manager.analyze_memory(request.dump_path)
    await emit_world_event(get_db(), event_type="edr_memory_analyzed", entity_refs=[request.dump_path], payload={"actor": current_user.get("id")}, trigger_triune=False)
    return result

@router.post("/memory/capture")
async def capture_live_memory(current_user: dict = Depends(check_permission("manage_users"))):
    """Capture live system memory"""
    result = await edr_manager.capture_memory()
    await emit_world_event(get_db(), event_type="edr_memory_capture_requested", entity_refs=[], payload={"actor": current_user.get("id")}, trigger_triune=False)
    return result

# Telemetry endpoints
@router.get("/telemetry")
async def collect_telemetry(current_user: dict = Depends(get_current_user)):
    """Collect EDR telemetry"""
    telemetry = await edr_manager.collect_telemetry()
    actor = (current_user or {}).get("email", (current_user or {}).get("id", "unknown"))
    await emit_world_event(
        get_db(),
        event_type="edr_telemetry_collected",
        entity_refs=[],
        payload={"actor": actor, "keys": list((telemetry or {}).keys())[:20]},
        trigger_triune=False,
    )
    _record_edr_audit(
        action="edr_collect_telemetry",
        principal=f"operator:{actor}",
        targets=["edr.telemetry"],
        result="success",
        constraints={"keys_count": len((telemetry or {}).keys())},
    )
    return telemetry
