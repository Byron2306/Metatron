"""
Zero Trust Architecture Router
"""
from fastapi import APIRouter, HTTPException, Depends, Request
from typing import Optional, Dict, List
from pydantic import BaseModel

from .dependencies import get_current_user, check_permission, logger
from zero_trust import zero_trust_engine

router = APIRouter(prefix="/zero-trust", tags=["Zero Trust"])

class RegisterDeviceRequest(BaseModel):
    device_id: str
    device_name: str
    device_type: str
    os_info: Dict[str, str] = {}
    security_posture: Dict = {}

class CreatePolicyRequest(BaseModel):
    name: str
    description: str = ""
    resource_pattern: str
    required_trust_level: str = "medium"
    require_mfa: bool = False
    allowed_device_types: List[str] = []
    allowed_networks: List[str] = []
    time_restrictions: Optional[Dict] = None

class EvaluateAccessRequest(BaseModel):
    resource: str
    device_id: str
    auth_method: str = "password"
    anomaly_score: float = 0.0
    recent_incidents: int = 0

@router.get("/stats")
async def get_zero_trust_stats(current_user: dict = Depends(get_current_user)):
    """Get zero trust statistics"""
    return zero_trust_engine.get_stats()

@router.get("/devices")
async def list_devices(current_user: dict = Depends(get_current_user)):
    """List all registered devices"""
    from .dependencies import get_db
    db = get_db()
    
    # Get devices from both memory and database
    memory_devices = zero_trust_engine.get_devices()
    
    # Also get from database
    db_devices = await db.zt_devices.find({}, {"_id": 0}).to_list(100)
    
    # Merge, preferring database records
    device_map = {d.get("device_id"): d for d in memory_devices}
    for d in db_devices:
        device_map[d.get("device_id")] = d
    
    devices = list(device_map.values())
    return {"devices": devices, "count": len(devices)}

@router.post("/devices")
async def register_device(
    request: RegisterDeviceRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Register a new device"""
    from .dependencies import get_db
    db = get_db()
    
    device = zero_trust_engine.register_device(
        device_id=request.device_id,
        device_name=request.device_name,
        device_type=request.device_type,
        os_info=request.os_info,
        security_posture=request.security_posture,
        owner_id=current_user["id"]
    )
    
    # Also store in database
    await db.zt_devices.update_one(
        {"device_id": request.device_id},
        {"$set": {
            **device,
            "registered_by": current_user.get("name", current_user["id"])
        }},
        upsert=True
    )
    
    logger.info(f"Registered device {device['device_id']} by user {current_user['id']}")
    return device

@router.get("/policies")
async def list_policies(current_user: dict = Depends(get_current_user)):
    """List all access policies"""
    policies = zero_trust_engine.get_policies()
    return {"policies": policies, "count": len(policies)}

@router.post("/policies")
async def create_policy(
    request: CreatePolicyRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Create a new access policy"""
    policy = zero_trust_engine.create_policy(request.model_dump())
    logger.info(f"Created policy {policy['id']} by user {current_user['id']}")
    return policy

@router.post("/evaluate")
async def evaluate_access(
    request: EvaluateAccessRequest,
    req: Request,
    current_user: dict = Depends(get_current_user)
):
    """Evaluate an access request"""
    user_context = {
        "user_id": current_user["id"],
        "auth_method": request.auth_method,
        "anomaly_score": request.anomaly_score,
        "recent_incidents": request.recent_incidents
    }
    
    request_context = {
        "source_ip": req.client.host if req.client else "unknown",
        "user_agent": req.headers.get("user-agent")
    }
    
    result = zero_trust_engine.evaluate_access(
        resource=request.resource,
        device_id=request.device_id,
        user_context=user_context,
        request_context=request_context
    )
    return result

@router.post("/trust-score")
async def calculate_trust_score(
    request: EvaluateAccessRequest,
    req: Request,
    current_user: dict = Depends(get_current_user)
):
    """Calculate trust score for current context"""
    user_context = {
        "user_id": current_user["id"],
        "auth_method": request.auth_method,
        "anomaly_score": request.anomaly_score,
        "recent_incidents": request.recent_incidents
    }
    
    request_context = {
        "source_ip": req.client.host if req.client else "unknown",
        "user_agent": req.headers.get("user-agent")
    }
    
    result = zero_trust_engine.calculate_trust_score(
        device_id=request.device_id,
        user_context=user_context,
        request_context=request_context
    )
    return result

@router.get("/access-logs")
async def get_access_logs(
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get recent access evaluation logs"""
    logs = zero_trust_engine.get_access_logs(limit=limit)
    return {"logs": logs, "count": len(logs)}


class BlockDeviceRequest(BaseModel):
    device_id: str
    reason: str = "Zero Trust violation"
    trigger_remediation: bool = True

@router.post("/devices/{device_id}/block")
async def block_device(
    device_id: str,
    request: BlockDeviceRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Block a device and optionally trigger remediation commands to the agent"""
    from .dependencies import get_db
    import uuid
    from datetime import datetime, timezone
    
    db = get_db()
    
    # Block the device in Zero Trust
    block_result = zero_trust_engine.block_device(device_id, request.reason)
    
    if not block_result.get("success"):
        raise HTTPException(status_code=404, detail=block_result.get("error", "Device not found"))
    
    # If remediation is requested, create agent commands
    commands_created = []
    if request.trigger_remediation:
        # Get device info
        device = zero_trust_engine.devices.get(device_id)
        
        # Create remediation command for the agent
        command_id = str(uuid.uuid4())[:12]
        command = {
            "command_id": command_id,
            "agent_id": device_id,  # Use device_id as agent_id
            "command_type": "remediate_compliance",
            "command_name": "Remediate Compliance Issue",
            "parameters": {
                "issue_type": "zero_trust_violation",
                "remediation_action": "full_scan_and_report",
                "reason": request.reason,
                "compliance_issues": device.compliance_issues if device else []
            },
            "priority": "high",
            "risk_level": "medium",
            "status": "pending_approval",
            "created_by": current_user.get("email", current_user.get("id")),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "approved_by": None,
            "approved_at": None,
            "executed_at": None,
            "result": None,
            "source": "zero_trust_violation"
        }
        
        await db.agent_commands.insert_one(command)
        commands_created.append(command_id)
        
        logger.info(f"Zero Trust remediation command created for device {device_id}: {command_id}")
    
    return {
        "success": True,
        "device_id": device_id,
        "status": "blocked",
        "reason": request.reason,
        "remediation_commands": commands_created,
        "message": f"Device blocked. {len(commands_created)} remediation command(s) queued for approval."
    }

@router.post("/devices/{device_id}/unblock")
async def unblock_device(
    device_id: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Unblock a previously blocked device"""
    device = zero_trust_engine.devices.get(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Reset device trust
    device.trust_score = 50  # Reset to baseline
    device.trust_level = zero_trust_engine._get_trust_level(50)
    device.is_compliant = True
    device.compliance_issues = [i for i in device.compliance_issues if not i.startswith("BLOCKED:")]
    
    logger.info(f"Device {device_id} unblocked by {current_user.get('email')}")
    
    return {
        "success": True,
        "device_id": device_id,
        "status": "unblocked",
        "new_trust_score": device.trust_score,
        "new_trust_level": device.trust_level.value
    }

