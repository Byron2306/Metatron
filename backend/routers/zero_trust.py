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
    device = zero_trust_engine.register_device(
        device_id=request.device_id,
        device_name=request.device_name,
        device_type=request.device_type,
        os_info=request.os_info,
        security_posture=request.security_posture,
        owner_id=current_user["id"]
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
