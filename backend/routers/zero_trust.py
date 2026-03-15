"""
Zero Trust Architecture Router
"""
from fastapi import APIRouter, HTTPException, Depends, Request
from typing import Optional, Dict, List
from pydantic import BaseModel
from datetime import datetime, timezone

from .dependencies import get_current_user, check_permission, logger, get_db
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
from zero_trust import (
    zero_trust_engine,
    DeviceTrust,
    AccessPolicy,
    AccessLog,
    DeviceType,
    TrustLevel,
    AccessDecision,
)

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


async def _sync_engine_from_db(db):
    """Hydrate in-memory zero trust engine state from MongoDB documents."""
    try:
        zero_trust_engine.set_db(db)
        device_docs = await db.zt_devices.find({}, {"_id": 0}).to_list(1000)
        policy_docs = await db.zt_policies.find({}, {"_id": 0}).to_list(1000)
        access_log_docs = await db.zt_access_logs.find({}, {"_id": 0}).sort("timestamp", -1).to_list(1000)

        hydrated_devices = {}
        for d in device_docs:
            try:
                trust_score = int(d.get("trust_score", 50))
                trust_level_str = d.get("trust_level")
                trust_level = TrustLevel(trust_level_str) if trust_level_str in {t.value for t in TrustLevel} else zero_trust_engine._get_trust_level(trust_score)
                device_type_str = d.get("device_type", "unknown")
                device_type = DeviceType(device_type_str) if device_type_str in {t.value for t in DeviceType} else DeviceType.UNKNOWN

                hydrated_devices[d["device_id"]] = DeviceTrust(
                    device_id=d["device_id"],
                    device_name=d.get("device_name", d["device_id"]),
                    device_type=device_type,
                    trust_score=trust_score,
                    trust_level=trust_level,
                    last_verified=d.get("last_verified", datetime.now(timezone.utc).isoformat()),
                    os_info=d.get("os_info", {}),
                    security_posture=d.get("security_posture", {}),
                    is_compliant=bool(d.get("is_compliant", False)),
                    compliance_issues=d.get("compliance_issues", []),
                    registered_at=d.get("registered_at", datetime.now(timezone.utc).isoformat()),
                    last_seen=d.get("last_seen", datetime.now(timezone.utc).isoformat()),
                    owner_id=d.get("owner_id")
                )
            except Exception as exc:
                logger.warning(f"Skipping invalid zt device doc: {exc}")

        hydrated_policies = dict(zero_trust_engine.policies)
        for p in policy_docs:
            try:
                required_level_str = p.get("required_trust_level", "medium")
                required_level = TrustLevel(required_level_str) if required_level_str in {t.value for t in TrustLevel} else TrustLevel.MEDIUM

                allowed_types = []
                for device_type in p.get("allowed_device_types", []):
                    if device_type in {t.value for t in DeviceType}:
                        allowed_types.append(DeviceType(device_type))

                policy = AccessPolicy(
                    id=p["id"],
                    name=p.get("name", p["id"]),
                    description=p.get("description", ""),
                    resource_pattern=p.get("resource_pattern", ""),
                    required_trust_level=required_level,
                    require_mfa=bool(p.get("require_mfa", False)),
                    allowed_device_types=allowed_types,
                    allowed_networks=p.get("allowed_networks", []),
                    time_restrictions=p.get("time_restrictions"),
                    is_active=bool(p.get("is_active", True)),
                    created_at=p.get("created_at", datetime.now(timezone.utc).isoformat())
                )
                hydrated_policies[policy.id] = policy
            except Exception as exc:
                logger.warning(f"Skipping invalid zt policy doc: {exc}")

        hydrated_logs = []
        for entry in reversed(access_log_docs):
            try:
                decision_str = entry.get("decision", "deny")
                decision = AccessDecision(decision_str) if decision_str in {d.value for d in AccessDecision} else AccessDecision.DENY
                hydrated_logs.append(
                    AccessLog(
                        id=entry.get("id", f"al_sync_{len(hydrated_logs)}"),
                        timestamp=entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        user_id=entry.get("user_id", "unknown"),
                        device_id=entry.get("device_id", "unknown"),
                        resource=entry.get("resource", "unknown"),
                        decision=decision,
                        trust_score=int(entry.get("trust_score", 0)),
                        factors=entry.get("factors", {}),
                        policy_id=entry.get("policy_id"),
                        challenge_reason=entry.get("challenge_reason")
                    )
                )
            except Exception as exc:
                logger.warning(f"Skipping invalid zt access log doc: {exc}")

        zero_trust_engine.devices = hydrated_devices
        zero_trust_engine.policies = hydrated_policies
        zero_trust_engine.access_logs = hydrated_logs[-1000:]
    except Exception as exc:
        logger.warning(f"Zero trust state sync skipped: {exc}")


async def _persist_device(db, device: Dict, registered_by: Optional[str] = None):
    payload = {**device}
    if registered_by:
        payload["registered_by"] = registered_by
    await db.zt_devices.update_one({"device_id": device["device_id"]}, {"$set": payload}, upsert=True)


def _device_to_dict(device: DeviceTrust) -> Dict:
    return {
        "device_id": device.device_id,
        "device_name": device.device_name,
        "device_type": device.device_type.value,
        "trust_score": device.trust_score,
        "trust_level": device.trust_level.value,
        "last_verified": device.last_verified,
        "os_info": device.os_info,
        "security_posture": device.security_posture,
        "is_compliant": device.is_compliant,
        "compliance_issues": device.compliance_issues,
        "registered_at": device.registered_at,
        "last_seen": device.last_seen,
        "owner_id": device.owner_id,
    }


async def _persist_policy(db, policy: Dict, updated_by: Optional[str] = None):
    payload = {**policy}
    if updated_by:
        payload["updated_by"] = updated_by
    await db.zt_policies.update_one({"id": policy["id"]}, {"$set": payload}, upsert=True)


async def _persist_latest_access_log(db):
    if not zero_trust_engine.access_logs:
        return
    latest = zero_trust_engine.access_logs[-1]
    doc = {
        "id": latest.id,
        "timestamp": latest.timestamp,
        "user_id": latest.user_id,
        "device_id": latest.device_id,
        "resource": latest.resource,
        "decision": latest.decision.value,
        "trust_score": latest.trust_score,
        "factors": latest.factors,
        "policy_id": latest.policy_id,
        "challenge_reason": latest.challenge_reason,
    }
    await db.zt_access_logs.update_one({"id": latest.id}, {"$set": doc}, upsert=True)

@router.get("/stats")
async def get_zero_trust_stats(current_user: dict = Depends(get_current_user)):
    """Get zero trust statistics"""
    from .dependencies import get_db
    db = get_db()
    await _sync_engine_from_db(db)
    return zero_trust_engine.get_stats()

@router.get("/devices")
async def list_devices(current_user: dict = Depends(get_current_user)):
    """List all registered devices"""
    from .dependencies import get_db
    db = get_db()
    
    await _sync_engine_from_db(db)
    devices = zero_trust_engine.get_devices()
    return {"devices": devices, "count": len(devices)}

@router.post("/devices")
async def register_device(
    request: RegisterDeviceRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Register a new device"""
    from .dependencies import get_db
    db = get_db()
    await _sync_engine_from_db(db)
    
    device = zero_trust_engine.register_device(
        device_id=request.device_id,
        device_name=request.device_name,
        device_type=request.device_type,
        os_info=request.os_info,
        security_posture=request.security_posture,
        owner_id=current_user["id"]
    )
    
    # Also store in database
    await _persist_device(db, device, registered_by=current_user.get("name", current_user["id"]))
    
    logger.info(f"Registered device {device['device_id']} by user {current_user['id']}")
    await emit_world_event(get_db(), event_type="zero_trust_device_registered", entity_refs=[device.get("device_id")], payload={"actor": current_user.get("id"), "device_type": device.get("device_type")}, trigger_triune=False)
    return device

@router.get("/policies")
async def list_policies(current_user: dict = Depends(get_current_user)):
    """List all access policies"""
    from .dependencies import get_db
    db = get_db()
    await _sync_engine_from_db(db)
    policies = zero_trust_engine.get_policies()
    return {"policies": policies, "count": len(policies)}

@router.post("/policies")
async def create_policy(
    request: CreatePolicyRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Create a new access policy"""
    from .dependencies import get_db
    db = get_db()
    await _sync_engine_from_db(db)
    policy = zero_trust_engine.create_policy(request.model_dump())
    await _persist_policy(db, policy, updated_by=current_user.get("id"))
    logger.info(f"Created policy {policy['id']} by user {current_user['id']}")
    await emit_world_event(get_db(), event_type="zero_trust_policy_created", entity_refs=[policy.get("id")], payload={"actor": current_user.get("id"), "resource_pattern": policy.get("resource_pattern")}, trigger_triune=False)
    return policy

@router.post("/evaluate")
async def evaluate_access(
    request: EvaluateAccessRequest,
    req: Request,
    current_user: dict = Depends(get_current_user)
):
    """Evaluate an access request"""
    from .dependencies import get_db
    db = get_db()
    await _sync_engine_from_db(db)

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
    await _persist_latest_access_log(db)
    await emit_world_event(get_db(), event_type="zero_trust_access_evaluated", entity_refs=[request.device_id, request.resource], payload={"actor": current_user.get("id"), "decision": result.get("decision") if isinstance(result, dict) else None}, trigger_triune=False)
    return result

@router.post("/trust-score")
async def calculate_trust_score(
    request: EvaluateAccessRequest,
    req: Request,
    current_user: dict = Depends(get_current_user)
):
    """Calculate trust score for current context"""
    from .dependencies import get_db
    db = get_db()
    await _sync_engine_from_db(db)

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
    from .dependencies import get_db
    db = get_db()
    await _sync_engine_from_db(db)
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
    """Queue device block through mandatory outbound governance."""
    from .dependencies import get_db
    
    db = get_db()
    await _sync_engine_from_db(db)
    from backend.services.outbound_gate import OutboundGateService
    gate = OutboundGateService(db)
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gated = await gate.gate_action(
        action_type="cross_sector_hardening",
        actor=actor,
        payload={
            "operation": "zero_trust_block_device",
            "device_id": device_id,
            "reason": request.reason,
            "trigger_remediation": bool(request.trigger_remediation),
        },
        impact_level="critical",
        subject_id=device_id,
        entity_refs=[device_id],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="zero_trust_device_block_gated",
        entity_refs=[device_id, gated.get("queue_id"), gated.get("decision_id")],
        payload={"actor": actor, "reason": request.reason},
        trigger_triune=True,
    )

    return {
        "success": True,
        "device_id": device_id,
        "status": "queued_for_triune_approval",
        "reason": request.reason,
        "queue_id": gated.get("queue_id"),
        "decision_id": gated.get("decision_id"),
        "message": "Device block queued for triune approval.",
    }

@router.post("/devices/{device_id}/unblock")
async def unblock_device(
    device_id: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Unblock a previously blocked device"""
    from .dependencies import get_db
    db = get_db()
    await _sync_engine_from_db(db)

    device = zero_trust_engine.devices.get(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Reset device trust
    device.trust_score = 50  # Reset to baseline
    device.trust_level = zero_trust_engine._get_trust_level(50)
    device.is_compliant = True
    device.compliance_issues = [i for i in device.compliance_issues if not i.startswith("BLOCKED:")]

    await _persist_device(db, _device_to_dict(device))
    
    logger.info(f"Device {device_id} unblocked by {current_user.get('email')}")
    await emit_world_event(get_db(), event_type="zero_trust_device_unblocked", entity_refs=[device_id], payload={"actor": current_user.get("id"), "new_trust_score": device.trust_score}, trigger_triune=False)
    return {
        "success": True,
        "device_id": device_id,
        "status": "unblocked",
        "new_trust_score": device.trust_score,
        "new_trust_level": device.trust_level.value
    }
