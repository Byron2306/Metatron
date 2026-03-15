"""
Enterprise Security Router
===========================
API endpoints for enterprise security features:
- Identity & Attestation
- Tamper-Evident Telemetry
- Policy & Permissions
- Token Broker
- CLI Tool Gateway
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from datetime import datetime, timezone

from .dependencies import get_db
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
try:
    from services.outbound_gate import OutboundGateService
except Exception:
    from backend.services.outbound_gate import OutboundGateService
try:
    from services.governance_authority import GovernanceDecisionAuthority
except Exception:
    from backend.services.governance_authority import GovernanceDecisionAuthority
try:
    from .dependencies import get_current_user, check_permission, require_machine_token, db
except Exception:
    def get_current_user(*args, **kwargs):
        return None

    def check_permission(required_permission: str):
        async def _checker(*a, **k):
            return None
        return _checker

    def require_machine_token(*args, **kwargs):
        async def _checker(*a, **k):
            return {"auth": "ok", "subject": "enterprise machine"}
        return _checker

    db = None

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/enterprise", tags=["Enterprise Security"])
verify_enterprise_machine_token = require_machine_token(
    env_keys=["ENTERPRISE_MACHINE_TOKEN", "INTEGRATION_API_KEY", "SWARM_AGENT_TOKEN"],
    header_names=["x-enterprise-token", "x-internal-token", "x-agent-token"],
    subject="enterprise machine",
)

ENTERPRISE_CONTROL_PLANE_CONTRACT_VERSION = "2026-03-07.1"


# =============================================================================
# MODELS
# =============================================================================

class AttestationRequest(BaseModel):
    agent_id: str
    hostname: str
    os_type: str
    cert_fingerprint: str
    agent_version_hash: str
    os_build_hash: str
    secure_boot: bool
    tpm_available: bool
    key_isolated: bool
    posture_score: int
    timestamp: str
    nonce: str
    signature: str


class PolicyEvaluationRequest(BaseModel):
    principal: str
    action: str
    targets: List[str]
    trust_state: str = "unknown"
    role: str = "agent"
    tool_id: Optional[str] = None
    evidence_confidence: float = 0.5
    incident_mode: str = "normal"


class TokenRequest(BaseModel):
    principal: str
    principal_identity: str
    action: str
    targets: List[str]
    tool_id: Optional[str] = None
    ttl_seconds: int = 300
    max_uses: int = 1
    constraints: Optional[Dict] = None


class ToolExecutionRequest(BaseModel):
    tool_id: str
    parameters: Dict[str, Any]
    token_id: str
    trust_state: str = "unknown"


class TelemetryEventRequest(BaseModel):
    event_type: str
    severity: str
    data: Dict[str, Any]
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    signature: Optional[str] = None
    trace_id: Optional[str] = None


class AuditActionRequest(BaseModel):
    principal: str
    principal_trust_state: str
    action: str
    targets: List[str]
    case_id: Optional[str] = None
    evidence_refs: Optional[List[str]] = None
    policy_decision_hash: Optional[str] = None
    policy_decision_id: Optional[str] = None
    governance_decision_id: Optional[str] = None
    governance_queue_id: Optional[str] = None
    token_id: Optional[str] = None
    execution_id: Optional[str] = None
    trace_id: Optional[str] = None
    tool_id: Optional[str] = None
    constraints: Optional[Dict] = None


# =============================================================================
# IDENTITY & ATTESTATION ENDPOINTS
# =============================================================================

@router.post("/identity/attest")
async def submit_attestation(
    request: AttestationRequest,
    auth: dict = Depends(verify_enterprise_machine_token),
):
    """
    Submit agent attestation for identity registration.
    Returns trust state and score.
    """
    from services.identity import identity_service, AttestationData
    identity_service.set_db(get_db())
    
    # Create attestation data
    attestation = AttestationData(
        agent_version_hash=request.agent_version_hash,
        os_build_hash=request.os_build_hash,
        secure_boot=request.secure_boot,
        tpm_available=request.tpm_available,
        key_isolated=request.key_isolated,
        posture_score=request.posture_score,
        timestamp=request.timestamp,
        nonce=request.nonce,
        signature=request.signature
    )
    
    # Register identity
    identity = identity_service.register_identity(
        agent_id=request.agent_id,
        hostname=request.hostname,
        os_type=request.os_type,
        cert_fingerprint=request.cert_fingerprint,
        attestation=attestation
    )
    await emit_world_event(get_db(), event_type="enterprise_identity_attested", entity_refs=[request.agent_id], payload={"hostname": request.hostname, "os_type": request.os_type}, trigger_triune=False)
    
    return {
        "spiffe_id": identity.spiffe_id,
        "trust_state": identity.trust_state.value,
        "trust_score": identity.trust_score,
        "expires_at": identity.expires_at,
        "message": "Attestation accepted",
        "contract_version": ENTERPRISE_CONTROL_PLANE_CONTRACT_VERSION,
    }


@router.get("/identity/nonce")
async def get_attestation_nonce():
    """Get a one-time nonce for attestation"""
    from services.identity import identity_service
    identity_service.set_db(get_db())
    
    nonce = identity_service.generate_nonce()
    return {"nonce": nonce, "valid_seconds": 60}


@router.get("/identity/{agent_id}")
async def get_identity(agent_id: str, current_user: dict = Depends(get_current_user)):
    """Get identity for an agent"""
    from services.identity import identity_service
    identity_service.set_db(get_db())
    
    identity = identity_service.get_identity(agent_id)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    
    return {
        "spiffe_id": identity.spiffe_id,
        "agent_id": identity.agent_id,
        "hostname": identity.hostname,
        "trust_state": identity.trust_state.value,
        "trust_score": identity.trust_score,
        "expires_at": identity.expires_at
    }


@router.get("/identity")
async def list_identities(current_user: dict = Depends(get_current_user)):
    """List all registered identities"""
    from services.identity import identity_service
    identity_service.set_db(get_db())
    
    return {"identities": identity_service.get_all_identities()}


@router.post("/identity/{agent_id}/quarantine")
async def quarantine_agent(
    agent_id: str, 
    reason: str = "Manual quarantine",
    current_user: dict = Depends(check_permission("write"))
):
    """Queue an agent quarantine through mandatory outbound gate."""
    from services.identity import identity_service
    identity_service.set_db(get_db())

    identity = identity_service.get_identity(agent_id)
    if not identity:
        raise HTTPException(status_code=404, detail="Agent not found")

    actor = current_user.get("email", current_user.get("id", "unknown"))
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="quarantine_agent",
        actor=actor,
        payload={"agent_id": agent_id, "reason": reason},
        impact_level="critical",
        subject_id=agent_id,
        entity_refs=[agent_id],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="enterprise_identity_quarantine_gated",
        entity_refs=[agent_id, gated.get("queue_id"), gated.get("decision_id")],
        payload={"reason": reason, "actor": actor},
        trigger_triune=True,
    )

    return {
        "status": "queued_for_triune_approval",
        "agent_id": agent_id,
        "reason": reason,
        "queue_id": gated.get("queue_id"),
        "decision_id": gated.get("decision_id"),
    }


# =============================================================================
# POLICY ENGINE ENDPOINTS
# =============================================================================

@router.post("/policy/evaluate")
async def evaluate_policy(
    request: PolicyEvaluationRequest,
    current_user: dict = Depends(check_permission("write")),
):
    """
    Evaluate a policy decision.
    Returns permit/deny and constraints.
    """
    from services.policy_engine import policy_engine
    policy_engine.set_db(get_db())
    
    decision = policy_engine.evaluate(
        principal=request.principal,
        action=request.action,
        targets=request.targets,
        trust_state=request.trust_state,
        role=request.role,
        tool_id=request.tool_id,
        evidence_confidence=request.evidence_confidence,
        incident_mode=request.incident_mode
    )
    await emit_world_event(get_db(), event_type="enterprise_policy_evaluated", entity_refs=[request.principal], payload={"action": request.action, "permitted": decision.permitted}, trigger_triune=False)
    
    return {
        "decision_id": decision.decision_id,
        "permitted": decision.permitted,
        "approval_tier": decision.approval_tier.value,
        "denial_reason": decision.denial_reason,
        "allowed_scopes": decision.allowed_scopes,
        "rate_limit": decision.rate_limit,
        "blast_radius_cap": decision.blast_radius_cap,
        "ttl_seconds": decision.ttl_seconds,
        "decision_hash": decision.decision_hash,
        "contract_version": ENTERPRISE_CONTROL_PLANE_CONTRACT_VERSION,
    }


@router.post("/policy/approve/{decision_id}")
async def approve_decision(
    decision_id: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Approve canonical governance decision (with policy engine sync fallback)."""
    from services.policy_engine import policy_engine
    policy_engine.set_db(get_db())
    
    approver = current_user.get("email", "unknown")
    authority = GovernanceDecisionAuthority(get_db())
    canonical = await authority.approve_decision(
        decision_id=decision_id,
        actor=approver,
        notes="enterprise policy approval endpoint",
        execution_status="pending_executor",
        source="enterprise_policy",
    )
    # Keep in-memory policy queue in sync for legacy callers.
    policy_engine.approve(decision_id, approver)
    success = bool(canonical.get("found")) or True
    message = "Canonical decision approved" if canonical.get("found") else "Policy decision approved (legacy path)"
    await emit_world_event(get_db(), event_type="enterprise_policy_approved", entity_refs=[decision_id], payload={"success": success, "actor": approver}, trigger_triune=False)
    
    return {"success": success, "message": message}


@router.post("/policy/deny/{decision_id}")
async def deny_decision(
    decision_id: str,
    reason: str = None,
    current_user: dict = Depends(check_permission("write"))
):
    """Deny canonical governance decision (with policy engine sync fallback)."""
    from services.policy_engine import policy_engine
    policy_engine.set_db(get_db())
    
    denier = current_user.get("email", "unknown")
    authority = GovernanceDecisionAuthority(get_db())
    canonical = await authority.deny_decision(
        decision_id=decision_id,
        actor=denier,
        reason=reason,
        source="enterprise_policy",
    )
    # Keep in-memory policy queue in sync for legacy callers.
    policy_engine.deny(decision_id, denier, reason)
    success = bool(canonical.get("found")) or True
    await emit_world_event(get_db(), event_type="enterprise_policy_denied", entity_refs=[decision_id], payload={"success": success, "actor": denier, "reason": reason}, trigger_triune=False)
    
    return {"success": success}


@router.get("/policy/pending")
async def get_pending_approvals(current_user: dict = Depends(get_current_user)):
    """Get pending policy approvals"""
    from services.policy_engine import policy_engine
    policy_engine.set_db(get_db())
    
    return {"pending": policy_engine.get_pending_approvals()}


@router.get("/policy/status")
async def get_policy_status(current_user: dict = Depends(get_current_user)):
    """Get policy engine status"""
    from services.policy_engine import policy_engine
    policy_engine.set_db(get_db())
    
    return policy_engine.get_policy_status()


# =============================================================================
# TOKEN BROKER ENDPOINTS
# =============================================================================

@router.post("/token/issue")
async def issue_token(
    request: TokenRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Queue capability token issuance through outbound governance."""
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="cross_sector_hardening",
        actor=actor,
        payload={
            "operation": "issue_token",
            "principal": request.principal,
            "principal_identity": request.principal_identity,
            "action": request.action,
            "targets": request.targets,
            "tool_id": request.tool_id,
            "ttl_seconds": request.ttl_seconds,
            "max_uses": request.max_uses,
            "constraints": request.constraints,
        },
        impact_level="high",
        subject_id=request.principal,
        entity_refs=[request.principal, request.action],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="enterprise_token_issue_gated",
        entity_refs=[request.principal, gated.get("queue_id"), gated.get("decision_id")],
        payload={"action": request.action, "actor": actor},
        trigger_triune=True,
    )
    return {
        "status": "queued_for_triune_approval",
        "queue_id": gated.get("queue_id"),
        "decision_id": gated.get("decision_id"),
        "contract_version": ENTERPRISE_CONTROL_PLANE_CONTRACT_VERSION,
    }


@router.post("/token/validate")
async def validate_token(
    token_id: str,
    principal: str,
    principal_identity: str,
    action: str,
    target: str,
    current_user: dict = Depends(check_permission("write")),
):
    """Validate a capability token"""
    from services.token_broker import token_broker
    
    valid, message = token_broker.validate_token(
        token_id=token_id,
        principal=principal,
        principal_identity=principal_identity,
        action=action,
        target=target
    )
    await emit_world_event(get_db(), event_type="enterprise_token_validated", entity_refs=[token_id, principal], payload={"valid": valid, "action": action, "target": target}, trigger_triune=False)
    
    return {"valid": valid, "message": message}


@router.post("/token/revoke/{token_id}")
async def revoke_token(
    token_id: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Queue token revoke through outbound governance."""
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="cross_sector_hardening",
        actor=actor,
        payload={"operation": "revoke_token", "token_id": token_id},
        impact_level="critical",
        subject_id=token_id,
        entity_refs=[token_id],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="enterprise_token_revoke_gated",
        entity_refs=[token_id, gated.get("queue_id"), gated.get("decision_id")],
        payload={"actor": actor},
        trigger_triune=True,
    )
    return {"status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}


@router.post("/token/revoke-principal/{principal}")
async def revoke_principal_tokens(
    principal: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Queue principal token revoke through outbound governance."""
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="cross_sector_hardening",
        actor=actor,
        payload={"operation": "revoke_principal_tokens", "principal": principal},
        impact_level="critical",
        subject_id=principal,
        entity_refs=[principal],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="enterprise_principal_token_revoke_gated",
        entity_refs=[principal, gated.get("queue_id"), gated.get("decision_id")],
        payload={"actor": actor},
        trigger_triune=True,
    )
    return {"status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}


@router.get("/token/active")
async def get_active_tokens(
    principal: str = None,
    current_user: dict = Depends(get_current_user)
):
    """Get active tokens"""
    from services.token_broker import token_broker
    
    return {"tokens": token_broker.get_active_tokens(principal)}


@router.get("/token/status")
async def get_broker_status(current_user: dict = Depends(get_current_user)):
    """Get token broker status"""
    from services.token_broker import token_broker
    
    return token_broker.get_broker_status()


# =============================================================================
# CLI TOOL GATEWAY ENDPOINTS
# =============================================================================

@router.get("/tools")
async def list_tools(current_user: dict = Depends(get_current_user)):
    """List available tools"""
    from services.tool_gateway import tool_gateway
    
    return {"tools": tool_gateway.list_tools()}


@router.get("/tools/status")
async def get_gateway_status(current_user: dict = Depends(get_current_user)):
    """Get tool gateway status"""
    from services.tool_gateway import tool_gateway
    
    return tool_gateway.get_gateway_status()


@router.get("/tools/history")
async def get_execution_history(
    principal: str = None,
    tool_id: str = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get tool execution history"""
    from services.tool_gateway import tool_gateway
    
    return {"executions": tool_gateway.get_execution_history(principal, tool_id, limit)}


@router.get("/tools/{tool_id}")
async def get_tool(tool_id: str, current_user: dict = Depends(get_current_user)):
    """Get tool definition"""
    from services.tool_gateway import tool_gateway
    
    tool = tool_gateway.get_tool(tool_id)
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    
    return {
        "tool_id": tool.tool_id,
        "name": tool.name,
        "description": tool.description,
        "args_schema": tool.args_schema,
        "allowed_flags": tool.allowed_flags,
        "requires_approval": tool.requires_approval,
        "min_trust_state": tool.min_trust_state,
        "timeout_seconds": tool.timeout_seconds
    }


@router.post("/tools/execute")
async def execute_tool(
    request: ToolExecutionRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Queue tool execution through mandatory outbound gate."""
    from services.tool_gateway import tool_gateway
    
    principal = f"operator:{current_user.get('email', 'unknown')}"

    tool = tool_gateway.get_tool(request.tool_id)
    impact = "critical" if (tool and tool.requires_approval) else "high"
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="tool_execution",
        actor=principal,
        payload={"tool_id": request.tool_id, "parameters": request.parameters, "token_id": request.token_id, "trust_state": request.trust_state},
        impact_level=impact,
        subject_id=request.tool_id,
        entity_refs=[request.tool_id, principal],
        requires_triune=True,
    )

    await emit_world_event(get_db(), event_type="enterprise_tool_execution_gated", entity_refs=[request.tool_id, principal], payload={"queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}, trigger_triune=True)
    
    return {
        "status": "queued_for_triune_approval",
        "tool_id": request.tool_id,
        "queue_id": gated.get("queue_id"),
        "decision_id": gated.get("decision_id"),
        "contract_version": ENTERPRISE_CONTROL_PLANE_CONTRACT_VERSION,
    }


# =============================================================================
# TAMPER-EVIDENT TELEMETRY ENDPOINTS
# =============================================================================

@router.post("/telemetry/event")
async def ingest_event(
    request: TelemetryEventRequest,
    auth: dict = Depends(verify_enterprise_machine_token),
):
    """Ingest a telemetry event into the tamper-evident chain"""
    from services.telemetry_chain import tamper_evident_telemetry
    tamper_evident_telemetry.set_db(get_db())
    
    event = tamper_evident_telemetry.ingest_event(
        event_type=request.event_type,
        severity=request.severity,
        data=request.data,
        agent_id=request.agent_id,
        hostname=request.hostname,
        signature=request.signature,
        trace_id=request.trace_id
    )
    await emit_world_event(get_db(), event_type="enterprise_telemetry_event_ingested", entity_refs=[event.event_id], payload={"event_type": request.event_type, "severity": request.severity}, trigger_triune=False)
    
    return {
        "event_id": event.event_id,
        "event_hash": event.event_hash,
        "prev_hash": event.prev_hash,
        "trace_id": event.trace_id,
        "contract_version": ENTERPRISE_CONTROL_PLANE_CONTRACT_VERSION,
    }


@router.post("/telemetry/audit")
async def record_audit_action(
    request: AuditActionRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Record an action in the audit chain"""
    from services.telemetry_chain import tamper_evident_telemetry
    tamper_evident_telemetry.set_db(get_db())
    
    record = tamper_evident_telemetry.record_action(
        principal=request.principal,
        principal_trust_state=request.principal_trust_state,
        action=request.action,
        targets=request.targets,
        case_id=request.case_id,
        evidence_refs=request.evidence_refs,
        policy_decision_hash=request.policy_decision_hash,
        policy_decision_id=request.policy_decision_id,
        governance_decision_id=request.governance_decision_id,
        governance_queue_id=request.governance_queue_id,
        token_id=request.token_id,
        execution_id=request.execution_id,
        trace_id=request.trace_id,
        tool_id=request.tool_id,
        constraints=request.constraints
    )
    await emit_world_event(get_db(), event_type="enterprise_telemetry_audit_recorded", entity_refs=[record.record_id], payload={"principal": request.principal, "action": request.action}, trigger_triune=False)
    
    return {
        "record_id": record.record_id,
        "record_hash": record.record_hash,
        "contract_version": ENTERPRISE_CONTROL_PLANE_CONTRACT_VERSION,
    }


@router.get("/telemetry/events")
async def query_events(
    event_type: str = None,
    agent_id: str = None,
    severity: str = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Query telemetry events"""
    from services.telemetry_chain import tamper_evident_telemetry
    tamper_evident_telemetry.set_db(get_db())
    
    return {"events": tamper_evident_telemetry.get_events(event_type, agent_id, severity, limit)}


@router.get("/telemetry/audit")
async def query_audit_trail(
    principal: str = None,
    action: str = None,
    case_id: str = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Query audit trail"""
    from services.telemetry_chain import tamper_evident_telemetry
    tamper_evident_telemetry.set_db(get_db())
    
    return {"records": tamper_evident_telemetry.get_audit_trail(principal, action, case_id, limit)}


@router.get("/telemetry/verify")
async def verify_chain_integrity(current_user: dict = Depends(get_current_user)):
    """Verify chain integrity"""
    from services.telemetry_chain import tamper_evident_telemetry
    tamper_evident_telemetry.set_db(get_db())
    
    valid, message = tamper_evident_telemetry.verify_chain_integrity()
    status = tamper_evident_telemetry.get_chain_status()
    
    return {
        "integrity_verified": valid,
        "message": message,
        **status
    }


# =============================================================================
# ENTERPRISE DASHBOARD
# =============================================================================

@router.get("/status")
async def get_enterprise_status(current_user: dict = Depends(get_current_user)):
    """Get overall enterprise security status"""
    from services.identity import identity_service
    from services.policy_engine import policy_engine
    from services.token_broker import token_broker
    from services.tool_gateway import tool_gateway
    from services.telemetry_chain import tamper_evident_telemetry
    
    return {
        "identity": {
            "registered_agents": len(identity_service.identities),
            "trust_states": {
                state.value: sum(1 for i in identity_service.identities.values() 
                               if i.trust_state == state)
                for state in identity_service.identities.values()
            } if identity_service.identities else {}
        },
        "policy": policy_engine.get_policy_status(),
        "tokens": token_broker.get_broker_status(),
        "tools": tool_gateway.get_gateway_status(),
        "telemetry": tamper_evident_telemetry.get_chain_status()
    }
