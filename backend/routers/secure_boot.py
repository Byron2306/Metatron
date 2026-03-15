"""
Secure Boot Verification API Router
=====================================
REST API endpoints for UEFI/Secure Boot verification, bootkit detection,
and firmware integrity monitoring.

Endpoints:
- GET /status - Get secure boot status
- POST /scan - Run firmware security scan  
- GET /scan/{scan_id} - Get scan results
- GET /bootchain - Get boot chain verification
- GET /firmware - Get firmware inventory
- POST /firmware/verify - Verify firmware integrity
- GET /history - Get boot verification history
- GET /alerts - Get boot security alerts

Author: Seraph Security Team
Version: 1.0.0
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks, Depends
from .dependencies import get_db
try:
    from .dependencies import get_current_user, check_permission
except Exception:
    def get_current_user(*args, **kwargs):
        return {"id": "system", "email": "system@local", "role": "admin"}

    def check_permission(required_permission: str):
        async def _checker(*a, **k):
            return {"id": "system", "email": "system@local", "role": "admin"}
        return _checker
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
try:
    from services.outbound_gate import OutboundGateService
except Exception:
    from backend.services.outbound_gate import OutboundGateService
from pydantic import BaseModel, Field
import asyncio
import logging
import uuid

from secure_boot_verification import (
    get_secure_boot_verifier,
    SecureBootVerifier,
    SecureBootState,
    BootChainComponent,
    FirmwareInfo,
    BootThreatType,
    SecureBootScanResult,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/secure-boot", tags=["Secure Boot Verification"])


# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class SecureBootStatusResponse(BaseModel):
    """Secure boot status response"""
    platform: str
    uefi_mode: bool
    secure_boot_enabled: bool
    secure_boot_enforced: bool
    setup_mode: bool
    pk_enrolled: bool
    kek_enrolled: bool
    db_enrolled: bool
    dbx_enrolled: bool
    measured_boot_supported: bool
    tpm_present: bool
    tpm_version: Optional[str]
    virtualization_based_security: bool
    last_check: str
    risk_level: str


class FirmwareScanRequest(BaseModel):
    """Request to scan firmware"""
    deep_scan: bool = Field(default=False, description="Perform deep firmware analysis")
    check_updates: bool = Field(default=True, description="Check for firmware updates")
    verify_signatures: bool = Field(default=True, description="Verify all signatures")


class FirmwareScanResponse(BaseModel):
    """Firmware scan response"""
    scan_id: str
    status: str
    started_at: str
    completed_at: Optional[str]
    total_components: int
    verified_components: int
    suspicious_components: int
    threats_detected: List[Dict[str, Any]]
    recommendations: List[str]


class BootChainResponse(BaseModel):
    """Boot chain verification response"""
    verified: bool
    chain_intact: bool
    components: List[Dict[str, Any]]
    chain_of_trust: List[Dict[str, Any]]
    issues: List[str]
    mitre_techniques: List[str]


class FirmwareComponent(BaseModel):
    """Firmware component details"""
    component_id: str
    name: str
    version: str
    vendor: str
    component_type: str
    hash: str
    signature_valid: bool
    last_modified: str
    update_available: bool


class FirmwareListResponse(BaseModel):
    """List of firmware components"""
    total: int
    components: List[FirmwareComponent]


class FirmwareVerifyRequest(BaseModel):
    """Request to verify specific firmware"""
    component_ids: Optional[List[str]] = None
    verify_against_known_good: bool = True
    check_rollback: bool = True


class FirmwareVerifyResponse(BaseModel):
    """Firmware verification response"""
    verified: bool
    total_checked: int
    passed: int
    failed: int
    results: List[Dict[str, Any]]
    threats: List[Dict[str, Any]]


class BootHistoryEntry(BaseModel):
    """Boot verification history entry"""
    boot_id: str
    timestamp: str
    boot_successful: bool
    secure_boot_active: bool
    chain_verified: bool
    threats_detected: int
    boot_time_ms: int
    notes: List[str]


class BootHistoryResponse(BaseModel):
    """Boot verification history"""
    total_boots: int
    successful_boots: int
    failed_boots: int
    history: List[BootHistoryEntry]


class BootAlertResponse(BaseModel):
    """Boot security alert"""
    alert_id: str
    severity: str
    timestamp: str
    threat_type: str
    component: str
    description: str
    mitre_technique: str
    remediation: str
    acknowledged: bool


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.get("/status", response_model=SecureBootStatusResponse)
async def get_secure_boot_status():
    """
    Get current secure boot and UEFI status.
    
    Returns comprehensive information about:
    - UEFI mode and Secure Boot state
    - Key enrollment status (PK, KEK, db, dbx)
    - TPM presence and version
    - Virtualization-based security
    - Overall risk assessment
    """
    verifier = get_secure_boot_verifier()
    status = await verifier.get_secure_boot_status()
    
    # Determine risk level
    risk_level = "low"
    if not status.secure_boot_enabled:
        risk_level = "high"
    elif status.setup_mode:
        risk_level = "critical"
    elif not status.tpm_present:
        risk_level = "medium"
    elif not status.virtualization_based_security:
        risk_level = "medium"
    
    return SecureBootStatusResponse(
        platform=status.platform,
        uefi_mode=status.uefi_mode,
        secure_boot_enabled=status.secure_boot_enabled,
        secure_boot_enforced=status.secure_boot_enforced,
        setup_mode=status.setup_mode,
        pk_enrolled=status.pk_enrolled,
        kek_enrolled=status.kek_enrolled,
        db_enrolled=status.db_enrolled,
        dbx_enrolled=status.dbx_enrolled,
        measured_boot_supported=status.measured_boot_supported,
        tpm_present=status.tpm_present,
        tpm_version=status.tpm_version,
        virtualization_based_security=status.virtualization_based_security,
        last_check=status.last_check,
        risk_level=risk_level,
    )


@router.post("/scan", response_model=FirmwareScanResponse)
async def start_firmware_scan(
    request: FirmwareScanRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(check_permission("write")),
):
    """
    Start a firmware security scan.
    
    Scans:
    - UEFI firmware integrity
    - Boot loader signatures
    - Option ROMs
    - SMM/runtime drivers
    - ACPI tables
    
    Deep scan additionally checks:
    - Firmware module hashes
    - Embedded executables
    - Known vulnerability patterns
    """
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="tool_execution",
        actor=actor,
        payload={
            "operation": "secure_boot_scan",
            "scan_id": scan_id,
            "deep_scan": request.deep_scan,
            "check_updates": request.check_updates,
            "verify_signatures": request.verify_signatures,
        },
        impact_level="high",
        subject_id=scan_id,
        entity_refs=[scan_id],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="secure_boot_firmware_scan_gated",
        entity_refs=[scan_id, gated.get("queue_id"), gated.get("decision_id")],
        payload={"deep_scan": request.deep_scan, "actor": actor},
        trigger_triune=True,
    )
    return FirmwareScanResponse(
        scan_id=scan_id,
        status="queued_for_triune_approval",
        started_at=datetime.now(timezone.utc).isoformat(),
        completed_at=None,
        total_components=0,
        verified_components=0,
        suspicious_components=0,
        threats_detected=[],
        recommendations=[],
    )


@router.get("/scan/{scan_id}")
async def get_scan_results(scan_id: str):
    """
    Get results of a firmware scan.
    
    Returns detailed scan results including all analyzed
    components and any detected threats.
    """
    verifier = get_secure_boot_verifier()
    
    # Check if scan exists in history
    if scan_id not in verifier.scan_history:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")
    
    return verifier.scan_history[scan_id]


@router.get("/bootchain", response_model=BootChainResponse)
async def verify_boot_chain():
    """
    Verify the complete boot chain of trust.
    
    Validates each component in the boot sequence:
    1. UEFI PEI (Pre-EFI Initialization)
    2. UEFI DXE (Driver Execution Environment)
    3. UEFI BDS (Boot Device Selection)
    4. Boot Loader (GRUB, Windows Boot Manager, etc.)
    5. OS Kernel
    
    Returns chain integrity status and any breaks in trust.
    """
    verifier = get_secure_boot_verifier()
    result = await verifier.verify_boot_chain()
    
    return BootChainResponse(
        verified=result.verified,
        chain_intact=result.chain_intact,
        components=[
            {
                "order": i,
                "name": c.name,
                "type": c.component_type.value if hasattr(c.component_type, 'value') else str(c.component_type),
                "verified": c.signature_verified,
                "hash": c.hash,
                "signer": c.signer,
            }
            for i, c in enumerate(result.components)
        ],
        chain_of_trust=[
            {
                "from": result.components[i].name if i > 0 else "Root of Trust",
                "to": c.name,
                "trust_established": c.signature_verified,
            }
            for i, c in enumerate(result.components)
        ],
        issues=result.issues,
        mitre_techniques=result.mitre_techniques,
    )


@router.get("/firmware", response_model=FirmwareListResponse)
async def list_firmware_components(
    component_type: Optional[str] = Query(None, description="Filter by component type"),
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    update_available: Optional[bool] = Query(None, description="Filter by update availability"),
):
    """
    List all firmware components on the system.
    
    Returns inventory of:
    - UEFI drivers
    - Option ROMs  
    - ACPI tables
    - SMM modules
    - Boot loaders
    """
    verifier = get_secure_boot_verifier()
    components = await verifier.get_firmware_inventory()
    
    # Apply filters
    if component_type:
        components = [c for c in components if c.component_type == component_type]
    if vendor:
        components = [c for c in components if vendor.lower() in c.vendor.lower()]
    if update_available is not None:
        components = [c for c in components if c.update_available == update_available]
    
    return FirmwareListResponse(
        total=len(components),
        components=[
            FirmwareComponent(
                component_id=c.component_id,
                name=c.name,
                version=c.version,
                vendor=c.vendor,
                component_type=c.component_type,
                hash=c.hash,
                signature_valid=c.signature_valid,
                last_modified=c.last_modified,
                update_available=c.update_available,
            )
            for c in components
        ]
    )


@router.post("/firmware/verify", response_model=FirmwareVerifyResponse)
async def verify_firmware(
    request: FirmwareVerifyRequest,
    current_user: dict = Depends(check_permission("write")),
):
    """
    Verify integrity of firmware components.
    
    Checks:
    - Hash against known-good database
    - Signature validity
    - Version rollback protection
    - Tampering indicators
    """
    actor = current_user.get("email", current_user.get("id", "unknown"))
    verification_id = f"verify-{uuid.uuid4().hex[:10]}"
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="tool_execution",
        actor=actor,
        payload={
            "operation": "secure_boot_firmware_verify",
            "verification_id": verification_id,
            "component_ids": request.component_ids,
            "verify_against_known_good": request.verify_against_known_good,
            "check_rollback": request.check_rollback,
        },
        impact_level="high",
        subject_id=verification_id,
        entity_refs=(request.component_ids or [])[:10] + [verification_id],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="secure_boot_firmware_verify_gated",
        entity_refs=[verification_id, gated.get("queue_id"), gated.get("decision_id")],
        payload={"actor": actor, "component_count": len(request.component_ids or [])},
        trigger_triune=True,
    )
    return FirmwareVerifyResponse(
        verified=False,
        total_checked=0,
        passed=0,
        failed=0,
        results=[],
        threats=[],
    )


@router.get("/history", response_model=BootHistoryResponse)
async def get_boot_history(
    limit: int = Query(20, ge=1, le=100, description="Number of entries to return"),
    include_successful: bool = Query(True, description="Include successful boots"),
    include_failed: bool = Query(True, description="Include failed boots"),
):
    """
    Get boot verification history.
    
    Returns history of system boots with verification status
    and any security events detected during boot.
    """
    verifier = get_secure_boot_verifier()
    history = await verifier.get_boot_history(limit=limit)
    
    # Apply filters
    if not include_successful:
        history = [h for h in history if not h.boot_successful]
    if not include_failed:
        history = [h for h in history if h.boot_successful]
    
    successful = sum(1 for h in history if h.boot_successful)
    failed = len(history) - successful
    
    return BootHistoryResponse(
        total_boots=len(history),
        successful_boots=successful,
        failed_boots=failed,
        history=[
            BootHistoryEntry(
                boot_id=h.boot_id,
                timestamp=h.timestamp,
                boot_successful=h.boot_successful,
                secure_boot_active=h.secure_boot_active,
                chain_verified=h.chain_verified,
                threats_detected=h.threats_detected,
                boot_time_ms=h.boot_time_ms,
                notes=h.notes,
            )
            for h in history
        ]
    )


@router.get("/alerts")
async def get_boot_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    acknowledged: Optional[bool] = Query(None, description="Filter by acknowledgment status"),
    limit: int = Query(50, ge=1, le=200),
):
    """
    Get boot security alerts.
    
    Returns alerts generated by boot verification including:
    - Secure Boot violations
    - Signature failures
    - Boot chain breaks
    - Bootkit/rootkit detections
    """
    verifier = get_secure_boot_verifier()
    alerts = await verifier.get_alerts(limit=limit)
    
    # Apply filters
    if severity:
        alerts = [a for a in alerts if a.severity.lower() == severity.lower()]
    if acknowledged is not None:
        alerts = [a for a in alerts if a.acknowledged == acknowledged]
    
    return {
        "total": len(alerts),
        "alerts": [
            BootAlertResponse(
                alert_id=a.alert_id,
                severity=a.severity,
                timestamp=a.timestamp,
                threat_type=a.threat_type,
                component=a.component,
                description=a.description,
                mitre_technique=a.mitre_technique,
                remediation=a.remediation,
                acknowledged=a.acknowledged,
            )
            for a in alerts
        ]
    }


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    current_user: dict = Depends(check_permission("write")),
):
    """Acknowledge a boot security alert."""
    verifier = get_secure_boot_verifier()
    
    success = await verifier.acknowledge_alert(alert_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Alert not found: {alert_id}")
    
    ts = datetime.now(timezone.utc).isoformat()
    await emit_world_event(get_db(), event_type="secure_boot_alert_acknowledged", entity_refs=[alert_id], payload={"timestamp": ts}, trigger_triune=False)
    return {
        "message": f"Alert {alert_id} acknowledged",
        "timestamp": ts,
    }


@router.get("/mitre-coverage")
async def get_mitre_coverage():
    """
    Get MITRE ATT&CK coverage for boot threats.
    
    Returns mapping of detected/detectable boot-level
    threats to MITRE techniques.
    """
    return {
        "coverage": [
            {
                "technique": "T1542",
                "name": "Pre-OS Boot",
                "subtechniques": [
                    {"id": "T1542.001", "name": "System Firmware", "detectable": True},
                    {"id": "T1542.002", "name": "Component Firmware", "detectable": True},
                    {"id": "T1542.003", "name": "Bootkit", "detectable": True},
                ],
                "detection_method": "Boot chain verification, firmware hashing",
            },
            {
                "technique": "T1014",
                "name": "Rootkit",
                "subtechniques": [],
                "detectable": True,
                "detection_method": "Kernel integrity, driver signature verification",
            },
            {
                "technique": "T1553",
                "name": "Subvert Trust Controls",
                "subtechniques": [
                    {"id": "T1553.006", "name": "Code Signing Policy Modification", "detectable": True},
                ],
                "detection_method": "Secure Boot policy monitoring, key enrollment tracking",
            },
            {
                "technique": "T1601",
                "name": "Modify System Image",
                "subtechniques": [
                    {"id": "T1601.001", "name": "Patch System Image", "detectable": True},
                ],
                "detection_method": "Firmware version tracking, integrity measurement",
            },
        ],
        "total_techniques": 4,
        "total_subtechniques": 6,
    }


@router.get("/health")
async def health_check():
    """Health check for secure boot verification service."""
    verifier = get_secure_boot_verifier()
    
    try:
        status = await verifier.get_secure_boot_status()
        return {
            "status": "healthy",
            "secure_boot_available": status.uefi_mode,
            "secure_boot_enabled": status.secure_boot_enabled,
            "tpm_present": status.tpm_present,
            "last_scan": verifier.last_scan_time,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        return {
            "status": "degraded",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
