"""
CSPM (Cloud Security Posture Management) API Router
====================================================
REST API endpoints for multi-cloud security posture management.

Endpoints:
- POST /api/v1/cspm/scan - Start a new scan
- GET /api/v1/cspm/scans - List scan history
- GET /api/v1/cspm/scans/{scan_id} - Get scan details
- GET /api/v1/cspm/posture - Get overall security posture
- GET /api/v1/cspm/findings - List all findings
- GET /api/v1/cspm/findings/{finding_id} - Get finding details
- PUT /api/v1/cspm/findings/{finding_id}/status - Update finding status
- GET /api/v1/cspm/resources - List discovered resources
- GET /api/v1/cspm/compliance/{framework} - Get compliance report
- GET /api/v1/cspm/providers - List configured providers
- POST /api/v1/cspm/providers - Configure a provider
- DELETE /api/v1/cspm/providers/{provider} - Remove provider
- GET /api/v1/cspm/checks - List available security checks
- PUT /api/v1/cspm/checks/{check_id} - Enable/disable check
- GET /api/v1/cspm/export - Export findings
- GET /api/v1/cspm/dashboard - Dashboard statistics
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from enum import Enum

from cspm_engine import (
    CSPMEngine, get_cspm_engine,
    CloudProvider, Severity, ResourceType, ComplianceFramework,
    FindingStatus, CloudCredentials, Finding, ScanResult
)
from cspm_aws_scanner import AWSScanner
from cspm_azure_scanner import AzureScanner
from cspm_gcp_scanner import GCPScanner

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cspm", tags=["CSPM"])


# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class ProviderConfig(BaseModel):
    """Cloud provider configuration"""
    provider: CloudProvider
    account_id: str
    region: Optional[str] = None
    
    # AWS
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    aws_role_arn: Optional[str] = None
    
    # Azure
    azure_tenant_id: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None
    azure_subscription_id: Optional[str] = None
    
    # GCP
    gcp_project_id: Optional[str] = None
    gcp_service_account_key_path: Optional[str] = None


class ScanRequest(BaseModel):
    """Request to start a CSPM scan"""
    providers: Optional[List[CloudProvider]] = None
    regions: Optional[List[str]] = None
    resource_types: Optional[List[ResourceType]] = None
    check_ids: Optional[List[str]] = None
    severity_filter: Optional[List[Severity]] = None


class FindingStatusUpdate(BaseModel):
    """Update finding status"""
    status: FindingStatus
    reason: Optional[str] = None
    updated_by: str = "system"


class CheckToggle(BaseModel):
    """Enable/disable a check"""
    enabled: bool
    auto_remediate: bool = False


class PostureResponse(BaseModel):
    """Security posture response"""
    overall_score: float
    grade: str
    total_resources: int
    total_findings: int
    open_findings: int
    severity_breakdown: Dict[str, int]
    provider_breakdown: Dict[str, int]
    last_scan: Optional[str]
    trend: str


class DashboardStats(BaseModel):
    """Dashboard statistics"""
    posture: PostureResponse
    recent_scans: List[Dict[str, Any]]
    top_risks: List[Dict[str, Any]]
    compliance_summary: Dict[str, float]
    resource_counts: Dict[str, int]
    findings_by_category: Dict[str, int]


# =============================================================================
# STATE
# =============================================================================

# In-memory state (would use database in production)
_configured_providers: Dict[CloudProvider, CloudCredentials] = {}
_active_scans: Dict[str, ScanResult] = {}


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.post("/providers", summary="Configure a cloud provider")
async def configure_provider(config: ProviderConfig) -> Dict[str, Any]:
    """
    Configure credentials for a cloud provider.
    
    - **provider**: Cloud provider (aws, azure, gcp)
    - **account_id**: Account/subscription/project identifier
    - **credentials**: Provider-specific credentials
    """
    credentials = CloudCredentials(
        provider=config.provider,
        account_id=config.account_id,
        region=config.region,
        aws_access_key=config.aws_access_key,
        aws_secret_key=config.aws_secret_key,
        aws_role_arn=config.aws_role_arn,
        azure_tenant_id=config.azure_tenant_id,
        azure_client_id=config.azure_client_id,
        azure_client_secret=config.azure_client_secret,
        azure_subscription_id=config.azure_subscription_id,
        gcp_project_id=config.gcp_project_id,
        gcp_service_account_key=config.gcp_service_account_key_path,
    )
    
    if not credentials.validate():
        raise HTTPException(status_code=400, detail="Invalid credentials for provider")
    
    # Store credentials
    _configured_providers[config.provider] = credentials
    
    # Register scanner with engine
    engine = get_cspm_engine()
    if config.provider == CloudProvider.AWS:
        engine.register_scanner(AWSScanner(credentials))
    elif config.provider == CloudProvider.AZURE:
        engine.register_scanner(AzureScanner(credentials))
    elif config.provider == CloudProvider.GCP:
        engine.register_scanner(GCPScanner(credentials))
    
    logger.info(f"Configured provider: {config.provider.value}")
    
    return {
        "status": "configured",
        "provider": config.provider.value,
        "account_id": config.account_id,
    }


@router.get("/providers", summary="List configured providers")
async def list_providers() -> List[Dict[str, Any]]:
    """Get list of configured cloud providers"""
    return [
        {
            "provider": provider.value,
            "account_id": creds.account_id,
            "configured": True,
        }
        for provider, creds in _configured_providers.items()
    ]


@router.delete("/providers/{provider}", summary="Remove provider configuration")
async def remove_provider(provider: CloudProvider) -> Dict[str, str]:
    """Remove a cloud provider configuration"""
    if provider in _configured_providers:
        del _configured_providers[provider]
        return {"status": "removed", "provider": provider.value}
    raise HTTPException(status_code=404, detail="Provider not configured")


@router.post("/scan", summary="Start a CSPM scan")
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """
    Start a new cloud security posture scan.
    
    - **providers**: List of providers to scan (default: all configured)
    - **regions**: Specific regions to scan (default: all)
    - **resource_types**: Filter by resource types
    - **check_ids**: Specific checks to run
    - **severity_filter**: Filter findings by severity
    """
    engine = get_cspm_engine()
    
    if not engine.scanners:
        raise HTTPException(
            status_code=400, 
            detail="No cloud providers configured. Add providers first."
        )
    
    # Generate scan ID
    import uuid
    scan_id = str(uuid.uuid4())
    
    # Start scan in background
    async def run_scan():
        try:
            results = await engine.scan_all(
                providers=request.providers,
                regions=request.regions,
                resource_types=request.resource_types,
                check_ids=request.check_ids,
                severity_filter=request.severity_filter,
            )
            # Store results
            for provider, result in results.items():
                _active_scans[result.scan_id] = result
        except Exception as e:
            logger.error(f"Scan failed: {e}")
    
    background_tasks.add_task(run_scan)
    
    return {
        "status": "started",
        "scan_id": scan_id,
        "providers": [p.value for p in (request.providers or list(engine.scanners.keys()))],
        "started_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/scans", summary="List scan history")
async def list_scans(
    limit: int = Query(20, ge=1, le=100),
    provider: Optional[CloudProvider] = None,
) -> List[Dict[str, Any]]:
    """Get list of historical scans"""
    engine = get_cspm_engine()
    scans = engine.scan_history[-limit:]
    
    if provider:
        scans = [s for s in scans if s.provider == provider]
    
    return [
        {
            "scan_id": s.scan_id,
            "provider": s.provider.value,
            "status": s.status,
            "started_at": s.started_at,
            "completed_at": s.completed_at,
            "resources_scanned": s.resources_scanned,
            "findings_count": s.findings_count,
            "critical_count": s.critical_count,
            "high_count": s.high_count,
        }
        for s in reversed(scans)
    ]


@router.get("/scans/{scan_id}", summary="Get scan details")
async def get_scan(scan_id: str) -> Dict[str, Any]:
    """Get detailed results of a specific scan"""
    engine = get_cspm_engine()
    
    for scan in engine.scan_history:
        if scan.scan_id == scan_id:
            return scan.to_dict()
    
    if scan_id in _active_scans:
        return _active_scans[scan_id].to_dict()
    
    raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/posture", summary="Get security posture")
async def get_posture() -> PostureResponse:
    """Get overall cloud security posture summary"""
    engine = get_cspm_engine()
    posture = engine.get_security_posture()
    return PostureResponse(**posture)


@router.get("/findings", summary="List findings")
async def list_findings(
    severity: Optional[Severity] = None,
    provider: Optional[CloudProvider] = None,
    status: Optional[FindingStatus] = Query(FindingStatus.OPEN),
    category: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """
    List security findings with filtering.
    
    - **severity**: Filter by severity level
    - **provider**: Filter by cloud provider
    - **status**: Filter by status (default: open)
    - **category**: Filter by category (iam, storage, network, etc.)
    """
    engine = get_cspm_engine()
    findings = list(engine.findings_db.values())
    
    # Apply filters
    if severity:
        findings = [f for f in findings if f.severity == severity]
    if provider:
        findings = [f for f in findings if f.provider == provider]
    if status:
        findings = [f for f in findings if f.status == status]
    if category:
        findings = [f for f in findings if f.category.lower() == category.lower()]
    
    # Sort by severity (critical first)
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.risk_score), reverse=False)
    
    total = len(findings)
    findings = findings[offset:offset + limit]
    
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "findings": [f.to_dict() for f in findings],
    }


@router.get("/findings/{finding_id}", summary="Get finding details")
async def get_finding(finding_id: str) -> Dict[str, Any]:
    """Get detailed information about a specific finding"""
    engine = get_cspm_engine()
    
    if finding_id in engine.findings_db:
        return engine.findings_db[finding_id].to_dict()
    
    raise HTTPException(status_code=404, detail="Finding not found")


@router.put("/findings/{finding_id}/status", summary="Update finding status")
async def update_finding_status(
    finding_id: str,
    update: FindingStatusUpdate
) -> Dict[str, Any]:
    """
    Update the status of a finding.
    
    - **status**: New status (resolved, suppressed, false_positive, in_progress)
    - **reason**: Reason for status change (required for suppression)
    - **updated_by**: User making the change
    """
    engine = get_cspm_engine()
    
    if finding_id not in engine.findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    if update.status == FindingStatus.SUPPRESSED:
        if not update.reason:
            raise HTTPException(status_code=400, detail="Reason required for suppression")
        engine.suppress_finding(finding_id, update.reason, update.updated_by)
    elif update.status == FindingStatus.RESOLVED:
        engine.resolve_finding(finding_id, update.reason or "Manually resolved")
    else:
        engine.findings_db[finding_id].status = update.status
    
    return {
        "finding_id": finding_id,
        "status": update.status.value,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/resources", summary="List discovered resources")
async def list_resources(
    provider: Optional[CloudProvider] = None,
    resource_type: Optional[ResourceType] = None,
    is_public: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """List discovered cloud resources with filtering"""
    engine = get_cspm_engine()
    resources = list(engine.resources_db.values())
    
    if provider:
        resources = [r for r in resources if r.provider == provider]
    if resource_type:
        resources = [r for r in resources if r.resource_type == resource_type]
    if is_public is not None:
        resources = [r for r in resources if r.is_public == is_public]
    
    total = len(resources)
    resources = resources[offset:offset + limit]
    
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "resources": [r.to_dict() for r in resources],
    }


@router.get("/compliance/{framework}", summary="Get compliance report")
async def get_compliance_report(framework: ComplianceFramework) -> Dict[str, Any]:
    """
    Get compliance report for a specific framework.
    
    Supported frameworks:
    - CIS AWS/Azure/GCP benchmarks
    - NIST 800-53, NIST CSF
    - SOC2, PCI-DSS 4.0, HIPAA, GDPR
    - ISO 27001
    """
    engine = get_cspm_engine()
    return engine.get_compliance_report(framework)


@router.get("/checks", summary="List security checks")
async def list_checks(
    provider: Optional[CloudProvider] = None,
    category: Optional[str] = None,
    enabled_only: bool = False,
) -> List[Dict[str, Any]]:
    """List available security checks"""
    engine = get_cspm_engine()
    checks = []
    
    for scanner in engine.scanners.values():
        if provider and scanner.provider != provider:
            continue
        
        for check in scanner.checks.values():
            if enabled_only and not check.enabled:
                continue
            if category and check.category.lower() != category.lower():
                continue
            
            checks.append({
                "check_id": check.check_id,
                "title": check.title,
                "description": check.description,
                "severity": check.severity.value,
                "provider": scanner.provider.value,
                "category": check.category,
                "subcategory": check.subcategory,
                "enabled": check.enabled,
                "auto_remediate": check.auto_remediate,
                "cis_controls": check.cis_controls,
                "mitre_techniques": check.mitre_techniques,
            })
    
    return checks


@router.put("/checks/{check_id}", summary="Toggle security check")
async def toggle_check(check_id: str, toggle: CheckToggle) -> Dict[str, Any]:
    """Enable or disable a security check"""
    engine = get_cspm_engine()
    
    for scanner in engine.scanners.values():
        if check_id in scanner.checks:
            scanner.checks[check_id].enabled = toggle.enabled
            scanner.checks[check_id].auto_remediate = toggle.auto_remediate
            return {
                "check_id": check_id,
                "enabled": toggle.enabled,
                "auto_remediate": toggle.auto_remediate,
            }
    
    raise HTTPException(status_code=404, detail="Check not found")


@router.get("/export", summary="Export findings")
async def export_findings(
    format: str = Query("json", regex="^(json|csv)$"),
    severity: Optional[Severity] = None,
    provider: Optional[CloudProvider] = None,
) -> Dict[str, Any]:
    """
    Export findings in JSON or CSV format.
    
    - **format**: Export format (json or csv)
    - **severity**: Filter by severity
    - **provider**: Filter by provider
    """
    engine = get_cspm_engine()
    
    # Apply filters before export
    findings = list(engine.findings_db.values())
    if severity:
        findings = [f for f in findings if f.severity == severity]
    if provider:
        findings = [f for f in findings if f.provider == provider]
    
    # Temporarily replace findings for export
    original_findings = engine.findings_db
    engine.findings_db = {f.finding_id: f for f in findings}
    
    try:
        export_data = engine.export_findings(format)
    finally:
        engine.findings_db = original_findings
    
    return {
        "format": format,
        "count": len(findings),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "data": export_data,
    }


@router.get("/dashboard", summary="Get dashboard statistics")
async def get_dashboard() -> DashboardStats:
    """Get comprehensive dashboard statistics"""
    engine = get_cspm_engine()
    posture = engine.get_security_posture()
    
    # Recent scans
    recent_scans = [
        {
            "scan_id": s.scan_id,
            "provider": s.provider.value,
            "completed_at": s.completed_at,
            "findings_count": s.findings_count,
        }
        for s in engine.scan_history[-5:]
    ]
    
    # Top risks (highest risk score findings)
    open_findings = [f for f in engine.findings_db.values() if f.status == FindingStatus.OPEN]
    top_risks = sorted(open_findings, key=lambda f: f.risk_score, reverse=True)[:10]
    
    # Compliance summary
    compliance_summary = {}
    for framework in [ComplianceFramework.CIS_AWS_2_0, ComplianceFramework.NIST_800_53, 
                      ComplianceFramework.SOC2, ComplianceFramework.PCI_DSS_4_0]:
        report = engine.get_compliance_report(framework)
        compliance_summary[framework.value] = report.get("compliance_percentage", 100)
    
    # Resource counts by type
    resource_counts = {}
    for resource in engine.resources_db.values():
        rt = resource.resource_type.value
        resource_counts[rt] = resource_counts.get(rt, 0) + 1
    
    # Findings by category
    findings_by_category = {}
    for finding in open_findings:
        cat = finding.category
        findings_by_category[cat] = findings_by_category.get(cat, 0) + 1
    
    return DashboardStats(
        posture=PostureResponse(**posture),
        recent_scans=recent_scans,
        top_risks=[
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity.value,
                "risk_score": f.risk_score,
                "resource_id": f.resource.resource_id,
            }
            for f in top_risks
        ],
        compliance_summary=compliance_summary,
        resource_counts=resource_counts,
        findings_by_category=findings_by_category,
    )


@router.get("/stats", summary="Get CSPM statistics")
async def get_stats() -> Dict[str, Any]:
    """Get CSPM engine statistics"""
    engine = get_cspm_engine()
    return {
        "total_scans": engine.stats["total_scans"],
        "total_findings": engine.stats["total_findings"],
        "total_resources": engine.stats["total_resources"],
        "scans_by_provider": dict(engine.stats["scans_by_provider"]),
        "findings_by_severity": dict(engine.stats["findings_by_severity"]),
        "configured_providers": len(_configured_providers),
        "active_scans": len(_active_scans),
    }
