"""
Audit Logging Router
"""
from fastapi import APIRouter, Depends
from typing import Optional

from .dependencies import get_current_user, check_permission

# Import audit logging services
from audit_logging import audit, AuditCategory, AuditSeverity

router = APIRouter(prefix="/audit", tags=["Audit"])

@router.get("/logs")
async def get_audit_logs(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    actor: Optional[str] = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get audit logs with filtering"""
    category_enum = AuditCategory(category) if category else None
    severity_enum = AuditSeverity(severity) if severity else None
    
    logs = await audit.get_logs(
        category=category_enum,
        severity=severity_enum,
        actor=actor,
        limit=limit
    )
    return logs

@router.get("/stats")
async def get_audit_stats(current_user: dict = Depends(get_current_user)):
    """Get audit log statistics"""
    stats = await audit.get_stats()
    return stats

@router.get("/recent")
async def get_recent_audit(limit: int = 20, current_user: dict = Depends(get_current_user)):
    """Get recent audit entries"""
    logs = await audit.get_logs(limit=limit)
    return logs

@router.post("/cleanup")
async def cleanup_audit_logs(days: int = 90, current_user: dict = Depends(check_permission("manage_users"))):
    """Clean up old audit logs"""
    result = await audit.cleanup_old_logs(days)
    return result
