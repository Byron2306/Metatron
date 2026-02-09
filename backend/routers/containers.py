"""
Container Security Router
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional
from pydantic import BaseModel

from .dependencies import get_current_user, check_permission

# Import container security service
from container_security import container_security, ContainerSecurityManager

router = APIRouter(prefix="/containers", tags=["Container Security"])

class ScanImageRequest(BaseModel):
    image_name: str
    force: bool = False

@router.get("/stats")
async def get_container_stats(current_user: dict = Depends(get_current_user)):
    """Get container security statistics"""
    return container_security.get_stats()

@router.get("")
async def get_containers(current_user: dict = Depends(get_current_user)):
    """Get running containers with security info"""
    containers = await container_security.get_containers()
    return {"containers": containers, "count": len(containers)}

@router.get("/{container_id}/security")
async def check_container_security(container_id: str, current_user: dict = Depends(get_current_user)):
    """Run security check on a specific container"""
    result = await container_security.check_container(container_id)
    return result

@router.post("/scan")
async def scan_container_image(request: ScanImageRequest, current_user: dict = Depends(get_current_user)):
    """Scan a container image for vulnerabilities"""
    result = await container_security.scan_image(request.image_name, request.force)
    return result

@router.post("/scan-all")
async def scan_all_images(current_user: dict = Depends(check_permission("write"))):
    """Scan all local container images"""
    results = await container_security.scan_all_images()
    
    # Summary
    total_vulns = sum(r.get("total_vulnerabilities", 0) for r in results)
    critical = sum(r.get("critical_count", 0) for r in results)
    
    return {
        "images_scanned": len(results),
        "total_vulnerabilities": total_vulns,
        "critical_count": critical,
        "results": results
    }

@router.get("/scans/history")
async def get_scan_history(limit: int = 20, current_user: dict = Depends(get_current_user)):
    """Get container scan history"""
    # Return cached scan results
    scans = list(container_security.scanner.scan_cache.values())
    sorted_scans = sorted(scans, key=lambda x: x.scanned_at, reverse=True)
    
    from dataclasses import asdict
    return {
        "scans": [asdict(s) for s in sorted_scans[:limit]],
        "total": len(sorted_scans)
    }

@router.get("/runtime-events")
async def get_runtime_events(limit: int = 50, current_user: dict = Depends(get_current_user)):
    """Get container runtime security events"""
    events = await container_security.runtime_monitor.get_runtime_events(limit)
    return {"events": events, "count": len(events)}
