"""
Container Security Router
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Optional
from pydantic import BaseModel

from .dependencies import get_current_user, check_permission, get_db

# Import container security service
from container_security import container_security, ContainerSecurityManager

router = APIRouter(prefix="/containers", tags=["Container Security"])

class ScanImageRequest(BaseModel):
    image_name: str
    force: bool = False

@router.get("/stats")
async def get_container_stats(current_user: dict = Depends(get_current_user)):
    """Get container security statistics"""
    db = get_db()
    
    # Get stats from service
    service_stats = container_security.get_stats()
    
    # Also get from database
    total_scans = await db.container_scans.count_documents({})
    total_containers = await db.containers.count_documents({})
    total_events = await db.container_runtime_events.count_documents({})
    
    # Count vulnerabilities from scans
    scans = await db.container_scans.find({}, {"_id": 0}).to_list(100)
    critical_vulns = sum(s.get("critical_count", 0) for s in scans)
    high_vulns = sum(s.get("high_count", 0) for s in scans)
    
    return {
        **service_stats,
        "total_scans": total_scans,
        "total_containers": total_containers,
        "runtime_events": total_events,
        "critical_vulnerabilities": critical_vulns,
        "high_vulnerabilities": high_vulns
    }

@router.get("")
async def get_containers(current_user: dict = Depends(get_current_user)):
    """Get running containers with security info"""
    db = get_db()
    
    # Try to get from Docker first
    containers = await container_security.get_containers()
    
    # If empty, get from database (sample data)
    if not containers:
        containers = await db.containers.find({}, {"_id": 0}).to_list(100)
    
    return {"containers": containers, "count": len(containers)}

@router.get("/{container_id}/security")
async def check_container_security(container_id: str, current_user: dict = Depends(get_current_user)):
    """Run security check on a specific container"""
    result = await container_security.check_container(container_id)
    return result

@router.post("/scan")
async def scan_container_image(request: ScanImageRequest, current_user: dict = Depends(get_current_user)):
    """Scan a container image for vulnerabilities"""
    db = get_db()
    result = await container_security.scan_image(request.image_name, request.force)
    
    # Store in database
    await db.container_scans.update_one(
        {"image_name": request.image_name},
        {"$set": result},
        upsert=True
    )
    
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
    db = get_db()
    
    # Get from database
    scans = await db.container_scans.find({}, {"_id": 0}).sort("scanned_at", -1).to_list(limit)
    
    return {
        "scans": scans,
        "total": len(scans)
    }

@router.get("/runtime-events")
async def get_runtime_events(limit: int = 50, current_user: dict = Depends(get_current_user)):
    """Get container runtime security events"""
    db = get_db()
    
    events = await db.container_runtime_events.find({}, {"_id": 0}).sort("timestamp", -1).to_list(limit)
    
    return {"events": events, "count": len(events)}


# =========================================================================
# Falco Runtime Security
# =========================================================================

@router.get("/falco/status")
async def get_falco_status(current_user: dict = Depends(get_current_user)):
    """Get Falco runtime security status"""
    status = await container_security.get_runtime_security_status()
    return status


@router.get("/falco/alerts")
async def get_falco_alerts(
    limit: int = 50,
    priority: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Get recent Falco alerts"""
    alerts = container_security.falco.get_alerts(limit=limit, priority=priority)
    return {"alerts": alerts, "count": len(alerts)}


@router.get("/falco/escape-attempts")
async def get_escape_attempts(limit: int = 50, current_user: dict = Depends(get_current_user)):
    """Get container escape attempt detections"""
    attempts = container_security.falco.get_escape_attempts(limit=limit)
    return {"attempts": attempts, "count": len(attempts)}


# =========================================================================
# Suricata IDS
# =========================================================================

@router.get("/suricata/alerts")
async def get_suricata_alerts(limit: int = 100, current_user: dict = Depends(get_current_user)):
    """Get recent Suricata IDS alerts from eve.json"""
    import json as _json
    from pathlib import Path

    eve_path = Path("/var/log/suricata/eve.json")
    alerts = []

    if not eve_path.exists():
        return {"alerts": [], "count": 0, "available": False,
                "message": "Suricata eve.json not found – mount suricata_logs volume"}

    try:
        # Read last N lines efficiently
        with open(eve_path, "r") as f:
            lines = f.readlines()

        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                evt = _json.loads(line)
                if evt.get("event_type") == "alert":
                    alerts.append({
                        "timestamp": evt.get("timestamp"),
                        "src_ip": evt.get("src_ip"),
                        "src_port": evt.get("src_port"),
                        "dest_ip": evt.get("dest_ip"),
                        "dest_port": evt.get("dest_port"),
                        "proto": evt.get("proto"),
                        "alert": evt.get("alert", {}),
                    })
                    if len(alerts) >= limit:
                        break
            except _json.JSONDecodeError:
                continue
    except Exception as e:
        return {"alerts": [], "count": 0, "available": True,
                "error": str(e)}

    return {"alerts": alerts, "count": len(alerts), "available": True}


@router.get("/suricata/stats")
async def get_suricata_stats(current_user: dict = Depends(get_current_user)):
    """Get Suricata IDS statistics from stats.log"""
    from pathlib import Path

    stats_path = Path("/var/log/suricata/stats.log")
    eve_path = Path("/var/log/suricata/eve.json")

    available = eve_path.exists() or stats_path.exists()
    alert_count = 0

    if eve_path.exists():
        try:
            with open(eve_path, "r") as f:
                for line in f:
                    if '"event_type":"alert"' in line or '"event_type": "alert"' in line:
                        alert_count += 1
        except Exception:
            pass

    return {
        "available": available,
        "eve_json_exists": eve_path.exists(),
        "stats_log_exists": stats_path.exists(),
        "total_alerts": alert_count,
    }


# =========================================================================
# YARA Scanning
# =========================================================================

@router.get("/yara/status")
async def get_yara_status(current_user: dict = Depends(get_current_user)):
    """Check YARA availability and rule count"""
    import subprocess
    from pathlib import Path

    yara_available = False
    yara_version = None
    try:
        result = subprocess.run(
            ["yara", "--version"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            yara_available = True
            yara_version = result.stdout.strip()
    except Exception:
        pass

    # Count rules in common locations
    rule_dirs = [
        Path("/app/yara_rules"),
        Path("/etc/yara/rules"),
        Path("/var/lib/seraph-ai/yara_rules"),
    ]
    rule_count = 0
    for d in rule_dirs:
        if d.exists():
            rule_count += sum(1 for _ in d.glob("**/*.yar")) + sum(
                1 for _ in d.glob("**/*.yara")
            )

    return {
        "available": yara_available,
        "version": yara_version,
        "rule_count": rule_count,
    }


# =========================================================================
# Tooling Status (unified view)
# =========================================================================

@router.get("/tooling-status")
async def get_security_tooling_status(current_user: dict = Depends(get_current_user)):
    """Get unified status of all security tooling (Trivy, Falco, Suricata, YARA)"""
    import subprocess
    from pathlib import Path

    def _check_binary(name):
        try:
            r = subprocess.run([name, "--version"], capture_output=True, text=True, timeout=5)
            return r.returncode == 0, r.stdout.strip()
        except Exception:
            return False, None

    trivy_ok, trivy_ver = _check_binary("trivy")
    yara_ok, yara_ver = _check_binary("yara")

    falco_status = await container_security.get_runtime_security_status()

    suricata_eve = Path("/var/log/suricata/eve.json").exists()

    return {
        "trivy": {
            "available": trivy_ok,
            "version": trivy_ver,
            "server": container_security.scanner.trivy_path is not None,
        },
        "falco": {
            "available": falco_status.get("falco_available", False),
            "monitoring": falco_status.get("falco_monitoring", False),
            "alert_count": len(container_security.falco.alerts),
        },
        "suricata": {
            "available": suricata_eve,
            "eve_json": suricata_eve,
        },
        "yara": {
            "available": yara_ok,
            "version": yara_ver,
        },
    }
