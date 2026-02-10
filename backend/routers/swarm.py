"""
Swarm Management Router
=======================
Manages the agent swarm - discovery, deployment, telemetry.
"""
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import Optional, List
from pydantic import BaseModel
from datetime import datetime, timezone

from .dependencies import get_current_user, check_permission, db

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/swarm", tags=["Swarm Management"])


# =============================================================================
# MODELS
# =============================================================================

class ScanNetworkRequest(BaseModel):
    network: Optional[str] = None  # e.g., "192.168.1.0/24"


class DeployAgentRequest(BaseModel):
    device_ip: str
    credentials: Optional[dict] = None


class DeploymentCredentials(BaseModel):
    method: str  # "ssh" or "winrm"
    username: str
    password: Optional[str] = None
    key_path: Optional[str] = None


class TelemetryIngestRequest(BaseModel):
    events: List[dict]


# =============================================================================
# NETWORK DISCOVERY
# =============================================================================

@router.get("/devices")
async def get_discovered_devices(
    status: Optional[str] = None,
    os_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get all discovered devices"""
    query = {}
    if status:
        query["deployment_status"] = status
    if os_type:
        query["os_type"] = os_type
    
    cursor = db.discovered_devices.find(query, {"_id": 0})
    devices = await cursor.to_list(500)
    
    # Calculate stats
    stats = {
        "total": len(devices),
        "managed": sum(1 for d in devices if d.get("is_managed")),
        "unmanaged": sum(1 for d in devices if not d.get("is_managed")),
        "by_os": {},
        "by_status": {},
        "high_risk": sum(1 for d in devices if d.get("risk_score", 0) >= 50)
    }
    
    for d in devices:
        os_type = d.get("os_type", "unknown")
        stats["by_os"][os_type] = stats["by_os"].get(os_type, 0) + 1
        
        status = d.get("deployment_status", "discovered")
        stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
    
    return {"devices": devices, "stats": stats}


@router.post("/scan")
async def trigger_network_scan(
    request: ScanNetworkRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(check_permission("write"))
):
    """Trigger a network scan"""
    from services.network_discovery import get_network_discovery
    
    discovery = get_network_discovery()
    if discovery is None:
        raise HTTPException(status_code=503, detail="Network discovery service not running")
    
    # Run scan in background
    async def run_scan():
        await discovery.trigger_manual_scan(request.network)
    
    background_tasks.add_task(run_scan)
    
    return {"message": "Network scan initiated", "network": request.network or "all"}


@router.get("/scan/status")
async def get_scan_status(current_user: dict = Depends(get_current_user)):
    """Get current scan status"""
    from services.network_discovery import get_network_discovery
    
    discovery = get_network_discovery()
    if discovery is None:
        return {"running": False, "message": "Discovery service not active"}
    
    return {
        "running": discovery.running,
        "devices_found": len(discovery.discovered_devices),
        "last_scan": discovery.discovered_devices and max(
            d.last_seen for d in discovery.discovered_devices.values()
        ) if discovery.discovered_devices else None
    }


# =============================================================================
# AGENT DEPLOYMENT
# =============================================================================

@router.post("/deploy")
async def deploy_agent_to_device(
    request: DeployAgentRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Deploy agent to a specific device"""
    from services.agent_deployment import get_deployment_service
    
    service = get_deployment_service()
    if service is None:
        raise HTTPException(status_code=503, detail="Deployment service not running")
    
    # Get device info
    device = await db.discovered_devices.find_one({"ip_address": request.device_ip}, {"_id": 0})
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    task = await service.queue_deployment(
        device_ip=request.device_ip,
        device_hostname=device.get("hostname"),
        os_type=device.get("os_type", "unknown"),
        credentials=request.credentials
    )
    
    return {
        "message": "Deployment queued",
        "device_ip": request.device_ip,
        "status": task.status
    }


@router.post("/deploy/batch")
async def deploy_agents_batch(
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(check_permission("write"))
):
    """Deploy agents to all deployable devices"""
    from services.agent_deployment import get_deployment_service
    
    service = get_deployment_service()
    if service is None:
        raise HTTPException(status_code=503, detail="Deployment service not running")
    
    # Get deployable devices
    cursor = db.discovered_devices.find({
        "deployment_status": {"$in": ["discovered", "failed"]},
        "os_type": {"$in": ["windows", "linux", "macos"]},
        "device_type": {"$in": ["workstation", "server"]}
    }, {"_id": 0})
    devices = await cursor.to_list(100)
    
    async def deploy_all():
        for device in devices:
            await service.queue_deployment(
                device_ip=device["ip_address"],
                device_hostname=device.get("hostname"),
                os_type=device.get("os_type", "unknown")
            )
    
    background_tasks.add_task(deploy_all)
    
    return {
        "message": f"Batch deployment initiated for {len(devices)} devices",
        "devices": [d["ip_address"] for d in devices]
    }


@router.get("/deployment/status")
async def get_deployment_status(
    device_ip: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get deployment task status"""
    from services.agent_deployment import get_deployment_service
    
    service = get_deployment_service()
    if service is None:
        return {"tasks": [], "message": "Deployment service not running"}
    
    tasks = await service.get_deployment_status(device_ip)
    
    return {
        "tasks": tasks,
        "queue_size": service.deployment_queue.qsize() if service else 0
    }


@router.post("/deployment/retry")
async def retry_failed_deployments(
    current_user: dict = Depends(check_permission("write"))
):
    """Retry all failed deployments"""
    from services.agent_deployment import get_deployment_service
    
    service = get_deployment_service()
    if service is None:
        raise HTTPException(status_code=503, detail="Deployment service not running")
    
    count = await service.retry_failed_deployments()
    
    return {"message": f"Retrying {count} failed deployments"}


@router.post("/credentials")
async def set_deployment_credentials(
    credentials: DeploymentCredentials,
    current_user: dict = Depends(check_permission("admin"))
):
    """Set default deployment credentials"""
    from services.agent_deployment import get_deployment_service
    
    service = get_deployment_service()
    if service is None:
        raise HTTPException(status_code=503, detail="Deployment service not running")
    
    creds = {}
    if credentials.username:
        creds["username"] = credentials.username
    if credentials.password:
        creds["password"] = credentials.password
    if credentials.key_path:
        creds["key_path"] = credentials.key_path
    
    service.set_credentials(credentials.method, creds)
    
    return {"message": f"Credentials updated for {credentials.method}"}


# =============================================================================
# TELEMETRY INGESTION
# =============================================================================

@router.post("/telemetry/ingest")
async def ingest_telemetry(request: TelemetryIngestRequest):
    """Ingest telemetry events from agents"""
    
    events = request.events
    if not events:
        return {"status": "ok", "ingested": 0}
    
    # Process and store events
    now = datetime.now(timezone.utc).isoformat()
    
    for event in events:
        event["ingested_at"] = now
        
        # Determine severity for alerting
        severity = event.get("severity", "info")
        
        # Store in telemetry collection
        await db.agent_telemetry.insert_one(event)
        
        # Create alert for high severity events
        if severity in ("critical", "high"):
            await db.alerts.insert_one({
                "type": "telemetry",
                "severity": severity,
                "source": event.get("host_id", "unknown"),
                "event_type": event.get("event_type"),
                "message": event.get("data", {}).get("message", "Security event detected"),
                "data": event.get("data"),
                "timestamp": now,
                "status": "open"
            })
    
    logger.info(f"Ingested {len(events)} telemetry events")
    
    return {"status": "ok", "ingested": len(events)}


@router.get("/telemetry")
async def get_telemetry(
    host_id: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get telemetry events"""
    query = {}
    if host_id:
        query["host_id"] = host_id
    if event_type:
        query["event_type"] = event_type
    if severity:
        query["severity"] = severity
    
    cursor = db.agent_telemetry.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit)
    events = await cursor.to_list(limit)
    
    return {"events": events, "count": len(events)}


@router.get("/telemetry/stats")
async def get_telemetry_stats(current_user: dict = Depends(get_current_user)):
    """Get telemetry statistics"""
    
    # Get event counts by type
    pipeline = [
        {"$group": {
            "_id": "$event_type",
            "count": {"$sum": 1}
        }}
    ]
    by_type = await db.agent_telemetry.aggregate(pipeline).to_list(50)
    
    # Get counts by severity
    pipeline = [
        {"$group": {
            "_id": "$severity",
            "count": {"$sum": 1}
        }}
    ]
    by_severity = await db.agent_telemetry.aggregate(pipeline).to_list(10)
    
    # Get counts by host
    pipeline = [
        {"$group": {
            "_id": "$host_id",
            "count": {"$sum": 1}
        }},
        {"$sort": {"count": -1}},
        {"$limit": 20}
    ]
    by_host = await db.agent_telemetry.aggregate(pipeline).to_list(20)
    
    total = await db.agent_telemetry.count_documents({})
    
    return {
        "total_events": total,
        "by_type": {item["_id"]: item["count"] for item in by_type if item["_id"]},
        "by_severity": {item["_id"]: item["count"] for item in by_severity if item["_id"]},
        "by_host": {item["_id"]: item["count"] for item in by_host if item["_id"]}
    }


# =============================================================================
# SWARM OVERVIEW
# =============================================================================

@router.get("/overview")
async def get_swarm_overview(current_user: dict = Depends(get_current_user)):
    """Get swarm overview statistics"""
    
    # Count devices
    total_devices = await db.discovered_devices.count_documents({})
    managed_devices = await db.discovered_devices.count_documents({"is_managed": True})
    
    # Count agents
    total_agents = await db.agents.count_documents({})
    online_agents = await db.agents.count_documents({"status": "online"})
    
    # Recent telemetry
    recent_events = await db.agent_telemetry.count_documents({})
    critical_events = await db.agent_telemetry.count_documents({"severity": "critical"})
    
    # Deployment stats
    deployments = await db.deployment_tasks.count_documents({})
    successful = await db.deployment_tasks.count_documents({"status": "deployed"})
    failed = await db.deployment_tasks.count_documents({"status": "failed"})
    
    return {
        "devices": {
            "total": total_devices,
            "managed": managed_devices,
            "unmanaged": total_devices - managed_devices
        },
        "agents": {
            "total": total_agents,
            "online": online_agents,
            "offline": total_agents - online_agents
        },
        "telemetry": {
            "total_events": recent_events,
            "critical": critical_events
        },
        "deployments": {
            "total": deployments,
            "successful": successful,
            "failed": failed,
            "success_rate": (successful / deployments * 100) if deployments > 0 else 0
        }
    }
