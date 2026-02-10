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


class CLIEventRequest(BaseModel):
    host_id: str
    session_id: str
    command: str
    user: Optional[str] = None
    shell_type: Optional[str] = None
    timestamp: Optional[str] = None


class ScannerReportRequest(BaseModel):
    scanner_id: str
    network: str
    scan_time: str
    devices: List[dict]


class AgentRegistrationRequest(BaseModel):
    agent_id: str
    hostname: str
    os_type: str
    version: str
    ip_address: Optional[str] = None


class AgentHeartbeatRequest(BaseModel):
    status: str = "online"
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    uptime: Optional[int] = None


# =============================================================================
# AGENT REGISTRATION & HEARTBEAT
# =============================================================================

@router.post("/agents/register")
async def register_agent(request: AgentRegistrationRequest):
    """Register a new Seraph Defender agent"""
    now = datetime.now(timezone.utc).isoformat()
    
    agent_doc = {
        "agent_id": request.agent_id,
        "hostname": request.hostname,
        "os": request.os_type,
        "version": request.version,
        "ip_address": request.ip_address,
        "status": "online",
        "first_seen": now,
        "last_seen": now
    }
    
    await db.agents.update_one(
        {"agent_id": request.agent_id},
        {"$set": agent_doc, "$setOnInsert": {"first_seen": now}},
        upsert=True
    )
    
    logger.info(f"Agent registered: {request.agent_id} ({request.hostname})")
    
    return {
        "status": "ok",
        "message": "Agent registered successfully",
        "agent_id": request.agent_id
    }


@router.post("/agents/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str, request: AgentHeartbeatRequest):
    """Receive heartbeat from agent"""
    now = datetime.now(timezone.utc).isoformat()
    
    update_doc = {
        "status": request.status,
        "last_seen": now
    }
    
    if request.cpu_percent is not None:
        update_doc["cpu_percent"] = request.cpu_percent
    if request.memory_percent is not None:
        update_doc["memory_percent"] = request.memory_percent
    if request.uptime is not None:
        update_doc["uptime"] = request.uptime
    
    result = await db.agents.update_one(
        {"agent_id": agent_id},
        {"$set": update_doc}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    return {"status": "ok", "timestamp": now}


# =============================================================================
# NETWORK DISCOVERY
# =============================================================================

@router.post("/scanner/report")
async def receive_scanner_report(request: ScannerReportRequest):
    """
    Receive device reports from network scanners running on user's LAN.
    This is the PRIMARY way devices get into the system.
    """
    now = datetime.now(timezone.utc).isoformat()
    
    # Track the scanner
    await db.network_scanners.update_one(
        {"scanner_id": request.scanner_id},
        {
            "$set": {
                "scanner_id": request.scanner_id,
                "network": request.network,
                "last_report": now,
                "last_device_count": len(request.devices)
            },
            "$inc": {"total_reports": 1}
        },
        upsert=True
    )
    
    new_devices = 0
    updated_devices = 0
    
    for device in request.devices:
        ip = device.get('ip_address')
        if not ip:
            continue
        
        # Determine risk score
        risk_score = 30  # Base risk
        if not device.get('deployable', False):
            risk_score += 20  # Higher risk if can't deploy agent
        if device.get('os') == 'unknown':
            risk_score += 15
        if device.get('device_type') == 'iot':
            risk_score += 10
        
        device_doc = {
            "ip_address": ip,
            "mac_address": device.get('mac_address'),
            "hostname": device.get('hostname'),
            "vendor": device.get('vendor'),
            "os_type": device.get('os', 'unknown'),
            "device_type": device.get('device_type', 'unknown'),
            "open_ports": device.get('open_ports', []),
            "discovery_method": device.get('discovery_method'),
            "deployable": device.get('deployable', False),
            "mobile_manageable": device.get('mobile_manageable', False),
            "risk_score": min(risk_score, 100),
            "last_seen": now,
            "scanner_id": request.scanner_id,
            "network": request.network
        }
        
        # Upsert device
        result = await db.discovered_devices.update_one(
            {"ip_address": ip},
            {
                "$set": device_doc,
                "$setOnInsert": {
                    "first_seen": now,
                    "deployment_status": "discovered",
                    "is_managed": False
                }
            },
            upsert=True
        )
        
        if result.upserted_id:
            new_devices += 1
        else:
            updated_devices += 1
    
    logger.info(f"Scanner {request.scanner_id} reported {len(request.devices)} devices ({new_devices} new, {updated_devices} updated)")
    
    return {
        "status": "ok",
        "message": f"Received {len(request.devices)} devices",
        "new_devices": new_devices,
        "updated_devices": updated_devices
    }


@router.get("/scanners")
async def get_network_scanners(current_user: dict = Depends(get_current_user)):
    """Get list of active network scanners"""
    cursor = db.network_scanners.find({}, {"_id": 0})
    scanners = await cursor.to_list(100)
    return {"scanners": scanners}


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
# AGENT DOWNLOAD
# =============================================================================

@router.get("/agent/download/{platform}")
async def download_agent(platform: str):
    """Download the Seraph Defender agent for the specified platform"""
    from fastapi.responses import FileResponse, PlainTextResponse
    import os
    
    agent_path = "/app/scripts/seraph_defender.py"
    
    if not os.path.exists(agent_path):
        raise HTTPException(status_code=404, detail="Agent not found")
    
    if platform == "linux":
        return FileResponse(
            agent_path,
            media_type="text/x-python",
            filename="seraph_defender.py"
        )
    elif platform == "windows":
        return FileResponse(
            agent_path,
            media_type="text/x-python",
            filename="seraph_defender.py"
        )
    elif platform == "macos":
        return FileResponse(
            agent_path,
            media_type="text/x-python",
            filename="seraph_defender.py"
        )
    elif platform == "scanner":
        scanner_path = "/app/scripts/seraph_network_scanner.py"
        if not os.path.exists(scanner_path):
            raise HTTPException(status_code=404, detail="Scanner not found")
        return FileResponse(
            scanner_path,
            media_type="text/x-python",
            filename="seraph_network_scanner.py"
        )
    elif platform == "mobile":
        mobile_path = "/app/scripts/seraph_mobile_agent.py"
        if not os.path.exists(mobile_path):
            raise HTTPException(status_code=404, detail="Mobile agent not found")
        return FileResponse(
            mobile_path,
            media_type="text/x-python",
            filename="seraph_mobile_agent.py"
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unknown platform: {platform}")


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
    
    # Get deployable devices - check both lowercase and capitalized OS types
    cursor = db.discovered_devices.find({
        "deployment_status": {"$in": ["discovered", "failed", None]},
        "$or": [
            {"os_type": {"$in": ["windows", "linux", "macos", "Windows", "Linux", "macOS"]}},
            {"deployable": True}
        ]
    }, {"_id": 0})
    devices = await cursor.to_list(100)
    
    if not devices:
        return {
            "message": "No deployable devices found",
            "devices": []
        }
    
    queued = []
    for device in devices:
        try:
            task_id = await service.queue_deployment(
                device_ip=device["ip_address"],
                device_hostname=device.get("hostname"),
                os_type=device.get("os_type", "unknown")
            )
            queued.append({
                "ip": device["ip_address"],
                "hostname": device.get("hostname"),
                "task_id": task_id
            })
            
            # Update device status
            await db.discovered_devices.update_one(
                {"ip_address": device["ip_address"]},
                {"$set": {"deployment_status": "queued"}}
            )
        except Exception as e:
            logger.error(f"Failed to queue deployment for {device['ip_address']}: {e}")
    
    logger.info(f"Batch deployment: queued {len(queued)} devices")
    
    return {
        "message": f"Batch deployment initiated for {len(queued)} devices",
        "devices": queued
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
    """Ingest telemetry events from agents and process through AATL"""
    from services.aatl import get_aatl_engine
    
    events = request.events
    if not events:
        return {"status": "ok", "ingested": 0}
    
    # Process and store events
    now = datetime.now(timezone.utc).isoformat()
    aatl_assessments = []
    agents_updated = 0
    
    for event in events:
        event["ingested_at"] = now
        
        # Handle agent heartbeat - register/update agent
        event_type = event.get("event_type", "")
        if event_type == "agent.heartbeat":
            agent_data = event.get("data", {})
            agent_id = event.get("agent_id") or event.get("host_id")
            
            if agent_id:
                await db.agents.update_one(
                    {"agent_id": agent_id},
                    {
                        "$set": {
                            "agent_id": agent_id,
                            "host_id": event.get("host_id"),
                            "hostname": agent_data.get("hostname"),
                            "os": agent_data.get("os"),
                            "version": agent_data.get("version"),
                            "status": "online",
                            "last_seen": now,
                            "uptime": agent_data.get("uptime")
                        },
                        "$setOnInsert": {
                            "first_seen": now
                        }
                    },
                    upsert=True
                )
                agents_updated += 1
        
        # Determine severity for alerting
        severity = event.get("severity", "info")
        event_type = event.get("event_type", "")
        
        # Store in telemetry collection
        await db.agent_telemetry.insert_one(event)
        
        # Process CLI events through AATL
        if event_type == "cli.command":
            engine = get_aatl_engine()
            if engine:
                try:
                    assessment = await engine.process_cli_event(event)
                    if assessment:
                        aatl_assessments.append(assessment.to_dict())
                        
                        # Update severity based on AATL assessment
                        if assessment.threat_score >= 80:
                            severity = "critical"
                        elif assessment.threat_score >= 60:
                            severity = "high"
                        elif assessment.threat_score >= 40:
                            severity = "medium"
                except Exception as e:
                    logger.warning(f"AATL processing failed: {e}")
        
        # Create alert for high severity events
        if severity in ("critical", "high"):
            await db.alerts.insert_one({
                "type": "telemetry",
                "severity": severity,
                "source": event.get("host_id", "unknown"),
                "event_type": event_type,
                "message": event.get("data", {}).get("message", "Security event detected"),
                "data": event.get("data"),
                "timestamp": now,
                "status": "open"
            })
    
    logger.info(f"Ingested {len(events)} telemetry events, {len(aatl_assessments)} AATL assessments")
    
    return {
        "status": "ok", 
        "ingested": len(events),
        "aatl_assessments": len(aatl_assessments)
    }


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



# =============================================================================
# CLI EVENT INGESTION (AATL Integration)
# =============================================================================

@router.post("/cli/event")
async def ingest_cli_event(request: CLIEventRequest):
    """
    Ingest a CLI event and process through AATL for AI threat detection.
    This is the primary endpoint for CLI monitoring integration.
    """
    from services.aatl import get_aatl_engine
    
    now = datetime.now(timezone.utc).isoformat()
    
    # Store CLI command
    cli_doc = {
        "host_id": request.host_id,
        "session_id": request.session_id,
        "command": request.command,
        "user": request.user,
        "shell_type": request.shell_type,
        "timestamp": request.timestamp or now,
        "ingested_at": now
    }
    
    await db.cli_commands.insert_one(cli_doc)
    
    # Process through AATL
    assessment = None
    engine = get_aatl_engine()
    
    if engine:
        try:
            event = {
                "host_id": request.host_id,
                "event_type": "cli.command",
                "timestamp": request.timestamp or now,
                "data": {
                    "session_id": request.session_id,
                    "command": request.command,
                    "user": request.user,
                    "shell_type": request.shell_type
                }
            }
            assessment = await engine.process_cli_event(event)
        except Exception as e:
            logger.error(f"AATL processing error: {e}")
    
    result = {
        "status": "ok",
        "command_stored": True
    }
    
    if assessment:
        result["aatl_assessment"] = {
            "machine_plausibility": assessment.machine_plausibility,
            "threat_score": assessment.threat_score,
            "threat_level": assessment.threat_level,
            "actor_type": assessment.actor_type.value,
            "recommended_strategy": assessment.recommended_strategy.value
        }
    
    return result


@router.post("/cli/batch")
async def ingest_cli_batch(events: List[CLIEventRequest]):
    """Ingest multiple CLI events in batch"""
    from services.aatl import get_aatl_engine
    
    now = datetime.now(timezone.utc).isoformat()
    processed = 0
    assessments = []
    
    engine = get_aatl_engine()
    
    for request in events:
        # Store CLI command
        cli_doc = {
            "host_id": request.host_id,
            "session_id": request.session_id,
            "command": request.command,
            "user": request.user,
            "shell_type": request.shell_type,
            "timestamp": request.timestamp or now,
            "ingested_at": now
        }
        
        await db.cli_commands.insert_one(cli_doc)
        processed += 1
        
        # Process through AATL
        if engine:
            try:
                event = {
                    "host_id": request.host_id,
                    "event_type": "cli.command",
                    "timestamp": request.timestamp or now,
                    "data": {
                        "session_id": request.session_id,
                        "command": request.command,
                        "user": request.user,
                        "shell_type": request.shell_type
                    }
                }
                assessment = await engine.process_cli_event(event)
                if assessment and assessment.threat_score >= 30:
                    assessments.append(assessment.to_dict())
            except Exception as e:
                logger.warning(f"AATL batch processing error: {e}")
    
    return {
        "status": "ok",
        "processed": processed,
        "aatl_assessments": len(assessments),
        "high_threat_sessions": [a for a in assessments if a.get("threat_score", 0) >= 60]
    }


@router.get("/cli/sessions/{host_id}")
async def get_cli_sessions(
    host_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get CLI sessions for a host with AATL assessments"""
    from services.aatl import get_aatl_engine
    
    # Get unique session IDs
    pipeline = [
        {"$match": {"host_id": host_id}},
        {"$group": {
            "_id": "$session_id",
            "command_count": {"$sum": 1},
            "first_seen": {"$min": "$timestamp"},
            "last_seen": {"$max": "$timestamp"}
        }},
        {"$sort": {"last_seen": -1}},
        {"$limit": 50}
    ]
    
    sessions = await db.cli_commands.aggregate(pipeline).to_list(50)
    
    # Enrich with AATL assessments
    engine = get_aatl_engine()
    enriched = []
    
    for session in sessions:
        session_data = {
            "session_id": session["_id"],
            "command_count": session["command_count"],
            "first_seen": session["first_seen"],
            "last_seen": session["last_seen"]
        }
        
        if engine:
            assessment = await engine.get_assessment(host_id, session["_id"])
            if assessment:
                session_data["aatl"] = {
                    "machine_plausibility": assessment.get("machine_plausibility"),
                    "threat_score": assessment.get("threat_score"),
                    "threat_level": assessment.get("threat_level"),
                    "actor_type": assessment.get("actor_type"),
                    "recommended_strategy": assessment.get("recommended_strategy")
                }
        
        enriched.append(session_data)
    
    return {"sessions": enriched, "host_id": host_id}
