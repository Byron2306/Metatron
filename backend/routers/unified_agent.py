"""
Unified Agent Router - Metatron Integration
============================================
API endpoints for the Metatron/Seraph unified agent management system.
Provides cross-platform agent registration, heartbeat, deployment, and monitoring.
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect, Request
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
import secrets
import logging
import asyncio

from .dependencies import get_current_user, check_permission, db

logger = logging.getLogger('seraph.unified_agent')

router = APIRouter(prefix="/unified", tags=["Unified Agent"])


# ============================================================
# PYDANTIC MODELS
# ============================================================

class AgentRegistrationModel(BaseModel):
    agent_id: str
    platform: str  # windows, linux, macos, android, ios
    hostname: str
    ip_address: str
    version: str
    capabilities: List[str] = []
    config: Optional[Dict[str, Any]] = None


class AgentHeartbeatModel(BaseModel):
    agent_id: str
    status: str  # online, offline, degraded
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    threat_count: Optional[int] = None
    network_connections: Optional[int] = None
    alerts: List[Dict] = []
    telemetry: Optional[Dict] = None


class DeploymentRequestModel(BaseModel):
    target_platform: str
    target_ip: str
    agent_config: Optional[Dict] = None
    credentials: Optional[Dict] = None


class AgentCommandModel(BaseModel):
    command_type: Optional[str] = None  # scan, remediate, update, restart, shutdown
    parameters: Dict[str, Any] = {}
    priority: str = "normal"  # low, normal, high, critical
    command: Optional[str] = None
    params: Optional[Dict[str, Any]] = None


class AlertModel(BaseModel):
    agent_id: str
    severity: str  # critical, high, medium, low
    category: str  # network, process, file, system
    message: str
    details: Optional[Dict] = None
    mitre_technique: Optional[str] = None


# ============================================================
# WEBSOCKET MANAGER
# ============================================================

class AgentConnectionManager:
    """Manage WebSocket connections for real-time agent communication"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.command_queues: Dict[str, List[Dict]] = {}
    
    async def connect(self, agent_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[agent_id] = websocket
        self.command_queues[agent_id] = []
        logger.info(f"Agent {agent_id} connected via WebSocket")
    
    def disconnect(self, agent_id: str):
        if agent_id in self.active_connections:
            del self.active_connections[agent_id]
        if agent_id in self.command_queues:
            del self.command_queues[agent_id]
        logger.info(f"Agent {agent_id} disconnected")
    
    async def send_command(self, agent_id: str, command: Dict):
        if agent_id in self.active_connections:
            await self.active_connections[agent_id].send_json(command)
            return True
        # Queue command for when agent reconnects
        if agent_id not in self.command_queues:
            self.command_queues[agent_id] = []
        self.command_queues[agent_id].append(command)
        return False
    
    async def broadcast(self, message: Dict):
        for connection in self.active_connections.values():
            try:
                await connection.send_json(message)
            except Exception:
                pass
    
    def get_queued_commands(self, agent_id: str) -> List[Dict]:
        commands = self.command_queues.get(agent_id, [])
        self.command_queues[agent_id] = []
        return commands
    
    def is_connected(self, agent_id: str) -> bool:
        return agent_id in self.active_connections


agent_ws_manager = AgentConnectionManager()


# ============================================================
# AGENT MANAGEMENT ENDPOINTS
# ============================================================

@router.post("/agents/register")
async def register_agent(agent: AgentRegistrationModel):
    """Register a new unified agent"""
    
    # Check if already exists
    existing = await db.unified_agents.find_one({"agent_id": agent.agent_id})
    if existing:
        # Update existing agent
        await db.unified_agents.update_one(
            {"agent_id": agent.agent_id},
            {"$set": {
                "platform": agent.platform,
                "hostname": agent.hostname,
                "ip_address": agent.ip_address,
                "version": agent.version,
                "capabilities": agent.capabilities,
                "config": agent.config,
                "status": "online",
                "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        logger.info(f"Agent re-registered: {agent.agent_id} ({agent.platform})")
        return {"status": "updated", "agent_id": agent.agent_id}
    
    # Create new agent
    agent_doc = {
        "agent_id": agent.agent_id,
        "platform": agent.platform,
        "hostname": agent.hostname,
        "ip_address": agent.ip_address,
        "version": agent.version,
        "capabilities": agent.capabilities,
        "config": agent.config or {},
        "status": "online",
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        "threat_count": 0,
        "alerts_count": 0
    }
    
    await db.unified_agents.insert_one(agent_doc)
    logger.info(f"New agent registered: {agent.agent_id} ({agent.platform}) from {agent.ip_address}")
    
    return {"status": "registered", "agent_id": agent.agent_id}


@router.post("/agents/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str, heartbeat: AgentHeartbeatModel):
    """Receive heartbeat from an agent"""
    
    agent = await db.unified_agents.find_one({"agent_id": agent_id})
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found. Please register first.")
    
    # Update agent status
    update_data = {
        "status": heartbeat.status,
        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        "cpu_usage": heartbeat.cpu_usage,
        "memory_usage": heartbeat.memory_usage,
        "disk_usage": heartbeat.disk_usage,
        "threat_count": heartbeat.threat_count or 0,
        "network_connections": heartbeat.network_connections
    }
    
    await db.unified_agents.update_one(
        {"agent_id": agent_id},
        {"$set": update_data}
    )
    
    # Process any alerts
    for alert_data in heartbeat.alerts:
        await _process_agent_alert(agent_id, alert_data)
    
    # Store telemetry if provided
    if heartbeat.telemetry:
        await db.agent_telemetry.insert_one({
            "agent_id": agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "telemetry": heartbeat.telemetry
        })
        
        # Run threat hunting on telemetry
        await _hunt_telemetry(heartbeat.telemetry)
    
    # Get queued commands for this agent
    commands = agent_ws_manager.get_queued_commands(agent_id)
    
    return {
        "status": "ok",
        "commands": commands,
        "config": agent.get("config", {}),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/agents")
async def list_unified_agents(
    platform: Optional[str] = None,
    status: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """List all unified agents"""
    
    query = {}
    if platform:
        query["platform"] = platform
    if status:
        query["status"] = status
    
    agents = await db.unified_agents.find(query, {"_id": 0}).to_list(1000)
    
    # Mark offline agents
    now = datetime.now(timezone.utc)
    for agent in agents:
        last_hb = agent.get("last_heartbeat")
        if last_hb:
            try:
                last_hb_dt = datetime.fromisoformat(last_hb.replace('Z', '+00:00'))
                if now - last_hb_dt > timedelta(minutes=5):
                    agent["status"] = "offline"
            except:
                pass
    
    return {
        "agents": agents,
        "total": len(agents),
        "online": len([a for a in agents if a.get("status") == "online"]),
        "offline": len([a for a in agents if a.get("status") == "offline"])
    }


@router.get("/agents/{agent_id}")
async def get_unified_agent(
    agent_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get details of a specific agent"""
    
    agent = await db.unified_agents.find_one({"agent_id": agent_id}, {"_id": 0})
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Get recent telemetry
    recent_telemetry = await db.agent_telemetry.find(
        {"agent_id": agent_id}
    ).sort("timestamp", -1).limit(10).to_list(10)
    
    # Get recent alerts
    recent_alerts = await db.unified_alerts.find(
        {"agent_id": agent_id}
    ).sort("timestamp", -1).limit(20).to_list(20)
    
    return {
        **agent,
        "recent_telemetry": [{k: v for k, v in t.items() if k != '_id'} for t in recent_telemetry],
        "recent_alerts": [{k: v for k, v in a.items() if k != '_id'} for a in recent_alerts],
        "ws_connected": agent_ws_manager.is_connected(agent_id)
    }


@router.delete("/agents/{agent_id}")
async def unregister_agent(
    agent_id: str,
    current_user: dict = Depends(check_permission("admin"))
):
    """Unregister an agent"""
    
    result = await db.unified_agents.delete_one({"agent_id": agent_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Disconnect WebSocket if connected
    agent_ws_manager.disconnect(agent_id)
    
    logger.info(f"Agent unregistered: {agent_id}")
    return {"status": "unregistered", "agent_id": agent_id}


@router.post("/agents/{agent_id}/command")
async def send_agent_command(
    agent_id: str,
    command: AgentCommandModel,
    current_user: dict = Depends(check_permission("write"))
):
    """Send a command to an agent"""
    
    agent = await db.unified_agents.find_one({"agent_id": agent_id})
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    resolved_command_type = command.command_type or command.command
    if not resolved_command_type:
        raise HTTPException(
            status_code=422,
            detail="Missing command type. Provide 'command_type' (preferred) or legacy 'command'."
        )

    resolved_parameters = command.parameters or command.params or {}
    
    command_id = secrets.token_hex(8)
    command_data = {
        "command_id": command_id,
        "type": "command",
        "command_type": resolved_command_type,
        "parameters": resolved_parameters,
        "priority": command.priority,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "issued_by": current_user.get("email", "system")
    }
    
    # Try to send immediately via WebSocket
    sent = await agent_ws_manager.send_command(agent_id, command_data)
    
    # Store command in database
    await db.agent_commands.insert_one({
        **command_data,
        "agent_id": agent_id,
        "status": "sent" if sent else "queued"
    })
    
    logger.info(f"Command {resolved_command_type} sent to {agent_id}: {'immediate' if sent else 'queued'}")
    
    return {
        "command_id": command_id,
        "status": "sent" if sent else "queued",
        "message": f"Command {'sent immediately' if sent else 'queued for delivery'}"
    }


# ============================================================
# DEPLOYMENT ENDPOINTS
# ============================================================

@router.post("/deployments")
async def create_deployment(
    deployment: DeploymentRequestModel,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(check_permission("admin"))
):
    """Create a new agent deployment"""
    
    deployment_id = secrets.token_hex(8)
    
    deployment_doc = {
        "deployment_id": deployment_id,
        "target_platform": deployment.target_platform,
        "target_ip": deployment.target_ip,
        "agent_config": deployment.agent_config or {},
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": current_user.get("email", "system")
    }
    
    await db.unified_deployments.insert_one(deployment_doc)
    
    # Start deployment in background
    background_tasks.add_task(_process_deployment, deployment_id, deployment)
    
    logger.info(f"Deployment created: {deployment_id} for {deployment.target_platform} at {deployment.target_ip}")
    
    return {
        "deployment_id": deployment_id,
        "status": "pending",
        "message": "Deployment queued for processing"
    }


@router.get("/deployments")
async def list_deployments(
    status: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """List all deployments"""
    
    query = {}
    if status:
        query["status"] = status
    
    deployments = await db.unified_deployments.find(query, {"_id": 0}).to_list(500)

    for deployment in deployments:
        await _sync_unified_deployment_status(deployment)
    
    return {
        "deployments": deployments,
        "total": len(deployments)
    }


@router.get("/deployments/{deployment_id}")
async def get_deployment(
    deployment_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get deployment details"""
    
    deployment = await db.unified_deployments.find_one(
        {"deployment_id": deployment_id},
        {"_id": 0}
    )
    if not deployment:
        raise HTTPException(status_code=404, detail="Deployment not found")

    await _sync_unified_deployment_status(deployment)
    deployment = await db.unified_deployments.find_one(
        {"deployment_id": deployment_id},
        {"_id": 0}
    )
    
    return deployment


# ============================================================
# ALERTS ENDPOINTS
# ============================================================

@router.post("/alerts")
async def create_alert(alert: AlertModel):
    """Create an alert from an agent"""
    
    alert_id = secrets.token_hex(8)
    
    alert_doc = {
        "alert_id": alert_id,
        "agent_id": alert.agent_id,
        "severity": alert.severity,
        "category": alert.category,
        "message": alert.message,
        "details": alert.details or {},
        "mitre_technique": alert.mitre_technique,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "acknowledged": False
    }
    
    await db.unified_alerts.insert_one(alert_doc)
    
    logger.warning(f"ALERT [{alert.severity.upper()}] from {alert.agent_id}: {alert.message}")
    
    return {"alert_id": alert_id, "status": "created"}


@router.get("/alerts")
async def list_alerts(
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """List alerts"""
    
    query = {}
    if severity:
        query["severity"] = severity
    if acknowledged is not None:
        query["acknowledged"] = acknowledged
    
    alerts = await db.unified_alerts.find(query, {"_id": 0}).sort(
        "timestamp", -1
    ).limit(limit).to_list(limit)
    
    return {
        "alerts": alerts,
        "total": len(alerts)
    }


@router.put("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Acknowledge an alert"""
    
    result = await db.unified_alerts.update_one(
        {"alert_id": alert_id},
        {"$set": {
            "acknowledged": True,
            "acknowledged_at": datetime.now(timezone.utc).isoformat(),
            "acknowledged_by": current_user.get("email", "system")
        }}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return {"status": "acknowledged"}


# ============================================================
# DASHBOARD / STATS ENDPOINTS
# ============================================================

@router.get("/dashboard")
async def get_unified_dashboard(current_user: dict = Depends(get_current_user)):
    """Get unified agent dashboard data"""
    
    # Count agents by status
    total_agents = await db.unified_agents.count_documents({})
    online_agents = await db.unified_agents.count_documents({"status": "online"})
    
    # Count by platform
    pipeline = [
        {"$group": {"_id": "$platform", "count": {"$sum": 1}}}
    ]
    platform_stats = await db.unified_agents.aggregate(pipeline).to_list(10)
    
    # Alert stats
    total_alerts = await db.unified_alerts.count_documents({})
    unack_alerts = await db.unified_alerts.count_documents({"acknowledged": False})
    
    # Deployment stats
    total_deployments = await db.unified_deployments.count_documents({})
    active_deployments = await db.unified_deployments.count_documents(
        {"status": {"$in": ["pending", "processing"]}}
    )
    
    # Recent agents
    recent_agents = await db.unified_agents.find(
        {}, {"_id": 0, "agent_id": 1, "hostname": 1, "platform": 1, "status": 1, "last_heartbeat": 1}
    ).sort("last_heartbeat", -1).limit(10).to_list(10)
    
    # Recent alerts
    recent_alerts = await db.unified_alerts.find(
        {}, {"_id": 0}
    ).sort("timestamp", -1).limit(10).to_list(10)
    
    return {
        "agents": {
            "total": total_agents,
            "online": online_agents,
            "offline": total_agents - online_agents,
            "by_platform": {s["_id"]: s["count"] for s in platform_stats},
            "recent": recent_agents
        },
        "alerts": {
            "total": total_alerts,
            "unacknowledged": unack_alerts,
            "recent": recent_alerts
        },
        "deployments": {
            "total": total_deployments,
            "active": active_deployments
        },
        "websocket_connections": len(agent_ws_manager.active_connections),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/stats")
async def get_unified_stats(current_user: dict = Depends(get_current_user)):
    """Get unified agent system statistics"""
    
    stats = {
        "total_agents": await db.unified_agents.count_documents({}),
        "online_agents": await db.unified_agents.count_documents({"status": "online"}),
        "total_alerts": await db.unified_alerts.count_documents({}),
        "total_commands": await db.agent_commands.count_documents({}),
        "total_deployments": await db.unified_deployments.count_documents({}),
        "websocket_connections": len(agent_ws_manager.active_connections),
        "supported_platforms": ["windows", "linux", "macos", "android", "ios"]
    }
    
    return stats


# ============================================================
# WEBSOCKET ENDPOINT
# ============================================================

@router.websocket("/ws/agent/{agent_id}")
async def websocket_agent_endpoint(websocket: WebSocket, agent_id: str):
    """WebSocket endpoint for real-time agent communication"""
    
    await agent_ws_manager.connect(agent_id, websocket)
    
    # Update agent status
    await db.unified_agents.update_one(
        {"agent_id": agent_id},
        {"$set": {"status": "online", "ws_connected": True}}
    )
    
    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type")
            
            if msg_type == "heartbeat":
                # Update heartbeat
                await db.unified_agents.update_one(
                    {"agent_id": agent_id},
                    {"$set": {
                        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                        "status": "online"
                    }}
                )
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            
            elif msg_type == "alert":
                # Store alert
                alert_data = data.get("data", {})
                await db.unified_alerts.insert_one({
                    "alert_id": secrets.token_hex(8),
                    "agent_id": agent_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **alert_data
                })
                logger.warning(f"Alert from {agent_id}: {alert_data.get('message', 'Unknown')}")
            
            elif msg_type == "telemetry":
                # Store telemetry
                telemetry = data.get("data", {})
                await db.agent_telemetry.insert_one({
                    "agent_id": agent_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "telemetry": telemetry
                })
                # Run threat hunting
                await _hunt_telemetry(telemetry)
            
            elif msg_type == "command_result":
                # Store command result
                result = data.get("data", {})
                await db.agent_commands.update_one(
                    {"command_id": result.get("command_id")},
                    {"$set": {
                        "status": result.get("status", "completed"),
                        "result": result,
                        "completed_at": datetime.now(timezone.utc).isoformat()
                    }}
                )
    
    except WebSocketDisconnect:
        agent_ws_manager.disconnect(agent_id)
        await db.unified_agents.update_one(
            {"agent_id": agent_id},
            {"$set": {"status": "offline", "ws_connected": False}}
        )


# ============================================================
# AGENT DOWNLOAD / INSTALL ENDPOINTS
# ============================================================

@router.get("/agent/download")
async def download_agent_package():
    """Download the unified agent package as a tarball"""
    import tarfile
    import io
    import os
    from fastapi.responses import StreamingResponse
    
    agent_dir = "/app/unified_agent"
    
    # Create tarball in memory
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
        # Add core agent files
        for item in ['core', 'requirements.txt']:
            item_path = os.path.join(agent_dir, item)
            if os.path.exists(item_path):
                tar.add(item_path, arcname=item)
    
    buffer.seek(0)
    
    return StreamingResponse(
        buffer,
        media_type="application/gzip",
        headers={"Content-Disposition": "attachment; filename=seraph-agent.tar.gz"}
    )


@router.get("/agent/install-script")
async def get_install_script(request: Request, server_url: Optional[str] = None):
    """Get the agent installation script"""
    
    # Use explicit query param first; otherwise infer from request/proxy headers
    forwarded_proto = request.headers.get("x-forwarded-proto")
    proto = forwarded_proto or request.url.scheme or "http"
    base_url = server_url or f"{proto}://{request.headers.get('host', 'localhost:8001')}"
    
    script = f'''#!/bin/bash
# Seraph AI Unified Agent Installer
# Automatically generated for: {base_url}

set -e

SERAPH_SERVER="{base_url}"
INSTALL_DIR="/opt/seraph-agent"

echo "================================================================"
echo "  SERAPH AI UNIFIED AGENT INSTALLER"
echo "  Target Server: $SERAPH_SERVER"
echo "================================================================"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Create installation directory
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Install Python dependencies
echo "Installing Python and dependencies..."
apt-get update
apt-get install -y python3 python3-pip python3-venv curl

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required packages
pip install --upgrade pip
pip install psutil requests netifaces scapy watchdog python-nmap aiohttp pyyaml

# Download agent package
echo "Downloading agent from server..."
curl -sSL "$SERAPH_SERVER/api/unified/agent/download" -o agent.tar.gz
tar -xzf agent.tar.gz
rm agent.tar.gz

# Create systemd service
cat > /etc/systemd/system/seraph-agent.service << EOF
[Unit]
Description=Seraph AI Unified Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
ExecStart=$INSTALL_DIR/venv/bin/python core/agent.py --server $SERAPH_SERVER
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable seraph-agent
systemctl start seraph-agent

echo ""
echo "================================================================"
echo "  INSTALLATION COMPLETE"
echo "================================================================"
echo "Agent installed to: $INSTALL_DIR"
echo "Service status: systemctl status seraph-agent"
echo "Service logs: journalctl -u seraph-agent -f"
echo ""
'''
    
    return {"script": script, "usage": f"curl -sSL {base_url}/api/unified/agent/install-script | sudo bash"}


@router.get("/agent/install-windows")
async def get_windows_install_script(request: Request, server_url: Optional[str] = None):
    """Get the Windows agent installation script (PowerShell)"""
    
    forwarded_proto = request.headers.get("x-forwarded-proto")
    proto = forwarded_proto or request.url.scheme or "http"
    base_url = server_url or f"{proto}://{request.headers.get('host', 'localhost:8001')}"
    
    script = f'''# Seraph AI Unified Agent - Windows Installer
# Run as Administrator

$SERAPH_SERVER = "{base_url}"
$INSTALL_DIR = "C:\\ProgramData\\SeraphAgent"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  SERAPH AI UNIFIED AGENT INSTALLER (Windows)" -ForegroundColor Cyan
Write-Host "  Target Server: $SERAPH_SERVER" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# Create installation directory
New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
Set-Location $INSTALL_DIR

# Download agent
Write-Host "Downloading agent..."
Invoke-WebRequest -Uri "$SERAPH_SERVER/api/unified/agent/download" -OutFile "agent.tar.gz"

# Extract (requires 7-zip or tar on Windows 10+)
tar -xzf agent.tar.gz
Remove-Item agent.tar.gz

# Install Python dependencies
Write-Host "Installing dependencies..."
python -m pip install psutil requests netifaces watchdog pyyaml

# Create scheduled task to run at startup
$action = New-ScheduledTaskAction -Execute "python" -Argument "core\\agent.py --server $SERAPH_SERVER" -WorkingDirectory $INSTALL_DIR
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
Register-ScheduledTask -TaskName "SeraphAgent" -Action $action -Trigger $trigger -Principal $principal -Force

# Start agent
Write-Host "Starting agent..."
Start-ScheduledTask -TaskName "SeraphAgent"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  INSTALLATION COMPLETE" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "Agent installed to: $INSTALL_DIR"
Write-Host "Check status: Get-ScheduledTask -TaskName SeraphAgent"
'''
    
    return {"script": script, "usage": f"Invoke-WebRequest -Uri {base_url}/api/unified/agent/install-windows | Invoke-Expression"}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

async def _process_agent_alert(agent_id: str, alert_data: Dict):
    """Process an alert from an agent"""
    
    await db.unified_alerts.insert_one({
        "alert_id": secrets.token_hex(8),
        "agent_id": agent_id,
        "severity": alert_data.get("severity", "medium"),
        "category": alert_data.get("category", "unknown"),
        "message": alert_data.get("message", "Unknown alert"),
        "details": alert_data.get("details", {}),
        "mitre_technique": alert_data.get("mitre_technique"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "acknowledged": False
    })
    
    # Update agent alert count
    await db.unified_agents.update_one(
        {"agent_id": agent_id},
        {"$inc": {"alerts_count": 1}}
    )


async def _hunt_telemetry(telemetry: Dict):
    """Run threat hunting on telemetry data"""
    try:
        from services.threat_hunting import threat_hunting_engine
        from dataclasses import asdict
        
        matches = threat_hunting_engine.hunt_all(telemetry)
        
        if matches:
            # Store matches
            for match in matches:
                await db.hunting_matches.insert_one(asdict(match))
            
            logger.info(f"Threat hunting found {len(matches)} matches")
    except Exception as e:
        logger.error(f"Threat hunting error: {e}")


async def _sync_unified_deployment_status(deployment: Dict[str, Any]):
    """Sync unified deployment status from underlying deployment task state."""
    task_id = deployment.get("deployment_task_id")
    if not task_id:
        return

    task_doc = await db.deployment_tasks.find_one({"task_id": task_id}, {"_id": 0})
    if not task_doc:
        return

    task_status = task_doc.get("status")
    simulated = bool(task_doc.get("simulated", False))
    error_message = task_doc.get("error_message")
    current_status = deployment.get("status")

    if task_status == "deployed" and current_status != "completed":
        await db.unified_deployments.update_one(
            {"deployment_id": deployment["deployment_id"]},
            {"$set": {
                "status": "completed",
                "simulated": simulated,
                "completed_at": datetime.now(timezone.utc).isoformat()
            }}
        )
    elif task_status == "failed" and current_status != "failed":
        await db.unified_deployments.update_one(
            {"deployment_id": deployment["deployment_id"]},
            {"$set": {
                "status": "failed",
                "error": error_message or "Deployment failed",
                "failed_at": datetime.now(timezone.utc).isoformat()
            }}
        )
    elif task_status in {"pending", "deploying"} and current_status not in {"running", "queued"}:
        await db.unified_deployments.update_one(
            {"deployment_id": deployment["deployment_id"]},
            {"$set": {
                "status": "running",
                "last_checked_at": datetime.now(timezone.utc).isoformat()
            }}
        )


async def _process_deployment(deployment_id: str, deployment: DeploymentRequestModel):
    """Process a deployment in the background"""
    
    try:
        await db.unified_deployments.update_one(
            {"deployment_id": deployment_id},
            {"$set": {"status": "processing", "started_at": datetime.now(timezone.utc).isoformat()}}
        )

        from services.agent_deployment import get_deployment_service, start_deployment_service

        service = get_deployment_service()
        if service is None:
            import os
            api_url = os.environ.get('API_URL', 'http://localhost:8001')
            service = await start_deployment_service(db, api_url)

        task_id = await service.queue_deployment(
            device_ip=deployment.target_ip,
            device_hostname=None,
            os_type=deployment.target_platform,
            credentials=deployment.credentials
        )

        await db.unified_deployments.update_one(
            {"deployment_id": deployment_id},
            {"$set": {
                "status": "queued",
                "deployment_task_id": task_id,
                "queued_at": datetime.now(timezone.utc).isoformat()
            }}
        )

        final_status = None
        simulated = False
        error_message = None

        for _ in range(120):
            task_doc = await db.deployment_tasks.find_one({"task_id": task_id}, {"_id": 0})
            if task_doc:
                task_status = task_doc.get("status")
                simulated = bool(task_doc.get("simulated", False))
                error_message = task_doc.get("error_message")
                if task_status in {"deployed", "failed"}:
                    final_status = task_status
                    break
            await asyncio.sleep(2)

        if final_status == "deployed":
            await db.unified_deployments.update_one(
                {"deployment_id": deployment_id},
                {"$set": {
                    "status": "completed",
                    "simulated": simulated,
                    "completed_at": datetime.now(timezone.utc).isoformat()
                }}
            )
            logger.info(f"Deployment {deployment_id} completed (task={task_id}, simulated={simulated})")
        elif final_status == "failed":
            await db.unified_deployments.update_one(
                {"deployment_id": deployment_id},
                {"$set": {
                    "status": "failed",
                    "error": error_message or "Deployment failed",
                    "failed_at": datetime.now(timezone.utc).isoformat()
                }}
            )
            logger.error(f"Deployment {deployment_id} failed (task={task_id}): {error_message}")
        else:
            await db.unified_deployments.update_one(
                {"deployment_id": deployment_id},
                {"$set": {
                    "status": "running",
                    "deployment_task_id": task_id,
                    "last_checked_at": datetime.now(timezone.utc).isoformat()
                }}
            )
            logger.info(f"Deployment {deployment_id} still running (task={task_id})")
        
    except Exception as e:
        await db.unified_deployments.update_one(
            {"deployment_id": deployment_id},
            {"$set": {
                "status": "failed",
                "error": str(e),
                "failed_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        logger.error(f"Deployment {deployment_id} failed: {e}")
