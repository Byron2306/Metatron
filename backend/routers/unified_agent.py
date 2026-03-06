"""
Unified Agent Router - Metatron Integration
============================================
API endpoints for the Metatron/Seraph unified agent management system.
Provides cross-platform agent registration, heartbeat, deployment, and monitoring.
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect, Request, Header
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
import secrets
import logging
import asyncio
import hmac
import hashlib
import os
import socket
import ipaddress

from .dependencies import get_current_user, check_permission, db

logger = logging.getLogger('seraph.unified_agent')

router = APIRouter(prefix="/unified", tags=["Unified Agent"])


# ============================================================
# AGENT SECURITY CONFIGURATION
# ============================================================

def _get_agent_secret() -> str:
    """Get or generate the agent enrollment secret"""
    secret = os.environ.get('SERAPH_AGENT_SECRET')
    if not secret:
        # Generate a secret for development - in production, set SERAPH_AGENT_SECRET
        secret = 'dev-agent-secret-change-in-production'
        logger.warning("SERAPH_AGENT_SECRET not set. Using default development secret.")
    return secret

AGENT_SECRET = _get_agent_secret()

# Trusted networks that agents can connect from (CIDR notation)
TRUSTED_NETWORKS = [
    "127.0.0.0/8",      # Localhost
    "10.0.0.0/8",       # Private Class A
    "172.16.0.0/12",    # Private Class B
    "192.168.0.0/16",   # Private Class C
    "::1/128",          # IPv6 localhost
    "fe80::/10",        # IPv6 link-local
]

# Server's own IPs - populated at startup
SERVER_IPS: set = set()

def _populate_server_ips():
    """Populate server's own IP addresses to prevent self-targeting"""
    global SERVER_IPS
    try:
        hostname = socket.gethostname()
        # Get all IPs for this host
        SERVER_IPS.add(socket.gethostbyname(hostname))
        for info in socket.getaddrinfo(hostname, None):
            SERVER_IPS.add(info[4][0])
        # Add common local addresses
        SERVER_IPS.update(['127.0.0.1', 'localhost', '::1', '0.0.0.0'])
        logger.info(f"Server IPs populated: {SERVER_IPS}")
    except Exception as e:
        logger.warning(f"Failed to populate server IPs: {e}")
        SERVER_IPS = {'127.0.0.1', 'localhost', '::1'}

_populate_server_ips()


def _is_ip_trusted(ip_address: str) -> bool:
    """Check if an IP is from a trusted network"""
    try:
        ip = ipaddress.ip_address(ip_address)
        for network in TRUSTED_NETWORKS:
            if ip in ipaddress.ip_network(network, strict=False):
                return True
        return False
    except ValueError:
        return False


def _generate_agent_token(agent_id: str) -> str:
    """Generate an HMAC-based token for agent authentication"""
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    message = f"{agent_id}:{timestamp}"
    signature = hmac.new(
        AGENT_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{timestamp}:{signature}"


def _verify_agent_token(agent_id: str, token: str) -> bool:
    """Verify an agent's authentication token"""
    try:
        parts = token.split(':')
        if len(parts) != 2:
            return False
        
        timestamp, provided_signature = parts
        # Token expiration: 24 hours
        token_time = int(timestamp)
        current_time = int(datetime.now(timezone.utc).timestamp())
        
        if current_time - token_time > 86400:  # 24 hours
            logger.warning(f"Expired token for agent {agent_id}")
            return False
        
        # Verify signature
        message = f"{agent_id}:{timestamp}"
        expected_signature = hmac.new(
            AGENT_SECRET.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(provided_signature, expected_signature)
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        return False


async def verify_agent_auth(
    request: Request,
    x_agent_id: Optional[str] = Header(None),
    x_agent_token: Optional[str] = Header(None),
    x_enrollment_key: Optional[str] = Header(None)
) -> Dict:
    """Dependency to verify agent authentication"""
    client_ip = request.client.host if request.client else "unknown"
    
    # Check if IP is trusted (allows initial enrollment from private networks)
    is_trusted_network = _is_ip_trusted(client_ip)
    
    # For registration with enrollment key (first-time setup)
    if x_enrollment_key:
        if hmac.compare_digest(x_enrollment_key, AGENT_SECRET):
            return {"type": "enrollment", "ip": client_ip, "trusted": is_trusted_network}
        raise HTTPException(status_code=403, detail="Invalid enrollment key")
    
    # For ongoing agent authentication
    if x_agent_id and x_agent_token:
        if _verify_agent_token(x_agent_id, x_agent_token):
            # Also verify agent is registered
            agent = await db.unified_agents.find_one({"agent_id": x_agent_id})
            if agent:
                return {
                    "type": "authenticated",
                    "agent_id": x_agent_id,
                    "ip": client_ip,
                    "trusted": is_trusted_network
                }
            raise HTTPException(status_code=404, detail="Agent not registered")
        raise HTTPException(status_code=401, detail="Invalid agent token")
    
    # Allow from trusted networks for backwards compatibility (with warning)
    if is_trusted_network:
        logger.warning(f"Agent request from {client_ip} without auth - allowed from trusted network")
        return {"type": "trusted_network", "ip": client_ip, "trusted": True}
    
    raise HTTPException(status_code=401, detail="Agent authentication required")


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


# Monitor-specific telemetry models
class MonitorTelemetry(BaseModel):
    """Base telemetry from a monitor"""
    last_run: Optional[str] = None
    threats_found: int = 0
    scan_duration_ms: Optional[int] = None


class RegistryMonitorTelemetry(MonitorTelemetry):
    """Registry/Startup persistence monitoring"""
    persistence_locations: int = 0
    changes_detected: int = 0
    recent_changes: List[Dict] = []


class ProcessTreeMonitorTelemetry(MonitorTelemetry):
    """Parent-child process chain anomalies"""
    processes_analyzed: int = 0
    suspicious_chains: int = 0
    chain_details: List[Dict] = []


class LOLBinMonitorTelemetry(MonitorTelemetry):
    """Living-off-the-land binary abuse"""
    lolbins_checked: int = 0
    detections: int = 0
    detection_details: List[Dict] = []


class CodeSigningMonitorTelemetry(MonitorTelemetry):
    """Executable signature verification"""
    executables_checked: int = 0
    unsigned_count: int = 0
    unsigned_executables: List[Dict] = []


class DNSMonitorTelemetry(MonitorTelemetry):
    """DNS anomaly detection"""
    queries_analyzed: int = 0
    suspicious_count: int = 0
    suspicious_queries: List[Dict] = []


class MemoryScannerTelemetry(MonitorTelemetry):
    """Process injection/memory scanning"""
    processes_scanned: int = 0
    suspicious_found: int = 0
    injection_details: List[Dict] = []


class ApplicationWhitelistTelemetry(MonitorTelemetry):
    """Application whitelist violations"""
    processes_checked: int = 0
    violations: int = 0
    whitelist_size: int = 0
    violation_details: List[Dict] = []


class DLPMonitorTelemetry(MonitorTelemetry):
    """Data loss prevention"""
    clipboard_alerts: int = 0
    file_alerts: int = 0
    network_alerts: int = 0
    alert_details: List[Dict] = []


class VulnerabilityScannerTelemetry(MonitorTelemetry):
    """Software vulnerability scanning"""
    software_checked: int = 0
    vulnerabilities_found: int = 0
    vulnerable_software: List[Dict] = []


class AMSIMonitorTelemetry(MonitorTelemetry):
    """Windows AMSI integration"""
    amsi_available: bool = False
    scripts_scanned: int = 0
    detections: int = 0
    detection_details: List[Dict] = []


class MonitorsTelemetry(BaseModel):
    """Aggregated telemetry from all monitors"""
    registry: Optional[RegistryMonitorTelemetry] = None
    process_tree: Optional[ProcessTreeMonitorTelemetry] = None
    lolbin: Optional[LOLBinMonitorTelemetry] = None
    code_signing: Optional[CodeSigningMonitorTelemetry] = None
    dns: Optional[DNSMonitorTelemetry] = None
    memory: Optional[MemoryScannerTelemetry] = None
    whitelist: Optional[ApplicationWhitelistTelemetry] = None
    dlp: Optional[DLPMonitorTelemetry] = None
    vulnerability: Optional[VulnerabilityScannerTelemetry] = None
    amsi: Optional[AMSIMonitorTelemetry] = None


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
    # Structured monitor telemetry
    monitors: Optional[MonitorsTelemetry] = None


class DeploymentRequestModel(BaseModel):
    target_platform: str
    target_ip: str
    agent_config: Optional[Dict] = None
    credentials: Optional[Dict] = None


class AgentCommandModel(BaseModel):
    # Standard: scan, remediate, update, restart, shutdown
    # AI Defense: throttle_cli, inject_latency, deploy_decoy, engage_tarpit, 
    #            capture_triage, capture_memory, kill_tree, tag_session, rotate_creds
    command_type: Optional[str] = None
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
async def register_agent(
    agent: AgentRegistrationModel,
    request: Request,
    auth: Dict = Depends(verify_agent_auth)
):
    """Register a new unified agent (requires enrollment key or trusted network)"""
    
    # Log authentication method
    logger.info(f"Agent registration attempt: {agent.agent_id} via {auth['type']} from {auth['ip']}")
    
    # Check if already exists
    existing = await db.unified_agents.find_one({"agent_id": agent.agent_id})
    
    # Generate auth token for the agent
    agent_token = _generate_agent_token(agent.agent_id)
    
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
        return {
            "status": "updated",
            "agent_id": agent.agent_id,
            "auth_token": agent_token,
            "server_ips": list(SERVER_IPS),
            "message": "Store auth_token for future requests via X-Agent-Token header"
        }
    
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
        "alerts_count": 0,
        "enrolled_from_ip": auth['ip'],
        "enrollment_type": auth['type']
    }
    
    await db.unified_agents.insert_one(agent_doc)
    logger.info(f"New agent registered: {agent.agent_id} ({agent.platform}) from {agent.ip_address}")
    
    return {
        "status": "registered",
        "agent_id": agent.agent_id,
        "auth_token": agent_token,
        "server_ips": list(SERVER_IPS),
        "message": "Store auth_token for future requests via X-Agent-Token header"
    }


@router.post("/agents/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    heartbeat: AgentHeartbeatModel,
    request: Request,
    auth: Dict = Depends(verify_agent_auth)
):
    """Receive heartbeat from an agent (authenticated)"""
    
    # Verify agent_id matches if authenticated
    if auth.get('agent_id') and auth['agent_id'] != agent_id:
        raise HTTPException(status_code=403, detail="Agent ID mismatch")
    
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
        "network_connections": heartbeat.network_connections,
        "last_ip": auth['ip']
    }
    
    # Store monitor summary in agent document for quick access
    if heartbeat.monitors:
        monitors_summary = {}
        for monitor_name in ['registry', 'process_tree', 'lolbin', 'code_signing', 
                            'dns', 'memory', 'whitelist', 'dlp', 'vulnerability', 'amsi']:
            monitor_data = getattr(heartbeat.monitors, monitor_name, None)
            if monitor_data:
                monitors_summary[monitor_name] = {
                    "last_run": monitor_data.last_run,
                    "threats_found": monitor_data.threats_found,
                    "status": "active"
                }
        update_data["monitors_summary"] = monitors_summary
    
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
    
    # Store structured monitor telemetry separately
    if heartbeat.monitors:
        monitor_doc = {
            "agent_id": agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        for monitor_name in ['registry', 'process_tree', 'lolbin', 'code_signing', 
                            'dns', 'memory', 'whitelist', 'dlp', 'vulnerability', 'amsi']:
            monitor_data = getattr(heartbeat.monitors, monitor_name, None)
            if monitor_data:
                monitor_doc[monitor_name] = monitor_data.dict()
        
        await db.agent_monitor_telemetry.insert_one(monitor_doc)
    
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


class AgentRenameModel(BaseModel):
    """Model for agent rename/alias change"""
    new_name: str
    new_alias: Optional[str] = None


@router.patch("/agents/{agent_id}/rename")
async def rename_agent(
    agent_id: str,
    rename_data: AgentRenameModel,
    current_user: dict = Depends(check_permission("write"))
):
    """
    Rename an agent or change its display alias.
    
    This allows operators to assign friendly names to agents for easier
    identification in the dashboard, regardless of the original hostname.
    """
    agent = await db.unified_agents.find_one({"agent_id": agent_id})
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Prepare update
    update_fields = {
        "display_name": rename_data.new_name,
        "renamed_at": datetime.now(timezone.utc).isoformat(),
        "renamed_by": current_user.get("username", "unknown")
    }
    
    if rename_data.new_alias:
        update_fields["alias"] = rename_data.new_alias
    
    # Store original name if not already stored
    if not agent.get("original_name"):
        update_fields["original_name"] = agent.get("agent_name", agent.get("hostname", "unknown"))
    
    await db.unified_agents.update_one(
        {"agent_id": agent_id},
        {"$set": update_fields}
    )
    
    logger.info(f"Agent {agent_id} renamed to '{rename_data.new_name}' by {current_user.get('username')}")
    
    return {
        "status": "renamed",
        "agent_id": agent_id,
        "new_name": rename_data.new_name,
        "new_alias": rename_data.new_alias,
        "original_name": update_fields.get("original_name", agent.get("original_name"))
    }


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


@router.get("/agents/{agent_id}/commands")
async def get_agent_commands(
    agent_id: str,
    request: Request,
    auth: Dict = Depends(verify_agent_auth)
):
    """Get pending commands for an agent (polling endpoint for MCP)"""
    
    # Verify agent_id matches if authenticated with token
    if auth.get('agent_id') and auth['agent_id'] != agent_id:
        raise HTTPException(status_code=403, detail="Agent ID mismatch")
    
    # First check in-memory queue (WebSocket manager)
    queued = agent_ws_manager.get_queued_commands(agent_id)
    
    # Also check database for queued commands
    db_commands = await db.agent_commands.find({
        "agent_id": agent_id,
        "status": "queued"
    }).sort("timestamp", 1).limit(10).to_list(length=10)
    
    # Mark as delivered
    if db_commands:
        command_ids = [cmd["command_id"] for cmd in db_commands]
        await db.agent_commands.update_many(
            {"command_id": {"$in": command_ids}},
            {"$set": {"status": "delivered", "delivered_at": datetime.now(timezone.utc).isoformat()}}
        )
    
    # Combine and return
    all_commands = queued + [{
        "command_id": c["command_id"],
        "command_type": c["command_type"],
        "parameters": c.get("parameters", {}),
        "priority": c.get("priority", "normal"),
        "timestamp": c["timestamp"]
    } for c in db_commands]
    
    return {"commands": all_commands, "count": len(all_commands)}


@router.post("/agents/{agent_id}/command-result")
async def report_command_result(
    agent_id: str,
    result: dict,
    request: Request,
    auth: Dict = Depends(verify_agent_auth)
):
    """Receive command execution result from agent"""
    
    # Verify agent_id matches
    if auth.get('agent_id') and auth['agent_id'] != agent_id:
        raise HTTPException(status_code=403, detail="Agent ID mismatch")
    
    command_id = result.get("command_id")
    if not command_id:
        raise HTTPException(status_code=400, detail="Missing command_id")
    
    # Update command status
    await db.agent_commands.update_one(
        {"command_id": command_id},
        {"$set": {
            "status": result.get("status", "completed"),
            "result": result.get("result", {}),
            "completed_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    # Store full result in command_results collection
    await db.command_results.insert_one({
        "command_id": command_id,
        "agent_id": agent_id,
        "command_type": result.get("command_type"),
        "status": result.get("status", "completed"),
        "result": result.get("result", {}),
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    logger.info(f"Command result received: {command_id} from {agent_id} - {result.get('status')}")
    
    return {"status": "received", "command_id": command_id}


@router.get("/commands/{command_id}/status")
async def get_command_status(command_id: str, current_user: dict = Depends(check_permission("read"))):
    """Get the status of a specific command"""
    
    command = await db.agent_commands.find_one({"command_id": command_id})
    if not command:
        raise HTTPException(status_code=404, detail="Command not found")
    
    return {
        "command_id": command_id,
        "agent_id": command.get("agent_id"),
        "command_type": command.get("command_type"),
        "status": command.get("status"),
        "result": command.get("result"),
        "timestamp": command.get("timestamp"),
        "completed_at": command.get("completed_at")
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


@router.get("/agent/install-macos")
async def get_macos_install_script(request: Request, server_url: Optional[str] = None):
    """Get the macOS agent installation script"""
    
    forwarded_proto = request.headers.get("x-forwarded-proto")
    proto = forwarded_proto or request.url.scheme or "http"
    base_url = server_url or f"{proto}://{request.headers.get('host', 'localhost:8001')}"
    
    script = f'''#!/bin/bash
# Seraph AI Unified Agent - macOS Installer

set -e

SERAPH_SERVER="{base_url}"
INSTALL_DIR="$HOME/Library/Application Support/SeraphAgent"
LAUNCH_AGENT_PATH="$HOME/Library/LaunchAgents/com.seraph.agent.plist"

echo "================================================================"
echo "  SERAPH AI UNIFIED AGENT INSTALLER (macOS)"
echo "  Target Server: $SERAPH_SERVER"
echo "================================================================"

# Create installation directory
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Python 3 not found. Installing via Homebrew..."
    if ! command -v brew &> /dev/null; then
        echo "Homebrew not found. Please install it first:"
        echo '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
        exit 1
    fi
    brew install python3
fi

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install psutil requests netifaces watchdog pyyaml scapy

# Download agent
echo "Downloading agent from server..."
curl -sSL "$SERAPH_SERVER/api/unified/agent/download" -o agent.tar.gz
tar -xzf agent.tar.gz
rm agent.tar.gz

# Create LaunchAgent plist for auto-start
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$LAUNCH_AGENT_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.seraph.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/venv/bin/python</string>
        <string>$INSTALL_DIR/core/agent.py</string>
        <string>--server</string>
        <string>$SERAPH_SERVER</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/agent.log</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/agent-error.log</string>
</dict>
</plist>
EOF

# Load the launch agent
launchctl load "$LAUNCH_AGENT_PATH"

echo ""
echo "================================================================"
echo "  INSTALLATION COMPLETE"
echo "================================================================"
echo "Agent installed to: $INSTALL_DIR"
echo "Logs: $INSTALL_DIR/agent.log"
echo "Stop: launchctl unload $LAUNCH_AGENT_PATH"
echo "Start: launchctl load $LAUNCH_AGENT_PATH"
'''
    
    return {"script": script, "usage": f"curl -sSL {base_url}/api/unified/agent/install-macos | bash"}


@router.get("/agent/install-android")
async def get_android_install_script(request: Request, server_url: Optional[str] = None):
    """Get the Android agent installation script (Termux)"""
    
    forwarded_proto = request.headers.get("x-forwarded-proto")
    proto = forwarded_proto or request.url.scheme or "http"
    base_url = server_url or f"{proto}://{request.headers.get('host', 'localhost:8001')}"
    
    script = f'''#!/data/data/com.termux/files/usr/bin/bash
# Seraph AI Unified Agent - Android Installer (Termux)
# Requires: Termux app from F-Droid (Play Store version has limitations)

set -e

SERAPH_SERVER="{base_url}"
INSTALL_DIR="$HOME/seraph-agent"

echo "================================================================"
echo "  SERAPH AI UNIFIED AGENT INSTALLER (Android/Termux)"
echo "  Target Server: $SERAPH_SERVER"
echo "================================================================"

# Update packages
pkg update -y
pkg upgrade -y

# Install Python and dependencies
pkg install -y python python-pip curl openssl

# Create installation directory
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install Python packages
pip install --upgrade pip
pip install psutil requests watchdog aiohttp pyyaml

# Download agent
echo "Downloading agent from server..."
curl -sSL "$SERAPH_SERVER/api/unified/agent/download" -o agent.tar.gz
tar -xzf agent.tar.gz
rm agent.tar.gz

# Create startup script
cat > "$HOME/.termux/boot/start-seraph.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
cd $INSTALL_DIR
source venv/bin/activate
python core/agent.py --server $SERAPH_SERVER &
EOF
chmod +x "$HOME/.termux/boot/start-seraph.sh"

# Create handy control script
cat > "$INSTALL_DIR/seraph-control.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
case "\\$1" in
    start)
        cd $INSTALL_DIR
        source venv/bin/activate
        nohup python core/agent.py --server $SERAPH_SERVER > agent.log 2>&1 &
        echo "Agent started"
        ;;
    stop)
        pkill -f "agent.py"
        echo "Agent stopped"
        ;;
    status)
        pgrep -f "agent.py" > /dev/null && echo "Running" || echo "Stopped"
        ;;
    logs)
        tail -f $INSTALL_DIR/agent.log
        ;;
    *)
        echo "Usage: seraph-control.sh {{start|stop|status|logs}}"
        ;;
esac
EOF
chmod +x "$INSTALL_DIR/seraph-control.sh"

# Start agent
source venv/bin/activate
nohup python core/agent.py --server "$SERAPH_SERVER" > agent.log 2>&1 &

echo ""
echo "================================================================"
echo "  INSTALLATION COMPLETE"
echo "================================================================"
echo "Agent installed to: $INSTALL_DIR"
echo "Control: $INSTALL_DIR/seraph-control.sh {{start|stop|status|logs}}"
echo ""
echo "NOTE: Enable Termux:Boot app for auto-start on device boot"
'''
    
    return {"script": script, "usage": f"curl -sSL {base_url}/api/unified/agent/install-android | bash"}


@router.get("/agent/install-ios")
async def get_ios_install_instructions(request: Request, server_url: Optional[str] = None):
    """Get iOS agent installation instructions (Pythonista or native app)"""
    
    forwarded_proto = request.headers.get("x-forwarded-proto")
    proto = forwarded_proto or request.url.scheme or "http"
    base_url = server_url or f"{proto}://{request.headers.get('host', 'localhost:8001')}"
    
    pythonista_script = f'''# Seraph AI Agent for iOS (Pythonista 3)
# Copy this script to Pythonista and run it

import requests
import json
import uuid
import platform
import socket
import time
import threading
from datetime import datetime

SERAPH_SERVER = "{base_url}"
AGENT_ID = f"ios-{{uuid.uuid4().hex[:8]}}"
UPDATE_INTERVAL = 60

class iOSAgent:
    def __init__(self):
        self.running = False
        self.agent_id = AGENT_ID
    
    def get_system_info(self):
        return {{
            "hostname": socket.gethostname(),
            "platform": "ios",
            "version": platform.version(),
            "python": platform.python_version()
        }}
    
    def register(self):
        try:
            response = requests.post(
                f"{{SERAPH_SERVER}}/api/unified/agents/register",
                json={{
                    "agent_id": self.agent_id,
                    "platform": "ios",
                    "hostname": socket.gethostname(),
                    "ip_address": socket.gethostbyname(socket.gethostname()),
                    "version": "1.0.0",
                    "capabilities": ["monitor", "scan"]
                }},
                timeout=10
            )
            print(f"Registered: {{response.json()}}")
            return True
        except Exception as e:
            print(f"Registration failed: {{e}}")
            return False
    
    def heartbeat(self):
        try:
            response = requests.post(
                f"{{SERAPH_SERVER}}/api/unified/agents/{{self.agent_id}}/heartbeat",
                json={{
                    "status": "online",
                    "cpu_usage": 0,
                    "memory_usage": 0,
                    "timestamp": datetime.now().isoformat()
                }},
                timeout=10
            )
            return True
        except Exception as e:
            print(f"Heartbeat failed: {{e}}")
            return False
    
    def poll_commands(self):
        try:
            response = requests.get(
                f"{{SERAPH_SERVER}}/api/unified/agents/{{self.agent_id}}/commands",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                for cmd in data.get("commands", []):
                    self.execute_command(cmd)
        except Exception as e:
            print(f"Command poll failed: {{e}}")
    
    def execute_command(self, cmd):
        cmd_type = cmd.get("command_type", "")
        print(f"Executing: {{cmd_type}}")
        
        result = {{"command_id": cmd.get("command_id"), "status": "completed", "result": {{}}}}
        
        if cmd_type == "get_status":
            result["result"] = self.get_system_info()
        
        # Report result
        try:
            requests.post(
                f"{{SERAPH_SERVER}}/api/unified/agents/{{self.agent_id}}/command-result",
                json=result,
                timeout=10
            )
        except:
            pass
    
    def run(self):
        print(f"Starting iOS Agent: {{self.agent_id}}")
        self.running = True
        
        if not self.register():
            print("Failed to register. Retrying in 30s...")
            time.sleep(30)
            self.register()
        
        while self.running:
            self.heartbeat()
            self.poll_commands()
            time.sleep(UPDATE_INTERVAL)
    
    def stop(self):
        self.running = False
        print("Agent stopped")

# Run agent
agent = iOSAgent()

# For Pythonista, run in background
def start_background():
    thread = threading.Thread(target=agent.run, daemon=True)
    thread.start()
    print("Agent running in background")
    return thread

# Start agent
start_background()
'''
    
    return {
        "platform": "ios",
        "methods": [
            {
                "name": "Pythonista 3 App",
                "description": "Run agent as Python script in Pythonista 3",
                "script": pythonista_script,
                "steps": [
                    "1. Download Pythonista 3 from App Store",
                    "2. Create new script and paste the code below",
                    "3. Run the script",
                    "4. Agent will register and start monitoring"
                ]
            },
            {
                "name": "Native SwiftUI App",
                "description": "Build and install the native iOS app",
                "steps": [
                    "1. Clone the repository",
                    "2. Open unified_agent/ui/ios/MetatronAgentApp.xcodeproj",
                    "3. Configure server URL in settings",
                    "4. Build and install on device (requires Apple Developer account)"
                ],
                "download_url": f"{base_url}/api/unified/agent/ios-source"
            }
        ]
    }


@router.get("/agent/installers")
async def get_all_installers(request: Request, server_url: Optional[str] = None):
    """Get installation info for all supported platforms"""
    
    forwarded_proto = request.headers.get("x-forwarded-proto")
    proto = forwarded_proto or request.url.scheme or "http"
    base_url = server_url or f"{proto}://{request.headers.get('host', 'localhost:8001')}"
    
    return {
        "server_url": base_url,
        "platforms": {
            "linux": {
                "name": "Linux",
                "icon": "🐧",
                "endpoint": f"{base_url}/api/unified/agent/install-script",
                "install_command": f"curl -sSL {base_url}/api/unified/agent/install-script | sudo bash",
                "requirements": ["Python 3.8+", "Root access", "systemd"]
            },
            "windows": {
                "name": "Windows",
                "icon": "🪟",
                "endpoint": f"{base_url}/api/unified/agent/install-windows",
                "install_command": f"Invoke-WebRequest -Uri {base_url}/api/unified/agent/install-windows | Invoke-Expression",
                "requirements": ["Python 3.8+", "Administrator access", "PowerShell 5+"]
            },
            "macos": {
                "name": "macOS",
                "icon": "🍎",
                "endpoint": f"{base_url}/api/unified/agent/install-macos",
                "install_command": f"curl -sSL {base_url}/api/unified/agent/install-macos | bash",
                "requirements": ["Python 3.8+ (via Homebrew)", "User account"]
            },
            "android": {
                "name": "Android",
                "icon": "🤖",
                "endpoint": f"{base_url}/api/unified/agent/install-android",
                "install_command": f"curl -sSL {base_url}/api/unified/agent/install-android | bash",
                "requirements": ["Termux app from F-Droid", "Termux:Boot (optional, for auto-start)"]
            },
            "ios": {
                "name": "iOS",
                "icon": "📱",
                "endpoint": f"{base_url}/api/unified/agent/install-ios",
                "methods": ["Pythonista 3", "Native SwiftUI App"],
                "requirements": ["Pythonista 3 app OR Xcode + Apple Developer account"]
            }
        }
    }


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


# ============================================================================
# MONITOR TELEMETRY ENDPOINTS
# ============================================================================

@router.get("/agents/{agent_id}/monitors")
async def get_agent_monitors(
    agent_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get all monitor summaries for an agent."""
    agent = await db.unified_agents.find_one({"agent_id": agent_id})
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    monitors_summary = agent.get("monitors_summary", {})
    
    # Get latest detailed telemetry for each monitor
    latest_telemetry = await db.agent_monitor_telemetry.find_one(
        {"agent_id": agent_id},
        sort=[("timestamp", -1)]
    )
    
    return {
        "agent_id": agent_id,
        "monitors_summary": monitors_summary,
        "latest_telemetry": latest_telemetry.get("monitors") if latest_telemetry else None,
        "last_updated": agent.get("last_heartbeat")
    }


@router.get("/agents/{agent_id}/monitors/{monitor_name}")
async def get_agent_monitor_history(
    agent_id: str,
    monitor_name: str,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get historical telemetry for a specific monitor."""
    valid_monitors = [
        "registry", "process_tree", "lolbin", "code_signing", "dns",
        "memory", "app_whitelist", "dlp", "vulnerability", "amsi"
    ]
    
    if monitor_name not in valid_monitors:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid monitor name. Valid monitors: {valid_monitors}"
        )
    
    # Fetch historical telemetry for this monitor
    cursor = db.agent_monitor_telemetry.find(
        {"agent_id": agent_id, f"monitors.{monitor_name}": {"$exists": True}},
        {f"monitors.{monitor_name}": 1, "timestamp": 1, "_id": 0}
    ).sort("timestamp", -1).limit(limit)
    
    history = []
    async for doc in cursor:
        if doc.get("monitors", {}).get(monitor_name):
            history.append({
                "timestamp": doc.get("timestamp"),
                "data": doc["monitors"][monitor_name]
            })
    
    return {
        "agent_id": agent_id,
        "monitor": monitor_name,
        "history": history,
        "count": len(history)
    }


@router.get("/stats/monitors")
async def get_monitors_aggregate_stats(
    current_user: dict = Depends(get_current_user)
):
    """Get aggregate monitor statistics across all agents."""
    # Aggregate monitor stats across all agents
    pipeline = [
        {"$match": {"monitors_summary": {"$exists": True}}},
        {"$group": {
            "_id": None,
            "total_agents": {"$sum": 1},
            "registry_alerts": {"$sum": {"$ifNull": ["$monitors_summary.registry.alerts", 0]}},
            "registry_persistence": {"$sum": {"$ifNull": ["$monitors_summary.registry.persistence_locations", 0]}},
            "process_tree_anomalies": {"$sum": {"$ifNull": ["$monitors_summary.process_tree.anomalies", 0]}},
            "lolbin_detections": {"$sum": {"$ifNull": ["$monitors_summary.lolbin.detections", 0]}},
            "unsigned_binaries": {"$sum": {"$ifNull": ["$monitors_summary.code_signing.unsigned", 0]}},
            "dns_alerts": {"$sum": {"$ifNull": ["$monitors_summary.dns.alerts", 0]}},
            "dga_detections": {"$sum": {"$ifNull": ["$monitors_summary.dns.dga_detected", 0]}},
            "memory_injections": {"$sum": {"$ifNull": ["$monitors_summary.memory.injections", 0]}},
            "rwx_regions": {"$sum": {"$ifNull": ["$monitors_summary.memory.rwx_regions", 0]}},
            "whitelist_violations": {"$sum": {"$ifNull": ["$monitors_summary.app_whitelist.violations", 0]}},
            "dlp_alerts": {"$sum": {"$ifNull": ["$monitors_summary.dlp.total_alerts", 0]}},
            "vulnerabilities_critical": {"$sum": {"$ifNull": ["$monitors_summary.vulnerability.critical", 0]}},
            "vulnerabilities_high": {"$sum": {"$ifNull": ["$monitors_summary.vulnerability.high", 0]}},
            "amsi_threats": {"$sum": {"$ifNull": ["$monitors_summary.amsi.threats_detected", 0]}},
            # New monitors - Ransomware
            "canary_alerts": {"$sum": {"$ifNull": ["$monitors_summary.ransomware.canary_alerts", 0]}},
            "shadow_copy_attempts": {"$sum": {"$ifNull": ["$monitors_summary.ransomware.shadow_copy_threats", 0]}},
            "entropy_alerts": {"$sum": {"$ifNull": ["$monitors_summary.ransomware.entropy_alerts", 0]}},
            # New monitors - Rootkit
            "hidden_processes": {"$sum": {"$ifNull": ["$monitors_summary.rootkit.hidden_processes", 0]}},
            "kernel_module_threats": {"$sum": {"$ifNull": ["$monitors_summary.rootkit.kernel_module_threats", 0]}},
            "dkom_detections": {"$sum": {"$ifNull": ["$monitors_summary.rootkit.dkom_detections", 0]}},
            # New monitors - Kernel Security
            "syscall_anomalies": {"$sum": {"$ifNull": ["$monitors_summary.kernel_security.syscall_anomalies", 0]}},
            "ptrace_detections": {"$sum": {"$ifNull": ["$monitors_summary.kernel_security.ptrace_detections", 0]}},
            "audit_log_alerts": {"$sum": {"$ifNull": ["$monitors_summary.kernel_security.audit_alerts", 0]}},
            # New monitors - Self Protection
            "tamper_events": {"$sum": {"$ifNull": ["$monitors_summary.self_protection.tamper_events", 0]}},
            "debug_attempts": {"$sum": {"$ifNull": ["$monitors_summary.self_protection.debug_attempts", 0]}},
            "injection_attempts": {"$sum": {"$ifNull": ["$monitors_summary.self_protection.injection_attempts", 0]}},
            # New monitors - Identity Protection  
            "credential_tools": {"$sum": {"$ifNull": ["$monitors_summary.identity.credential_tools_detected", 0]}},
            "lsass_access": {"$sum": {"$ifNull": ["$monitors_summary.identity.lsass_access_events", 0]}},
            "kerberos_anomalies": {"$sum": {"$ifNull": ["$monitors_summary.identity.kerberos_anomalies", 0]}},
            # ============================================
            # NEW MONITORS - Unified Agent v2.0
            # ============================================
            # Trusted AI Detection
            "trusted_ai_violations": {"$sum": {"$ifNull": ["$monitors_summary.trusted_ai.violations", 0]}},
            "untrusted_models": {"$sum": {"$ifNull": ["$monitors_summary.trusted_ai.untrusted_models", 0]}},
            "ai_processes": {"$sum": {"$ifNull": ["$monitors_summary.trusted_ai.total_processes", 0]}},
            # Bootkit Detection
            "bootkit_threats": {"$sum": {"$ifNull": ["$monitors_summary.bootkit.threats_detected", 0]}},
            "mbr_anomalies": {"$sum": {"$ifNull": ["$monitors_summary.bootkit.mbr_threats", 0]}},
            "uefi_violations": {"$sum": {"$ifNull": ["$monitors_summary.bootkit.uefi_violations", 0]}},
            # Certificate Authority Monitor
            "rogue_ca_certs": {"$sum": {"$ifNull": ["$monitors_summary.certificate_authority.rogue_certs", 0]}},
            "untrusted_roots": {"$sum": {"$ifNull": ["$monitors_summary.certificate_authority.untrusted_roots", 0]}},
            # BIOS/UEFI Security
            "bios_threats": {"$sum": {"$ifNull": ["$monitors_summary.bios_uefi.threats_detected", 0]}},
            "secure_boot_disabled": {"$sum": {"$ifNull": ["$monitors_summary.bios_uefi.secure_boot_disabled", 0]}},
            # Scheduled Task Monitor
            "suspicious_tasks": {"$sum": {"$ifNull": ["$monitors_summary.scheduled_task.suspicious_count", 0]}},
            "hidden_tasks": {"$sum": {"$ifNull": ["$monitors_summary.scheduled_task.hidden_tasks", 0]}},
            # Service Integrity Monitor
            "suspicious_services": {"$sum": {"$ifNull": ["$monitors_summary.service_integrity.suspicious_count", 0]}},
            "service_dll_hijacks": {"$sum": {"$ifNull": ["$monitors_summary.service_integrity.dll_hijacks", 0]}},
            # WMI Persistence Monitor
            "wmi_consumers": {"$sum": {"$ifNull": ["$monitors_summary.wmi_persistence.suspicious_consumers", 0]}},
            "wmi_subscriptions": {"$sum": {"$ifNull": ["$monitors_summary.wmi_persistence.malicious_subscriptions", 0]}},
            # USB Device Monitor
            "usb_violations": {"$sum": {"$ifNull": ["$monitors_summary.usb_device.violations", 0]}},
            "unauthorized_usb": {"$sum": {"$ifNull": ["$monitors_summary.usb_device.unauthorized_devices", 0]}},
            # Power State Monitor
            "power_anomalies": {"$sum": {"$ifNull": ["$monitors_summary.power_state.anomalies", 0]}},
            "wake_on_lan_events": {"$sum": {"$ifNull": ["$monitors_summary.power_state.wol_events", 0]}},
            # AutoThrottle Monitor
            "throttled_processes": {"$sum": {"$ifNull": ["$monitors_summary.auto_throttle.throttled_count", 0]}},
            "cryptominers": {"$sum": {"$ifNull": ["$monitors_summary.auto_throttle.cryptominers_detected", 0]}},
            # Firewall Monitor
            "firewall_disabled": {"$sum": {"$ifNull": ["$monitors_summary.firewall.disabled_count", 0]}},
            "firewall_rules": {"$sum": {"$ifNull": ["$monitors_summary.firewall.suspicious_rules", 0]}},
            # WebView2 Monitor
            "webview2_suspicious": {"$sum": {"$ifNull": ["$monitors_summary.webview2.suspicious_instances", 0]}},
            "webview2_debug": {"$sum": {"$ifNull": ["$monitors_summary.webview2.remote_debug_active", 0]}},
            # CLI Telemetry
            "cli_commands": {"$sum": {"$ifNull": ["$monitors_summary.cli_telemetry.commands_captured", 0]}},
            "cli_lolbins": {"$sum": {"$ifNull": ["$monitors_summary.cli_telemetry.lolbin_executions", 0]}},
            # Hidden File Scanner
            "hidden_files": {"$sum": {"$ifNull": ["$monitors_summary.hidden_file.hidden_count", 0]}},
            "ads_found": {"$sum": {"$ifNull": ["$monitors_summary.hidden_file.ads_streams", 0]}},
            # Alias/Rename Monitor
            "renamed_exes": {"$sum": {"$ifNull": ["$monitors_summary.alias_rename.renamed_executables", 0]}},
            "path_hijacks": {"$sum": {"$ifNull": ["$monitors_summary.alias_rename.path_hijack_risks", 0]}},
            # Privilege Escalation
            "dangerous_privs": {"$sum": {"$ifNull": ["$monitors_summary.privilege_escalation.dangerous_privileges", 0]}},
            "system_processes": {"$sum": {"$ifNull": ["$monitors_summary.privilege_escalation.system_processes", 0]}},
            "system_tasks": {"$sum": {"$ifNull": ["$monitors_summary.privilege_escalation.non_ms_system_tasks", 0]}}
        }}
    ]
    
    result = await db.unified_agents.aggregate(pipeline).to_list(1)
    
    if not result:
        return {
            "total_agents": 0,
            "monitors": {}
        }
    
    stats = result[0]
    del stats["_id"]
    
    # Organize into categories
    return {
        "total_agents_with_monitors": stats.pop("total_agents", 0),
        "threat_summary": {
            "registry_persistence": stats.get("registry_persistence", 0),
            "process_anomalies": stats.get("process_tree_anomalies", 0),
            "lolbin_abuse": stats.get("lolbin_detections", 0),
            "memory_injections": stats.get("memory_injections", 0),
            "dga_domains": stats.get("dga_detections", 0),
            "amsi_threats": stats.get("amsi_threats", 0),
            # Ransomware
            "canary_alerts": stats.get("canary_alerts", 0),
            "shadow_copy_attempts": stats.get("shadow_copy_attempts", 0),
            "entropy_alerts": stats.get("entropy_alerts", 0),
            # Rootkit
            "hidden_processes": stats.get("hidden_processes", 0),
            "kernel_module_threats": stats.get("kernel_module_threats", 0),
            "dkom_detections": stats.get("dkom_detections", 0),
            # Kernel Security
            "syscall_anomalies": stats.get("syscall_anomalies", 0),
            "ptrace_detections": stats.get("ptrace_detections", 0),
            "audit_log_alerts": stats.get("audit_log_alerts", 0),
            # Self Protection
            "tamper_events": stats.get("tamper_events", 0),
            "debug_attempts": stats.get("debug_attempts", 0),
            "injection_attempts": stats.get("injection_attempts", 0),
            # Identity Protection
            "credential_tools": stats.get("credential_tools", 0),
            "lsass_access": stats.get("lsass_access", 0),
            "kerberos_anomalies": stats.get("kerberos_anomalies", 0),
            # ============================================
            # NEW MONITORS - Unified Agent v2.0
            # ============================================
            # Trusted AI Detection
            "trusted_ai_violations": stats.get("trusted_ai_violations", 0),
            "untrusted_models": stats.get("untrusted_models", 0),
            "ai_processes": stats.get("ai_processes", 0),
            # Bootkit Detection
            "bootkit_threats": stats.get("bootkit_threats", 0),
            "mbr_anomalies": stats.get("mbr_anomalies", 0),
            "uefi_violations": stats.get("uefi_violations", 0),
            # Certificate Authority Monitor
            "rogue_ca_certs": stats.get("rogue_ca_certs", 0),
            "untrusted_roots": stats.get("untrusted_roots", 0),
            # BIOS/UEFI Security
            "bios_threats": stats.get("bios_threats", 0),
            "secure_boot_disabled": stats.get("secure_boot_disabled", 0),
            # Scheduled Task Monitor
            "suspicious_tasks": stats.get("suspicious_tasks", 0),
            "hidden_tasks": stats.get("hidden_tasks", 0),
            # Service Integrity Monitor
            "suspicious_services": stats.get("suspicious_services", 0),
            "service_dll_hijacks": stats.get("service_dll_hijacks", 0),
            # WMI Persistence Monitor
            "wmi_consumers": stats.get("wmi_consumers", 0),
            "wmi_subscriptions": stats.get("wmi_subscriptions", 0),
            # USB Device Monitor
            "usb_violations": stats.get("usb_violations", 0),
            "unauthorized_usb": stats.get("unauthorized_usb", 0),
            # Power State Monitor
            "power_anomalies": stats.get("power_anomalies", 0),
            "wake_on_lan_events": stats.get("wake_on_lan_events", 0),
            # AutoThrottle Monitor
            "throttled_processes": stats.get("throttled_processes", 0),
            "cryptominers": stats.get("cryptominers", 0),
            # Firewall Monitor
            "firewall_disabled": stats.get("firewall_disabled", 0),
            "firewall_rules": stats.get("firewall_rules", 0),
            # WebView2 Monitor
            "webview2_suspicious": stats.get("webview2_suspicious", 0),
            "webview2_debug": stats.get("webview2_debug", 0),
            # CLI Telemetry
            "cli_commands": stats.get("cli_commands", 0),
            "cli_lolbins": stats.get("cli_lolbins", 0),
            # Hidden File Scanner
            "hidden_files": stats.get("hidden_files", 0),
            "ads_found": stats.get("ads_found", 0),
            # Alias/Rename Monitor
            "renamed_exes": stats.get("renamed_exes", 0),
            "path_hijacks": stats.get("path_hijacks", 0),
            # Privilege Escalation
            "dangerous_privs": stats.get("dangerous_privs", 0),
            "system_processes": stats.get("system_processes", 0),
            "system_tasks": stats.get("system_tasks", 0)
        },
        "compliance_summary": {
            "unsigned_binaries": stats.get("unsigned_binaries", 0),
            "whitelist_violations": stats.get("whitelist_violations", 0),
            "dlp_alerts": stats.get("dlp_alerts", 0),
            "critical_vulnerabilities": stats.get("vulnerabilities_critical", 0),
            "high_vulnerabilities": stats.get("vulnerabilities_high", 0)
        },
        "raw_stats": stats
    }


@router.get("/monitors/alerts")
async def get_recent_monitor_alerts(
    limit: int = 50,
    monitor_type: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get recent alerts from all monitors across all agents."""
    # Build match conditions
    match_conditions = {}
    
    if monitor_type:
        valid_monitors = [
            "registry", "process_tree", "lolbin", "code_signing", "dns",
            "memory", "app_whitelist", "dlp", "vulnerability", "amsi",
            "ransomware", "rootkit", "kernel_security", "self_protection", "identity"
        ]
        if monitor_type not in valid_monitors:
            raise HTTPException(status_code=400, detail=f"Invalid monitor type")
        match_conditions[f"monitors.{monitor_type}"] = {"$exists": True}
    
    # Fetch recent telemetry with alerts
    cursor = db.agent_monitor_telemetry.find(
        match_conditions,
        {"agent_id": 1, "timestamp": 1, "monitors": 1, "_id": 0}
    ).sort("timestamp", -1).limit(limit)
    
    alerts = []
    async for doc in cursor:
        monitors = doc.get("monitors", {})
        for mon_name, mon_data in monitors.items():
            if isinstance(mon_data, dict):
                # Check for alerts/detections in this monitor
                alert_count = (
                    mon_data.get("alerts", 0) or
                    mon_data.get("detections", 0) or
                    mon_data.get("threats_detected", 0) or
                    mon_data.get("total_alerts", 0) or
                    mon_data.get("anomalies_detected", 0) or
                    mon_data.get("injections_detected", 0)
                )
                if alert_count and alert_count > 0:
                    alerts.append({
                        "agent_id": doc.get("agent_id"),
                        "monitor": mon_name,
                        "timestamp": doc.get("timestamp"),
                        "alert_count": alert_count,
                        "details": mon_data
                    })
    
    return {
        "alerts": alerts,
        "count": len(alerts),
        "filter": {
            "monitor_type": monitor_type,
            "severity": severity
        }
    }
