from __future__ import annotations
"""
Unified Agent Router - Metatron Integration
============================================
API endpoints for the Metatron/Seraph unified agent management system.
Provides cross-platform agent registration, heartbeat, deployment, and monitoring.
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect, Request, Header
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict
from datetime import datetime, timezone, timedelta
import secrets
import logging
import asyncio
import hmac
import hashlib
import json
import os
import socket
import ipaddress

# Outbound gating: ensure potentially impactful agent commands are queued for triune approval
from backend.services.governed_dispatch import GovernedDispatchService


class EDMHitTelemetryModel(BaseModel):
    """EDM match telemetry emitted by endpoint agents."""
    dataset_id: str
    record_id: Optional[str] = None
    fingerprint: str
    host: Optional[str] = None
    process: Optional[str] = None
    file_path_masked: Optional[str] = None
    source: Optional[str] = None
    timestamp: Optional[str] = None
    # Additional field for telemetry
    additional_info: Optional[str] = None

from .dependencies import get_db
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
try:
    from services.telemetry_chain import tamper_evident_telemetry
except Exception:
    from backend.services.telemetry_chain import tamper_evident_telemetry
try:
    from .dependencies import get_current_user, check_permission, db, verify_websocket_machine_token
except Exception:
    def get_current_user(*args, **kwargs):
        return None

    def check_permission(required_permission: str):
        async def _checker(*a, **k):
            return None
        return _checker

    db = None

    def verify_websocket_machine_token(*args, **kwargs):
        return {"auth": "ok"}

logger = logging.getLogger('seraph.unified_agent')

router = APIRouter(prefix="/unified", tags=["Unified Agent"])
ALERT_STATUSES = {"unacknowledged", "acknowledged"}
MONITOR_TELEMETRY_KEYS = [
    "registry",
    "process_tree",
    "lolbin",
    "code_signing",
    "dns",
    "memory",
    "whitelist",
    "dlp",
    "vulnerability",
    "amsi",
    "firewall",
    "ransomware",
    "rootkit",
    "kernel_security",
    "self_protection",
    "identity",
    "auto_throttle",
    "cli_telemetry",
    "hidden_file",
    "alias_rename",
    "priv_escalation",
    "email_protection",
    "mobile_security",
    "webview2",
]


def _record_unified_audit(
    *,
    principal: str,
    action: str,
    targets: List[str],
    result: str,
    result_details: Optional[str] = None,
    constraints: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        tamper_evident_telemetry.set_db(get_db())
        tamper_evident_telemetry.record_action(
            principal=principal,
            principal_trust_state="trusted",
            action=action,
            targets=targets,
            constraints=constraints or {},
            result=result,
            result_details=result_details,
        )
    except Exception:
        logger.exception("Failed to record unified audit action: %s", action)


def _coerce_monitor_payload(monitor_data: Any) -> Dict[str, Any]:
    if monitor_data is None:
        return {}
    if isinstance(monitor_data, dict):
        return dict(monitor_data)
    if hasattr(monitor_data, "model_dump"):
        try:
            return monitor_data.model_dump()
        except Exception:
            return {}
    return {}


def _extract_telemetry_threat_count(telemetry: Optional[Dict[str, Any]]) -> int:
    if not isinstance(telemetry, dict):
        return 0
    direct_count = telemetry.get("threat_count")
    if isinstance(direct_count, (int, float)):
        return max(0, int(direct_count))
    threats = telemetry.get("threats")
    if isinstance(threats, list):
        return len(threats)
    detections = telemetry.get("detections")
    if isinstance(detections, list):
        return len(detections)
    return 0


def _build_monitor_summary(monitors: Any) -> Dict[str, Dict[str, Any]]:
    if not monitors:
        return {}
    summary: Dict[str, Dict[str, Any]] = {}
    for monitor_name in MONITOR_TELEMETRY_KEYS:
        payload = _coerce_monitor_payload(getattr(monitors, monitor_name, None))
        if not payload:
            continue
        threats_found = payload.get("threats_found")
        if not isinstance(threats_found, (int, float)):
            threats_found = 0
        condensed = {
            "last_run": payload.get("last_run"),
            "threats_found": int(threats_found),
            "status": "active",
        }
        # Preserve numeric/boolean detail fields so downstream analytics can aggregate.
        for key, value in payload.items():
            if key in condensed:
                continue
            if isinstance(value, (int, float, bool, str)):
                condensed[key] = value
        summary[monitor_name] = condensed
    return summary


async def _project_unified_state_snapshot(
    *,
    agent_id: str,
    source: str,
    status: Optional[str],
    telemetry: Optional[Dict[str, Any]] = None,
    monitors_summary: Optional[Dict[str, Dict[str, Any]]] = None,
) -> None:
    db_handle = get_db()
    if db_handle is None or not hasattr(db_handle, "world_entities"):
        return
    monitors_summary = monitors_summary or {}
    monitor_threat_total = sum(int((item or {}).get("threats_found") or 0) for item in monitors_summary.values())
    telemetry_threat_count = _extract_telemetry_threat_count(telemetry if isinstance(telemetry, dict) else {})
    hot_monitors = [
        name for name, item in monitors_summary.items()
        if int((item or {}).get("threats_found") or 0) > 0
    ][:12]
    trust_state = "trusted"
    if monitor_threat_total >= 8 or telemetry_threat_count >= 8:
        trust_state = "compromised"
    elif monitor_threat_total > 0 or telemetry_threat_count > 0:
        trust_state = "degraded"

    now = datetime.now(timezone.utc).isoformat()
    attributes = {
        "agent_status": status or "unknown",
        "trust_state": trust_state,
        "last_projection_source": source,
        "monitor_summary": monitors_summary,
        "monitor_threat_total": monitor_threat_total,
        "telemetry_threat_count": telemetry_threat_count,
        "hot_monitors": hot_monitors,
        "updated_at": now,
    }
    if isinstance(telemetry, dict):
        attributes["telemetry_overview"] = {
            "cpu_usage": telemetry.get("cpu_usage"),
            "memory_usage": telemetry.get("memory_usage"),
            "disk_usage": telemetry.get("disk_usage"),
            "network_connections": telemetry.get("network_connections"),
            "process_count": telemetry.get("process_count"),
        }
    try:
        await db_handle.world_entities.update_one(
            {"id": agent_id},
            {
                "$set": {
                    "id": agent_id,
                    "type": "agent",
                    "updated": now,
                    "attributes": attributes,
                }
            },
            upsert=True,
        )
    except Exception:
        logger.exception("Failed to project unified agent state for %s", agent_id)
        return

    trigger_triune = (monitor_threat_total + telemetry_threat_count) >= 3
    try:
        await emit_world_event(
            db_handle,
            event_type="unified_agent_world_state_projected",
            entity_refs=[agent_id],
            payload={
                "source": source,
                "trust_state": trust_state,
                "monitor_threat_total": monitor_threat_total,
                "telemetry_threat_count": telemetry_threat_count,
                "hot_monitors": hot_monitors,
            },
            trigger_triune=trigger_triune,
        )
        _record_unified_audit(
            principal=f"agent:{agent_id}",
            action="unified_agent_world_state_projection",
            targets=[agent_id],
            result="success",
            constraints={
                "source": source,
                "monitor_threat_total": monitor_threat_total,
                "telemetry_threat_count": telemetry_threat_count,
                "trust_state": trust_state,
            },
        )
    except Exception:
        logger.exception("Failed to emit world-state projection event for %s", agent_id)


def _alert_transition_entry(
    from_status: Optional[str],
    to_status: str,
    actor: str,
    reason: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    entry = {
        "from_status": from_status,
        "to_status": to_status,
        "actor": actor,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if metadata:
        entry["metadata"] = metadata
    return entry


def _build_unified_alert_doc(
    *,
    alert_id: str,
    agent_id: str,
    severity: str,
    category: str,
    message: str,
    details: Optional[Dict[str, Any]],
    mitre_technique: Optional[str],
    actor: str,
    reason: str,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    return {
        "alert_id": alert_id,
        "agent_id": agent_id,
        "severity": severity,
        "category": category,
        "message": message,
        "details": details or {},
        "mitre_technique": mitre_technique,
        "timestamp": ts,
        "acknowledged": False,
        "status": "unacknowledged",
        "updated_at": ts,
        "state_version": 1,
        "state_transition_log": [
            _alert_transition_entry(
                from_status=None,
                to_status="unacknowledged",
                actor=actor,
                reason=reason,
            )
        ],
    }


async def _ensure_unified_alert_state_fields(
    alert_id: str,
    *,
    actor: str,
    reason: str,
) -> Dict[str, Any]:
    alert = await db.unified_alerts.find_one({"alert_id": alert_id}, {"_id": 0})
    if not alert:
        return {}

    if alert.get("state_version") is not None and alert.get("state_transition_log") is not None:
        return alert

    current_status = str(alert.get("status") or ("acknowledged" if alert.get("acknowledged") else "unacknowledged"))
    if current_status not in ALERT_STATUSES:
        current_status = "acknowledged" if alert.get("acknowledged") else "unacknowledged"

    bootstrap = {
        "status": current_status,
        "state_version": int(alert.get("state_version") or 1),
        "state_transition_log": alert.get("state_transition_log")
        or [
            _alert_transition_entry(
                from_status=None,
                to_status=current_status,
                actor=actor,
                reason=reason,
            )
        ],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.unified_alerts.update_one({"alert_id": alert_id}, {"$set": bootstrap})
    return await db.unified_alerts.find_one({"alert_id": alert_id}, {"_id": 0}) or {}


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
EDM_DATASET_COLLECTION = "edm_dataset_versions"
EDM_HITS_COLLECTION = "agent_edm_telemetry"
EDM_ROLLOUT_COLLECTION = "edm_rollouts"
_edm_indexes_ready = False
EDM_CONTROL_PLANE_CONTRACT_VERSION = "2026-03-07.1"
UNIFIED_DEPLOYMENT_TERMINAL_STATUSES = {"completed", "failed"}

# EDM publish-time quality gates
EDM_MAX_RECORDS_PER_PUBLISH = max(1000, int(os.environ.get("EDM_MAX_RECORDS_PER_PUBLISH", "20000")))
EDM_MIN_CANONICAL_COVERAGE = min(max(float(os.environ.get("EDM_MIN_CANONICAL_COVERAGE", "0.95")), 0.0), 1.0)
EDM_MIN_ALLOWED_MIN_CONFIDENCE = min(max(float(os.environ.get("EDM_MIN_ALLOWED_MIN_CONFIDENCE", "0.85")), 0.0), 1.0)
EDM_ALLOWED_CANDIDATE_TYPES = {
    "line",
    "delimited_bundle",
    "delimited_window_4",
    "delimited_window_3",
    "delimited_window_2",
}

# Trusted networks that agents can connect from (CIDR notation)
TRUSTED_NETWORKS = [
    "127.0.0.0/8",      # Localhost
    "10.0.0.0/8",       # Private Class A
    "172.16.0.0/12",    # Private Class B
    "192.168.0.0/16",   # Private Class C
    "::1/128",          # IPv6 localhost
    "fe80::/10",        # IPv6 link-local
]
ALLOW_TRUSTED_NETWORK_FALLBACK = os.environ.get(
    "UNIFIED_AGENT_ALLOW_TRUSTED_NETWORK_AUTH",
    "false",
).strip().lower() in {"1", "true", "yes", "on"}

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
    
    # Optional compatibility fallback (disabled by default).
    if is_trusted_network and ALLOW_TRUSTED_NETWORK_FALLBACK:
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
    local_ui_url: Optional[str] = None  # URL of the agent's built-in local web UI


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
    model_config = ConfigDict(extra="allow")
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
    firewall: Optional[Dict[str, Any]] = None
    ransomware: Optional[Dict[str, Any]] = None
    rootkit: Optional[Dict[str, Any]] = None
    kernel_security: Optional[Dict[str, Any]] = None
    self_protection: Optional[Dict[str, Any]] = None
    identity: Optional[Dict[str, Any]] = None
    auto_throttle: Optional[Dict[str, Any]] = None
    cli_telemetry: Optional[Dict[str, Any]] = None
    hidden_file: Optional[Dict[str, Any]] = None
    alias_rename: Optional[Dict[str, Any]] = None
    priv_escalation: Optional[Dict[str, Any]] = None
    email_protection: Optional[Dict[str, Any]] = None
    mobile_security: Optional[Dict[str, Any]] = None
    webview2: Optional[Dict[str, Any]] = None


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
    edm_hits: List[EDMHitTelemetryModel] = []
    # Structured monitor telemetry
    monitors: Optional[MonitorsTelemetry] = None
    endpoint_fortress: Optional[Dict[str, Any]] = None
    local_ui_url: Optional[str] = None  # URL of the agent's built-in local web UI


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


class ToolingCommandModel(BaseModel):
    """Payload for explicit endpoint tooling commands (Trivy/Falco/Suricata/Volatility)."""
    parameters: Dict[str, Any] = {}
    priority: str = "normal"


class RemediationProposalModel(BaseModel):
    """Agent-submitted remediation proposal for governance gating."""
    action: str
    parameters: Dict[str, Any] = {}
    priority: str = "critical"
    reason: Optional[str] = None
    threat: Optional[Dict[str, Any]] = None


class EDMDatasetCommandModel(BaseModel):
    """Payload for updating EDM datasets on agent(s)."""
    dataset: Dict[str, Any]
    priority: str = "high"


class EDMBulkTargetModel(BaseModel):
    """Targeting options for fleet EDM fanout commands."""
    online_only: bool = True
    platforms: Optional[List[str]] = None
    groups: Optional[List[str]] = None
    agent_ids: Optional[List[str]] = None
    limit: int = 500


class EDMBulkDatasetCommandModel(BaseModel):
    """Bulk dataset update payload for multi-agent EDM orchestration."""
    dataset: Dict[str, Any]
    priority: str = "high"
    targets: EDMBulkTargetModel = EDMBulkTargetModel()


class EDMDatasetVersionCreateModel(BaseModel):
    """Create a new EDM dataset version in source-of-truth registry."""
    dataset: Dict[str, Any]
    note: Optional[str] = None


class EDMDatasetPublishModel(BaseModel):
    """Publish a stored EDM dataset version to matching agents."""
    targets: EDMBulkTargetModel = EDMBulkTargetModel()
    priority: str = "high"


class EDMDatasetRollbackModel(BaseModel):
    """Rollback dataset by cloning a previous version into new head."""
    target_version: int
    note: Optional[str] = None
    publish: bool = True
    targets: EDMBulkTargetModel = EDMBulkTargetModel()
    priority: str = "high"


class EDMRolloutPolicyModel(BaseModel):
    """Progressive rollout controls and anomaly guardrails."""
    stages: List[int] = [5, 25, 100]
    anomaly_spike_multiplier: float = 3.0
    anomaly_min_hits: int = 20
    evaluation_window_minutes: int = 15
    auto_rollback: bool = True


class EDMRolloutStartModel(BaseModel):
    """Start canary rollout for a specific EDM dataset version."""
    dataset_id: str
    target_version: int
    targets: EDMBulkTargetModel = EDMBulkTargetModel()
    priority: str = "high"
    policy: EDMRolloutPolicyModel = EDMRolloutPolicyModel()


class EDMRolloutRollbackModel(BaseModel):
    """Manual rollback controls for an active rollout."""
    rollback_version: Optional[int] = None
    reason: Optional[str] = None


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
                "updated_at": datetime.now(timezone.utc).isoformat(),
                **( {"local_ui_url": agent.local_ui_url} if agent.local_ui_url else {} )
            }}
        )
        logger.info(f"Agent re-registered: {agent.agent_id} ({agent.platform})")
        await emit_world_event(get_db(), event_type="unified_agent_registered", entity_refs=[agent.agent_id], payload={"platform": agent.platform, "re_registered": True, "enrollment_type": auth.get("type")}, trigger_triune=False)
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
        "enrollment_type": auth['type'],
        "local_ui_url": agent.local_ui_url or "",
    }
    
    await db.unified_agents.insert_one(agent_doc)
    logger.info(f"New agent registered: {agent.agent_id} ({agent.platform}) from {agent.ip_address}")
    await emit_world_event(get_db(), event_type="unified_agent_registered", entity_refs=[agent.agent_id], payload={"platform": agent.platform, "re_registered": False, "enrollment_type": auth.get("type")}, trigger_triune=False)
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

    # Persist local UI URL when provided
    if heartbeat.local_ui_url:
        update_data["local_ui_url"] = heartbeat.local_ui_url
    if isinstance(heartbeat.endpoint_fortress, dict):
        update_data["endpoint_fortress"] = heartbeat.endpoint_fortress
    
    monitors_summary: Dict[str, Dict[str, Any]] = {}
    # Store monitor summary in agent document for quick access.
    if heartbeat.monitors:
        monitors_summary = _build_monitor_summary(heartbeat.monitors)
        update_data["monitors_summary"] = monitors_summary
    
    await db.unified_agents.update_one(
        {"agent_id": agent_id},
        {"$set": update_data}
    )
    await emit_world_event(get_db(), event_type="unified_agent_heartbeat", entity_refs=[agent_id], payload={"status": heartbeat.status, "threat_count": heartbeat.threat_count or 0}, trigger_triune=False)
    
    # Process any alerts
    for alert_data in heartbeat.alerts:
        await _process_agent_alert(agent_id, alert_data)

    # Ingest EDM hit telemetry loop-back from endpoint.
    if heartbeat.edm_hits:
        await _ensure_edm_indexes()
        for hit in heartbeat.edm_hits:
            await _process_agent_edm_hit(agent_id, hit.model_dump(), agent)
        await _evaluate_active_edm_rollouts(agent_id)
    
    # Store telemetry if provided
    if heartbeat.telemetry:
        await db.agent_telemetry.insert_one({
            "agent_id": agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "telemetry": heartbeat.telemetry
        })
        await emit_world_event(
            get_db(),
            event_type="unified_agent_telemetry_ingested",
            entity_refs=[agent_id],
            payload={
                "source": "heartbeat",
                "telemetry_keys": len(heartbeat.telemetry.keys()) if isinstance(heartbeat.telemetry, dict) else None,
            },
            trigger_triune=False,
        )
        _record_unified_audit(
            principal=f"agent:{agent_id}",
            action="unified_agent_telemetry_ingest",
            targets=[agent_id],
            result="success",
            constraints={"source": "heartbeat"},
        )
        
        # Run threat hunting on telemetry
        await _hunt_telemetry(heartbeat.telemetry)

    if isinstance(heartbeat.endpoint_fortress, dict):
        beacon = heartbeat.endpoint_fortress.get("beacon") if isinstance(heartbeat.endpoint_fortress.get("beacon"), dict) else {}
        beacon_state = str(beacon.get("state") or "").lower()
        await emit_world_event(
            get_db(),
            event_type="endpoint_beacon_state_reported",
            entity_refs=[agent_id],
            payload={
                "beacon_state": beacon.get("state"),
                "beacon_score": beacon.get("score"),
                "classification": beacon.get("classification"),
                "endpoint_fortress": heartbeat.endpoint_fortress,
            },
            trigger_triune=beacon_state in {"amber", "red"},
        )
    
    # Store structured monitor telemetry separately.
    if heartbeat.monitors:
        monitor_doc = {
            "agent_id": agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        for monitor_name in MONITOR_TELEMETRY_KEYS:
            monitor_payload = _coerce_monitor_payload(getattr(heartbeat.monitors, monitor_name, None))
            if monitor_payload:
                monitor_doc[monitor_name] = monitor_payload
        
        await db.agent_monitor_telemetry.insert_one(monitor_doc)
        await emit_world_event(
            get_db(),
            event_type="unified_agent_monitor_telemetry_ingested",
            entity_refs=[agent_id],
            payload={
                "source": "heartbeat",
                "monitor_count": len(monitors_summary),
                "monitor_threat_total": sum(
                    int((item or {}).get("threats_found") or 0) for item in monitors_summary.values()
                ),
                "hot_monitors": [
                    name for name, item in monitors_summary.items()
                    if int((item or {}).get("threats_found") or 0) > 0
                ][:12],
            },
            trigger_triune=sum(
                int((item or {}).get("threats_found") or 0) for item in monitors_summary.values()
            ) >= 3,
        )
        _record_unified_audit(
            principal=f"agent:{agent_id}",
            action="unified_agent_monitor_telemetry_ingest",
            targets=[agent_id],
            result="success",
            constraints={"source": "heartbeat", "monitor_count": len(monitors_summary)},
        )
    if heartbeat.telemetry or heartbeat.monitors:
        await _project_unified_state_snapshot(
            agent_id=agent_id,
            source="heartbeat",
            status=heartbeat.status,
            telemetry=heartbeat.telemetry if isinstance(heartbeat.telemetry, dict) else {},
            monitors_summary=monitors_summary,
        )
    
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


@router.get("/fleet/endpoint-posture-map")
async def get_fleet_endpoint_posture_map(
    limit: int = 1000,
    current_user: dict = Depends(get_current_user),
):
    """
    Fleet posture map for dashboard consumption.
    Returns per-agent beacon posture, trust state, and last boundary outcome.
    """
    safe_limit = max(1, min(int(limit or 1000), 5000))
    agents = await db.unified_agents.find({}, {"_id": 0}).limit(safe_limit).to_list(safe_limit)
    agent_ids = [str(a.get("agent_id") or "").strip() for a in agents if str(a.get("agent_id") or "").strip()]

    posture_by_agent: Dict[str, Dict[str, Any]] = {}
    if hasattr(db, "endpoint_posture"):
        try:
            cursor = db.endpoint_posture.find(
                {"agent_id": {"$in": agent_ids}} if agent_ids else {},
                {"_id": 0},
            )
            for row in await cursor.to_list(safe_limit):
                aid = str(row.get("agent_id") or "").strip()
                if aid:
                    posture_by_agent[aid] = row
        except Exception:
            logger.exception("Failed to load endpoint_posture collection")

    latest_boundary_by_agent: Dict[str, Dict[str, Any]] = {}
    if hasattr(db, "agent_commands"):
        try:
            pipeline = [
                {"$match": {"boundary_outcome": {"$exists": True, "$ne": None}}},
                {"$sort": {"completed_at": -1, "updated_at": -1, "created_at": -1}},
                {
                    "$group": {
                        "_id": "$agent_id",
                        "boundary_outcome": {"$first": "$boundary_outcome"},
                        "boundary_updated_at": {"$first": "$updated_at"},
                        "command_id": {"$first": "$command_id"},
                    }
                },
            ]
            rows = await db.agent_commands.aggregate(pipeline).to_list(safe_limit)
            for row in rows:
                aid = str(row.get("_id") or "").strip()
                if aid:
                    latest_boundary_by_agent[aid] = row
        except Exception:
            logger.exception("Failed to aggregate boundary outcomes from agent_commands")

    entries: List[Dict[str, Any]] = []
    for agent in agents:
        agent_id = str(agent.get("agent_id") or "").strip()
        if not agent_id:
            continue
        posture = posture_by_agent.get(agent_id, {})
        fortress = agent.get("endpoint_fortress") if isinstance(agent.get("endpoint_fortress"), dict) else {}
        fortress_beacon = fortress.get("beacon") if isinstance(fortress.get("beacon"), dict) else {}
        boundary = latest_boundary_by_agent.get(agent_id, {})

        beacon_state = (
            posture.get("beacon_state")
            or fortress_beacon.get("state")
            or "Green"
        )
        beacon_score = int(
            posture.get("beacon_score")
            or fortress_beacon.get("score")
            or 0
        )
        trust_state = "trusted"
        state_lower = str(beacon_state or "green").lower()
        if state_lower == "red":
            trust_state = "compromised"
        elif state_lower in {"amber", "yellow"}:
            trust_state = "degraded"

        last_boundary_outcome = (
            posture.get("last_boundary_outcome")
            or boundary.get("boundary_outcome")
            or "unknown"
        )
        entries.append(
            {
                "agent_id": agent_id,
                "hostname": agent.get("hostname"),
                "platform": agent.get("platform"),
                "ip_address": agent.get("ip_address"),
                "status": agent.get("status", "unknown"),
                "beacon_state": beacon_state,
                "beacon_score": beacon_score,
                "trust_state": trust_state,
                "last_boundary_outcome": last_boundary_outcome,
                "last_boundary_at": posture.get("updated_at") or boundary.get("boundary_updated_at"),
            }
        )

    severity_rank = {"red": 4, "amber": 3, "yellow": 2, "green": 1}
    entries.sort(
        key=lambda e: (
            severity_rank.get(str(e.get("beacon_state") or "").lower(), 0),
            int(e.get("beacon_score") or 0),
            str(e.get("last_boundary_at") or ""),
        ),
        reverse=True,
    )
    return {
        "entries": entries,
        "total": len(entries),
        "summary": {
            "green": sum(1 for e in entries if str(e.get("beacon_state") or "").lower() == "green"),
            "yellow": sum(1 for e in entries if str(e.get("beacon_state") or "").lower() == "yellow"),
            "amber": sum(1 for e in entries if str(e.get("beacon_state") or "").lower() == "amber"),
            "red": sum(1 for e in entries if str(e.get("beacon_state") or "").lower() == "red"),
            "degraded_or_worse": sum(
                1 for e in entries if str(e.get("trust_state") or "").lower() in {"degraded", "compromised"}
            ),
        },
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

    await emit_world_event(get_db(), event_type="unified_agent_command_requested", entity_refs=[agent_id], payload={"command_type": resolved_command_type, "actor": current_user.get("id")}, trigger_triune=False)
    return await _dispatch_agent_command(
        agent_id=agent_id,
        command_type=resolved_command_type,
        parameters=resolved_parameters,
        priority=command.priority,
        issued_by=current_user.get("email", "system"),
    )


_TOOLING_COMMAND_MAP: Dict[str, str] = {
    "trivy": "trivy_scan",
    "falco": "falco_status",
    "suricata": "suricata_status",
    "volatility": "volatility_status",
}
_REMEDIATION_ACTION_COMMAND_MAP: Dict[str, str] = {
    "kill_process": "kill_process",
    "block_ip": "block_ip",
    "block_connection": "block_ip",
    "quarantine_file": "quarantine_file",
}

_HIGH_IMPACT_AGENT_COMMAND_TYPES = {
    "kill_process",
    "block_ip",
    "quarantine_file",
    "update_config",
    "collect_forensics",
    "run_command",
    "shell_command",
    "powershell_command",
    "vpn_connect",
    "vpn_disconnect",
}


def _command_scope_for_type(command_type: str) -> Dict[str, str]:
    ctype = str(command_type or "").lower().strip()
    if ctype in {"block_ip", "block_connection", "vpn_connect", "vpn_disconnect"}:
        return {"zone_from": "governance", "zone_to": "network_egress_zone"}
    if ctype in {"quarantine_file"}:
        return {"zone_from": "governance", "zone_to": "browser_email_document_zone"}
    if ctype in {"run_command", "shell_command", "powershell_command", "kill_process", "collect_forensics", "update_config"}:
        return {"zone_from": "governance", "zone_to": "admin_tooling_zone"}
    return {"zone_from": "governance", "zone_to": "agent_control_zone"}


def _resolve_command_target(command_type: str, parameters: Dict[str, Any], agent_id: str) -> str:
    params = parameters or {}
    ctype = str(command_type or "").lower().strip()
    if ctype == "kill_process":
        return str(params.get("pid") or params.get("name") or f"agent:{agent_id}")
    if ctype in {"block_ip", "block_connection"}:
        return str(params.get("ip") or f"agent:{agent_id}")
    if ctype == "quarantine_file":
        return str(params.get("filepath") or f"agent:{agent_id}")
    if ctype in {"run_command", "shell_command", "powershell_command"}:
        return str(params.get("command") or f"agent:{agent_id}")[:240]
    return str(params.get("target") or f"agent:{agent_id}")


def _extract_token_for_contract(parameters: Dict[str, Any]) -> Dict[str, Any]:
    params = parameters or {}
    token = params.get("token")
    if isinstance(token, dict):
        token_payload = dict(token)
        if "token_id" not in token_payload and params.get("token_id"):
            token_payload["token_id"] = params.get("token_id")
        return token_payload
    if params.get("token_id"):
        return {"token_id": str(params.get("token_id"))}
    return {}


def _build_authority_context(
    *,
    command_type: str,
    parameters: Dict[str, Any],
    issued_by: str,
    agent_id: str,
) -> Dict[str, Any]:
    token_payload = _extract_token_for_contract(parameters)
    target = _resolve_command_target(command_type, parameters, agent_id)
    return {
        "principal": issued_by,
        "capability": command_type,
        "target": target,
        "scope": _command_scope_for_type(command_type),
        "token": token_payload,
        "token_id": str(token_payload.get("token_id") or ""),
        "requires_token": command_type in _HIGH_IMPACT_AGENT_COMMAND_TYPES,
        "requires_decision_context": command_type in _HIGH_IMPACT_AGENT_COMMAND_TYPES,
        "contract_version": "endpoint-boundary.v1",
    }


def _serialize_agent_command_for_delivery(command_doc: Dict[str, Any]) -> Dict[str, Any]:
    command_doc = dict(command_doc or {})
    command_type = str(command_doc.get("command_type") or command_doc.get("type") or "")
    parameters = command_doc.get("parameters") or {}
    authority_context = command_doc.get("authority_context")
    if not isinstance(authority_context, dict):
        authority_context = _build_authority_context(
            command_type=command_type,
            parameters=parameters if isinstance(parameters, dict) else {},
            issued_by=str(command_doc.get("issued_by") or command_doc.get("created_by") or "system"),
            agent_id=str(command_doc.get("agent_id") or ""),
        )
    decision_context = command_doc.get("decision_context")
    if not isinstance(decision_context, dict):
        decision_context = {
            "decision_id": command_doc.get("decision_id"),
            "queue_id": command_doc.get("queue_id") or command_doc.get("outbound_queue_id"),
            "approved": bool(command_doc.get("approved", False)),
            "released_to_execution": bool(
                command_doc.get("released_to_execution", False)
                or str(command_doc.get("status") or "").lower() in {"pending", "queued", "delivered", "sent"}
            ),
        }

    return {
        "command_id": command_doc.get("command_id"),
        "command_type": command_type,
        "parameters": parameters,
        "priority": command_doc.get("priority", "normal"),
        "timestamp": command_doc.get("timestamp") or command_doc.get("created_at") or datetime.now(timezone.utc).isoformat(),
        "decision_id": decision_context.get("decision_id"),
        "queue_id": decision_context.get("queue_id"),
        "decision_context": decision_context,
        "authority_context": authority_context,
        "principal": authority_context.get("principal"),
        "token_id": authority_context.get("token_id"),
        "token": authority_context.get("token"),
    }


@router.post("/agents/{agent_id}/commands/tooling/{tool_name}")
async def send_agent_tooling_command(
    agent_id: str,
    tool_name: str,
    command: ToolingCommandModel,
    current_user: dict = Depends(check_permission("write"))
):
    """Send a first-class tooling command to an agent (Trivy/Falco/Suricata/Volatility)."""

    agent = await db.unified_agents.find_one({"agent_id": agent_id})
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    key = (tool_name or "").strip().lower()
    command_type = _TOOLING_COMMAND_MAP.get(key)
    if not command_type:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported tooling command '{tool_name}'. Supported: {sorted(_TOOLING_COMMAND_MAP.keys())}",
        )

    await emit_world_event(get_db(), event_type="unified_agent_command_requested", entity_refs=[agent_id], payload={"command_type": resolved_command_type, "actor": current_user.get("id")}, trigger_triune=False)
    return await _dispatch_agent_command(
        agent_id=agent_id,
        command_type=command_type,
        parameters=command.parameters or {},
        priority=command.priority,
        issued_by=current_user.get("email", "system"),
    )


async def _dispatch_agent_command(
    agent_id: str,
    command_type: str,
    parameters: Dict[str, Any],
    priority: str,
    issued_by: str,
) -> Dict[str, Any]:
    """Queue command through outbound gate before any execution path."""
    command_id = secrets.token_hex(8)
    authority_context = _build_authority_context(
        command_type=command_type,
        parameters=parameters or {},
        issued_by=issued_by,
        agent_id=agent_id,
    )
    command_data = {
        "command_id": command_id,
        "type": "command",
        "command_type": command_type,
        "parameters": parameters,
        "priority": priority,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "issued_by": issued_by,
        "authority_context": authority_context,
        "decision_context": {
            "decision_id": None,
            "queue_id": None,
            "approved": False,
            "released_to_execution": False,
        },
    }

    action_type = "cross_sector_hardening" if command_type in {"remediate_compliance", "remove_persistence"} else "agent_command"
    dispatch = GovernedDispatchService(db)
    queued_result = await dispatch.queue_gated_agent_command(
        action_type=action_type,
        actor=issued_by,
        agent_id=agent_id,
        command_doc={
            **command_data,
            "state_version": 1,
            "state_transition_log": [
                {
                    "from_status": None,
                    "to_status": "gated_pending_approval",
                    "actor": issued_by,
                    "reason": "queued for triune approval",
                    "timestamp": command_data["timestamp"],
                    "metadata": {"delivery_mode": "triune_queue"},
                }
            ],
        },
        impact_level="high",
        entity_refs=[agent_id, command_id],
        requires_triune=True,
    )
    queued = queued_result.get("queued", {})

    logger.info("Command %s queued for triune approval for %s", command_type, agent_id)
    return {
        "command_id": command_id,
        "status": "queued_for_approval",
        "queue_id": queued.get("queue_id"),
        "decision_id": queued.get("decision_id"),
        "authority_context": authority_context,
        "message": "Command queued for triune approval; execution awaits outbound gate decision",
    }


@router.post("/agents/{agent_id}/remediation/propose")
async def propose_agent_remediation(
    agent_id: str,
    proposal: RemediationProposalModel,
    request: Request,
    auth: Dict = Depends(verify_agent_auth),
):
    """
    Allow endpoint agents to submit high-impact remediation proposals into
    governed dispatch instead of executing local actions immediately.
    """
    if auth.get("agent_id") and auth["agent_id"] != agent_id:
        raise HTTPException(status_code=403, detail="Agent ID mismatch")

    action = (proposal.action or "").strip().lower()
    command_type = _REMEDIATION_ACTION_COMMAND_MAP.get(action)
    if not command_type:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported remediation action '{proposal.action}'. Supported: {sorted(_REMEDIATION_ACTION_COMMAND_MAP.keys())}",
        )

    agent = await db.unified_agents.find_one({"agent_id": agent_id}, {"_id": 0, "agent_id": 1})
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    parameters = dict(proposal.parameters or {})
    threat = proposal.threat or {}
    evidence = threat.get("evidence") or {}
    if command_type == "kill_process":
        if not parameters.get("pid") and evidence.get("pid"):
            parameters["pid"] = evidence.get("pid")
        if not parameters.get("name") and (evidence.get("name") or threat.get("process_name")):
            parameters["name"] = evidence.get("name") or threat.get("process_name")
    elif command_type == "block_ip":
        if not parameters.get("ip"):
            remote = evidence.get("remote") or evidence.get("remote_ip")
            if isinstance(remote, str) and remote:
                parameters["ip"] = remote.split(":")[0]
    elif command_type == "quarantine_file":
        if not parameters.get("filepath"):
            parameters["filepath"] = evidence.get("path") or evidence.get("filepath")

    if proposal.reason:
        parameters.setdefault("reason", proposal.reason)
    if threat:
        parameters.setdefault(
            "threat_context",
            {
                "threat_id": threat.get("threat_id"),
                "severity": threat.get("severity"),
                "title": threat.get("title"),
                "source": threat.get("source"),
            },
        )

    dispatch_result = await _dispatch_agent_command(
        agent_id=agent_id,
        command_type=command_type,
        parameters=parameters,
        priority=proposal.priority,
        issued_by=f"agent:{agent_id}",
    )

    await emit_world_event(
        get_db(),
        event_type="unified_agent_remediation_proposed",
        entity_refs=[agent_id, dispatch_result.get("command_id"), dispatch_result.get("queue_id"), dispatch_result.get("decision_id")],
        payload={
            "action": action,
            "command_type": command_type,
            "proposal_reason": proposal.reason,
            "auth_type": auth.get("type"),
        },
        trigger_triune=True,
    )

    return {
        **dispatch_result,
        "status": "queued_for_triune_approval",
        "remediation_action": action,
        "command_type": command_type,
    }


async def _resolve_edm_targets(targets: EDMBulkTargetModel) -> List[Dict[str, Any]]:
    """Resolve target agents for bulk EDM operations."""
    query: Dict[str, Any] = {}
    limit = max(1, min(int(targets.limit or 500), 5000))

    if targets.online_only:
        query["status"] = "online"

    if targets.platforms:
        normalized = [p.lower().strip() for p in targets.platforms if p and p.strip()]
        if normalized:
            query["platform"] = {"$in": normalized}

    if targets.groups:
        normalized_groups = [g.strip() for g in targets.groups if g and g.strip()]
        if normalized_groups:
            query["$or"] = [
                {"group": {"$in": normalized_groups}},
                {"config.group": {"$in": normalized_groups}},
                {"config.groups": {"$in": normalized_groups}},
                {"tags": {"$in": normalized_groups}},
                {"config.tags": {"$in": normalized_groups}},
            ]

    if targets.agent_ids:
        ids = [a.strip() for a in targets.agent_ids if a and a.strip()]
        if ids:
            query["agent_id"] = {"$in": ids}

    agents = await db.unified_agents.find(query, {"_id": 0, "agent_id": 1, "platform": 1, "status": 1}).limit(limit).to_list(length=limit)
    return agents


def _cohort_percent(rollout_id: str, agent_id: str) -> int:
    """Deterministic 0-99 cohort placement per rollout and agent."""
    digest = hashlib.sha256(f"{rollout_id}:{agent_id}".encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 100


def _select_rollout_agents(rollout_id: str, eligible_ids: List[str], cumulative_percent: int) -> List[str]:
    pct = max(0, min(int(cumulative_percent), 100))
    return [aid for aid in eligible_ids if _cohort_percent(rollout_id, aid) < pct]


async def _count_edm_hits(dataset_id: str, agent_ids: List[str], since_iso: str) -> int:
    if not agent_ids:
        return 0
    return await db[EDM_HITS_COLLECTION].count_documents({
        "dataset_id": dataset_id,
        "agent_id": {"$in": agent_ids},
        "ingested_at": {"$gte": since_iso},
    })


async def _ensure_edm_indexes() -> None:
    """Create EDM telemetry/rollout indexes lazily for production safety/perf."""
    global _edm_indexes_ready
    if _edm_indexes_ready:
        return
    try:
        await db[EDM_HITS_COLLECTION].create_index([("dataset_id", 1), ("ingested_at", -1)])
        await db[EDM_HITS_COLLECTION].create_index([("agent_id", 1), ("ingested_at", -1)])
        await db[EDM_HITS_COLLECTION].create_index([("fingerprint", 1), ("ingested_at", -1)])
        await db[EDM_HITS_COLLECTION].create_index([("ingested_at", -1)])

        await db[EDM_ROLLOUT_COLLECTION].create_index([("rollout_id", 1)], unique=True)
        await db[EDM_ROLLOUT_COLLECTION].create_index([("status", 1), ("updated_at", -1)])
        await db[EDM_ROLLOUT_COLLECTION].create_index([("dataset_id", 1), ("status", 1)])
        _edm_indexes_ready = True
    except Exception as e:
        logger.warning(f"Failed to initialize EDM indexes: {e}")


async def _compute_rollout_readiness(rollout: Dict[str, Any]) -> Dict[str, Any]:
    """Compute cohort/control anomaly metrics used for readiness/auto-rollback."""
    now = datetime.now(timezone.utc)
    dataset_id = rollout.get("dataset_id")
    policy = rollout.get("policy", {})
    eval_minutes = max(5, int(policy.get("evaluation_window_minutes", 15)))
    min_hits = max(1, int(policy.get("anomaly_min_hits", 20)))
    spike_multiplier = max(1.0, float(policy.get("anomaly_spike_multiplier", 3.0)))

    since_iso = (now - timedelta(minutes=eval_minutes)).isoformat()
    eligible_ids = rollout.get("eligible_agent_ids") or []
    cohort_ids = rollout.get("applied_agent_ids") or []
    cohort_set = set(cohort_ids)
    control_ids = [aid for aid in eligible_ids if aid not in cohort_set]

    cohort_hits = await _count_edm_hits(dataset_id, cohort_ids, since_iso)
    control_hits = await _count_edm_hits(dataset_id, control_ids, since_iso) if control_ids else 0
    cohort_rate = cohort_hits / max(len(cohort_ids), 1) / float(eval_minutes)
    control_rate = control_hits / max(len(control_ids), 1) / float(eval_minutes) if control_ids else 0.0
    threshold_rate = max(control_rate * spike_multiplier, 0.05)
    has_spike = cohort_hits >= min_hits and cohort_rate > threshold_rate

    return {
        "dataset_id": dataset_id,
        "window_minutes": eval_minutes,
        "since": since_iso,
        "cohort": {
            "agents": len(cohort_ids),
            "hits": cohort_hits,
            "rate_per_agent_min": cohort_rate,
        },
        "control": {
            "agents": len(control_ids),
            "hits": control_hits,
            "rate_per_agent_min": control_rate,
        },
        "threshold": {
            "multiplier": spike_multiplier,
            "min_hits": min_hits,
            "rate_per_agent_min": threshold_rate,
        },
        "has_spike": has_spike,
        "can_advance": not has_spike,
    }


def _rollout_conflict_error() -> HTTPException:
    return HTTPException(
        status_code=409,
        detail="Rollout state changed concurrently; refresh rollout state and retry",
    )


def _deployment_conflict_error() -> HTTPException:
    return HTTPException(
        status_code=409,
        detail="Deployment state changed concurrently; refresh deployment state and retry",
    )


async def _transition_unified_deployment_state(
    deployment_id: str,
    expected_statuses: List[str],
    next_status: str,
    extra_updates: Optional[Dict[str, Any]] = None,
    deployment_task_id: Optional[str] = None,
    transition_actor: str = "system",
    transition_reason: Optional[str] = None,
    transition_metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    query: Dict[str, Any] = {
        "deployment_id": deployment_id,
        "status": {"$in": expected_statuses},
    }
    if deployment_task_id is not None:
        query["deployment_task_id"] = deployment_task_id

    update_doc = {
        "status": next_status,
        "updated_at": now,
    }
    if extra_updates:
        update_doc.update(extra_updates)

    result = await db.unified_deployments.update_one(
        query,
        {
            "$set": update_doc,
            "$inc": {"state_version": 1},
            "$push": {
                "state_transition_log": {
                    "from_status": expected_statuses[0] if len(expected_statuses) == 1 else list(expected_statuses),
                    "to_status": next_status,
                    "actor": transition_actor,
                    "reason": transition_reason,
                    "metadata": transition_metadata or {},
                    "timestamp": now,
                }
            },
        },
    )
    return getattr(result, "matched_count", 0) > 0


def _extract_boundary_crossing_from_command_result(
    *,
    agent_id: str,
    command_id: str,
    result: Dict[str, Any],
) -> Dict[str, Any]:
    fortress = result.get("fortress")
    if not isinstance(fortress, dict):
        return {}

    pre = fortress.get("pre") if isinstance(fortress.get("pre"), dict) else {}
    post = fortress.get("post") if isinstance(fortress.get("post"), dict) else {}
    gate = fortress.get("gate") if isinstance(fortress.get("gate"), dict) else {}
    boundary = fortress.get("boundary") if isinstance(fortress.get("boundary"), dict) else {}
    decision_context = boundary.get("decision_context") if isinstance(boundary.get("decision_context"), dict) else {}

    gate_outcome = str(post.get("gate_outcome") or gate.get("decision") or "").lower().strip()
    world_outcome = str(post.get("world_event_outcome") or "").lower().strip()
    if not world_outcome:
        if gate_outcome in {"deny", "denied"}:
            world_outcome = "denied"
        elif gate_outcome in {"queue", "queued", "throttle", "throttled"}:
            world_outcome = "queued"
        elif gate_outcome in {"quarantine", "quarantined"}:
            world_outcome = "anomalous"
        elif gate_outcome == "token-invalid":
            world_outcome = "token-invalid"
        else:
            world_outcome = "allowed"

    beacon = post.get("beacon") if isinstance(post.get("beacon"), dict) else {}
    beacon_state = str(beacon.get("state") or "").lower()
    trigger_triune = world_outcome in {"denied", "queued", "token-invalid", "anomalous", "decoy-hit"} or beacon_state in {"amber", "red"}

    refs = [agent_id, command_id, str(decision_context.get("queue_id") or ""), str(decision_context.get("decision_id") or "")]
    refs = [r for r in refs if r]
    return {
        "event_type": "boundary_crossing",
        "entity_refs": refs,
        "payload": {
            "source": "endpoint_fortress_command_result",
            "agent_id": agent_id,
            "command_id": command_id,
            "crossing_outcome": world_outcome,
            "decision_context": decision_context,
            "boundary": boundary,
            "pre_observation": pre,
            "gate_decision": gate,
            "post_observation": post,
        },
        "trigger_triune": trigger_triune,
        "world_outcome": world_outcome,
    }


async def _finalize_agent_command_result(
    command_id: str,
    status: str,
    result_payload: Dict[str, Any],
    transition_actor: str = "agent",
    transition_reason: str = "command result received",
    fortress_payload: Optional[Dict[str, Any]] = None,
    boundary_outcome: Optional[str] = None,
) -> Dict[str, Any]:
    normalized_status = str(status or "completed").lower().strip()
    if normalized_status not in {"completed", "failed"}:
        normalized_status = "completed"

    now = datetime.now(timezone.utc).isoformat()
    set_doc: Dict[str, Any] = {
        "status": normalized_status,
        "result": result_payload,
        "completed_at": now,
        "updated_at": now,
    }
    if isinstance(fortress_payload, dict) and fortress_payload:
        set_doc["endpoint_fortress"] = fortress_payload
    if boundary_outcome:
        set_doc["boundary_outcome"] = str(boundary_outcome)

    update_result = await db.agent_commands.update_one(
        {
            "command_id": command_id,
            "status": {"$in": ["queued", "sent", "delivered", "in_progress", "running"]},
        },
        {
            "$set": set_doc,
            "$inc": {"state_version": 1},
            "$push": {
                "state_transition_log": {
                    "from_status": ["queued", "sent", "delivered", "in_progress", "running"],
                    "to_status": normalized_status,
                    "actor": transition_actor,
                    "reason": transition_reason,
                    "timestamp": now,
                }
            },
        },
    )

    if getattr(update_result, "matched_count", 0) > 0:
        return {"updated": True, "status": normalized_status}

    existing = await db.agent_commands.find_one(
        {"command_id": command_id},
        {"_id": 0, "status": 1},
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Command not found")

    raise HTTPException(
        status_code=409,
        detail=f"Command is already terminal (status={existing.get('status')})",
    )


async def _claim_rollout_for_rollback(
    rollout_id: str,
    reason: str,
    requested_by: str,
    allowed_statuses: List[str],
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    claim = await db[EDM_ROLLOUT_COLLECTION].update_one(
        {
            "rollout_id": rollout_id,
            "status": {"$in": allowed_statuses},
        },
        {
            "$set": {
                "status": "rolling_back",
                "rollback_reason": reason,
                "rollback_requested_by": requested_by,
                "rollback_requested_at": now,
                "updated_at": now,
            },
            "$inc": {"state_version": 1},
            "$push": {
                "state_transition_log": {
                    "from_status": list(allowed_statuses),
                    "to_status": "rolling_back",
                    "actor": requested_by,
                    "reason": reason,
                    "timestamp": now,
                }
            },
        },
    )
    if getattr(claim, "matched_count", 0) == 0:
        raise _rollout_conflict_error()

    refreshed = await db[EDM_ROLLOUT_COLLECTION].find_one({"rollout_id": rollout_id}, {"_id": 0})
    if not refreshed:
        raise HTTPException(status_code=404, detail="Rollout not found")
    return refreshed


def _canonical_json(value: Any) -> str:
    """Stable canonical JSON serialization for checksums/signatures."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _compute_edm_checksum(dataset: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(dataset).encode("utf-8")).hexdigest()


def _normalize_edm_text(value: Any) -> str:
    text = str(value or "").strip().lower()
    return " ".join(text.split())


def _canonicalize_edm_record(record: Any) -> str:
    """Canonicalization aligned with agent EDM behavior for quality estimation."""
    if isinstance(record, dict):
        parts: List[str] = []
        for key in sorted(record.keys()):
            val = _normalize_edm_text(record.get(key))
            if val:
                parts.append(f"{_normalize_edm_text(key)}={val}")
        return "|".join(parts)

    if isinstance(record, list):
        vals = [_normalize_edm_text(v) for v in record]
        vals = [v for v in vals if v]
        return "|".join(vals)

    return _normalize_edm_text(record)


def _validate_and_score_edm_dataset(dataset_payload: Any) -> Dict[str, Any]:
    """Validate EDM schema and score publish readiness quality gates."""
    report: Dict[str, Any] = {
        "valid": False,
        "quality_gate_passed": False,
        "schema_errors": [],
        "quality_errors": [],
        "quality_warnings": [],
        "metrics": {
            "datasets": 0,
            "total_records": 0,
            "canonicalizable_records": 0,
            "canonical_coverage": 0.0,
            "datasets_missing_id": 0,
            "datasets_with_empty_records": 0,
            "duplicate_dataset_ids": 0,
            "duplicate_record_ids": 0,
            "unknown_candidate_types": 0,
        },
    }

    schema_errors: List[str] = report["schema_errors"]
    quality_errors: List[str] = report["quality_errors"]
    quality_warnings: List[str] = report["quality_warnings"]
    metrics: Dict[str, Any] = report["metrics"]

    if not isinstance(dataset_payload, dict):
        schema_errors.append("dataset payload must be an object")
        return report

    datasets = dataset_payload.get("datasets")
    if not isinstance(datasets, list):
        schema_errors.append("dataset payload must contain 'datasets' as a list")
        return report

    metrics["datasets"] = len(datasets)
    if len(datasets) == 0:
        schema_errors.append("'datasets' must not be empty")
        return report

    seen_dataset_ids: set = set()
    seen_record_ids: set = set()
    unknown_candidate_types: set = set()

    for ds_index, ds in enumerate(datasets):
        if not isinstance(ds, dict):
            schema_errors.append(f"datasets[{ds_index}] must be an object")
            continue

        ds_id = str(ds.get("dataset_id") or ds.get("name") or "").strip()
        if not ds_id:
            metrics["datasets_missing_id"] += 1
            schema_errors.append(f"datasets[{ds_index}] missing dataset_id/name")
        else:
            if ds_id in seen_dataset_ids:
                metrics["duplicate_dataset_ids"] += 1
            seen_dataset_ids.add(ds_id)

        records = ds.get("records")
        if not isinstance(records, list):
            schema_errors.append(f"datasets[{ds_index}].records must be a list")
            continue
        if len(records) == 0:
            metrics["datasets_with_empty_records"] += 1
            quality_warnings.append(f"datasets[{ds_index}] has no records")

        precision = ds.get("precision")
        if precision is not None and not isinstance(precision, dict):
            schema_errors.append(f"datasets[{ds_index}].precision must be an object if provided")
            precision = None

        if isinstance(precision, dict):
            if "min_confidence" in precision:
                try:
                    min_conf = float(precision.get("min_confidence"))
                except Exception:
                    schema_errors.append(f"datasets[{ds_index}].precision.min_confidence must be numeric")
                    min_conf = None
                if min_conf is not None:
                    if min_conf < 0.0 or min_conf > 1.0:
                        schema_errors.append(f"datasets[{ds_index}].precision.min_confidence must be between 0 and 1")
                    elif min_conf < EDM_MIN_ALLOWED_MIN_CONFIDENCE:
                        quality_errors.append(
                            f"datasets[{ds_index}].precision.min_confidence ({min_conf}) below enforced floor ({EDM_MIN_ALLOWED_MIN_CONFIDENCE})"
                        )

            if "allowed_candidate_types" in precision:
                allowed = precision.get("allowed_candidate_types")
                if not isinstance(allowed, list):
                    schema_errors.append(f"datasets[{ds_index}].precision.allowed_candidate_types must be a list")
                else:
                    unknown = {str(v).strip() for v in allowed if str(v).strip() and str(v).strip() not in EDM_ALLOWED_CANDIDATE_TYPES}
                    if unknown:
                        unknown_candidate_types.update(unknown)

        for record_index, record in enumerate(records):
            metrics["total_records"] += 1
            canonical = _canonicalize_edm_record(record)
            if canonical:
                metrics["canonicalizable_records"] += 1

            if isinstance(record, dict):
                record_id = str(record.get("record_id") or "").strip()
                if record_id and ds_id:
                    key = f"{ds_id}:{record_id}"
                    if key in seen_record_ids:
                        metrics["duplicate_record_ids"] += 1
                    seen_record_ids.add(key)
            elif record is None:
                quality_warnings.append(f"datasets[{ds_index}].records[{record_index}] is null and contributes no fingerprint")

    total_records = int(metrics.get("total_records", 0))
    canonicalizable = int(metrics.get("canonicalizable_records", 0))
    coverage = (canonicalizable / total_records) if total_records else 0.0
    metrics["canonical_coverage"] = round(coverage, 6)
    metrics["unknown_candidate_types"] = len(unknown_candidate_types)

    if total_records == 0:
        quality_errors.append("dataset contains zero records")

    if total_records > EDM_MAX_RECORDS_PER_PUBLISH:
        quality_errors.append(
            f"record count {total_records} exceeds publish gate limit {EDM_MAX_RECORDS_PER_PUBLISH}"
        )

    if coverage < EDM_MIN_CANONICAL_COVERAGE:
        quality_errors.append(
            f"canonical coverage {coverage:.3f} below threshold {EDM_MIN_CANONICAL_COVERAGE:.3f}"
        )

    if metrics["duplicate_dataset_ids"] > 0:
        quality_errors.append("duplicate dataset_id values detected")

    if metrics["duplicate_record_ids"] > 0:
        quality_errors.append("duplicate record_id values detected within dataset scope")

    if unknown_candidate_types:
        quality_errors.append(
            f"unknown precision.allowed_candidate_types: {sorted(unknown_candidate_types)}"
        )

    report["valid"] = len(schema_errors) == 0
    report["quality_gate_passed"] = report["valid"] and len(quality_errors) == 0
    return report


def _enforce_edm_publish_gates(dataset_payload: Any, *, context: str) -> Dict[str, Any]:
    """Enforce schema and quality gates prior to version promotion/distribution."""
    report = _validate_and_score_edm_dataset(dataset_payload)
    if not report.get("valid") or not report.get("quality_gate_passed"):
        raise HTTPException(
            status_code=422,
            detail={
                "message": f"EDM dataset failed {context} validation gates",
                "context": context,
                "validation": report,
            },
        )
    return report


def _sign_edm_metadata(dataset_id: str, version: int, checksum: str) -> str:
    message = f"{dataset_id}:{version}:{checksum}"
    return hmac.new(AGENT_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def _build_edm_meta(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "dataset_id": doc.get("dataset_id"),
        "version": int(doc.get("version", 0)),
        "checksum": doc.get("checksum"),
        "signature": doc.get("signature"),
        "signed_at": doc.get("published_at"),
    }


async def _dispatch_edm_dataset_to_targets(
    dataset: Dict[str, Any],
    edm_meta: Dict[str, Any],
    targets: EDMBulkTargetModel,
    priority: str,
    issued_by: str,
) -> Dict[str, Any]:
    agents = await _resolve_edm_targets(targets)
    if not agents:
        return {
            "matched_agents": 0,
            "dispatched": 0,
            "sent": 0,
            "queued": 0,
            "results": [],
        }

    sent = 0
    queued = 0
    results: List[Dict[str, Any]] = []
    for agent in agents:
        dispatch = await _dispatch_agent_command(
            agent_id=agent["agent_id"],
            command_type="update_edm_dataset",
            parameters={"dataset": dataset, "edm_meta": edm_meta},
            priority=priority,
            issued_by=issued_by,
        )
        if dispatch.get("status") == "sent":
            sent += 1
        else:
            queued += 1
        results.append({
            "agent_id": agent["agent_id"],
            "platform": agent.get("platform"),
            "agent_status": agent.get("status"),
            "command_id": dispatch.get("command_id"),
            "delivery": dispatch.get("status"),
        })

    return {
        "matched_agents": len(agents),
        "dispatched": len(results),
        "sent": sent,
        "queued": queued,
        "results": results,
    }


@router.post("/agents/{agent_id}/edm/reload")
async def reload_agent_edm_dataset(
    agent_id: str,
    current_user: dict = Depends(check_permission("write")),
):
    """Trigger EDM dataset reload on an agent without restarting the process."""
    agent = await db.unified_agents.find_one({"agent_id": agent_id})
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    cmd = await _dispatch_agent_command(
        agent_id=agent_id,
        command_type="reload_edm_dataset",
        parameters={},
        priority="high",
        issued_by=current_user.get("email", "system"),
    )
    return {
        "agent_id": agent_id,
        "action": "reload_edm_dataset",
        **cmd,
    }


@router.post("/agents/{agent_id}/edm/dataset")
async def update_agent_edm_dataset(
    agent_id: str,
    payload: EDMDatasetCommandModel,
    current_user: dict = Depends(check_permission("write")),
):
    """Push a full EDM dataset payload to an agent and hot-reload it."""
    agent = await db.unified_agents.find_one({"agent_id": agent_id})
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    _enforce_edm_publish_gates(payload.dataset, context="single-agent edm update")

    adhoc_dataset_id = f"adhoc-{agent_id}"
    adhoc_version = int(datetime.now(timezone.utc).timestamp())
    checksum = _compute_edm_checksum(payload.dataset)
    signature = _sign_edm_metadata(adhoc_dataset_id, adhoc_version, checksum)
    edm_meta = {
        "dataset_id": adhoc_dataset_id,
        "version": adhoc_version,
        "checksum": checksum,
        "signature": signature,
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }

    cmd = await _dispatch_agent_command(
        agent_id=agent_id,
        command_type="update_edm_dataset",
        parameters={"dataset": payload.dataset, "edm_meta": edm_meta},
        priority=payload.priority,
        issued_by=current_user.get("email", "system"),
    )
    return {
        "agent_id": agent_id,
        "action": "update_edm_dataset",
        "datasets_count": len(payload.dataset.get("datasets", [])),
        "edm_meta": edm_meta,
        **cmd,
    }


@router.post("/agents/edm/reload-all")
async def reload_edm_dataset_fleet(
    targets: EDMBulkTargetModel,
    current_user: dict = Depends(check_permission("write")),
):
    """Fanout EDM reload command to all matching agents."""
    agents = await _resolve_edm_targets(targets)
    if not agents:
        return {
            "action": "reload_edm_dataset",
            "matched_agents": 0,
            "dispatched": 0,
            "sent": 0,
            "queued": 0,
            "results": [],
        }

    results: List[Dict[str, Any]] = []
    sent = 0
    queued = 0
    for agent in agents:
        dispatch = await _dispatch_agent_command(
            agent_id=agent["agent_id"],
            command_type="reload_edm_dataset",
            parameters={},
            priority="high",
            issued_by=current_user.get("email", "system"),
        )
        if dispatch.get("status") == "sent":
            sent += 1
        else:
            queued += 1
        results.append({
            "agent_id": agent["agent_id"],
            "platform": agent.get("platform"),
            "agent_status": agent.get("status"),
            "command_id": dispatch.get("command_id"),
            "delivery": dispatch.get("status"),
        })

    return {
        "action": "reload_edm_dataset",
        "matched_agents": len(agents),
        "dispatched": len(results),
        "sent": sent,
        "queued": queued,
        "results": results,
    }


@router.post("/agents/edm/dataset-all")
async def update_edm_dataset_fleet(
    payload: EDMBulkDatasetCommandModel,
    current_user: dict = Depends(check_permission("write")),
):
    """Fanout EDM dataset update command to all matching agents."""
    _enforce_edm_publish_gates(payload.dataset, context="fleet edm update")

    agents = await _resolve_edm_targets(payload.targets)
    if not agents:
        return {
            "action": "update_edm_dataset",
            "matched_agents": 0,
            "dispatched": 0,
            "sent": 0,
            "queued": 0,
            "datasets_count": len(payload.dataset.get("datasets", [])),
            "results": [],
        }

    # Ad hoc fanout still signs payloads so agents can verify trust/integrity.
    adhoc_dataset_id = "adhoc-global"
    adhoc_version = int(datetime.now(timezone.utc).timestamp())
    checksum = _compute_edm_checksum(payload.dataset)
    signature = _sign_edm_metadata(adhoc_dataset_id, adhoc_version, checksum)
    edm_meta = {
        "dataset_id": adhoc_dataset_id,
        "version": adhoc_version,
        "checksum": checksum,
        "signature": signature,
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }

    fanout = await _dispatch_edm_dataset_to_targets(
        dataset=payload.dataset,
        edm_meta=edm_meta,
        targets=payload.targets,
        priority=payload.priority,
        issued_by=current_user.get("email", "system"),
    )

    return {
        "action": "update_edm_dataset",
        "matched_agents": fanout.get("matched_agents", 0),
        "dispatched": fanout.get("dispatched", 0),
        "sent": fanout.get("sent", 0),
        "queued": fanout.get("queued", 0),
        "datasets_count": len(payload.dataset.get("datasets", [])),
        "edm_meta": edm_meta,
        "results": fanout.get("results", []),
    }


# ============================================================
# EDM SOURCE-OF-TRUTH DATASET REGISTRY
# ============================================================

@router.get("/edm/datasets")
async def list_edm_datasets(current_user: dict = Depends(check_permission("read"))):
    """List latest EDM dataset head per dataset_id."""
    _ = current_user
    docs = await db[EDM_DATASET_COLLECTION].find({}, {"_id": 0}).sort([("dataset_id", 1), ("version", -1)]).to_list(5000)
    latest: Dict[str, Dict[str, Any]] = {}
    for doc in docs:
        dsid = doc.get("dataset_id")
        if dsid and dsid not in latest:
            latest[dsid] = doc

    datasets = []
    for dsid, doc in latest.items():
        datasets.append({
            "dataset_id": dsid,
            "version": doc.get("version"),
            "checksum": doc.get("checksum"),
            "published_by": doc.get("published_by"),
            "published_at": doc.get("published_at"),
            "rollback_target": doc.get("rollback_target"),
            "note": doc.get("note"),
        })
    return {"datasets": datasets, "count": len(datasets)}


@router.get("/edm/datasets/{dataset_id}/versions")
async def list_edm_dataset_versions(dataset_id: str, current_user: dict = Depends(check_permission("read"))):
    """List all versions for a dataset_id."""
    _ = current_user
    versions = await db[EDM_DATASET_COLLECTION].find({"dataset_id": dataset_id}, {"_id": 0}).sort("version", -1).to_list(1000)
    return {"dataset_id": dataset_id, "versions": versions, "count": len(versions)}


@router.get("/edm/datasets/{dataset_id}/versions/{version}")
async def get_edm_dataset_version(dataset_id: str, version: int, current_user: dict = Depends(check_permission("read"))):
    """Get a specific dataset version payload + metadata."""
    _ = current_user
    doc = await db[EDM_DATASET_COLLECTION].find_one({"dataset_id": dataset_id, "version": version}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Dataset version not found")
    return doc


@router.post("/edm/datasets/{dataset_id}/versions")
async def create_edm_dataset_version(
    dataset_id: str,
    payload: EDMDatasetVersionCreateModel,
    current_user: dict = Depends(check_permission("write")),
):
    """Create a new version in EDM source-of-truth registry."""
    quality_report = _enforce_edm_publish_gates(payload.dataset, context="dataset version creation")

    latest = await db[EDM_DATASET_COLLECTION].find_one({"dataset_id": dataset_id}, {"_id": 0, "version": 1}, sort=[("version", -1)])
    next_version = int(latest.get("version", 0)) + 1 if latest else 1
    checksum = _compute_edm_checksum(payload.dataset)
    signature = _sign_edm_metadata(dataset_id, next_version, checksum)
    now = datetime.now(timezone.utc).isoformat()

    doc = {
        "dataset_id": dataset_id,
        "version": next_version,
        "dataset": payload.dataset,
        "quality_report": quality_report,
        "checksum": checksum,
        "signature": signature,
        "published_by": current_user.get("email", "system"),
        "published_at": now,
        "rollback_target": None,
        "note": payload.note,
        "created_at": now,
    }
    await db[EDM_DATASET_COLLECTION].insert_one(doc)
    return {"status": "created", "contract_version": EDM_CONTROL_PLANE_CONTRACT_VERSION, **doc}


@router.post("/edm/datasets/{dataset_id}/versions/{version}/publish")
async def publish_edm_dataset_version(
    dataset_id: str,
    version: int,
    payload: EDMDatasetPublishModel,
    current_user: dict = Depends(check_permission("write")),
):
    """Publish a stored dataset version to matching agents."""
    doc = await db[EDM_DATASET_COLLECTION].find_one({"dataset_id": dataset_id, "version": version}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Dataset version not found")

    quality_report = _enforce_edm_publish_gates(doc.get("dataset", {}), context="dataset publish")

    fanout = await _dispatch_edm_dataset_to_targets(
        dataset=doc.get("dataset", {}),
        edm_meta=_build_edm_meta(doc),
        targets=payload.targets,
        priority=payload.priority,
        issued_by=current_user.get("email", "system"),
    )

    await db[EDM_DATASET_COLLECTION].update_one(
        {"dataset_id": dataset_id, "version": version},
        {"$set": {"last_published_at": datetime.now(timezone.utc).isoformat(), "last_published_by": current_user.get("email", "system")}},
    )

    return {
        "action": "publish_edm_dataset_version",
        "contract_version": EDM_CONTROL_PLANE_CONTRACT_VERSION,
        "dataset_id": dataset_id,
        "version": version,
        "quality_report": quality_report,
        "edm_meta": _build_edm_meta(doc),
        **fanout,
    }


@router.post("/edm/datasets/{dataset_id}/rollback")
async def rollback_edm_dataset(
    dataset_id: str,
    payload: EDMDatasetRollbackModel,
    current_user: dict = Depends(check_permission("write")),
):
    """Rollback by cloning target version into new latest version, optionally publish immediately."""
    target = await db[EDM_DATASET_COLLECTION].find_one({"dataset_id": dataset_id, "version": payload.target_version}, {"_id": 0})
    if not target:
        raise HTTPException(status_code=404, detail="Rollback target version not found")

    latest = await db[EDM_DATASET_COLLECTION].find_one({"dataset_id": dataset_id}, {"_id": 0, "version": 1}, sort=[("version", -1)])
    new_version = int((latest or {}).get("version", 0)) + 1
    dataset = target.get("dataset", {})
    checksum = _compute_edm_checksum(dataset)
    signature = _sign_edm_metadata(dataset_id, new_version, checksum)
    now = datetime.now(timezone.utc).isoformat()

    rollback_doc = {
        "dataset_id": dataset_id,
        "version": new_version,
        "dataset": dataset,
        "checksum": checksum,
        "signature": signature,
        "published_by": current_user.get("email", "system"),
        "published_at": now,
        "rollback_target": payload.target_version,
        "note": payload.note or f"Rollback to version {payload.target_version}",
        "created_at": now,
    }
    await db[EDM_DATASET_COLLECTION].insert_one(rollback_doc)

    response: Dict[str, Any] = {
        "status": "rolled_back",
        "contract_version": EDM_CONTROL_PLANE_CONTRACT_VERSION,
        "dataset_id": dataset_id,
        "new_version": new_version,
        "rollback_target": payload.target_version,
        "edm_meta": _build_edm_meta(rollback_doc),
    }

    if payload.publish:
        quality_report = _enforce_edm_publish_gates(dataset, context="rollback publish")
        fanout = await _dispatch_edm_dataset_to_targets(
            dataset=dataset,
            edm_meta=_build_edm_meta(rollback_doc),
            targets=payload.targets,
            priority=payload.priority,
            issued_by=current_user.get("email", "system"),
        )
        response["publish"] = {**fanout, "quality_report": quality_report}

    return response


@router.get("/edm/telemetry/summary")
async def get_edm_telemetry_summary(
    dataset_id: Optional[str] = None,
    since_minutes: int = 60,
    current_user: dict = Depends(check_permission("read")),
):
    """Centralized EDM hit analytics across agents."""
    _ = current_user
    await _ensure_edm_indexes()
    since_minutes = max(1, min(int(since_minutes), 24 * 60))
    since_iso = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()

    match: Dict[str, Any] = {"ingested_at": {"$gte": since_iso}}
    if dataset_id:
        match["dataset_id"] = dataset_id

    by_dataset = await db[EDM_HITS_COLLECTION].aggregate([
        {"$match": match},
        {"$group": {"_id": "$dataset_id", "hits": {"$sum": 1}, "agents": {"$addToSet": "$agent_id"}}},
        {"$project": {"_id": 0, "dataset_id": "$_id", "hits": 1, "agents": {"$size": "$agents"}}},
        {"$sort": {"hits": -1}},
    ]).to_list(200)

    by_platform = await db[EDM_HITS_COLLECTION].aggregate([
        {"$match": match},
        {"$group": {"_id": "$agent_platform", "hits": {"$sum": 1}}},
        {"$project": {"_id": 0, "platform": {"$ifNull": ["$_id", "unknown"]}, "hits": 1}},
        {"$sort": {"hits": -1}},
    ]).to_list(20)

    top_agents = await db[EDM_HITS_COLLECTION].aggregate([
        {"$match": match},
        {"$group": {"_id": "$agent_id", "hits": {"$sum": 1}, "host": {"$first": "$host"}}},
        {"$project": {"_id": 0, "agent_id": "$_id", "host": 1, "hits": 1}},
        {"$sort": {"hits": -1}},
        {"$limit": 20},
    ]).to_list(20)

    by_candidate_type = await db[EDM_HITS_COLLECTION].aggregate([
        {"$match": match},
        {"$group": {"_id": "$match_candidate_type", "hits": {"$sum": 1}}},
        {"$project": {"_id": 0, "candidate_type": {"$ifNull": ["$_id", "unknown"]}, "hits": 1}},
        {"$sort": {"hits": -1}},
    ]).to_list(20)

    confidence_bands = await db[EDM_HITS_COLLECTION].aggregate([
        {"$match": match},
        {"$project": {
            "band": {
                "$switch": {
                    "branches": [
                        {"case": {"$gte": ["$match_confidence", 0.98]}, "then": "0.98-1.00"},
                        {"case": {"$gte": ["$match_confidence", 0.95]}, "then": "0.95-0.97"},
                        {"case": {"$gte": ["$match_confidence", 0.90]}, "then": "0.90-0.94"},
                    ],
                    "default": "<0.90/unknown",
                }
            }
        }},
        {"$group": {"_id": "$band", "hits": {"$sum": 1}}},
        {"$project": {"_id": 0, "band": "$_id", "hits": 1}},
        {"$sort": {"hits": -1}},
    ]).to_list(10)

    total_hits = int(sum(int(i.get("hits", 0)) for i in by_dataset))
    return {
        "since_minutes": since_minutes,
        "dataset_filter": dataset_id,
        "total_hits": total_hits,
        "by_dataset": by_dataset,
        "by_platform": by_platform,
        "top_agents": top_agents,
        "by_candidate_type": by_candidate_type,
        "confidence_bands": confidence_bands,
    }


@router.get("/edm/rollouts")
async def list_edm_rollouts(
    status: Optional[str] = None,
    current_user: dict = Depends(check_permission("read")),
):
    """List EDM rollout runs with high-level state."""
    _ = current_user
    await _ensure_edm_indexes()
    query: Dict[str, Any] = {}
    if status:
        query["status"] = status
    docs = await db[EDM_ROLLOUT_COLLECTION].find(query, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"rollouts": docs, "count": len(docs)}


@router.get("/edm/rollouts/{rollout_id}")
async def get_edm_rollout(
    rollout_id: str,
    current_user: dict = Depends(check_permission("read")),
):
    """Get full rollout state and progress telemetry."""
    _ = current_user
    await _ensure_edm_indexes()
    doc = await db[EDM_ROLLOUT_COLLECTION].find_one({"rollout_id": rollout_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Rollout not found")
    return doc


@router.get("/edm/rollouts/{rollout_id}/readiness")
async def get_edm_rollout_readiness(
    rollout_id: str,
    current_user: dict = Depends(check_permission("read")),
):
    """Pre-advance readiness check using cohort/control anomaly rates."""
    _ = current_user
    await _ensure_edm_indexes()
    rollout = await db[EDM_ROLLOUT_COLLECTION].find_one({"rollout_id": rollout_id}, {"_id": 0})
    if not rollout:
        raise HTTPException(status_code=404, detail="Rollout not found")

    readiness = await _compute_rollout_readiness(rollout)
    stages = rollout.get("stages") or [5, 25, 100]
    stage_index = int(rollout.get("stage_index", 0))
    next_stage_index = stage_index + 1
    next_stage_percent = stages[next_stage_index] if next_stage_index < len(stages) else None
    readiness["rollout_id"] = rollout_id
    readiness["status"] = rollout.get("status")
    readiness["current_stage"] = {
        "index": stage_index,
        "percent": stages[stage_index] if stage_index < len(stages) else None,
    }
    readiness["next_stage"] = {
        "index": next_stage_index if next_stage_percent is not None else None,
        "percent": next_stage_percent,
    }
    readiness["can_advance"] = bool(
        rollout.get("status") == "active"
        and next_stage_percent is not None
        and not readiness.get("has_spike")
    )
    return readiness


@router.post("/edm/rollouts/start")
async def start_edm_rollout(
    payload: EDMRolloutStartModel,
    current_user: dict = Depends(check_permission("write")),
):
    """Start progressive canary rollout for an EDM dataset version."""
    await _ensure_edm_indexes()
    version_doc = await db[EDM_DATASET_COLLECTION].find_one(
        {"dataset_id": payload.dataset_id, "version": int(payload.target_version)},
        {"_id": 0},
    )
    if not version_doc:
        raise HTTPException(status_code=404, detail="Target dataset version not found")

    quality_report = _enforce_edm_publish_gates(version_doc.get("dataset", {}), context="rollout start")

    previous_doc = await db[EDM_DATASET_COLLECTION].find_one(
        {"dataset_id": payload.dataset_id, "version": {"$lt": int(payload.target_version)}},
        {"_id": 0, "version": 1},
        sort=[("version", -1)],
    )

    agents = await _resolve_edm_targets(payload.targets)
    if not agents:
        raise HTTPException(status_code=422, detail="No target agents matched rollout filters")

    rollout_id = f"edm-rollout-{secrets.token_hex(6)}"
    stages = [max(1, min(int(s), 100)) for s in (payload.policy.stages or [5, 25, 100])]
    stages = sorted(set(stages))
    if stages[-1] != 100:
        stages.append(100)

    eligible_ids = [a["agent_id"] for a in agents]
    stage_index = 0
    stage_pct = stages[stage_index]
    selected_ids = _select_rollout_agents(rollout_id, eligible_ids, stage_pct)
    if not selected_ids:
        selected_ids = eligible_ids[:1]

    fanout = await _dispatch_edm_dataset_to_targets(
        dataset=version_doc.get("dataset", {}),
        edm_meta=_build_edm_meta(version_doc),
        targets=EDMBulkTargetModel(agent_ids=selected_ids, online_only=False),
        priority=payload.priority,
        issued_by=current_user.get("email", "system"),
    )

    now = datetime.now(timezone.utc).isoformat()
    rollout_doc = {
        "contract_version": EDM_CONTROL_PLANE_CONTRACT_VERSION,
        "rollout_id": rollout_id,
        "dataset_id": payload.dataset_id,
        "target_version": int(payload.target_version),
        "previous_version": (previous_doc or {}).get("version"),
        "quality_report": quality_report,
        "status": "active",
        "targets": payload.targets.model_dump(),
        "policy": payload.policy.model_dump(),
        "stages": stages,
        "stage_index": stage_index,
        "eligible_agent_ids": eligible_ids,
        "applied_agent_ids": selected_ids,
        "created_at": now,
        "updated_at": now,
        "state_version": 1,
        "state_transition_log": [
            {
                "from_status": None,
                "to_status": "active",
                "actor": current_user.get("email", "system"),
                "reason": "rollout created",
                "timestamp": now,
                "metadata": {
                    "target_version": int(payload.target_version),
                    "initial_stage_index": stage_index,
                    "initial_stage_percent": stage_pct,
                },
            }
        ],
        "created_by": current_user.get("email", "system"),
        "stage_history": [{
            "stage_index": stage_index,
            "stage_percent": stage_pct,
            "applied_now": len(selected_ids),
            "applied_total": len(selected_ids),
            "fanout": fanout,
            "timestamp": now,
        }],
    }
    await db[EDM_ROLLOUT_COLLECTION].insert_one(rollout_doc)
    return rollout_doc


@router.post("/edm/rollouts/{rollout_id}/advance")
async def advance_edm_rollout(
    rollout_id: str,
    current_user: dict = Depends(check_permission("write")),
):
    """Advance rollout to next stage (5% -> 25% -> 100%)."""
    await _ensure_edm_indexes()
    rollout = await db[EDM_ROLLOUT_COLLECTION].find_one({"rollout_id": rollout_id}, {"_id": 0})
    if not rollout:
        raise HTTPException(status_code=404, detail="Rollout not found")
    if rollout.get("status") != "active":
        raise HTTPException(status_code=409, detail=f"Rollout is not active (status={rollout.get('status')})")

    readiness = await _compute_rollout_readiness(rollout)
    if readiness.get("has_spike"):
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Rollout advance blocked due to anomaly spike",
                "readiness": readiness,
            },
        )

    stages = rollout.get("stages") or [5, 25, 100]
    current_stage_index = int(rollout.get("stage_index", 0))
    stage_index = current_stage_index + 1
    if stage_index >= len(stages):
        close_result = await db[EDM_ROLLOUT_COLLECTION].update_one(
            {
                "rollout_id": rollout_id,
                "status": "active",
                "stage_index": current_stage_index,
            },
            {
                "$set": {"status": "completed", "updated_at": datetime.now(timezone.utc).isoformat()},
                "$inc": {"state_version": 1},
                "$push": {
                    "state_transition_log": {
                        "from_status": "active",
                        "to_status": "completed",
                        "actor": current_user.get("email", "system"),
                        "reason": "rollout completed all stages",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "metadata": {"stage_index": current_stage_index},
                    }
                },
            },
        )
        if getattr(close_result, "matched_count", 0) == 0:
            raise _rollout_conflict_error()
        return {"rollout_id": rollout_id, "status": "completed", "message": "All rollout stages already applied"}

    version_doc = await db[EDM_DATASET_COLLECTION].find_one(
        {"dataset_id": rollout.get("dataset_id"), "version": int(rollout.get("target_version"))},
        {"_id": 0},
    )
    if not version_doc:
        raise HTTPException(status_code=404, detail="Rollout target dataset version missing")

    eligible_ids = rollout.get("eligible_agent_ids") or []
    already_applied = set(rollout.get("applied_agent_ids") or [])
    stage_pct = int(stages[stage_index])
    target_set = set(_select_rollout_agents(rollout_id, eligible_ids, stage_pct))
    delta_ids = [aid for aid in target_set if aid not in already_applied]

    fanout = {"matched_agents": 0, "dispatched": 0, "sent": 0, "queued": 0, "results": []}
    if delta_ids:
        fanout = await _dispatch_edm_dataset_to_targets(
            dataset=version_doc.get("dataset", {}),
            edm_meta=_build_edm_meta(version_doc),
            targets=EDMBulkTargetModel(agent_ids=delta_ids, online_only=False),
            priority="high",
            issued_by=current_user.get("email", "system"),
        )

    updated_applied = list(already_applied.union(set(delta_ids)))
    now = datetime.now(timezone.utc).isoformat()
    done = stage_index >= len(stages) - 1
    update_result = await db[EDM_ROLLOUT_COLLECTION].update_one(
        {
            "rollout_id": rollout_id,
            "status": "active",
            "stage_index": current_stage_index,
        },
        {
            "$set": {
                "stage_index": stage_index,
                "applied_agent_ids": updated_applied,
                "updated_at": now,
                "status": "completed" if done else "active",
            },
            "$inc": {"state_version": 1},
            "$push": {
                "state_transition_log": {
                    "from_status": "active",
                    "to_status": "completed" if done else "active",
                    "actor": current_user.get("email", "system"),
                    "reason": "rollout stage advanced",
                    "timestamp": now,
                    "metadata": {
                        "from_stage_index": current_stage_index,
                        "to_stage_index": stage_index,
                        "stage_percent": stage_pct,
                        "applied_now": len(delta_ids),
                    },
                },
                "stage_history": {
                    "stage_index": stage_index,
                    "stage_percent": stage_pct,
                    "applied_now": len(delta_ids),
                    "applied_total": len(updated_applied),
                    "fanout": fanout,
                    "timestamp": now,
                }
            },
        },
    )
    if getattr(update_result, "matched_count", 0) == 0:
        raise _rollout_conflict_error()

    return {
        "rollout_id": rollout_id,
        "status": "completed" if done else "active",
        "stage_index": stage_index,
        "stage_percent": stage_pct,
        "applied_now": len(delta_ids),
        "applied_total": len(updated_applied),
        "fanout": fanout,
    }


@router.post("/edm/rollouts/{rollout_id}/rollback")
async def rollback_edm_rollout(
    rollout_id: str,
    payload: EDMRolloutRollbackModel,
    current_user: dict = Depends(check_permission("write")),
):
    """Manually rollback a rollout to previous or explicit dataset version."""
    await _ensure_edm_indexes()
    rollout = await db[EDM_ROLLOUT_COLLECTION].find_one({"rollout_id": rollout_id}, {"_id": 0})
    if not rollout:
        raise HTTPException(status_code=404, detail="Rollout not found")

    rollback_version = payload.rollback_version
    if rollback_version is None:
        rollback_version = rollout.get("previous_version")
    if rollback_version is None:
        raise HTTPException(status_code=422, detail="No rollback version available")

    refreshed = await _claim_rollout_for_rollback(
        rollout_id=rollout_id,
        reason=payload.reason or "Manual rollback requested",
        requested_by=current_user.get("email", "system"),
        allowed_statuses=["active", "completed"],
    )
    update_previous = await db[EDM_ROLLOUT_COLLECTION].update_one(
        {"rollout_id": rollout_id, "status": "rolling_back"},
        {
            "$set": {"previous_version": int(rollback_version), "updated_at": datetime.now(timezone.utc).isoformat()},
            "$inc": {"state_version": 1},
            "$push": {
                "state_transition_log": {
                    "from_status": "rolling_back",
                    "to_status": "rolling_back",
                    "actor": current_user.get("email", "system"),
                    "reason": "rollback version selected",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "metadata": {"rollback_version": int(rollback_version)},
                }
            },
        },
    )
    if getattr(update_previous, "matched_count", 0) == 0:
        raise _rollout_conflict_error()
    refreshed = await db[EDM_ROLLOUT_COLLECTION].find_one({"rollout_id": rollout_id}, {"_id": 0})
    rollback = await _execute_rollout_rollback(
        refreshed,
        payload.reason or "Manual rollback requested",
        current_user.get("email", "system"),
    )
    if not rollback.get("rolled_back"):
        raise HTTPException(status_code=422, detail=rollback.get("reason", "Rollback failed"))
    return {"rollout_id": rollout_id, **rollback}


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
    db_commands = await db.agent_commands.find(
        {
            "agent_id": agent_id,
            "status": {"$in": ["pending", "queued"]},
        }
    ).sort("created_at", 1).limit(10).to_list(length=10)
    
    # Mark as delivered
    if db_commands:
        command_ids = [cmd["command_id"] for cmd in db_commands]
        await db.agent_commands.update_many(
            {
                "command_id": {"$in": command_ids},
                "status": {"$in": ["pending", "queued"]},
            },
            {
                "$set": {
                    "status": "delivered",
                    "delivered_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
                "$inc": {"state_version": 1},
                "$push": {
                    "state_transition_log": {
                        "from_status": ["pending", "queued"],
                        "to_status": "delivered",
                        "actor": f"agent:{agent_id}",
                        "reason": "agent polled commands",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                },
            }
        )
    
    # Combine and return with full authority contract for endpoint-local MCP/VNS gate.
    serialized_queued = [
        _serialize_agent_command_for_delivery(c if isinstance(c, dict) else {})
        for c in queued
    ]
    serialized_db = [_serialize_agent_command_for_delivery(c) for c in db_commands]
    all_commands = serialized_queued + serialized_db
    
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

    fortress_payload = result.get("fortress") if isinstance(result.get("fortress"), dict) else {}
    boundary_event = _extract_boundary_crossing_from_command_result(
        agent_id=agent_id,
        command_id=command_id,
        result=result if isinstance(result, dict) else {},
    )
    boundary_outcome = boundary_event.get("world_outcome")
    
    finalize = await _finalize_agent_command_result(
        command_id=command_id,
        status=result.get("status", "completed"),
        result_payload=result.get("result", {}),
        transition_actor=f"agent:{agent_id}",
        transition_reason="agent reported command result",
        fortress_payload=fortress_payload,
        boundary_outcome=str(boundary_outcome) if boundary_outcome else None,
    )
    
    # Store full result in command_results collection
    await db.command_results.insert_one({
        "command_id": command_id,
        "agent_id": agent_id,
        "command_type": result.get("command_type"),
        "status": result.get("status", "completed"),
        "result": result.get("result", {}),
        "fortress": fortress_payload if fortress_payload else None,
        "boundary_outcome": boundary_outcome,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    logger.info(f"Command result received: {command_id} from {agent_id} - {finalize.get('status')}")
    _record_unified_audit(
        principal=f"agent:{agent_id}",
        action="unified_agent_command_result_ingest",
        targets=[agent_id, command_id],
        result="success",
        constraints={
            "boundary_outcome": boundary_outcome,
            "fortress_present": bool(fortress_payload),
        },
    )
    await emit_world_event(
        get_db(),
        event_type="unified_agent_command_result_received",
        entity_refs=[agent_id, command_id],
        payload={
            "status": finalize.get("status"),
            "boundary_outcome": boundary_outcome,
            "fortress_present": bool(fortress_payload),
        },
        trigger_triune=boundary_outcome in {"denied", "queued", "token-invalid", "anomalous", "decoy-hit"},
    )
    if boundary_event:
        await emit_world_event(
            get_db(),
            event_type=boundary_event["event_type"],
            entity_refs=boundary_event["entity_refs"],
            payload=boundary_event["payload"],
            trigger_triune=bool(boundary_event.get("trigger_triune")),
        )
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
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "state_version": 1,
        "state_transition_log": [
            {
                "from_status": None,
                "to_status": "pending",
                "actor": current_user.get("email", "system"),
                "reason": "deployment created",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": {
                    "target_platform": deployment.target_platform,
                    "target_ip": deployment.target_ip,
                },
            }
        ],
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
async def create_alert(
    alert: AlertModel,
    auth: Dict = Depends(verify_agent_auth),
):
    """Create an alert from an agent"""
    
    alert_id = secrets.token_hex(8)
    
    alert_doc = _build_unified_alert_doc(
        alert_id=alert_id,
        agent_id=alert.agent_id,
        severity=alert.severity,
        category=alert.category,
        message=alert.message,
        details=alert.details,
        mitre_technique=alert.mitre_technique,
        actor="system:api",
        reason="alert created via API",
    )
    
    await db.unified_alerts.insert_one(alert_doc)
    logger.warning(f"ALERT [{alert.severity.upper()}] from {alert.agent_id}: {alert.message}")
    await emit_world_event(get_db(), event_type="unified_agent_alert_created", entity_refs=[alert_id, alert.agent_id], payload={"severity": alert.severity, "category": alert.category}, trigger_triune=False)
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
    
    actor = current_user.get("email", "system")
    alert = await _ensure_unified_alert_state_fields(
        alert_id,
        actor=actor,
        reason="bootstrap unified alert durability fields",
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if bool(alert.get("acknowledged")):
        raise HTTPException(status_code=409, detail="Alert already acknowledged")

    current_version = int(alert.get("state_version") or 0)
    query: Dict[str, Any] = {
        "alert_id": alert_id,
        "acknowledged": False,
    }
    if current_version <= 0:
        query["$or"] = [{"state_version": {"$exists": False}}, {"state_version": 0}]
    else:
        query["state_version"] = current_version

    now = datetime.now(timezone.utc).isoformat()
    result = await db.unified_alerts.update_one(
        query,
        {
            "$set": {
                "acknowledged": True,
                "status": "acknowledged",
                "acknowledged_at": now,
                "acknowledged_by": actor,
                "updated_at": now,
            },
            "$inc": {"state_version": 1},
            "$push": {
                "state_transition_log": _alert_transition_entry(
                    from_status="unacknowledged",
                    to_status="acknowledged",
                    actor=actor,
                    reason="alert acknowledged",
                )
            },
        },
    )

    if getattr(result, "modified_count", 0) == 0:
        refreshed = await db.unified_alerts.find_one({"alert_id": alert_id}, {"_id": 0, "acknowledged": 1})
        if not refreshed:
            raise HTTPException(status_code=404, detail="Alert not found")
        if bool(refreshed.get("acknowledged")):
            raise HTTPException(status_code=409, detail="Alert already acknowledged")
        raise HTTPException(status_code=409, detail="Alert acknowledgment conflict; state changed concurrently")
    
    await emit_world_event(get_db(), event_type="unified_agent_alert_acknowledged", entity_refs=[alert_id], payload={"actor": actor}, trigger_triune=False)
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
    verify_websocket_machine_token(
        websocket,
        env_keys=["UNIFIED_AGENT_WS_TOKEN", "SWARM_AGENT_TOKEN", "INTEGRATION_API_KEY"],
        header_names=["x-agent-token", "x-internal-token"],
        subject="unified agent websocket",
    )
    
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
                alert_doc = _build_unified_alert_doc(
                    alert_id=secrets.token_hex(8),
                    agent_id=agent_id,
                    severity=alert_data.get("severity", "medium"),
                    category=alert_data.get("category", "unknown"),
                    message=alert_data.get("message", "Unknown alert"),
                    details=alert_data.get("details", {}),
                    mitre_technique=alert_data.get("mitre_technique"),
                    actor=f"agent:{agent_id}",
                    reason="alert received via websocket",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
                await db.unified_alerts.insert_one(alert_doc)
                logger.warning(f"Alert from {agent_id}: {alert_data.get('message', 'Unknown')}")
            
            elif msg_type == "telemetry":
                # Store telemetry
                telemetry = data.get("data", {})
                await db.agent_telemetry.insert_one({
                    "agent_id": agent_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "telemetry": telemetry
                })
                await emit_world_event(
                    get_db(),
                    event_type="unified_agent_telemetry_ingested",
                    entity_refs=[agent_id],
                    payload={
                        "source": "websocket",
                        "telemetry_keys": len(telemetry.keys()) if isinstance(telemetry, dict) else None,
                    },
                    trigger_triune=False,
                )
                _record_unified_audit(
                    principal=f"agent:{agent_id}",
                    action="unified_agent_telemetry_ingest",
                    targets=[agent_id],
                    result="success",
                    constraints={"source": "websocket"},
                )
                await _project_unified_state_snapshot(
                    agent_id=agent_id,
                    source="websocket",
                    status="online",
                    telemetry=telemetry if isinstance(telemetry, dict) else {},
                    monitors_summary={},
                )
                # Run threat hunting
                await _hunt_telemetry(telemetry)
            
            elif msg_type == "command_result":
                # Store command result
                result = data.get("data", {})
                try:
                    boundary_event = _extract_boundary_crossing_from_command_result(
                        agent_id=agent_id,
                        command_id=str(result.get("command_id") or ""),
                        result=result if isinstance(result, dict) else {},
                    )
                    await _finalize_agent_command_result(
                        command_id=result.get("command_id"),
                        status=result.get("status", "completed"),
                        result_payload=result.get("result", {}) if isinstance(result, dict) else {},
                        transition_actor=f"agent:{agent_id}",
                        transition_reason="websocket command_result",
                        fortress_payload=result.get("fortress") if isinstance(result, dict) and isinstance(result.get("fortress"), dict) else None,
                        boundary_outcome=str(boundary_event.get("world_outcome") or "") if boundary_event else None,
                    )
                    if boundary_event:
                        await emit_world_event(
                            get_db(),
                            event_type=boundary_event["event_type"],
                            entity_refs=boundary_event["entity_refs"],
                            payload=boundary_event["payload"],
                            trigger_triune=bool(boundary_event.get("trigger_triune")),
                        )
                except HTTPException:
                    # Commands can race with API completion; keep WS loop resilient.
                    pass
    
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


@router.get("/agent/download/windows")
async def download_agent_package_windows():
    """Download the unified agent package as a ZIP archive for Windows installers."""
    import io
    import os
    import zipfile
    from fastapi.responses import StreamingResponse

    agent_dir = "/app/unified_agent"

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        for item in ['core', 'requirements.txt']:
            item_path = os.path.join(agent_dir, item)
            if not os.path.exists(item_path):
                continue

            if os.path.isdir(item_path):
                for root, _, files in os.walk(item_path):
                    for file_name in files:
                        full_path = os.path.join(root, file_name)
                        arcname = os.path.relpath(full_path, agent_dir)
                        zf.write(full_path, arcname=arcname)
            else:
                zf.write(item_path, arcname=item)

    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=seraph-agent-windows.zip"}
    )


@router.get("/agent/install-script")
async def get_install_script(
    request: Request,
    server_url: Optional[str] = None,
    format: Optional[str] = None,
    enrollment_key: Optional[str] = None,
    integration_token: Optional[str] = None,
    ca_cert_pem_b64: Optional[str] = None,
    noninteractive: Optional[bool] = False,
):
    """Get an auth/cert aware Linux agent installation script."""

    forwarded_proto = request.headers.get("x-forwarded-proto")
    proto = forwarded_proto or request.url.scheme or "http"
    base_url = server_url or f"{proto}://{request.headers.get('host', 'localhost:8001')}"
    embedded_enrollment = (enrollment_key or "").strip()
    embedded_integration = (integration_token or "").strip()
    embedded_ca_b64 = (ca_cert_pem_b64 or "").strip()
    noninteractive_flag = "1" if bool(noninteractive) else "0"

    script = f'''#!/bin/bash
# Seraph AI Unified Agent Installer (auth + cert aware)
set -euo pipefail

SERAPH_SERVER="{base_url}"
INSTALL_DIR="/opt/seraph-agent"
EMBEDDED_ENROLLMENT_KEY="{embedded_enrollment}"
EMBEDDED_INTEGRATION_TOKEN="{embedded_integration}"
EMBEDDED_CA_CERT_B64="{embedded_ca_b64}"
SERAPH_NONINTERACTIVE="${{SERAPH_NONINTERACTIVE:-{noninteractive_flag}}}"

SERAPH_ENROLLMENT_KEY="${{SERAPH_ENROLLMENT_KEY:-$EMBEDDED_ENROLLMENT_KEY}}"
SERAPH_INTEGRATION_TOKEN="${{SERAPH_INTEGRATION_TOKEN:-$EMBEDDED_INTEGRATION_TOKEN}}"
SERAPH_CA_CERT_PEM_B64="${{SERAPH_CA_CERT_PEM_B64:-$EMBEDDED_CA_CERT_B64}}"

if [[ $EUID -ne 0 ]]; then
  echo "This installer must run as root (use sudo)."
  exit 1
fi

if [[ -z "${{SERAPH_ENROLLMENT_KEY}}" ]]; then
  echo "Missing enrollment key. Export SERAPH_ENROLLMENT_KEY before install."
  exit 2
fi

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y python3 python3-pip python3-venv curl ca-certificates
  apt-get install -y wireguard-tools ufw iptables >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y python3 python3-pip curl ca-certificates
  dnf install -y wireguard-tools firewalld iptables >/dev/null 2>&1 || true
elif command -v yum >/dev/null 2>&1; then
  yum install -y python3 python3-pip curl ca-certificates
  yum install -y wireguard-tools firewalld iptables >/dev/null 2>&1 || true
elif command -v pacman >/dev/null 2>&1; then
  pacman -Sy --noconfirm python python-pip curl ca-certificates
  pacman -Sy --noconfirm wireguard-tools ufw iptables >/dev/null 2>&1 || true
fi

curl -fsSL "$SERAPH_SERVER/api/unified/agent/download" -o agent.tar.gz
tar -xzf agent.tar.gz
rm -f agent.tar.gz

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
if [[ -f "requirements.txt" ]]; then
  pip install -r requirements.txt
else
  pip install psutil requests netifaces watchdog pyyaml cryptography
fi
# Ensure substantive web dashboard dependencies are available.
pip install flask flask-cors >/dev/null 2>&1 || true

mkdir -p "$INSTALL_DIR/certs"
CA_CERT_PATH=""
if [[ -n "${{SERAPH_CA_CERT_PEM_B64}}" ]]; then
  CA_CERT_PATH="$INSTALL_DIR/certs/seraph-agent-ca.pem"
  SERAPH_CA_CERT_PEM_B64="$SERAPH_CA_CERT_PEM_B64" CA_CERT_PATH="$CA_CERT_PATH" python3 - <<'PY'
import base64, os, pathlib
payload = os.environ.get("SERAPH_CA_CERT_PEM_B64", "").strip()
target = os.environ.get("CA_CERT_PATH", "").strip()
if payload and target:
    pathlib.Path(target).write_bytes(base64.b64decode(payload.encode()))
PY
  chmod 600 "$CA_CERT_PATH"
fi

cat > "$INSTALL_DIR/agent_config.json" <<EOF
{{
  "server_url": "$SERAPH_SERVER",
  "enrollment_key": "$SERAPH_ENROLLMENT_KEY",
  "auth_token": "",
  "integration_api_key": "$SERAPH_INTEGRATION_TOKEN",
  "local_ui_enabled": false
}}
EOF
chmod 600 "$INSTALL_DIR/agent_config.json"

cat > /etc/default/seraph-agent <<EOF
SERAPH_ENROLLMENT_KEY=$SERAPH_ENROLLMENT_KEY
SERAPH_INTEGRATION_TOKEN=$SERAPH_INTEGRATION_TOKEN
SERAPH_NONINTERACTIVE=$SERAPH_NONINTERACTIVE
EOF
if [[ -n "$CA_CERT_PATH" ]]; then
  echo "REQUESTS_CA_BUNDLE=$CA_CERT_PATH" >> /etc/default/seraph-agent
fi
chmod 600 /etc/default/seraph-agent

# Firewall baseline for dashboard/control surfaces and WireGuard.
if command -v ufw >/dev/null 2>&1; then
  ufw allow 3000/tcp >/dev/null 2>&1 || true
  ufw allow 5000/tcp >/dev/null 2>&1 || true
  ufw allow 51820/udp >/dev/null 2>&1 || true
elif command -v firewall-cmd >/dev/null 2>&1; then
  systemctl enable --now firewalld >/dev/null 2>&1 || true
  firewall-cmd --permanent --add-port=3000/tcp >/dev/null 2>&1 || true
  firewall-cmd --permanent --add-port=5000/tcp >/dev/null 2>&1 || true
  firewall-cmd --permanent --add-port=51820/udp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
elif command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -p tcp --dport 3000 -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p tcp --dport 3000 -j ACCEPT
  iptables -C INPUT -p tcp --dport 5000 -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p tcp --dport 5000 -j ACCEPT
  iptables -C INPUT -p udp --dport 51820 -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p udp --dport 51820 -j ACCEPT
fi

# WireGuard autostart if a managed config is present.
VPN_CONF_SOURCE=""
for candidate in \
  "/etc/wireguard/metatron-vpn.conf" \
  "/etc/wireguard/wg0.conf" \
  "$INSTALL_DIR/vpn/metatron-vpn.conf" \
  "$INSTALL_DIR/vpn/wg0.conf"; do
  if [[ -f "$candidate" ]]; then
    VPN_CONF_SOURCE="$candidate"
    break
  fi
done
if command -v wg-quick >/dev/null 2>&1 && [[ -n "$VPN_CONF_SOURCE" ]]; then
  mkdir -p /etc/wireguard
  cp -f "$VPN_CONF_SOURCE" /etc/wireguard/metatron-vpn.conf
  chmod 600 /etc/wireguard/metatron-vpn.conf
  ln -sf /etc/wireguard/metatron-vpn.conf /etc/wireguard/wg0.conf || true
  systemctl enable wg-quick@metatron-vpn.service >/dev/null 2>&1 || systemctl enable wg-quick@wg0.service >/dev/null 2>&1 || true
  systemctl restart wg-quick@metatron-vpn.service >/dev/null 2>&1 || systemctl restart wg-quick@wg0.service >/dev/null 2>&1 || true
fi

cat > /etc/systemd/system/seraph-agent.service <<'EOF'
[Unit]
Description=Seraph Unified Agent Core
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/seraph-agent
EnvironmentFile=-/etc/default/seraph-agent
Environment=PATH=/opt/seraph-agent/venv/bin
ExecStart=/opt/seraph-agent/venv/bin/python /opt/seraph-agent/core/agent.py --config /opt/seraph-agent/agent_config.json --no-ui
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/seraph-agent-dashboard.service <<'EOF'
[Unit]
Description=Seraph Unified Agent Web Dashboard (port 5000)
After=network.target seraph-agent.service
Requires=seraph-agent.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/seraph-agent
EnvironmentFile=-/etc/default/seraph-agent
Environment=PATH=/opt/seraph-agent/venv/bin
ExecStart=/opt/seraph-agent/venv/bin/python /opt/seraph-agent/ui/web/app.py --host 0.0.0.0 --port 5000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable seraph-agent seraph-agent-dashboard
systemctl restart seraph-agent seraph-agent-dashboard
systemctl is-active --quiet seraph-agent
systemctl is-active --quiet seraph-agent-dashboard
systemctl is-active --quiet wg-quick@metatron-vpn.service >/dev/null 2>&1 || systemctl is-active --quiet wg-quick@wg0.service >/dev/null 2>&1 || true
echo "SERAPH_DEPLOY_SUCCESS"
'''

    usage = (
        f"curl -sSL {base_url}/api/unified/agent/install-script | "
        "sudo SERAPH_ENROLLMENT_KEY=<ENROLLMENT_KEY> bash"
    )
    if (format or "").lower() == "json":
        return {"script": script, "usage": usage}

    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        content=script,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": "attachment; filename=seraph-agent-install.sh", "X-Install-Usage": usage},
    )


@router.get("/agent/install-windows")
async def get_windows_install_script(
    request: Request,
    server_url: Optional[str] = None,
    format: Optional[str] = None,
    enrollment_key: Optional[str] = None,
    integration_token: Optional[str] = None,
    ca_cert_pem_b64: Optional[str] = None,
    noninteractive: Optional[bool] = False,
):
    """Get an auth/cert aware Windows installer script."""

    forwarded_proto = request.headers.get("x-forwarded-proto")
    proto = forwarded_proto or request.url.scheme or "http"
    base_url = server_url or f"{proto}://{request.headers.get('host', 'localhost:8001')}"
    embedded_enrollment = (enrollment_key or "").strip()
    embedded_integration = (integration_token or "").strip()
    embedded_ca_b64 = (ca_cert_pem_b64 or "").strip()
    noninteractive_flag = "$true" if bool(noninteractive) else "$false"

    script = f'''# Seraph Unified Agent Installer (Windows)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$SERAPH_SERVER = "{base_url}"
$INSTALL_DIR = "C:\\ProgramData\\SeraphAgent"
$SYSTEM32_DIR = "$env:WINDIR\\System32"
$ZIP_PATH = "$INSTALL_DIR\\agent.zip"
$CONFIG_PATH = "$INSTALL_DIR\\agent_config.json"
$RUNNER_PATH = "$INSTALL_DIR\\run-agent.ps1"
$DASHBOARD_RUNNER_PATH = "$INSTALL_DIR\\run-dashboard.ps1"
$VPN_RUNNER_PATH = "$INSTALL_DIR\\run-vpn.ps1"
$CA_CERT_PATH = "$INSTALL_DIR\\certs\\seraph-agent-ca.pem"
$EMBEDDED_ENROLLMENT_KEY = "{embedded_enrollment}"
$EMBEDDED_INTEGRATION_TOKEN = "{embedded_integration}"
$EMBEDDED_CA_CERT_B64 = "{embedded_ca_b64}"
$NONINTERACTIVE = {noninteractive_flag}

function Assert-Admin {{
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    throw "Installer must run as Administrator."
  }}
}}

function Get-PythonExecutable {{
  if (Get-Command py -ErrorAction SilentlyContinue) {{ return "py -3" }}
  if (Get-Command python -ErrorAction SilentlyContinue) {{ return "python" }}
  return $null
}}

function Ensure-FirewallRule {{
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][string]$Protocol,
    [Parameter(Mandatory=$true)][int]$Port
  )
  & netsh advfirewall firewall delete rule name="$Name" | Out-Null
  & netsh advfirewall firewall add rule name="$Name" dir=in action=allow protocol=$Protocol localport=$Port | Out-Null
}}

function Install-System32Launcher {{
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$Content
  )
  Set-Content -Path $Path -Value $Content -Encoding Ascii
}}

try {{
  Assert-Admin
  New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
  New-Item -ItemType Directory -Force -Path "$INSTALL_DIR\\certs" | Out-Null
  Set-Location $INSTALL_DIR

  $enrollment = $env:SERAPH_ENROLLMENT_KEY
  if (-not $enrollment) {{ $enrollment = $EMBEDDED_ENROLLMENT_KEY }}
  if (-not $enrollment) {{ throw "Missing SERAPH_ENROLLMENT_KEY" }}

  $integration = $env:SERAPH_INTEGRATION_TOKEN
  if (-not $integration) {{ $integration = $EMBEDDED_INTEGRATION_TOKEN }}

  $caCertB64 = $env:SERAPH_CA_CERT_PEM_B64
  if (-not $caCertB64) {{ $caCertB64 = $EMBEDDED_CA_CERT_B64 }}
  if ($caCertB64) {{
    [IO.File]::WriteAllBytes($CA_CERT_PATH, [Convert]::FromBase64String($caCertB64))
  }}

  Invoke-WebRequest -UseBasicParsing -Uri "$SERAPH_SERVER/api/unified/agent/download/windows" -OutFile $ZIP_PATH
  Expand-Archive -Path $ZIP_PATH -DestinationPath $INSTALL_DIR -Force
  Remove-Item $ZIP_PATH -Force

  $pythonCmd = Get-PythonExecutable
  if (-not $pythonCmd) {{
    throw "Python 3 not found. Install Python 3 and rerun installer."
  }}

  cmd /c "$pythonCmd -m pip install --upgrade pip"
  if (Test-Path "$INSTALL_DIR\\requirements.txt") {{
    cmd /c "$pythonCmd -m pip install -r $INSTALL_DIR\\requirements.txt"
  }} else {{
    cmd /c "$pythonCmd -m pip install psutil requests netifaces watchdog pyyaml cryptography"
  }}
  cmd /c "$pythonCmd -m pip install flask flask-cors"

  $config = @{{
    server_url = $SERAPH_SERVER
    enrollment_key = $enrollment
    auth_token = ""
    integration_api_key = $integration
    local_ui_enabled = $false
  }} | ConvertTo-Json -Depth 6
  Set-Content -Path $CONFIG_PATH -Value $config -Encoding UTF8

  $runner = @"
$ErrorActionPreference = 'Stop'
if (Test-Path '$CA_CERT_PATH') {{ $env:REQUESTS_CA_BUNDLE = '$CA_CERT_PATH' }}
& cmd /c "$pythonCmd core\\agent.py --config `"$CONFIG_PATH`" --no-ui"
"@
  Set-Content -Path $RUNNER_PATH -Value $runner -Encoding UTF8

  $dashboardRunner = @"
$ErrorActionPreference = 'Stop'
if (Test-Path '$CA_CERT_PATH') {{ $env:REQUESTS_CA_BUNDLE = '$CA_CERT_PATH' }}
& cmd /c "$pythonCmd ui\\web\\app.py --host 0.0.0.0 --port 5000"
"@
  Set-Content -Path $DASHBOARD_RUNNER_PATH -Value $dashboardRunner -Encoding UTF8

  $vpnRunner = @"
$ErrorActionPreference = 'SilentlyContinue'
$wgExe = 'C:\\Program Files\\WireGuard\\wireguard.exe'
if (Test-Path $wgExe) {{
  $vpnConfigs = @(
    'C:\\Program Files\\WireGuard\\Data\\Configurations\\metatron-vpn.conf',
    'C:\\Program Files\\WireGuard\\Data\\Configurations\\wg0.conf',
    '$INSTALL_DIR\\vpn\\metatron-vpn.conf',
    '$INSTALL_DIR\\vpn\\wg0.conf'
  )
  foreach ($cfg in $vpnConfigs) {{
    if (Test-Path $cfg) {{
      & $wgExe /installtunnelservice $cfg | Out-Null
      break
    }}
  }}
  Start-Service -Name 'WireGuardTunnel$metatron-vpn' -ErrorAction SilentlyContinue
  Start-Service -Name 'WireGuardTunnel$wg0' -ErrorAction SilentlyContinue
}}
"@
  Set-Content -Path $VPN_RUNNER_PATH -Value $vpnRunner -Encoding UTF8

  Ensure-FirewallRule -Name "Seraph Agent Dashboard 5000" -Protocol "TCP" -Port 5000
  Ensure-FirewallRule -Name "Seraph Frontend 3000" -Protocol "TCP" -Port 3000
  Ensure-FirewallRule -Name "Seraph WireGuard 51820" -Protocol "UDP" -Port 51820

  Install-System32Launcher -Path "$SYSTEM32_DIR\\seraph-agent.cmd" -Content "@echo off`r`npowershell.exe -ExecutionPolicy Bypass -File `"$RUNNER_PATH`"`r`n"
  Install-System32Launcher -Path "$SYSTEM32_DIR\\seraph-dashboard.cmd" -Content "@echo off`r`npowershell.exe -ExecutionPolicy Bypass -File `"$DASHBOARD_RUNNER_PATH`"`r`n"
  Install-System32Launcher -Path "$SYSTEM32_DIR\\seraph-vpn-start.cmd" -Content "@echo off`r`npowershell.exe -ExecutionPolicy Bypass -File `"$VPN_RUNNER_PATH`"`r`n"

  $taskArgs = "-ExecutionPolicy Bypass -File `"$RUNNER_PATH`""
  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskArgs -WorkingDirectory $INSTALL_DIR
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
  Register-ScheduledTask -TaskName "SeraphAgent" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
  Start-ScheduledTask -TaskName "SeraphAgent"

  $dashboardTaskArgs = "-ExecutionPolicy Bypass -File `"$DASHBOARD_RUNNER_PATH`""
  $dashboardAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $dashboardTaskArgs -WorkingDirectory $INSTALL_DIR
  Register-ScheduledTask -TaskName "SeraphAgentDashboard" -Action $dashboardAction -Trigger $trigger -Principal $principal -Force | Out-Null
  Start-ScheduledTask -TaskName "SeraphAgentDashboard"

  $vpnTaskArgs = "-ExecutionPolicy Bypass -File `"$VPN_RUNNER_PATH`""
  $vpnAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $vpnTaskArgs -WorkingDirectory $INSTALL_DIR
  Register-ScheduledTask -TaskName "SeraphAgentVPN" -Action $vpnAction -Trigger $trigger -Principal $principal -Force | Out-Null
  Start-ScheduledTask -TaskName "SeraphAgentVPN"
}} catch {{
  Write-Host "INSTALL FAILED: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}}

Write-Host "SERAPH_DEPLOY_SUCCESS" -ForegroundColor Green
if (-not $NONINTERACTIVE) {{
  Write-Host "Agent installed to: $INSTALL_DIR"
}}
'''

    usage = (
        f"irm {base_url}/api/unified/agent/install-windows | "
        "powershell -Command \"$env:SERAPH_ENROLLMENT_KEY='<ENROLLMENT_KEY>'; iex ($input | Out-String)\""
    )
    if (format or "").lower() == "json":
        return {"script": script, "usage": usage}

    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        content=script,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=seraph-agent-install.ps1", "X-Install-Usage": usage},
    )


@router.get("/agent/install-macos")
async def get_macos_install_script(
    request: Request,
    server_url: Optional[str] = None,
    format: Optional[str] = None,
    enrollment_key: Optional[str] = None,
    integration_token: Optional[str] = None,
    ca_cert_pem_b64: Optional[str] = None,
    noninteractive: Optional[bool] = False,
):
    """Get the macOS agent installation script"""
    
    forwarded_proto = request.headers.get("x-forwarded-proto")
    proto = forwarded_proto or request.url.scheme or "http"
    base_url = server_url or f"{proto}://{request.headers.get('host', 'localhost:8001')}"
    embedded_enrollment = (enrollment_key or "").strip()
    embedded_integration = (integration_token or "").strip()
    embedded_ca_b64 = (ca_cert_pem_b64 or "").strip()
    noninteractive_flag = "1" if bool(noninteractive) else "0"
    
    script = f'''#!/bin/bash
# Seraph AI Unified Agent - macOS Installer

set -euo pipefail

SERAPH_SERVER="{base_url}"
INSTALL_DIR="$HOME/Library/Application Support/SeraphAgent"
LAUNCH_AGENT_PATH="$HOME/Library/LaunchAgents/com.seraph.agent.plist"
DASHBOARD_LAUNCH_AGENT_PATH="$HOME/Library/LaunchAgents/com.seraph.dashboard.plist"
VPN_LAUNCH_DAEMON_PATH="/Library/LaunchDaemons/com.seraph.vpn.plist"
EMBEDDED_ENROLLMENT_KEY="{embedded_enrollment}"
EMBEDDED_INTEGRATION_TOKEN="{embedded_integration}"
EMBEDDED_CA_CERT_B64="{embedded_ca_b64}"
SERAPH_NONINTERACTIVE="${{SERAPH_NONINTERACTIVE:-{noninteractive_flag}}}"
SERAPH_ENROLLMENT_KEY="${{SERAPH_ENROLLMENT_KEY:-$EMBEDDED_ENROLLMENT_KEY}}"
SERAPH_INTEGRATION_TOKEN="${{SERAPH_INTEGRATION_TOKEN:-$EMBEDDED_INTEGRATION_TOKEN}}"
SERAPH_CA_CERT_PEM_B64="${{SERAPH_CA_CERT_PEM_B64:-$EMBEDDED_CA_CERT_B64}}"

echo "================================================================"
echo "  SERAPH AI UNIFIED AGENT INSTALLER (macOS)"
echo "  Target Server: $SERAPH_SERVER"
echo "================================================================"

if [[ -z "${{SERAPH_ENROLLMENT_KEY}}" ]]; then
    echo "Missing enrollment key. Export SERAPH_ENROLLMENT_KEY before install."
    exit 2
fi

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
pip install psutil requests netifaces watchdog pyyaml scapy cryptography
pip install flask flask-cors

# Install YARA (optional, for malware scanning)
echo "Installing YARA..."
brew install yara 2>/dev/null || true
pip install yara-python 2>/dev/null || echo "YARA installation skipped (optional)"
brew install wireguard-tools 2>/dev/null || true

# Download agent
echo "Downloading agent from server..."
curl -sSL "$SERAPH_SERVER/api/unified/agent/download" -o agent.tar.gz
tar -xzf agent.tar.gz
rm agent.tar.gz

# Optional custom CA bundle for TLS trust
mkdir -p "$INSTALL_DIR/certs"
if [[ -n "${{SERAPH_CA_CERT_PEM_B64}}" ]]; then
    SERAPH_CA_CERT_PEM_B64="$SERAPH_CA_CERT_PEM_B64" python3 - <<'PY'
import base64, os, pathlib
payload = os.environ.get("SERAPH_CA_CERT_PEM_B64", "").strip()
if payload:
    pathlib.Path("certs/seraph-agent-ca.pem").write_bytes(base64.b64decode(payload.encode()))
PY
fi

# Persist auth/bootstrap configuration
cat > "$INSTALL_DIR/agent_config.json" <<EOF
{{
  "server_url": "$SERAPH_SERVER",
  "enrollment_key": "$SERAPH_ENROLLMENT_KEY",
  "auth_token": "",
  "integration_api_key": "$SERAPH_INTEGRATION_TOKEN",
  "local_ui_enabled": false
}}
EOF

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
        <string>--config</string>
        <string>$INSTALL_DIR/agent_config.json</string>
        <string>--no-ui</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>REQUESTS_CA_BUNDLE</key>
        <string>$INSTALL_DIR/certs/seraph-agent-ca.pem</string>
    </dict>
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

cat > "$DASHBOARD_LAUNCH_AGENT_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.seraph.dashboard</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/venv/bin/python</string>
        <string>$INSTALL_DIR/ui/web/app.py</string>
        <string>--host</string>
        <string>0.0.0.0</string>
        <string>--port</string>
        <string>5000</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>REQUESTS_CA_BUNDLE</key>
        <string>$INSTALL_DIR/certs/seraph-agent-ca.pem</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/dashboard.log</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/dashboard-error.log</string>
</dict>
</plist>
EOF

# Load launch agents (core + dashboard)
launchctl unload "$LAUNCH_AGENT_PATH" 2>/dev/null || true
launchctl unload "$DASHBOARD_LAUNCH_AGENT_PATH" 2>/dev/null || true
launchctl load "$LAUNCH_AGENT_PATH"
launchctl load "$DASHBOARD_LAUNCH_AGENT_PATH"

# Root-level VPN autostart + firewall allowances (best effort).
if [[ $EUID -eq 0 ]]; then
  cat > "$VPN_LAUNCH_DAEMON_PATH" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.seraph.vpn</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>-lc</string>
    <string>wg-quick up metatron-vpn || wg-quick up wg0 || true</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/seraph-vpn.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/seraph-vpn-error.log</string>
</dict>
</plist>
EOF
  chmod 644 "$VPN_LAUNCH_DAEMON_PATH"
  launchctl unload "$VPN_LAUNCH_DAEMON_PATH" 2>/dev/null || true
  launchctl load "$VPN_LAUNCH_DAEMON_PATH" 2>/dev/null || true

  cat > /etc/pf.anchors/com.seraph.agent << 'EOF'
pass in proto tcp from any to any port 3000
pass in proto tcp from any to any port 5000
pass in proto udp from any to any port 51820
EOF
  if ! grep -q "com.seraph.agent" /etc/pf.conf; then
    echo "" >> /etc/pf.conf
    echo "anchor \"com.seraph.agent\"" >> /etc/pf.conf
    echo "load anchor \"com.seraph.agent\" from \"/etc/pf.anchors/com.seraph.agent\"" >> /etc/pf.conf
  fi
  pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
  pfctl -e >/dev/null 2>&1 || true
else
  echo "Skipping root-only VPN/firewall autostart setup on macOS (run installer with sudo to enable)."
fi

echo ""
echo "================================================================"
echo "  INSTALLATION COMPLETE"
echo "================================================================"
echo "Agent installed to: $INSTALL_DIR"
echo "Logs: $INSTALL_DIR/agent.log"
echo "Stop: launchctl unload $LAUNCH_AGENT_PATH"
echo "Start: launchctl load $LAUNCH_AGENT_PATH"
'''
    
    usage = f"curl -sSL {base_url}/api/unified/agent/install-macos | SERAPH_ENROLLMENT_KEY=<ENROLLMENT_KEY> bash"
    if (format or "").lower() == "json":
        return {"script": script, "usage": usage}

    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        content=script,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": "attachment; filename=seraph-agent-install-macos.sh", "X-Install-Usage": usage},
    )


@router.get("/agent/install-android")
async def get_android_install_script(request: Request, server_url: Optional[str] = None, format: Optional[str] = None):
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
pip install psutil requests watchdog aiohttp pyyaml cryptography

# Note: YARA is not available on Termux/Android
# Malware scanning will use alternative methods

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
    
    usage = f"curl -sSL {base_url}/api/unified/agent/install-android | bash"
    if (format or "").lower() == "json":
        return {"script": script, "usage": usage}

    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        content=script,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": "attachment; filename=seraph-agent-install-android.sh", "X-Install-Usage": usage},
    )


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
                "install_command": f"curl -sSL {base_url}/api/unified/agent/install-script | sudo SERAPH_ENROLLMENT_KEY=<ENROLLMENT_KEY> bash",
                "requirements": [
                    "Python 3.8+",
                    "Root access",
                    "systemd",
                    "Dashboard exposed on port 5000",
                    "Firewall rules for 3000/tcp, 5000/tcp, 51820/udp",
                    "WireGuard autostart (if config present)",
                ]
            },
            "windows": {
                "name": "Windows",
                "icon": "🪟",
                "endpoint": f"{base_url}/api/unified/agent/install-windows",
                "install_command": (
                    f"irm {base_url}/api/unified/agent/install-windows | "
                    "powershell -Command \"$env:SERAPH_ENROLLMENT_KEY='<ENROLLMENT_KEY>'; iex ($input | Out-String)\""
                ),
                "requirements": [
                    "Python 3.8+",
                    "Administrator access",
                    "PowerShell 5+",
                    "Dashboard exposed on port 5000",
                    "Firewall rules for 3000/tcp, 5000/tcp, 51820/udp",
                    "System32 launchers (seraph-agent.cmd, seraph-dashboard.cmd, seraph-vpn-start.cmd)",
                    "WireGuard autostart task (if config present)",
                ]
            },
            "macos": {
                "name": "macOS",
                "icon": "🍎",
                "endpoint": f"{base_url}/api/unified/agent/install-macos",
                "install_command": f"curl -sSL {base_url}/api/unified/agent/install-macos | SERAPH_ENROLLMENT_KEY=<ENROLLMENT_KEY> bash",
                "requirements": [
                    "Python 3.8+ (via Homebrew)",
                    "User account",
                    "Dashboard exposed on port 5000",
                    "Root required for VPN launch daemon + pf firewall rules",
                ]
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


@router.get("/agent/bootstrap-manifest")
async def get_agent_bootstrap_manifest(
    request: Request,
    server_url: Optional[str] = None,
    current_user: dict = Depends(check_permission("admin")),
):
    """Return secret-free bootstrap command templates for fleet installs."""
    forwarded_proto = request.headers.get("x-forwarded-proto")
    proto = forwarded_proto or request.url.scheme or "http"
    base_url = server_url or f"{proto}://{request.headers.get('host', 'localhost:8001')}"

    linux_cmd = (
        f"curl -sSL {base_url}/api/unified/agent/install-script | "
        "sudo SERAPH_ENROLLMENT_KEY=<ENROLLMENT_KEY> "
        "[SERAPH_INTEGRATION_TOKEN=<INTEGRATION_TOKEN>] "
        "[SERAPH_CA_CERT_PEM_B64=<BASE64_CA_PEM>] bash"
    )
    windows_cmd = (
        f"irm {base_url}/api/unified/agent/install-windows | "
        "powershell -Command "
        "\"$env:SERAPH_ENROLLMENT_KEY='<ENROLLMENT_KEY>'; "
        "$env:SERAPH_INTEGRATION_TOKEN='<INTEGRATION_TOKEN>'; "
        "$env:SERAPH_CA_CERT_PEM_B64='<BASE64_CA_PEM>'; "
        "iex ($input | Out-String)\""
    )
    macos_cmd = (
        f"curl -sSL {base_url}/api/unified/agent/install-macos | "
        "SERAPH_ENROLLMENT_KEY=<ENROLLMENT_KEY> "
        "[SERAPH_INTEGRATION_TOKEN=<INTEGRATION_TOKEN>] "
        "[SERAPH_CA_CERT_PEM_B64=<BASE64_CA_PEM>] bash"
    )

    return {
        "server_url": base_url,
        "security": {
            "secret_free": True,
            "admin_only": True,
            "required_env": ["SERAPH_ENROLLMENT_KEY"],
            "optional_env": ["SERAPH_INTEGRATION_TOKEN", "SERAPH_CA_CERT_PEM_B64"],
        },
        "dashboard_contract": {
            "canonical_port": 5000,
            "surface": "unified_agent/ui/web/app.py",
            "minimal_ui_disabled": True,
        },
        "platforms": {
            "linux": {
                "script_endpoint": f"{base_url}/api/unified/agent/install-script",
                "command_template": linux_cmd,
            },
            "windows": {
                "script_endpoint": f"{base_url}/api/unified/agent/install-windows",
                "command_template": windows_cmd,
            },
            "macos": {
                "script_endpoint": f"{base_url}/api/unified/agent/install-macos",
                "command_template": macos_cmd,
            },
        },
        "notes": [
            "Replace placeholder values before execution.",
            "Do not publish enrollment or integration tokens in docs or tickets.",
            "Installers provision core agent execution and the substantive dashboard on port 5000.",
            "Installers also apply baseline firewall rules (3000/tcp, 5000/tcp, 51820/udp).",
            "Windows installer installs System32 launchers and a VPN autostart task.",
        ],
        "requested_by": current_user.get("id") if isinstance(current_user, dict) else None,
    }


# ============================================================
# HELPER FUNCTIONS
# ============================================================

async def _process_agent_alert(agent_id: str, alert_data: Dict):
    """Process an alert from an agent"""

    await db.unified_alerts.insert_one(
        _build_unified_alert_doc(
            alert_id=secrets.token_hex(8),
            agent_id=agent_id,
            severity=alert_data.get("severity", "medium"),
            category=alert_data.get("category", "unknown"),
            message=alert_data.get("message", "Unknown alert"),
            details=alert_data.get("details", {}),
            mitre_technique=alert_data.get("mitre_technique"),
            actor=f"agent:{agent_id}",
            reason="alert processed from heartbeat",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
    )
    
    # Update agent alert count
    await db.unified_agents.update_one(
        {"agent_id": agent_id},
        {"$inc": {"alerts_count": 1}}
    )


async def _process_agent_edm_hit(agent_id: str, hit_data: Dict[str, Any], agent_doc: Optional[Dict[str, Any]] = None):
    """Persist EDM hit telemetry for centralized analytics."""
    if not hit_data.get("dataset_id") or not hit_data.get("fingerprint"):
        return

    now = datetime.now(timezone.utc).isoformat()
    path_masked = hit_data.get("file_path_masked")
    if not path_masked and hit_data.get("file_path"):
        raw_path = str(hit_data.get("file_path"))
        path_masked = f".../{os.path.basename(raw_path)}#{hashlib.sha256(raw_path.encode('utf-8')).hexdigest()[:12]}"

    await db[EDM_HITS_COLLECTION].insert_one({
        "agent_id": agent_id,
        "dataset_id": str(hit_data.get("dataset_id")),
        "record_id": hit_data.get("record_id"),
        "fingerprint": str(hit_data.get("fingerprint")),
        "host": hit_data.get("host") or (agent_doc or {}).get("hostname"),
        "process": hit_data.get("process") or "unknown",
        "file_path_masked": path_masked,
        "source": hit_data.get("source") or "unknown",
        "match_confidence": hit_data.get("match_confidence"),
        "match_candidate_type": hit_data.get("match_candidate_type"),
        "match_variant_type": hit_data.get("match_variant_type"),
        "agent_platform": (agent_doc or {}).get("platform"),
        "timestamp": hit_data.get("timestamp") or now,
        "ingested_at": now,
    })

    await db.unified_agents.update_one(
        {"agent_id": agent_id},
        {
            "$inc": {"edm_hits_count": 1},
            "$set": {"edm_last_hit_at": now},
        },
    )


async def _execute_rollout_rollback(rollout: Dict[str, Any], reason: str, triggered_by: str) -> Dict[str, Any]:
    dataset_id = rollout.get("dataset_id")
    rollback_version = rollout.get("previous_version")
    applied_ids = rollout.get("applied_agent_ids") or []

    if rollback_version is None:
        return {"rolled_back": False, "reason": "No previous_version available"}

    doc = await db[EDM_DATASET_COLLECTION].find_one(
        {"dataset_id": dataset_id, "version": int(rollback_version)},
        {"_id": 0},
    )
    if not doc:
        return {"rolled_back": False, "reason": "Rollback dataset version not found"}

    targets = EDMBulkTargetModel(agent_ids=applied_ids, online_only=False)
    fanout = await _dispatch_edm_dataset_to_targets(
        dataset=doc.get("dataset", {}),
        edm_meta=_build_edm_meta(doc),
        targets=targets,
        priority="critical",
        issued_by=triggered_by,
    )

    finalize = await db[EDM_ROLLOUT_COLLECTION].update_one(
        {
            "rollout_id": rollout.get("rollout_id"),
            "status": {"$in": ["active", "completed", "rolling_back"]},
        },
        {
            "$set": {
                "status": "rolled_back",
                "rolled_back_at": datetime.now(timezone.utc).isoformat(),
                "rollback_reason": reason,
                "rollback_triggered_by": triggered_by,
                "rollback_version": rollback_version,
                "rollback_fanout": fanout,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
            "$inc": {"state_version": 1},
            "$push": {
                "state_transition_log": {
                    "from_status": ["active", "completed", "rolling_back"],
                    "to_status": "rolled_back",
                    "actor": triggered_by,
                    "reason": reason,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "metadata": {"rollback_version": rollback_version},
                }
            },
        },
    )
    if getattr(finalize, "matched_count", 0) == 0:
        existing = await db[EDM_ROLLOUT_COLLECTION].find_one(
            {"rollout_id": rollout.get("rollout_id")},
            {"_id": 0, "status": 1, "rollback_version": 1, "rollback_fanout": 1},
        )
        if existing and existing.get("status") == "rolled_back":
            return {
                "rolled_back": True,
                "rollback_version": existing.get("rollback_version", rollback_version),
                "fanout": existing.get("rollback_fanout", fanout),
            }
        return {"rolled_back": False, "reason": "Rollout state changed during rollback finalize"}
    return {"rolled_back": True, "rollback_version": rollback_version, "fanout": fanout}


async def _evaluate_active_edm_rollouts(agent_id: str):
    """Evaluate anomaly rate spikes for active EDM rollouts and auto-rollback when needed."""
    await _ensure_edm_indexes()
    active_rollouts = await db[EDM_ROLLOUT_COLLECTION].find(
        {
            "status": "active",
            "applied_agent_ids": {"$in": [agent_id]},
            "policy.auto_rollback": True,
        },
        {"_id": 0},
    ).to_list(100)

    for rollout in active_rollouts:
        readiness = await _compute_rollout_readiness(rollout)
        if not readiness.get("has_spike"):
            continue

        reason = (
            "Anomaly spike detected: "
            f"cohort_rate={readiness['cohort']['rate_per_agent_min']:.4f}/agent/min "
            f"control_rate={readiness['control']['rate_per_agent_min']:.4f}/agent/min "
            f"threshold={readiness['threshold']['rate_per_agent_min']:.4f}"
        )
        try:
            claimed = await _claim_rollout_for_rollback(
                rollout_id=rollout.get("rollout_id"),
                reason=reason,
                requested_by="system:auto-rollback",
                allowed_statuses=["active"],
            )
        except HTTPException:
            # Another worker likely claimed or transitioned this rollout.
            continue

        rollback = await _execute_rollout_rollback(claimed, reason, "system:auto-rollback")
        logger.warning(
            "EDM rollout auto-rollback executed for %s: %s (result=%s)",
            rollout.get("rollout_id"),
            reason,
            rollback,
        )


async def _hunt_telemetry(telemetry: Dict):
    """Run threat hunting on telemetry data"""
    try:
        from services.threat_hunting import threat_hunting_engine
        from dataclasses import asdict
        threat_hunting_engine.set_db(db)
        
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
        await _transition_unified_deployment_state(
            deployment_id=deployment["deployment_id"],
            expected_statuses=["pending", "processing", "queued", "running"],
            next_status="completed",
            extra_updates={
                "simulated": simulated,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            },
            deployment_task_id=task_id,
            transition_reason="task reached deployed",
        )
    elif task_status == "failed" and current_status != "failed":
        await _transition_unified_deployment_state(
            deployment_id=deployment["deployment_id"],
            expected_statuses=["pending", "processing", "queued", "running"],
            next_status="failed",
            extra_updates={
                "error": error_message or "Deployment failed",
                "failed_at": datetime.now(timezone.utc).isoformat(),
            },
            deployment_task_id=task_id,
            transition_reason="task reached failed",
        )
    elif task_status in {"pending", "deploying"} and current_status not in {"running", "queued"}:
        await _transition_unified_deployment_state(
            deployment_id=deployment["deployment_id"],
            expected_statuses=["pending", "processing", "queued"],
            next_status="running",
            extra_updates={"last_checked_at": datetime.now(timezone.utc).isoformat()},
            deployment_task_id=task_id,
            transition_reason="task in progress",
        )


async def _process_deployment(deployment_id: str, deployment: DeploymentRequestModel):
    """Process a deployment in the background"""
    
    try:
        claimed = await _transition_unified_deployment_state(
            deployment_id=deployment_id,
            expected_statuses=["pending"],
            next_status="processing",
            extra_updates={"started_at": datetime.now(timezone.utc).isoformat()},
            transition_actor="system:deployment-worker",
            transition_reason="deployment worker claimed job",
        )
        if not claimed:
            logger.warning("Deployment %s was already claimed or transitioned by another worker", deployment_id)
            return

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

        claimed_queue = await _transition_unified_deployment_state(
            deployment_id=deployment_id,
            expected_statuses=["processing"],
            next_status="queued",
            extra_updates={
                "deployment_task_id": task_id,
                "queued_at": datetime.now(timezone.utc).isoformat(),
            },
            transition_actor="system:deployment-worker",
            transition_reason="deployment task queued",
            transition_metadata={"deployment_task_id": task_id},
        )
        if not claimed_queue:
            logger.warning("Deployment %s queue transition lost due to concurrent update", deployment_id)
            return

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
            await _transition_unified_deployment_state(
                deployment_id=deployment_id,
                expected_statuses=["queued", "running", "processing"],
                next_status="completed",
                extra_updates={
                    "simulated": simulated,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                },
                deployment_task_id=task_id,
                transition_actor="system:deployment-worker",
                transition_reason="deployment task completed",
                transition_metadata={"deployment_task_id": task_id, "simulated": simulated},
            )
            logger.info(f"Deployment {deployment_id} completed (task={task_id}, simulated={simulated})")
        elif final_status == "failed":
            await _transition_unified_deployment_state(
                deployment_id=deployment_id,
                expected_statuses=["queued", "running", "processing"],
                next_status="failed",
                extra_updates={
                    "error": error_message or "Deployment failed",
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                },
                deployment_task_id=task_id,
                transition_actor="system:deployment-worker",
                transition_reason="deployment task failed",
                transition_metadata={"deployment_task_id": task_id},
            )
            logger.error(f"Deployment {deployment_id} failed (task={task_id}): {error_message}")
        else:
            await _transition_unified_deployment_state(
                deployment_id=deployment_id,
                expected_statuses=["queued", "processing"],
                next_status="running",
                extra_updates={
                    "deployment_task_id": task_id,
                    "last_checked_at": datetime.now(timezone.utc).isoformat(),
                },
                deployment_task_id=task_id,
                transition_actor="system:deployment-worker",
                transition_reason="deployment task still running",
                transition_metadata={"deployment_task_id": task_id},
            )
            logger.info(f"Deployment {deployment_id} still running (task={task_id})")
        
    except Exception as e:
        await _transition_unified_deployment_state(
            deployment_id=deployment_id,
            expected_statuses=["pending", "processing", "queued", "running"],
            next_status="failed",
            extra_updates={
                "error": str(e),
                "failed_at": datetime.now(timezone.utc).isoformat(),
            },
            transition_actor="system:deployment-worker",
            transition_reason="deployment worker exception",
            transition_metadata={"exception": str(e)},
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
        "memory", "app_whitelist", "dlp", "vulnerability", "yara", "amsi"
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
            "yara_matches": {"$sum": {"$ifNull": ["$monitors_summary.yara.match_count", 0]}},
            "yara_files_scanned": {"$sum": {"$ifNull": ["$monitors_summary.yara.files_scanned", 0]}},
            "yara_scans": {"$sum": {"$ifNull": ["$monitors_summary.yara.scan_count", 0]}},
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
            "yara_matches": stats.get("yara_matches", 0),
            "yara_files_scanned": stats.get("yara_files_scanned", 0),
            "yara_scans": stats.get("yara_scans", 0),
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
            "memory", "app_whitelist", "dlp", "vulnerability", "yara", "amsi",
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
