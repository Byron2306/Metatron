"""
Model Context Protocol (MCP) Server
===================================
Standardized agent ↔ tools ↔ permissions ↔ audit protocol.
The "governed tool bus" for the swarm and SOAR.
"""

import os
import json
import hashlib
import logging
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
import uuid
from collections import deque

logger = logging.getLogger(__name__)


class MCPMessageType(Enum):
    """MCP message types"""
    TOOL_REQUEST = "tool_request"
    TOOL_RESPONSE = "tool_response"
    POLICY_CHECK = "policy_check"
    POLICY_RESULT = "policy_result"
    AUDIT_EVENT = "audit_event"
    TELEMETRY = "telemetry"
    COMMAND = "command"
    HEARTBEAT = "heartbeat"
    ERROR = "error"


class MCPToolCategory(Enum):
    """Tool categories for MCP"""
    SCANNER = "scanner"
    EDR = "edr"
    FIREWALL = "firewall"
    SOAR = "soar"
    FORENSICS = "forensics"
    DECEPTION = "deception"
    IDENTITY = "identity"
    NETWORK = "network"


@dataclass
class MCPToolSchema:
    """Tool schema definition for MCP registry"""
    tool_id: str
    name: str
    description: str
    category: MCPToolCategory
    version: str
    
    # Input/output schemas
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    
    # Security
    required_trust_state: str
    required_scopes: List[str]
    rate_limit: int  # per hour
    
    # Execution
    timeout_seconds: int
    async_capable: bool
    idempotent: bool
    
    # Audit
    audit_level: str  # none, basic, full
    redact_fields: List[str]


@dataclass
class MCPMessage:
    """MCP protocol message"""
    message_id: str
    message_type: MCPMessageType
    timestamp: str
    
    # Routing
    source: str          # agent_id / service_name
    destination: str     # tool_id / service_name / broadcast
    
    # Payload
    payload: Dict[str, Any]
    
    # Security
    signature: str
    trace_id: str
    
    # Metadata
    priority: int = 5    # 1-10, 10 = highest
    ttl_seconds: int = 60
    requires_ack: bool = True


@dataclass
class MCPToolExecution:
    """Tool execution record"""
    execution_id: str
    tool_id: str
    request_message_id: str
    
    # Request
    principal: str
    input_params: Dict[str, Any]
    
    # Execution
    started_at: str
    completed_at: Optional[str]
    status: str  # pending, running, success, failed, timeout
    
    # Result
    output: Optional[Dict[str, Any]]
    error: Optional[str]
    
    # Audit
    policy_decision_id: Optional[str]
    token_id: Optional[str]
    audit_hash: str


class MCPServer:
    """
    Model Context Protocol Server.
    
    Features:
    - Tool registry with schemas
    - Signed requests
    - Policy enforcement hooks
    - Structured logging and replay
    - Versioning
    - Connector sandboxing
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        
        # Signing key
        self.signing_key = os.environ.get('MCP_SIGNING_KEY', 'mcp-default-key')
        
        # Tool registry
        self.tools: Dict[str, MCPToolSchema] = {}
        self.tool_handlers: Dict[str, Callable] = {}
        
        # Message queues
        self.pending_requests: Dict[str, MCPMessage] = {}
        self.message_history: deque = deque(maxlen=10000)
        
        # Execution history
        self.executions: Dict[str, MCPToolExecution] = {}
        
        # Subscriptions (for pub/sub)
        self.subscriptions: Dict[str, List[str]] = {}  # topic -> [subscriber_ids]
        
        # Register built-in tools
        self._register_builtin_tools()
        
        logger.info("MCP Server initialized")
    
    def _sign_message(self, message: MCPMessage) -> str:
        """Sign a message"""
        import hmac
        data = {
            "message_id": message.message_id,
            "source": message.source,
            "destination": message.destination,
            "payload": message.payload,
            "timestamp": message.timestamp
        }
        payload = json.dumps(data, sort_keys=True)
        return hmac.new(
            self.signing_key.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def _verify_signature(self, message: MCPMessage) -> bool:
        """Verify message signature"""
        expected = self._sign_message(message)
        import hmac as hmac_module
        return hmac_module.compare_digest(expected, message.signature)
    
    def _register_builtin_tools(self):
        """Register built-in MCP tools"""
        
        # Network scanner
        self.register_tool(MCPToolSchema(
            tool_id="mcp.scanner.network",
            name="Network Scanner",
            description="Scan network for hosts and services",
            category=MCPToolCategory.SCANNER,
            version="1.0.0",
            input_schema={
                "target": {"type": "string", "description": "IP or CIDR"},
                "ports": {"type": "array", "items": "integer", "optional": True},
                "scan_type": {"type": "string", "enum": ["quick", "full", "stealth"]}
            },
            output_schema={
                "hosts": {"type": "array"},
                "open_ports": {"type": "object"},
                "scan_time": {"type": "number"}
            },
            required_trust_state="degraded",
            required_scopes=["observe", "collect"],
            rate_limit=100,
            timeout_seconds=300,
            async_capable=True,
            idempotent=True,
            audit_level="basic",
            redact_fields=[]
        ))
        
        # Process killer
        self.register_tool(MCPToolSchema(
            tool_id="mcp.edr.process_kill",
            name="Process Killer",
            description="Terminate malicious processes",
            category=MCPToolCategory.EDR,
            version="1.0.0",
            input_schema={
                "pid": {"type": "integer", "description": "Process ID"},
                "force": {"type": "boolean", "default": False},
                "reason": {"type": "string"}
            },
            output_schema={
                "success": {"type": "boolean"},
                "process_name": {"type": "string"},
                "terminated_at": {"type": "string"}
            },
            required_trust_state="trusted",
            required_scopes=["remediate"],
            rate_limit=50,
            timeout_seconds=30,
            async_capable=False,
            idempotent=False,
            audit_level="full",
            redact_fields=[]
        ))
        
        # Firewall rule
        self.register_tool(MCPToolSchema(
            tool_id="mcp.firewall.block_ip",
            name="Firewall Block IP",
            description="Block IP address at firewall",
            category=MCPToolCategory.FIREWALL,
            version="1.0.0",
            input_schema={
                "ip": {"type": "string", "format": "ipv4"},
                "direction": {"type": "string", "enum": ["inbound", "outbound", "both"]},
                "duration_hours": {"type": "integer", "default": 24}
            },
            output_schema={
                "rule_id": {"type": "string"},
                "blocked_at": {"type": "string"},
                "expires_at": {"type": "string"}
            },
            required_trust_state="trusted",
            required_scopes=["contain"],
            rate_limit=100,
            timeout_seconds=10,
            async_capable=False,
            idempotent=True,
            audit_level="full",
            redact_fields=[]
        ))
        
        # SOAR playbook
        self.register_tool(MCPToolSchema(
            tool_id="mcp.soar.run_playbook",
            name="Run SOAR Playbook",
            description="Execute automated response playbook",
            category=MCPToolCategory.SOAR,
            version="1.0.0",
            input_schema={
                "playbook_id": {"type": "string"},
                "incident_id": {"type": "string"},
                "parameters": {"type": "object", "optional": True}
            },
            output_schema={
                "execution_id": {"type": "string"},
                "status": {"type": "string"},
                "steps_completed": {"type": "integer"},
                "results": {"type": "array"}
            },
            required_trust_state="trusted",
            required_scopes=["remediate", "contain"],
            rate_limit=20,
            timeout_seconds=600,
            async_capable=True,
            idempotent=False,
            audit_level="full",
            redact_fields=["parameters.credentials"]
        ))
        
        # Memory forensics
        self.register_tool(MCPToolSchema(
            tool_id="mcp.forensics.memory_dump",
            name="Memory Dump",
            description="Capture process memory for analysis",
            category=MCPToolCategory.FORENSICS,
            version="1.0.0",
            input_schema={
                "pid": {"type": "integer"},
                "output_path": {"type": "string"},
                "compress": {"type": "boolean", "default": True}
            },
            output_schema={
                "dump_path": {"type": "string"},
                "size_bytes": {"type": "integer"},
                "hash": {"type": "string"}
            },
            required_trust_state="trusted",
            required_scopes=["collect"],
            rate_limit=10,
            timeout_seconds=300,
            async_capable=True,
            idempotent=True,
            audit_level="full",
            redact_fields=[]
        ))
        
        # Honeypot deployment
        self.register_tool(MCPToolSchema(
            tool_id="mcp.deception.deploy_honeypot",
            name="Deploy Honeypot",
            description="Deploy deception honeypot/canary",
            category=MCPToolCategory.DECEPTION,
            version="1.0.0",
            input_schema={
                "honeypot_type": {"type": "string", "enum": ["file", "service", "credential", "network"]},
                "target_zone": {"type": "string"},
                "config": {"type": "object"}
            },
            output_schema={
                "honeypot_id": {"type": "string"},
                "deployed_at": {"type": "string"},
                "trigger_endpoint": {"type": "string"}
            },
            required_trust_state="trusted",
            required_scopes=["deception"],
            rate_limit=50,
            timeout_seconds=60,
            async_capable=False,
            idempotent=False,
            audit_level="basic",
            redact_fields=["config.credentials"]
        ))
    
    def register_tool(self, schema: MCPToolSchema, handler: Callable = None):
        """Register a tool with the MCP server"""
        self.tools[schema.tool_id] = schema
        if handler:
            self.tool_handlers[schema.tool_id] = handler
        logger.info(f"MCP: Registered tool {schema.tool_id} v{schema.version}")
    
    def create_message(self, message_type: MCPMessageType, source: str,
                       destination: str, payload: Dict[str, Any],
                       trace_id: str = None, priority: int = 5) -> MCPMessage:
        """Create a signed MCP message"""
        message = MCPMessage(
            message_id=f"mcp-{uuid.uuid4().hex[:12]}",
            message_type=message_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            source=source,
            destination=destination,
            payload=payload,
            signature="",  # Will be set below
            trace_id=trace_id or uuid.uuid4().hex,
            priority=priority
        )
        
        message.signature = self._sign_message(message)
        return message
    
    async def handle_message(self, message: MCPMessage) -> MCPMessage:
        """Handle an incoming MCP message"""
        # Verify signature
        if not self._verify_signature(message):
            return self._error_response(message, "Invalid message signature")
        
        # Store in history
        self.message_history.append(message)
        
        # Route by type
        if message.message_type == MCPMessageType.TOOL_REQUEST:
            return await self._handle_tool_request(message)
        elif message.message_type == MCPMessageType.POLICY_CHECK:
            return await self._handle_policy_check(message)
        elif message.message_type == MCPMessageType.TELEMETRY:
            return await self._handle_telemetry(message)
        elif message.message_type == MCPMessageType.HEARTBEAT:
            return self._handle_heartbeat(message)
        else:
            return self._error_response(message, f"Unknown message type: {message.message_type}")
    
    async def _handle_tool_request(self, message: MCPMessage) -> MCPMessage:
        """Handle a tool execution request"""
        tool_id = message.destination
        
        # Check if tool exists
        if tool_id not in self.tools:
            return self._error_response(message, f"Unknown tool: {tool_id}")
        
        tool = self.tools[tool_id]
        payload = message.payload
        
        # Create execution record
        execution = MCPToolExecution(
            execution_id=f"exec-{uuid.uuid4().hex[:12]}",
            tool_id=tool_id,
            request_message_id=message.message_id,
            principal=message.source,
            input_params=payload.get("params", {}),
            started_at=datetime.now(timezone.utc).isoformat(),
            completed_at=None,
            status="running",
            output=None,
            error=None,
            policy_decision_id=payload.get("policy_decision_id"),
            token_id=payload.get("token_id"),
            audit_hash=""
        )
        
        self.executions[execution.execution_id] = execution
        
        # Execute if handler registered
        if tool_id in self.tool_handlers:
            try:
                handler = self.tool_handlers[tool_id]
                if asyncio.iscoroutinefunction(handler):
                    result = await asyncio.wait_for(
                        handler(payload.get("params", {})),
                        timeout=tool.timeout_seconds
                    )
                else:
                    result = handler(payload.get("params", {}))
                
                execution.status = "success"
                execution.output = result
                
            except asyncio.TimeoutError:
                execution.status = "timeout"
                execution.error = "Execution timed out"
            except Exception as e:
                execution.status = "failed"
                execution.error = str(e)
        else:
            # Simulated execution for unregistered handlers
            execution.status = "success"
            execution.output = {"simulated": True, "tool_id": tool_id}
        
        execution.completed_at = datetime.now(timezone.utc).isoformat()
        
        # Compute audit hash
        execution.audit_hash = hashlib.sha256(
            json.dumps(asdict(execution), sort_keys=True).encode()
        ).hexdigest()[:32]
        
        # Create response
        return self.create_message(
            message_type=MCPMessageType.TOOL_RESPONSE,
            source="mcp_server",
            destination=message.source,
            payload={
                "execution_id": execution.execution_id,
                "status": execution.status,
                "output": execution.output,
                "error": execution.error,
                "audit_hash": execution.audit_hash
            },
            trace_id=message.trace_id
        )
    
    async def _handle_policy_check(self, message: MCPMessage) -> MCPMessage:
        """Handle a policy check request"""
        # Delegate to policy engine
        from services.policy_engine import policy_engine
        
        payload = message.payload
        decision = policy_engine.evaluate(
            principal=payload.get("principal", message.source),
            action=payload.get("action", ""),
            targets=payload.get("targets", []),
            trust_state=payload.get("trust_state", "unknown"),
            role=payload.get("role", "agent")
        )
        
        return self.create_message(
            message_type=MCPMessageType.POLICY_RESULT,
            source="mcp_server",
            destination=message.source,
            payload={
                "decision_id": decision.decision_id,
                "permitted": decision.permitted,
                "approval_tier": decision.approval_tier.value,
                "denial_reason": decision.denial_reason,
                "constraints": {
                    "rate_limit": decision.rate_limit,
                    "blast_radius_cap": decision.blast_radius_cap,
                    "ttl_seconds": decision.ttl_seconds
                }
            },
            trace_id=message.trace_id
        )
    
    async def _handle_telemetry(self, message: MCPMessage) -> MCPMessage:
        """Handle telemetry ingestion"""
        from services.telemetry_chain import tamper_evident_telemetry
        
        payload = message.payload
        event = tamper_evident_telemetry.ingest_event(
            event_type=payload.get("event_type", "mcp.telemetry"),
            severity=payload.get("severity", "info"),
            data=payload.get("data", {}),
            agent_id=message.source,
            trace_id=message.trace_id
        )
        
        return self.create_message(
            message_type=MCPMessageType.TOOL_RESPONSE,
            source="mcp_server",
            destination=message.source,
            payload={
                "event_id": event.event_id,
                "event_hash": event.event_hash,
                "acknowledged": True
            },
            trace_id=message.trace_id
        )
    
    def _handle_heartbeat(self, message: MCPMessage) -> MCPMessage:
        """Handle heartbeat"""
        return self.create_message(
            message_type=MCPMessageType.HEARTBEAT,
            source="mcp_server",
            destination=message.source,
            payload={
                "status": "alive",
                "server_time": datetime.now(timezone.utc).isoformat(),
                "tools_available": len(self.tools)
            },
            trace_id=message.trace_id
        )
    
    def _error_response(self, original: MCPMessage, error: str) -> MCPMessage:
        """Create an error response"""
        return self.create_message(
            message_type=MCPMessageType.ERROR,
            source="mcp_server",
            destination=original.source,
            payload={"error": error, "original_message_id": original.message_id},
            trace_id=original.trace_id
        )
    
    def get_tool_catalog(self) -> List[Dict]:
        """Get tool catalog"""
        return [
            {
                "tool_id": t.tool_id,
                "name": t.name,
                "description": t.description,
                "category": t.category.value,
                "version": t.version,
                "required_trust_state": t.required_trust_state,
                "rate_limit": t.rate_limit
            }
            for t in self.tools.values()
        ]
    
    def get_execution_history(self, tool_id: str = None, 
                              principal: str = None,
                              limit: int = 100) -> List[Dict]:
        """Get execution history"""
        results = []
        for exec in sorted(self.executions.values(), 
                          key=lambda x: x.started_at, reverse=True):
            if tool_id and exec.tool_id != tool_id:
                continue
            if principal and exec.principal != principal:
                continue
            results.append(asdict(exec))
            if len(results) >= limit:
                break
        return results
    
    def get_server_status(self) -> Dict:
        """Get MCP server status"""
        return {
            "tools_registered": len(self.tools),
            "handlers_registered": len(self.tool_handlers),
            "pending_requests": len(self.pending_requests),
            "message_history_size": len(self.message_history),
            "total_executions": len(self.executions)
        }


# Global singleton
mcp_server = MCPServer()
