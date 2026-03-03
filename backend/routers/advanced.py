"""
Advanced Security Router
========================
API endpoints for advanced security features:
- MCP Server
- Vector Memory
- VNS (Virtual Network Sensor)
- Quantum Security
- AI Reasoning
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from datetime import datetime, timezone

from .dependencies import get_current_user, check_permission

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/advanced", tags=["Advanced Security"])


# =============================================================================
# MODELS
# =============================================================================

class MCPToolRequest(BaseModel):
    tool_id: str
    params: Dict[str, Any]
    trace_id: Optional[str] = None


class MemoryStoreRequest(BaseModel):
    content: str
    namespace: str = "observations"
    structured_data: Optional[Dict[str, Any]] = None
    source: str = "api"
    trust_level: str = "low"
    confidence: float = 0.5
    ttl_days: Optional[int] = None


class MemorySearchRequest(BaseModel):
    query: str
    namespace: Optional[str] = None
    top_k: int = 10
    min_confidence: float = 0.0


class IncidentCaseRequest(BaseModel):
    title: str
    symptoms: List[Dict[str, Any]]
    indicators: List[str]
    affected_hosts: List[str]
    confidence: float = 0.5


class FlowRecordRequest(BaseModel):
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"
    bytes_sent: int = 0
    bytes_recv: int = 0
    ja3_hash: Optional[str] = None
    sni: Optional[str] = None


class DNSQueryRequest(BaseModel):
    src_ip: str
    query_name: str
    query_type: str = "A"
    response_code: str = "NOERROR"
    response_ips: List[str] = []


class ThreatAnalysisRequest(BaseModel):
    title: str
    description: str
    source: Optional[str] = None
    indicators: List[str] = []
    process_name: Optional[str] = None
    command_line: Optional[str] = None


class AIQueryRequest(BaseModel):
    question: str
    context: Optional[Dict[str, Any]] = None


# =============================================================================
# MCP SERVER ENDPOINTS
# =============================================================================

@router.get("/mcp/tools")
async def list_mcp_tools(current_user: dict = Depends(get_current_user)):
    """List available MCP tools"""
    from services.mcp_server import mcp_server
    return {"tools": mcp_server.get_tool_catalog()}


@router.get("/mcp/tools/{tool_id}")
async def get_mcp_tool(tool_id: str, current_user: dict = Depends(get_current_user)):
    """Get MCP tool details"""
    from services.mcp_server import mcp_server
    
    if tool_id not in mcp_server.tools:
        raise HTTPException(status_code=404, detail="Tool not found")
    
    tool = mcp_server.tools[tool_id]
    return {
        "tool_id": tool.tool_id,
        "name": tool.name,
        "description": tool.description,
        "category": tool.category.value,
        "version": tool.version,
        "input_schema": tool.input_schema,
        "output_schema": tool.output_schema,
        "required_trust_state": tool.required_trust_state,
        "rate_limit": tool.rate_limit
    }


@router.post("/mcp/execute")
async def execute_mcp_tool(
    request: MCPToolRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Execute an MCP tool"""
    from services.mcp_server import mcp_server, MCPMessageType
    import asyncio
    
    # Create MCP message
    message = mcp_server.create_message(
        message_type=MCPMessageType.TOOL_REQUEST,
        source=f"operator:{current_user.get('email', 'unknown')}",
        destination=request.tool_id,
        payload={"params": request.params},
        trace_id=request.trace_id
    )
    
    # Execute
    response = await mcp_server.handle_message(message)
    
    return {
        "message_id": response.message_id,
        "status": response.payload.get("status"),
        "output": response.payload.get("output"),
        "error": response.payload.get("error"),
        "execution_id": response.payload.get("execution_id")
    }


@router.get("/mcp/history")
async def get_mcp_history(
    tool_id: str = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get MCP execution history"""
    from services.mcp_server import mcp_server
    return {"executions": mcp_server.get_execution_history(tool_id=tool_id, limit=limit)}


@router.get("/mcp/status")
async def get_mcp_status(current_user: dict = Depends(get_current_user)):
    """Get MCP server status"""
    from services.mcp_server import mcp_server
    return mcp_server.get_server_status()


# =============================================================================
# VECTOR MEMORY ENDPOINTS
# =============================================================================

@router.post("/memory/store")
async def store_memory(
    request: MemoryStoreRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Store a memory entry"""
    from services.vector_memory import vector_memory, MemoryNamespace, TrustLevel
    
    namespace = MemoryNamespace(request.namespace)
    trust_level = TrustLevel(request.trust_level)
    
    entry = vector_memory.store(
        content=request.content,
        namespace=namespace,
        structured_data=request.structured_data,
        source=request.source,
        source_type="api",
        created_by=current_user.get("email", "unknown"),
        trust_level=trust_level,
        confidence=request.confidence,
        ttl_days=request.ttl_days
    )
    
    return {
        "entry_id": entry.entry_id,
        "namespace": entry.namespace.value,
        "trust_level": entry.trust_level.value
    }


@router.post("/memory/search")
async def search_memory(
    request: MemorySearchRequest,
    current_user: dict = Depends(get_current_user)
):
    """Search memory by semantic similarity"""
    from services.vector_memory import vector_memory, MemoryNamespace
    
    namespace = MemoryNamespace(request.namespace) if request.namespace else None
    
    results = vector_memory.retrieve(
        query=request.query,
        namespace=namespace,
        top_k=request.top_k,
        min_confidence=request.min_confidence
    )
    
    return {
        "results": [
            {
                "entry_id": entry.entry_id,
                "content": entry.content[:500],
                "namespace": entry.namespace.value,
                "trust_level": entry.trust_level.value,
                "confidence": entry.confidence,
                "similarity": score,
                "source": entry.source
            }
            for entry, score in results
        ],
        "count": len(results)
    }


@router.post("/memory/case")
async def create_incident_case(
    request: IncidentCaseRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Create an incident case"""
    from services.vector_memory import vector_memory
    
    case = vector_memory.create_case(
        title=request.title,
        symptoms=request.symptoms,
        indicators=request.indicators,
        affected_hosts=request.affected_hosts,
        created_by=current_user.get("email", "unknown"),
        confidence=request.confidence
    )
    
    return {
        "case_id": case.case_id,
        "title": case.title,
        "status": case.status
    }


@router.post("/memory/case/{case_id}/similar")
async def find_similar_cases(
    case_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Find similar historical cases"""
    from services.vector_memory import vector_memory
    
    case = vector_memory.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    similar = vector_memory.find_similar_cases(
        symptoms=case.symptoms,
        indicators=case.indicators
    )
    
    return {
        "similar_cases": [
            {
                "case_id": c.case_id,
                "title": c.title,
                "status": c.status,
                "root_cause": c.root_cause,
                "similarity": score
            }
            for c, score in similar
        ]
    }


@router.get("/memory/stats")
async def get_memory_stats(current_user: dict = Depends(get_current_user)):
    """Get memory database statistics"""
    from services.vector_memory import vector_memory
    return vector_memory.get_memory_stats()


# =============================================================================
# VNS (VIRTUAL NETWORK SENSOR) ENDPOINTS
# =============================================================================

@router.post("/vns/flow")
async def record_network_flow(
    request: FlowRecordRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Record a network flow"""
    from services.vns import vns
    
    flow = vns.record_flow(
        src_ip=request.src_ip,
        src_port=request.src_port,
        dst_ip=request.dst_ip,
        dst_port=request.dst_port,
        protocol=request.protocol,
        bytes_sent=request.bytes_sent,
        bytes_recv=request.bytes_recv,
        ja3_hash=request.ja3_hash,
        sni=request.sni
    )
    
    return {
        "flow_id": flow.flow_id,
        "direction": flow.direction.value,
        "status": flow.status.value,
        "threat_score": flow.threat_score,
        "threat_indicators": flow.threat_indicators
    }


@router.post("/vns/dns")
async def record_dns_query(
    request: DNSQueryRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Record a DNS query"""
    from services.vns import vns
    
    query = vns.record_dns_query(
        src_ip=request.src_ip,
        query_name=request.query_name,
        query_type=request.query_type,
        response_code=request.response_code,
        response_ips=request.response_ips
    )
    
    return {
        "query_id": query.query_id,
        "is_suspicious": query.is_suspicious,
        "threat_indicators": query.threat_indicators
    }


@router.get("/vns/flows")
async def get_network_flows(
    src_ip: str = None,
    dst_ip: str = None,
    suspicious_only: bool = False,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Query network flows"""
    from services.vns import vns
    
    flows = vns.get_flows(
        src_ip=src_ip,
        dst_ip=dst_ip,
        suspicious_only=suspicious_only,
        limit=limit
    )
    
    return {"flows": flows, "count": len(flows)}


@router.get("/vns/dns")
async def get_dns_queries(
    src_ip: str = None,
    domain: str = None,
    suspicious_only: bool = False,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Query DNS queries"""
    from services.vns import vns
    
    queries = vns.get_dns_queries(
        src_ip=src_ip,
        domain=domain,
        suspicious_only=suspicious_only,
        limit=limit
    )
    
    return {"queries": queries, "count": len(queries)}


@router.get("/vns/beacons")
async def get_beacon_detections(
    confirmed_only: bool = False,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get C2 beacon detections"""
    from services.vns import vns
    
    beacons = vns.get_beacon_detections(confirmed_only=confirmed_only, limit=limit)
    return {"beacons": beacons, "count": len(beacons)}


@router.post("/vns/canary/ip")
async def add_canary_ip(
    ip: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Add a canary IP"""
    from services.vns import vns
    vns.add_canary_ip(ip)
    return {"status": "added", "canary_ip": ip}


@router.post("/vns/canary/domain")
async def add_canary_domain(
    domain: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Add a canary domain"""
    from services.vns import vns
    vns.add_canary_domain(domain)
    return {"status": "added", "canary_domain": domain}


@router.post("/vns/validate")
async def validate_endpoint_telemetry(
    endpoint_ip: str,
    endpoint_flows: List[Dict[str, Any]],
    current_user: dict = Depends(get_current_user)
):
    """Validate endpoint telemetry against VNS"""
    from services.vns import vns
    
    result = vns.validate_endpoint_telemetry(endpoint_ip, endpoint_flows)
    return result


@router.get("/vns/stats")
async def get_vns_stats(current_user: dict = Depends(get_current_user)):
    """Get VNS statistics"""
    from services.vns import vns
    return vns.get_vns_stats()


# =============================================================================
# QUANTUM SECURITY ENDPOINTS
# =============================================================================

@router.post("/quantum/keypair/kyber")
async def generate_kyber_keypair(
    key_id: str = None,
    security_level: int = 768,
    current_user: dict = Depends(check_permission("write"))
):
    """Generate a Kyber key pair (post-quantum KEM)"""
    from services.quantum_security import quantum_security
    
    keypair = quantum_security.generate_kyber_keypair(key_id, security_level)
    
    return {
        "key_id": keypair.key_id,
        "algorithm": keypair.algorithm,
        "public_key": keypair.public_key,
        "expires_at": keypair.expires_at
    }


@router.post("/quantum/keypair/dilithium")
async def generate_dilithium_keypair(
    key_id: str = None,
    security_level: int = 3,
    current_user: dict = Depends(check_permission("write"))
):
    """Generate a Dilithium key pair (post-quantum signatures)"""
    from services.quantum_security import quantum_security
    
    keypair = quantum_security.generate_dilithium_keypair(key_id, security_level)
    
    return {
        "key_id": keypair.key_id,
        "algorithm": keypair.algorithm,
        "public_key": keypair.public_key,
        "expires_at": keypair.expires_at
    }


@router.post("/quantum/encrypt")
async def quantum_hybrid_encrypt(
    plaintext: str,
    recipient_public_key: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Hybrid encrypt (Kyber + AES-GCM)"""
    from services.quantum_security import quantum_security
    
    encrypted = quantum_security.hybrid_encrypt(
        plaintext.encode(),
        recipient_public_key
    )
    
    return encrypted


@router.post("/quantum/decrypt")
async def quantum_hybrid_decrypt(
    key_id: str,
    encrypted_data: Dict[str, str],
    current_user: dict = Depends(check_permission("write"))
):
    """Hybrid decrypt (Kyber + AES-GCM)"""
    from services.quantum_security import quantum_security
    
    plaintext = quantum_security.hybrid_decrypt(key_id, encrypted_data)
    
    if plaintext is None:
        raise HTTPException(status_code=400, detail="Decryption failed")
    
    return {"plaintext": plaintext.decode()}


@router.get("/quantum/keypairs")
async def list_quantum_keypairs(
    algorithm: str = None,
    current_user: dict = Depends(get_current_user)
):
    """List quantum key pairs"""
    from services.quantum_security import quantum_security
    return {"keypairs": quantum_security.get_keypairs(algorithm)}


@router.get("/quantum/status")
async def get_quantum_status(current_user: dict = Depends(get_current_user)):
    """Get quantum security status"""
    from services.quantum_security import quantum_security
    return quantum_security.get_quantum_status()


# =============================================================================
# AI REASONING ENDPOINTS
# =============================================================================

@router.post("/ai/analyze")
async def analyze_threat_with_ai(
    request: ThreatAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """Analyze a threat with AI reasoning"""
    from services.ai_reasoning import ai_reasoning
    from dataclasses import asdict
    
    analysis = ai_reasoning.analyze_threat({
        "title": request.title,
        "description": request.description,
        "source": request.source,
        "indicators": request.indicators,
        "process_name": request.process_name,
        "command_line": request.command_line
    })
    
    return asdict(analysis)


@router.post("/ai/triage")
async def triage_incidents(
    incidents: List[Dict[str, Any]],
    current_user: dict = Depends(get_current_user)
):
    """Triage and prioritize incidents"""
    from services.ai_reasoning import ai_reasoning
    
    prioritized = ai_reasoning.triage_incident(incidents)
    return {"prioritized_incidents": prioritized}


@router.post("/ai/query")
async def query_ai(
    request: AIQueryRequest,
    current_user: dict = Depends(get_current_user)
):
    """Query the AI reasoning engine"""
    from services.ai_reasoning import ai_reasoning
    from dataclasses import asdict
    
    result = ai_reasoning.query(request.question, request.context)
    return asdict(result)


@router.get("/ai/stats")
async def get_ai_stats(current_user: dict = Depends(get_current_user)):
    """Get AI reasoning statistics"""
    from services.ai_reasoning import ai_reasoning
    return ai_reasoning.get_reasoning_stats()


# =============================================================================
# UNIFIED DASHBOARD DATA
# =============================================================================

@router.get("/dashboard")
async def get_advanced_dashboard(current_user: dict = Depends(get_current_user)):
    """Get unified advanced security dashboard data"""
    from services.mcp_server import mcp_server
    from services.vector_memory import vector_memory
    from services.vns import vns
    from services.quantum_security import quantum_security
    from services.ai_reasoning import ai_reasoning
    
    return {
        "mcp": mcp_server.get_server_status(),
        "memory": vector_memory.get_memory_stats(),
        "vns": vns.get_vns_stats(),
        "quantum": quantum_security.get_quantum_status(),
        "ai": ai_reasoning.get_reasoning_stats()
    }
