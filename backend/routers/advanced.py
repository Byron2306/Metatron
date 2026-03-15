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

from .dependencies import get_current_user, check_permission, get_db
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
try:
    from services.outbound_gate import OutboundGateService
except Exception:
    from backend.services.outbound_gate import OutboundGateService

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/advanced", tags=["Advanced Security"])


def _safe_get_reasoning_stats() -> Dict[str, Any]:
    """Reload the AI reasoning module and call get_reasoning_stats if available.
    Provide a safe fallback when the engine is not fully initialized to avoid 500s.
    """
    try:
        import importlib
        try:
            ar_mod = importlib.import_module('backend.services.ai_reasoning')
        except ModuleNotFoundError:
            ar_mod = importlib.import_module('services.ai_reasoning')
        importlib.reload(ar_mod)
        if hasattr(ar_mod, 'ai_reasoning') and hasattr(ar_mod.ai_reasoning, 'get_reasoning_stats'):
            return ar_mod.ai_reasoning.get_reasoning_stats()
    except Exception:
        logger.exception("Failed to reload ai_reasoning module")

    return {
        "status": "unavailable",
        "note": "AI reasoning engine not available"
    }


def _safe_call_ai_sync(method_name: str, *args, **kwargs):
    try:
        import importlib
        try:
            ar_mod = importlib.import_module('backend.services.ai_reasoning')
        except ModuleNotFoundError:
            ar_mod = importlib.import_module('services.ai_reasoning')
        importlib.reload(ar_mod)
        inst = getattr(ar_mod, 'ai_reasoning', None)
        # Prefer instance-bound method
        if inst and hasattr(inst, method_name):
            method = getattr(inst, method_name)
            return method(*args, **kwargs)
        # Fallback: call unbound class method with the instance as self
        try:
            cls = getattr(ar_mod, 'LocalAIReasoningEngine', None)
            if cls and hasattr(cls, method_name) and inst is not None:
                method = getattr(cls, method_name)
                return method(inst, *args, **kwargs)
        except Exception:
            # allow outer except to log
            raise
    except Exception:
        logger.exception("Safe AI sync call failed: %s", method_name)
    # Special-case handlers for Ollama configuration/status when the
    # ai_reasoning instance does not expose the methods (workaround).
    try:
        if method_name == 'configure_ollama':
            # args: base_url, model
            base_url = args[0] if len(args) > 0 else kwargs.get('base_url')
            model = args[1] if len(args) > 1 else kwargs.get('model')
            base_url = base_url or 'http://localhost:11434'
            model = model or 'mistral'
            try:
                from backend.ai.ollama_client import OllamaClient
                if inst is None:
                    return {"status": "connection_failed", "note": "AI instance missing"}
                client = OllamaClient(base_url, model)
                tags = client.get_tags(timeout=5)
                if tags and not tags.get('error'):
                    try:
                        inst.ollama_client = client
                        inst.ollama_url = base_url
                        inst.ollama_model = model
                        inst.use_local_llm = True
                    except Exception:
                        pass
                    models = tags.get('models') or []
                    return {"status": "connected", "base_url": base_url, "model": model, "available_models": [m.get('name') for m in models]}
                return {"status": "connection_failed", "note": "Ollama tags call failed"}
            except Exception as e:
                return {"status": "connection_failed", "error": str(e)}
        if method_name == 'get_ollama_status':
            try:
                if inst is None:
                    return {"status": "disconnected", "note": "AI instance missing"}
                if getattr(inst, 'ollama_client', None) is None:
                    from backend.ai.ollama_client import OllamaClient
                    inst.ollama_client = OllamaClient(getattr(inst, 'ollama_url', 'http://localhost:11434'), getattr(inst, 'ollama_model', 'mistral'))
                tags = inst.ollama_client.get_tags(timeout=5)
                if tags and not tags.get('error'):
                    models = tags.get('models') or []
                    return {"status": "connected", "url": getattr(inst, 'ollama_url', 'http://localhost:11434'), "models": [m.get('name') for m in models], "configured_model": getattr(inst, 'ollama_model', 'mistral')}
            except Exception:
                pass
    except Exception:
        pass
    return {"status": "unavailable", "note": f"AI method {method_name} unavailable"}


async def _safe_call_ai_async(method_name: str, *args, **kwargs):
    try:
        import importlib, asyncio
        try:
            ar_mod = importlib.import_module('backend.services.ai_reasoning')
        except ModuleNotFoundError:
            ar_mod = importlib.import_module('services.ai_reasoning')
        importlib.reload(ar_mod)
        inst = getattr(ar_mod, 'ai_reasoning', None)
        # Prefer instance-bound method
        if inst and hasattr(inst, method_name):
            method = getattr(inst, method_name)
            if asyncio.iscoroutinefunction(method):
                return await method(*args, **kwargs)
            # support async wrappers that return awaitables
            res = method(*args, **kwargs)
            if hasattr(res, '__await__'):
                return await res
            return res
        # Fallback to class method (which may be sync or async)
        cls = getattr(ar_mod, 'LocalAIReasoningEngine', None)
        if cls and hasattr(cls, method_name) and inst is not None:
            method = getattr(cls, method_name)
            # if it's a coroutine function defined on the class, call with instance
            if asyncio.iscoroutinefunction(method):
                return await method(inst, *args, **kwargs)
            res = method(inst, *args, **kwargs)
            if hasattr(res, '__await__'):
                return await res
            return res
    except Exception:
        logger.exception("Safe AI async call failed: %s", method_name)
    return {"status": "unavailable", "note": f"AI method {method_name} unavailable"}


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
    mcp_server.set_db(get_db())
    return {"tools": mcp_server.get_tool_catalog()}


@router.get("/mcp/tools/{tool_id}")
async def get_mcp_tool(tool_id: str, current_user: dict = Depends(get_current_user)):
    """Get MCP tool details"""
    from services.mcp_server import mcp_server
    mcp_server.set_db(get_db())
    
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
    mcp_server.set_db(get_db())
    import asyncio
    
    gate = OutboundGateService(get_db())
    actor = f"operator:{current_user.get('email', 'unknown')}"
    gated = await gate.gate_action(
        action_type="mcp_tool_execution",
        actor=actor,
        payload={"tool_id": request.tool_id, "params": request.params, "trace_id": request.trace_id},
        impact_level="critical",
        subject_id=request.tool_id,
        entity_refs=[request.tool_id, actor],
        requires_triune=True,
    )

    await emit_world_event(get_db(), event_type="advanced_mcp_execution_gated", entity_refs=[request.tool_id, actor], payload={"queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}, trigger_triune=True)

    return {
        "status": "queued_for_triune_approval",
        "tool_id": request.tool_id,
        "queue_id": gated.get("queue_id"),
        "decision_id": gated.get("decision_id"),
    }


@router.get("/mcp/history")
async def get_mcp_history(
    tool_id: str = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get MCP execution history"""
    from services.mcp_server import mcp_server
    mcp_server.set_db(get_db())
    return {"executions": mcp_server.get_execution_history(tool_id=tool_id, limit=limit)}


@router.get("/mcp/status")
async def get_mcp_status(current_user: dict = Depends(get_current_user)):
    """Get MCP server status"""
    from services.mcp_server import mcp_server
    mcp_server.set_db(get_db())
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
    current_user: dict = Depends(check_permission("write"))
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
    current_user: dict = Depends(check_permission("write"))
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
    """Queue canary IP deployment through outbound governance."""
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="cross_sector_hardening",
        actor=actor,
        payload={"operation": "vns_add_canary_ip", "ip": ip},
        impact_level="high",
        subject_id=ip,
        entity_refs=[ip],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="advanced_vns_canary_ip_gated",
        entity_refs=[ip, gated.get("queue_id"), gated.get("decision_id")],
        payload={"actor": actor},
        trigger_triune=True,
    )
    return {"status": "queued_for_triune_approval", "canary_ip": ip, "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}


@router.post("/vns/canary/domain")
async def add_canary_domain(
    domain: str,
    current_user: dict = Depends(check_permission("write"))
):
    """Queue canary domain deployment through outbound governance."""
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="cross_sector_hardening",
        actor=actor,
        payload={"operation": "vns_add_canary_domain", "domain": domain},
        impact_level="high",
        subject_id=domain,
        entity_refs=[domain],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="advanced_vns_canary_domain_gated",
        entity_refs=[domain, gated.get("queue_id"), gated.get("decision_id")],
        payload={"actor": actor},
        trigger_triune=True,
    )
    return {"status": "queued_for_triune_approval", "canary_domain": domain, "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}


@router.post("/vns/validate")
async def validate_endpoint_telemetry(
    endpoint_ip: str,
    endpoint_flows: List[Dict[str, Any]],
    current_user: dict = Depends(check_permission("write"))
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
    quantum_security.set_db(get_db())
    
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
    quantum_security.set_db(get_db())
    
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
    quantum_security.set_db(get_db())
    
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
    quantum_security.set_db(get_db())
    
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
    quantum_security.set_db(get_db())
    return {"keypairs": quantum_security.get_keypairs(algorithm)}


@router.get("/quantum/status")
async def get_quantum_status(current_user: dict = Depends(get_current_user)):
    """Get quantum security status"""
    from services.quantum_security import quantum_security
    quantum_security.set_db(get_db())
    return quantum_security.get_quantum_status()


# =============================================================================
# AI REASONING ENDPOINTS
# =============================================================================

@router.post("/ai/analyze")
async def analyze_threat_with_ai(
    request: ThreatAnalysisRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Analyze a threat with AI reasoning"""
    from dataclasses import asdict
    
    analysis = _safe_call_ai_sync('analyze_threat', {
        "title": request.title,
        "description": request.description,
        "source": request.source,
        "indicators": request.indicators,
        "process_name": request.process_name,
        "command_line": request.command_line
    })

    # analysis may be a dataclass or a dict/fallback
    try:
        return asdict(analysis)
    except Exception:
        return analysis


@router.post("/ai/triage")
async def triage_incidents(
    incidents: List[Dict[str, Any]],
    current_user: dict = Depends(check_permission("write"))
):
    """Triage and prioritize incidents"""
    prioritized = _safe_call_ai_sync('triage_incident', incidents)
    return {"prioritized_incidents": prioritized}


@router.post("/ai/query")
async def query_ai(
    request: AIQueryRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Query the AI reasoning engine"""
    from dataclasses import asdict

    result = _safe_call_ai_sync('query', request.question, request.context)
    try:
        return asdict(result)
    except Exception:
        return result


@router.get("/ai/stats")
async def get_ai_stats(current_user: dict = Depends(get_current_user)):
    """Get AI reasoning statistics"""
    return _safe_get_reasoning_stats()


# =============================================================================
# OLLAMA INTEGRATION ENDPOINTS
# =============================================================================

class OllamaConfigRequest(BaseModel):
    base_url: str = "http://localhost:11434"
    model: str = "mistral"


class OllamaGenerateRequest(BaseModel):
    prompt: str
    model: Optional[str] = None
    system_prompt: Optional[str] = None


@router.post("/ai/ollama/configure")
async def configure_ollama(
    request: OllamaConfigRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Configure Ollama for local AI reasoning"""
    result = _safe_call_ai_sync('configure_ollama', request.base_url, request.model)
    await emit_world_event(
        get_db(),
        event_type="advanced_ollama_configured",
        entity_refs=[],
        payload={"base_url": request.base_url, "model": request.model, "status": result.get("status") if isinstance(result, dict) else None},
        trigger_triune=False,
    )
    return result


@router.get("/ai/ollama/status")
async def get_ollama_status(current_user: dict = Depends(get_current_user)):
    """Get Ollama connection status"""
    return _safe_call_ai_sync('get_ollama_status')


@router.post("/ai/ollama/generate")
async def ollama_generate(
    request: OllamaGenerateRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Generate response using Ollama"""
    result = await _safe_call_ai_async('ollama_generate', request.prompt, request.model, request.system_prompt)
    return result


@router.post("/ai/ollama/analyze")
async def ollama_analyze_threat(
    request: ThreatAnalysisRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Analyze threat using Ollama LLM"""
    result = await _safe_call_ai_async('ollama_analyze_threat', {
        "title": request.title,
        "description": request.description,
        "source": request.source,
        "indicators": request.indicators,
        "process_name": request.process_name,
        "command_line": request.command_line
    })
    return result


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

    return {
        "mcp": mcp_server.get_server_status(),
        "memory": vector_memory.get_memory_stats(),
        "vns": vns.get_vns_stats(),
        "quantum": quantum_security.get_quantum_status(),
        "ai": _safe_get_reasoning_stats()
    }


# =============================================================================
# VNS ALERTS ENDPOINTS
# =============================================================================

class AlertConfigRequest(BaseModel):
    slack_webhook_url: Optional[str] = None
    email_config: Optional[Dict[str, Any]] = None


class TestAlertRequest(BaseModel):
    channel: str = "all"  # all, slack, email


@router.get("/alerts/status")
async def get_alert_status(current_user: dict = Depends(get_current_user)):
    """Get VNS alert service status"""
    from services.vns_alerts import vns_alert_service
    
    return vns_alert_service.get_status()


@router.post("/alerts/configure")
async def configure_alerts(
    request: AlertConfigRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Configure VNS alert channels"""
    from services.vns_alerts import vns_alert_service
    
    result = vns_alert_service.configure(
        slack_webhook=request.slack_webhook_url,
        email_config=request.email_config
    )
    await emit_world_event(
        get_db(),
        event_type="advanced_alert_channels_configured",
        entity_refs=[],
        payload={"has_slack": bool(request.slack_webhook_url), "has_email": bool(request.email_config)},
        trigger_triune=False,
    )
    
    return {"status": "configured", **result}


@router.post("/alerts/test")
async def test_alert(
    request: TestAlertRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Send a test alert"""
    from services.vns_alerts import vns_alert_service
    
    results = vns_alert_service.test_alert(request.channel)
    await emit_world_event(
        get_db(),
        event_type="advanced_alert_test_sent",
        entity_refs=[],
        payload={"channel": request.channel},
        trigger_triune=False,
    )
    return {"status": "sent", "results": results}


# =============================================================================
# CUCKOO SANDBOX ENDPOINTS
# =============================================================================

class SandboxSubmitRequest(BaseModel):
    file_path: Optional[str] = None
    file_base64: Optional[str] = None
    file_name: Optional[str] = None
    url: Optional[str] = None
    options: Optional[Dict[str, Any]] = None


@router.get("/sandbox/status")
async def get_sandbox_status(current_user: dict = Depends(get_current_user)):
    """Get Cuckoo sandbox status"""
    from services.cuckoo_sandbox import cuckoo_sandbox
    cuckoo_sandbox.set_db(get_db())
    
    return cuckoo_sandbox.get_status()


@router.post("/sandbox/submit/file")
async def submit_file_to_sandbox(
    request: SandboxSubmitRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Queue file submission to sandbox through outbound governance."""
    if not request.file_base64 and not request.file_path:
        raise HTTPException(status_code=400, detail="file_path or file_base64 required")

    subject = request.file_name or request.file_path or "inline_file_submission"
    actor = current_user.get("email", current_user.get("id", "unknown"))
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="tool_execution",
        actor=actor,
        payload={
            "sandbox_action": "submit_file",
            "file_name": request.file_name,
            "file_path": request.file_path,
            "has_inline_file": bool(request.file_base64),
            "options": request.options or {},
        },
        impact_level="high",
        subject_id=subject,
        entity_refs=[subject],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="advanced_sandbox_file_submission_gated",
        entity_refs=[subject, gated.get("queue_id"), gated.get("decision_id")],
        payload={"actor": actor},
        trigger_triune=True,
    )
    return {"status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}


@router.post("/sandbox/submit/url")
async def submit_url_to_sandbox(
    request: SandboxSubmitRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Queue URL submission to sandbox through outbound governance."""
    if not request.url:
        raise HTTPException(status_code=400, detail="url required")

    actor = current_user.get("email", current_user.get("id", "unknown"))
    gate = OutboundGateService(get_db())
    gated = await gate.gate_action(
        action_type="tool_execution",
        actor=actor,
        payload={"sandbox_action": "submit_url", "url": request.url, "options": request.options or {}},
        impact_level="high",
        subject_id=request.url,
        entity_refs=[request.url],
        requires_triune=True,
    )
    await emit_world_event(
        get_db(),
        event_type="advanced_sandbox_url_submission_gated",
        entity_refs=[request.url, gated.get("queue_id"), gated.get("decision_id")],
        payload={"actor": actor},
        trigger_triune=True,
    )
    return {"status": "queued_for_triune_approval", "queue_id": gated.get("queue_id"), "decision_id": gated.get("decision_id")}


@router.get("/sandbox/task/{task_id}")
async def get_sandbox_task_status(
    task_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get sandbox task status"""
    from services.cuckoo_sandbox import cuckoo_sandbox
    cuckoo_sandbox.set_db(get_db())
    
    return cuckoo_sandbox.get_task_status(task_id)


@router.get("/sandbox/report/{task_id}")
async def get_sandbox_report(
    task_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get full sandbox analysis report"""
    from services.cuckoo_sandbox import cuckoo_sandbox
    cuckoo_sandbox.set_db(get_db())
    
    return cuckoo_sandbox.get_report(task_id)
