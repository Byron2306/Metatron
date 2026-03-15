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

from .dependencies import (
    get_current_user,
    get_optional_current_user,
    check_permission,
    has_permission,
    optional_machine_token,
    get_db,
)
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
try:
    from services.outbound_gate import OutboundGateService
except Exception:
    from backend.services.outbound_gate import OutboundGateService
try:
    from services.telemetry_chain import tamper_evident_telemetry
except Exception:
    from backend.services.telemetry_chain import tamper_evident_telemetry

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/advanced", tags=["Advanced Security"])
verify_advanced_ingest_machine_token = optional_machine_token(
    env_keys=["ADVANCED_INGEST_TOKEN", "INTEGRATION_API_KEY", "SWARM_AGENT_TOKEN"],
    header_names=["x-advanced-token", "x-internal-token", "x-agent-token"],
    subject="advanced ingest",
)


def _record_advanced_audit(
    *,
    principal: str,
    action: str,
    targets: List[str],
    result: str,
    result_details: Optional[str] = None,
    tool_id: Optional[str] = None,
    constraints: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        tamper_evident_telemetry.set_db(get_db())
        tamper_evident_telemetry.record_action(
            principal=principal,
            principal_trust_state="trusted",
            action=action,
            targets=targets,
            tool_id=tool_id,
            constraints=constraints or {},
            result=result,
            result_details=result_details,
        )
    except Exception:
        logger.exception("Failed to record advanced audit action: %s", action)


def _resolve_write_actor(
    *,
    machine_auth: Optional[dict],
    current_user: Optional[dict],
) -> str:
    if machine_auth is not None:
        return f"machine:{machine_auth.get('subject', 'advanced ingest')}"
    if current_user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    if not has_permission(current_user, "write"):
        raise HTTPException(status_code=403, detail="Permission denied. Required: write or machine token")
    return current_user.get("email", current_user.get("id", "unknown"))


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


class QuantumSignRequest(BaseModel):
    key_id: str
    data: str


class QuantumVerifyRequest(BaseModel):
    public_key: str
    data: str
    signature: str


class QuantumVerifyStoredRequest(BaseModel):
    signature_id: str
    data: str


class QuantumHashRequest(BaseModel):
    data: str


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
    actor = current_user.get("email", current_user.get("id", "unknown"))
    await emit_world_event(
        get_db(),
        event_type="advanced_memory_stored",
        entity_refs=[entry.entry_id, entry.namespace.value],
        payload={
            "actor": actor,
            "namespace": entry.namespace.value,
            "trust_level": entry.trust_level.value,
            "source": entry.source,
        },
        trigger_triune=False,
    )
    _record_advanced_audit(
        principal=f"operator:{actor}",
        action="advanced_memory_store",
        targets=[entry.entry_id, entry.namespace.value],
        result="success",
        constraints={"trust_level": entry.trust_level.value, "source": entry.source},
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
    actor = current_user.get("email", current_user.get("id", "unknown"))
    namespace_value = namespace.value if namespace else "all"
    await emit_world_event(
        get_db(),
        event_type="advanced_memory_searched",
        entity_refs=[namespace_value],
        payload={
            "actor": actor,
            "query": request.query[:128],
            "top_k": request.top_k,
            "min_confidence": request.min_confidence,
            "result_count": len(results),
        },
        trigger_triune=False,
    )
    _record_advanced_audit(
        principal=f"operator:{actor}",
        action="advanced_memory_search",
        targets=[namespace_value],
        result="success",
        constraints={"top_k": request.top_k, "result_count": len(results)},
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
    actor = current_user.get("email", current_user.get("id", "unknown"))
    await emit_world_event(
        get_db(),
        event_type="advanced_memory_case_created",
        entity_refs=[case.case_id],
        payload={
            "actor": actor,
            "title": case.title,
            "affected_hosts": case.affected_hosts,
            "confidence": case.confidence,
        },
        trigger_triune=False,
    )
    _record_advanced_audit(
        principal=f"operator:{actor}",
        action="advanced_memory_case_create",
        targets=[case.case_id],
        result="success",
        constraints={"affected_hosts_count": len(case.affected_hosts or [])},
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
    actor = current_user.get("email", current_user.get("id", "unknown"))
    await emit_world_event(
        get_db(),
        event_type="advanced_memory_case_similarity_queried",
        entity_refs=[case_id],
        payload={"actor": actor, "result_count": len(similar)},
        trigger_triune=False,
    )
    _record_advanced_audit(
        principal=f"operator:{actor}",
        action="advanced_memory_case_similarity",
        targets=[case_id],
        result="success",
        constraints={"result_count": len(similar)},
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
    stats = vector_memory.get_memory_stats()
    actor = (current_user or {}).get("email", (current_user or {}).get("id", "unknown"))
    await emit_world_event(
        get_db(),
        event_type="advanced_memory_stats_requested",
        entity_refs=[],
        payload={"actor": actor, "total_entries": stats.get("total_entries", 0)},
        trigger_triune=False,
    )
    return stats


# =============================================================================
# VNS (VIRTUAL NETWORK SENSOR) ENDPOINTS
# =============================================================================

@router.post("/vns/flow")
async def record_network_flow(
    request: FlowRecordRequest,
    machine_auth: Optional[dict] = Depends(verify_advanced_ingest_machine_token),
    current_user: Optional[dict] = Depends(get_optional_current_user),
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
    actor = _resolve_write_actor(machine_auth=machine_auth, current_user=current_user)
    await emit_world_event(
        get_db(),
        event_type="advanced_vns_flow_recorded",
        entity_refs=[flow.flow_id, request.src_ip, request.dst_ip],
        payload={
            "actor": actor,
            "protocol": request.protocol,
            "threat_score": flow.threat_score,
            "status": flow.status.value,
        },
        trigger_triune=flow.threat_score >= 0.8,
    )
    _record_advanced_audit(
        principal=("operator:" + actor) if not actor.startswith("machine:") else actor,
        action="advanced_vns_flow_record",
        targets=[flow.flow_id, request.src_ip, request.dst_ip],
        result="success",
        constraints={"threat_score": flow.threat_score, "protocol": request.protocol},
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
    machine_auth: Optional[dict] = Depends(verify_advanced_ingest_machine_token),
    current_user: Optional[dict] = Depends(get_optional_current_user),
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
    actor = _resolve_write_actor(machine_auth=machine_auth, current_user=current_user)
    await emit_world_event(
        get_db(),
        event_type="advanced_vns_dns_query_recorded",
        entity_refs=[query.query_id, request.src_ip, request.query_name],
        payload={
            "actor": actor,
            "query_type": request.query_type,
            "response_code": request.response_code,
            "is_suspicious": query.is_suspicious,
        },
        trigger_triune=bool(query.is_suspicious),
    )
    _record_advanced_audit(
        principal=("operator:" + actor) if not actor.startswith("machine:") else actor,
        action="advanced_vns_dns_record",
        targets=[query.query_id, request.query_name],
        result="success",
        constraints={"is_suspicious": bool(query.is_suspicious), "response_code": request.response_code},
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
    actor = current_user.get("email", current_user.get("id", "unknown"))
    await emit_world_event(
        get_db(),
        event_type="advanced_quantum_kyber_keypair_generated",
        entity_refs=[keypair.key_id],
        payload={"actor": actor, "security_level": security_level, "algorithm": keypair.algorithm},
        trigger_triune=False,
    )
    _record_advanced_audit(
        principal=f"operator:{actor}",
        action="advanced_quantum_generate_kyber",
        targets=[keypair.key_id],
        result="success",
        constraints={"security_level": security_level},
    )
    
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
    actor = current_user.get("email", current_user.get("id", "unknown"))
    await emit_world_event(
        get_db(),
        event_type="advanced_quantum_dilithium_keypair_generated",
        entity_refs=[keypair.key_id],
        payload={"actor": actor, "security_level": security_level, "algorithm": keypair.algorithm},
        trigger_triune=False,
    )
    _record_advanced_audit(
        principal=f"operator:{actor}",
        action="advanced_quantum_generate_dilithium",
        targets=[keypair.key_id],
        result="success",
        constraints={"security_level": security_level},
    )
    
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
    import binascii
    from services.quantum_security import quantum_security
    quantum_security.set_db(get_db())
    
    try:
        encrypted = quantum_security.hybrid_encrypt(
            plaintext.encode(),
            recipient_public_key
        )
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid quantum encryption input: {exc}") from exc
    actor = current_user.get("email", current_user.get("id", "unknown"))
    await emit_world_event(
        get_db(),
        event_type="advanced_quantum_hybrid_encryption_performed",
        entity_refs=["quantum_encryption"],
        payload={"actor": actor, "ciphertext_len": len(encrypted.get("ciphertext", ""))},
        trigger_triune=False,
    )
    _record_advanced_audit(
        principal=f"operator:{actor}",
        action="advanced_quantum_encrypt",
        targets=["quantum_encryption"],
        result="success",
        constraints={"ciphertext_len": len(encrypted.get("ciphertext", ""))},
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

    required_fields = {"kem_ciphertext", "nonce", "ciphertext"}
    if not isinstance(encrypted_data, dict) or not required_fields.issubset(set(encrypted_data.keys())):
        raise HTTPException(
            status_code=400,
            detail=f"encrypted_data must include fields: {sorted(required_fields)}",
        )
    
    plaintext = quantum_security.hybrid_decrypt(key_id, encrypted_data)
    
    if plaintext is None:
        actor = current_user.get("email", current_user.get("id", "unknown"))
        await emit_world_event(
            get_db(),
            event_type="advanced_quantum_hybrid_decryption_failed",
            entity_refs=[key_id],
            payload={"actor": actor},
            trigger_triune=True,
        )
        _record_advanced_audit(
            principal=f"operator:{actor}",
            action="advanced_quantum_decrypt",
            targets=[key_id],
            result="failed",
            result_details="decryption_failed",
        )
        raise HTTPException(status_code=400, detail="Decryption failed")
    actor = current_user.get("email", current_user.get("id", "unknown"))
    await emit_world_event(
        get_db(),
        event_type="advanced_quantum_hybrid_decryption_performed",
        entity_refs=[key_id],
        payload={"actor": actor, "plaintext_len": len(plaintext)},
        trigger_triune=False,
    )
    _record_advanced_audit(
        principal=f"operator:{actor}",
        action="advanced_quantum_decrypt",
        targets=[key_id],
        result="success",
        constraints={"plaintext_len": len(plaintext)},
    )
    return {"plaintext": plaintext.decode()}


@router.post("/quantum/sign")
async def quantum_sign(
    request: QuantumSignRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Create a Dilithium signature for application payloads."""
    from services.quantum_security import quantum_security
    quantum_security.set_db(get_db())

    signature = quantum_security.dilithium_sign(request.key_id, request.data.encode())
    actor = current_user.get("email", current_user.get("id", "unknown"))
    if signature is None:
        await emit_world_event(
            get_db(),
            event_type="advanced_quantum_signature_creation_failed",
            entity_refs=[request.key_id],
            payload={"actor": actor},
            trigger_triune=True,
        )
        _record_advanced_audit(
            principal=f"operator:{actor}",
            action="advanced_quantum_sign",
            targets=[request.key_id],
            result="failed",
            result_details="invalid_or_missing_dilithium_key",
        )
        raise HTTPException(status_code=404, detail="Dilithium key not found")

    await emit_world_event(
        get_db(),
        event_type="advanced_quantum_signature_created",
        entity_refs=[signature.signature_id, signature.signer_key_id],
        payload={"actor": actor, "algorithm": signature.algorithm},
        trigger_triune=False,
    )
    _record_advanced_audit(
        principal=f"operator:{actor}",
        action="advanced_quantum_sign",
        targets=[signature.signature_id, signature.signer_key_id],
        result="success",
        constraints={"algorithm": signature.algorithm},
    )
    return {
        "signature_id": signature.signature_id,
        "algorithm": signature.algorithm,
        "data_hash": signature.data_hash,
        "signature": signature.signature,
        "signer_key_id": signature.signer_key_id,
        "timestamp": signature.timestamp,
    }


@router.post("/quantum/verify")
async def quantum_verify(
    request: QuantumVerifyRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Verify a Dilithium signature using a provided public key."""
    from services.quantum_security import quantum_security
    quantum_security.set_db(get_db())

    valid = quantum_security.dilithium_verify(
        public_key=request.public_key,
        data=request.data.encode(),
        signature=request.signature,
    )
    actor = current_user.get("email", current_user.get("id", "unknown"))
    await emit_world_event(
        get_db(),
        event_type="advanced_quantum_signature_verified",
        entity_refs=[],
        payload={"actor": actor, "valid": valid},
        trigger_triune=not valid,
    )
    _record_advanced_audit(
        principal=f"operator:{actor}",
        action="advanced_quantum_verify",
        targets=["signature_verification"],
        result="success" if valid else "failed",
        constraints={"valid": bool(valid)},
    )
    return {"valid": bool(valid)}


@router.post("/quantum/verify/stored")
async def quantum_verify_stored(
    request: QuantumVerifyStoredRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Verify a previously generated signature by signature_id."""
    from services.quantum_security import quantum_security
    quantum_security.set_db(get_db())

    valid = quantum_security.verify_stored_signature(request.signature_id, request.data.encode())
    actor = current_user.get("email", current_user.get("id", "unknown"))
    await emit_world_event(
        get_db(),
        event_type="advanced_quantum_stored_signature_verified",
        entity_refs=[request.signature_id],
        payload={"actor": actor, "valid": valid},
        trigger_triune=not valid,
    )
    _record_advanced_audit(
        principal=f"operator:{actor}",
        action="advanced_quantum_verify_stored",
        targets=[request.signature_id],
        result="success" if valid else "failed",
        constraints={"valid": bool(valid)},
    )
    return {"signature_id": request.signature_id, "valid": bool(valid)}


@router.post("/quantum/hash")
async def quantum_hash(
    request: QuantumHashRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Compute a SHA3-256 quantum-safe hash."""
    from services.quantum_security import quantum_security
    quantum_security.set_db(get_db())

    digest = quantum_security.quantum_hash(request.data.encode())
    actor = current_user.get("email", current_user.get("id", "unknown"))
    await emit_world_event(
        get_db(),
        event_type="advanced_quantum_hash_computed",
        entity_refs=[],
        payload={"actor": actor},
        trigger_triune=False,
    )
    _record_advanced_audit(
        principal=f"operator:{actor}",
        action="advanced_quantum_hash",
        targets=["quantum_hash"],
        result="success",
    )
    return {"algorithm": "SHA3-256", "digest": digest}


@router.get("/quantum/keypairs")
async def list_quantum_keypairs(
    algorithm: str = None,
    current_user: dict = Depends(get_current_user)
):
    """List quantum key pairs"""
    from services.quantum_security import quantum_security
    quantum_security.set_db(get_db())
    return {"keypairs": quantum_security.get_keypairs(algorithm)}


@router.get("/quantum/signatures")
async def list_quantum_signatures(
    signer_key_id: str = None,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """List generated signature metadata."""
    from services.quantum_security import quantum_security
    quantum_security.set_db(get_db())
    return {"signatures": quantum_security.get_signatures(signer_key_id=signer_key_id, limit=limit)}


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
    machine_auth: Optional[dict] = Depends(verify_advanced_ingest_machine_token),
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """Analyze a threat with AI reasoning"""
    from dataclasses import asdict
    actor = _resolve_write_actor(machine_auth=machine_auth, current_user=current_user)
    
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
        payload = asdict(analysis)
    except Exception:
        payload = analysis
    await emit_world_event(
        get_db(),
        event_type="advanced_ai_threat_analyzed",
        entity_refs=[],
        payload={"actor": actor, "source": "advanced_ai_analyze"},
        trigger_triune=False,
    )
    _record_advanced_audit(
        principal=("operator:" + actor) if not actor.startswith("machine:") else actor,
        action="advanced_ai_analyze_threat",
        targets=["ai_reasoning"],
        result="success",
    )
    return payload


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
    machine_auth: Optional[dict] = Depends(verify_advanced_ingest_machine_token),
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """Query the AI reasoning engine"""
    from dataclasses import asdict
    actor = _resolve_write_actor(machine_auth=machine_auth, current_user=current_user)

    result = _safe_call_ai_sync('query', request.question, request.context)
    try:
        payload = asdict(result)
    except Exception:
        payload = result
    await emit_world_event(
        get_db(),
        event_type="advanced_ai_query_executed",
        entity_refs=[],
        payload={"actor": actor, "question_len": len(request.question or "")},
        trigger_triune=False,
    )
    _record_advanced_audit(
        principal=("operator:" + actor) if not actor.startswith("machine:") else actor,
        action="advanced_ai_query",
        targets=["ai_reasoning"],
        result="success",
        constraints={"question_len": len(request.question or "")},
    )
    return payload


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
