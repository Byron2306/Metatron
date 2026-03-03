"""
Agents Router - Handle local security agents
"""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from datetime import datetime, timezone
from typing import List, Dict, Any
from pathlib import Path
import uuid
import json
import io

from .dependencies import (
    AgentEvent, AgentInfo, get_current_user, get_db, logger
)
from .honeypots import ws_manager

router = APIRouter(prefix="/agent", tags=["Agents"])

@router.post("/event")
async def receive_agent_event(event: AgentEvent):
    """Receive events from local security agents (no auth required for agents)"""
    db = get_db()
    logger.info(f"Agent event from {event.agent_name}: {event.event_type}")
    
    # Update or create agent record
    agent_doc = {
        "id": event.agent_id,
        "name": event.agent_name,
        "status": "online",
        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
    }
    
    if event.event_type == "heartbeat":
        # Update agent system info
        agent_doc["system_info"] = event.data
        agent_doc["ip"] = event.data.get("network_interfaces", [{}])[0].get("ip") if event.data.get("network_interfaces") else None
        agent_doc["os"] = event.data.get("os")
        
        await db.agents.update_one(
            {"id": event.agent_id},
            {"$set": agent_doc, "$setOnInsert": {"created_at": datetime.now(timezone.utc).isoformat()}},
            upsert=True
        )
        
        # Broadcast to WebSocket
        await ws_manager.broadcast({
            "type": "agent_heartbeat",
            "agent_id": event.agent_id,
            "agent_name": event.agent_name,
            "timestamp": event.timestamp
        })
        
        return {"status": "ok", "message": "Heartbeat received"}
    
    elif event.event_type == "alert":
        # Create alert from agent
        alert_data = event.data
        alert_doc = {
            "id": str(uuid.uuid4()),
            "title": alert_data.get("title", "Agent Alert"),
            "type": alert_data.get("alert_type", "agent"),
            "severity": alert_data.get("severity", "medium"),
            "message": json.dumps(alert_data.get("details", {}))[:500],
            "status": "new",
            "source_agent": event.agent_name,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.alerts.insert_one(alert_doc)
        
        # Broadcast to WebSocket
        await ws_manager.broadcast({
            "type": "new_alert",
            "alert": alert_doc,
            "from_agent": event.agent_name
        })
        
        return {"status": "ok", "alert_id": alert_doc["id"]}
    
    elif event.event_type == "suricata_alert":
        # Create threat from Suricata IDS alert
        suricata_data = event.data
        severity = "critical" if suricata_data.get("severity", 3) == 1 else "high" if suricata_data.get("severity", 3) == 2 else "medium"
        
        threat_doc = {
            "id": str(uuid.uuid4()),
            "name": f"IDS Alert: {suricata_data.get('signature', 'Unknown')}",
            "type": "ids_alert",
            "severity": severity,
            "status": "active",
            "source_ip": suricata_data.get("src_ip"),
            "target_system": suricata_data.get("dest_ip"),
            "description": f"Suricata IDS detected: {suricata_data.get('signature', 'Unknown attack')}. Category: {suricata_data.get('category', 'unknown')}",
            "indicators": [
                f"Source: {suricata_data.get('src_ip')}:{suricata_data.get('src_port', 0)}",
                f"Destination: {suricata_data.get('dest_ip')}:{suricata_data.get('dest_port', 0)}",
                f"Signature ID: {suricata_data.get('signature_id', 'unknown')}"
            ],
            "ai_analysis": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "source_agent": event.agent_name
        }
        await db.threats.insert_one(threat_doc)
        
        # Broadcast
        await ws_manager.broadcast({
            "type": "new_threat",
            "threat": threat_doc,
            "from_agent": event.agent_name
        })
        
        return {"status": "ok", "threat_id": threat_doc["id"]}
    
    elif event.event_type == "falco_alert":
        # Create alert from Falco runtime security
        falco_data = event.data
        alert_doc = {
            "id": str(uuid.uuid4()),
            "title": f"Runtime: {falco_data.get('rule', 'Unknown')}",
            "type": "runtime_security",
            "severity": falco_data.get("priority", "medium").lower(),
            "message": falco_data.get("output", "Falco runtime security alert"),
            "status": "new",
            "source_agent": event.agent_name,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.alerts.insert_one(alert_doc)
        
        await ws_manager.broadcast({
            "type": "new_alert",
            "alert": alert_doc,
            "from_agent": event.agent_name
        })
        
        return {"status": "ok", "alert_id": alert_doc["id"]}
    
    elif event.event_type == "yara_match":
        # Create threat from YARA malware match
        yara_data = event.data
        threat_doc = {
            "id": str(uuid.uuid4()),
            "name": f"Malware: {yara_data.get('matches', [{}])[0].get('rule', 'Unknown')}",
            "type": "malware",
            "severity": yara_data.get('matches', [{}])[0].get('meta', {}).get('severity', 'high'),
            "status": "active",
            "source_ip": None,
            "target_system": yara_data.get("filepath", "Unknown"),
            "description": f"YARA rule matched on file: {yara_data.get('filepath', 'Unknown')}",
            "indicators": [m.get('rule', 'Unknown rule') for m in yara_data.get('matches', [])],
            "ai_analysis": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "source_agent": event.agent_name
        }
        await db.threats.insert_one(threat_doc)
        
        await ws_manager.broadcast({
            "type": "new_threat",
            "threat": threat_doc,
            "from_agent": event.agent_name
        })
        
        return {"status": "ok", "threat_id": threat_doc["id"]}
    
    elif event.event_type == "network_scan":
        # Store network scan results
        scan_doc = {
            "id": str(uuid.uuid4()),
            "agent_id": event.agent_id,
            "agent_name": event.agent_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hosts": event.data.get("hosts", [])
        }
        await db.network_scans.insert_one(scan_doc)
        
        # Update discovered hosts
        for host in event.data.get("hosts", []):
            await db.discovered_hosts.update_one(
                {"ip": host.get("ip")},
                {"$set": {**host, "last_seen": datetime.now(timezone.utc).isoformat(), "discovered_by": event.agent_name}},
                upsert=True
            )
        
        return {"status": "ok", "scan_id": scan_doc["id"]}
    
    # Default response for unknown event types
    return {"status": "ok", "message": f"Event {event.event_type} received"}

@router.get("/download/installer")
async def download_installer():
    """Download the defender installer script"""
    try:
        script_path = Path(__file__).parent.parent.parent / "scripts" / "defender_installer.py"
        with open(script_path, 'r') as f:
            content = f.read()
        
        return StreamingResponse(
            io.StringIO(content),
            media_type="text/x-python",
            headers={
                "Content-Disposition": "attachment; filename=defender_installer.py"
            }
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Installer not found")

@router.get("/download/advanced-agent")
async def download_advanced_agent():
    """Download the advanced security agent with enhanced monitoring"""
    try:
        script_path = Path(__file__).parent.parent.parent / "scripts" / "advanced_agent.py"
        with open(script_path, 'r') as f:
            content = f.read()
        
        return StreamingResponse(
            io.StringIO(content),
            media_type="text/x-python",
            headers={
                "Content-Disposition": "attachment; filename=advanced_agent.py"
            }
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Advanced agent not found")

# Agents list endpoint
agents_router = APIRouter(prefix="/agents", tags=["Agents"])

@agents_router.get("", response_model=List[AgentInfo])
async def get_agents(current_user: dict = Depends(get_current_user)):
    """Get all registered agents"""
    db = get_db()
    agents = await db.agents.find({}, {"_id": 0}).sort("last_heartbeat", -1).to_list(100)
    
    # Mark agents as offline if no heartbeat in 2 minutes
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    result = []
    for agent in agents:
        if agent.get("last_heartbeat", "") < cutoff:
            agent["status"] = "offline"
        # Handle both 'id' and 'agent_id' field names
        if "agent_id" in agent and "id" not in agent:
            agent["id"] = agent["agent_id"]
        # Ensure name field exists
        if "name" not in agent:
            agent["name"] = agent.get("hostname", agent.get("id", "Unknown"))
        try:
            result.append(AgentInfo(**agent))
        except Exception as e:
            logger.warning(f"Skipping invalid agent record: {e}")
    
    return result
