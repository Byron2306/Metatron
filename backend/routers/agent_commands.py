"""
Agent Command System - Bi-directional communication between server and agents
Commands require manual approval before execution
"""
from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from datetime import datetime, timezone
import uuid
import json
import asyncio

from .dependencies import get_current_user, check_permission, get_db

router = APIRouter(prefix="/agent-commands", tags=["Agent Commands"])

# In-memory storage for connected agents and pending commands
connected_agents: Dict[str, WebSocket] = {}
pending_commands: Dict[str, Dict] = {}
command_results: Dict[str, Dict] = {}


class CommandRequest(BaseModel):
    agent_id: str
    command_type: str  # block_ip, kill_process, quarantine_file, remediate, scan, etc.
    parameters: Dict[str, Any]
    priority: str = "medium"  # low, medium, high, critical


class CommandApproval(BaseModel):
    approved: bool
    notes: Optional[str] = None


# Command types and their descriptions
COMMAND_TYPES = {
    "block_ip": {
        "name": "Block IP Address",
        "description": "Add IP to local firewall blocklist",
        "parameters": ["ip_address", "duration_hours"],
        "risk_level": "medium"
    },
    "kill_process": {
        "name": "Terminate Process",
        "description": "Kill a running process by PID or name",
        "parameters": ["pid", "process_name"],
        "risk_level": "high"
    },
    "quarantine_file": {
        "name": "Quarantine File",
        "description": "Move suspicious file to quarantine folder",
        "parameters": ["file_path"],
        "risk_level": "medium"
    },
    "delete_file": {
        "name": "Delete File",
        "description": "Permanently delete a malicious file",
        "parameters": ["file_path"],
        "risk_level": "critical"
    },
    "remove_persistence": {
        "name": "Remove Persistence",
        "description": "Remove registry/startup persistence mechanisms",
        "parameters": ["persistence_type", "path"],
        "risk_level": "high"
    },
    "block_user": {
        "name": "Block User Account",
        "description": "Disable a compromised user account",
        "parameters": ["username"],
        "risk_level": "high"
    },
    "collect_forensics": {
        "name": "Collect Forensic Data",
        "description": "Gather logs, memory dump, and artifacts",
        "parameters": ["collection_type"],
        "risk_level": "low"
    },
    "full_scan": {
        "name": "Run Full Security Scan",
        "description": "Execute comprehensive security scan",
        "parameters": ["scan_types"],
        "risk_level": "low"
    },
    "update_agent": {
        "name": "Update Agent",
        "description": "Download and apply agent updates",
        "parameters": [],
        "risk_level": "low"
    },
    "restart_service": {
        "name": "Restart Security Service",
        "description": "Restart the local security monitoring service",
        "parameters": ["service_name"],
        "risk_level": "medium"
    },
    "remediate_compliance": {
        "name": "Remediate Compliance Issue",
        "description": "Fix security compliance violations",
        "parameters": ["issue_type", "remediation_action"],
        "risk_level": "medium"
    }
}


@router.get("/types")
async def get_command_types(current_user: dict = Depends(get_current_user)):
    """Get available command types"""
    return {"command_types": COMMAND_TYPES}


@router.post("/create")
async def create_command(
    request: CommandRequest,
    current_user: dict = Depends(check_permission("write"))
):
    """Create a new command for an agent (requires approval)"""
    db = get_db()
    
    if request.command_type not in COMMAND_TYPES:
        raise HTTPException(status_code=400, detail=f"Unknown command type: {request.command_type}")
    
    command_id = str(uuid.uuid4())[:12]
    command = {
        "command_id": command_id,
        "agent_id": request.agent_id,
        "command_type": request.command_type,
        "command_name": COMMAND_TYPES[request.command_type]["name"],
        "parameters": request.parameters,
        "priority": request.priority,
        "risk_level": COMMAND_TYPES[request.command_type]["risk_level"],
        "status": "pending_approval",
        "created_by": current_user.get("email", current_user.get("id")),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "approved_by": None,
        "approved_at": None,
        "executed_at": None,
        "result": None
    }
    
    pending_commands[command_id] = command
    await db.agent_commands.insert_one(command)
    
    return {"command_id": command_id, "status": "pending_approval", "command": command}


@router.get("/pending")
async def get_pending_commands(current_user: dict = Depends(get_current_user)):
    """Get all commands pending approval"""
    db = get_db()
    commands = await db.agent_commands.find(
        {"status": "pending_approval"},
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    
    return {"commands": commands, "count": len(commands)}


@router.post("/{command_id}/approve")
async def approve_command(
    command_id: str,
    approval: CommandApproval,
    current_user: dict = Depends(check_permission("manage_users"))
):
    """Approve or reject a pending command"""
    db = get_db()
    
    command = await db.agent_commands.find_one({"command_id": command_id}, {"_id": 0})
    if not command:
        raise HTTPException(status_code=404, detail="Command not found")
    
    if command["status"] != "pending_approval":
        raise HTTPException(status_code=400, detail=f"Command already {command['status']}")
    
    new_status = "approved" if approval.approved else "rejected"
    
    await db.agent_commands.update_one(
        {"command_id": command_id},
        {"$set": {
            "status": new_status,
            "approved_by": current_user.get("email", current_user.get("id")),
            "approved_at": datetime.now(timezone.utc).isoformat(),
            "approval_notes": approval.notes
        }}
    )
    
    # If approved, try to send to agent
    if approval.approved:
        agent_id = command["agent_id"]
        if agent_id in connected_agents:
            try:
                ws = connected_agents[agent_id]
                await ws.send_json({
                    "type": "command",
                    "command_id": command_id,
                    "command_type": command["command_type"],
                    "parameters": command["parameters"]
                })
                await db.agent_commands.update_one(
                    {"command_id": command_id},
                    {"$set": {"status": "sent_to_agent"}}
                )
            except Exception as e:
                pass  # Agent might be disconnected
    
    return {"command_id": command_id, "status": new_status}


@router.get("/history")
async def get_command_history(
    agent_id: Optional[str] = None,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get command execution history"""
    db = get_db()
    
    query = {}
    if agent_id:
        query["agent_id"] = agent_id
    
    commands = await db.agent_commands.find(query, {"_id": 0}).sort("created_at", -1).to_list(limit)
    
    return {"commands": commands, "count": len(commands)}


@router.post("/{command_id}/result")
async def report_command_result(
    command_id: str,
    result: Dict[str, Any],
    current_user: dict = Depends(get_current_user)
):
    """Agent reports command execution result"""
    db = get_db()
    
    await db.agent_commands.update_one(
        {"command_id": command_id},
        {"$set": {
            "status": "completed" if result.get("success") else "failed",
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "result": result
        }}
    )
    
    command_results[command_id] = result
    
    return {"status": "recorded"}


@router.get("/agents/connected")
async def get_connected_agents(current_user: dict = Depends(get_current_user)):
    """Get list of currently connected agents"""
    return {
        "agents": list(connected_agents.keys()),
        "count": len(connected_agents)
    }


@router.websocket("/ws/{agent_id}")
async def agent_websocket(websocket: WebSocket, agent_id: str):
    """WebSocket connection for agent bi-directional communication"""
    await websocket.accept()
    connected_agents[agent_id] = websocket
    
    db = get_db()
    
    # Update agent status in database
    await db.connected_agents.update_one(
        {"agent_id": agent_id},
        {"$set": {
            "agent_id": agent_id,
            "connected_at": datetime.now(timezone.utc).isoformat(),
            "status": "connected",
            "last_heartbeat": datetime.now(timezone.utc).isoformat()
        }},
        upsert=True
    )
    
    try:
        # Send any pending approved commands
        pending = await db.agent_commands.find({
            "agent_id": agent_id,
            "status": "approved"
        }, {"_id": 0}).to_list(100)
        
        for cmd in pending:
            await websocket.send_json({
                "type": "command",
                "command_id": cmd["command_id"],
                "command_type": cmd["command_type"],
                "parameters": cmd["parameters"]
            })
            await db.agent_commands.update_one(
                {"command_id": cmd["command_id"]},
                {"$set": {"status": "sent_to_agent"}}
            )
        
        # Listen for messages from agent
        while True:
            data = await websocket.receive_json()
            
            if data.get("type") == "heartbeat":
                await db.connected_agents.update_one(
                    {"agent_id": agent_id},
                    {"$set": {"last_heartbeat": datetime.now(timezone.utc).isoformat()}}
                )
            
            elif data.get("type") == "scan_result":
                # Agent sending scan results
                await db.agent_scan_results.insert_one({
                    "agent_id": agent_id,
                    "scan_type": data.get("scan_type"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "results": data.get("results", {})
                })
            
            elif data.get("type") == "alert":
                # Agent reporting an alert
                await db.agent_alerts.insert_one({
                    "agent_id": agent_id,
                    "alert_type": data.get("alert_type"),
                    "severity": data.get("severity", "medium"),
                    "message": data.get("message"),
                    "details": data.get("details", {}),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            
            elif data.get("type") == "command_result":
                # Agent reporting command execution result
                command_id = data.get("command_id")
                await db.agent_commands.update_one(
                    {"command_id": command_id},
                    {"$set": {
                        "status": "completed" if data.get("success") else "failed",
                        "executed_at": datetime.now(timezone.utc).isoformat(),
                        "result": data.get("result", {})
                    }}
                )
            
            elif data.get("type") == "status_update":
                # Agent sending status update
                await db.agent_status.update_one(
                    {"agent_id": agent_id},
                    {"$set": {
                        "agent_id": agent_id,
                        "hostname": data.get("hostname"),
                        "os": data.get("os"),
                        "ip_address": data.get("ip_address"),
                        "security_status": data.get("security_status", {}),
                        "last_scan": data.get("last_scan"),
                        "updated_at": datetime.now(timezone.utc).isoformat()
                    }},
                    upsert=True
                )
                
    except WebSocketDisconnect:
        pass
    finally:
        if agent_id in connected_agents:
            del connected_agents[agent_id]
        await db.connected_agents.update_one(
            {"agent_id": agent_id},
            {"$set": {
                "status": "disconnected",
                "disconnected_at": datetime.now(timezone.utc).isoformat()
            }}
        )


@router.get("/agents/status")
async def get_all_agent_status(current_user: dict = Depends(get_current_user)):
    """Get status of all registered agents"""
    db = get_db()
    
    agents = await db.agent_status.find({}, {"_id": 0}).to_list(100)
    connected = await db.connected_agents.find({}, {"_id": 0}).to_list(100)
    
    # Merge status
    connected_map = {a["agent_id"]: a for a in connected}
    for agent in agents:
        conn_info = connected_map.get(agent["agent_id"], {})
        agent["connected"] = conn_info.get("status") == "connected"
        agent["last_heartbeat"] = conn_info.get("last_heartbeat")
    
    return {"agents": agents, "count": len(agents)}


@router.get("/agents/{agent_id}/alerts")
async def get_agent_alerts(
    agent_id: str,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get alerts from a specific agent"""
    db = get_db()
    alerts = await db.agent_alerts.find(
        {"agent_id": agent_id},
        {"_id": 0}
    ).sort("timestamp", -1).to_list(limit)
    
    return {"alerts": alerts, "count": len(alerts)}


@router.get("/agents/{agent_id}/scan-results")
async def get_agent_scan_results(
    agent_id: str,
    limit: int = 20,
    current_user: dict = Depends(get_current_user)
):
    """Get scan results from a specific agent"""
    db = get_db()
    results = await db.agent_scan_results.find(
        {"agent_id": agent_id},
        {"_id": 0}
    ).sort("timestamp", -1).to_list(limit)
    
    return {"results": results, "count": len(results)}
