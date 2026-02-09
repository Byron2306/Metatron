"""
SOAR (Security Orchestration, Automation and Response) Playbook Engine
"""
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
import uuid
import logging

logger = logging.getLogger(__name__)

class PlaybookAction(str, Enum):
    BLOCK_IP = "block_ip"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    SEND_ALERT = "send_alert"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    COLLECT_FORENSICS = "collect_forensics"
    DISABLE_USER = "disable_user"
    SCAN_ENDPOINT = "scan_endpoint"
    UPDATE_FIREWALL = "update_firewall"
    CREATE_TICKET = "create_ticket"

class PlaybookTrigger(str, Enum):
    THREAT_DETECTED = "threat_detected"
    MALWARE_FOUND = "malware_found"
    RANSOMWARE_DETECTED = "ransomware_detected"
    SUSPICIOUS_PROCESS = "suspicious_process"
    IOC_MATCH = "ioc_match"
    HONEYPOT_TRIGGERED = "honeypot_triggered"
    ANOMALY_DETECTED = "anomaly_detected"
    MANUAL = "manual"

class PlaybookStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    TESTING = "testing"

class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"

@dataclass
class PlaybookStep:
    action: PlaybookAction
    params: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 30  # seconds
    continue_on_failure: bool = False
    condition: Optional[str] = None  # e.g., "severity >= high"

@dataclass
class Playbook:
    id: str
    name: str
    description: str
    trigger: PlaybookTrigger
    trigger_conditions: Dict[str, Any]  # e.g., {"severity": ["critical", "high"]}
    steps: List[PlaybookStep]
    status: PlaybookStatus = PlaybookStatus.ACTIVE
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    created_by: str = "system"
    execution_count: int = 0
    last_executed: Optional[str] = None
    is_template: bool = False
    template_id: Optional[str] = None  # If cloned from a template
    tags: List[str] = field(default_factory=list)

@dataclass
class PlaybookTemplate:
    id: str
    name: str
    description: str
    category: str  # e.g., "malware", "ransomware", "network", "compliance"
    trigger: PlaybookTrigger
    trigger_conditions: Dict[str, Any]
    steps: List[PlaybookStep]
    tags: List[str]
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    use_count: int = 0
    is_official: bool = False  # Official templates from the system

@dataclass
class PlaybookExecution:
    id: str
    playbook_id: str
    playbook_name: str
    trigger_event: Dict[str, Any]
    status: ExecutionStatus
    started_at: str
    completed_at: Optional[str] = None
    step_results: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None

class SOAREngine:
    def __init__(self):
        self.playbooks: Dict[str, Playbook] = {}
        self.templates: Dict[str, PlaybookTemplate] = {}
        self.executions: List[PlaybookExecution] = []
        self._init_default_playbooks()
        self._init_templates()
    
    def _init_default_playbooks(self):
        """Initialize default playbooks"""
        # Malware Response Playbook
        self.playbooks["pb_malware_response"] = Playbook(
            id="pb_malware_response",
            name="Malware Auto-Response",
            description="Automatically quarantine malware and alert security team",
            trigger=PlaybookTrigger.MALWARE_FOUND,
            trigger_conditions={"severity": ["critical", "high", "medium"]},
            steps=[
                PlaybookStep(
                    action=PlaybookAction.QUARANTINE_FILE,
                    params={"auto": True},
                    timeout=60
                ),
                PlaybookStep(
                    action=PlaybookAction.SCAN_ENDPOINT,
                    params={"full_scan": True},
                    timeout=300,
                    continue_on_failure=True
                ),
                PlaybookStep(
                    action=PlaybookAction.SEND_ALERT,
                    params={"channels": ["slack", "email"], "priority": "high"}
                ),
                PlaybookStep(
                    action=PlaybookAction.CREATE_TICKET,
                    params={"category": "malware", "auto_assign": True}
                )
            ]
        )
        
        # Ransomware Response Playbook
        self.playbooks["pb_ransomware_response"] = Playbook(
            id="pb_ransomware_response",
            name="Ransomware Emergency Response",
            description="Isolate endpoint, kill process, and escalate immediately",
            trigger=PlaybookTrigger.RANSOMWARE_DETECTED,
            trigger_conditions={"severity": ["critical"]},
            steps=[
                PlaybookStep(
                    action=PlaybookAction.KILL_PROCESS,
                    params={"force": True},
                    timeout=10
                ),
                PlaybookStep(
                    action=PlaybookAction.ISOLATE_ENDPOINT,
                    params={"network": True, "usb": True},
                    timeout=30
                ),
                PlaybookStep(
                    action=PlaybookAction.COLLECT_FORENSICS,
                    params={"memory_dump": True, "disk_image": False},
                    timeout=120,
                    continue_on_failure=True
                ),
                PlaybookStep(
                    action=PlaybookAction.SEND_ALERT,
                    params={"channels": ["slack", "email", "sms"], "priority": "critical"}
                )
            ]
        )
        
        # IOC Match Response
        self.playbooks["pb_ioc_response"] = Playbook(
            id="pb_ioc_response",
            name="IOC Match Response",
            description="Block IPs and update firewall when IOC is matched",
            trigger=PlaybookTrigger.IOC_MATCH,
            trigger_conditions={"ioc_type": ["ip", "domain"], "confidence": ["high"]},
            steps=[
                PlaybookStep(
                    action=PlaybookAction.BLOCK_IP,
                    params={"duration": 86400},  # 24 hours
                    timeout=30
                ),
                PlaybookStep(
                    action=PlaybookAction.UPDATE_FIREWALL,
                    params={"rule_type": "block"},
                    timeout=60
                ),
                PlaybookStep(
                    action=PlaybookAction.SEND_ALERT,
                    params={"channels": ["slack"], "priority": "medium"}
                )
            ]
        )
        
        # Suspicious Process Response
        self.playbooks["pb_suspicious_process"] = Playbook(
            id="pb_suspicious_process",
            name="Suspicious Process Response",
            description="Investigate and potentially kill suspicious processes",
            trigger=PlaybookTrigger.SUSPICIOUS_PROCESS,
            trigger_conditions={"confidence": ["high"]},
            steps=[
                PlaybookStep(
                    action=PlaybookAction.COLLECT_FORENSICS,
                    params={"process_info": True, "network_connections": True},
                    timeout=60
                ),
                PlaybookStep(
                    action=PlaybookAction.KILL_PROCESS,
                    params={"force": False},
                    timeout=10,
                    condition="confidence >= 0.9"
                ),
                PlaybookStep(
                    action=PlaybookAction.SEND_ALERT,
                    params={"channels": ["slack"], "priority": "medium"}
                )
            ]
        )
        
        # Honeypot Alert Playbook
        self.playbooks["pb_honeypot_alert"] = Playbook(
            id="pb_honeypot_alert",
            name="Honeypot Alert Response",
            description="Respond to honeypot triggers with intelligence gathering",
            trigger=PlaybookTrigger.HONEYPOT_TRIGGERED,
            trigger_conditions={},
            steps=[
                PlaybookStep(
                    action=PlaybookAction.COLLECT_FORENSICS,
                    params={"attacker_info": True, "techniques": True},
                    timeout=120
                ),
                PlaybookStep(
                    action=PlaybookAction.BLOCK_IP,
                    params={"duration": 604800},  # 7 days
                    timeout=30
                ),
                PlaybookStep(
                    action=PlaybookAction.SEND_ALERT,
                    params={"channels": ["slack", "email"], "priority": "high"}
                ),
                PlaybookStep(
                    action=PlaybookAction.CREATE_TICKET,
                    params={"category": "honeypot", "include_iocs": True}
                )
            ]
        )
    
    def get_playbooks(self) -> List[Dict]:
        """Get all playbooks"""
        return [asdict(pb) for pb in self.playbooks.values()]
    
    def get_playbook(self, playbook_id: str) -> Optional[Dict]:
        """Get a specific playbook"""
        pb = self.playbooks.get(playbook_id)
        return asdict(pb) if pb else None
    
    def create_playbook(self, data: Dict) -> Dict:
        """Create a new playbook"""
        playbook_id = f"pb_{uuid.uuid4().hex[:8]}"
        
        steps = []
        for step_data in data.get("steps", []):
            steps.append(PlaybookStep(
                action=PlaybookAction(step_data["action"]),
                params=step_data.get("params", {}),
                timeout=step_data.get("timeout", 30),
                continue_on_failure=step_data.get("continue_on_failure", False),
                condition=step_data.get("condition")
            ))
        
        playbook = Playbook(
            id=playbook_id,
            name=data["name"],
            description=data.get("description", ""),
            trigger=PlaybookTrigger(data["trigger"]),
            trigger_conditions=data.get("trigger_conditions", {}),
            steps=steps,
            status=PlaybookStatus(data.get("status", "active")),
            created_by=data.get("created_by", "user")
        )
        
        self.playbooks[playbook_id] = playbook
        return asdict(playbook)
    
    def update_playbook(self, playbook_id: str, data: Dict) -> Optional[Dict]:
        """Update an existing playbook"""
        if playbook_id not in self.playbooks:
            return None
        
        pb = self.playbooks[playbook_id]
        
        if "name" in data:
            pb.name = data["name"]
        if "description" in data:
            pb.description = data["description"]
        if "status" in data:
            pb.status = PlaybookStatus(data["status"])
        if "trigger_conditions" in data:
            pb.trigger_conditions = data["trigger_conditions"]
        if "steps" in data:
            pb.steps = [
                PlaybookStep(
                    action=PlaybookAction(s["action"]),
                    params=s.get("params", {}),
                    timeout=s.get("timeout", 30),
                    continue_on_failure=s.get("continue_on_failure", False),
                    condition=s.get("condition")
                ) for s in data["steps"]
            ]
        
        pb.updated_at = datetime.now(timezone.utc).isoformat()
        return asdict(pb)
    
    def delete_playbook(self, playbook_id: str) -> bool:
        """Delete a playbook"""
        if playbook_id in self.playbooks:
            del self.playbooks[playbook_id]
            return True
        return False
    
    def matches_trigger(self, playbook: Playbook, event: Dict) -> bool:
        """Check if an event matches a playbook's trigger conditions"""
        if playbook.status != PlaybookStatus.ACTIVE:
            return False
        
        # Check trigger type
        event_trigger = event.get("trigger_type")
        if event_trigger and event_trigger != playbook.trigger.value:
            return False
        
        # Check conditions
        for key, allowed_values in playbook.trigger_conditions.items():
            event_value = event.get(key)
            if event_value and allowed_values:
                if isinstance(allowed_values, list):
                    if event_value not in allowed_values:
                        return False
                elif event_value != allowed_values:
                    return False
        
        return True
    
    async def execute_playbook(self, playbook_id: str, event: Dict) -> PlaybookExecution:
        """Execute a playbook"""
        playbook = self.playbooks.get(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook {playbook_id} not found")
        
        execution = PlaybookExecution(
            id=f"exec_{uuid.uuid4().hex[:12]}",
            playbook_id=playbook_id,
            playbook_name=playbook.name,
            trigger_event=event,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc).isoformat()
        )
        
        all_success = True
        
        for i, step in enumerate(playbook.steps):
            step_result = {
                "step": i + 1,
                "action": step.action.value,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "status": "running"
            }
            
            try:
                # Execute the action
                result = await self._execute_action(step, event)
                step_result["status"] = "completed"
                step_result["result"] = result
                step_result["completed_at"] = datetime.now(timezone.utc).isoformat()
            except Exception as e:
                step_result["status"] = "failed"
                step_result["error"] = str(e)
                step_result["completed_at"] = datetime.now(timezone.utc).isoformat()
                all_success = False
                
                if not step.continue_on_failure:
                    execution.step_results.append(step_result)
                    execution.status = ExecutionStatus.FAILED
                    execution.error = f"Step {i+1} failed: {str(e)}"
                    break
            
            execution.step_results.append(step_result)
        
        if all_success:
            execution.status = ExecutionStatus.COMPLETED
        elif execution.status != ExecutionStatus.FAILED:
            execution.status = ExecutionStatus.PARTIAL
        
        execution.completed_at = datetime.now(timezone.utc).isoformat()
        
        # Update playbook stats
        playbook.execution_count += 1
        playbook.last_executed = execution.completed_at
        
        self.executions.append(execution)
        
        # Keep only last 100 executions
        if len(self.executions) > 100:
            self.executions = self.executions[-100:]
        
        return execution
    
    async def _execute_action(self, step: PlaybookStep, event: Dict) -> Dict:
        """Execute a single playbook action"""
        action = step.action
        params = step.params
        
        # Simulated action execution - in production, these would call real services
        if action == PlaybookAction.BLOCK_IP:
            ip = event.get("source_ip") or params.get("ip")
            logger.info(f"SOAR: Blocking IP {ip} for {params.get('duration', 3600)}s")
            return {"blocked_ip": ip, "duration": params.get("duration", 3600)}
        
        elif action == PlaybookAction.KILL_PROCESS:
            pid = event.get("pid") or params.get("pid")
            logger.info(f"SOAR: Killing process {pid}")
            return {"killed_pid": pid, "force": params.get("force", False)}
        
        elif action == PlaybookAction.QUARANTINE_FILE:
            file_path = event.get("file_path") or params.get("path")
            logger.info(f"SOAR: Quarantining file {file_path}")
            return {"quarantined": file_path}
        
        elif action == PlaybookAction.SEND_ALERT:
            channels = params.get("channels", ["slack"])
            priority = params.get("priority", "medium")
            logger.info(f"SOAR: Sending alert to {channels} with priority {priority}")
            return {"channels_notified": channels, "priority": priority}
        
        elif action == PlaybookAction.ISOLATE_ENDPOINT:
            agent_id = event.get("agent_id")
            logger.info(f"SOAR: Isolating endpoint {agent_id}")
            return {"isolated_agent": agent_id, "network": params.get("network", True)}
        
        elif action == PlaybookAction.COLLECT_FORENSICS:
            logger.info(f"SOAR: Collecting forensics data")
            return {"forensics_collected": True, "params": params}
        
        elif action == PlaybookAction.DISABLE_USER:
            user = event.get("user") or params.get("user")
            logger.info(f"SOAR: Disabling user {user}")
            return {"disabled_user": user}
        
        elif action == PlaybookAction.SCAN_ENDPOINT:
            agent_id = event.get("agent_id")
            logger.info(f"SOAR: Scanning endpoint {agent_id}")
            return {"scan_initiated": True, "full_scan": params.get("full_scan", False)}
        
        elif action == PlaybookAction.UPDATE_FIREWALL:
            rule_type = params.get("rule_type", "block")
            logger.info(f"SOAR: Updating firewall with {rule_type} rule")
            return {"firewall_updated": True, "rule_type": rule_type}
        
        elif action == PlaybookAction.CREATE_TICKET:
            category = params.get("category", "security")
            logger.info(f"SOAR: Creating ticket for {category}")
            return {"ticket_created": True, "category": category}
        
        return {"action": action.value, "status": "executed"}
    
    async def trigger_playbooks(self, event: Dict) -> List[PlaybookExecution]:
        """Trigger all matching playbooks for an event"""
        executions = []
        
        for playbook in self.playbooks.values():
            if self.matches_trigger(playbook, event):
                try:
                    execution = await self.execute_playbook(playbook.id, event)
                    executions.append(execution)
                except Exception as e:
                    logger.error(f"Failed to execute playbook {playbook.id}: {e}")
        
        return executions
    
    def get_executions(self, limit: int = 50, playbook_id: Optional[str] = None) -> List[Dict]:
        """Get playbook executions"""
        execs = self.executions
        
        if playbook_id:
            execs = [e for e in execs if e.playbook_id == playbook_id]
        
        # Return most recent first
        execs = sorted(execs, key=lambda x: x.started_at, reverse=True)[:limit]
        return [asdict(e) for e in execs]
    
    def get_stats(self) -> Dict:
        """Get SOAR statistics"""
        total_playbooks = len(self.playbooks)
        active_playbooks = sum(1 for pb in self.playbooks.values() if pb.status == PlaybookStatus.ACTIVE)
        total_executions = len(self.executions)
        
        successful = sum(1 for e in self.executions if e.status == ExecutionStatus.COMPLETED)
        failed = sum(1 for e in self.executions if e.status == ExecutionStatus.FAILED)
        partial = sum(1 for e in self.executions if e.status == ExecutionStatus.PARTIAL)
        
        # By trigger type
        by_trigger = {}
        for pb in self.playbooks.values():
            trigger = pb.trigger.value
            by_trigger[trigger] = by_trigger.get(trigger, 0) + 1
        
        return {
            "total_playbooks": total_playbooks,
            "active_playbooks": active_playbooks,
            "disabled_playbooks": total_playbooks - active_playbooks,
            "total_executions": total_executions,
            "executions_completed": successful,
            "executions_failed": failed,
            "executions_partial": partial,
            "success_rate": round((successful / total_executions * 100) if total_executions > 0 else 0, 1),
            "by_trigger": by_trigger,
            "available_actions": [a.value for a in PlaybookAction],
            "available_triggers": [t.value for t in PlaybookTrigger]
        }


# Global instance
soar_engine = SOAREngine()
