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
            logger.info("SOAR: Collecting forensics data")
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
            "available_triggers": [t.value for t in PlaybookTrigger],
            "total_templates": len(self.templates)
        }
    
    def _init_templates(self):
        """Initialize playbook templates"""
        templates_data = [
            {
                "id": "tpl_data_breach",
                "name": "Data Breach Response",
                "description": "Comprehensive response to potential data breach",
                "category": "incident_response",
                "trigger": PlaybookTrigger.THREAT_DETECTED,
                "trigger_conditions": {"severity": ["critical"], "type": ["data_exfiltration"]},
                "steps": [
                    PlaybookStep(PlaybookAction.ISOLATE_ENDPOINT, {"network": True}, 30),
                    PlaybookStep(PlaybookAction.COLLECT_FORENSICS, {"memory_dump": True, "disk_image": True}, 300),
                    PlaybookStep(PlaybookAction.DISABLE_USER, {}, 10),
                    PlaybookStep(PlaybookAction.SEND_ALERT, {"channels": ["slack", "email", "sms"], "priority": "critical"}, 30),
                    PlaybookStep(PlaybookAction.CREATE_TICKET, {"category": "data_breach", "escalate": True}, 30)
                ],
                "tags": ["breach", "data", "critical", "compliance"],
                "is_official": True
            },
            {
                "id": "tpl_credential_theft",
                "name": "Credential Theft Response",
                "description": "Response when credential theft is detected",
                "category": "identity",
                "trigger": PlaybookTrigger.IOC_MATCH,
                "trigger_conditions": {"ioc_type": ["credential"], "confidence": ["high"]},
                "steps": [
                    PlaybookStep(PlaybookAction.DISABLE_USER, {"force_logout": True}, 10),
                    PlaybookStep(PlaybookAction.BLOCK_IP, {"duration": 86400}, 30),
                    PlaybookStep(PlaybookAction.COLLECT_FORENSICS, {"auth_logs": True}, 60),
                    PlaybookStep(PlaybookAction.SEND_ALERT, {"channels": ["slack", "email"], "priority": "high"}, 30),
                    PlaybookStep(PlaybookAction.CREATE_TICKET, {"category": "credential_theft"}, 30)
                ],
                "tags": ["identity", "credentials", "authentication"],
                "is_official": True
            },
            {
                "id": "tpl_ddos_mitigation",
                "name": "DDoS Attack Mitigation",
                "description": "Automated response to DDoS attacks",
                "category": "network",
                "trigger": PlaybookTrigger.ANOMALY_DETECTED,
                "trigger_conditions": {"anomaly_type": ["traffic_spike"], "severity": ["high", "critical"]},
                "steps": [
                    PlaybookStep(PlaybookAction.UPDATE_FIREWALL, {"rule_type": "rate_limit"}, 30),
                    PlaybookStep(PlaybookAction.BLOCK_IP, {"duration": 3600, "bulk": True}, 60),
                    PlaybookStep(PlaybookAction.SEND_ALERT, {"channels": ["slack"], "priority": "high"}, 30)
                ],
                "tags": ["network", "ddos", "availability"],
                "is_official": True
            },
            {
                "id": "tpl_insider_threat",
                "name": "Insider Threat Response",
                "description": "Response to potential insider threat activity",
                "category": "insider",
                "trigger": PlaybookTrigger.ANOMALY_DETECTED,
                "trigger_conditions": {"anomaly_type": ["user_behavior"], "confidence": ["high"]},
                "steps": [
                    PlaybookStep(PlaybookAction.COLLECT_FORENSICS, {"user_activity": True, "file_access": True}, 120),
                    PlaybookStep(PlaybookAction.SEND_ALERT, {"channels": ["email"], "priority": "medium", "recipients": ["security@company.com"]}, 30),
                    PlaybookStep(PlaybookAction.CREATE_TICKET, {"category": "insider_threat", "confidential": True}, 30)
                ],
                "tags": ["insider", "user", "behavior"],
                "is_official": True
            },
            {
                "id": "tpl_compliance_violation",
                "name": "Compliance Violation Alert",
                "description": "Alert and document compliance violations",
                "category": "compliance",
                "trigger": PlaybookTrigger.THREAT_DETECTED,
                "trigger_conditions": {"type": ["compliance_violation"]},
                "steps": [
                    PlaybookStep(PlaybookAction.COLLECT_FORENSICS, {"audit_trail": True}, 60),
                    PlaybookStep(PlaybookAction.SEND_ALERT, {"channels": ["email"], "priority": "medium"}, 30),
                    PlaybookStep(PlaybookAction.CREATE_TICKET, {"category": "compliance", "sla": "24h"}, 30)
                ],
                "tags": ["compliance", "audit", "regulatory"],
                "is_official": True
            },
            {
                "id": "tpl_crypto_mining",
                "name": "Cryptomining Detection Response",
                "description": "Response to detected cryptomining activity",
                "category": "malware",
                "trigger": PlaybookTrigger.MALWARE_FOUND,
                "trigger_conditions": {"malware_type": ["cryptominer"]},
                "steps": [
                    PlaybookStep(PlaybookAction.KILL_PROCESS, {"force": True}, 10),
                    PlaybookStep(PlaybookAction.QUARANTINE_FILE, {}, 30),
                    PlaybookStep(PlaybookAction.SCAN_ENDPOINT, {"full_scan": True}, 300),
                    PlaybookStep(PlaybookAction.BLOCK_IP, {"duration": 604800}, 30),
                    PlaybookStep(PlaybookAction.SEND_ALERT, {"channels": ["slack"], "priority": "medium"}, 30)
                ],
                "tags": ["malware", "cryptominer", "resource_abuse"],
                "is_official": True
            }
        ]
        
        for tpl_data in templates_data:
            template = PlaybookTemplate(
                id=tpl_data["id"],
                name=tpl_data["name"],
                description=tpl_data["description"],
                category=tpl_data["category"],
                trigger=tpl_data["trigger"],
                trigger_conditions=tpl_data["trigger_conditions"],
                steps=tpl_data["steps"],
                tags=tpl_data["tags"],
                is_official=tpl_data["is_official"]
            )
            self.templates[template.id] = template
    
    def get_templates(self, category: Optional[str] = None) -> List[Dict]:
        """Get all playbook templates"""
        templates = list(self.templates.values())
        
        if category:
            templates = [t for t in templates if t.category == category]
        
        result = []
        for tpl in templates:
            d = asdict(tpl)
            d["trigger"] = tpl.trigger.value
            d["steps"] = [{"action": s.action.value, "params": s.params, "timeout": s.timeout} for s in tpl.steps]
            result.append(d)
        
        return result
    
    def get_template(self, template_id: str) -> Optional[Dict]:
        """Get a specific template"""
        tpl = self.templates.get(template_id)
        if tpl:
            d = asdict(tpl)
            d["trigger"] = tpl.trigger.value
            d["steps"] = [{"action": s.action.value, "params": s.params, "timeout": s.timeout} for s in tpl.steps]
            return d
        return None
    
    def clone_from_template(self, template_id: str, name: str, created_by: str) -> Dict:
        """Create a new playbook from a template"""
        template = self.templates.get(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")
        
        playbook_id = f"pb_{uuid.uuid4().hex[:8]}"
        
        playbook = Playbook(
            id=playbook_id,
            name=name,
            description=f"Created from template: {template.name}",
            trigger=template.trigger,
            trigger_conditions=template.trigger_conditions.copy(),
            steps=template.steps.copy(),
            created_by=created_by,
            template_id=template_id,
            tags=template.tags.copy()
        )
        
        self.playbooks[playbook_id] = playbook
        template.use_count += 1
        
        return asdict(playbook)
    
    def create_template(self, data: Dict, created_by: str) -> Dict:
        """Create a custom template"""
        template_id = f"tpl_{uuid.uuid4().hex[:8]}"
        
        steps = []
        for step_data in data.get("steps", []):
            steps.append(PlaybookStep(
                action=PlaybookAction(step_data["action"]),
                params=step_data.get("params", {}),
                timeout=step_data.get("timeout", 30),
                continue_on_failure=step_data.get("continue_on_failure", False)
            ))
        
        template = PlaybookTemplate(
            id=template_id,
            name=data["name"],
            description=data.get("description", ""),
            category=data.get("category", "custom"),
            trigger=PlaybookTrigger(data["trigger"]),
            trigger_conditions=data.get("trigger_conditions", {}),
            steps=steps,
            tags=data.get("tags", []),
            is_official=False
        )
        
        self.templates[template_id] = template
        return asdict(template)
    
    def get_template_categories(self) -> List[Dict]:
        """Get all template categories with counts"""
        categories = {}
        for tpl in self.templates.values():
            if tpl.category not in categories:
                categories[tpl.category] = {"name": tpl.category, "count": 0, "templates": []}
            categories[tpl.category]["count"] += 1
            categories[tpl.category]["templates"].append(tpl.name)
        
        return list(categories.values())
    
    # =========================================================================
    # AI-AGENTIC EVENT EVALUATION
    # =========================================================================
    
    async def evaluate_event(self, event: Dict, db=None) -> List[Dict]:
        """
        Evaluate an event against AI-Agentic playbooks.
        Called by the CLI events router for session summaries and deception hits.
        
        Args:
            event: Event dict with event_type, host_id, session_id, etc.
            db: Database instance for logging
            
        Returns:
            List of triggered playbook execution results
        """
        event_type = event.get("event_type")
        results = []
        
        logger.info(f"SOAR: Evaluating event type '{event_type}' for host {event.get('host_id')}")
        
        # Map event types to playbook triggers
        if event_type == "cli.session_summary":
            results = await self._evaluate_session_summary(event, db)
        elif event_type == "deception.hit":
            results = await self._evaluate_deception_hit(event, db)
        
        return results
    
    async def _evaluate_session_summary(self, event: Dict, db=None) -> List[Dict]:
        """Evaluate a CLI session summary against AI-Agentic playbooks"""
        results = []
        host_id = event.get("host_id")
        session_id = event.get("session_id")
        machine_likelihood = event.get("machine_likelihood", 0)
        burstiness = event.get("burstiness_score", 0)
        intents = event.get("dominant_intents", [])
        decoy_touched = event.get("decoy_touched", False)
        tool_switch_ms = event.get("tool_switch_latency_ms", 1000)
        goal_persistence = event.get("goal_persistence", 0)
        
        # Threshold values
        ML_HIGH = 0.80
        ML_CRITICAL = 0.92
        BURST_HIGH = 0.75
        TOOL_SWITCH_FAST = 300
        
        triggered_playbooks = []
        
        # AI-RECON-DEGRADE-01: Machine-paced recon loop
        if (machine_likelihood >= ML_HIGH and 
            "recon" in intents and 
            burstiness >= BURST_HIGH):
            triggered_playbooks.append({
                "playbook_id": "AI-RECON-DEGRADE-01",
                "name": "Machine-Paced Recon Loop — Degrade + Observe",
                "reason": f"ML:{machine_likelihood:.2f} Burst:{burstiness:.2f} Intent:recon"
            })
        
        # AI-CRED-ACCESS-RESP-01: Credential access pattern
        if machine_likelihood >= ML_HIGH and "credential_access" in intents:
            triggered_playbooks.append({
                "playbook_id": "AI-CRED-ACCESS-RESP-01",
                "name": "Credential Access Pattern — Decoy + Credential Controls",
                "reason": f"ML:{machine_likelihood:.2f} Intent:credential_access"
            })
        
        # AI-PIVOT-CONTAIN-01: Fast tool switching + lateral movement
        if (machine_likelihood >= ML_HIGH and 
            tool_switch_ms <= TOOL_SWITCH_FAST and
            goal_persistence >= 0.70 and
            any(i in intents for i in ["lateral_movement", "privilege_escalation"])):
            triggered_playbooks.append({
                "playbook_id": "AI-PIVOT-CONTAIN-01",
                "name": "Autonomous Pivot / Toolchain Switching — Contain Fast",
                "reason": f"ML:{machine_likelihood:.2f} ToolSwitch:{tool_switch_ms}ms Persist:{goal_persistence:.2f}"
            })
        
        # AI-EXFIL-PREP-CUT-01: Exfil preparation
        if machine_likelihood >= ML_HIGH and any(i in intents for i in ["exfil_prep", "data_staging"]):
            triggered_playbooks.append({
                "playbook_id": "AI-EXFIL-PREP-CUT-01",
                "name": "Exfil Prep — Cut Egress + Snapshot",
                "reason": f"ML:{machine_likelihood:.2f} Intent:{intents}"
            })
        
        # AI-HIGHCONF-ERADICATE-01: High confidence + decoy touched
        if machine_likelihood >= ML_CRITICAL and decoy_touched:
            triggered_playbooks.append({
                "playbook_id": "AI-HIGHCONF-ERADICATE-01",
                "name": "High Confidence Agentic Intrusion — Full Containment + Eradication",
                "reason": f"ML:{machine_likelihood:.2f} + DecoyTouched"
            })
        
        # Execute triggered playbooks
        for pb in triggered_playbooks:
            try:
                execution_result = await self._execute_ai_playbook(pb, event, db)
                results.append(execution_result)
                logger.warning(
                    f"SOAR AI Playbook Triggered: {pb['playbook_id']} for {host_id}/{session_id} - {pb['reason']}"
                )
            except Exception as e:
                logger.error(f"SOAR AI Playbook execution failed: {e}")
                results.append({
                    "playbook_id": pb["playbook_id"],
                    "status": "failed",
                    "error": str(e)
                })
        
        return results
    
    async def _evaluate_deception_hit(self, event: Dict, db=None) -> List[Dict]:
        """Evaluate a deception/honey token hit"""
        results = []
        severity = event.get("severity", "medium")
        
        if severity in ["high", "critical"]:
            pb = {
                "playbook_id": "AI-DECOY-HIT-CONTAIN-01",
                "name": "Decoy/Honey Token Hit — Immediate Containment",
                "reason": f"Severity:{severity} Token:{event.get('token_id')}"
            }
            
            try:
                execution_result = await self._execute_ai_playbook(pb, event, db)
                results.append(execution_result)
                logger.critical(
                    f"SOAR Deception Hit: {pb['playbook_id']} for {event.get('host_id')} - {pb['reason']}"
                )
            except Exception as e:
                logger.error(f"SOAR Deception playbook failed: {e}")
                results.append({
                    "playbook_id": pb["playbook_id"],
                    "status": "failed",
                    "error": str(e)
                })
        
        return results
    
    async def _execute_ai_playbook(self, playbook_info: Dict, event: Dict, db=None) -> Dict:
        """
        Execute an AI-Agentic playbook and create agent commands.
        
        This creates commands in the agent_commands collection for manual approval.
        """
        import uuid
        
        playbook_id = playbook_info["playbook_id"]
        host_id = event.get("host_id")
        session_id = event.get("session_id")
        
        execution_id = f"ai_exec_{uuid.uuid4().hex[:12]}"
        actions_created = []
        
        # Define actions for each playbook
        playbook_actions = {
            "AI-RECON-DEGRADE-01": [
                {"action": "tag_session", "params": {"tags": ["ai_suspected", "recon"]}},
                {"action": "throttle_cli", "params": {"rate_per_min": 20, "mode": "soft"}},
                {"action": "inject_latency", "params": {"delay_ms": 250, "jitter_ms": 200, "mode": "soft"}},
                {"action": "capture_triage_bundle", "params": {"window_s": 30}}
            ],
            "AI-DECOY-HIT-CONTAIN-01": [
                {"action": "isolate_host", "params": {"block_network": True}},
                {"action": "capture_triage_bundle", "params": {"window_s": 300}},
                {"action": "kill_process_tree", "params": {"mode": "force"}}
            ],
            "AI-CRED-ACCESS-RESP-01": [
                {"action": "throttle_cli", "params": {"rate_per_min": 10, "mode": "hard"}},
                {"action": "inject_latency", "params": {"delay_ms": 600, "jitter_ms": 400, "mode": "hard"}},
                {"action": "capture_triage_bundle", "params": {"window_s": 180}}
            ],
            "AI-PIVOT-CONTAIN-01": [
                {"action": "isolate_host", "params": {"block_network": True}},
                {"action": "capture_triage_bundle", "params": {"window_s": 300}}
            ],
            "AI-EXFIL-PREP-CUT-01": [
                {"action": "isolate_host", "params": {"block_network": True}},
                {"action": "capture_triage_bundle", "params": {"window_s": 600}}
            ],
            "AI-HIGHCONF-ERADICATE-01": [
                {"action": "isolate_host", "params": {"block_network": True}},
                {"action": "kill_process_tree", "params": {"mode": "force"}},
                {"action": "capture_memory_snapshot", "params": {"mode": "quick"}},
                {"action": "capture_triage_bundle", "params": {"window_s": 900}}
            ]
        }
        
        actions = playbook_actions.get(playbook_id, [])
        
        # Create agent commands for each action (requires manual approval)
        if db is not None:
            for action in actions:
                command_id = str(uuid.uuid4())[:12]
                command = {
                    "command_id": command_id,
                    "agent_id": host_id,
                    "command_type": action["action"],
                    "command_name": f"AI Playbook: {action['action']}",
                    "parameters": {
                        **action["params"],
                        "session_id": session_id,
                        "playbook_id": playbook_id,
                        "execution_id": execution_id
                    },
                    "priority": "critical" if "isolate" in action["action"] else "high",
                    "risk_level": "high",
                    "status": "pending_approval",
                    "created_by": f"SOAR:{playbook_id}",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "source": "ai_agentic_playbook",
                    "playbook_info": playbook_info
                }
                
                await db.agent_commands.insert_one(command)
                actions_created.append(command_id)
        
        # Log the execution
        execution_result = {
            "execution_id": execution_id,
            "playbook_id": playbook_id,
            "playbook_name": playbook_info["name"],
            "trigger_reason": playbook_info["reason"],
            "host_id": host_id,
            "session_id": session_id,
            "status": "commands_queued",
            "commands_created": actions_created,
            "executed_at": datetime.now(timezone.utc).isoformat()
        }
        
        if db:
            await db.soar_executions.insert_one({
                **execution_result,
                "event": event
            })
        
        # Store in memory
        self.executions.append(PlaybookExecution(
            id=execution_id,
            playbook_id=playbook_id,
            playbook_name=playbook_info["name"],
            trigger_event=event,
            status=ExecutionStatus.COMPLETED,
            started_at=datetime.now(timezone.utc).isoformat(),
            completed_at=datetime.now(timezone.utc).isoformat()
        ))
        
        return execution_result


# Global instance
soar_engine = SOAREngine()
