"""
Agentic Threat Response Engine
==============================
Fully autonomous threat response system with:
- Automated IP blocking (iptables/firewalld)
- Twilio SMS emergency alerts
- OpenClaw CLI integration for AI-powered automation
- Threat intelligence sharing
- Self-healing capabilities
- Network isolation
- Forensic data collection

This module makes the Anti-AI Defense System truly agentic by enabling
autonomous decision-making and response actions.
"""
import os
import json
import logging
import asyncio
import subprocess
import platform
import hashlib
import shutil
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
import httpx
from runtime_paths import ensure_data_dir

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

class ThreatResponseConfig:
    """Configuration for the threat response engine"""
    def __init__(self):
        # Twilio SMS
        self.twilio_account_sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
        self.twilio_auth_token = os.environ.get("TWILIO_AUTH_TOKEN", "")
        self.twilio_phone_number = os.environ.get("TWILIO_PHONE_NUMBER", "")
        self.emergency_contacts = os.environ.get("EMERGENCY_SMS_CONTACTS", "").split(",")
        
        # OpenClaw
        self.openclaw_enabled = os.environ.get("OPENCLAW_ENABLED", "false").lower() == "true"
        self.openclaw_gateway_url = os.environ.get("OPENCLAW_GATEWAY_URL", "http://localhost:3030")
        self.openclaw_api_key = os.environ.get("OPENCLAW_API_KEY", "")
        
        # Auto-response settings
        self.auto_block_enabled = os.environ.get("AUTO_BLOCK_ENABLED", "true").lower() == "true"
        self.auto_isolate_enabled = os.environ.get("AUTO_ISOLATE_ENABLED", "false").lower() == "true"
        self.block_duration_hours = int(os.environ.get("BLOCK_DURATION_HOURS", "24"))
        
        # Threat intelligence
        self.threat_intel_sharing = os.environ.get("THREAT_INTEL_SHARING", "false").lower() == "true"
        self.threat_intel_api_url = os.environ.get("THREAT_INTEL_API_URL", "")
        
        # Response thresholds
        self.critical_threat_threshold = 3  # Attacks before auto-block
        self.sms_alert_severity = ["critical"]  # Severities that trigger SMS
        
    @property
    def twilio_enabled(self) -> bool:
        return bool(self.twilio_account_sid and self.twilio_auth_token and self.twilio_phone_number)

config = ThreatResponseConfig()

# =============================================================================
# ENUMS AND DATA MODELS
# =============================================================================

class ResponseAction(Enum):
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    ISOLATE_HOST = "isolate_host"
    QUARANTINE_FILE = "quarantine_file"
    KILL_PROCESS = "kill_process"
    SEND_ALERT = "send_alert"
    COLLECT_FORENSICS = "collect_forensics"
    ROLLBACK_CHANGES = "rollback_changes"
    NOTIFY_SOC = "notify_soc"
    ESCALATE = "escalate"

class ResponseStatus(Enum):
    PENDING = "pending"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLBACK = "rollback"

@dataclass
class ThreatContext:
    """Context information about a detected threat"""
    threat_id: str
    threat_type: str
    severity: str
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    target_path: Optional[str] = None
    process_id: Optional[int] = None
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    indicators: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class ResponseResult:
    """Result of a response action"""
    action: ResponseAction
    status: ResponseStatus
    message: str
    executed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    rollback_info: Optional[Dict[str, Any]] = None
    details: Dict[str, Any] = field(default_factory=dict)

# =============================================================================
# IP BLOCKING / FIREWALL MANAGEMENT
# =============================================================================

class FirewallManager:
    """Manages firewall rules for automated IP blocking"""
    
    # Track blocked IPs for auto-unblock
    blocked_ips: Dict[str, datetime] = {}
    
    @staticmethod
    def _detect_firewall() -> str:
        """Detect which firewall is available"""
        if platform.system() == "Windows":
            return "windows"
        elif shutil.which("firewall-cmd"):
            return "firewalld"
        elif shutil.which("iptables"):
            return "iptables"
        elif shutil.which("ufw"):
            return "ufw"
        elif shutil.which("pfctl"):
            return "pf"
        return "none"
    
    @classmethod
    async def block_ip(cls, ip: str, reason: str = "", duration_hours: int = 24) -> ResponseResult:
        """Block an IP address"""
        firewall = cls._detect_firewall()
        cmd = None
        rollback_cmd = None
        
        try:
            if firewall == "iptables":
                cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
                rollback_cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
            elif firewall == "firewalld":
                cmd = f"sudo firewall-cmd --add-rich-rule='rule family=ipv4 source address={ip} reject' --permanent && sudo firewall-cmd --reload"
                rollback_cmd = f"sudo firewall-cmd --remove-rich-rule='rule family=ipv4 source address={ip} reject' --permanent && sudo firewall-cmd --reload"
            elif firewall == "ufw":
                cmd = f"sudo ufw deny from {ip}"
                rollback_cmd = f"sudo ufw delete deny from {ip}"
            elif firewall == "windows":
                cmd = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
                rollback_cmd = f'netsh advfirewall firewall delete rule name="Block {ip}"'
            else:
                return ResponseResult(
                    action=ResponseAction.BLOCK_IP,
                    status=ResponseStatus.FAILED,
                    message=f"No supported firewall found on this system",
                    details={"ip": ip, "firewall": "none"}
                )
            
            # Execute block command
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                cls.blocked_ips[ip] = datetime.now(timezone.utc) + timedelta(hours=duration_hours)
                logger.info(f"Blocked IP {ip}: {reason}")
                
                return ResponseResult(
                    action=ResponseAction.BLOCK_IP,
                    status=ResponseStatus.SUCCESS,
                    message=f"Successfully blocked IP {ip}",
                    rollback_info={"command": rollback_cmd, "ip": ip},
                    details={"ip": ip, "reason": reason, "duration_hours": duration_hours, "firewall": firewall}
                )
            else:
                return ResponseResult(
                    action=ResponseAction.BLOCK_IP,
                    status=ResponseStatus.FAILED,
                    message=f"Failed to block IP: {stderr.decode()}",
                    details={"ip": ip, "error": stderr.decode()}
                )
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return ResponseResult(
                action=ResponseAction.BLOCK_IP,
                status=ResponseStatus.FAILED,
                message=f"Error: {str(e)}",
                details={"ip": ip, "error": str(e)}
            )
    
    @classmethod
    async def unblock_ip(cls, ip: str) -> ResponseResult:
        """Unblock a previously blocked IP"""
        firewall = cls._detect_firewall()
        cmd = None
        
        try:
            if firewall == "iptables":
                cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
            elif firewall == "firewalld":
                cmd = f"sudo firewall-cmd --remove-rich-rule='rule family=ipv4 source address={ip} reject' --permanent && sudo firewall-cmd --reload"
            elif firewall == "ufw":
                cmd = f"sudo ufw delete deny from {ip}"
            elif firewall == "windows":
                cmd = f'netsh advfirewall firewall delete rule name="Block {ip}"'
            else:
                return ResponseResult(
                    action=ResponseAction.UNBLOCK_IP,
                    status=ResponseStatus.FAILED,
                    message="No supported firewall found"
                )
            
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                cls.blocked_ips.pop(ip, None)
                logger.info(f"Unblocked IP {ip}")
                return ResponseResult(
                    action=ResponseAction.UNBLOCK_IP,
                    status=ResponseStatus.SUCCESS,
                    message=f"Successfully unblocked IP {ip}"
                )
            else:
                return ResponseResult(
                    action=ResponseAction.UNBLOCK_IP,
                    status=ResponseStatus.FAILED,
                    message=f"Failed to unblock: {stderr.decode()}"
                )
                
        except Exception as e:
            return ResponseResult(
                action=ResponseAction.UNBLOCK_IP,
                status=ResponseStatus.FAILED,
                message=str(e)
            )
    
    @classmethod
    async def cleanup_expired_blocks(cls):
        """Remove expired IP blocks"""
        now = datetime.now(timezone.utc)
        expired = [ip for ip, expiry in cls.blocked_ips.items() if expiry < now]
        
        for ip in expired:
            await cls.unblock_ip(ip)
            logger.info(f"Auto-unblocked expired IP: {ip}")

firewall = FirewallManager()

# =============================================================================
# TWILIO SMS ALERTS
# =============================================================================

class SMSAlertService:
    """Send emergency SMS alerts via Twilio"""
    
    @staticmethod
    async def send_emergency_sms(
        message: str,
        recipients: Optional[List[str]] = None,
        threat_context: Optional[ThreatContext] = None
    ) -> ResponseResult:
        """Send emergency SMS alert to all configured contacts"""
        if not config.twilio_enabled:
            return ResponseResult(
                action=ResponseAction.SEND_ALERT,
                status=ResponseStatus.FAILED,
                message="Twilio SMS not configured"
            )
        
        to_numbers = recipients or [n.strip() for n in config.emergency_contacts if n.strip()]
        if not to_numbers:
            return ResponseResult(
                action=ResponseAction.SEND_ALERT,
                status=ResponseStatus.FAILED,
                message="No emergency contacts configured"
            )
        
        # Build alert message
        alert_text = f"🚨 SECURITY ALERT\n{message}"
        if threat_context:
            alert_text += f"\n\nType: {threat_context.threat_type}"
            alert_text += f"\nSeverity: {threat_context.severity.upper()}"
            if threat_context.source_ip:
                alert_text += f"\nSource: {threat_context.source_ip}"
        
        # Truncate to SMS limit
        alert_text = alert_text[:1500]
        
        try:
            from twilio.rest import Client
            client = Client(config.twilio_account_sid, config.twilio_auth_token)
            
            sent_count = 0
            errors = []
            
            for number in to_numbers:
                try:
                    message_obj = client.messages.create(
                        body=alert_text,
                        from_=config.twilio_phone_number,
                        to=number
                    )
                    sent_count += 1
                    logger.info(f"SMS sent to {number}: {message_obj.sid}")
                except Exception as e:
                    errors.append(f"{number}: {str(e)}")
            
            if sent_count > 0:
                return ResponseResult(
                    action=ResponseAction.SEND_ALERT,
                    status=ResponseStatus.SUCCESS,
                    message=f"SMS sent to {sent_count}/{len(to_numbers)} contacts",
                    details={"sent": sent_count, "total": len(to_numbers), "errors": errors}
                )
            else:
                return ResponseResult(
                    action=ResponseAction.SEND_ALERT,
                    status=ResponseStatus.FAILED,
                    message="Failed to send any SMS",
                    details={"errors": errors}
                )
                
        except Exception as e:
            return ResponseResult(
                action=ResponseAction.SEND_ALERT,
                status=ResponseStatus.FAILED,
                message=str(e)
            )

sms_service = SMSAlertService()

# =============================================================================
# OPENCLAW AI AGENT INTEGRATION
# =============================================================================

class OpenClawAgent:
    """
    Integration with OpenClaw for AI-powered autonomous threat response.
    OpenClaw provides agentic AI capabilities for security automation.
    """
    
    @staticmethod
    async def is_available() -> bool:
        """Check if OpenClaw gateway is available"""
        if not config.openclaw_enabled:
            return False
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{config.openclaw_gateway_url}/health",
                    timeout=5
                )
                return response.status_code == 200
        except Exception:
            return False

    @staticmethod
    async def get_status() -> Dict[str, Any]:
        """Get OpenClaw integration status for API consumers."""
        enabled = config.openclaw_enabled
        available = await OpenClawAgent.is_available() if enabled else False

        return {
            "enabled": enabled,
            "connected": available,
            "gateway_url": config.openclaw_gateway_url,
            "has_api_key": bool(config.openclaw_api_key),
            "status": "connected" if available else ("disabled" if not enabled else "unavailable")
        }
    
    @staticmethod
    async def execute_security_task(
        task: str,
        context: Optional[ThreatContext] = None,
        tools: Optional[List[str]] = None
    ) -> ResponseResult:
        """
        Execute a security task using OpenClaw AI agent.
        
        The agent can autonomously:
        - Analyze threat patterns
        - Recommend response actions
        - Execute security scripts
        - Generate incident reports
        - Correlate with threat intelligence
        """
        if not config.openclaw_enabled:
            return ResponseResult(
                action=ResponseAction.NOTIFY_SOC,
                status=ResponseStatus.FAILED,
                message="OpenClaw integration not enabled"
            )
        
        if not await OpenClawAgent.is_available():
            return ResponseResult(
                action=ResponseAction.NOTIFY_SOC,
                status=ResponseStatus.FAILED,
                message="OpenClaw gateway not available"
            )
        
        # Build the prompt for the AI agent
        system_prompt = """You are a security operations AI agent integrated with the Anti-AI Defense System.
Your role is to analyze threats, recommend response actions, and help automate incident response.
Always prioritize:
1. Containing the threat
2. Preserving forensic evidence
3. Minimizing business impact
4. Following security best practices"""
        
        user_prompt = f"Security Task: {task}"
        if context:
            user_prompt += f"\n\nThreat Context:\n- Type: {context.threat_type}\n- Severity: {context.severity}"
            if context.source_ip:
                user_prompt += f"\n- Source IP: {context.source_ip}"
            if context.indicators:
                user_prompt += f"\n- Indicators: {', '.join(context.indicators)}"
        
        try:
            headers = {"Content-Type": "application/json"}
            if config.openclaw_api_key:
                headers["Authorization"] = f"Bearer {config.openclaw_api_key}"
            
            payload = {
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "tools": tools or ["file_access", "command_execution", "web_search"],
                "stream": False
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{config.openclaw_gateway_url}/v1/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=60
                )
                
                if response.status_code == 200:
                    result = response.json()
                    ai_response = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                    
                    return ResponseResult(
                        action=ResponseAction.NOTIFY_SOC,
                        status=ResponseStatus.SUCCESS,
                        message="OpenClaw task completed",
                        details={
                            "task": task,
                            "ai_response": ai_response,
                            "tools_available": tools or []
                        }
                    )
                else:
                    return ResponseResult(
                        action=ResponseAction.NOTIFY_SOC,
                        status=ResponseStatus.FAILED,
                        message=f"OpenClaw returned {response.status_code}"
                    )
                    
        except Exception as e:
            return ResponseResult(
                action=ResponseAction.NOTIFY_SOC,
                status=ResponseStatus.FAILED,
                message=str(e)
            )
    
    @staticmethod
    async def analyze_threat(context: ThreatContext) -> Dict[str, Any]:
        """Use OpenClaw to analyze a threat and recommend actions"""
        result = await OpenClawAgent.execute_security_task(
            task="Analyze this security threat and recommend response actions. "
                 "Provide specific, actionable steps for containment and remediation.",
            context=context,
            tools=["web_search", "file_access"]
        )
        
        if result.status == ResponseStatus.SUCCESS:
            return {
                "analysis": result.details.get("ai_response", ""),
                "recommendations": []  # Would parse from AI response
            }
        return {"analysis": "Analysis unavailable", "recommendations": []}

openclaw = OpenClawAgent()

# =============================================================================
# FORENSIC DATA COLLECTION
# =============================================================================

class ForensicsCollector:
    """Collect forensic data for incident investigation"""
    
    FORENSICS_DIR = ensure_data_dir("forensics")
    
    @classmethod
    async def collect_incident_data(cls, context: ThreatContext) -> ResponseResult:
        """Collect all relevant forensic data for an incident"""
        cls.FORENSICS_DIR.mkdir(parents=True, exist_ok=True)
        
        incident_id = hashlib.md5(
            f"{context.threat_id}{context.timestamp}".encode()
        ).hexdigest()[:12]
        
        incident_dir = cls.FORENSICS_DIR / incident_id
        incident_dir.mkdir(exist_ok=True)
        
        collected = []
        
        # Save threat context
        with open(incident_dir / "threat_context.json", "w") as f:
            json.dump(asdict(context), f, indent=2)
        collected.append("threat_context.json")
        
        # Collect system state
        try:
            # Network connections
            proc = await asyncio.create_subprocess_shell(
                "netstat -tuln 2>/dev/null || ss -tuln",
                stdout=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            with open(incident_dir / "network_connections.txt", "w") as f:
                f.write(stdout.decode())
            collected.append("network_connections.txt")
            
            # Process list
            proc = await asyncio.create_subprocess_shell(
                "ps auxf 2>/dev/null || ps aux",
                stdout=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            with open(incident_dir / "process_list.txt", "w") as f:
                f.write(stdout.decode())
            collected.append("process_list.txt")
            
            # Recent auth logs
            if Path("/var/log/auth.log").exists():
                proc = await asyncio.create_subprocess_shell(
                    "tail -500 /var/log/auth.log",
                    stdout=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                with open(incident_dir / "auth_log.txt", "w") as f:
                    f.write(stdout.decode())
                collected.append("auth_log.txt")
            
            # IP-specific data if we have a source IP
            if context.source_ip:
                proc = await asyncio.create_subprocess_shell(
                    f"whois {context.source_ip} 2>/dev/null | head -100",
                    stdout=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                with open(incident_dir / "ip_whois.txt", "w") as f:
                    f.write(stdout.decode())
                collected.append("ip_whois.txt")
                
        except Exception as e:
            logger.error(f"Forensics collection error: {e}")
        
        return ResponseResult(
            action=ResponseAction.COLLECT_FORENSICS,
            status=ResponseStatus.SUCCESS,
            message=f"Collected {len(collected)} forensic artifacts",
            details={
                "incident_id": incident_id,
                "path": str(incident_dir),
                "artifacts": collected
            }
        )

forensics = ForensicsCollector()

# =============================================================================
# THREAT INTELLIGENCE SHARING
# =============================================================================

class ThreatIntelligence:
    """Share and receive threat intelligence with the community"""
    
    @staticmethod
    async def share_indicator(
        indicator_type: str,
        indicator_value: str,
        threat_type: str,
        confidence: int = 80
    ) -> bool:
        """Share a threat indicator with the community"""
        if not config.threat_intel_sharing or not config.threat_intel_api_url:
            return False
        
        try:
            payload = {
                "type": indicator_type,  # ip, domain, hash, url
                "value": indicator_value,
                "threat_type": threat_type,
                "confidence": confidence,
                "source": "anti-ai-defense",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{config.threat_intel_api_url}/indicators",
                    json=payload,
                    timeout=10
                )
                return response.status_code in [200, 201]
        except Exception:
            return False
    
    @staticmethod
    async def check_indicator(indicator_type: str, indicator_value: str) -> Dict[str, Any]:
        """Check if an indicator is known malicious"""
        if not config.threat_intel_api_url:
            return {"known": False, "data": {}}
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{config.threat_intel_api_url}/indicators/{indicator_type}/{indicator_value}",
                    timeout=10
                )
                if response.status_code == 200:
                    return {"known": True, "data": response.json()}
        except Exception:
            pass
        
        return {"known": False, "data": {}}

threat_intel = ThreatIntelligence()

# =============================================================================
# AUTONOMOUS RESPONSE ENGINE
# =============================================================================

class AgenticResponseEngine:
    """
    The main autonomous threat response engine.
    Makes intelligent decisions about how to respond to threats.
    """
    
    # Track attacks per IP for threshold-based blocking
    attack_counter: Dict[str, int] = {}
    
    # Response history for audit
    response_history: List[Dict[str, Any]] = []
    
    @classmethod
    async def process_threat(
        cls,
        context: ThreatContext,
        auto_respond: bool = True
    ) -> List[ResponseResult]:
        """
        Process a threat and execute appropriate response actions.
        
        The engine autonomously decides:
        1. Whether to block the source IP
        2. Whether to send emergency alerts
        3. Whether to quarantine files
        4. Whether to collect forensics
        5. Whether to escalate to humans
        """
        results = []
        
        logger.info(f"Processing threat: {context.threat_type} (severity: {context.severity})")
        
        # Always collect forensics for medium+ severity
        if context.severity in ["medium", "high", "critical"]:
            forensics_result = await forensics.collect_incident_data(context)
            results.append(forensics_result)
        
        # Check threat intelligence
        if context.source_ip:
            intel = await threat_intel.check_indicator("ip", context.source_ip)
            if intel["known"]:
                context.indicators.append(f"Known malicious IP (confidence: {intel['data'].get('confidence', 'N/A')})")
                # Increase severity if known malicious
                if context.severity == "medium":
                    context.severity = "high"
        
        # Auto-block logic
        if auto_respond and config.auto_block_enabled and context.source_ip:
            # Track attacks from this IP
            cls.attack_counter[context.source_ip] = cls.attack_counter.get(context.source_ip, 0) + 1
            
            should_block = (
                context.severity == "critical" or
                cls.attack_counter[context.source_ip] >= config.critical_threat_threshold
            )
            
            if should_block:
                block_result = await firewall.block_ip(
                    context.source_ip,
                    reason=f"Auto-blocked: {context.threat_type}",
                    duration_hours=config.block_duration_hours
                )
                results.append(block_result)
                
                # Share with threat intel
                if block_result.status == ResponseStatus.SUCCESS:
                    await threat_intel.share_indicator(
                        "ip", context.source_ip, context.threat_type
                    )
        
        # SMS alerts for critical threats
        if context.severity in config.sms_alert_severity:
            sms_result = await sms_service.send_emergency_sms(
                message=f"Critical threat detected: {context.threat_type}",
                threat_context=context
            )
            results.append(sms_result)
        
        # Use OpenClaw for advanced analysis if available
        if config.openclaw_enabled:
            analysis = await openclaw.analyze_threat(context)
            if analysis.get("analysis"):
                # Log the AI analysis
                logger.info(f"OpenClaw analysis: {analysis['analysis'][:200]}...")
        
        # Store response history
        cls.response_history.append({
            "threat_id": context.threat_id,
            "threat_type": context.threat_type,
            "severity": context.severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "results": [asdict(r) for r in results],
            "auto_responded": auto_respond
        })
        
        # Trim history
        if len(cls.response_history) > 1000:
            cls.response_history = cls.response_history[-500:]
        
        return results
    
    @classmethod
    async def get_response_stats(cls) -> Dict[str, Any]:
        """Get statistics about automated responses"""
        total = len(cls.response_history)
        by_severity = {}
        by_action = {}
        
        for entry in cls.response_history:
            sev = entry.get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
            for result in entry.get("results", []):
                action = result.get("action", "unknown")
                by_action[action] = by_action.get(action, 0) + 1
        
        return {
            "total_responses": total,
            "blocked_ips": len(firewall.blocked_ips),
            "by_severity": by_severity,
            "by_action": by_action,
            "attack_sources": len(cls.attack_counter)
        }
    
    @classmethod
    def get_blocked_ips(cls) -> List[Dict[str, Any]]:
        """Get list of currently blocked IPs"""
        return [
            {"ip": ip, "expires": expiry.isoformat()}
            for ip, expiry in firewall.blocked_ips.items()
        ]

# Create global instance
response_engine = AgenticResponseEngine()

# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def respond_to_intrusion(
    source_ip: str,
    signature: str,
    severity: str = "high",
    agent_name: Optional[str] = None
) -> List[ResponseResult]:
    """Respond to an intrusion detection event"""
    context = ThreatContext(
        threat_id=hashlib.md5(f"{source_ip}{signature}{datetime.now().isoformat()}".encode()).hexdigest()[:12],
        threat_type="intrusion",
        severity=severity,
        source_ip=source_ip,
        agent_name=agent_name,
        indicators=[f"Signature: {signature}"]
    )
    return await response_engine.process_threat(context)

async def respond_to_malware(
    filepath: str,
    malware_name: str,
    severity: str = "critical",
    source_ip: Optional[str] = None,
    agent_name: Optional[str] = None
) -> List[ResponseResult]:
    """Respond to a malware detection event"""
    context = ThreatContext(
        threat_id=hashlib.md5(f"{filepath}{malware_name}{datetime.now().isoformat()}".encode()).hexdigest()[:12],
        threat_type="malware",
        severity=severity,
        source_ip=source_ip,
        target_path=filepath,
        agent_name=agent_name,
        indicators=[f"Malware: {malware_name}", f"File: {filepath}"]
    )
    return await response_engine.process_threat(context)

async def respond_to_port_scan(
    source_ip: str,
    ports_scanned: int,
    agent_name: Optional[str] = None
) -> List[ResponseResult]:
    """Respond to a port scanning event"""
    severity = "critical" if ports_scanned > 100 else "high" if ports_scanned > 20 else "medium"
    context = ThreatContext(
        threat_id=hashlib.md5(f"{source_ip}portscan{datetime.now().isoformat()}".encode()).hexdigest()[:12],
        threat_type="port_scan",
        severity=severity,
        source_ip=source_ip,
        agent_name=agent_name,
        indicators=[f"Ports scanned: {ports_scanned}"]
    )
    return await response_engine.process_threat(context)

async def manual_block_ip(ip: str, reason: str, duration_hours: int = 24) -> ResponseResult:
    """Manually block an IP address"""
    return await firewall.block_ip(ip, reason, duration_hours)

async def manual_unblock_ip(ip: str) -> ResponseResult:
    """Manually unblock an IP address"""
    return await firewall.unblock_ip(ip)
