"""
Metatron/Seraph Unified Security Agent - Core Module v2.0
=========================================================
Cross-platform security agent with advanced threat detection,
AI reasoning, SIEM integration, and enterprise security features.

Combines:
- Metatron's cross-platform architecture
- Seraph's advanced security features (VNS, AI, Quantum, SIEM)
- Aggressive auto-kill capabilities
- Network scanning (Port, WiFi, Bluetooth)
- Cuckoo sandbox integration
- USB device monitoring

Supports: Windows, macOS, Linux, Android (Termux), iOS (Pythonista)
"""

import os
import sys
import json
import uuid
import time
import socket
import hashlib
import logging
import platform
import threading
import subprocess
import re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple, Set
from dataclasses import dataclass, field, asdict
from collections import deque, defaultdict
from abc import ABC, abstractmethod
from enum import Enum

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('metatron.core')

# Agent identification
AGENT_VERSION = "2.0.0"
HOSTNAME = socket.gethostname()
PLATFORM = platform.system().lower()

# Directories
if PLATFORM == "windows":
    INSTALL_DIR = Path(os.environ.get('LOCALAPPDATA', 'C:/SeraphDefender')) / "SeraphDefender"
else:
    INSTALL_DIR = Path.home() / ".seraph-defender"

DATA_DIR = INSTALL_DIR / "data"
LOGS_DIR = INSTALL_DIR / "logs"
QUARANTINE_DIR = INSTALL_DIR / "quarantine"

for d in [INSTALL_DIR, DATA_DIR, LOGS_DIR, QUARANTINE_DIR]:
    d.mkdir(parents=True, exist_ok=True)


class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# THREAT INTELLIGENCE DATABASE
# =============================================================================

class ThreatIntelligence:
    """Known malicious indicators"""
    
    MALICIOUS_IPS = {
        "185.220.101.", "45.33.32.", "198.51.100.", "203.0.113.",
    }
    
    SUSPICIOUS_PORTS = {
        4444: "Metasploit default", 5555: "Android ADB", 6666: "IRC botnet",
        6667: "IRC botnet", 31337: "Back Orifice", 12345: "NetBus",
        27374: "SubSeven", 1234: "Common backdoor", 9001: "Tor",
        9050: "Tor SOCKS", 4443: "Common C2", 8443: "Alt HTTPS",
        3389: "RDP", 5900: "VNC", 5800: "VNC HTTP",
    }
    
    MALICIOUS_DOMAINS = [
        r".*\.onion$", r".*\.bit$", r".*dyndns.*", r".*no-ip.*",
        r".*\.tk$", r".*\.ml$", r".*\.ga$", r".*\.cf$",
        r".*pastebin\.com.*", r".*ngrok\.io.*",
    ]
    
    MALICIOUS_PROCESSES = [
        'mimikatz', 'lazagne', 'procdump', 'pwdump', 'fgdump',
        'gsecdump', 'wce', 'nc.exe', 'ncat.exe', 'netcat',
        'psexec', 'paexec', 'crackmapexec', 'bloodhound',
        'sharphound', 'rubeus', 'kerberoast', 'responder',
        'impacket', 'empire', 'covenant', 'cobalt',
        'meterpreter', 'beacon', 'sliver', 'mythic',
        'cryptolocker', 'wannacry', 'petya', 'ryuk',
        'conti', 'lockbit', 'revil', 'darkside',
        'xmrig', 'minerd', 'cgminer', 'bfgminer',
    ]
    
    MALICIOUS_COMMANDS = [
        r'powershell.*-enc', r'powershell.*downloadstring',
        r'powershell.*iex', r'certutil.*-urlcache',
        r'bitsadmin.*\/transfer', r'mshta.*http',
        r'regsvr32.*\/s.*\/u.*\/i:http', r'rundll32.*javascript',
        r'wmic.*process.*call.*create', r'net.*user.*\/add',
        r'net.*localgroup.*administrators', r'reg.*add.*run',
        r'schtasks.*\/create', r'sc.*create',
        r'whoami.*\/priv', r'mimikatz', r'sekurlsa', r'lsadump',
        r'base64.*-d.*\|.*bash', r'curl.*\|.*bash',
        r'wget.*\|.*bash', r'python.*-c.*import.*socket',
        r'nc.*-e.*\/bin', r'bash.*-i.*>&.*\/dev\/tcp',
    ]
    
    EXFIL_PATTERNS = [
        r'curl.*-d.*@', r'curl.*--data-binary', r'wget.*--post-file',
        r'scp.*@.*:', r'rsync.*@.*:', r'ftp.*put', r'rclone.*copy',
    ]
    
    # Critical patterns that ALWAYS trigger auto-kill
    CRITICAL_PATTERNS = [
        'mimikatz', 'lazagne', 'credential', 'lsass', 'sekurlsa',
        'procdump', 'gsecdump', 'pwdump', 'fgdump', 'wce',
        'ntdsutil', 'secretsdump', 'ransomware', 'cryptolocker',
        'wannacry', 'petya', 'locky', 'cerber', 'ryuk',
        'sodinokibi', 'revil', 'lockbit', 'conti', 'blackmatter',
        'encrypt', '.crypt', '.locked', '.encrypted',
        'wiper', 'format c:', 'del /f /s /q', 'rm -rf',
        'dd if=/dev/zero', 'diskpart', 'clean all', 'cipher /w',
        'reverse shell', 'meterpreter', 'beacon', 'cobalt',
        'covenant', 'empire', 'sliver', 'brute ratel', 'havoc',
        'mythic', 'nighthawk', 'netcat', 'nc -e', 'ncat -e',
        'psexec', 'wmiexec', 'smbexec', 'atexec', 'dcomexec',
        'pass the hash', 'pass-the-hash', 'pth-', 'overpass',
        'golden ticket', 'silver ticket', 'getsystem',
        'privilege::debug', 'token::elevate', 'uac bypass',
        'exfiltrat', 'megasync', 'rclone', 'winscp -script',
        'keylog', 'keyboard hook', 'getasynckeystate',
        'process hollowing', 'dll injection', 'reflective',
        'shellcode', 'createremotethread', 'ntqueueapcthread',
        'xmrig', 'cryptonight', 'stratum+tcp', 'minerd',
    ]
    
    # Process names to IMMEDIATELY kill
    INSTANT_KILL_PROCESSES = {
        'mimikatz.exe', 'lazagne.exe', 'procdump.exe', 'gsecdump.exe',
        'pwdump.exe', 'wce.exe', 'xmrig.exe', 'minerd.exe', 'cgminer.exe',
        'netcat.exe', 'nc.exe', 'ncat.exe', 'psexec.exe', 'paexec.exe',
        'cobaltstrike.exe', 'beacon.exe', 'meterpreter.exe',
    }


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class AgentConfig:
    """Agent configuration"""
    server_url: str = ""
    agent_id: str = ""
    agent_name: str = ""
    update_interval: int = 30
    heartbeat_interval: int = 60
    auto_remediate: bool = True
    severity_auto_kill: List[str] = field(default_factory=lambda: ["critical", "high"])
    
    # Feature toggles
    network_scanning: bool = True
    process_monitoring: bool = True
    file_scanning: bool = True
    wireless_scanning: bool = True
    bluetooth_scanning: bool = True
    usb_monitoring: bool = True
    
    # Advanced features
    vns_sync: bool = True
    ai_analysis: bool = True
    siem_integration: bool = False
    quantum_secure: bool = False
    threat_hunting: bool = True
    
    # SIEM Configuration
    elasticsearch_url: str = ""
    splunk_hec_url: str = ""
    splunk_hec_token: str = ""
    syslog_server: str = ""
    syslog_port: int = 514
    
    @classmethod
    def from_file(cls, path: str) -> 'AgentConfig':
        """Load config from file"""
        if os.path.exists(path):
            with open(path, 'r') as f:
                data = json.load(f)
            return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})
        return cls()
    
    def save(self, path: str):
        """Save config to file"""
        with open(path, 'w') as f:
            json.dump(asdict(self), f, indent=2)


@dataclass
class Threat:
    """Threat data structure"""
    threat_id: str = ""
    title: str = ""
    description: str = ""
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    threat_type: str = "unknown"
    source: str = ""
    target: str = ""
    evidence: Dict = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    detected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "active"
    auto_kill_eligible: bool = False
    remediation_action: Optional[str] = None
    remediation_params: Dict = field(default_factory=dict)
    ai_analysis: Optional[Dict] = None
    kill_reason: Optional[str] = None
    user_approved: Optional[bool] = None
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d['severity'] = self.severity.value if isinstance(self.severity, ThreatSeverity) else self.severity
        return d


@dataclass
class TelemetryData:
    """Telemetry data structure"""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent_id: str = ""
    hostname: str = HOSTNAME
    platform: str = PLATFORM
    
    # System metrics
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    
    # Security data
    processes: List[Dict] = field(default_factory=list)
    connections: List[Dict] = field(default_factory=list)
    threats: List[Dict] = field(default_factory=list)
    events: List[Dict] = field(default_factory=list)
    
    # Network data
    network_interfaces: List[Dict] = field(default_factory=list)
    wifi_networks: List[Dict] = field(default_factory=list)
    bluetooth_devices: List[Dict] = field(default_factory=list)
    usb_devices: List[Dict] = field(default_factory=list)


# =============================================================================
# SIEM INTEGRATION
# =============================================================================

class SIEMIntegration:
    """Full SIEM integration for enterprise logging"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.enabled = False
        self.siem_type = None
        self.buffer: deque = deque(maxlen=1000)
        self.last_flush = time.time()
        self.flush_interval = 5
        
        # Auto-detect SIEM
        if config.elasticsearch_url:
            self.enabled = True
            self.siem_type = 'elasticsearch'
            logger.info(f"SIEM: Elasticsearch enabled at {config.elasticsearch_url}")
        elif config.splunk_hec_url:
            self.enabled = True
            self.siem_type = 'splunk'
            logger.info(f"SIEM: Splunk HEC enabled")
        elif config.syslog_server:
            self.enabled = True
            self.siem_type = 'syslog'
            logger.info(f"SIEM: Syslog enabled at {config.syslog_server}")
    
    def log_event(self, event_type: str, severity: str, data: dict, immediate: bool = False):
        """Log a security event to SIEM"""
        event = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.config.agent_id,
            "hostname": HOSTNAME,
            "os": PLATFORM,
            "event_type": event_type,
            "severity": severity,
            "data": data,
            "source": "metatron_agent"
        }
        
        if immediate or severity in ['critical', 'high']:
            self._send_event(event)
        else:
            self.buffer.append(event)
            if time.time() - self.last_flush >= self.flush_interval:
                self._flush_buffer()
    
    def log_threat(self, threat: Threat, action: str = "detected"):
        """Log a threat detection/remediation to SIEM"""
        self.log_event(
            event_type=f"threat.{action}",
            severity=threat.severity.value if isinstance(threat.severity, ThreatSeverity) else threat.severity,
            data={
                "threat_id": threat.threat_id,
                "threat_type": threat.threat_type,
                "title": threat.title,
                "description": threat.description,
                "remediation_action": threat.remediation_action,
                "status": threat.status,
                "kill_reason": threat.kill_reason
            },
            immediate=threat.severity in {ThreatSeverity.CRITICAL, ThreatSeverity.HIGH}
        )
    
    def _send_event(self, event: dict):
        """Send event to configured SIEM"""
        if not self.enabled or not REQUESTS_AVAILABLE:
            return
        
        try:
            if self.siem_type == 'elasticsearch':
                self._send_to_elasticsearch(event)
            elif self.siem_type == 'splunk':
                self._send_to_splunk(event)
            elif self.siem_type == 'syslog':
                self._send_to_syslog(event)
        except Exception as e:
            logger.debug(f"SIEM send error: {e}")
    
    def _send_to_elasticsearch(self, event: dict):
        """Send to Elasticsearch"""
        url = f"{self.config.elasticsearch_url}/seraph-security/_doc"
        requests.post(url, json=event, timeout=5)
    
    def _send_to_splunk(self, event: dict):
        """Send to Splunk HEC"""
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Splunk {self.config.splunk_hec_token}'
        }
        requests.post(self.config.splunk_hec_url, json={"event": event}, headers=headers, timeout=5)
    
    def _send_to_syslog(self, event: dict):
        """Send to Syslog server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        severity_map = {'critical': 10, 'high': 7, 'medium': 5, 'low': 3, 'info': 1}
        sev = severity_map.get(event.get('severity', 'info'), 1)
        msg = f"CEF:0|Seraph|Metatron|2.0|{event['event_type']}|Security Event|{sev}|src={HOSTNAME}"
        sock.sendto(msg.encode(), (self.config.syslog_server, self.config.syslog_port))
        sock.close()
    
    def _flush_buffer(self):
        """Flush buffered events to SIEM"""
        while self.buffer:
            event = self.buffer.popleft()
            self._send_event(event)
        self.last_flush = time.time()


# =============================================================================
# MONITORING MODULES
# =============================================================================

class MonitorModule(ABC):
    """Base class for monitoring modules"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.enabled = True
        self.last_run = None
        self.error_count = 0
    
    @abstractmethod
    def scan(self) -> Dict[str, Any]:
        """Perform scan and return results"""
        pass
    
    @abstractmethod
    def get_threats(self) -> List[Threat]:
        """Get detected threats from last scan"""
        pass


class ProcessMonitor(MonitorModule):
    """Process monitoring module with aggressive detection"""
    
    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.intel = ThreatIntelligence()
        self.processes = []
        self.threats = []
    
    def scan(self) -> Dict[str, Any]:
        """Scan running processes"""
        if not PSUTIL_AVAILABLE:
            return {"error": "psutil not available", "processes": []}
        
        self.processes = []
        self.threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    process_data = {
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'username': pinfo['username'] or 'SYSTEM',
                        'cmdline': ' '.join(pinfo['cmdline'] or []),
                        'cpu_percent': pinfo['cpu_percent'] or 0,
                        'memory_percent': pinfo['memory_percent'] or 0,
                        'risk_score': 0,
                        'threat_indicators': []
                    }
                    
                    name_lower = (pinfo['name'] or '').lower()
                    cmdline_lower = process_data['cmdline'].lower()
                    
                    # Check instant-kill processes
                    if name_lower in self.intel.INSTANT_KILL_PROCESSES:
                        process_data['risk_score'] = 100
                        process_data['threat_indicators'].append('instant_kill_process')
                    
                    # Check malicious process names
                    for mal_proc in self.intel.MALICIOUS_PROCESSES:
                        if mal_proc in name_lower:
                            process_data['risk_score'] += 80
                            process_data['threat_indicators'].append(f'malicious_name:{mal_proc}')
                    
                    # Check malicious command patterns
                    for pattern in self.intel.MALICIOUS_COMMANDS:
                        if re.search(pattern, cmdline_lower, re.IGNORECASE):
                            process_data['risk_score'] += 50
                            process_data['threat_indicators'].append(f'malicious_cmd:{pattern[:20]}')
                    
                    # Check critical patterns
                    for pattern in self.intel.CRITICAL_PATTERNS:
                        if pattern in cmdline_lower:
                            process_data['risk_score'] += 40
                            process_data['threat_indicators'].append(f'critical_pattern:{pattern}')
                    
                    # Cap risk score
                    process_data['risk_score'] = min(100, process_data['risk_score'])
                    
                    self.processes.append(process_data)
                    
                    # Create threat if high risk
                    if process_data['risk_score'] >= 50:
                        self._create_threat(process_data)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
        except Exception as e:
            logger.error(f"Process scan error: {e}")
            self.error_count += 1
        
        self.last_run = datetime.now(timezone.utc)
        return {"processes": self.processes, "count": len(self.processes)}
    
    def _create_threat(self, process_data: Dict):
        """Create a threat from suspicious process"""
        risk = process_data['risk_score']
        severity = ThreatSeverity.CRITICAL if risk >= 90 else ThreatSeverity.HIGH if risk >= 70 else ThreatSeverity.MEDIUM
        
        # Determine MITRE techniques
        mitre = []
        cmdline = process_data['cmdline'].lower()
        if 'mimikatz' in cmdline or 'sekurlsa' in cmdline:
            mitre.extend(['T1003', 'T1003.001'])
        if 'invoke-expression' in cmdline or 'downloadstring' in cmdline:
            mitre.extend(['T1059.001', 'T1105'])
        if 'psexec' in cmdline:
            mitre.extend(['T1570', 'T1021.002'])
        if 'schtasks' in cmdline:
            mitre.append('T1053.005')
        
        threat = Threat(
            threat_id=f"proc-{uuid.uuid4().hex[:8]}",
            title=f"Suspicious Process: {process_data['name']}",
            description=f"Detected suspicious process with risk score {process_data['risk_score']}",
            severity=severity,
            threat_type="credential_theft" if 'mimikatz' in cmdline else "suspicious_process",
            source="process_monitor",
            target=process_data['name'],
            evidence={
                'pid': process_data['pid'],
                'name': process_data['name'],
                'cmdline': process_data['cmdline'][:500],
                'indicators': process_data['threat_indicators']
            },
            mitre_techniques=mitre,
            auto_kill_eligible=severity in {ThreatSeverity.CRITICAL, ThreatSeverity.HIGH},
            remediation_action="kill_process",
            remediation_params={"pid": process_data['pid'], "process_name": process_data['name']}
        )
        
        self.threats.append(threat)
    
    def get_threats(self) -> List[Threat]:
        return self.threats


class NetworkMonitor(MonitorModule):
    """Network monitoring module"""
    
    def __init__(self, config: AgentConfig):
        super().__init__(config)
        self.intel = ThreatIntelligence()
        self.connections = []
        self.interfaces = []
        self.threats = []
        self.connection_counts = defaultdict(int)
    
    def scan(self) -> Dict[str, Any]:
        """Scan network connections and interfaces"""
        if not PSUTIL_AVAILABLE:
            return {"error": "psutil not available"}
        
        self.connections = []
        self.interfaces = []
        self.threats = []
        
        try:
            # Get network interfaces
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        self.interfaces.append({
                            'name': name,
                            'ip': addr.address,
                            'netmask': addr.netmask
                        })
            
            # Get connections
            for conn in psutil.net_connections(kind='inet'):
                try:
                    conn_data = {
                        'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6',
                        'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'local_ip': conn.laddr.ip if conn.laddr else '',
                        'local_port': conn.laddr.port if conn.laddr else 0,
                        'remote_ip': conn.raddr.ip if conn.raddr else '',
                        'remote_port': conn.raddr.port if conn.raddr else 0,
                        'status': conn.status,
                        'pid': conn.pid,
                        'risk_score': 0,
                        'threat_indicators': []
                    }
                    
                    remote_ip = conn_data['remote_ip']
                    remote_port = conn_data['remote_port']
                    
                    # Skip local connections
                    if not remote_ip or remote_ip.startswith('127.') or remote_ip.startswith('::'):
                        self.connections.append(conn_data)
                        continue
                    
                    # Check malicious IP ranges
                    for mal_ip in self.intel.MALICIOUS_IPS:
                        if remote_ip.startswith(mal_ip):
                            conn_data['risk_score'] += 80
                            conn_data['threat_indicators'].append(f'malicious_ip:{mal_ip}')
                    
                    # Check suspicious ports
                    if remote_port in self.intel.SUSPICIOUS_PORTS:
                        conn_data['risk_score'] += 50
                        conn_data['threat_indicators'].append(f'suspicious_port:{remote_port}')
                    
                    # Check connection frequency (potential exfil)
                    conn_key = f"{remote_ip}:{remote_port}"
                    self.connection_counts[conn_key] += 1
                    if self.connection_counts[conn_key] > 100:
                        conn_data['risk_score'] += 30
                        conn_data['threat_indicators'].append('high_frequency')
                    
                    self.connections.append(conn_data)
                    
                    # Create threat if high risk
                    if conn_data['risk_score'] >= 50:
                        self._create_threat(conn_data)
                        
                except Exception:
                    pass
                    
        except Exception as e:
            logger.error(f"Network scan error: {e}")
            self.error_count += 1
        
        self.last_run = datetime.now(timezone.utc)
        return {
            "connections": self.connections,
            "interfaces": self.interfaces,
            "connection_count": len(self.connections)
        }
    
    def _create_threat(self, conn_data: Dict):
        """Create a threat from suspicious connection"""
        risk = conn_data['risk_score']
        severity = ThreatSeverity.CRITICAL if risk >= 80 else ThreatSeverity.HIGH if risk >= 60 else ThreatSeverity.MEDIUM
        
        threat = Threat(
            threat_id=f"net-{uuid.uuid4().hex[:8]}",
            title=f"Suspicious Connection: {conn_data['remote_ip']}:{conn_data['remote_port']}",
            description=f"Suspicious network connection detected",
            severity=severity,
            threat_type="c2_activity" if conn_data['remote_port'] in self.intel.SUSPICIOUS_PORTS else "suspicious_connection",
            source="network_monitor",
            target=f"{conn_data['remote_ip']}:{conn_data['remote_port']}",
            evidence={
                'local': f"{conn_data['local_ip']}:{conn_data['local_port']}",
                'remote': f"{conn_data['remote_ip']}:{conn_data['remote_port']}",
                'pid': conn_data['pid'],
                'indicators': conn_data['threat_indicators']
            },
            mitre_techniques=['T1071', 'T1095'],
            auto_kill_eligible=False,
            remediation_action="block_ip",
            remediation_params={"ip": conn_data['remote_ip'], "port": conn_data['remote_port']}
        )
        self.threats.append(threat)
    
    def get_threats(self) -> List[Threat]:
        return self.threats


class NetworkScanner:
    """Advanced network scanner for ports, router, local network"""
    
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
        self.dangerous_ports = [23, 445, 1433, 3389, 5900]
        self.scan_results = {}
    
    def get_gateway(self) -> Optional[str]:
        """Get default gateway IP"""
        try:
            if PLATFORM == 'windows':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Default Gateway' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            ip = parts[1].strip()
                            if ip:
                                return ip
            else:
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'default' in line:
                        parts = line.split()
                        for i, p in enumerate(parts):
                            if p == 'via' and i + 1 < len(parts):
                                return parts[i + 1]
        except:
            pass
        return None
    
    def scan_port(self, ip: str, port: int, timeout: float = 0.5) -> bool:
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_host(self, ip: str, ports: List[int] = None) -> Dict:
        """Scan a host for open ports"""
        if ports is None:
            ports = self.common_ports
        
        open_ports = []
        for port in ports:
            if self.scan_port(ip, port):
                service = self._get_service_name(port)
                open_ports.append({
                    "port": port,
                    "service": service,
                    "dangerous": port in self.dangerous_ports
                })
        
        return {
            "ip": ip,
            "open_ports": open_ports,
            "scan_time": datetime.now(timezone.utc).isoformat()
        }
    
    def scan_router(self) -> Dict:
        """Scan the default gateway/router"""
        gateway = self.get_gateway()
        if not gateway:
            return {"error": "Could not determine gateway"}
        
        router_ports = [80, 443, 8080, 22, 23, 53]
        result = self.scan_host(gateway, router_ports)
        result["is_gateway"] = True
        
        vulnerabilities = []
        if any(p["port"] == 23 for p in result["open_ports"]):
            vulnerabilities.append({"type": "telnet_open", "severity": "high"})
        if any(p["port"] == 80 for p in result["open_ports"]):
            vulnerabilities.append({"type": "http_admin", "severity": "medium"})
        
        result["vulnerabilities"] = vulnerabilities
        return result
    
    def _get_service_name(self, port: int) -> str:
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        return services.get(port, "Unknown")


class WiFiScanner:
    """WiFi network scanner"""
    
    def scan_networks(self) -> List[Dict]:
        """Scan for available WiFi networks"""
        networks = []
        
        try:
            if PLATFORM == 'windows':
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                    capture_output=True, text=True
                )
                
                current_network = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('SSID') and ':' in line:
                        if current_network and current_network.get('ssid'):
                            networks.append(current_network)
                        current_network = {'ssid': line.split(':', 1)[1].strip()}
                    elif line.startswith('BSSID'):
                        current_network['bssid'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Signal'):
                        current_network['signal'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Authentication'):
                        current_network['auth'] = line.split(':', 1)[1].strip()
                
                if current_network and current_network.get('ssid'):
                    networks.append(current_network)
                    
            else:
                try:
                    result = subprocess.run(
                        ['nmcli', '-t', '-f', 'SSID,BSSID,SIGNAL,SECURITY', 'device', 'wifi', 'list'],
                        capture_output=True, text=True
                    )
                    for line in result.stdout.strip().split('\n'):
                        if line:
                            parts = line.split(':')
                            if len(parts) >= 4:
                                networks.append({
                                    'ssid': parts[0],
                                    'bssid': parts[1],
                                    'signal': parts[2] + '%',
                                    'auth': parts[3]
                                })
                except:
                    pass
        except Exception as e:
            logger.error(f"WiFi scan error: {e}")
        
        # Analyze for threats
        for network in networks:
            network['threats'] = self._analyze_network(network)
        
        return networks
    
    def _analyze_network(self, network: Dict) -> List[Dict]:
        """Analyze a network for potential threats"""
        threats = []
        
        auth = network.get('auth', '').lower()
        
        if 'open' in auth or 'none' in auth:
            threats.append({"type": "open_network", "severity": "high"})
        
        if 'wep' in auth:
            threats.append({"type": "weak_encryption", "severity": "critical"})
        
        return threats


class BluetoothScanner:
    """Bluetooth device scanner"""
    
    def scan_devices(self) -> List[Dict]:
        """Scan for nearby Bluetooth devices"""
        devices = []
        
        try:
            if PLATFORM == 'windows':
                ps_script = '''
                Get-PnpDevice -Class Bluetooth | Where-Object {$_.Status -eq 'OK'} | 
                Select-Object FriendlyName, DeviceID, Status | ConvertTo-Json
                '''
                result = subprocess.run(
                    ['powershell', '-Command', ps_script],
                    capture_output=True, text=True
                )
                if result.stdout:
                    try:
                        data = json.loads(result.stdout)
                        if isinstance(data, dict):
                            data = [data]
                        for d in data:
                            devices.append({
                                "name": d.get('FriendlyName', 'Unknown'),
                                "id": d.get('DeviceID', ''),
                                "status": d.get('Status', 'Unknown'),
                                "type": "paired"
                            })
                    except:
                        pass
            else:
                try:
                    result = subprocess.run(['hcitool', 'scan'], capture_output=True, text=True, timeout=10)
                    for line in result.stdout.strip().split('\n')[1:]:
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            devices.append({
                                "address": parts[0],
                                "name": parts[1] if len(parts) > 1 else "Unknown",
                                "type": "discovered"
                            })
                except:
                    pass
        except Exception as e:
            logger.error(f"Bluetooth scan error: {e}")
        
        return devices


# =============================================================================
# REMEDIATION ENGINE
# =============================================================================

class RemediationEngine:
    """Execute remediation actions"""
    
    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.blocked_ports: Set[int] = set()
    
    def execute(self, threat: Threat) -> Tuple[bool, str]:
        """Execute remediation action"""
        action = threat.remediation_action
        params = threat.remediation_params
        
        try:
            if action == "kill_process":
                return self._kill_process(params)
            elif action == "block_ip":
                return self._block_ip(params)
            elif action == "block_connection":
                return self._block_connection(params)
            elif action == "quarantine_file":
                return self._quarantine_file(params)
            else:
                return False, f"Unknown action: {action}"
        except Exception as e:
            return False, str(e)
    
    def _kill_process(self, params: Dict) -> Tuple[bool, str]:
        """Kill a malicious process"""
        if not PSUTIL_AVAILABLE:
            return False, "psutil not available"
        
        pid = params.get('pid')
        name = params.get('process_name', 'unknown')
        
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            time.sleep(1)
            if proc.is_running():
                proc.kill()
            logger.warning(f"Killed malicious process: {name} (PID: {pid})")
            return True, f"Successfully terminated process {name} (PID: {pid})"
        except psutil.NoSuchProcess:
            return True, "Process already terminated"
        except psutil.AccessDenied:
            return False, f"Access denied - run as administrator"
        except Exception as e:
            return False, f"Failed to kill process: {e}"
    
    def _block_ip(self, params: Dict) -> Tuple[bool, str]:
        """Block an IP address"""
        ip = params.get('ip')
        
        try:
            if PLATFORM == 'windows':
                cmd = f'netsh advfirewall firewall add rule name="Metatron Block {ip}" dir=out action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
            elif PLATFORM == 'linux':
                subprocess.run(['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=True, capture_output=True)
            elif PLATFORM == 'darwin':
                with open('/etc/pf.anchors/metatron', 'a') as f:
                    f.write(f'block out quick to {ip}\n')
                subprocess.run(['pfctl', '-f', '/etc/pf.conf'], capture_output=True)
            
            self.blocked_ips.add(ip)
            logger.info(f"Blocked IP: {ip}")
            return True, f"Successfully blocked IP {ip}"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to block IP (need admin): {e}"
        except Exception as e:
            return False, f"Failed to block IP: {e}"
    
    def _block_connection(self, params: Dict) -> Tuple[bool, str]:
        """Block a specific connection"""
        ip = params.get('ip')
        pid = params.get('pid')
        
        if pid:
            self._kill_process({'pid': pid})
        
        return self._block_ip({'ip': ip})
    
    def _quarantine_file(self, params: Dict) -> Tuple[bool, str]:
        """Move a file to quarantine"""
        filepath = params.get('filepath')
        
        try:
            src = Path(filepath)
            if not src.exists():
                return False, "File not found"
            
            dst = QUARANTINE_DIR / f"{src.name}.{uuid.uuid4().hex[:8]}.quarantine"
            src.rename(dst)
            
            logger.info(f"Quarantined file: {filepath} -> {dst}")
            return True, f"File quarantined: {dst}"
        except Exception as e:
            return False, f"Failed to quarantine: {e}"


# =============================================================================
# UNIFIED AGENT
# =============================================================================

class UnifiedAgent:
    """
    Metatron/Seraph Unified Security Agent v2.0
    
    Cross-platform security agent with:
    - Process and network monitoring
    - Aggressive auto-kill for threats
    - SIEM integration
    - VNS sync
    - AI analysis
    - Network scanning (ports, WiFi, Bluetooth)
    - Threat hunting integration
    """
    
    def __init__(self, config: AgentConfig = None, config_path: str = None):
        """Initialize the unified agent"""
        if config:
            self.config = config
        elif config_path:
            self.config = AgentConfig.from_file(config_path)
        else:
            self.config = AgentConfig()
        
        # Generate agent ID if not set
        if not self.config.agent_id:
            self.config.agent_id = f"metatron-{HOSTNAME}-{uuid.uuid4().hex[:8]}"
        
        if not self.config.agent_name:
            self.config.agent_name = f"Metatron-{HOSTNAME}"
        
        # Initialize monitors
        self.monitors: Dict[str, MonitorModule] = {}
        
        if self.config.process_monitoring:
            self.monitors['process'] = ProcessMonitor(self.config)
        
        if self.config.network_scanning:
            self.monitors['network'] = NetworkMonitor(self.config)
        
        # Initialize scanners
        self.network_scanner = NetworkScanner()
        self.wifi_scanner = WiFiScanner()
        self.bluetooth_scanner = BluetoothScanner()
        
        # Initialize SIEM
        self.siem = SIEMIntegration(self.config)
        
        # Initialize remediation
        self.remediation = RemediationEngine()
        
        # Telemetry storage
        self.telemetry = TelemetryData(agent_id=self.config.agent_id)
        self.threat_history: deque = deque(maxlen=1000)
        self.event_log: deque = deque(maxlen=5000)
        self.auto_remediated: deque = deque(maxlen=100)
        self.alarms: deque = deque(maxlen=50)
        
        # State
        self.running = False
        self.registered = False
        self.last_heartbeat = None
        
        # Stats
        self.stats = {
            "threats_detected": 0,
            "threats_blocked": 0,
            "threats_auto_killed": 0,
            "scans_performed": 0,
        }
        
        # Callbacks
        self.on_threat_detected: Optional[Callable[[Threat], None]] = None
        self.on_telemetry_update: Optional[Callable[[TelemetryData], None]] = None
        
        logger.info(f"Unified Agent initialized: {self.config.agent_id}")
    
    def register(self) -> bool:
        """Register with the server"""
        if not REQUESTS_AVAILABLE or not self.config.server_url:
            logger.warning("Cannot register: requests not available or server URL not set")
            return False
        
        try:
            response = requests.post(
                f"{self.config.server_url}/api/unified/agents/register",
                json={
                    'agent_id': self.config.agent_id,
                    'platform': PLATFORM,
                    'hostname': HOSTNAME,
                    'ip_address': self._get_primary_ip(),
                    'version': AGENT_VERSION,
                    'capabilities': list(self.monitors.keys()) + ['network_scan', 'wifi_scan', 'bluetooth_scan', 'siem'],
                    'config': {
                        'auto_remediate': self.config.auto_remediate,
                        'features': {
                            'vns_sync': self.config.vns_sync,
                            'ai_analysis': self.config.ai_analysis,
                            'siem_integration': self.siem.enabled,
                            'threat_hunting': self.config.threat_hunting
                        }
                    }
                },
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                self.registered = True
                logger.info(f"Registered with server: {self.config.server_url}")
                return True
            else:
                logger.error(f"Registration failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False
    
    def _get_primary_ip(self) -> str:
        """Get primary IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def scan_all(self) -> Dict[str, Any]:
        """Run all enabled monitors"""
        results = {}
        all_threats = []
        
        for name, monitor in self.monitors.items():
            if monitor.enabled:
                try:
                    results[name] = monitor.scan()
                    all_threats.extend(monitor.get_threats())
                except Exception as e:
                    logger.error(f"Monitor {name} error: {e}")
                    results[name] = {"error": str(e)}
        
        # Process detected threats
        for threat in all_threats:
            self._handle_threat(threat)
        
        # Update telemetry
        self._update_telemetry(results)
        
        self.stats["scans_performed"] += 1
        
        return results
    
    def _handle_threat(self, threat: Threat):
        """Handle a detected threat with aggressive auto-kill"""
        self.threat_history.append(threat)
        self.stats["threats_detected"] += 1
        
        # Determine if auto-kill should be triggered
        should_auto_kill = False
        kill_reason = None
        
        if self.config.auto_remediate and threat.auto_kill_eligible:
            # Auto-kill for CRITICAL and HIGH severity
            if threat.severity in {ThreatSeverity.CRITICAL, ThreatSeverity.HIGH}:
                should_auto_kill = True
                kill_reason = f"SEVERITY_{threat.severity.value.upper()}"
            
            # Check critical patterns
            threat_text = f"{threat.title} {threat.description}".lower()
            for pattern in ThreatIntelligence.CRITICAL_PATTERNS:
                if pattern in threat_text:
                    should_auto_kill = True
                    kill_reason = f"PATTERN_MATCH_{pattern.upper()}"
                    break
        
        # Execute auto-kill
        if should_auto_kill:
            threat.kill_reason = kill_reason
            threat.status = "auto_remediated"
            threat.user_approved = True
            
            # Execute remediation
            success, msg = self.remediation.execute(threat)
            
            if success:
                self.stats["threats_auto_killed"] += 1
                self.stats["threats_blocked"] += 1
                self.auto_remediated.append(threat)
                logger.warning(f"AUTO-KILL EXECUTED: {threat.title} | Reason: {kill_reason}")
                
                # Log to SIEM
                self.siem.log_threat(threat, "auto_killed")
            else:
                logger.error(f"AUTO-KILL FAILED: {threat.title} - {msg}")
            
            # Trigger alarm
            self._trigger_alarm(threat, f"AUTO_KILL:{kill_reason}")
        else:
            # Log to SIEM
            self.siem.log_threat(threat, "detected")
        
        # Log event
        self._log_event("threat_detected", {
            "threat_id": threat.threat_id,
            "title": threat.title,
            "severity": threat.severity.value if isinstance(threat.severity, ThreatSeverity) else threat.severity,
            "auto_kill_triggered": should_auto_kill,
            "kill_reason": kill_reason
        })
        
        # Callback
        if self.on_threat_detected:
            self.on_threat_detected(threat)
        
        # Send to AI for analysis
        if self.config.ai_analysis and self.config.server_url:
            self._request_ai_analysis(threat)
        
        # Sync to VNS
        if self.config.vns_sync and self.config.server_url:
            self._sync_to_vns(threat)
    
    def _trigger_alarm(self, threat: Threat, alarm_type: str):
        """Trigger an alarm for critical threats"""
        alarm = {
            "id": f"alarm-{uuid.uuid4().hex[:8]}",
            "type": alarm_type,
            "threat_id": threat.threat_id,
            "threat_title": threat.title,
            "severity": threat.severity.value if isinstance(threat.severity, ThreatSeverity) else threat.severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "acknowledged": False
        }
        self.alarms.append(alarm)
        logger.warning(f"ALARM: {alarm_type} - {threat.title}")
    
    def _request_ai_analysis(self, threat: Threat):
        """Request AI analysis for a threat"""
        if not REQUESTS_AVAILABLE:
            return
        
        try:
            response = requests.post(
                f"{self.config.server_url}/api/advanced/ai/analyze",
                json={
                    "title": threat.title,
                    "description": threat.description,
                    "process_name": threat.evidence.get('name'),
                    "command_line": threat.evidence.get('cmdline'),
                    "indicators": threat.evidence.get('indicators', [])
                },
                timeout=30
            )
            
            if response.status_code == 200:
                threat.ai_analysis = response.json()
                logger.info(f"AI Analysis: Risk {threat.ai_analysis.get('risk_score')}")
                
        except Exception as e:
            logger.debug(f"AI analysis request failed: {e}")
    
    def _sync_to_vns(self, threat: Threat):
        """Sync threat to VNS"""
        if not REQUESTS_AVAILABLE:
            return
        
        try:
            if 'remote_ip' in str(threat.evidence):
                evidence = threat.evidence
                local = evidence.get('local', ':0')
                remote = evidence.get('remote', ':0')
                
                requests.post(
                    f"{self.config.server_url}/api/advanced/vns/flow",
                    json={
                        "src_ip": local.split(':')[0] if ':' in local else '0.0.0.0',
                        "src_port": int(local.split(':')[-1]) if ':' in local else 0,
                        "dst_ip": remote.split(':')[0] if ':' in remote else '0.0.0.0',
                        "dst_port": int(remote.split(':')[-1]) if ':' in remote else 0,
                        "protocol": "TCP"
                    },
                    timeout=5
                )
        except Exception as e:
            logger.debug(f"VNS sync failed: {e}")
    
    def _update_telemetry(self, scan_results: Dict):
        """Update telemetry data"""
        if PSUTIL_AVAILABLE:
            self.telemetry.cpu_usage = psutil.cpu_percent()
            self.telemetry.memory_usage = psutil.virtual_memory().percent
            try:
                self.telemetry.disk_usage = psutil.disk_usage('/').percent
            except:
                self.telemetry.disk_usage = 0
        
        self.telemetry.timestamp = datetime.now(timezone.utc).isoformat()
        
        if 'process' in scan_results:
            self.telemetry.processes = scan_results['process'].get('processes', [])[:100]
        
        if 'network' in scan_results:
            self.telemetry.connections = scan_results['network'].get('connections', [])[:100]
            self.telemetry.network_interfaces = scan_results['network'].get('interfaces', [])
        
        self.telemetry.threats = [t.to_dict() for t in list(self.threat_history)[-50:]]
        
        if self.on_telemetry_update:
            self.on_telemetry_update(self.telemetry)
    
    def _log_event(self, event_type: str, data: Dict):
        """Log an event"""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "agent_id": self.config.agent_id,
            **data
        }
        self.event_log.append(event)
        self.telemetry.events = list(self.event_log)[-100:]
        
        # Log to SIEM
        self.siem.log_event(event_type, data.get('severity', 'info'), data)
    
    def heartbeat(self) -> bool:
        """Send heartbeat to server"""
        if not REQUESTS_AVAILABLE or not self.config.server_url:
            return False
        
        try:
            response = requests.post(
                f"{self.config.server_url}/api/unified/agents/{self.config.agent_id}/heartbeat",
                json={
                    "agent_id": self.config.agent_id,
                    "status": "online",
                    "cpu_usage": self.telemetry.cpu_usage,
                    "memory_usage": self.telemetry.memory_usage,
                    "disk_usage": self.telemetry.disk_usage,
                    "threat_count": len(self.threat_history),
                    "network_connections": len(self.telemetry.connections),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "telemetry": asdict(self.telemetry)
                },
                timeout=10
            )
            
            self.last_heartbeat = datetime.now(timezone.utc)
            return response.status_code == 200
            
        except Exception as e:
            logger.debug(f"Heartbeat failed: {e}")
            return False
    
    def get_status(self) -> Dict:
        """Get agent status"""
        return {
            "agent_id": self.config.agent_id,
            "agent_name": self.config.agent_name,
            "platform": PLATFORM,
            "hostname": HOSTNAME,
            "version": AGENT_VERSION,
            "running": self.running,
            "registered": self.registered,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "monitors": {name: monitor.enabled for name, monitor in self.monitors.items()},
            "threat_count": len(self.threat_history),
            "event_count": len(self.event_log),
            "auto_kills": len(self.auto_remediated),
            "stats": self.stats,
            "siem": {"enabled": self.siem.enabled, "type": self.siem.siem_type},
            "telemetry": {
                "cpu_usage": self.telemetry.cpu_usage,
                "memory_usage": self.telemetry.memory_usage,
                "disk_usage": self.telemetry.disk_usage
            }
        }
    
    def get_dashboard_data(self) -> Dict:
        """Get all data for dashboard"""
        return {
            "agent": self.get_status(),
            "stats": self.stats,
            "events": list(self.event_log)[-100:],
            "threats": [t.to_dict() for t in list(self.threat_history)[-50:]],
            "auto_remediated": [t.to_dict() for t in list(self.auto_remediated)[-20:]],
            "alarms": list(self.alarms)[-20:],
            "telemetry": asdict(self.telemetry)
        }
    
    # Advanced scanning methods
    def scan_ports(self, target_ip: str = None) -> Dict:
        """Scan ports on a target IP"""
        if target_ip:
            return self.network_scanner.scan_host(target_ip)
        return self.network_scanner.scan_router()
    
    def scan_wifi(self) -> List[Dict]:
        """Scan WiFi networks"""
        return self.wifi_scanner.scan_networks()
    
    def scan_bluetooth(self) -> List[Dict]:
        """Scan Bluetooth devices"""
        return self.bluetooth_scanner.scan_devices()
    
    def run_once(self):
        """Run a single monitoring cycle"""
        self.scan_all()
        self.heartbeat()
    
    def start(self, blocking: bool = True):
        """Start the agent"""
        self.running = True
        self.register()
        
        logger.info(f"Agent started: {self.config.agent_id}")
        
        if blocking:
            self._run_loop()
        else:
            thread = threading.Thread(target=self._run_loop, daemon=True)
            thread.start()
            return thread
    
    def _run_loop(self):
        """Main monitoring loop"""
        heartbeat_counter = 0
        
        while self.running:
            try:
                self.scan_all()
                
                heartbeat_counter += self.config.update_interval
                if heartbeat_counter >= self.config.heartbeat_interval:
                    self.heartbeat()
                    heartbeat_counter = 0
                
                time.sleep(self.config.update_interval)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                time.sleep(5)
        
        self.running = False
        logger.info("Agent stopped")
    
    def stop(self):
        """Stop the agent"""
        self.running = False


# Convenience function
def create_agent(server_url: str = None, **kwargs) -> UnifiedAgent:
    """Create and configure a unified agent"""
    config = AgentConfig(server_url=server_url or "", **kwargs)
    return UnifiedAgent(config=config)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Metatron/Seraph Unified Security Agent")
    parser.add_argument("--server", "-s", help="Server URL", default="")
    parser.add_argument("--config", "-c", help="Config file path")
    parser.add_argument("--name", "-n", help="Agent name")
    parser.add_argument("--interval", "-i", type=int, default=30, help="Update interval")
    parser.add_argument("--no-auto-kill", action="store_true", help="Disable auto-kill")
    
    args = parser.parse_args()
    
    if args.config:
        agent = UnifiedAgent(config_path=args.config)
    else:
        config = AgentConfig(
            server_url=args.server,
            agent_name=args.name or f"Metatron-{HOSTNAME}",
            update_interval=args.interval,
            auto_remediate=not args.no_auto_kill
        )
        agent = UnifiedAgent(config=config)
    
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║     ███╗   ███╗███████╗████████╗ █████╗ ████████╗██████╗  ██████╗ ███╗   ██╗
║     ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
║     ██╔████╔██║█████╗     ██║   ███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║
║     ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║
║     ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
║     ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
║                    UNIFIED SECURITY AGENT v{AGENT_VERSION}
╚══════════════════════════════════════════════════════════════════╝

Agent ID: {agent.config.agent_id}
Platform: {PLATFORM}
Server: {agent.config.server_url or 'Not configured'}
Auto-Kill: {'Enabled' if agent.config.auto_remediate else 'Disabled'}
SIEM: {'Enabled' if agent.siem.enabled else 'Disabled'}
""")
    
    agent.start()
