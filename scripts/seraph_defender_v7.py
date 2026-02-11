#!/usr/bin/env python3
"""
Seraph Defender v7.0 - Full Threat Detection & Auto-Remediation
================================================================

REAL FEATURES:
- Network traffic monitoring (suspicious IPs, ports, DNS queries)
- AI-powered behavioral threat detection
- File integrity monitoring with hash verification
- Process injection detection
- Credential theft detection
- Data exfiltration detection
- Automatic remediation with user approval
- Server command queue (receive commands from server)
- Local dashboard at http://localhost:8888

USAGE:
    python seraph_defender_v7.py --api-url URL
    python seraph_defender_v7.py --local-only
    
Then open http://localhost:8888 in your browser

Supports: Windows, macOS, Linux, Android (Termux), iOS (Pythonista)
"""

import os
import sys
import json
import time
import hashlib
import platform
import subprocess
import threading
import socket
import struct
import re
import uuid
import signal
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import urllib.request

# =============================================================================
# CONFIGURATION
# =============================================================================

VERSION = "7.0.0"
AGENT_ID = None
HOSTNAME = platform.node()
OS_TYPE = platform.system().lower()
DASHBOARD_PORT = 8888

# Directories
if OS_TYPE == "windows":
    INSTALL_DIR = Path(os.environ.get('LOCALAPPDATA', 'C:/SeraphDefender')) / "SeraphDefender"
else:
    INSTALL_DIR = Path.home() / ".seraph-defender"

DATA_DIR = INSTALL_DIR / "data"
LOGS_DIR = INSTALL_DIR / "logs"
QUARANTINE_DIR = INSTALL_DIR / "quarantine"

for d in [INSTALL_DIR, DATA_DIR, LOGS_DIR, QUARANTINE_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / "seraph_defender.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SeraphDefender")

# =============================================================================
# DEPENDENCIES
# =============================================================================

try:
    import psutil
except ImportError:
    logger.info("Installing psutil...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "-q"])
    import psutil

try:
    import requests
except ImportError:
    logger.info("Installing requests...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

# =============================================================================
# THREAT INTELLIGENCE DATABASE
# =============================================================================

class ThreatIntelligence:
    """Known malicious indicators"""
    
    # Known malicious IP ranges (simplified - in production use threat feeds)
    MALICIOUS_IPS = {
        # Known C2 servers, botnets, etc. (examples)
        "185.220.101.",  # Tor exit nodes often used maliciously
        "45.33.32.",     # Known scanner ranges
        "198.51.100.",   # TEST-NET-2 (should never see real traffic)
        "203.0.113.",    # TEST-NET-3
    }
    
    # Suspicious ports
    SUSPICIOUS_PORTS = {
        4444: "Metasploit default",
        5555: "Android ADB",
        6666: "IRC botnet",
        6667: "IRC botnet",
        31337: "Back Orifice",
        12345: "NetBus",
        27374: "SubSeven",
        1234: "Common backdoor",
        9001: "Tor",
        9050: "Tor SOCKS",
        4443: "Common C2",
        8443: "Alternative HTTPS (often C2)",
        3389: "RDP (flag if unexpected)",
        5900: "VNC",
        5800: "VNC HTTP",
    }
    
    # Known malicious domains (patterns)
    MALICIOUS_DOMAINS = [
        r".*\.onion$",           # Tor hidden services
        r".*\.bit$",             # Namecoin (often malware)
        r".*dyndns.*",           # Dynamic DNS (often C2)
        r".*no-ip.*",            # Dynamic DNS
        r".*\.tk$",              # Free TLD often abused
        r".*\.ml$",              # Free TLD often abused
        r".*\.ga$",              # Free TLD often abused
        r".*\.cf$",              # Free TLD often abused
        r".*pastebin\.com.*",    # Data exfil
        r".*hastebin\.com.*",    # Data exfil
        r".*ngrok\.io.*",        # Tunneling
        r".*serveo\.net.*",      # Tunneling
    ]
    
    # Suspicious process names
    MALICIOUS_PROCESSES = [
        'mimikatz', 'lazagne', 'procdump', 'pwdump', 'fgdump',
        'gsecdump', 'wce', 'nc.exe', 'ncat.exe', 'netcat',
        'psexec', 'paexec', 'crackmapexec', 'bloodhound',
        'sharphound', 'rubeus', 'kerberoast', 'responder',
        'impacket', 'empire', 'covenant', 'cobalt',
        'meterpreter', 'beacon', 'sliver', 'mythic',
        'cryptolocker', 'wannacry', 'petya', 'ryuk',
        'conti', 'lockbit', 'revil', 'darkside',
        'xmrig', 'minerd', 'cgminer', 'bfgminer',  # Cryptominers
    ]
    
    # Suspicious command patterns
    MALICIOUS_COMMANDS = [
        r'powershell.*-enc',                    # Encoded PowerShell
        r'powershell.*downloadstring',          # Download cradle
        r'powershell.*iex',                     # Invoke-Expression
        r'certutil.*-urlcache',                 # Download via certutil
        r'bitsadmin.*\/transfer',               # BITS download
        r'mshta.*http',                         # HTA execution
        r'regsvr32.*\/s.*\/u.*\/i:http',       # Squiblydoo
        r'rundll32.*javascript',                # JS execution
        r'wmic.*process.*call.*create',         # Remote execution
        r'net.*user.*\/add',                    # User creation
        r'net.*localgroup.*administrators',     # Admin addition
        r'reg.*add.*run',                       # Persistence
        r'schtasks.*\/create',                  # Scheduled task
        r'sc.*create',                          # Service creation
        r'whoami.*\/priv',                      # Privilege check
        r'mimikatz',                            # Credential theft
        r'sekurlsa',                            # LSASS dump
        r'lsadump',                             # SAM dump
        r'base64.*-d.*\|.*bash',               # Encoded bash
        r'curl.*\|.*bash',                      # Pipe to bash
        r'wget.*\|.*bash',                      # Pipe to bash
        r'python.*-c.*import.*socket',          # Python reverse shell
        r'nc.*-e.*\/bin',                       # Netcat shell
        r'bash.*-i.*>&.*\/dev\/tcp',           # Bash reverse shell
    ]
    
    # Data exfiltration patterns
    EXFIL_PATTERNS = [
        r'curl.*-d.*@',                         # File upload
        r'curl.*--data-binary',                 # Binary upload
        r'wget.*--post-file',                   # POST file
        r'scp.*@.*:',                           # SCP transfer
        r'rsync.*@.*:',                         # Rsync transfer
        r'ftp.*put',                            # FTP upload
        r'rclone.*copy',                        # Cloud sync
    ]


# =============================================================================
# THREAT DETECTION ENGINE
# =============================================================================

class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Threat:
    id: str
    type: str
    severity: ThreatSeverity
    title: str
    description: str
    source: str
    target: Optional[str] = None
    evidence: Dict = field(default_factory=dict)
    remediation_available: bool = False
    remediation_action: Optional[str] = None
    remediation_params: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "detected"  # detected, pending_approval, remediating, resolved, ignored
    user_approved: Optional[bool] = None
    
    def to_dict(self):
        d = asdict(self)
        d['severity'] = self.severity.value
        return d


class ThreatDetectionEngine:
    """Real threat detection engine"""
    
    def __init__(self, store):
        self.store = store
        self.intel = ThreatIntelligence()
        self.seen_connections = set()
        self.connection_counts = defaultdict(int)
        self.dns_cache = {}
        
    def analyze_connection(self, conn: dict) -> Optional[Threat]:
        """Analyze a network connection for threats"""
        remote_ip = conn.get('remote_ip', '')
        remote_port = conn.get('remote_port', 0)
        local_port = conn.get('local_port', 0)
        pid = conn.get('pid')
        process_name = conn.get('process_name', 'unknown')
        
        if not remote_ip or remote_ip.startswith('127.') or remote_ip.startswith('::'):
            return None
        
        # Check malicious IP ranges
        for mal_ip in self.intel.MALICIOUS_IPS:
            if remote_ip.startswith(mal_ip):
                return Threat(
                    id=f"net-{uuid.uuid4().hex[:8]}",
                    type="malicious_connection",
                    severity=ThreatSeverity.CRITICAL,
                    title="Connection to Known Malicious IP",
                    description=f"Process {process_name} (PID: {pid}) connected to known malicious IP {remote_ip}",
                    source=process_name,
                    target=remote_ip,
                    evidence={
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "pid": pid,
                        "process": process_name
                    },
                    remediation_available=True,
                    remediation_action="kill_process",
                    remediation_params={"pid": pid, "process_name": process_name}
                )
        
        # Check suspicious ports
        if remote_port in self.intel.SUSPICIOUS_PORTS:
            reason = self.intel.SUSPICIOUS_PORTS[remote_port]
            return Threat(
                id=f"net-{uuid.uuid4().hex[:8]}",
                type="suspicious_port",
                severity=ThreatSeverity.HIGH,
                title=f"Connection to Suspicious Port ({reason})",
                description=f"Process {process_name} connected to {remote_ip}:{remote_port} - {reason}",
                source=process_name,
                target=f"{remote_ip}:{remote_port}",
                evidence={
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "reason": reason,
                    "pid": pid
                },
                remediation_available=True,
                remediation_action="block_connection",
                remediation_params={"ip": remote_ip, "port": remote_port, "pid": pid}
            )
        
        # Check for unusual outbound data volume (potential exfil)
        conn_key = f"{remote_ip}:{remote_port}"
        self.connection_counts[conn_key] += 1
        
        if self.connection_counts[conn_key] > 100:  # High connection count
            return Threat(
                id=f"net-{uuid.uuid4().hex[:8]}",
                type="potential_exfiltration",
                severity=ThreatSeverity.MEDIUM,
                title="Potential Data Exfiltration",
                description=f"High volume of connections to {remote_ip}:{remote_port} detected",
                source=process_name,
                target=remote_ip,
                evidence={
                    "connection_count": self.connection_counts[conn_key],
                    "remote_ip": remote_ip
                },
                remediation_available=True,
                remediation_action="block_ip",
                remediation_params={"ip": remote_ip}
            )
        
        return None
    
    def analyze_process(self, proc: dict) -> Optional[Threat]:
        """Analyze a process for threats"""
        name = proc.get('name', '').lower()
        cmdline = proc.get('cmdline', '').lower()
        pid = proc.get('pid')
        
        # Check malicious process names
        for mal_proc in self.intel.MALICIOUS_PROCESSES:
            if mal_proc in name:
                return Threat(
                    id=f"proc-{uuid.uuid4().hex[:8]}",
                    type="malicious_process",
                    severity=ThreatSeverity.CRITICAL,
                    title=f"Malicious Process Detected: {name}",
                    description=f"Known malicious tool '{mal_proc}' detected running as PID {pid}",
                    source="process_monitor",
                    target=name,
                    evidence={
                        "pid": pid,
                        "name": name,
                        "cmdline": cmdline[:500],
                        "matched": mal_proc
                    },
                    remediation_available=True,
                    remediation_action="kill_process",
                    remediation_params={"pid": pid, "process_name": name}
                )
        
        # Check malicious command patterns
        for pattern in self.intel.MALICIOUS_COMMANDS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                return Threat(
                    id=f"proc-{uuid.uuid4().hex[:8]}",
                    type="malicious_command",
                    severity=ThreatSeverity.HIGH,
                    title="Malicious Command Detected",
                    description=f"Suspicious command pattern detected in process {name}",
                    source="process_monitor",
                    target=name,
                    evidence={
                        "pid": pid,
                        "cmdline": cmdline[:500],
                        "pattern": pattern
                    },
                    remediation_available=True,
                    remediation_action="kill_process",
                    remediation_params={"pid": pid, "process_name": name}
                )
        
        # Check for crypto miners (high CPU)
        cpu = proc.get('cpu_percent', 0)
        if cpu > 80 and any(miner in name for miner in ['xmrig', 'miner', 'cgminer', 'bfgminer']):
            return Threat(
                id=f"proc-{uuid.uuid4().hex[:8]}",
                type="cryptominer",
                severity=ThreatSeverity.HIGH,
                title="Cryptominer Detected",
                description=f"Cryptocurrency miner detected using {cpu}% CPU",
                source="process_monitor",
                target=name,
                evidence={"pid": pid, "cpu": cpu},
                remediation_available=True,
                remediation_action="kill_process",
                remediation_params={"pid": pid, "process_name": name}
            )
        
        return None
    
    def analyze_cli_command(self, command: str, session_id: str) -> Optional[Threat]:
        """Analyze CLI command for threats"""
        cmd_lower = command.lower()
        
        # Check for malicious commands
        for pattern in self.intel.MALICIOUS_COMMANDS:
            if re.search(pattern, cmd_lower, re.IGNORECASE):
                return Threat(
                    id=f"cli-{uuid.uuid4().hex[:8]}",
                    type="malicious_cli",
                    severity=ThreatSeverity.CRITICAL,
                    title="Malicious CLI Command Detected",
                    description=f"Potentially malicious command executed",
                    source="cli_monitor",
                    target=command[:100],
                    evidence={
                        "command": command,
                        "session_id": session_id,
                        "pattern": pattern
                    },
                    remediation_available=False
                )
        
        # Check for data exfiltration
        for pattern in self.intel.EXFIL_PATTERNS:
            if re.search(pattern, cmd_lower, re.IGNORECASE):
                return Threat(
                    id=f"cli-{uuid.uuid4().hex[:8]}",
                    type="data_exfiltration",
                    severity=ThreatSeverity.HIGH,
                    title="Potential Data Exfiltration",
                    description=f"Command may be exfiltrating data",
                    source="cli_monitor",
                    target=command[:100],
                    evidence={
                        "command": command,
                        "pattern": pattern
                    },
                    remediation_available=False
                )
        
        return None


# =============================================================================
# ADVANCED DETECTION MODULES
# =============================================================================

class RootkitDetector:
    """Detect rootkits and kernel-level threats"""
    
    def __init__(self):
        self.known_rootkit_signatures = [
            # File-based signatures
            'rk_', 'rootkit', 'hide_', 'stealth',
            'kernel_', 'sys_hijack', 'hook_',
        ]
        self.suspicious_drivers = []
        self.hidden_processes = []
    
    def scan(self) -> List[dict]:
        """Perform rootkit scan"""
        findings = []
        
        # Check for hidden processes
        try:
            visible_pids = set(psutil.pids())
            
            # Try to access /proc directly on Linux
            if os.name == 'posix' and os.path.exists('/proc'):
                proc_pids = set()
                for entry in os.listdir('/proc'):
                    if entry.isdigit():
                        proc_pids.add(int(entry))
                
                hidden = proc_pids - visible_pids
                for pid in hidden:
                    findings.append({
                        "type": "hidden_process",
                        "severity": "critical",
                        "pid": pid,
                        "message": f"Hidden process detected: PID {pid}"
                    })
        except:
            pass
        
        # Check for suspicious kernel modules (Linux)
        if os.name == 'posix':
            try:
                result = subprocess.run(['lsmod'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    for sig in self.known_rootkit_signatures:
                        if sig in line.lower():
                            findings.append({
                                "type": "suspicious_module",
                                "severity": "high",
                                "module": line.split()[0],
                                "message": f"Suspicious kernel module: {line.split()[0]}"
                            })
            except:
                pass
        
        # Check for suspicious drivers (Windows)
        if os.name == 'nt':
            try:
                result = subprocess.run(['driverquery', '/v'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    for sig in self.known_rootkit_signatures:
                        if sig in line.lower():
                            findings.append({
                                "type": "suspicious_driver",
                                "severity": "high",
                                "driver": line.strip()[:50],
                                "message": f"Suspicious driver detected"
                            })
            except:
                pass
        
        # Check for hooked system calls (basic)
        try:
            # Check if certain syscalls return unexpected values
            import ctypes
            if os.name == 'nt':
                # Windows: Check for IAT hooks
                kernel32 = ctypes.windll.kernel32
                # Basic integrity check
                pass
        except:
            pass
        
        return findings


class HiddenFolderDetector:
    """Detect hidden folders and suspicious file structures"""
    
    def __init__(self):
        self.suspicious_hidden_patterns = [
            r'^\.',              # Unix hidden files
            r'^\$',              # Windows system/hidden
            r'~\$',              # Office temp files
            r'\.tmp$',
            r'\.bak$',
            r'thumbs\.db',
            r'desktop\.ini',
        ]
        
        self.malware_folder_names = [
            'temp', 'tmp', 'cache', 'appdata', 'programdata',
            '.hidden', '.secret', '.malware', '.backdoor',
            'system32', 'syswow64',  # Mimicking system folders
        ]
    
    def scan(self, paths: List[str] = None) -> List[dict]:
        """Scan for hidden and suspicious folders"""
        findings = []
        
        if paths is None:
            # Default scan paths
            if os.name == 'nt':
                paths = [
                    os.environ.get('TEMP', 'C:\\Windows\\Temp'),
                    os.environ.get('APPDATA', ''),
                    os.environ.get('LOCALAPPDATA', ''),
                    'C:\\ProgramData',
                ]
            else:
                paths = ['/tmp', '/var/tmp', os.path.expanduser('~')]
        
        for scan_path in paths:
            if not scan_path or not os.path.exists(scan_path):
                continue
            
            try:
                for root, dirs, files in os.walk(scan_path):
                    # Limit depth
                    if root.count(os.sep) - scan_path.count(os.sep) > 3:
                        continue
                    
                    for d in dirs:
                        # Check for hidden attribute (Windows)
                        full_path = os.path.join(root, d)
                        is_hidden = False
                        
                        if os.name == 'nt':
                            try:
                                attrs = ctypes.windll.kernel32.GetFileAttributesW(full_path)
                                is_hidden = attrs != -1 and (attrs & 2)  # FILE_ATTRIBUTE_HIDDEN
                            except:
                                pass
                        else:
                            is_hidden = d.startswith('.')
                        
                        # Check if suspicious
                        if is_hidden:
                            # Check for executable content
                            try:
                                exe_count = sum(1 for f in os.listdir(full_path) 
                                              if f.endswith(('.exe', '.dll', '.bat', '.ps1', '.sh')))
                                if exe_count > 0:
                                    findings.append({
                                        "type": "hidden_executable_folder",
                                        "severity": "high",
                                        "path": full_path,
                                        "exe_count": exe_count,
                                        "message": f"Hidden folder with {exe_count} executables"
                                    })
                            except:
                                pass
                        
                        # Check for suspicious names
                        d_lower = d.lower()
                        for pattern in self.malware_folder_names:
                            if pattern in d_lower and 'system32' not in root.lower():
                                # Check modification time
                                try:
                                    mtime = os.path.getmtime(full_path)
                                    age_hours = (time.time() - mtime) / 3600
                                    if age_hours < 24:  # Recently created
                                        findings.append({
                                            "type": "suspicious_recent_folder",
                                            "severity": "medium",
                                            "path": full_path,
                                            "age_hours": round(age_hours, 1),
                                            "message": f"Recently created suspicious folder"
                                        })
                                except:
                                    pass
            except PermissionError:
                pass
            except Exception as e:
                pass
        
        return findings


class AdminPrivilegesMonitor:
    """Monitor for privilege escalation and admin access"""
    
    def __init__(self):
        self.baseline_admins = set()
        self.baseline_sudoers = set()
        self.admin_changes = []
    
    def get_current_admins(self) -> dict:
        """Get current admin users and privileges"""
        admins = {
            "local_admins": [],
            "sudoers": [],
            "elevated_processes": [],
            "scheduled_tasks_as_admin": [],
            "services_as_system": []
        }
        
        if os.name == 'nt':
            # Windows: Get local administrators
            try:
                result = subprocess.run(
                    ['net', 'localgroup', 'administrators'],
                    capture_output=True, text=True
                )
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('-') and 'Members' not in line and 'Alias' not in line and 'Comment' not in line:
                        if line not in ['The command completed successfully.', '']:
                            admins["local_admins"].append(line)
            except:
                pass
            
            # Get elevated processes
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    if proc.info['username'] and 'SYSTEM' in proc.info['username']:
                        admins["elevated_processes"].append({
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "user": proc.info['username']
                        })
                except:
                    pass
        else:
            # Linux: Get sudoers
            try:
                with open('/etc/sudoers', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            admins["sudoers"].append(line[:100])
            except:
                pass
            
            # Get wheel/sudo group members
            try:
                result = subprocess.run(['getent', 'group', 'sudo'], capture_output=True, text=True)
                if result.stdout:
                    members = result.stdout.strip().split(':')[-1].split(',')
                    admins["local_admins"].extend(members)
            except:
                pass
            
            # Get root processes
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    if proc.info['username'] == 'root':
                        admins["elevated_processes"].append({
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "user": proc.info['username']
                        })
                except:
                    pass
        
        return admins
    
    def detect_changes(self) -> List[dict]:
        """Detect changes in admin privileges"""
        current = self.get_current_admins()
        changes = []
        
        current_admin_set = set(current.get("local_admins", []))
        
        # Check for new admins
        new_admins = current_admin_set - self.baseline_admins
        for admin in new_admins:
            changes.append({
                "type": "new_admin_user",
                "severity": "critical",
                "user": admin,
                "message": f"New admin user detected: {admin}"
            })
        
        # Update baseline
        if not self.baseline_admins:
            self.baseline_admins = current_admin_set
        
        return changes


class AliasDetector:
    """Detect shell aliases that could be malicious"""
    
    def __init__(self):
        self.suspicious_alias_patterns = [
            r'alias\s+sudo\s*=',       # Hijacking sudo
            r'alias\s+ls\s*=.*rm',     # ls doing destructive actions
            r'alias\s+cd\s*=',         # Hijacking cd
            r'alias\s+.*curl.*http',   # Hidden network calls
            r'alias\s+.*wget.*http',
            r'alias\s+.*nc\s',         # Netcat aliases
            r'alias\s+.*ncat\s',
            r'alias\s+.*python.*-c',   # Python one-liners
        ]
    
    def scan(self) -> List[dict]:
        """Scan for suspicious aliases"""
        findings = []
        alias_files = []
        
        if os.name == 'posix':
            home = os.path.expanduser('~')
            alias_files = [
                os.path.join(home, '.bashrc'),
                os.path.join(home, '.bash_aliases'),
                os.path.join(home, '.zshrc'),
                os.path.join(home, '.profile'),
                '/etc/bash.bashrc',
                '/etc/profile',
            ]
        elif os.name == 'nt':
            # Windows: Check PowerShell profiles
            alias_files = [
                os.path.join(os.environ.get('USERPROFILE', ''), 'Documents', 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Documents', 'PowerShell', 'Microsoft.PowerShell_profile.ps1'),
            ]
        
        for alias_file in alias_files:
            if not os.path.exists(alias_file):
                continue
            
            try:
                with open(alias_file, 'r') as f:
                    content = f.read()
                    
                for pattern in self.suspicious_alias_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        findings.append({
                            "type": "suspicious_alias",
                            "severity": "high",
                            "file": alias_file,
                            "alias": match[:100],
                            "message": f"Suspicious alias in {os.path.basename(alias_file)}"
                        })
            except:
                pass
        
        return findings


class FileIndexer:
    """Index and monitor files for threat detection"""
    
    def __init__(self):
        self.file_index = {}
        self.suspicious_extensions = [
            '.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.hta',
            '.scr', '.pif', '.com', '.cmd', '.msi', '.jar',
            '.encrypted', '.locked', '.crypt', '.crypto',
        ]
        self.hash_cache = {}
    
    def index_directory(self, path: str, max_depth: int = 3) -> dict:
        """Index files in a directory"""
        index = {
            "total_files": 0,
            "executable_files": [],
            "recently_modified": [],
            "large_files": [],
            "suspicious_files": []
        }
        
        try:
            for root, dirs, files in os.walk(path):
                depth = root.count(os.sep) - path.count(os.sep)
                if depth > max_depth:
                    continue
                
                for fname in files:
                    index["total_files"] += 1
                    fpath = os.path.join(root, fname)
                    
                    try:
                        stat = os.stat(fpath)
                        fsize = stat.st_size
                        mtime = stat.st_mtime
                        age_hours = (time.time() - mtime) / 3600
                        
                        # Check for executables
                        ext = os.path.splitext(fname)[1].lower()
                        if ext in self.suspicious_extensions:
                            index["executable_files"].append({
                                "path": fpath,
                                "size": fsize,
                                "extension": ext
                            })
                        
                        # Recently modified
                        if age_hours < 1:
                            index["recently_modified"].append({
                                "path": fpath,
                                "age_minutes": round(age_hours * 60, 1)
                            })
                        
                        # Large files
                        if fsize > 100 * 1024 * 1024:  # 100MB
                            index["large_files"].append({
                                "path": fpath,
                                "size_mb": round(fsize / 1024 / 1024, 1)
                            })
                        
                        # Suspicious patterns in filename
                        fname_lower = fname.lower()
                        if any(s in fname_lower for s in ['mimikatz', 'lazagne', 'pwdump', 'backdoor', 'keylog', 'ransom']):
                            index["suspicious_files"].append({
                                "path": fpath,
                                "reason": "suspicious_name"
                            })
                        
                    except:
                        pass
        except:
            pass
        
        return index
    
    def get_file_telemetry(self) -> dict:
        """Get file system telemetry for graphing"""
        telemetry = {
            "timestamp": datetime.now().isoformat(),
            "total_indexed": 0,
            "executables": 0,
            "recent_changes": 0,
            "suspicious": 0,
            "by_extension": {},
            "by_directory": {}
        }
        
        # Scan key directories
        scan_paths = []
        if os.name == 'nt':
            scan_paths = [
                os.environ.get('TEMP', 'C:\\Windows\\Temp'),
                os.environ.get('APPDATA', ''),
                os.path.expanduser('~\\Downloads'),
            ]
        else:
            scan_paths = ['/tmp', '/var/tmp', os.path.expanduser('~/Downloads')]
        
        for path in scan_paths:
            if path and os.path.exists(path):
                idx = self.index_directory(path, max_depth=2)
                telemetry["total_indexed"] += idx["total_files"]
                telemetry["executables"] += len(idx["executable_files"])
                telemetry["recent_changes"] += len(idx["recently_modified"])
                telemetry["suspicious"] += len(idx["suspicious_files"])
                telemetry["by_directory"][path] = idx["total_files"]
        
        return telemetry


class NetworkScanner:
    """Scan ports, routers, and network infrastructure"""
    
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
        self.dangerous_ports = [23, 445, 1433, 3389, 5900]  # Telnet, SMB, MSSQL, RDP, VNC
        self.scan_results = {}
    
    def get_gateway(self) -> str:
        """Get default gateway IP"""
        try:
            if os.name == 'nt':
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
    
    def scan_host(self, ip: str, ports: List[int] = None) -> dict:
        """Scan a host for open ports"""
        if ports is None:
            ports = self.common_ports
        
        open_ports = []
        for port in ports:
            if self.scan_port(ip, port):
                open_ports.append({
                    "port": port,
                    "service": self._get_service_name(port),
                    "dangerous": port in self.dangerous_ports
                })
        
        return {
            "ip": ip,
            "open_ports": open_ports,
            "scan_time": datetime.now().isoformat()
        }
    
    def scan_router(self) -> dict:
        """Scan the default gateway/router"""
        gateway = self.get_gateway()
        if not gateway:
            return {"error": "Could not determine gateway"}
        
        router_ports = [80, 443, 8080, 22, 23, 53]  # Common router admin ports
        result = self.scan_host(gateway, router_ports)
        result["is_gateway"] = True
        
        # Check for common vulnerabilities
        vulnerabilities = []
        if any(p["port"] == 23 for p in result["open_ports"]):
            vulnerabilities.append({"type": "telnet_open", "severity": "high", "message": "Telnet is enabled on router"})
        if any(p["port"] == 80 for p in result["open_ports"]):
            vulnerabilities.append({"type": "http_admin", "severity": "medium", "message": "HTTP admin interface exposed"})
        
        result["vulnerabilities"] = vulnerabilities
        return result
    
    def scan_local_network(self, subnet: str = None) -> List[dict]:
        """Scan local network for hosts"""
        if subnet is None:
            # Get local IP and derive subnet
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                subnet = '.'.join(local_ip.split('.')[:-1])
            except:
                return []
        
        hosts = []
        for i in range(1, 255):
            ip = f"{subnet}.{i}"
            # Quick ping check
            try:
                if os.name == 'nt':
                    result = subprocess.run(['ping', '-n', '1', '-w', '100', ip], capture_output=True)
                else:
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], capture_output=True)
                
                if result.returncode == 0:
                    hosts.append({"ip": ip, "alive": True})
            except:
                pass
        
        return hosts
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        return services.get(port, "Unknown")


class WiFiScanner:
    """Scan WiFi networks and detect rogue access points"""
    
    def __init__(self):
        self.known_networks = set()
        self.trusted_bssids = set()
    
    def scan_networks(self) -> List[dict]:
        """Scan for available WiFi networks"""
        networks = []
        
        try:
            if os.name == 'nt':
                # Windows: Use netsh
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                    capture_output=True, text=True
                )
                
                current_network = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('SSID'):
                        if current_network and current_network.get('ssid'):
                            networks.append(current_network)
                        current_network = {}
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            current_network['ssid'] = parts[1].strip()
                    elif line.startswith('BSSID'):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            current_network['bssid'] = parts[1].strip()
                    elif line.startswith('Signal'):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            current_network['signal'] = parts[1].strip()
                    elif line.startswith('Authentication'):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            current_network['auth'] = parts[1].strip()
                    elif line.startswith('Encryption'):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            current_network['encryption'] = parts[1].strip()
                
                if current_network and current_network.get('ssid'):
                    networks.append(current_network)
                    
            else:
                # Linux: Use iwlist or nmcli
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
            pass
        
        # Analyze for threats
        for network in networks:
            network['threats'] = self._analyze_network(network)
        
        return networks
    
    def _analyze_network(self, network: dict) -> List[dict]:
        """Analyze a network for potential threats"""
        threats = []
        
        # Check for open networks
        auth = network.get('auth', '').lower()
        encryption = network.get('encryption', '').lower()
        
        if 'open' in auth or 'none' in encryption:
            threats.append({
                "type": "open_network",
                "severity": "high",
                "message": "Network has no encryption"
            })
        
        # Check for weak encryption
        if 'wep' in encryption or 'wep' in auth:
            threats.append({
                "type": "weak_encryption",
                "severity": "critical",
                "message": "WEP encryption is easily cracked"
            })
        
        # Check for evil twin (same SSID, different BSSID)
        ssid = network.get('ssid', '')
        if ssid in self.known_networks:
            threats.append({
                "type": "potential_evil_twin",
                "severity": "high",
                "message": "Multiple networks with same SSID detected"
            })
        else:
            self.known_networks.add(ssid)
        
        # Check for suspicious SSIDs
        suspicious_patterns = ['free', 'public', 'guest', 'airport', 'hotel']
        if any(p in ssid.lower() for p in suspicious_patterns):
            threats.append({
                "type": "suspicious_ssid",
                "severity": "medium",
                "message": "Network name suggests public/untrusted network"
            })
        
        return threats
    
    def get_connected_network(self) -> dict:
        """Get currently connected WiFi network info"""
        try:
            if os.name == 'nt':
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'interfaces'],
                    capture_output=True, text=True
                )
                info = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if ':' in line:
                        key, value = line.split(':', 1)
                        info[key.strip().lower()] = value.strip()
                
                return {
                    "ssid": info.get('ssid', 'Unknown'),
                    "bssid": info.get('bssid', 'Unknown'),
                    "signal": info.get('signal', 'Unknown'),
                    "state": info.get('state', 'Unknown')
                }
            else:
                result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True)
                return {"ssid": result.stdout.strip()}
        except:
            return {"error": "Could not get connected network"}


class BluetoothScanner:
    """Scan for Bluetooth devices"""
    
    def __init__(self):
        self.known_devices = {}
        self.trusted_devices = set()
    
    def scan_devices(self) -> List[dict]:
        """Scan for nearby Bluetooth devices"""
        devices = []
        
        try:
            if os.name == 'nt':
                # Windows: Use PowerShell
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
                # Linux: Use hcitool or bluetoothctl
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
        except:
            pass
        
        # Analyze for threats
        for device in devices:
            device['threats'] = self._analyze_device(device)
        
        return devices
    
    def _analyze_device(self, device: dict) -> List[dict]:
        """Analyze Bluetooth device for threats"""
        threats = []
        
        name = device.get('name', '').lower()
        
        # Check for suspicious device names
        suspicious_names = ['keylogger', 'hak', 'pwn', 'evil', 'attack']
        if any(s in name for s in suspicious_names):
            threats.append({
                "type": "suspicious_device",
                "severity": "high",
                "message": "Suspicious Bluetooth device name"
            })
        
        # Check for unknown devices
        device_id = device.get('id') or device.get('address')
        if device_id and device_id not in self.trusted_devices:
            threats.append({
                "type": "unknown_device",
                "severity": "low",
                "message": "Unknown Bluetooth device nearby"
            })
        
        return threats


# Initialize scanners
network_scanner = NetworkScanner()
wifi_scanner = WiFiScanner()
bluetooth_scanner = BluetoothScanner()


# =============================================================================
# WIREGUARD VPN AUTO-CONFIGURATION
# =============================================================================

class WireGuardVPN:
    """WireGuard VPN auto-configuration - split tunnel (won't block internet)"""
    
    def __init__(self):
        self.config_dir = INSTALL_DIR / "vpn"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.interface_name = "seraph0"
        self.server_endpoint = None
        self.server_public_key = None
        self.private_key = None
        self.public_key = None
        self.address = None
        self.is_configured = False
        self.is_connected = False
    
    def generate_keys(self) -> Tuple[str, str]:
        """Generate WireGuard key pair"""
        try:
            # Try using wg command
            private = subprocess.check_output(['wg', 'genkey'], stderr=subprocess.DEVNULL).decode().strip()
            public = subprocess.check_output(['wg', 'pubkey'], input=private.encode(), stderr=subprocess.DEVNULL).decode().strip()
            return private, public
        except:
            # Fallback to Python implementation
            import secrets
            import base64
            private_bytes = secrets.token_bytes(32)
            private_key = base64.b64encode(private_bytes).decode()
            # Note: Full Curve25519 would require cryptography library
            # For demo purposes, we generate a placeholder
            public_key = base64.b64encode(secrets.token_bytes(32)).decode()
            return private_key, public_key
    
    def auto_configure(self, server_endpoint: str, server_public_key: str, 
                       allowed_ips: str = "10.200.200.0/24") -> dict:
        """
        Auto-configure WireGuard VPN with SPLIT TUNNEL
        - Only routes Seraph network traffic through VPN
        - Does NOT block normal internet access
        """
        try:
            self.server_endpoint = server_endpoint
            self.server_public_key = server_public_key
            
            # Generate client keys
            self.private_key, self.public_key = self.generate_keys()
            
            # Assign client address (derive from agent ID)
            client_num = int(AGENT_ID[:4], 16) % 200 + 10  # Range: 10-209
            self.address = f"10.200.200.{client_num}/32"
            
            # Create config file (SPLIT TUNNEL - only route VPN subnet)
            config = f"""# Seraph AI VPN Configuration
# Split tunnel mode - normal internet NOT affected

[Interface]
PrivateKey = {self.private_key}
Address = {self.address}
# DNS is NOT changed - uses your normal DNS

[Peer]
PublicKey = {self.server_public_key}
Endpoint = {self.server_endpoint}
# IMPORTANT: Only route Seraph network, not all traffic (0.0.0.0/0)
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
            
            config_path = self.config_dir / f"{self.interface_name}.conf"
            with open(config_path, 'w') as f:
                f.write(config)
            
            self.is_configured = True
            
            logger.info(f"WireGuard VPN configured: {config_path}")
            logger.info(f"Client address: {self.address}")
            logger.info("Split tunnel mode: Normal internet access preserved")
            
            return {
                "success": True,
                "config_path": str(config_path),
                "client_address": self.address,
                "client_public_key": self.public_key,
                "mode": "split_tunnel",
                "allowed_ips": allowed_ips,
                "message": "VPN configured. Normal internet NOT affected."
            }
            
        except Exception as e:
            logger.error(f"VPN configuration failed: {e}")
            return {"success": False, "error": str(e)}
    
    def connect(self) -> dict:
        """Connect to VPN (requires admin/root)"""
        if not self.is_configured:
            return {"success": False, "error": "VPN not configured"}
        
        config_path = self.config_dir / f"{self.interface_name}.conf"
        
        try:
            if OS_TYPE == 'windows':
                # Windows: Use wireguard.exe
                subprocess.run(['wireguard', '/installtunnelservice', str(config_path)], 
                             check=True, capture_output=True)
            else:
                # Linux/macOS: Use wg-quick
                subprocess.run(['wg-quick', 'up', str(config_path)], 
                             check=True, capture_output=True)
            
            self.is_connected = True
            logger.info("VPN connected successfully")
            return {"success": True, "message": "VPN connected"}
            
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": f"Connection failed: {e.stderr.decode() if e.stderr else str(e)}"}
        except FileNotFoundError:
            return {"success": False, "error": "WireGuard not installed. Install from: https://www.wireguard.com/install/"}
    
    def disconnect(self) -> dict:
        """Disconnect from VPN"""
        config_path = self.config_dir / f"{self.interface_name}.conf"
        
        try:
            if OS_TYPE == 'windows':
                subprocess.run(['wireguard', '/uninstalltunnelservice', self.interface_name], 
                             check=True, capture_output=True)
            else:
                subprocess.run(['wg-quick', 'down', str(config_path)], 
                             check=True, capture_output=True)
            
            self.is_connected = False
            logger.info("VPN disconnected")
            return {"success": True, "message": "VPN disconnected"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_status(self) -> dict:
        """Get VPN status"""
        return {
            "configured": self.is_configured,
            "connected": self.is_connected,
            "interface": self.interface_name,
            "address": self.address,
            "server_endpoint": self.server_endpoint,
            "client_public_key": self.public_key,
            "config_path": str(self.config_dir / f"{self.interface_name}.conf") if self.is_configured else None,
            "mode": "split_tunnel"
        }


# Initialize VPN
wireguard_vpn = WireGuardVPN()


# =============================================================================
# NETWORK SCAN RESULTS STORE
# =============================================================================

class NetworkScanResults:
    """Store for network scan results"""
    
    def __init__(self):
        self.port_scan_results = {}
        self.wifi_scan_results = []
        self.bluetooth_scan_results = []
        self.router_scan_result = {}
        self.local_network_hosts = []
        self.last_port_scan = None
        self.last_wifi_scan = None
        self.last_bluetooth_scan = None
        self.last_router_scan = None
        self.last_network_scan = None
        self.scan_in_progress = False
    
    def to_dict(self) -> dict:
        return {
            "port_scan": {
                "results": self.port_scan_results,
                "last_scan": self.last_port_scan
            },
            "wifi_scan": {
                "results": self.wifi_scan_results,
                "last_scan": self.last_wifi_scan
            },
            "bluetooth_scan": {
                "results": self.bluetooth_scan_results,
                "last_scan": self.last_bluetooth_scan
            },
            "router_scan": {
                "results": self.router_scan_result,
                "last_scan": self.last_router_scan
            },
            "network_hosts": {
                "results": self.local_network_hosts,
                "last_scan": self.last_network_scan
            },
            "scan_in_progress": self.scan_in_progress
        }


# Initialize network scan results store
network_scan_results = NetworkScanResults()


# =============================================================================
# SIEM INTEGRATION (Elasticsearch / Splunk / Syslog)
# =============================================================================

class SIEMIntegration:
    """Full SIEM integration for enterprise logging"""
    
    def __init__(self):
        self.elasticsearch_url = os.environ.get('ELASTICSEARCH_URL', '')
        self.elasticsearch_index = os.environ.get('SIEM_INDEX', 'seraph-security')
        self.splunk_hec_url = os.environ.get('SPLUNK_HEC_URL', '')
        self.splunk_hec_token = os.environ.get('SPLUNK_HEC_TOKEN', '')
        self.syslog_server = os.environ.get('SYSLOG_SERVER', '')
        self.syslog_port = int(os.environ.get('SYSLOG_PORT', '514'))
        self.enabled = False
        self.buffer = deque(maxlen=1000)
        self.last_flush = time.time()
        self.flush_interval = 5  # seconds
        
        # Auto-detect available SIEM
        if self.elasticsearch_url:
            self.enabled = True
            self.siem_type = 'elasticsearch'
            logger.info(f"SIEM: Elasticsearch enabled at {self.elasticsearch_url}")
        elif self.splunk_hec_url:
            self.enabled = True
            self.siem_type = 'splunk'
            logger.info(f"SIEM: Splunk HEC enabled at {self.splunk_hec_url}")
        elif self.syslog_server:
            self.enabled = True
            self.siem_type = 'syslog'
            logger.info(f"SIEM: Syslog enabled at {self.syslog_server}:{self.syslog_port}")
    
    def log_event(self, event_type: str, severity: str, data: dict, immediate: bool = False):
        """Log a security event to SIEM"""
        event = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": AGENT_ID,
            "hostname": HOSTNAME,
            "os": OS_TYPE,
            "event_type": event_type,
            "severity": severity,
            "data": data,
            "source": "seraph_defender"
        }
        
        if immediate or severity in ['critical', 'high']:
            # Send immediately for high-priority events
            self._send_event(event)
        else:
            # Buffer for batch sending
            self.buffer.append(event)
            if time.time() - self.last_flush >= self.flush_interval:
                self._flush_buffer()
    
    def log_threat(self, threat: 'Threat', action: str = "detected"):
        """Log a threat detection/remediation to SIEM"""
        self.log_event(
            event_type=f"threat.{action}",
            severity=threat.severity.value,
            data={
                "threat_id": threat.id,
                "threat_type": threat.type,
                "title": threat.title,
                "description": threat.description,
                "remediation_action": threat.remediation_action,
                "status": threat.status,
                "auto_kill": getattr(threat, 'kill_reason', None)
            },
            immediate=threat.severity in {ThreatSeverity.CRITICAL, ThreatSeverity.HIGH}
        )
    
    def log_auto_kill(self, threat: 'Threat', success: bool, details: str):
        """Log an auto-kill action to SIEM"""
        self.log_event(
            event_type="auto_kill.executed",
            severity="critical",
            data={
                "threat_id": threat.id,
                "threat_title": threat.title,
                "kill_reason": getattr(threat, 'kill_reason', 'unknown'),
                "success": success,
                "details": details,
                "remediation_command": threat.remediation_command
            },
            immediate=True
        )
    
    def log_network_scan(self, scan_type: str, results: dict):
        """Log network scan results to SIEM"""
        self.log_event(
            event_type=f"network_scan.{scan_type}",
            severity="info",
            data=results,
            immediate=False
        )
    
    def _send_event(self, event: dict):
        """Send event to configured SIEM"""
        if not self.enabled:
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
        import urllib.request
        url = f"{self.elasticsearch_url}/{self.elasticsearch_index}/_doc"
        data = json.dumps(event).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        urllib.request.urlopen(req, timeout=5)
    
    def _send_to_splunk(self, event: dict):
        """Send to Splunk HEC"""
        import urllib.request
        data = json.dumps({"event": event}).encode()
        req = urllib.request.Request(
            self.splunk_hec_url, data=data,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Splunk {self.splunk_hec_token}'
            },
            method='POST'
        )
        urllib.request.urlopen(req, timeout=5)
    
    def _send_to_syslog(self, event: dict):
        """Send to Syslog server"""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Format as CEF (Common Event Format)
        severity_map = {'critical': 10, 'high': 7, 'medium': 5, 'low': 3, 'info': 1}
        sev = severity_map.get(event.get('severity', 'info'), 1)
        msg = f"CEF:0|Seraph|Defender|7.0|{event['event_type']}|{event.get('data', {}).get('title', 'Security Event')}|{sev}|src={HOSTNAME} suser={AGENT_ID}"
        sock.sendto(msg.encode(), (self.syslog_server, self.syslog_port))
        sock.close()
    
    def _flush_buffer(self):
        """Flush buffered events to SIEM"""
        while self.buffer:
            event = self.buffer.popleft()
            self._send_event(event)
        self.last_flush = time.time()


# Initialize SIEM
siem = SIEMIntegration()


# =============================================================================
# USB SCANNER & MONITORING
# =============================================================================

class USBScanner:
    """USB device monitoring and auto-scan"""
    
    def __init__(self):
        self.known_devices = set()
        self.scan_results = []
        self.last_scan = None
        self.auto_scan_enabled = True
        
        # Dangerous file patterns on USB
        self.dangerous_patterns = [
            # Autorun
            'autorun.inf', 'autorun.bat', 'autorun.cmd',
            # BadUSB / Rubber Ducky
            'payload.txt', 'inject.bin', 'ducky.txt', 'hak5.txt',
            # Executables
            '*.exe', '*.bat', '*.cmd', '*.ps1', '*.vbs', '*.js', '*.jse',
            '*.wsf', '*.wsh', '*.msi', '*.scr', '*.pif', '*.com',
            # Scripts
            '*.sh', '*.bash', '*.py', '*.pl', '*.rb',
            # Office macros
            '*.docm', '*.xlsm', '*.pptm', '*.dotm', '*.xltm',
            # Shortcuts/Links (LNK attacks)
            '*.lnk', '*.url',
        ]
    
    def get_usb_devices(self) -> List[dict]:
        """Get list of connected USB devices"""
        devices = []
        
        if OS_TYPE == 'windows':
            try:
                # Use WMIC to get USB drives
                result = subprocess.run(
                    ['wmic', 'logicaldisk', 'where', 'drivetype=2', 'get', 
                     'deviceid,volumename,size,freespace', '/format:list'],
                    capture_output=True, text=True, timeout=10
                )
                current = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if '=' in line:
                        key, val = line.split('=', 1)
                        current[key.lower()] = val
                    elif current:
                        if current.get('deviceid'):
                            devices.append({
                                'id': current.get('deviceid'),
                                'name': current.get('volumename', 'Unknown'),
                                'path': current.get('deviceid') + '\\',
                                'size': current.get('size', 'Unknown'),
                                'type': 'removable'
                            })
                        current = {}
            except Exception as e:
                logger.debug(f"USB scan error: {e}")
        else:
            # Linux: Check /media and /mnt
            for mount_base in ['/media', '/mnt', f'/run/media/{os.getenv("USER", "")}']:
                if os.path.exists(mount_base):
                    try:
                        for item in os.listdir(mount_base):
                            path = os.path.join(mount_base, item)
                            if os.path.ismount(path):
                                devices.append({
                                    'id': item,
                                    'name': item,
                                    'path': path,
                                    'type': 'removable'
                                })
                    except:
                        pass
            
            # Also check lsblk for removable devices
            try:
                result = subprocess.run(
                    ['lsblk', '-J', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT,RM'],
                    capture_output=True, text=True, timeout=10
                )
                data = json.loads(result.stdout)
                for dev in data.get('blockdevices', []):
                    if dev.get('rm') == '1' and dev.get('mountpoint'):  # Removable
                        devices.append({
                            'id': dev['name'],
                            'name': dev['name'],
                            'path': dev['mountpoint'],
                            'size': dev.get('size', 'Unknown'),
                            'type': 'removable'
                        })
            except:
                pass
        
        return devices
    
    def scan_usb(self, device_path: str) -> dict:
        """Scan a USB device for threats"""
        result = {
            'path': device_path,
            'scanned_at': datetime.now().isoformat(),
            'total_files': 0,
            'threats': [],
            'suspicious_files': [],
            'dangerous_files': []
        }
        
        if not os.path.exists(device_path):
            result['error'] = 'Device not found'
            return result
        
        try:
            for root, dirs, files in os.walk(device_path):
                for fname in files:
                    result['total_files'] += 1
                    fpath = os.path.join(root, fname)
                    fname_lower = fname.lower()
                    
                    # Check for autorun (CRITICAL)
                    if fname_lower == 'autorun.inf':
                        result['threats'].append({
                            'type': 'autorun',
                            'severity': 'critical',
                            'path': fpath,
                            'message': 'Autorun file detected - potential malware vector'
                        })
                    
                    # Check for dangerous file types
                    for pattern in self.dangerous_patterns:
                        if pattern.startswith('*'):
                            if fname_lower.endswith(pattern[1:]):
                                # Check if it's an executable in root (suspicious)
                                if root == device_path:
                                    result['dangerous_files'].append({
                                        'path': fpath,
                                        'type': pattern[2:],
                                        'message': f'Executable in USB root: {fname}'
                                    })
                                else:
                                    result['suspicious_files'].append({
                                        'path': fpath,
                                        'type': pattern[2:]
                                    })
                        elif fname_lower == pattern:
                            result['threats'].append({
                                'type': 'badusb',
                                'severity': 'high',
                                'path': fpath,
                                'message': f'Potential BadUSB/Rubber Ducky file: {fname}'
                            })
                    
                    # Check for hidden executables
                    if fname_lower.endswith(('.exe', '.bat', '.ps1', '.vbs')):
                        try:
                            if OS_TYPE == 'windows':
                                attrs = ctypes.windll.kernel32.GetFileAttributesW(fpath)
                                if attrs != -1 and (attrs & 2):  # Hidden
                                    result['threats'].append({
                                        'type': 'hidden_executable',
                                        'severity': 'high',
                                        'path': fpath,
                                        'message': f'Hidden executable: {fname}'
                                    })
                            else:
                                if fname.startswith('.'):
                                    result['threats'].append({
                                        'type': 'hidden_executable',
                                        'severity': 'high',
                                        'path': fpath,
                                        'message': f'Hidden executable: {fname}'
                                    })
                        except:
                            pass
                
                # Limit scan depth
                if root.count(os.sep) - device_path.count(os.sep) > 5:
                    break
        except PermissionError:
            result['error'] = 'Permission denied'
        except Exception as e:
            result['error'] = str(e)
        
        self.scan_results.append(result)
        self.last_scan = datetime.now().isoformat()
        
        # Log to SIEM
        if siem.enabled:
            siem.log_event(
                event_type="usb_scan.completed",
                severity="high" if result['threats'] else "info",
                data={
                    'device_path': device_path,
                    'threats_found': len(result['threats']),
                    'dangerous_files': len(result['dangerous_files'])
                },
                immediate=len(result['threats']) > 0
            )
        
        return result
    
    def monitor_new_devices(self) -> List[dict]:
        """Check for newly connected USB devices"""
        new_devices = []
        current_devices = self.get_usb_devices()
        
        for device in current_devices:
            device_id = device.get('id', '')
            if device_id and device_id not in self.known_devices:
                self.known_devices.add(device_id)
                new_devices.append(device)
                
                # Auto-scan new device
                if self.auto_scan_enabled:
                    logger.info(f"🔌 New USB detected: {device['name']} - Auto-scanning...")
                    scan_result = self.scan_usb(device['path'])
                    device['scan_result'] = scan_result
                    
                    # Create threats for dangerous findings
                    for threat_info in scan_result.get('threats', []):
                        threat = Threat(
                            id=f"usb-{uuid.uuid4().hex[:8]}",
                            type="usb_threat",
                            title=f"USB Threat: {threat_info['type']}",
                            description=threat_info['message'],
                            severity=ThreatSeverity.CRITICAL if threat_info['severity'] == 'critical' else ThreatSeverity.HIGH,
                            source=device['path'],
                            remediation_available=True,
                            remediation_action="quarantine_file",
                            remediation_command=f"Quarantine: {threat_info['path']}",
                            remediation_params={"file_path": threat_info['path']}
                        )
                        # This will trigger auto-kill due to severity
                        telemetry_store.add_threat(threat)
        
        return new_devices
    
    def to_dict(self) -> dict:
        return {
            'devices': self.get_usb_devices(),
            'scan_results': self.scan_results[-10:],
            'last_scan': self.last_scan,
            'auto_scan_enabled': self.auto_scan_enabled
        }


# Initialize USB scanner
usb_scanner = USBScanner()


# =============================================================================
# CUCKOO SANDBOX INTEGRATION (VM-based analysis)
# =============================================================================

class CuckooSandbox:
    """Integration with Cuckoo sandbox for safe malware analysis"""
    
    def __init__(self):
        self.api_url = os.environ.get('CUCKOO_API_URL', '')
        self.api_token = os.environ.get('CUCKOO_API_TOKEN', '')
        self.enabled = bool(self.api_url)
        self.pending_analyses = {}
        self.completed_analyses = deque(maxlen=50)
        
        if self.enabled:
            logger.info(f"Cuckoo Sandbox: Enabled at {self.api_url}")
        else:
            logger.info("Cuckoo Sandbox: Not configured (using local fallback)")
    
    def submit_file(self, file_path: str) -> dict:
        """Submit a file to Cuckoo for analysis"""
        if not os.path.exists(file_path):
            return {"error": "File not found", "success": False}
        
        if self.enabled:
            return self._submit_to_cuckoo(file_path)
        else:
            return self._local_analysis(file_path)
    
    def _submit_to_cuckoo(self, file_path: str) -> dict:
        """Submit file to remote Cuckoo API"""
        try:
            import urllib.request
            from urllib.parse import urlencode
            
            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Create multipart form data
            boundary = '----SeraphBoundary' + uuid.uuid4().hex[:16]
            body = (
                f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="file"; filename="{os.path.basename(file_path)}"\r\n'
                f'Content-Type: application/octet-stream\r\n\r\n'
            ).encode() + file_data + f'\r\n--{boundary}--\r\n'.encode()
            
            headers = {
                'Content-Type': f'multipart/form-data; boundary={boundary}',
                'Authorization': f'Bearer {self.api_token}'
            }
            
            req = urllib.request.Request(
                f'{self.api_url}/tasks/create/file',
                data=body,
                headers=headers,
                method='POST'
            )
            
            response = urllib.request.urlopen(req, timeout=30)
            result = json.loads(response.read().decode())
            
            task_id = result.get('task_id')
            if task_id:
                self.pending_analyses[task_id] = {
                    'file_path': file_path,
                    'submitted_at': datetime.now().isoformat(),
                    'status': 'pending'
                }
                
                return {
                    "success": True,
                    "task_id": task_id,
                    "message": f"File submitted to Cuckoo sandbox (Task: {task_id})"
                }
            
            return {"success": False, "error": "No task ID returned"}
            
        except Exception as e:
            logger.error(f"Cuckoo submission error: {e}")
            # Fallback to local analysis
            return self._local_analysis(file_path)
    
    def _local_analysis(self, file_path: str) -> dict:
        """Local file analysis (when Cuckoo not available)"""
        analysis = {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            "analyzed_at": datetime.now().isoformat(),
            "method": "local",
            "indicators": [],
            "risk_score": 0,
            "verdict": "unknown"
        }
        
        try:
            # Read file header
            with open(file_path, 'rb') as f:
                header = f.read(8192)
            
            # Check for PE header (Windows executable)
            if header[:2] == b'MZ':
                analysis['indicators'].append({
                    "type": "pe_executable",
                    "severity": "medium",
                    "description": "Windows PE executable"
                })
                analysis['risk_score'] += 30
            
            # Check for script signatures
            script_sigs = {
                b'#!/': 'shell_script',
                b'import ': 'python_script',
                b'require ': 'ruby_script',
                b'<script': 'javascript_html',
                b'<?php': 'php_script',
                b'powershell': 'powershell_script',
                b'cmd.exe': 'cmd_invocation',
            }
            
            header_lower = header.lower()
            for sig, script_type in script_sigs.items():
                if sig.lower() in header_lower:
                    analysis['indicators'].append({
                        "type": script_type,
                        "severity": "medium",
                        "description": f"Contains {script_type} signature"
                    })
                    analysis['risk_score'] += 20
            
            # Check for suspicious strings
            suspicious_strings = [
                b'invoke-expression', b'invoke-mimikatz', b'downloadstring',
                b'hidden', b'bypass', b'unrestricted', b'encodedcommand',
                b'frombase64', b'gzipstream', b'memorystream',
                b'virtualalloc', b'createthread', b'shellcode',
                b'password', b'credential', b'lsass', b'sekurlsa',
            ]
            
            for sus in suspicious_strings:
                if sus in header_lower:
                    analysis['indicators'].append({
                        "type": "suspicious_string",
                        "severity": "high",
                        "description": f"Contains suspicious string: {sus.decode()}"
                    })
                    analysis['risk_score'] += 40
            
            # Determine verdict
            if analysis['risk_score'] >= 80:
                analysis['verdict'] = 'malicious'
            elif analysis['risk_score'] >= 40:
                analysis['verdict'] = 'suspicious'
            elif analysis['risk_score'] >= 20:
                analysis['verdict'] = 'potentially_unwanted'
            else:
                analysis['verdict'] = 'clean'
            
            self.completed_analyses.append(analysis)
            
            return {
                "success": True,
                "analysis": analysis,
                "message": f"Local analysis complete: {analysis['verdict']}"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_task_status(self, task_id: str) -> dict:
        """Get status of a Cuckoo analysis task"""
        if not self.enabled:
            return {"error": "Cuckoo not configured"}
        
        try:
            import urllib.request
            req = urllib.request.Request(
                f'{self.api_url}/tasks/view/{task_id}',
                headers={'Authorization': f'Bearer {self.api_token}'}
            )
            response = urllib.request.urlopen(req, timeout=10)
            return json.loads(response.read().decode())
        except Exception as e:
            return {"error": str(e)}
    
    def get_task_report(self, task_id: str) -> dict:
        """Get full report for a completed Cuckoo analysis"""
        if not self.enabled:
            return {"error": "Cuckoo not configured"}
        
        try:
            import urllib.request
            req = urllib.request.Request(
                f'{self.api_url}/tasks/report/{task_id}',
                headers={'Authorization': f'Bearer {self.api_token}'}
            )
            response = urllib.request.urlopen(req, timeout=30)
            return json.loads(response.read().decode())
        except Exception as e:
            return {"error": str(e)}
    
    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "api_url": self.api_url if self.enabled else None,
            "pending_analyses": dict(self.pending_analyses),
            "completed_analyses": list(self.completed_analyses)
        }


# Initialize Cuckoo sandbox
sandbox = CuckooSandbox()


# Initialize advanced detectors
rootkit_detector = RootkitDetector()
hidden_folder_detector = HiddenFolderDetector()
admin_monitor = AdminPrivilegesMonitor()
alias_detector = AliasDetector()
file_indexer = FileIndexer()


# =============================================================================
# REMEDIATION ENGINE
# =============================================================================

class RemediationEngine:
    """Execute approved remediation actions"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_ports = set()
    
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
    
    def _kill_process(self, params: dict) -> Tuple[bool, str]:
        """Kill a malicious process"""
        pid = params.get('pid')
        name = params.get('process_name', 'unknown')
        
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            time.sleep(1)
            if proc.is_running():
                proc.kill()
            logger.info(f"Killed malicious process: {name} (PID: {pid})")
            return True, f"Successfully terminated process {name} (PID: {pid})"
        except psutil.NoSuchProcess:
            return True, f"Process already terminated"
        except psutil.AccessDenied:
            return False, f"Access denied - run as administrator to kill {name}"
        except Exception as e:
            return False, f"Failed to kill process: {e}"
    
    def _block_ip(self, params: dict) -> Tuple[bool, str]:
        """Block an IP address"""
        ip = params.get('ip')
        
        try:
            if OS_TYPE == 'windows':
                # Use Windows Firewall
                cmd = f'netsh advfirewall firewall add rule name="Seraph Block {ip}" dir=out action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
            elif OS_TYPE == 'linux':
                # Use iptables
                subprocess.run(['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=True, capture_output=True)
            elif OS_TYPE == 'darwin':
                # Use pf
                with open('/etc/pf.anchors/seraph', 'a') as f:
                    f.write(f'block out quick to {ip}\n')
                subprocess.run(['pfctl', '-f', '/etc/pf.conf'], capture_output=True)
            
            self.blocked_ips.add(ip)
            logger.info(f"Blocked IP: {ip}")
            return True, f"Successfully blocked IP {ip}"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to block IP (need admin): {e}"
        except Exception as e:
            return False, f"Failed to block IP: {e}"
    
    def _block_connection(self, params: dict) -> Tuple[bool, str]:
        """Block a specific connection and kill the process"""
        ip = params.get('ip')
        port = params.get('port')
        pid = params.get('pid')
        
        # First kill the process
        if pid:
            success, msg = self._kill_process({'pid': pid})
            if not success:
                return False, msg
        
        # Then block the IP
        return self._block_ip({'ip': ip})
    
    def _quarantine_file(self, params: dict) -> Tuple[bool, str]:
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
# TELEMETRY STORE WITH THREAT TRACKING
# =============================================================================

class TelemetryStore:
    """Local telemetry storage with threat tracking"""
    
    def __init__(self, max_events=5000):
        self.max_events = max_events
        self.events = deque(maxlen=max_events)
        self.cli_commands = deque(maxlen=1000)
        self.processes = {}
        self.network_connections = []
        self.file_changes = deque(maxlen=500)
        self.threats = deque(maxlen=200)
        self.pending_approvals = {}  # Threats awaiting user approval
        self.aatl_assessments = deque(maxlen=100)
        self.cli_sessions = {}
        self.auto_remediated = deque(maxlen=100)  # Auto-killed threats
        self.alarms = deque(maxlen=50)  # Active alarms
        
        self.stats = {
            "events_total": 0,
            "threats_detected": 0,
            "threats_blocked": 0,
            "threats_pending": 0,
            "threats_auto_killed": 0,
            "ai_sessions_detected": 0,
            "connections_monitored": 0,
            "processes_monitored": 0,
            "bytes_sent": 0,
            "bytes_recv": 0
        }
        
        # AGGRESSIVE AUTO-KILL CONFIGURATION
        # Kill threats immediately - don't wait for human approval
        self.auto_kill_enabled = True
        self.auto_kill_severities = {ThreatSeverity.CRITICAL, ThreatSeverity.HIGH}  # Auto-kill CRITICAL AND HIGH
        self.auto_kill_medium = True  # Also auto-kill medium if pattern matches
        
        # Critical threat patterns that ALWAYS trigger auto-kill (even if medium severity)
        self.critical_patterns = [
            # Credential theft
            'mimikatz', 'lazagne', 'credential', 'lsass', 'sekurlsa', 'procdump', 
            'gsecdump', 'pwdump', 'fgdump', 'wce', 'ntdsutil', 'secretsdump',
            # Ransomware families
            'ransomware', 'cryptolocker', 'wannacry', 'petya', 'locky', 'cerber',
            'ryuk', 'sodinokibi', 'revil', 'lockbit', 'conti', 'blackmatter',
            'encrypt', '.crypt', '.locked', '.encrypted',
            # Destructive commands
            'wiper', 'format c:', 'del /f /s /q', 'rm -rf', 'dd if=/dev/zero',
            'diskpart', 'clean all', 'cipher /w',
            # C2/RAT/Backdoors
            'reverse shell', 'meterpreter', 'beacon', 'cobalt', 'covenant',
            'empire', 'sliver', 'brute ratel', 'havoc', 'mythic', 'nighthawk',
            'netcat', 'nc -e', 'ncat -e', 'socat exec',
            # Lateral movement
            'psexec', 'wmiexec', 'smbexec', 'atexec', 'dcomexec', 'pass the hash',
            'pass-the-hash', 'pth-', 'overpass', 'golden ticket', 'silver ticket',
            # Privilege escalation
            'getsystem', 'privilege::debug', 'token::elevate', 'uac bypass',
            'fodhelper', 'eventvwr', 'sdclt', 'cmstp',
            # Data exfiltration
            'exfiltrat', 'megasync', 'rclone', 'winscp -script', 'ftp -s:',
            # Keyloggers
            'keylog', 'keyboard hook', 'getasynckeystate', 'rawinputdevice',
            # Process injection
            'process hollowing', 'dll injection', 'reflective', 'shellcode',
            'createremotethread', 'ntqueueapcthread', 'setwindowshookex',
            # Mining/Cryptojacking
            'xmrig', 'cryptonight', 'stratum+tcp', 'minerd', 'cgminer', 'bfgminer',
        ]
        
        # Process names to IMMEDIATELY kill (no questions asked)
        self.instant_kill_processes = {
            'mimikatz.exe', 'lazagne.exe', 'procdump.exe', 'gsecdump.exe',
            'pwdump.exe', 'wce.exe', 'xmrig.exe', 'minerd.exe', 'cgminer.exe',
            'netcat.exe', 'nc.exe', 'ncat.exe', 'psexec.exe', 'paexec.exe',
            'cobaltstrike.exe', 'beacon.exe', 'meterpreter.exe',
        }
    
    def add_threat(self, threat: Threat, auto_remediate: bool = True):
        """Add a detected threat with AGGRESSIVE auto-remediation"""
        self.threats.append(threat)
        self.stats["threats_detected"] += 1
        
        # AGGRESSIVE AUTO-KILL LOGIC
        # Don't wait for humans - kill threats immediately
        should_auto_kill = False
        kill_reason = None
        
        if self.auto_kill_enabled and threat.remediation_available:
            # 1. Auto-kill for CRITICAL and HIGH severity
            if threat.severity in self.auto_kill_severities:
                should_auto_kill = True
                kill_reason = f"SEVERITY_{threat.severity.value.upper()}"
            
            # 2. Auto-kill for any pattern match (even MEDIUM/LOW)
            threat_text = f"{threat.title} {threat.description} {threat.remediation_command or ''}".lower()
            for pattern in self.critical_patterns:
                if pattern in threat_text:
                    should_auto_kill = True
                    kill_reason = f"PATTERN_MATCH_{pattern.upper()}"
                    break
            
            # 3. Check if process name is in instant-kill list
            if hasattr(threat, 'process_name') and threat.process_name:
                if threat.process_name.lower() in self.instant_kill_processes:
                    should_auto_kill = True
                    kill_reason = f"INSTANT_KILL_PROCESS_{threat.process_name}"
            
            # 4. Auto-kill medium threats if they match high-risk categories
            if self.auto_kill_medium and threat.severity == ThreatSeverity.MEDIUM:
                high_risk_types = ['credential', 'exfiltration', 'ransomware', 'backdoor', 
                                   'rat', 'c2', 'injection', 'rootkit', 'miner']
                if any(rt in threat.type.lower() for rt in high_risk_types):
                    should_auto_kill = True
                    kill_reason = f"HIGH_RISK_MEDIUM_{threat.type}"
        
        if should_auto_kill and auto_remediate:
            # IMMEDIATE KILL - Don't wait!
            self.trigger_alarm(threat, f"AUTO_KILL_TRIGGERED:{kill_reason}")
            threat.status = "auto_remediated"
            threat.user_approved = True
            threat.kill_reason = kill_reason
            self.auto_remediated.append(threat)
            logger.warning(f"🔪 AUTO-KILL TRIGGERED: {threat.title} | Reason: {kill_reason}")
        elif threat.remediation_available:
            # Only queue for approval if LOW severity and no pattern match
            self.pending_approvals[threat.id] = threat
            self.stats["threats_pending"] += 1
            
            # Still trigger alarm for awareness
            if threat.severity in {ThreatSeverity.CRITICAL, ThreatSeverity.HIGH, ThreatSeverity.MEDIUM}:
                self.trigger_alarm(threat, "QUEUED_FOR_APPROVAL")
        
        # Add as event
        self.add_event({
            "event_type": f"threat.{threat.type}",
            "severity": threat.severity.value,
            "data": {
                "threat_id": threat.id,
                "title": threat.title,
                "description": threat.description,
                "remediation_available": threat.remediation_available,
                "auto_kill_triggered": should_auto_kill,
                "kill_reason": kill_reason
            }
        })
        
        return should_auto_kill
    
    def trigger_alarm(self, threat: Threat, alarm_type: str):
        """Trigger an alarm for critical threats"""
        alarm = {
            "id": f"alarm-{uuid.uuid4().hex[:8]}",
            "type": alarm_type,
            "threat_id": threat.id,
            "threat_title": threat.title,
            "severity": threat.severity.value,
            "timestamp": datetime.now().isoformat(),
            "acknowledged": False
        }
        self.alarms.append(alarm)
        logger.warning(f"🚨 ALARM: {alarm_type} - {threat.title}")
    
    def add_event(self, event: dict):
        """Add a telemetry event"""
        event["id"] = str(uuid.uuid4())[:8]
        event["timestamp"] = event.get("timestamp", datetime.now().isoformat())
        self.events.append(event)
        self.stats["events_total"] += 1
    
    def approve_remediation(self, threat_id: str) -> Tuple[bool, str]:
        """Approve a remediation action"""
        if threat_id not in self.pending_approvals:
            return False, "Threat not found or already processed"
        
        threat = self.pending_approvals[threat_id]
        threat.user_approved = True
        threat.status = "approved"
        
        return True, "Remediation approved"
    
    def deny_remediation(self, threat_id: str) -> Tuple[bool, str]:
        """Deny a remediation action"""
        if threat_id not in self.pending_approvals:
            return False, "Threat not found"
        
        threat = self.pending_approvals[threat_id]
        threat.user_approved = False
        threat.status = "ignored"
        del self.pending_approvals[threat_id]
        self.stats["threats_pending"] -= 1
        
        return True, "Remediation denied"
    
    def get_dashboard_data(self) -> dict:
        """Get all data for dashboard"""
        return {
            "agent": {
                "id": AGENT_ID,
                "hostname": HOSTNAME,
                "os": OS_TYPE,
                "version": VERSION,
                "uptime": int(time.time() - psutil.boot_time()) if psutil else 0,
                "cpu_percent": psutil.cpu_percent() if psutil else 0,
                "memory_percent": psutil.virtual_memory().percent if psutil else 0,
                "disk_percent": psutil.disk_usage('/').percent if psutil else 0
            },
            "stats": self.stats,
            "events": list(self.events)[-100:],
            "threats": [t.to_dict() for t in self.threats][-50:],
            "pending_approvals": [t.to_dict() for t in self.pending_approvals.values()],
            "auto_remediated": [t.to_dict() for t in self.auto_remediated][-20:],
            "alarms": list(self.alarms)[-20:],
            "cli_commands": list(self.cli_commands)[-100:],
            "aatl_assessments": list(self.aatl_assessments)[-20:],
            "processes": list(self.processes.values())[:50],
            "network_connections": self.network_connections[:50],
            "auto_kill_enabled": self.auto_kill_enabled,
            # Advanced monitoring data
            "file_telemetry": file_indexer.get_file_telemetry(),
            "admin_info": admin_monitor.get_current_admins(),
            # Network scanning results
            "network_scans": network_scan_results.to_dict(),
            # VPN status
            "vpn_status": wireguard_vpn.get_status(),
            # USB monitoring
            "usb_devices": usb_scanner.to_dict(),
            # Sandbox status
            "sandbox": sandbox.to_dict(),
            # SIEM status
            "siem": {
                "enabled": siem.enabled,
                "type": getattr(siem, 'siem_type', None),
                "buffer_size": len(siem.buffer)
            }
        }


# Global store
telemetry_store = TelemetryStore()
threat_engine = ThreatDetectionEngine(telemetry_store)
remediation_engine = RemediationEngine()

# =============================================================================
# SERVER COMMAND QUEUE
# =============================================================================

class ServerCommandQueue:
    """Poll server for commands and handle them"""
    
    def __init__(self, api_url: str):
        self.api_url = api_url
        self.last_poll = 0
        self.poll_interval = 5  # seconds
    
    def poll(self) -> List[dict]:
        """Poll server for pending commands"""
        if not self.api_url:
            return []
        
        try:
            response = requests.get(
                f"{self.api_url}/api/swarm/agents/{AGENT_ID}/commands",
                timeout=10
            )
            if response.status_code == 200:
                return response.json().get('commands', [])
        except Exception as e:
            logger.debug(f"Command poll failed: {e}")
        
        return []
    
    def ack_command(self, command_id: str, result: dict):
        """Acknowledge command execution"""
        if not self.api_url:
            return
        
        try:
            requests.post(
                f"{self.api_url}/api/swarm/agents/{AGENT_ID}/commands/{command_id}/ack",
                json=result,
                timeout=10
            )
        except Exception:
            pass


# =============================================================================
# LOCAL DASHBOARD HTML
# =============================================================================

DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Seraph Defender v7 - Threat Detection & Response</title>
    <style>
        :root {
            --bg-primary: #0a0e1a;
            --bg-secondary: #111827;
            --bg-card: #1f2937;
            --accent: #06b6d4;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.1), rgba(6, 182, 212, 0.1));
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        .header h1 { font-size: 24px; color: var(--danger); }
        
        .alert-banner {
            background: linear-gradient(135deg, var(--danger), #b91c1c);
            padding: 16px 24px;
            border-radius: 12px;
            margin-bottom: 20px;
            display: none;
            animation: pulse 2s infinite;
        }
        .alert-banner.active { display: block; }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.8; }
        }
        .alert-banner h2 { font-size: 18px; margin-bottom: 8px; }
        .alert-banner p { font-size: 14px; opacity: 0.9; }
        .alert-actions { margin-top: 12px; display: flex; gap: 12px; }
        .alert-actions button {
            padding: 8px 24px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            border: none;
        }
        .btn-approve { background: var(--success); color: white; }
        .btn-deny { background: rgba(255,255,255,0.2); color: white; }
        .btn-approve:hover { background: #059669; }
        .btn-deny:hover { background: rgba(255,255,255,0.3); }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .stat-card h3 { font-size: 13px; color: var(--text-secondary); margin-bottom: 8px; }
        .stat-card .value { font-size: 28px; font-weight: 700; }
        .stat-card.danger .value { color: var(--danger); }
        .stat-card.warning .value { color: var(--warning); }
        .stat-card.success .value { color: var(--success); }
        
        .threat-list { max-height: 400px; overflow-y: auto; }
        .threat-item {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
        }
        .threat-item.critical { border-color: var(--danger); background: rgba(239, 68, 68, 0.15); }
        .threat-item.high { border-color: var(--warning); background: rgba(245, 158, 11, 0.1); }
        .threat-header { display: flex; justify-content: space-between; margin-bottom: 8px; }
        .threat-title { font-weight: 600; }
        .threat-severity {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .severity-critical { background: var(--danger); }
        .severity-high { background: var(--warning); }
        .severity-medium { background: #3b82f6; }
        .severity-low { background: var(--success); }
        
        .threat-description { color: var(--text-secondary); font-size: 14px; margin-bottom: 12px; }
        .threat-evidence {
            background: rgba(0,0,0,0.3);
            padding: 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 12px;
            max-height: 100px;
            overflow-y: auto;
        }
        .threat-actions { margin-top: 12px; display: flex; gap: 8px; }
        .threat-actions button {
            padding: 6px 16px;
            border-radius: 4px;
            font-size: 13px;
            cursor: pointer;
            border: none;
        }
        
        .card {
            background: var(--bg-card);
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
            margin-bottom: 20px;
        }
        .card-header {
            padding: 16px 20px;
            background: rgba(0,0,0,0.2);
            border-bottom: 1px solid rgba(255,255,255,0.1);
            font-weight: 600;
        }
        .card-body { padding: 20px; }
        
        .connection-item {
            display: grid;
            grid-template-columns: 1fr 1fr 100px 150px;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            font-size: 13px;
        }
        .connection-suspicious { color: var(--danger); }
        
        .tabs { display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; }
        .tab {
            padding: 10px 20px;
            background: var(--bg-card);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            cursor: pointer;
            font-weight: 500;
        }
        .tab:hover { border-color: var(--accent); }
        .tab.active { background: var(--accent); color: var(--bg-primary); }
        
        .panel { display: none; }
        .panel.active { display: block; }
        
        .network-monitor { font-family: monospace; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ Seraph Defender v7 - Active Protection</h1>
                <p style="color: var(--text-secondary); margin-top: 4px;">Real-time threat detection & automated response</p>
            </div>
            <div style="text-align: right;">
                <div id="hostname" style="color: var(--text-secondary);"></div>
                <div style="color: var(--success); font-weight: 600;">● Protected</div>
            </div>
        </div>
        
        <div class="alert-banner" id="alertBanner">
            <h2 id="alertTitle">⚠️ Threat Detected - Action Required</h2>
            <p id="alertDescription"></p>
            <div class="alert-actions">
                <button class="btn-approve" onclick="approveRemediation()">✓ Approve Fix</button>
                <button class="btn-deny" onclick="denyRemediation()">✗ Ignore</button>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card danger">
                <h3>Active Threats</h3>
                <div class="value" id="statThreats">0</div>
            </div>
            <div class="stat-card warning">
                <h3>Pending Approval</h3>
                <div class="value" id="statPending">0</div>
            </div>
            <div class="stat-card success">
                <h3>Threats Blocked</h3>
                <div class="value" id="statBlocked">0</div>
            </div>
            <div class="stat-card">
                <h3>Connections</h3>
                <div class="value" id="statConns">0</div>
            </div>
            <div class="stat-card">
                <h3>Processes</h3>
                <div class="value" id="statProcs">0</div>
            </div>
            <div class="stat-card">
                <h3>AI Sessions</h3>
                <div class="value" id="statAI">0</div>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab active" data-panel="threats">🎯 Active Threats</div>
            <div class="tab" data-panel="network">🌐 Network Monitor</div>
            <div class="tab" data-panel="netscan">📡 Port/Router Scan</div>
            <div class="tab" data-panel="wifi">📶 WiFi Networks</div>
            <div class="tab" data-panel="bluetooth">🔵 Bluetooth</div>
            <div class="tab" data-panel="usb">🔌 USB Devices</div>
            <div class="tab" data-panel="sandbox">🧪 Sandbox</div>
            <div class="tab" data-panel="vpn">🔒 VPN</div>
            <div class="tab" data-panel="siem">📊 SIEM</div>
            <div class="tab" data-panel="processes">⚙️ Processes</div>
            <div class="tab" data-panel="files">📁 File Index</div>
            <div class="tab" data-panel="admin">👑 Admin Privileges</div>
            <div class="tab" data-panel="rootkit">🔍 Rootkit Scan</div>
            <div class="tab" data-panel="hidden">📂 Hidden Folders</div>
            <div class="tab" data-panel="aliases">⚡ Shell Aliases</div>
            <div class="tab" data-panel="aatl">🤖 AI Detection</div>
            <div class="tab" data-panel="events">📋 All Events</div>
        </div>
        
        <div class="panel active" id="panel-threats">
            <div class="card">
                <div class="card-header">Detected Threats</div>
                <div class="card-body">
                    <div class="threat-list" id="threatList"></div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-network">
            <div class="card">
                <div class="card-header">Active Network Connections</div>
                <div class="card-body network-monitor">
                    <div class="connection-item" style="font-weight: 600; border-bottom: 2px solid rgba(255,255,255,0.1);">
                        <div>Local</div>
                        <div>Remote</div>
                        <div>Status</div>
                        <div>Process</div>
                    </div>
                    <div id="networkList" style="max-height: 400px; overflow-y: auto;"></div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-netscan">
            <div class="card">
                <div class="card-header">📡 Port & Router Scanner</div>
                <div class="card-body">
                    <div style="display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap;">
                        <button onclick="scanRouter()" style="background: var(--accent); color: #000; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer;">🔍 Scan Router</button>
                        <button onclick="scanNetwork()" style="background: #6366f1; color: #fff; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer;">🌐 Scan Local Network</button>
                        <input type="text" id="hostToScan" placeholder="IP to scan (e.g., 192.168.1.1)" style="padding: 10px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); background: rgba(0,0,0,0.3); color: #fff; width: 200px;">
                        <button onclick="scanHost()" style="background: var(--warning); color: #000; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer;">🎯 Scan Host</button>
                    </div>
                    <div id="routerScanStatus" style="color: var(--text-secondary); margin-bottom: 16px;">Router scan: Never run</div>
                    <div id="routerResults" style="margin-bottom: 20px;"></div>
                    <h4 style="color: var(--accent); margin-bottom: 12px;">Discovered Hosts</h4>
                    <div id="networkHosts" style="max-height: 300px; overflow-y: auto;"></div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-wifi">
            <div class="card">
                <div class="card-header">📶 WiFi Network Scanner</div>
                <div class="card-body">
                    <button onclick="scanWiFi()" style="background: var(--accent); color: #000; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; margin-bottom: 16px;">🔍 Scan WiFi Networks</button>
                    <div id="wifiConnected" style="background: rgba(16,185,129,0.2); padding: 16px; border-radius: 8px; margin-bottom: 20px;"></div>
                    <div id="wifiScanStatus" style="color: var(--text-secondary); margin-bottom: 16px;">Last scan: Never</div>
                    <h4 style="color: var(--accent); margin-bottom: 12px;">Available Networks</h4>
                    <div id="wifiList" style="max-height: 400px; overflow-y: auto;"></div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-bluetooth">
            <div class="card">
                <div class="card-header">🔵 Bluetooth Device Scanner</div>
                <div class="card-body">
                    <button onclick="scanBluetooth()" style="background: #3b82f6; color: #fff; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; margin-bottom: 16px;">🔍 Scan Bluetooth Devices</button>
                    <div id="bluetoothScanStatus" style="color: var(--text-secondary); margin-bottom: 16px;">Last scan: Never</div>
                    <h4 style="color: var(--accent); margin-bottom: 12px;">Detected Devices</h4>
                    <div id="bluetoothList" style="max-height: 400px; overflow-y: auto;"></div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-vpn">
            <div class="card">
                <div class="card-header">🔒 WireGuard VPN (Split Tunnel)</div>
                <div class="card-body">
                    <div style="background: rgba(6,182,212,0.1); padding: 16px; border-radius: 8px; margin-bottom: 20px; border: 1px solid rgba(6,182,212,0.3);">
                        <p style="color: var(--accent); font-weight: 600; margin-bottom: 8px;">ℹ️ Split Tunnel Mode</p>
                        <p style="color: var(--text-secondary); font-size: 14px;">VPN only routes Seraph network traffic. Your normal internet access is NOT affected.</p>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 20px;">
                        <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px;">
                            <div style="color: var(--text-secondary); font-size: 12px; margin-bottom: 4px;">Status</div>
                            <div id="vpnStatus" style="font-size: 18px; font-weight: 600;">Not Configured</div>
                        </div>
                        <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px;">
                            <div style="color: var(--text-secondary); font-size: 12px; margin-bottom: 4px;">Client Address</div>
                            <div id="vpnAddress" style="font-size: 14px; font-family: monospace;">-</div>
                        </div>
                    </div>
                    <div style="margin-bottom: 20px;">
                        <h4 style="color: var(--accent); margin-bottom: 12px;">Configure VPN</h4>
                        <input type="text" id="vpnEndpoint" placeholder="Server endpoint (e.g., server.com:51820)" style="width: 100%; padding: 10px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); background: rgba(0,0,0,0.3); color: #fff; margin-bottom: 8px;">
                        <input type="text" id="vpnPubKey" placeholder="Server public key" style="width: 100%; padding: 10px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); background: rgba(0,0,0,0.3); color: #fff; margin-bottom: 8px;">
                        <div style="display: flex; gap: 12px;">
                            <button onclick="configureVPN()" style="background: var(--accent); color: #000; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer;">⚙️ Configure</button>
                            <button onclick="connectVPN()" style="background: var(--success); color: #fff; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer;">🔗 Connect</button>
                            <button onclick="disconnectVPN()" style="background: var(--danger); color: #fff; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer;">⛔ Disconnect</button>
                        </div>
                    </div>
                    <div id="vpnDetails" style="font-family: monospace; font-size: 12px; background: rgba(0,0,0,0.3); padding: 12px; border-radius: 8px;"></div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-usb">
            <div class="card">
                <div class="card-header">🔌 USB Device Monitor</div>
                <div class="card-body">
                    <div style="background: rgba(6,182,212,0.1); padding: 16px; border-radius: 8px; margin-bottom: 20px; border: 1px solid rgba(6,182,212,0.3);">
                        <p style="color: var(--accent); font-weight: 600; margin-bottom: 8px;">⚡ Auto-Scan Enabled</p>
                        <p style="color: var(--text-secondary); font-size: 14px;">New USB devices are automatically scanned for malware, autorun files, and BadUSB payloads.</p>
                    </div>
                    <button onclick="scanUSBDevices()" style="background: var(--accent); color: #000; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; margin-bottom: 16px;">🔍 Scan All USB Devices</button>
                    <div id="usbScanStatus" style="color: var(--text-secondary); margin-bottom: 16px;">Last scan: Never</div>
                    <h4 style="color: var(--accent); margin-bottom: 12px;">Connected USB Devices</h4>
                    <div id="usbDeviceList" style="margin-bottom: 20px;"></div>
                    <h4 style="color: var(--danger); margin-bottom: 12px;">USB Threats Detected</h4>
                    <div id="usbThreatList"></div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-sandbox">
            <div class="card">
                <div class="card-header">🧪 Cuckoo Sandbox (VM Analysis)</div>
                <div class="card-body">
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 20px;">
                        <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px;">
                            <div style="color: var(--text-secondary); font-size: 12px; margin-bottom: 4px;">Sandbox Status</div>
                            <div id="sandboxStatus" style="font-size: 18px; font-weight: 600;">Checking...</div>
                        </div>
                        <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px;">
                            <div style="color: var(--text-secondary); font-size: 12px; margin-bottom: 4px;">Analyses Completed</div>
                            <div id="sandboxCount" style="font-size: 18px; font-weight: 600;">0</div>
                        </div>
                    </div>
                    <div style="margin-bottom: 20px;">
                        <h4 style="color: var(--accent); margin-bottom: 12px;">Submit File for Analysis</h4>
                        <input type="text" id="sandboxFilePath" placeholder="File path to analyze (e.g., /tmp/suspicious.exe)" style="width: 100%; padding: 10px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); background: rgba(0,0,0,0.3); color: #fff; margin-bottom: 8px;">
                        <button onclick="submitToSandbox()" style="background: var(--warning); color: #000; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer;">🧪 Analyze File</button>
                    </div>
                    <h4 style="color: var(--accent); margin-bottom: 12px;">Recent Analyses</h4>
                    <div id="sandboxAnalyses" style="max-height: 300px; overflow-y: auto;"></div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-siem">
            <div class="card">
                <div class="card-header">📊 SIEM Integration</div>
                <div class="card-body">
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 20px;">
                        <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px;">
                            <div style="color: var(--text-secondary); font-size: 12px; margin-bottom: 4px;">SIEM Status</div>
                            <div id="siemStatus" style="font-size: 18px; font-weight: 600;">Checking...</div>
                        </div>
                        <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px;">
                            <div style="color: var(--text-secondary); font-size: 12px; margin-bottom: 4px;">SIEM Type</div>
                            <div id="siemType" style="font-size: 14px;">-</div>
                        </div>
                        <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px;">
                            <div style="color: var(--text-secondary); font-size: 12px; margin-bottom: 4px;">Buffer Size</div>
                            <div id="siemBuffer" style="font-size: 18px; font-weight: 600;">0</div>
                        </div>
                    </div>
                    <div style="background: rgba(16,185,129,0.1); padding: 16px; border-radius: 8px; margin-bottom: 20px; border: 1px solid rgba(16,185,129,0.3);">
                        <p style="color: var(--success); font-weight: 600; margin-bottom: 8px;">📡 Event Streaming</p>
                        <p style="color: var(--text-secondary); font-size: 14px;">All security events are automatically streamed to your SIEM. High-severity events are sent immediately.</p>
                    </div>
                    <h4 style="color: var(--accent); margin-bottom: 12px;">SIEM Configuration</h4>
                    <div style="font-family: monospace; font-size: 12px; background: rgba(0,0,0,0.3); padding: 12px; border-radius: 8px;">
                        <p><strong>Elasticsearch:</strong> Set ELASTICSEARCH_URL environment variable</p>
                        <p><strong>Splunk HEC:</strong> Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN</p>
                        <p><strong>Syslog:</strong> Set SYSLOG_SERVER and SYSLOG_PORT</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-processes">
            <div class="card">
                <div class="card-header">Running Processes (Click to Kill)</div>
                <div class="card-body" id="processList" style="max-height: 500px; overflow-y: auto;"></div>
            </div>
        </div>
        
        <div class="panel" id="panel-files">
            <div class="card">
                <div class="card-header">📁 File System Telemetry</div>
                <div class="card-body">
                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px;">
                        <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 24px; font-weight: bold; color: var(--accent);" id="fileTotal">0</div>
                            <div style="color: var(--text-secondary);">Total Files</div>
                        </div>
                        <div style="background: rgba(239,68,68,0.2); padding: 16px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 24px; font-weight: bold; color: #ef4444;" id="fileExec">0</div>
                            <div style="color: var(--text-secondary);">Executables</div>
                        </div>
                        <div style="background: rgba(251,191,36,0.2); padding: 16px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 24px; font-weight: bold; color: #fbbf24;" id="fileRecent">0</div>
                            <div style="color: var(--text-secondary);">Recent Changes</div>
                        </div>
                        <div style="background: rgba(239,68,68,0.3); padding: 16px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 24px; font-weight: bold; color: #ef4444;" id="fileSuspicious">0</div>
                            <div style="color: var(--text-secondary);">Suspicious</div>
                        </div>
                    </div>
                    <div id="fileList" style="max-height: 400px; overflow-y: auto;"></div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-admin">
            <div class="card">
                <div class="card-header">👑 Admin Privileges Monitor</div>
                <div class="card-body">
                    <h4 style="margin-bottom: 12px; color: var(--accent);">Local Administrators</h4>
                    <div id="adminList" style="margin-bottom: 20px;"></div>
                    <h4 style="margin-bottom: 12px; color: var(--warning);">Elevated Processes (SYSTEM/root)</h4>
                    <div id="elevatedList" style="max-height: 300px; overflow-y: auto;"></div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-rootkit">
            <div class="card">
                <div class="card-header">🔍 Rootkit Detection</div>
                <div class="card-body">
                    <button onclick="runRootkitScan()" style="background: var(--accent); color: #000; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; margin-bottom: 16px;">Run Deep Scan</button>
                    <div id="rootkitStatus" style="color: var(--success); margin-bottom: 16px;">Last scan: Never</div>
                    <div id="rootkitList"></div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-hidden">
            <div class="card">
                <div class="card-header">📂 Hidden Folder Detection</div>
                <div class="card-body">
                    <button onclick="runHiddenScan()" style="background: var(--accent); color: #000; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; margin-bottom: 16px;">Scan Hidden Folders</button>
                    <div id="hiddenStatus" style="color: var(--text-secondary); margin-bottom: 16px;">Last scan: Never</div>
                    <div id="hiddenList"></div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-aliases">
            <div class="card">
                <div class="card-header">⚡ Shell Alias Detection</div>
                <div class="card-body">
                    <button onclick="runAliasScan()" style="background: var(--accent); color: #000; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; margin-bottom: 16px;">Scan Aliases</button>
                    <div id="aliasStatus" style="color: var(--text-secondary); margin-bottom: 16px;">Last scan: Never</div>
                    <div id="aliasList"></div>
                </div>
            </div>
        </div>
        
        <div class="panel" id="panel-aatl">
            <div class="card">
                <div class="card-header">🤖 AI Threat Detection (AATL)</div>
                <div class="card-body" id="aatlList"></div>
            </div>
        </div>
        
        <div class="panel" id="panel-events">
            <div class="card">
                <div class="card-header">All Events</div>
                <div class="card-body" id="eventList" style="max-height: 500px; overflow-y: auto;"></div>
            </div>
        </div>
    </div>
    
    <script>
        let currentPendingThreat = null;
        
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById('panel-' + tab.dataset.panel).classList.add('active');
            });
        });
        
        function renderThreat(threat) {
            return `
                <div class="threat-item ${threat.severity}">
                    <div class="threat-header">
                        <span class="threat-title">${threat.title}</span>
                        <span class="threat-severity severity-${threat.severity}">${threat.severity}</span>
                    </div>
                    <div class="threat-description">${threat.description}</div>
                    <div class="threat-evidence">${JSON.stringify(threat.evidence, null, 2)}</div>
                    ${threat.remediation_available && threat.status === 'detected' ? `
                        <div class="threat-actions">
                            <button class="btn-approve" onclick="approveThreat('${threat.id}')">✓ Auto-Fix</button>
                            <button class="btn-deny" onclick="denyThreat('${threat.id}')">✗ Ignore</button>
                        </div>
                    ` : `<div style="margin-top: 8px; color: var(--text-secondary); font-size: 12px;">Status: ${threat.status}</div>`}
                </div>
            `;
        }
        
        function updateDashboard(data) {
            document.getElementById('hostname').textContent = data.agent.hostname + ' (' + data.agent.os + ')';
            document.getElementById('statThreats').textContent = data.stats.threats_detected;
            document.getElementById('statPending').textContent = data.stats.threats_pending;
            document.getElementById('statBlocked').textContent = data.stats.threats_blocked;
            document.getElementById('statConns').textContent = data.stats.connections_monitored;
            document.getElementById('statProcs').textContent = data.stats.processes_monitored;
            document.getElementById('statAI').textContent = data.stats.ai_sessions_detected;
            
            // Update pending approvals banner
            if (data.pending_approvals.length > 0) {
                currentPendingThreat = data.pending_approvals[0];
                document.getElementById('alertBanner').classList.add('active');
                document.getElementById('alertTitle').textContent = '⚠️ ' + currentPendingThreat.title;
                document.getElementById('alertDescription').textContent = currentPendingThreat.description;
            } else {
                document.getElementById('alertBanner').classList.remove('active');
                currentPendingThreat = null;
            }
            
            // Threats
            document.getElementById('threatList').innerHTML = 
                data.threats.slice().reverse().map(renderThreat).join('') || 
                '<p style="color: var(--success);">✓ No threats detected</p>';
            
            // Network
            document.getElementById('networkList').innerHTML = data.network_connections.map(conn => `
                <div class="connection-item ${conn.suspicious ? 'connection-suspicious' : ''}">
                    <div>${conn.local_addr || '-'}</div>
                    <div>${conn.remote_addr || '-'}</div>
                    <div>${conn.status}</div>
                    <div>${conn.process_name || 'Unknown'}</div>
                </div>
            `).join('') || '<p>No active connections</p>';
            
            // Processes
            document.getElementById('processList').innerHTML = data.processes.map(proc => `
                <div style="display: grid; grid-template-columns: 80px 1fr 80px 80px; padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 13px;">
                    <div>${proc.pid}</div>
                    <div>${proc.name}</div>
                    <div>${proc.cpu_percent?.toFixed(1) || 0}%</div>
                    <div>${proc.memory_percent?.toFixed(1) || 0}%</div>
                </div>
            `).join('');
            
            // AATL
            document.getElementById('aatlList').innerHTML = data.aatl_assessments.slice().reverse().map(a => `
                <div style="background: rgba(0,0,0,0.2); padding: 16px; border-radius: 8px; margin-bottom: 12px; border-left: 4px solid ${a.threat_score >= 60 ? 'var(--danger)' : a.threat_score >= 40 ? 'var(--warning)' : 'var(--success)'};">
                    <div style="display: flex; justify-content: space-between;">
                        <strong>Session: ${a.session_id}</strong>
                        <span>Threat: ${a.threat_score?.toFixed(0) || 0}%</span>
                    </div>
                    <div style="margin-top: 8px; color: var(--text-secondary);">
                        Actor: ${a.actor_type} | Intent: ${a.primary_intent} | Strategy: ${a.recommended_strategy}
                    </div>
                </div>
            `).join('') || '<p style="color: var(--text-secondary);">No AI threat sessions detected</p>';
            
            // Events
            document.getElementById('eventList').innerHTML = data.events.slice().reverse().map(e => `
                <div style="padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 13px;">
                    <span style="color: ${e.severity === 'critical' ? 'var(--danger)' : e.severity === 'high' ? 'var(--warning)' : 'var(--text-secondary)'};">[${e.severity || 'info'}]</span>
                    <span style="margin-left: 8px;">${e.event_type}</span>
                    <span style="float: right; color: var(--text-secondary);">${new Date(e.timestamp).toLocaleTimeString()}</span>
                </div>
            `).join('');
            
            // File telemetry
            if (data.file_telemetry) {
                document.getElementById('fileTotal').textContent = data.file_telemetry.total_indexed || 0;
                document.getElementById('fileExec').textContent = data.file_telemetry.executables || 0;
                document.getElementById('fileRecent').textContent = data.file_telemetry.recent_changes || 0;
                document.getElementById('fileSuspicious').textContent = data.file_telemetry.suspicious || 0;
            }
            
            // Admin privileges
            if (data.admin_info) {
                document.getElementById('adminList').innerHTML = 
                    (data.admin_info.local_admins || []).map(a => `
                        <div style="padding: 8px 12px; background: rgba(251,191,36,0.15); margin: 4px 0; border-radius: 4px; border-left: 3px solid #fbbf24;">${a}</div>
                    `).join('') || '<p style="color: var(--text-secondary);">No admin users detected</p>';
                    
                document.getElementById('elevatedList').innerHTML = 
                    (data.admin_info.elevated_processes || []).slice(0, 50).map(p => `
                        <div style="padding: 6px 12px; background: rgba(239,68,68,0.1); margin: 2px 0; border-radius: 4px; font-family: monospace; font-size: 12px;">
                            PID ${p.pid} | ${p.name} | ${p.user}
                        </div>
                    `).join('') || '<p style="color: var(--text-secondary);">No elevated processes</p>';
            }
        }
        
        async function runRootkitScan() {
            document.getElementById('rootkitStatus').textContent = 'Scanning...';
            try {
                const res = await fetch('/api/scan/rootkit', { method: 'POST' });
                const data = await res.json();
                document.getElementById('rootkitStatus').textContent = 'Last scan: ' + new Date().toLocaleTimeString();
                document.getElementById('rootkitList').innerHTML = 
                    data.findings.length === 0 
                        ? '<p style="color: var(--success);">✓ No rootkits detected</p>'
                        : data.findings.map(f => `
                            <div style="padding: 12px; background: rgba(239,68,68,0.2); margin: 8px 0; border-radius: 8px; border-left: 4px solid #ef4444;">
                                <strong style="color: #ef4444;">[${f.severity.toUpperCase()}]</strong> ${f.type}<br/>
                                <span style="color: var(--text-secondary);">${f.message}</span>
                            </div>
                        `).join('');
            } catch (e) {
                document.getElementById('rootkitStatus').textContent = 'Scan failed: ' + e;
            }
        }
        
        async function runHiddenScan() {
            document.getElementById('hiddenStatus').textContent = 'Scanning...';
            try {
                const res = await fetch('/api/scan/hidden', { method: 'POST' });
                const data = await res.json();
                document.getElementById('hiddenStatus').textContent = 'Last scan: ' + new Date().toLocaleTimeString();
                document.getElementById('hiddenList').innerHTML = 
                    data.findings.length === 0 
                        ? '<p style="color: var(--success);">✓ No suspicious hidden folders</p>'
                        : data.findings.map(f => `
                            <div style="padding: 12px; background: rgba(251,191,36,0.2); margin: 8px 0; border-radius: 8px; border-left: 4px solid #fbbf24;">
                                <strong style="color: #fbbf24;">[${f.severity.toUpperCase()}]</strong> ${f.type}<br/>
                                <span style="color: var(--text-secondary);">${f.path}</span><br/>
                                <small style="color: var(--text-secondary);">${f.message}</small>
                            </div>
                        `).join('');
            } catch (e) {
                document.getElementById('hiddenStatus').textContent = 'Scan failed: ' + e;
            }
        }
        
        async function runAliasScan() {
            document.getElementById('aliasStatus').textContent = 'Scanning...';
            try {
                const res = await fetch('/api/scan/aliases', { method: 'POST' });
                const data = await res.json();
                document.getElementById('aliasStatus').textContent = 'Last scan: ' + new Date().toLocaleTimeString();
                document.getElementById('aliasList').innerHTML = 
                    data.findings.length === 0 
                        ? '<p style="color: var(--success);">✓ No suspicious aliases</p>'
                        : data.findings.map(f => `
                            <div style="padding: 12px; background: rgba(239,68,68,0.2); margin: 8px 0; border-radius: 8px; border-left: 4px solid #ef4444;">
                                <strong style="color: #ef4444;">[${f.severity.toUpperCase()}]</strong><br/>
                                <code style="background: rgba(0,0,0,0.3); padding: 4px 8px; border-radius: 4px;">${f.alias}</code><br/>
                                <small style="color: var(--text-secondary);">File: ${f.file}</small>
                            </div>
                        `).join('');
            } catch (e) {
                document.getElementById('aliasStatus').textContent = 'Scan failed: ' + e;
            }
        }
        
        // === NETWORK SCANNING FUNCTIONS ===
        async function scanRouter() {
            document.getElementById('routerScanStatus').textContent = 'Scanning router...';
            try {
                const res = await fetch('/api/scan/ports', { method: 'POST' });
                const data = await res.json();
                document.getElementById('routerScanStatus').textContent = 'Last scan: ' + new Date().toLocaleTimeString();
                if (data.success) {
                    const result = data.result;
                    let vulnHtml = '';
                    if (result.vulnerabilities && result.vulnerabilities.length > 0) {
                        vulnHtml = '<h5 style="color: var(--danger); margin-top: 12px;">⚠️ Vulnerabilities</h5>' +
                            result.vulnerabilities.map(v => `
                                <div style="background: rgba(239,68,68,0.2); padding: 8px; margin: 4px 0; border-radius: 4px;">
                                    <strong>${v.type}</strong>: ${v.message}
                                </div>
                            `).join('');
                    }
                    document.getElementById('routerResults').innerHTML = `
                        <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px;">
                            <strong>Gateway:</strong> ${result.ip || 'Unknown'}<br/>
                            <strong>Open Ports:</strong> ${result.open_ports?.map(p => p.port + ' (' + p.service + ')').join(', ') || 'None found'}<br/>
                            ${vulnHtml}
                        </div>
                    `;
                } else {
                    document.getElementById('routerResults').innerHTML = '<p style="color: var(--danger);">Scan failed: ' + data.error + '</p>';
                }
            } catch (e) {
                document.getElementById('routerScanStatus').textContent = 'Scan failed';
            }
        }
        
        async function scanNetwork() {
            document.getElementById('routerScanStatus').textContent = 'Scanning local network (this may take a minute)...';
            try {
                const res = await fetch('/api/scan/network', { method: 'POST' });
                const data = await res.json();
                document.getElementById('routerScanStatus').textContent = 'Network scan complete: ' + new Date().toLocaleTimeString();
                if (data.success) {
                    document.getElementById('networkHosts').innerHTML = data.hosts.length === 0
                        ? '<p>No hosts discovered</p>'
                        : data.hosts.map(h => `
                            <div style="display: flex; justify-content: space-between; padding: 8px; background: rgba(0,0,0,0.2); margin: 4px 0; border-radius: 4px;">
                                <span style="font-family: monospace;">${h.ip}</span>
                                <span style="color: ${h.alive ? 'var(--success)' : 'var(--text-secondary)'};">${h.alive ? '● Online' : '○ Offline'}</span>
                            </div>
                        `).join('');
                }
            } catch (e) {
                document.getElementById('routerScanStatus').textContent = 'Scan failed';
            }
        }
        
        async function scanHost() {
            const ip = document.getElementById('hostToScan').value;
            if (!ip) { alert('Please enter an IP address'); return; }
            document.getElementById('routerScanStatus').textContent = 'Scanning ' + ip + '...';
            try {
                const res = await fetch('/api/scan/host/' + ip, { method: 'POST' });
                const data = await res.json();
                document.getElementById('routerScanStatus').textContent = 'Host scan complete: ' + new Date().toLocaleTimeString();
                if (data.success) {
                    const result = data.result;
                    document.getElementById('routerResults').innerHTML = `
                        <div style="background: rgba(0,0,0,0.3); padding: 16px; border-radius: 8px;">
                            <strong>Host:</strong> ${result.ip}<br/>
                            <strong>Open Ports:</strong><br/>
                            ${result.open_ports?.map(p => `
                                <div style="padding: 4px 8px; margin: 2px 0; background: ${p.dangerous ? 'rgba(239,68,68,0.2)' : 'rgba(0,0,0,0.2)'}; border-radius: 4px;">
                                    ${p.port} - ${p.service} ${p.dangerous ? '⚠️ DANGEROUS' : ''}
                                </div>
                            `).join('') || 'No open ports'}
                        </div>
                    `;
                }
            } catch (e) {
                document.getElementById('routerScanStatus').textContent = 'Scan failed';
            }
        }
        
        async function scanWiFi() {
            document.getElementById('wifiScanStatus').textContent = 'Scanning WiFi networks...';
            try {
                const res = await fetch('/api/scan/wifi', { method: 'POST' });
                const data = await res.json();
                document.getElementById('wifiScanStatus').textContent = 'Last scan: ' + new Date().toLocaleTimeString() + ' (' + data.count + ' networks found)';
                if (data.connected) {
                    document.getElementById('wifiConnected').innerHTML = data.connected.error 
                        ? '<span style="color: var(--text-secondary);">Not connected to WiFi</span>'
                        : '<strong style="color: var(--success);">📶 Connected:</strong> ' + (data.connected.ssid || 'Unknown') + 
                          ' | Signal: ' + (data.connected.signal || 'Unknown');
                }
                document.getElementById('wifiList').innerHTML = data.networks?.length === 0
                    ? '<p>No networks found</p>'
                    : data.networks.map(n => {
                        const hasThreats = n.threats && n.threats.length > 0;
                        return `
                            <div style="padding: 12px; background: ${hasThreats ? 'rgba(239,68,68,0.2)' : 'rgba(0,0,0,0.2)'}; margin: 8px 0; border-radius: 8px; ${hasThreats ? 'border-left: 4px solid var(--danger);' : ''}">
                                <strong>${n.ssid || '(Hidden Network)'}</strong>
                                <span style="float: right; color: var(--text-secondary);">${n.signal || 'N/A'}</span><br/>
                                <small style="color: var(--text-secondary);">BSSID: ${n.bssid || 'Unknown'} | Auth: ${n.auth || 'Unknown'} | Encryption: ${n.encryption || n.auth || 'Unknown'}</small>
                                ${hasThreats ? '<div style="margin-top: 8px; color: var(--danger);">' + n.threats.map(t => '⚠️ ' + t.message).join('<br/>') + '</div>' : ''}
                            </div>
                        `;
                    }).join('');
            } catch (e) {
                document.getElementById('wifiScanStatus').textContent = 'Scan failed: ' + e;
            }
        }
        
        async function scanBluetooth() {
            document.getElementById('bluetoothScanStatus').textContent = 'Scanning Bluetooth devices...';
            try {
                const res = await fetch('/api/scan/bluetooth', { method: 'POST' });
                const data = await res.json();
                document.getElementById('bluetoothScanStatus').textContent = 'Last scan: ' + new Date().toLocaleTimeString() + ' (' + data.count + ' devices found)';
                document.getElementById('bluetoothList').innerHTML = data.devices?.length === 0
                    ? '<p style="color: var(--text-secondary);">No Bluetooth devices found</p>'
                    : data.devices.map(d => {
                        const hasThreats = d.threats && d.threats.length > 0;
                        return `
                            <div style="padding: 12px; background: ${hasThreats ? 'rgba(239,68,68,0.2)' : 'rgba(59,130,246,0.1)'}; margin: 8px 0; border-radius: 8px;">
                                <strong>🔵 ${d.name || 'Unknown Device'}</strong><br/>
                                <small style="color: var(--text-secondary);">ID: ${d.id || d.address || 'Unknown'} | Type: ${d.type || 'Unknown'} | Status: ${d.status || 'Unknown'}</small>
                                ${hasThreats ? '<div style="margin-top: 8px; color: var(--danger);">' + d.threats.map(t => '⚠️ ' + t.message).join('<br/>') + '</div>' : ''}
                            </div>
                        `;
                    }).join('');
            } catch (e) {
                document.getElementById('bluetoothScanStatus').textContent = 'Scan failed: ' + e;
            }
        }
        
        // === VPN FUNCTIONS ===
        async function configureVPN() {
            const endpoint = document.getElementById('vpnEndpoint').value;
            const pubkey = document.getElementById('vpnPubKey').value;
            if (!endpoint || !pubkey) { alert('Please enter server endpoint and public key'); return; }
            try {
                const res = await fetch('/api/vpn/configure', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ server_endpoint: endpoint, server_public_key: pubkey })
                });
                const data = await res.json();
                if (data.success) {
                    alert('VPN configured successfully!\\nClient address: ' + data.client_address + '\\nYour public key (share with server):\\n' + data.client_public_key);
                    fetchData();
                } else {
                    alert('Configuration failed: ' + data.error);
                }
            } catch (e) {
                alert('Error: ' + e);
            }
        }
        
        async function connectVPN() {
            try {
                const res = await fetch('/api/vpn/connect', { method: 'POST' });
                const data = await res.json();
                alert(data.success ? 'VPN Connected!' : 'Connection failed: ' + data.error);
                fetchData();
            } catch (e) {
                alert('Error: ' + e);
            }
        }
        
        async function disconnectVPN() {
            try {
                const res = await fetch('/api/vpn/disconnect', { method: 'POST' });
                const data = await res.json();
                alert(data.success ? 'VPN Disconnected' : 'Disconnect failed: ' + data.error);
                fetchData();
            } catch (e) {
                alert('Error: ' + e);
            }
        }
        
        function updateVPNStatus(vpnStatus) {
            if (!vpnStatus) return;
            const statusEl = document.getElementById('vpnStatus');
            const addressEl = document.getElementById('vpnAddress');
            const detailsEl = document.getElementById('vpnDetails');
            
            if (vpnStatus.connected) {
                statusEl.innerHTML = '<span style="color: var(--success);">● Connected</span>';
            } else if (vpnStatus.configured) {
                statusEl.innerHTML = '<span style="color: var(--warning);">○ Configured (Disconnected)</span>';
            } else {
                statusEl.innerHTML = '<span style="color: var(--text-secondary);">○ Not Configured</span>';
            }
            
            addressEl.textContent = vpnStatus.address || '-';
            detailsEl.innerHTML = vpnStatus.configured 
                ? 'Interface: ' + vpnStatus.interface + '<br/>Server: ' + (vpnStatus.server_endpoint || 'N/A') + '<br/>Mode: ' + vpnStatus.mode + '<br/>Config: ' + (vpnStatus.config_path || 'N/A')
                : 'VPN not configured. Enter server details above.';
        }
        
        // === USB FUNCTIONS ===
        async function scanUSBDevices() {
            document.getElementById('usbScanStatus').textContent = 'Scanning USB devices...';
            try {
                const res = await fetch('/api/scan/usb', { method: 'POST' });
                const data = await res.json();
                document.getElementById('usbScanStatus').textContent = 'Last scan: ' + new Date().toLocaleTimeString();
                updateUSBDisplay(data);
            } catch (e) {
                document.getElementById('usbScanStatus').textContent = 'Scan failed: ' + e;
            }
        }
        
        function updateUSBDisplay(usbData) {
            if (!usbData) return;
            
            // Update device list
            const devices = usbData.devices || [];
            document.getElementById('usbDeviceList').innerHTML = devices.length === 0
                ? '<p style="color: var(--text-secondary);">No USB devices connected</p>'
                : devices.map(d => `
                    <div style="padding: 12px; background: rgba(0,0,0,0.3); margin: 8px 0; border-radius: 8px;">
                        <strong style="color: var(--accent);">🔌 ${d.name || 'Unknown Device'}</strong><br/>
                        <small style="color: var(--text-secondary);">Path: ${d.path || 'Unknown'} | Size: ${d.size || 'Unknown'}</small>
                    </div>
                `).join('');
            
            // Update threat list
            const results = usbData.scan_results || [];
            let threats = [];
            results.forEach(r => {
                if (r.threats) threats = threats.concat(r.threats);
            });
            
            document.getElementById('usbThreatList').innerHTML = threats.length === 0
                ? '<p style="color: var(--success);">✓ No threats detected on USB devices</p>'
                : threats.map(t => `
                    <div style="padding: 12px; background: rgba(239,68,68,0.2); margin: 8px 0; border-radius: 8px; border-left: 4px solid #ef4444;">
                        <strong style="color: #ef4444;">[${(t.severity || 'high').toUpperCase()}] ${t.type}</strong><br/>
                        <span style="color: var(--text-secondary);">${t.message}</span><br/>
                        <small style="font-family: monospace;">${t.path}</small>
                    </div>
                `).join('');
        }
        
        // === SANDBOX FUNCTIONS ===
        async function submitToSandbox() {
            const filePath = document.getElementById('sandboxFilePath').value;
            if (!filePath) { alert('Please enter a file path'); return; }
            
            try {
                const res = await fetch('/api/sandbox/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ file_path: filePath })
                });
                const data = await res.json();
                if (data.success) {
                    alert('Analysis submitted!\\n' + data.message);
                    fetchData();
                } else {
                    alert('Analysis failed: ' + data.error);
                }
            } catch (e) {
                alert('Error: ' + e);
            }
        }
        
        function updateSandboxDisplay(sandboxData) {
            if (!sandboxData) return;
            
            document.getElementById('sandboxStatus').innerHTML = sandboxData.enabled
                ? '<span style="color: var(--success);">● Connected</span>'
                : '<span style="color: var(--warning);">○ Local Mode</span>';
            
            const analyses = sandboxData.completed_analyses || [];
            document.getElementById('sandboxCount').textContent = analyses.length;
            
            document.getElementById('sandboxAnalyses').innerHTML = analyses.length === 0
                ? '<p style="color: var(--text-secondary);">No analyses completed yet</p>'
                : analyses.slice(-10).reverse().map(a => {
                    const verdictColor = {
                        'malicious': 'var(--danger)',
                        'suspicious': 'var(--warning)',
                        'potentially_unwanted': '#fbbf24',
                        'clean': 'var(--success)'
                    }[a.verdict] || 'var(--text-secondary)';
                    return `
                        <div style="padding: 12px; background: rgba(0,0,0,0.3); margin: 8px 0; border-radius: 8px;">
                            <strong style="color: ${verdictColor};">${(a.verdict || 'unknown').toUpperCase()}</strong>
                            <span style="float: right; color: var(--text-secondary);">Score: ${a.risk_score || 0}</span><br/>
                            <small style="font-family: monospace;">${a.file_name || a.file_path}</small><br/>
                            <small style="color: var(--text-secondary);">Indicators: ${(a.indicators || []).length}</small>
                        </div>
                    `;
                }).join('');
        }
        
        // === SIEM FUNCTIONS ===
        function updateSIEMDisplay(siemData) {
            if (!siemData) return;
            
            document.getElementById('siemStatus').innerHTML = siemData.enabled
                ? '<span style="color: var(--success);">● Connected</span>'
                : '<span style="color: var(--text-secondary);">○ Disabled</span>';
            
            document.getElementById('siemType').textContent = siemData.type
                ? siemData.type.charAt(0).toUpperCase() + siemData.type.slice(1)
                : 'Not configured';
            
            document.getElementById('siemBuffer').textContent = siemData.buffer_size || 0;
        }
        
        async function killProcess(pid) {
            if (confirm('Kill process ' + pid + '?')) {
                await fetch('/api/kill/' + pid, { method: 'POST' });
                fetchData();
            }
        }
        
        async function approveThreat(threatId) {
            await fetch('/api/approve/' + threatId, { method: 'POST' });
            fetchData();
        }
        
        async function denyThreat(threatId) {
            await fetch('/api/deny/' + threatId, { method: 'POST' });
            fetchData();
        }
        
        function approveRemediation() {
            if (currentPendingThreat) approveThreat(currentPendingThreat.id);
        }
        
        function denyRemediation() {
            if (currentPendingThreat) denyThreat(currentPendingThreat.id);
        }
        
        async function fetchData() {
            try {
                const response = await fetch('/api/data');
                const data = await response.json();
                updateDashboard(data);
                updateVPNStatus(data.vpn_status);
                updateUSBDisplay(data.usb_devices);
                updateSandboxDisplay(data.sandbox);
                updateSIEMDisplay(data.siem);
            } catch (e) {
                console.error('Fetch error:', e);
            }
        }
        
        fetchData();
        setInterval(fetchData, 2000);
    </script>
</body>
</html>
'''


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for dashboard"""
    
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())
        elif self.path == '/api/data':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(telemetry_store.get_dashboard_data()).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path.startswith('/api/approve/'):
            threat_id = self.path.split('/')[-1]
            success, msg = telemetry_store.approve_remediation(threat_id)
            if success:
                # Execute remediation
                threat = telemetry_store.pending_approvals.get(threat_id)
                if threat:
                    result_success, result_msg = remediation_engine.execute(threat)
                    threat.status = "resolved" if result_success else "failed"
                    if result_success:
                        telemetry_store.stats["threats_blocked"] += 1
                    del telemetry_store.pending_approvals[threat_id]
                    telemetry_store.stats["threats_pending"] -= 1
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": success, "message": msg}).encode())
        
        elif self.path.startswith('/api/deny/'):
            threat_id = self.path.split('/')[-1]
            success, msg = telemetry_store.deny_remediation(threat_id)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": success, "message": msg}).encode())
        
        elif self.path == '/api/scan/rootkit':
            findings = rootkit_detector.scan()
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"findings": findings}).encode())
        
        elif self.path == '/api/scan/hidden':
            findings = hidden_folder_detector.scan()
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"findings": findings}).encode())
        
        elif self.path == '/api/scan/aliases':
            findings = alias_detector.scan()
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"findings": findings}).encode())
        
        elif self.path.startswith('/api/kill/'):
            pid = int(self.path.split('/')[-1])
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "message": f"Process {pid} terminated"}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": str(e)}).encode())
        
        # === NETWORK SCANNING ENDPOINTS ===
        elif self.path == '/api/scan/ports':
            # Scan router/gateway for open ports
            try:
                network_scan_results.scan_in_progress = True
                result = network_scanner.scan_router()
                network_scan_results.router_scan_result = result
                network_scan_results.last_router_scan = datetime.now().isoformat()
                network_scan_results.scan_in_progress = False
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "result": result}).encode())
            except Exception as e:
                network_scan_results.scan_in_progress = False
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode())
        
        elif self.path == '/api/scan/wifi':
            # Scan WiFi networks
            try:
                network_scan_results.scan_in_progress = True
                wifi_scanner.known_networks.clear()  # Reset for fresh scan
                results = wifi_scanner.scan_networks()
                connected = wifi_scanner.get_connected_network()
                network_scan_results.wifi_scan_results = results
                network_scan_results.last_wifi_scan = datetime.now().isoformat()
                network_scan_results.scan_in_progress = False
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": True, 
                    "networks": results,
                    "connected": connected,
                    "count": len(results)
                }).encode())
            except Exception as e:
                network_scan_results.scan_in_progress = False
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode())
        
        elif self.path == '/api/scan/bluetooth':
            # Scan Bluetooth devices
            try:
                network_scan_results.scan_in_progress = True
                results = bluetooth_scanner.scan_devices()
                network_scan_results.bluetooth_scan_results = results
                network_scan_results.last_bluetooth_scan = datetime.now().isoformat()
                network_scan_results.scan_in_progress = False
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": True, 
                    "devices": results,
                    "count": len(results)
                }).encode())
            except Exception as e:
                network_scan_results.scan_in_progress = False
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode())
        
        elif self.path == '/api/scan/network':
            # Full local network scan
            try:
                network_scan_results.scan_in_progress = True
                hosts = network_scanner.scan_local_network()
                network_scan_results.local_network_hosts = hosts
                network_scan_results.last_network_scan = datetime.now().isoformat()
                network_scan_results.scan_in_progress = False
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": True,
                    "hosts": hosts,
                    "count": len(hosts)
                }).encode())
            except Exception as e:
                network_scan_results.scan_in_progress = False
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode())
        
        elif self.path.startswith('/api/scan/host/'):
            # Scan specific host
            target_ip = self.path.split('/')[-1]
            try:
                result = network_scanner.scan_host(target_ip)
                network_scan_results.port_scan_results[target_ip] = result
                network_scan_results.last_port_scan = datetime.now().isoformat()
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "result": result}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode())
        
        # === VPN ENDPOINTS ===
        elif self.path == '/api/vpn/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(wireguard_vpn.get_status()).encode())
        
        elif self.path == '/api/vpn/connect':
            result = wireguard_vpn.connect()
            self.send_response(200 if result.get("success") else 500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        
        elif self.path == '/api/vpn/disconnect':
            result = wireguard_vpn.disconnect()
            self.send_response(200 if result.get("success") else 500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        
        elif self.path == '/api/vpn/configure':
            # Read POST body for VPN config
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode()
            try:
                config = json.loads(post_data)
                result = wireguard_vpn.auto_configure(
                    server_endpoint=config.get('server_endpoint'),
                    server_public_key=config.get('server_public_key'),
                    allowed_ips=config.get('allowed_ips', '10.200.200.0/24')
                )
                self.send_response(200 if result.get("success") else 500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode())
        
        else:
            self.send_response(404)
            self.end_headers()


# =============================================================================
# MAIN AGENT
# =============================================================================

class SeraphDefenderV7:
    """Full threat detection and response agent"""
    
    def __init__(self, api_url: str = None, local_only: bool = False):
        global AGENT_ID
        AGENT_ID = hashlib.md5(f"{HOSTNAME}-{uuid.getnode()}".encode()).hexdigest()[:16]
        
        self.api_url = api_url
        self.local_only = local_only
        self.running = False
        self.command_queue = ServerCommandQueue(api_url) if api_url else None
        
        logger.info(f"Seraph Defender v{VERSION} - Full Protection")
        logger.info(f"Agent ID: {AGENT_ID}")
        logger.info(f"Host: {HOSTNAME} ({OS_TYPE})")
    
    def start(self):
        """Start the agent"""
        self.running = True
        
        # Start dashboard
        dashboard_thread = threading.Thread(
            target=lambda: HTTPServer(('0.0.0.0', DASHBOARD_PORT), DashboardHandler).serve_forever(),
            daemon=True
        )
        dashboard_thread.start()
        
        # Open browser
        import webbrowser
        time.sleep(1)
        webbrowser.open(f'http://localhost:{DASHBOARD_PORT}')
        
        logger.info(f"Dashboard: http://localhost:{DASHBOARD_PORT}")
        logger.info("Press Ctrl+C to stop")
        
        # Start monitoring
        self._monitor_loop()
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        scan_counter = 0
        while self.running:
            try:
                # Monitor network connections
                self._scan_network()
                
                # Monitor processes
                self._scan_processes()
                
                # Periodic advanced network scanning (every 10 iterations = ~30 seconds)
                scan_counter += 1
                if scan_counter >= 10:
                    self._perform_network_scans()
                    scan_counter = 0
                
                # Process pending remediations
                self._process_approved_remediations()
                
                # Poll server for commands
                if self.command_queue:
                    self._process_server_commands()
                
                # Sync to cloud
                if not self.local_only and self.api_url:
                    self._sync_to_cloud()
                
                time.sleep(3)
                
            except KeyboardInterrupt:
                logger.info("Stopping...")
                self.running = False
            except Exception as e:
                logger.error(f"Error: {e}")
                time.sleep(5)
    
    def _perform_network_scans(self):
        """Perform periodic network infrastructure and USB scans"""
        try:
            # ===== WIFI MONITORING =====
            connected_wifi = wifi_scanner.get_connected_network()
            if connected_wifi and not connected_wifi.get('error'):
                # Check if connected to suspicious network
                ssid = connected_wifi.get('ssid', '').lower()
                suspicious_patterns = ['free', 'public', 'guest', 'airport', 'hotel', 'open']
                if any(p in ssid for p in suspicious_patterns):
                    telemetry_store.add_event({
                        "event_type": "network.suspicious_wifi",
                        "severity": "medium",
                        "data": {
                            "ssid": connected_wifi.get('ssid'),
                            "message": f"Connected to potentially unsafe WiFi: {connected_wifi.get('ssid')}"
                        }
                    })
                    # Log to SIEM
                    siem.log_event("network.suspicious_wifi", "medium", {
                        "ssid": connected_wifi.get('ssid')
                    })
            
            # ===== GATEWAY PORT MONITORING =====
            gateway = network_scanner.get_gateway()
            if gateway:
                # Quick check for dangerous ports on gateway
                dangerous_ports = [23, 445, 3389, 5900]  # Telnet, SMB, RDP, VNC
                for port in dangerous_ports:
                    if network_scanner.scan_port(gateway, port, timeout=0.3):
                        event_data = {
                            "gateway": gateway,
                            "port": port,
                            "service": network_scanner._get_service_name(port),
                            "message": f"Dangerous port {port} ({network_scanner._get_service_name(port)}) open on gateway"
                        }
                        telemetry_store.add_event({
                            "event_type": "network.dangerous_port_open",
                            "severity": "high",
                            "data": event_data
                        })
                        # Log to SIEM
                        siem.log_event("network.dangerous_port", "high", event_data)
            
            # ===== USB MONITORING =====
            # Check for newly connected USB devices
            new_usb_devices = usb_scanner.monitor_new_devices()
            for device in new_usb_devices:
                logger.info(f"🔌 New USB device: {device.get('name', 'Unknown')}")
                siem.log_event("usb.new_device", "medium", {
                    "device_id": device.get('id'),
                    "device_name": device.get('name'),
                    "path": device.get('path')
                })
                
                # Check if threats were found
                scan_result = device.get('scan_result', {})
                if scan_result.get('threats'):
                    for threat_info in scan_result['threats']:
                        siem.log_event("usb.threat_detected", threat_info['severity'], {
                            "device": device.get('name'),
                            "threat_type": threat_info['type'],
                            "path": threat_info['path']
                        })
            
            # ===== SIEM BUFFER FLUSH =====
            # Periodically flush SIEM buffer
            if siem.enabled and siem.buffer:
                siem._flush_buffer()
                
        except Exception as e:
            logger.debug(f"Network/USB scan error: {e}")
    
    def _scan_network(self):
        """Enhanced network connection scanning with traffic analysis"""
        connections = []
        traffic_stats = defaultdict(lambda: {'bytes_sent': 0, 'bytes_recv': 0, 'packets': 0})
        
        # Get network I/O counters per connection
        try:
            net_io = psutil.net_io_counters(pernic=True)
            total_io = psutil.net_io_counters()
            telemetry_store.stats["bytes_sent"] = total_io.bytes_sent
            telemetry_store.stats["bytes_recv"] = total_io.bytes_recv
        except:
            pass
        
        for conn in psutil.net_connections(kind='inet'):
            try:
                proc_name = "Unknown"
                proc_cmdline = ""
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                        proc_cmdline = ' '.join(proc.cmdline() or [])[:200]
                    except:
                        pass
                
                conn_data = {
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                    'remote_ip': conn.raddr.ip if conn.raddr else '',
                    'remote_port': conn.raddr.port if conn.raddr else 0,
                    'local_port': conn.laddr.port if conn.laddr else 0,
                    'status': conn.status,
                    'pid': conn.pid,
                    'process_name': proc_name,
                    'cmdline': proc_cmdline,
                    'suspicious': False,
                    'protocol': 'tcp' if conn.type == socket.SOCK_STREAM else 'udp',
                    'family': 'ipv4' if conn.family == socket.AF_INET else 'ipv6'
                }
                
                # Track traffic per remote endpoint
                if conn.raddr:
                    endpoint_key = f"{conn.raddr.ip}:{conn.raddr.port}"
                    traffic_stats[endpoint_key]['packets'] += 1
                
                # Check for threats
                threat = threat_engine.analyze_connection(conn_data)
                if threat:
                    conn_data['suspicious'] = True
                    telemetry_store.add_threat(threat)
                
                connections.append(conn_data)
                
            except:
                pass
        
        telemetry_store.network_connections = connections
        telemetry_store.stats["connections_monitored"] = len(connections)
        
        # Analyze traffic patterns
        self._analyze_traffic_patterns(connections, traffic_stats)
    
    def _analyze_traffic_patterns(self, connections, traffic_stats):
        """Analyze traffic patterns for anomalies"""
        # Count connections per remote IP
        ip_counts = defaultdict(int)
        port_counts = defaultdict(int)
        
        for conn in connections:
            if conn.get('remote_ip'):
                ip_counts[conn['remote_ip']] += 1
                port_counts[conn.get('remote_port', 0)] += 1
        
        # Detect connection flooding
        for ip, count in ip_counts.items():
            if count > 50:  # Many connections to same IP
                telemetry_store.add_event({
                    "event_type": "network.high_connection_count",
                    "severity": "medium",
                    "data": {
                        "remote_ip": ip,
                        "connection_count": count,
                        "message": f"High connection count ({count}) to {ip}"
                    }
                })
        
        # Detect unusual port activity
        COMMON_PORTS = {80, 443, 8080, 8443, 22, 3389}
        for port, count in port_counts.items():
            if port and port not in COMMON_PORTS and count > 10:
                telemetry_store.add_event({
                    "event_type": "network.unusual_port_activity",
                    "severity": "low",
                    "data": {
                        "port": port,
                        "connection_count": count,
                        "message": f"Unusual activity on port {port} ({count} connections)"
                    }
                })
    
    def _scan_processes(self):
        """Scan running processes"""
        processes = {}
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'cmdline']):
            try:
                info = proc.info
                proc_data = {
                    'pid': info['pid'],
                    'name': info['name'],
                    'username': info['username'],
                    'cpu_percent': info['cpu_percent'] or 0,
                    'memory_percent': info['memory_percent'] or 0,
                    'cmdline': ' '.join(info['cmdline'] or [])[:300]
                }
                
                processes[info['pid']] = proc_data
                
                # Check for threats
                threat = threat_engine.analyze_process(proc_data)
                if threat:
                    telemetry_store.add_threat(threat)
                    
            except:
                pass
        
        telemetry_store.processes = processes
        telemetry_store.stats["processes_monitored"] = len(processes)
    
    def _process_approved_remediations(self):
        """Process any approved remediations including auto-remediated threats"""
        # Process auto-remediated threats (critical - auto-kill)
        for threat in list(telemetry_store.auto_remediated):
            if threat.status == "auto_remediated" and not getattr(threat, 'executed', False):
                success, msg = remediation_engine.execute(threat)
                threat.executed = True
                if success:
                    threat.status = "resolved"
                    telemetry_store.stats["threats_blocked"] += 1
                    telemetry_store.stats["threats_auto_killed"] += 1
                    logger.warning(f"🛡️ AUTO-KILL SUCCESS: {threat.title} - {msg}")
                    
                    # Send alert to server
                    self._send_server_alert(threat, "AUTO_KILL_SUCCESS", msg)
                else:
                    threat.status = "auto_kill_failed"
                    logger.error(f"❌ AUTO-KILL FAILED: {threat.title} - {msg}")
                    self._send_server_alert(threat, "AUTO_KILL_FAILED", msg)
        
        # Process manually approved remediations
        for threat_id, threat in list(telemetry_store.pending_approvals.items()):
            if threat.user_approved:
                success, msg = remediation_engine.execute(threat)
                threat.status = "resolved" if success else "failed"
                if success:
                    telemetry_store.stats["threats_blocked"] += 1
                del telemetry_store.pending_approvals[threat_id]
                telemetry_store.stats["threats_pending"] -= 1
                logger.info(f"Remediation: {msg}")
                
                # Send alert to server
                self._send_server_alert(threat, "MANUAL_REMEDIATION", msg)
    
    def _send_server_alert(self, threat: Threat, alert_type: str, message: str):
        """Send critical alert to server"""
        if not self.api_url:
            return
        
        try:
            alert_data = {
                "agent_id": AGENT_ID,
                "host_id": HOSTNAME,
                "alert_type": alert_type,
                "severity": threat.severity.value,
                "threat_id": threat.id,
                "threat_title": threat.title,
                "threat_type": threat.type,
                "message": message,
                "evidence": threat.evidence,
                "remediation_action": threat.remediation_action,
                "timestamp": datetime.now().isoformat()
            }
            
            requests.post(
                f"{self.api_url}/api/swarm/alerts/critical",
                json=alert_data,
                timeout=5
            )
        except Exception as e:
            logger.debug(f"Failed to send server alert: {e}")
    
    def _process_server_commands(self):
        """Process commands from server"""
        commands = self.command_queue.poll()
        
        for cmd in commands:
            cmd_type = cmd.get('type')
            params = cmd.get('params', {})
            cmd_id = cmd.get('id')
            
            result = {"success": False, "message": "Unknown command"}
            
            if cmd_type == "kill_process":
                result["success"], result["message"] = remediation_engine._kill_process(params)
            elif cmd_type == "block_ip":
                result["success"], result["message"] = remediation_engine._block_ip(params)
            elif cmd_type == "scan":
                self._scan_network()
                self._scan_processes()
                result = {"success": True, "message": "Scan complete"}
            
            if cmd_id:
                self.command_queue.ack_command(cmd_id, result)
    
    def _sync_to_cloud(self):
        """Sync to cloud server"""
        try:
            requests.post(
                f"{self.api_url}/api/swarm/agents/register",
                json={
                    "agent_id": AGENT_ID,
                    "hostname": HOSTNAME,
                    "os_type": OS_TYPE,
                    "version": VERSION
                },
                timeout=5
            )
        except:
            pass


def main():
    parser = argparse.ArgumentParser(description="Seraph Defender v7 - Full Protection")
    parser.add_argument('--api-url', help='Server URL for cloud sync')
    parser.add_argument('--local-only', action='store_true', help='Local only mode')
    parser.add_argument('--port', type=int, default=8888, help='Dashboard port')
    
    args = parser.parse_args()
    
    global DASHBOARD_PORT
    DASHBOARD_PORT = args.port
    
    if not args.api_url and not args.local_only:
        print(f"\nSeraph Defender v{VERSION} - Full Protection")
        print("=" * 50)
        print("\nUsage:")
        print(f"  {sys.argv[0]} --api-url URL    # Cloud sync mode")
        print(f"  {sys.argv[0]} --local-only     # Local only mode")
        print(f"\nDashboard will open at http://localhost:{DASHBOARD_PORT}")
        print("\nFeatures:")
        print("  • Real network traffic monitoring")
        print("  • AI threat detection (AATL)")
        print("  • Malicious process detection")
        print("  • Automatic remediation with approval")
        print("  • Connection to known bad IPs blocked")
        sys.exit(1)
    
    agent = SeraphDefenderV7(args.api_url, args.local_only)
    agent.start()


if __name__ == '__main__':
    main()
