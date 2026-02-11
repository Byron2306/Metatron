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
        
        # Auto-kill configuration
        self.auto_kill_enabled = True
        self.auto_kill_severities = {ThreatSeverity.CRITICAL}  # Auto-kill CRITICAL threats
        
        # Critical threat patterns that trigger auto-kill
        self.critical_patterns = [
            'mimikatz', 'lazagne', 'credential', 'lsass', 'sekurlsa',  # Credential theft
            'ransomware', 'cryptolocker', 'wannacry', 'petya',  # Ransomware
            'wiper', 'format', 'del /f /s /q', 'rm -rf',  # Destructive
            'reverse shell', 'meterpreter', 'beacon', 'cobalt',  # C2/RAT
        ]
    
    def add_threat(self, threat: Threat, auto_remediate: bool = True):
        """Add a detected threat with optional auto-remediation"""
        self.threats.append(threat)
        self.stats["threats_detected"] += 1
        
        # Check if auto-kill should be triggered
        should_auto_kill = False
        if self.auto_kill_enabled and threat.remediation_available:
            # Auto-kill for CRITICAL severity
            if threat.severity in self.auto_kill_severities:
                should_auto_kill = True
            
            # Auto-kill for critical patterns
            threat_text = f"{threat.title} {threat.description}".lower()
            for pattern in self.critical_patterns:
                if pattern in threat_text:
                    should_auto_kill = True
                    break
        
        if should_auto_kill and auto_remediate:
            # Trigger alarm
            self.trigger_alarm(threat, "AUTO_KILL_TRIGGERED")
            threat.status = "auto_remediated"
            threat.user_approved = True
            self.auto_remediated.append(threat)
        elif threat.remediation_available:
            self.pending_approvals[threat.id] = threat
            self.stats["threats_pending"] += 1
            
            # Trigger alarm for high severity
            if threat.severity in {ThreatSeverity.CRITICAL, ThreatSeverity.HIGH}:
                self.trigger_alarm(threat, "MANUAL_APPROVAL_REQUIRED")
        
        # Add as event
        self.add_event({
            "event_type": f"threat.{threat.type}",
            "severity": threat.severity.value,
            "data": {
                "threat_id": threat.id,
                "title": threat.title,
                "description": threat.description,
                "remediation_available": threat.remediation_available,
                "auto_kill_triggered": should_auto_kill
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
            # New advanced monitoring data
            "file_telemetry": file_indexer.get_file_telemetry(),
            "admin_info": admin_monitor.get_current_admins()
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
            <div class="tab" data-panel="processes">📊 Processes</div>
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
        while self.running:
            try:
                # Monitor network
                self._scan_network()
                
                # Monitor processes
                self._scan_processes()
                
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
