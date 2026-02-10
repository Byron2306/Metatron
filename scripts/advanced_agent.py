#!/usr/bin/env python3
"""
Anti-AI Defense System - Advanced Security Agent v4.0
======================================================
Complete endpoint protection with advanced monitoring.

NEW IN v4.0:
- Real-time Task Manager with process monitoring
- User privilege and alias monitoring
- Browser extension analysis (Chrome, Firefox, Edge, Brave)
- Deep folder indexing and hidden file scraping
- Advanced process behavioral analysis
- Credential theft detection
- USB device monitoring
- Scheduled task/cron monitoring

USAGE:
    python advanced_agent.py                    # Start all monitors
    python advanced_agent.py --process-only    # Process monitoring only
    python advanced_agent.py --browser-scan    # Browser extension scan
    python advanced_agent.py --folder-scan     # Deep folder scan
    python advanced_agent.py --dashboard       # Launch local dashboard

Supports: Windows, macOS, Linux
"""

import os
import sys
import json
import time
import hashlib
import platform
import subprocess
import threading
import sqlite3
import struct
import re
import base64
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Set
from enum import Enum
import shutil

# =============================================================================
# CONFIGURATION
# =============================================================================

VERSION = "4.0.0"
INSTALL_DIR = Path.home() / ".anti-ai-defense"
DATA_DIR = INSTALL_DIR / "data"
LOGS_DIR = INSTALL_DIR / "logs"
REPORTS_DIR = INSTALL_DIR / "reports"
QUARANTINE_DIR = INSTALL_DIR / "quarantine"

for d in [INSTALL_DIR, DATA_DIR, LOGS_DIR, REPORTS_DIR, QUARANTINE_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Load config if exists
CONFIG_PATH = INSTALL_DIR / "config.json"
CONFIG = {}
if CONFIG_PATH.exists():
    with open(CONFIG_PATH) as f:
        CONFIG = json.load(f)

# =============================================================================
# IMPORTS (with fallbacks)
# =============================================================================

def safe_import(module_name):
    try:
        return __import__(module_name)
    except ImportError:
        return None

psutil = safe_import('psutil')
requests = safe_import('requests')

if not psutil:
    print("ERROR: psutil is required. Install with: pip install psutil")
    sys.exit(1)

# =============================================================================
# ENUMS & DATA CLASSES
# =============================================================================

class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ProcessRisk(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    PUP = "pup"
    CLEAN = "clean"
    UNKNOWN = "unknown"

@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe: str
    cmdline: str
    username: str
    cpu_percent: float
    memory_mb: float
    create_time: str
    parent_pid: int
    status: str
    num_threads: int
    open_files: int
    connections: int
    risk: ProcessRisk = ProcessRisk.UNKNOWN
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)

@dataclass
class UserPrivilege:
    username: str
    uid: int
    gid: int
    groups: List[str]
    is_admin: bool
    home_dir: str
    shell: str
    last_login: Optional[str] = None
    sudo_access: bool = False
    aliases: Dict[str, str] = field(default_factory=dict)

@dataclass
class BrowserExtension:
    browser: str
    name: str
    id: str
    version: str
    description: str
    permissions: List[str]
    enabled: bool
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)
    manifest_path: str = ""

@dataclass
class FileIndex:
    path: str
    name: str
    size: int
    modified: str
    created: str
    is_hidden: bool
    is_system: bool
    extension: str
    hash_md5: Optional[str] = None
    risk_score: int = 0
    flags: List[str] = field(default_factory=list)

# =============================================================================
# PROCESS MONITOR (Task Manager)
# =============================================================================

class ProcessMonitor:
    """
    Real-time Task Manager with threat detection
    Monitors all running processes and identifies suspicious behavior
    """
    
    SUSPICIOUS_PROCESS_NAMES = {
        # Known malware process names
        "mimikatz", "pwdump", "lsass_dump", "procdump", "gsecdump",
        "wce", "fgdump", "secretsdump", "lazagne", "crackmapexec",
        "bloodhound", "sharphound", "rubeus", "kekeo", "covenant",
        # Crypto miners
        "xmrig", "minerd", "cgminer", "bfgminer", "cpuminer", "nicehash",
        "ethminer", "phoenixminer", "nbminer", "t-rex", "gminer",
        # RATs and backdoors
        "netcat", "nc.exe", "ncat", "socat", "chisel", "plink",
        "ngrok", "serveo", "localtunnel", "reverse_shell",
        # Offensive tools
        "metasploit", "msfconsole", "msfvenom", "empire", "cobalt",
        "havoc", "sliver", "brute", "hydra", "medusa", "ncrack",
        # System abuse
        "psexec", "winexe", "wmiexec", "dcomexec", "smbexec",
        "atexec", "certutil", "bitsadmin", "regsvr32", "mshta",
    }
    
    SUSPICIOUS_CMDLINE_PATTERNS = [
        r"powershell.*-enc",
        r"powershell.*bypass",
        r"powershell.*hidden",
        r"powershell.*downloadstring",
        r"powershell.*iex",
        r"cmd.*\/c.*whoami",
        r"cmd.*\/c.*net\s+user",
        r"cmd.*\/c.*net\s+localgroup",
        r"reg\s+save.*sam",
        r"reg\s+save.*system",
        r"vssadmin.*shadows",
        r"wmic.*process.*call.*create",
        r"wmic.*shadowcopy.*delete",
        r"bcdedit.*safeboot",
        r"schtasks.*\/create",
        r"certutil.*-urlcache",
        r"bitsadmin.*\/transfer",
        r"curl.*\|.*sh",
        r"wget.*\|.*sh",
        r"base64.*decode",
        r"python.*-c.*import",
        r"nc\s+-[e|c]",
        r"ncat.*-e",
        r"bash.*-i.*>.*\/dev\/tcp",
    ]
    
    HIGH_RISK_PORTS = {
        4444, 5555, 6666, 7777, 8888,  # Common reverse shell ports
        1234, 9999, 12345, 31337,      # Common backdoor ports
        3389,                           # RDP (if unexpected)
        5900, 5901, 5902,              # VNC
        4443, 8443,                     # Alternative HTTPS (C2)
    }
    
    def __init__(self):
        self.processes: Dict[int, ProcessInfo] = {}
        self.process_history: deque = deque(maxlen=10000)
        self.alerts: deque = deque(maxlen=500)
        self.killed_processes: List[Dict] = []
        self.baseline_processes: Set[str] = set()
        self.monitoring = False
        self._lock = threading.Lock()
    
    def _get_process_info(self, proc: psutil.Process) -> Optional[ProcessInfo]:
        """Extract detailed process information"""
        try:
            with proc.oneshot():
                # Basic info
                pid = proc.pid
                name = proc.name()
                
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    exe = ""
                
                try:
                    cmdline = " ".join(proc.cmdline())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cmdline = ""
                
                try:
                    username = proc.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    username = "SYSTEM"
                
                try:
                    cpu = proc.cpu_percent(interval=0.1)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cpu = 0.0
                
                try:
                    mem = proc.memory_info().rss / (1024 * 1024)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    mem = 0.0
                
                try:
                    create_time = datetime.fromtimestamp(proc.create_time()).isoformat()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    create_time = ""
                
                try:
                    ppid = proc.ppid()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    ppid = 0
                
                try:
                    status = proc.status()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    status = "unknown"
                
                try:
                    num_threads = proc.num_threads()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    num_threads = 0
                
                try:
                    open_files = len(proc.open_files())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    open_files = 0
                
                try:
                    connections = len(proc.connections())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    connections = 0
                
                return ProcessInfo(
                    pid=pid,
                    name=name,
                    exe=exe,
                    cmdline=cmdline,
                    username=username,
                    cpu_percent=cpu,
                    memory_mb=round(mem, 2),
                    create_time=create_time,
                    parent_pid=ppid,
                    status=status,
                    num_threads=num_threads,
                    open_files=open_files,
                    connections=connections
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    def _analyze_process_risk(self, proc_info: ProcessInfo) -> ProcessInfo:
        """Analyze process for suspicious behavior"""
        risk_factors = []
        risk_score = 0
        
        name_lower = proc_info.name.lower()
        cmdline_lower = proc_info.cmdline.lower()
        
        # Check suspicious process names
        for sus_name in self.SUSPICIOUS_PROCESS_NAMES:
            if sus_name in name_lower:
                risk_factors.append(f"Suspicious process name: {sus_name}")
                risk_score += 30
                break
        
        # Check command line patterns
        for pattern in self.SUSPICIOUS_CMDLINE_PATTERNS:
            if re.search(pattern, cmdline_lower, re.IGNORECASE):
                risk_factors.append(f"Suspicious cmdline pattern: {pattern}")
                risk_score += 25
        
        # Check for encoded PowerShell
        if "powershell" in cmdline_lower and "-enc" in cmdline_lower:
            risk_factors.append("Encoded PowerShell command")
            risk_score += 35
        
        # Check for unusual parent processes
        try:
            parent = psutil.Process(proc_info.parent_pid)
            parent_name = parent.name().lower()
            
            # Word/Excel/PDF spawning cmd/powershell
            if parent_name in ["winword.exe", "excel.exe", "acrord32.exe", "outlook.exe"]:
                if "cmd" in name_lower or "powershell" in name_lower or "wscript" in name_lower:
                    risk_factors.append(f"Office/PDF app spawned shell: {parent_name} -> {proc_info.name}")
                    risk_score += 40
        except:
            pass
        
        # Check high CPU usage (potential miner)
        if proc_info.cpu_percent > 80:
            risk_factors.append(f"High CPU usage: {proc_info.cpu_percent}%")
            risk_score += 15
        
        # Check for processes with many network connections
        if proc_info.connections > 50:
            risk_factors.append(f"Many network connections: {proc_info.connections}")
            risk_score += 10
        
        # Check network connections for high-risk ports
        try:
            proc = psutil.Process(proc_info.pid)
            for conn in proc.connections():
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.raddr.port in self.HIGH_RISK_PORTS:
                        risk_factors.append(f"Connection to high-risk port: {conn.raddr.port}")
                        risk_score += 25
                    if conn.laddr.port in self.HIGH_RISK_PORTS:
                        risk_factors.append(f"Listening on high-risk port: {conn.laddr.port}")
                        risk_score += 20
        except:
            pass
        
        # Determine risk level
        if risk_score >= 60:
            proc_info.risk = ProcessRisk.MALICIOUS
        elif risk_score >= 40:
            proc_info.risk = ProcessRisk.SUSPICIOUS
        elif risk_score >= 20:
            proc_info.risk = ProcessRisk.PUP
        elif risk_score > 0:
            proc_info.risk = ProcessRisk.UNKNOWN
        else:
            proc_info.risk = ProcessRisk.CLEAN
        
        proc_info.risk_score = risk_score
        proc_info.risk_factors = risk_factors
        
        return proc_info
    
    def get_all_processes(self) -> List[ProcessInfo]:
        """Get all running processes with risk analysis"""
        processes = []
        
        for proc in psutil.process_iter():
            proc_info = self._get_process_info(proc)
            if proc_info:
                proc_info = self._analyze_process_risk(proc_info)
                processes.append(proc_info)
        
        # Sort by risk score
        processes.sort(key=lambda x: x.risk_score, reverse=True)
        
        with self._lock:
            self.processes = {p.pid: p for p in processes}
        
        return processes
    
    def get_suspicious_processes(self) -> List[ProcessInfo]:
        """Get only suspicious/malicious processes"""
        all_procs = self.get_all_processes()
        return [p for p in all_procs if p.risk in [ProcessRisk.MALICIOUS, ProcessRisk.SUSPICIOUS, ProcessRisk.PUP]]
    
    def kill_process(self, pid: int, force: bool = False) -> bool:
        """Kill a process by PID"""
        try:
            proc = psutil.Process(pid)
            proc_info = self._get_process_info(proc)
            
            if force:
                proc.kill()
            else:
                proc.terminate()
                proc.wait(timeout=5)
            
            self.killed_processes.append({
                "pid": pid,
                "name": proc_info.name if proc_info else "unknown",
                "cmdline": proc_info.cmdline if proc_info else "",
                "killed_at": datetime.now().isoformat(),
                "forced": force
            })
            
            return True
        except psutil.NoSuchProcess:
            return True  # Already dead
        except Exception as e:
            print(f"Failed to kill process {pid}: {e}")
            return False
    
    def auto_kill_threats(self) -> List[Dict]:
        """Automatically kill high-risk processes"""
        killed = []
        suspicious = self.get_suspicious_processes()
        
        for proc in suspicious:
            if proc.risk == ProcessRisk.MALICIOUS and proc.risk_score >= 70:
                if self.kill_process(proc.pid, force=True):
                    killed.append({
                        "pid": proc.pid,
                        "name": proc.name,
                        "risk_score": proc.risk_score,
                        "risk_factors": proc.risk_factors
                    })
                    
                    self.alerts.append({
                        "type": "process_killed",
                        "severity": "critical",
                        "message": f"Auto-killed malicious process: {proc.name} (PID: {proc.pid})",
                        "details": asdict(proc),
                        "timestamp": datetime.now().isoformat()
                    })
        
        return killed
    
    def get_process_tree(self, pid: int) -> Dict:
        """Get process tree for a given PID"""
        try:
            proc = psutil.Process(pid)
            
            def build_tree(p):
                info = self._get_process_info(p)
                children = []
                try:
                    for child in p.children():
                        children.append(build_tree(child))
                except:
                    pass
                
                return {
                    "pid": p.pid,
                    "name": p.name(),
                    "info": asdict(info) if info else {},
                    "children": children
                }
            
            return build_tree(proc)
        except:
            return {}
    
    def get_stats(self) -> Dict:
        """Get process monitoring statistics"""
        all_procs = self.get_all_processes()
        
        by_risk = defaultdict(int)
        by_user = defaultdict(int)
        
        total_cpu = 0
        total_mem = 0
        
        for p in all_procs:
            by_risk[p.risk.value] += 1
            by_user[p.username] += 1
            total_cpu += p.cpu_percent
            total_mem += p.memory_mb
        
        return {
            "total_processes": len(all_procs),
            "by_risk_level": dict(by_risk),
            "by_user": dict(by_user),
            "total_cpu_percent": round(total_cpu, 2),
            "total_memory_mb": round(total_mem, 2),
            "killed_count": len(self.killed_processes),
            "alerts_count": len(self.alerts)
        }


# =============================================================================
# USER PRIVILEGE MONITOR
# =============================================================================

class UserPrivilegeMonitor:
    """
    Monitor user privileges, sudo access, and shell aliases
    Detects privilege escalation and suspicious alias definitions
    """
    
    SUSPICIOUS_ALIASES = [
        "sudo", "su", "passwd", "shadow", "id", "whoami",
        "ls", "cat", "rm", "mv", "cp",  # Command hijacking
        "ssh", "scp", "rsync",          # Network command hijacking
    ]
    
    def __init__(self):
        self.users: Dict[str, UserPrivilege] = {}
        self.alerts: List[Dict] = []
    
    def _get_user_groups(self, username: str) -> List[str]:
        """Get groups for a user"""
        groups = []
        try:
            if platform.system() != "Windows":
                result = subprocess.run(["groups", username], capture_output=True, text=True)
                if result.returncode == 0:
                    # Format: "username : group1 group2 group3"
                    parts = result.stdout.strip().split(":")
                    if len(parts) > 1:
                        groups = parts[1].strip().split()
            else:
                # Windows - use net user
                result = subprocess.run(["net", "user", username], capture_output=True, text=True)
                # Parse group memberships from output
                for line in result.stdout.split('\n'):
                    if 'Local Group' in line or 'Global Group' in line:
                        groups.append(line.split()[-1])
        except:
            pass
        return groups
    
    def _check_sudo_access(self, username: str) -> bool:
        """Check if user has sudo access"""
        try:
            if platform.system() == "Windows":
                # Check if user is in Administrators group
                result = subprocess.run(
                    ["net", "localgroup", "Administrators"],
                    capture_output=True, text=True
                )
                return username in result.stdout
            else:
                # Check sudoers
                groups = self._get_user_groups(username)
                sudo_groups = ["sudo", "wheel", "admin", "root"]
                return any(g in sudo_groups for g in groups)
        except:
            return False
    
    def _get_shell_aliases(self, username: str) -> Dict[str, str]:
        """Extract shell aliases for a user"""
        aliases = {}
        
        if platform.system() == "Windows":
            return aliases  # Windows doesn't use shell aliases the same way
        
        # Check common shell config files
        home = Path(f"/home/{username}") if username != "root" else Path("/root")
        
        alias_files = [
            home / ".bashrc",
            home / ".bash_aliases",
            home / ".zshrc",
            home / ".profile",
            home / ".bash_profile"
        ]
        
        alias_pattern = re.compile(r"^\s*alias\s+(\w+)=['\"]?(.+?)['\"]?\s*$")
        
        for alias_file in alias_files:
            try:
                if alias_file.exists():
                    with open(alias_file, 'r') as f:
                        for line in f:
                            match = alias_pattern.match(line.strip())
                            if match:
                                alias_name, alias_cmd = match.groups()
                                aliases[alias_name] = alias_cmd
            except:
                pass
        
        return aliases
    
    def _analyze_alias_risk(self, aliases: Dict[str, str]) -> List[Dict]:
        """Analyze aliases for suspicious patterns"""
        risks = []
        
        for alias_name, alias_cmd in aliases.items():
            # Check if aliasing a security-sensitive command
            if alias_name in self.SUSPICIOUS_ALIASES:
                risks.append({
                    "alias": alias_name,
                    "command": alias_cmd,
                    "risk": "Command hijacking - security-sensitive command aliased",
                    "severity": "high"
                })
            
            # Check for suspicious patterns in alias commands
            suspicious_patterns = [
                (r"curl.*\|.*sh", "Remote code execution via curl"),
                (r"wget.*\|.*sh", "Remote code execution via wget"),
                (r"nc\s+-", "Netcat usage"),
                (r"base64.*decode", "Base64 decoding"),
                (r"python.*-c", "Inline Python execution"),
                (r"eval\s", "Eval usage"),
                (r"\$\(.*\)", "Command substitution"),
                (r">\s*/dev/null\s*2>&1", "Output suppression"),
            ]
            
            for pattern, description in suspicious_patterns:
                if re.search(pattern, alias_cmd, re.IGNORECASE):
                    risks.append({
                        "alias": alias_name,
                        "command": alias_cmd,
                        "risk": description,
                        "severity": "medium"
                    })
        
        return risks
    
    def get_all_users(self) -> List[UserPrivilege]:
        """Get all system users with their privileges"""
        users = []
        
        try:
            if platform.system() == "Windows":
                # Windows users
                result = subprocess.run(["net", "user"], capture_output=True, text=True)
                # Parse user list from output
                for line in result.stdout.split('\n'):
                    for word in line.split():
                        if word and not word.startswith('-') and word not in ['User', 'accounts', 'for', 'The', 'command', 'completed']:
                            try:
                                user = UserPrivilege(
                                    username=word,
                                    uid=0,
                                    gid=0,
                                    groups=self._get_user_groups(word),
                                    is_admin=self._check_sudo_access(word),
                                    home_dir=str(Path.home()),
                                    shell="cmd.exe",
                                    sudo_access=self._check_sudo_access(word),
                                    aliases={}
                                )
                                users.append(user)
                            except:
                                pass
            else:
                # Unix users
                import pwd
                for pw in pwd.getpwall():
                    # Skip system users (usually UID < 1000, except root)
                    if pw.pw_uid < 1000 and pw.pw_uid != 0:
                        continue
                    
                    aliases = self._get_shell_aliases(pw.pw_name)
                    
                    user = UserPrivilege(
                        username=pw.pw_name,
                        uid=pw.pw_uid,
                        gid=pw.pw_gid,
                        groups=self._get_user_groups(pw.pw_name),
                        is_admin=(pw.pw_uid == 0),
                        home_dir=pw.pw_dir,
                        shell=pw.pw_shell,
                        sudo_access=self._check_sudo_access(pw.pw_name),
                        aliases=aliases
                    )
                    users.append(user)
        except Exception as e:
            print(f"Error getting users: {e}")
        
        self.users = {u.username: u for u in users}
        return users
    
    def get_privileged_users(self) -> List[UserPrivilege]:
        """Get only users with elevated privileges"""
        all_users = self.get_all_users()
        return [u for u in all_users if u.is_admin or u.sudo_access]
    
    def check_alias_risks(self) -> List[Dict]:
        """Check all users for suspicious aliases"""
        all_risks = []
        
        for username, user in self.users.items():
            risks = self._analyze_alias_risk(user.aliases)
            for risk in risks:
                risk["username"] = username
                all_risks.append(risk)
                
                if risk["severity"] == "high":
                    self.alerts.append({
                        "type": "suspicious_alias",
                        "severity": "high",
                        "username": username,
                        "message": f"Suspicious alias detected for {username}: {risk['alias']}",
                        "details": risk,
                        "timestamp": datetime.now().isoformat()
                    })
        
        return all_risks
    
    def get_stats(self) -> Dict:
        """Get user privilege statistics"""
        self.get_all_users()
        
        return {
            "total_users": len(self.users),
            "admin_users": len([u for u in self.users.values() if u.is_admin]),
            "sudo_users": len([u for u in self.users.values() if u.sudo_access]),
            "users_with_aliases": len([u for u in self.users.values() if u.aliases]),
            "total_aliases": sum(len(u.aliases) for u in self.users.values()),
            "alerts_count": len(self.alerts)
        }


# =============================================================================
# BROWSER EXTENSION MONITOR
# =============================================================================

class BrowserExtensionMonitor:
    """
    Scan and analyze browser extensions for malicious behavior
    Supports Chrome, Firefox, Edge, Brave, and Chromium
    """
    
    DANGEROUS_PERMISSIONS = [
        "webRequest",
        "webRequestBlocking",
        "cookies",
        "clipboardRead",
        "clipboardWrite",
        "nativeMessaging",
        "debugger",
        "history",
        "bookmarks",
        "browsingData",
        "downloads",
        "management",
        "proxy",
        "privacy",
        "topSites",
        "sessions",
        "identity",
        "identity.email",
        "<all_urls>",
        "http://*/*",
        "https://*/*",
        "*://*/*",
    ]
    
    KNOWN_MALICIOUS_EXTENSIONS = [
        # Add known malicious extension IDs here
        "fake-extension-id-1",
        "fake-extension-id-2",
    ]
    
    BROWSER_PATHS = {
        "chrome": {
            "windows": [
                Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/User Data",
                Path(os.environ.get("APPDATA", "")) / "Google/Chrome/User Data",
            ],
            "darwin": [
                Path.home() / "Library/Application Support/Google/Chrome",
            ],
            "linux": [
                Path.home() / ".config/google-chrome",
                Path.home() / ".config/chromium",
            ]
        },
        "firefox": {
            "windows": [
                Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox/Profiles",
            ],
            "darwin": [
                Path.home() / "Library/Application Support/Firefox/Profiles",
            ],
            "linux": [
                Path.home() / ".mozilla/firefox",
            ]
        },
        "edge": {
            "windows": [
                Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/Edge/User Data",
            ],
            "darwin": [
                Path.home() / "Library/Application Support/Microsoft Edge",
            ],
            "linux": [
                Path.home() / ".config/microsoft-edge",
            ]
        },
        "brave": {
            "windows": [
                Path(os.environ.get("LOCALAPPDATA", "")) / "BraveSoftware/Brave-Browser/User Data",
            ],
            "darwin": [
                Path.home() / "Library/Application Support/BraveSoftware/Brave-Browser",
            ],
            "linux": [
                Path.home() / ".config/BraveSoftware/Brave-Browser",
            ]
        }
    }
    
    def __init__(self):
        self.extensions: List[BrowserExtension] = []
        self.alerts: List[Dict] = []
        self.system = platform.system().lower()
    
    def _get_browser_path(self, browser: str) -> Optional[Path]:
        """Get browser data path for current OS"""
        paths = self.BROWSER_PATHS.get(browser, {}).get(self.system, [])
        for path in paths:
            if path.exists():
                return path
        return None
    
    def _scan_chromium_extensions(self, browser: str, base_path: Path) -> List[BrowserExtension]:
        """Scan Chrome/Edge/Brave extensions"""
        extensions = []
        
        # Find all profiles (Default, Profile 1, Profile 2, etc.)
        profiles = [d for d in base_path.iterdir() if d.is_dir() and 
                   (d.name == "Default" or d.name.startswith("Profile"))]
        
        for profile in profiles:
            extensions_dir = profile / "Extensions"
            if not extensions_dir.exists():
                continue
            
            for ext_id_dir in extensions_dir.iterdir():
                if not ext_id_dir.is_dir():
                    continue
                
                ext_id = ext_id_dir.name
                
                # Get latest version
                versions = sorted(ext_id_dir.iterdir(), reverse=True)
                if not versions:
                    continue
                
                latest = versions[0]
                manifest_path = latest / "manifest.json"
                
                if not manifest_path.exists():
                    continue
                
                try:
                    with open(manifest_path, 'r', encoding='utf-8') as f:
                        manifest = json.load(f)
                    
                    permissions = manifest.get("permissions", [])
                    permissions += manifest.get("optional_permissions", [])
                    
                    # Check host permissions (Manifest V3)
                    if "host_permissions" in manifest:
                        permissions += manifest["host_permissions"]
                    
                    ext = BrowserExtension(
                        browser=browser,
                        name=manifest.get("name", "Unknown"),
                        id=ext_id,
                        version=manifest.get("version", "0.0.0"),
                        description=manifest.get("description", ""),
                        permissions=permissions,
                        enabled=True,  # Would need Preferences file to determine
                        manifest_path=str(manifest_path)
                    )
                    
                    ext = self._analyze_extension_risk(ext)
                    extensions.append(ext)
                    
                except Exception as e:
                    pass
        
        return extensions
    
    def _scan_firefox_extensions(self, base_path: Path) -> List[BrowserExtension]:
        """Scan Firefox extensions"""
        extensions = []
        
        # Find profile directories
        profiles = [d for d in base_path.iterdir() if d.is_dir() and 
                   (".default" in d.name or "default-release" in d.name)]
        
        for profile in profiles:
            extensions_json = profile / "extensions.json"
            if not extensions_json.exists():
                continue
            
            try:
                with open(extensions_json, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                for addon in data.get("addons", []):
                    if addon.get("type") != "extension":
                        continue
                    
                    permissions = addon.get("userPermissions", {}).get("permissions", [])
                    permissions += addon.get("userPermissions", {}).get("origins", [])
                    
                    ext = BrowserExtension(
                        browser="firefox",
                        name=addon.get("defaultLocale", {}).get("name", addon.get("id", "Unknown")),
                        id=addon.get("id", ""),
                        version=addon.get("version", "0.0.0"),
                        description=addon.get("defaultLocale", {}).get("description", ""),
                        permissions=permissions,
                        enabled=addon.get("active", False),
                        manifest_path=str(profile)
                    )
                    
                    ext = self._analyze_extension_risk(ext)
                    extensions.append(ext)
                    
            except Exception as e:
                pass
        
        return extensions
    
    def _analyze_extension_risk(self, ext: BrowserExtension) -> BrowserExtension:
        """Analyze extension for security risks"""
        risk_factors = []
        risk_score = 0
        
        # Check for dangerous permissions
        for perm in ext.permissions:
            if perm in self.DANGEROUS_PERMISSIONS:
                risk_factors.append(f"Dangerous permission: {perm}")
                risk_score += 10
            
            # All URLs permission is especially dangerous
            if perm in ["<all_urls>", "*://*/*"]:
                risk_factors.append("Extension has access to ALL websites")
                risk_score += 20
        
        # Check for known malicious extensions
        if ext.id in self.KNOWN_MALICIOUS_EXTENSIONS:
            risk_factors.append("Known malicious extension")
            risk_score += 50
        
        # Check for suspicious patterns in name/description
        suspicious_keywords = ["free vpn", "hack", "crack", "keygen", "download manager", "video downloader"]
        name_lower = ext.name.lower()
        desc_lower = ext.description.lower()
        
        for keyword in suspicious_keywords:
            if keyword in name_lower or keyword in desc_lower:
                risk_factors.append(f"Suspicious keyword: {keyword}")
                risk_score += 15
        
        # High permission count
        if len(ext.permissions) > 10:
            risk_factors.append(f"Excessive permissions: {len(ext.permissions)}")
            risk_score += 10
        
        ext.risk_score = min(risk_score, 100)
        ext.risk_factors = risk_factors
        
        return ext
    
    def scan_all_browsers(self) -> List[BrowserExtension]:
        """Scan all browsers for extensions"""
        self.extensions = []
        
        # Chrome-based browsers
        for browser in ["chrome", "edge", "brave"]:
            path = self._get_browser_path(browser)
            if path:
                self.extensions.extend(self._scan_chromium_extensions(browser, path))
        
        # Firefox
        firefox_path = self._get_browser_path("firefox")
        if firefox_path:
            self.extensions.extend(self._scan_firefox_extensions(firefox_path))
        
        # Generate alerts for high-risk extensions
        for ext in self.extensions:
            if ext.risk_score >= 40:
                self.alerts.append({
                    "type": "risky_extension",
                    "severity": "high" if ext.risk_score >= 60 else "medium",
                    "browser": ext.browser,
                    "extension": ext.name,
                    "message": f"High-risk extension detected: {ext.name} ({ext.browser})",
                    "details": asdict(ext),
                    "timestamp": datetime.now().isoformat()
                })
        
        return self.extensions
    
    def get_risky_extensions(self, min_score: int = 30) -> List[BrowserExtension]:
        """Get extensions above a certain risk threshold"""
        if not self.extensions:
            self.scan_all_browsers()
        return [e for e in self.extensions if e.risk_score >= min_score]
    
    def get_stats(self) -> Dict:
        """Get browser extension statistics"""
        if not self.extensions:
            self.scan_all_browsers()
        
        by_browser = defaultdict(int)
        by_risk = {"high": 0, "medium": 0, "low": 0}
        
        for ext in self.extensions:
            by_browser[ext.browser] += 1
            if ext.risk_score >= 60:
                by_risk["high"] += 1
            elif ext.risk_score >= 30:
                by_risk["medium"] += 1
            else:
                by_risk["low"] += 1
        
        return {
            "total_extensions": len(self.extensions),
            "by_browser": dict(by_browser),
            "by_risk_level": by_risk,
            "browsers_scanned": list(by_browser.keys()),
            "alerts_count": len(self.alerts)
        }


# =============================================================================
# FOLDER INDEXER & SCRAPER
# =============================================================================

class FolderIndexer:
    """
    Deep folder indexing and hidden file scraping
    Detects hidden files, suspicious files, and anomalies
    """
    
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".vbe",
        ".js", ".jse", ".ws", ".wsf", ".wsc", ".wsh", ".ps1",
        ".psm1", ".psd1", ".msi", ".msp", ".mst", ".com", ".pif",
        ".application", ".gadget", ".msc", ".hta", ".cpl", ".msc",
        ".jar", ".reg", ".inf", ".scf", ".lnk"
    }
    
    SENSITIVE_FILENAMES = [
        "password", "passwd", "credentials", "secret", "private",
        "key", "token", "api_key", "apikey", ".env", "config",
        "wallet", "bitcoin", "ethereum", "crypto", "seed", "mnemonic",
        "id_rsa", "id_ed25519", "known_hosts", "authorized_keys",
        ".aws", ".ssh", ".gnupg", ".pgp"
    ]
    
    HIDDEN_FILE_PATTERNS = [
        r"^\.",                    # Unix hidden files
        r"~\$",                    # Office temp files
        r"^\$",                    # Windows system files
        r"^desktop\.ini$",
        r"^thumbs\.db$",
        r"^\.ds_store$",
    ]
    
    def __init__(self):
        self.indexed_files: List[FileIndex] = []
        self.hidden_files: List[FileIndex] = []
        self.suspicious_files: List[FileIndex] = []
        self.alerts: List[Dict] = []
        self._index_cache: Dict[str, FileIndex] = {}
    
    def _is_hidden(self, path: Path) -> bool:
        """Check if file/folder is hidden"""
        name = path.name
        
        # Check patterns
        for pattern in self.HIDDEN_FILE_PATTERNS:
            if re.match(pattern, name, re.IGNORECASE):
                return True
        
        # Windows hidden attribute
        if platform.system() == "Windows":
            try:
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
                return bool(attrs & 2)  # FILE_ATTRIBUTE_HIDDEN
            except:
                pass
        
        return name.startswith('.')
    
    def _is_system_file(self, path: Path) -> bool:
        """Check if file is a system file"""
        if platform.system() == "Windows":
            try:
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
                return bool(attrs & 4)  # FILE_ATTRIBUTE_SYSTEM
            except:
                pass
        return False
    
    def _calculate_file_hash(self, path: Path, quick: bool = True) -> Optional[str]:
        """Calculate MD5 hash of file"""
        try:
            hasher = hashlib.md5()
            with open(path, 'rb') as f:
                if quick:
                    # Only hash first 1MB for speed
                    hasher.update(f.read(1024 * 1024))
                else:
                    for chunk in iter(lambda: f.read(8192), b""):
                        hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return None
    
    def _analyze_file_risk(self, file_idx: FileIndex) -> FileIndex:
        """Analyze file for security risks"""
        flags = []
        risk_score = 0
        
        name_lower = file_idx.name.lower()
        
        # Check for suspicious extensions
        if file_idx.extension.lower() in self.SUSPICIOUS_EXTENSIONS:
            flags.append(f"Suspicious extension: {file_idx.extension}")
            risk_score += 20
        
        # Check for sensitive filenames
        for sensitive in self.SENSITIVE_FILENAMES:
            if sensitive in name_lower:
                flags.append(f"Sensitive filename pattern: {sensitive}")
                risk_score += 15
        
        # Hidden file in non-hidden directory
        if file_idx.is_hidden:
            flags.append("Hidden file")
            risk_score += 10
        
        # System file in user directory
        if file_idx.is_system and str(Path.home()) in file_idx.path:
            flags.append("System file in user directory")
            risk_score += 25
        
        # Executable in temp/downloads
        temp_dirs = ["/tmp", "temp", "downloads", "desktop"]
        if file_idx.extension.lower() in [".exe", ".dll", ".scr", ".bat", ".ps1"]:
            if any(td in file_idx.path.lower() for td in temp_dirs):
                flags.append("Executable in temp/downloads directory")
                risk_score += 30
        
        # Double extension (file.pdf.exe)
        if file_idx.name.count('.') > 1:
            if file_idx.extension.lower() in self.SUSPICIOUS_EXTENSIONS:
                flags.append("Double extension detected")
                risk_score += 35
        
        # Very recent file
        try:
            modified = datetime.fromisoformat(file_idx.modified.replace('Z', '+00:00'))
            if (datetime.now(modified.tzinfo) - modified).total_seconds() < 300:  # 5 minutes
                flags.append("Very recently modified")
                risk_score += 5
        except:
            pass
        
        file_idx.risk_score = min(risk_score, 100)
        file_idx.flags = flags
        
        return file_idx
    
    def index_directory(self, directory: str, max_depth: int = 5, include_hidden: bool = True) -> List[FileIndex]:
        """Index all files in a directory"""
        indexed = []
        dir_path = Path(directory)
        
        if not dir_path.exists():
            return indexed
        
        def scan_dir(path: Path, depth: int):
            if depth > max_depth:
                return
            
            try:
                for item in path.iterdir():
                    try:
                        is_hidden = self._is_hidden(item)
                        
                        if not include_hidden and is_hidden:
                            continue
                        
                        if item.is_file():
                            stat = item.stat()
                            
                            file_idx = FileIndex(
                                path=str(item),
                                name=item.name,
                                size=stat.st_size,
                                modified=datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                created=datetime.fromtimestamp(stat.st_ctime).isoformat(),
                                is_hidden=is_hidden,
                                is_system=self._is_system_file(item),
                                extension=item.suffix
                            )
                            
                            file_idx = self._analyze_file_risk(file_idx)
                            indexed.append(file_idx)
                            
                            if file_idx.is_hidden:
                                self.hidden_files.append(file_idx)
                            
                            if file_idx.risk_score >= 30:
                                self.suspicious_files.append(file_idx)
                        
                        elif item.is_dir() and not item.is_symlink():
                            scan_dir(item, depth + 1)
                    
                    except PermissionError:
                        pass
                    except Exception as e:
                        pass
            
            except PermissionError:
                pass
        
        scan_dir(dir_path, 0)
        self.indexed_files.extend(indexed)
        
        # Generate alerts for high-risk files
        for f in indexed:
            if f.risk_score >= 50:
                self.alerts.append({
                    "type": "suspicious_file",
                    "severity": "high" if f.risk_score >= 70 else "medium",
                    "path": f.path,
                    "message": f"Suspicious file detected: {f.name}",
                    "details": asdict(f),
                    "timestamp": datetime.now().isoformat()
                })
        
        return indexed
    
    def scan_user_directories(self) -> List[FileIndex]:
        """Scan common user directories for suspicious files"""
        home = Path.home()
        
        dirs_to_scan = [
            home / "Downloads",
            home / "Desktop",
            home / "Documents",
            home / "AppData" / "Local" / "Temp" if platform.system() == "Windows" else Path("/tmp"),
            home / ".local" / "share" if platform.system() != "Windows" else None,
        ]
        
        for d in dirs_to_scan:
            if d and d.exists():
                self.index_directory(str(d), max_depth=3)
        
        return self.indexed_files
    
    def find_hidden_files(self, directory: str) -> List[FileIndex]:
        """Find all hidden files in a directory"""
        self.hidden_files = []
        self.index_directory(directory, include_hidden=True)
        return self.hidden_files
    
    def get_suspicious_files(self, min_score: int = 30) -> List[FileIndex]:
        """Get files above a certain risk threshold"""
        return [f for f in self.indexed_files if f.risk_score >= min_score]
    
    def get_stats(self) -> Dict:
        """Get folder indexing statistics"""
        return {
            "total_indexed": len(self.indexed_files),
            "hidden_files": len(self.hidden_files),
            "suspicious_files": len(self.suspicious_files),
            "total_size_mb": round(sum(f.size for f in self.indexed_files) / (1024 * 1024), 2),
            "by_extension": dict(defaultdict(int, {f.extension: 1 for f in self.indexed_files})),
            "alerts_count": len(self.alerts)
        }


# =============================================================================
# SCHEDULED TASK / CRON MONITOR
# =============================================================================

@dataclass
class ScheduledTask:
    name: str
    command: str
    schedule: str
    user: str
    enabled: bool
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    path: str = ""
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)

class ScheduledTaskMonitor:
    """
    Monitor scheduled tasks (Windows Task Scheduler) and cron jobs (Linux/macOS)
    Detect persistence mechanisms and suspicious scheduled executions
    """
    
    SUSPICIOUS_COMMANDS = [
        "powershell", "cmd.exe", "wscript", "cscript", "mshta",
        "certutil", "bitsadmin", "regsvr32", "rundll32",
        "curl", "wget", "nc", "ncat", "python", "perl", "ruby",
        "base64", "eval", "exec", "sh -c", "bash -c",
    ]
    
    SUSPICIOUS_PATHS = [
        "temp", "tmp", "appdata", "programdata", "public",
        "/dev/shm", "/var/tmp", "/tmp",
    ]
    
    def __init__(self):
        self.tasks: List[ScheduledTask] = []
        self.alerts: List[Dict] = []
        self.system = platform.system()
    
    def _get_windows_tasks(self) -> List[ScheduledTask]:
        """Get Windows scheduled tasks"""
        tasks = []
        
        try:
            # Use schtasks to list all tasks
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    # Parse CSV header
                    headers = [h.strip('"') for h in lines[0].split(',')]
                    
                    for line in lines[1:]:
                        try:
                            values = [v.strip('"') for v in line.split(',')]
                            if len(values) >= len(headers):
                                task_dict = dict(zip(headers, values))
                                
                                task = ScheduledTask(
                                    name=task_dict.get("TaskName", ""),
                                    command=task_dict.get("Task To Run", ""),
                                    schedule=task_dict.get("Schedule Type", ""),
                                    user=task_dict.get("Run As User", ""),
                                    enabled=task_dict.get("Status", "") == "Ready",
                                    last_run=task_dict.get("Last Run Time", ""),
                                    next_run=task_dict.get("Next Run Time", ""),
                                    path=task_dict.get("TaskName", "")
                                )
                                tasks.append(task)
                        except:
                            pass
        except Exception as e:
            print(f"Error getting Windows tasks: {e}")
        
        return tasks
    
    def _get_linux_cron_jobs(self) -> List[ScheduledTask]:
        """Get Linux/macOS cron jobs"""
        tasks = []
        
        # System crontabs
        cron_dirs = [
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/var/spool/cron/crontabs",  # User crontabs (Linux)
            "/var/spool/cron",            # User crontabs (some distros)
            "/usr/lib/cron/tabs",         # macOS
        ]
        
        def parse_crontab_line(line: str, source: str, user: str = "root") -> Optional[ScheduledTask]:
            line = line.strip()
            if not line or line.startswith('#'):
                return None
            
            # Parse cron schedule and command
            parts = line.split()
            if len(parts) >= 6:
                # Standard cron format: min hour day month dow command
                schedule = " ".join(parts[:5])
                
                # Check if there's a user field (system crontab)
                if source == "/etc/crontab":
                    user = parts[5]
                    command = " ".join(parts[6:])
                else:
                    command = " ".join(parts[5:])
                
                return ScheduledTask(
                    name=f"cron:{source}",
                    command=command,
                    schedule=schedule,
                    user=user,
                    enabled=True,
                    path=source
                )
            return None
        
        # Parse crontab files
        for cron_path in cron_dirs:
            path = Path(cron_path)
            if not path.exists():
                continue
            
            try:
                if path.is_file():
                    with open(path, 'r') as f:
                        for line in f:
                            task = parse_crontab_line(line, str(path))
                            if task:
                                tasks.append(task)
                
                elif path.is_dir():
                    for file in path.iterdir():
                        if file.is_file():
                            try:
                                user = file.name  # User crontab filename is username
                                with open(file, 'r') as f:
                                    for line in f:
                                        task = parse_crontab_line(line, str(file), user)
                                        if task:
                                            tasks.append(task)
                            except:
                                pass
            except PermissionError:
                pass
            except Exception as e:
                pass
        
        # Also check systemd timers
        try:
            result = subprocess.run(
                ["systemctl", "list-timers", "--all", "--no-pager"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 5:
                        tasks.append(ScheduledTask(
                            name=parts[-1] if parts else "systemd-timer",
                            command="systemd timer",
                            schedule="systemd",
                            user="system",
                            enabled=True,
                            next_run=f"{parts[0]} {parts[1]}" if len(parts) > 1 else "",
                            path="systemd"
                        ))
        except:
            pass
        
        # macOS launchd
        if self.system == "Darwin":
            launch_dirs = [
                "/Library/LaunchDaemons",
                "/Library/LaunchAgents",
                Path.home() / "Library/LaunchAgents",
            ]
            
            for launch_dir in launch_dirs:
                if Path(launch_dir).exists():
                    for plist in Path(launch_dir).glob("*.plist"):
                        try:
                            # Parse plist (simplified)
                            result = subprocess.run(
                                ["plutil", "-p", str(plist)],
                                capture_output=True, text=True
                            )
                            if result.returncode == 0:
                                # Extract program/command from plist output
                                content = result.stdout
                                program = ""
                                if "ProgramArguments" in content or "Program" in content:
                                    program = "launchd job"
                                
                                tasks.append(ScheduledTask(
                                    name=plist.stem,
                                    command=program,
                                    schedule="launchd",
                                    user="system",
                                    enabled=True,
                                    path=str(plist)
                                ))
                        except:
                            pass
        
        return tasks
    
    def _analyze_task_risk(self, task: ScheduledTask) -> ScheduledTask:
        """Analyze scheduled task for security risks"""
        risk_factors = []
        risk_score = 0
        
        cmd_lower = task.command.lower()
        path_lower = task.path.lower()
        
        # Check for suspicious commands
        for sus_cmd in self.SUSPICIOUS_COMMANDS:
            if sus_cmd in cmd_lower:
                risk_factors.append(f"Suspicious command: {sus_cmd}")
                risk_score += 15
        
        # Check for suspicious paths
        for sus_path in self.SUSPICIOUS_PATHS:
            if sus_path in cmd_lower or sus_path in path_lower:
                risk_factors.append(f"Suspicious path: {sus_path}")
                risk_score += 20
        
        # Check for encoded commands
        if "base64" in cmd_lower or "-enc" in cmd_lower or "-e " in cmd_lower:
            risk_factors.append("Encoded/obfuscated command")
            risk_score += 30
        
        # Check for network activity
        if any(net in cmd_lower for net in ["curl", "wget", "http://", "https://", "ftp://"]):
            risk_factors.append("Network activity in scheduled task")
            risk_score += 20
        
        # Check for reverse shells
        if any(shell in cmd_lower for shell in ["/dev/tcp", "nc -e", "ncat", "bash -i"]):
            risk_factors.append("Potential reverse shell")
            risk_score += 40
        
        # Hidden or obfuscated task names
        if task.name.startswith('.') or len(task.name) > 50 or re.search(r'[^\x00-\x7F]', task.name):
            risk_factors.append("Suspicious task name")
            risk_score += 10
        
        task.risk_score = min(risk_score, 100)
        task.risk_factors = risk_factors
        
        return task
    
    def get_all_tasks(self) -> List[ScheduledTask]:
        """Get all scheduled tasks/cron jobs"""
        if self.system == "Windows":
            self.tasks = self._get_windows_tasks()
        else:
            self.tasks = self._get_linux_cron_jobs()
        
        # Analyze each task
        self.tasks = [self._analyze_task_risk(t) for t in self.tasks]
        
        # Generate alerts
        for task in self.tasks:
            if task.risk_score >= 40:
                self.alerts.append({
                    "type": "suspicious_scheduled_task",
                    "severity": "high" if task.risk_score >= 60 else "medium",
                    "task_name": task.name,
                    "message": f"Suspicious scheduled task: {task.name}",
                    "details": asdict(task),
                    "timestamp": datetime.now().isoformat()
                })
        
        return self.tasks
    
    def get_suspicious_tasks(self, min_score: int = 30) -> List[ScheduledTask]:
        """Get tasks above a certain risk threshold"""
        if not self.tasks:
            self.get_all_tasks()
        return [t for t in self.tasks if t.risk_score >= min_score]
    
    def get_stats(self) -> Dict:
        """Get scheduled task statistics"""
        if not self.tasks:
            self.get_all_tasks()
        
        return {
            "total_tasks": len(self.tasks),
            "suspicious_tasks": len([t for t in self.tasks if t.risk_score >= 30]),
            "high_risk_tasks": len([t for t in self.tasks if t.risk_score >= 60]),
            "by_user": dict(defaultdict(int, {t.user: 1 for t in self.tasks})),
            "alerts_count": len(self.alerts)
        }


# =============================================================================
# USB DEVICE MONITOR
# =============================================================================

@dataclass
class USBDevice:
    device_id: str
    name: str
    vendor: str
    product: str
    serial: Optional[str] = None
    mount_point: Optional[str] = None
    device_type: str = "unknown"
    first_seen: str = ""
    last_seen: str = ""
    is_storage: bool = False
    is_allowed: bool = True
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)

class USBDeviceMonitor:
    """
    Monitor USB device connections
    Detect unauthorized devices, BadUSB attacks, and data exfiltration
    """
    
    # Known BadUSB vendor/product IDs
    SUSPICIOUS_USB_IDS = [
        ("16c0", "0486"),  # Teensy
        ("16c0", "0483"),  # Teensy
        ("1b4f", "9204"),  # Digispark
        ("1b4f", "9205"),  # Digispark
        ("2341", "8036"),  # Arduino Leonardo (can be used as HID)
        ("2341", "8037"),  # Arduino Micro
        ("1d50", "6080"),  # HackRF
        ("0483", "5740"),  # STM32 (common in BadUSB)
    ]
    
    def __init__(self):
        self.devices: Dict[str, USBDevice] = {}
        self.device_history: List[Dict] = []
        self.alerts: List[Dict] = []
        self.allowed_devices: Set[str] = set()  # Whitelisted device IDs
        self.system = platform.system()
    
    def _get_linux_usb_devices(self) -> List[USBDevice]:
        """Get USB devices on Linux"""
        devices = []
        
        try:
            # Use lsusb
            result = subprocess.run(
                ["lsusb"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    # Format: Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
                    match = re.match(r'Bus (\d+) Device (\d+): ID ([0-9a-f]+):([0-9a-f]+) (.+)', line)
                    if match:
                        bus, dev, vendor, product, name = match.groups()
                        device_id = f"{vendor}:{product}"
                        
                        device = USBDevice(
                            device_id=device_id,
                            name=name,
                            vendor=vendor,
                            product=product,
                            first_seen=datetime.now().isoformat(),
                            last_seen=datetime.now().isoformat()
                        )
                        devices.append(device)
        except:
            pass
        
        # Check for storage devices
        try:
            result = subprocess.run(
                ["lsblk", "-o", "NAME,TRAN,VENDOR,MODEL,SIZE,MOUNTPOINT", "-J"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for block in data.get("blockdevices", []):
                    if block.get("tran") == "usb":
                        for dev in devices:
                            if block.get("vendor", "").strip() in dev.name:
                                dev.is_storage = True
                                dev.mount_point = block.get("mountpoint")
                                dev.device_type = "storage"
        except:
            pass
        
        return devices
    
    def _get_macos_usb_devices(self) -> List[USBDevice]:
        """Get USB devices on macOS"""
        devices = []
        
        try:
            result = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                
                def parse_usb_tree(items):
                    for item in items:
                        if isinstance(item, dict):
                            vendor_id = item.get("vendor_id", "").replace("0x", "")
                            product_id = item.get("product_id", "").replace("0x", "")
                            
                            if vendor_id and product_id:
                                device = USBDevice(
                                    device_id=f"{vendor_id}:{product_id}",
                                    name=item.get("_name", "Unknown"),
                                    vendor=vendor_id,
                                    product=product_id,
                                    serial=item.get("serial_num"),
                                    first_seen=datetime.now().isoformat(),
                                    last_seen=datetime.now().isoformat()
                                )
                                devices.append(device)
                            
                            # Check for nested devices
                            if "_items" in item:
                                parse_usb_tree(item["_items"])
                
                usb_data = data.get("SPUSBDataType", [])
                for controller in usb_data:
                    if "_items" in controller:
                        parse_usb_tree(controller["_items"])
        except:
            pass
        
        return devices
    
    def _get_windows_usb_devices(self) -> List[USBDevice]:
        """Get USB devices on Windows"""
        devices = []
        
        try:
            # Use WMIC
            result = subprocess.run(
                ["wmic", "path", "Win32_USBControllerDevice", "get", "Dependent"],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if 'DeviceID' in line:
                        # Extract device ID
                        match = re.search(r'USB\\VID_([0-9A-F]+)&PID_([0-9A-F]+)', line)
                        if match:
                            vendor, product = match.groups()
                            device = USBDevice(
                                device_id=f"{vendor.lower()}:{product.lower()}",
                                name=line.strip(),
                                vendor=vendor.lower(),
                                product=product.lower(),
                                first_seen=datetime.now().isoformat(),
                                last_seen=datetime.now().isoformat()
                            )
                            devices.append(device)
        except:
            pass
        
        # Check for USB storage
        try:
            result = subprocess.run(
                ["wmic", "logicaldisk", "where", "drivetype=2", "get", "deviceid,volumename,size"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n')[1:]:
                    parts = line.split()
                    if parts:
                        # Mark as storage device
                        for dev in devices:
                            dev.is_storage = True
                            dev.device_type = "storage"
        except:
            pass
        
        return devices
    
    def _analyze_device_risk(self, device: USBDevice) -> USBDevice:
        """Analyze USB device for security risks"""
        risk_factors = []
        risk_score = 0
        
        # Check against known BadUSB devices
        device_tuple = (device.vendor.lower(), device.product.lower())
        if device_tuple in self.SUSPICIOUS_USB_IDS:
            risk_factors.append("Known BadUSB/HID attack device")
            risk_score += 50
        
        # Check if device is not whitelisted
        if device.device_id not in self.allowed_devices:
            risk_factors.append("Device not in whitelist")
            risk_score += 10
        
        # USB storage devices carry data exfiltration risk
        if device.is_storage:
            risk_factors.append("USB storage device - potential data exfiltration")
            risk_score += 15
        
        # Check for HID devices that could be keyboard emulators
        hid_indicators = ["keyboard", "mouse", "hid", "input"]
        if any(ind in device.name.lower() for ind in hid_indicators):
            # Multiple HID devices are suspicious
            risk_factors.append("HID device - potential keystroke injection")
            risk_score += 20
        
        # Unknown/generic devices
        if "unknown" in device.name.lower() or not device.name.strip():
            risk_factors.append("Unknown device type")
            risk_score += 15
        
        device.risk_score = min(risk_score, 100)
        device.risk_factors = risk_factors
        device.is_allowed = device.device_id in self.allowed_devices
        
        return device
    
    def get_all_devices(self) -> List[USBDevice]:
        """Get all connected USB devices"""
        if self.system == "Linux":
            devices = self._get_linux_usb_devices()
        elif self.system == "Darwin":
            devices = self._get_macos_usb_devices()
        elif self.system == "Windows":
            devices = self._get_windows_usb_devices()
        else:
            devices = []
        
        # Analyze each device
        devices = [self._analyze_device_risk(d) for d in devices]
        
        # Update device tracking
        for device in devices:
            if device.device_id in self.devices:
                device.first_seen = self.devices[device.device_id].first_seen
            self.devices[device.device_id] = device
        
        # Generate alerts
        for device in devices:
            if device.risk_score >= 40:
                self.alerts.append({
                    "type": "suspicious_usb_device",
                    "severity": "high" if device.risk_score >= 60 else "medium",
                    "device_id": device.device_id,
                    "message": f"Suspicious USB device: {device.name}",
                    "details": asdict(device),
                    "timestamp": datetime.now().isoformat()
                })
        
        return list(self.devices.values())
    
    def add_to_whitelist(self, device_id: str):
        """Add device to whitelist"""
        self.allowed_devices.add(device_id)
    
    def remove_from_whitelist(self, device_id: str):
        """Remove device from whitelist"""
        self.allowed_devices.discard(device_id)
    
    def get_suspicious_devices(self, min_score: int = 30) -> List[USBDevice]:
        """Get devices above a certain risk threshold"""
        return [d for d in self.devices.values() if d.risk_score >= min_score]
    
    def get_stats(self) -> Dict:
        """Get USB device statistics"""
        devices = list(self.devices.values())
        
        return {
            "total_devices": len(devices),
            "storage_devices": len([d for d in devices if d.is_storage]),
            "suspicious_devices": len([d for d in devices if d.risk_score >= 30]),
            "whitelisted_devices": len(self.allowed_devices),
            "alerts_count": len(self.alerts)
        }


# =============================================================================
# CREDENTIAL THEFT DETECTION
# =============================================================================

@dataclass
class CredentialAccessEvent:
    """Records credential access attempts"""
    timestamp: str
    event_type: str
    process_name: str
    pid: int
    target_path: str
    access_type: str  # read, write, execute
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)
    blocked: bool = False

class CredentialTheftDetector:
    """
    Detect credential theft attempts
    Monitors access to:
    - Windows: LSASS, SAM/SECURITY hives, browser credentials, Windows Vault
    - Linux: /etc/shadow, /etc/passwd, SSH keys, browser profiles
    - macOS: Keychain, browser credentials, SSH keys
    """
    
    # Known credential theft tools
    CREDENTIAL_THEFT_TOOLS = {
        "mimikatz", "mimikatz.exe", "mimilib.dll", "mimidrv.sys",
        "pwdump", "pwdump.exe", "fgdump", "gsecdump",
        "wce", "wce.exe", "windows credential editor",
        "lazagne", "lazagne.exe", "credentialdumper",
        "secretsdump", "secretsdump.py", "impacket",
        "lsassy", "pypykatz", "procdump", "procdump.exe",
        "nanodump", "handlekatz", "dcsync",
        "kerberoast", "asreproast", "rubeus",
        "keethief", "keethief.exe", "keepass",
        "chromepass", "webbrowserpassview", "passwordfox",
        "netpass", "network password recovery",
        "credentialmanager", "vaultcmd",
    }
    
    # Windows credential locations
    WINDOWS_CREDENTIAL_PATHS = [
        # SAM and SECURITY hives
        r"C:\Windows\System32\config\SAM",
        r"C:\Windows\System32\config\SECURITY",
        r"C:\Windows\System32\config\SYSTEM",
        # NTDS (domain controller)
        r"C:\Windows\NTDS\ntds.dit",
        # Browser credentials
        r"\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        r"\AppData\Local\Microsoft\Edge\User Data\Default\Login Data",
        r"\AppData\Roaming\Mozilla\Firefox\Profiles\*\logins.json",
        r"\AppData\Roaming\Mozilla\Firefox\Profiles\*\key4.db",
        # Windows Vault
        r"\AppData\Local\Microsoft\Vault",
        r"\AppData\Roaming\Microsoft\Credentials",
        r"\AppData\Local\Microsoft\Credentials",
        # RDP credentials
        r"\AppData\Local\Microsoft\Terminal Server Client\Cache",
        # WiFi passwords (requires admin)
        r"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\*",
    ]
    
    # Linux credential locations
    LINUX_CREDENTIAL_PATHS = [
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/ssh/ssh_host_*_key",
        "~/.ssh/id_rsa",
        "~/.ssh/id_ed25519",
        "~/.ssh/id_ecdsa",
        "~/.ssh/id_dsa",
        "~/.ssh/authorized_keys",
        "~/.ssh/known_hosts",
        # Browser credentials
        "~/.config/google-chrome/*/Login Data",
        "~/.config/chromium/*/Login Data",
        "~/.mozilla/firefox/*/logins.json",
        "~/.mozilla/firefox/*/key4.db",
        # GNOME Keyring
        "~/.local/share/keyrings/*",
        # KDE Wallet
        "~/.local/share/kwalletd/*",
        # Environment files with potential secrets
        "~/.bash_history",
        "~/.zsh_history",
        "~/.netrc",
        "~/.pgpass",
        "~/.my.cnf",
        "~/.docker/config.json",
        "~/.aws/credentials",
        "~/.azure/accessTokens.json",
    ]
    
    # macOS credential locations
    MACOS_CREDENTIAL_PATHS = [
        "/var/db/dslocal/nodes/Default/users/*.plist",
        "~/Library/Keychains/*",
        "/Library/Keychains/*",
        "~/.ssh/id_*",
        "~/.ssh/authorized_keys",
        # Browser credentials
        "~/Library/Application Support/Google/Chrome/*/Login Data",
        "~/Library/Application Support/Firefox/Profiles/*/logins.json",
        "~/Library/Application Support/Firefox/Profiles/*/key4.db",
        "~/Library/Safari/Passwords.plist",
        # Other secrets
        "~/.bash_history",
        "~/.zsh_history",
        "~/.netrc",
        "~/.aws/credentials",
        "~/.docker/config.json",
    ]
    
    # Suspicious process behaviors for LSASS access
    LSASS_ACCESS_PATTERNS = [
        r"lsass.*memory",
        r"dump.*lsass",
        r"minidump",
        r"procdump.*lsass",
        r"comsvcs.*MiniDump",
        r"rundll32.*comsvcs",
        r"task.*manager.*dump",
    ]
    
    def __init__(self):
        self.system = platform.system()
        self.events: List[CredentialAccessEvent] = []
        self.alerts: List[Dict] = []
        self.monitoring = False
        self._lock = threading.Lock()
        self._monitored_processes: Dict[int, Dict] = {}
        
        # Track LSASS PID on Windows
        self.lsass_pid = None
        if self.system == "Windows":
            self._find_lsass()
    
    def _find_lsass(self):
        """Find LSASS process on Windows"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == 'lsass.exe':
                    self.lsass_pid = proc.info['pid']
                    break
        except:
            pass
    
    def _expand_path(self, path: str) -> List[str]:
        """Expand path patterns to actual paths"""
        expanded = []
        
        # Replace ~ with home directory
        if path.startswith("~"):
            path = str(Path.home()) + path[1:]
        
        # Handle wildcards
        if "*" in path:
            try:
                from glob import glob
                expanded.extend(glob(path, recursive=True))
            except:
                pass
        else:
            if Path(path).exists():
                expanded.append(path)
        
        return expanded
    
    def _get_credential_paths(self) -> List[str]:
        """Get all credential paths for current OS"""
        paths = []
        
        if self.system == "Windows":
            base_paths = self.WINDOWS_CREDENTIAL_PATHS
        elif self.system == "Linux":
            base_paths = self.LINUX_CREDENTIAL_PATHS
        elif self.system == "Darwin":
            base_paths = self.MACOS_CREDENTIAL_PATHS
        else:
            return []
        
        for path in base_paths:
            paths.extend(self._expand_path(path))
        
        return list(set(paths))
    
    def check_credential_theft_tools(self) -> List[Dict]:
        """Check for running credential theft tools"""
        found_tools = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                name = proc.info['name'].lower()
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                
                # Check process name
                for tool in self.CREDENTIAL_THEFT_TOOLS:
                    if tool in name or tool in cmdline:
                        found_tools.append({
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "tool_matched": tool,
                            "cmdline": ' '.join(proc.info['cmdline'] or []),
                            "risk_score": 95,
                            "severity": "critical"
                        })
                        
                        # Create alert
                        with self._lock:
                            self.alerts.append({
                                "type": "credential_theft_tool",
                                "severity": "critical",
                                "message": f"Credential theft tool detected: {tool}",
                                "process": proc.info['name'],
                                "pid": proc.info['pid'],
                                "timestamp": datetime.now().isoformat()
                            })
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return found_tools
    
    def check_lsass_access(self) -> List[Dict]:
        """Check for suspicious LSASS access (Windows)"""
        suspicious_access = []
        
        if self.system != "Windows" or not self.lsass_pid:
            return []
        
        try:
            lsass = psutil.Process(self.lsass_pid)
            
            # Get processes accessing LSASS
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    # Skip system processes
                    if proc.info['name'].lower() in ['system', 'csrss.exe', 'smss.exe', 'wininit.exe']:
                        continue
                    
                    cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                    
                    # Check for LSASS access patterns
                    for pattern in self.LSASS_ACCESS_PATTERNS:
                        if re.search(pattern, cmdline, re.IGNORECASE):
                            suspicious_access.append({
                                "pid": proc.info['pid'],
                                "name": proc.info['name'],
                                "cmdline": cmdline,
                                "pattern_matched": pattern,
                                "risk_score": 90,
                                "severity": "critical"
                            })
                            
                            with self._lock:
                                self.alerts.append({
                                    "type": "lsass_access",
                                    "severity": "critical",
                                    "message": f"Suspicious LSASS access detected",
                                    "process": proc.info['name'],
                                    "pid": proc.info['pid'],
                                    "pattern": pattern,
                                    "timestamp": datetime.now().isoformat()
                                })
                            break
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return suspicious_access
    
    def check_credential_file_access(self) -> List[Dict]:
        """Check for recent access to credential files"""
        access_events = []
        cred_paths = self._get_credential_paths()
        
        # Check each credential file
        for path in cred_paths:
            try:
                stat = os.stat(path)
                mtime = datetime.fromtimestamp(stat.st_mtime)
                atime = datetime.fromtimestamp(stat.st_atime)
                
                # Check if accessed recently (last 10 minutes)
                if (datetime.now() - atime).total_seconds() < 600:
                    risk_score = 30
                    risk_factors = []
                    
                    # Higher risk for sensitive files
                    if any(x in path.lower() for x in ['shadow', 'sam', 'security', 'ntds', 'lsass']):
                        risk_score = 80
                        risk_factors.append("High-value credential store")
                    elif any(x in path.lower() for x in ['ssh', 'id_rsa', 'id_ed25519']):
                        risk_score = 60
                        risk_factors.append("SSH private key")
                    elif any(x in path.lower() for x in ['login data', 'logins.json', 'key4.db']):
                        risk_score = 50
                        risk_factors.append("Browser credential store")
                    elif any(x in path.lower() for x in ['credentials', 'vault', 'keychain']):
                        risk_score = 55
                        risk_factors.append("System credential store")
                    
                    access_events.append({
                        "path": path,
                        "last_accessed": atime.isoformat(),
                        "last_modified": mtime.isoformat(),
                        "risk_score": risk_score,
                        "risk_factors": risk_factors
                    })
                    
                    if risk_score >= 50:
                        with self._lock:
                            self.alerts.append({
                                "type": "credential_file_access",
                                "severity": "high" if risk_score >= 70 else "medium",
                                "message": f"Recent access to credential file: {path}",
                                "path": path,
                                "risk_score": risk_score,
                                "timestamp": datetime.now().isoformat()
                            })
            except (OSError, PermissionError):
                pass
        
        return access_events
    
    def check_browser_credential_databases(self) -> List[Dict]:
        """Check browser credential database integrity"""
        browser_checks = []
        
        browser_db_paths = {
            "Chrome": [
                "~/.config/google-chrome/*/Login Data",
                "~/Library/Application Support/Google/Chrome/*/Login Data",
                r"\AppData\Local\Google\Chrome\User Data\*\Login Data",
            ],
            "Firefox": [
                "~/.mozilla/firefox/*/logins.json",
                "~/Library/Application Support/Firefox/Profiles/*/logins.json",
                r"\AppData\Roaming\Mozilla\Firefox\Profiles\*\logins.json",
            ],
            "Edge": [
                r"\AppData\Local\Microsoft\Edge\User Data\*\Login Data",
            ]
        }
        
        for browser, paths in browser_db_paths.items():
            for path_pattern in paths:
                for path in self._expand_path(path_pattern):
                    try:
                        stat = os.stat(path)
                        atime = datetime.fromtimestamp(stat.st_atime)
                        
                        check = {
                            "browser": browser,
                            "path": path,
                            "size": stat.st_size,
                            "last_accessed": atime.isoformat(),
                            "recently_accessed": (datetime.now() - atime).total_seconds() < 600
                        }
                        
                        # Check if database is being accessed by non-browser process
                        if check["recently_accessed"]:
                            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                                try:
                                    open_files = proc.info.get('open_files') or []
                                    for f in open_files:
                                        if path in str(f):
                                            if browser.lower() not in proc.info['name'].lower():
                                                check["suspicious_process"] = {
                                                    "pid": proc.info['pid'],
                                                    "name": proc.info['name']
                                                }
                                                check["risk_score"] = 75
                                                
                                                with self._lock:
                                                    self.alerts.append({
                                                        "type": "browser_credential_theft",
                                                        "severity": "high",
                                                        "message": f"Non-browser process accessing {browser} credentials",
                                                        "process": proc.info['name'],
                                                        "pid": proc.info['pid'],
                                                        "path": path,
                                                        "timestamp": datetime.now().isoformat()
                                                    })
                                except:
                                    pass
                        
                        browser_checks.append(check)
                    except (OSError, PermissionError):
                        pass
        
        return browser_checks
    
    def scan(self) -> Dict:
        """Perform full credential theft scan"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "system": self.system,
            "credential_theft_tools": [],
            "lsass_access": [],
            "credential_file_access": [],
            "browser_credential_checks": [],
            "alerts": [],
            "risk_score": 0
        }
        
        # Check for credential theft tools
        results["credential_theft_tools"] = self.check_credential_theft_tools()
        
        # Check LSASS access (Windows)
        results["lsass_access"] = self.check_lsass_access()
        
        # Check credential file access
        results["credential_file_access"] = self.check_credential_file_access()
        
        # Check browser credential databases
        results["browser_credential_checks"] = self.check_browser_credential_databases()
        
        # Calculate overall risk
        max_risk = 0
        if results["credential_theft_tools"]:
            max_risk = max(max_risk, max(t.get("risk_score", 0) for t in results["credential_theft_tools"]))
        if results["lsass_access"]:
            max_risk = max(max_risk, max(a.get("risk_score", 0) for a in results["lsass_access"]))
        if results["credential_file_access"]:
            max_risk = max(max_risk, max(a.get("risk_score", 0) for a in results["credential_file_access"]))
        for check in results["browser_credential_checks"]:
            if "risk_score" in check:
                max_risk = max(max_risk, check["risk_score"])
        
        results["risk_score"] = max_risk
        
        with self._lock:
            results["alerts"] = list(self.alerts)
        
        return results
    
    def get_stats(self) -> Dict:
        """Get credential theft detection statistics"""
        with self._lock:
            return {
                "system": self.system,
                "lsass_pid": self.lsass_pid,
                "monitored_paths": len(self._get_credential_paths()),
                "known_theft_tools": len(self.CREDENTIAL_THEFT_TOOLS),
                "alerts_count": len(self.alerts),
                "recent_alerts": self.alerts[-5:] if self.alerts else []
            }
    
    def clear_alerts(self):
        """Clear all alerts"""
        with self._lock:
            self.alerts.clear()


# =============================================================================
# MEMORY FORENSICS (Volatility Integration)
# =============================================================================

@dataclass
class MemoryAnalysisResult:
    analysis_id: str
    dump_path: str
    profile: str
    timestamp: str
    processes: List[Dict] = field(default_factory=list)
    network_connections: List[Dict] = field(default_factory=list)
    injected_code: List[Dict] = field(default_factory=list)
    hidden_processes: List[Dict] = field(default_factory=list)
    suspicious_dlls: List[Dict] = field(default_factory=list)
    registry_keys: List[Dict] = field(default_factory=list)
    risk_score: int = 0
    findings: List[str] = field(default_factory=list)

class MemoryForensics:
    """
    Memory dump analysis using Volatility 3
    Detect rootkits, injected code, and hidden processes
    """
    
    def __init__(self):
        self.volatility_path = self._find_volatility()
        self.analyses: Dict[str, MemoryAnalysisResult] = {}
        self.alerts: List[Dict] = []
    
    def _find_volatility(self) -> Optional[str]:
        """Find Volatility 3 installation"""
        paths = ["vol", "vol3", "volatility3", "/root/.venv/bin/vol"]
        
        for path in paths:
            full_path = shutil.which(path)
            if full_path:
                try:
                    result = subprocess.run([full_path, "-h"], capture_output=True, timeout=10)
                    if result.returncode == 0:
                        return full_path
                except:
                    pass
        
        return None
    
    def _run_volatility(self, dump_path: str, plugin: str) -> Optional[str]:
        """Run a Volatility plugin"""
        if not self.volatility_path:
            return None
        
        try:
            cmd = [self.volatility_path, "-f", dump_path, plugin]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return result.stdout
            return None
        except Exception as e:
            print(f"Volatility error: {e}")
            return None
    
    def create_memory_dump(self, output_path: str) -> bool:
        """Create a memory dump of the current system"""
        system = platform.system()
        
        try:
            if system == "Linux":
                # Use /proc/kcore or dd on /dev/mem (requires root)
                if os.geteuid() != 0:
                    print("Memory dump requires root privileges")
                    return False
                
                # Try LiME if available
                lime = shutil.which("lime")
                if lime:
                    subprocess.run([lime, output_path, "lime"], timeout=300)
                    return Path(output_path).exists()
                
                # Fallback to /proc/kcore
                if Path("/proc/kcore").exists():
                    subprocess.run(["dd", "if=/proc/kcore", f"of={output_path}", "bs=1M", "count=100"], timeout=120)
                    return Path(output_path).exists()
            
            elif system == "Windows":
                # Use DumpIt or winpmem if available
                dumpit = shutil.which("DumpIt.exe")
                if dumpit:
                    subprocess.run([dumpit, "/O", output_path], timeout=300)
                    return Path(output_path).exists()
            
            elif system == "Darwin":
                # macOS requires specialized tools
                print("macOS memory dump requires specialized tools")
                return False
            
        except Exception as e:
            print(f"Memory dump error: {e}")
        
        return False
    
    def analyze_dump(self, dump_path: str) -> MemoryAnalysisResult:
        """Analyze a memory dump"""
        analysis_id = hashlib.md5(f"{dump_path}{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        result = MemoryAnalysisResult(
            analysis_id=analysis_id,
            dump_path=dump_path,
            profile="auto",
            timestamp=datetime.now().isoformat()
        )
        
        if not self.volatility_path:
            result.findings.append("Volatility 3 not found - install with: pip install volatility3")
            self.analyses[analysis_id] = result
            return result
        
        if not Path(dump_path).exists():
            result.findings.append(f"Dump file not found: {dump_path}")
            self.analyses[analysis_id] = result
            return result
        
        # Run various plugins
        plugins = [
            ("windows.pslist", "processes"),
            ("windows.netscan", "network_connections"),
            ("windows.malfind", "injected_code"),
            ("windows.psscan", "hidden_processes"),
            ("windows.dlllist", "suspicious_dlls"),
        ]
        
        risk_score = 0
        
        for plugin, attr in plugins:
            output = self._run_volatility(dump_path, plugin)
            if output:
                # Parse output (simplified)
                lines = output.strip().split('\n')
                parsed = []
                
                for line in lines[1:]:  # Skip header
                    parts = line.split()
                    if parts:
                        parsed.append({"raw": line, "fields": parts})
                
                setattr(result, attr, parsed)
                
                # Analyze for threats
                if plugin == "windows.malfind" and parsed:
                    risk_score += 30 * len(parsed)
                    result.findings.append(f"Found {len(parsed)} potential code injections")
                
                if plugin == "windows.psscan":
                    # Compare with pslist for hidden processes
                    ps_count = len(result.processes)
                    psscan_count = len(parsed)
                    if psscan_count > ps_count:
                        hidden = psscan_count - ps_count
                        risk_score += 40 * hidden
                        result.findings.append(f"Found {hidden} potentially hidden processes")
        
        result.risk_score = min(risk_score, 100)
        
        # Generate alerts
        if result.risk_score >= 40:
            self.alerts.append({
                "type": "memory_forensics",
                "severity": "critical" if result.risk_score >= 70 else "high",
                "analysis_id": analysis_id,
                "message": f"Memory analysis found threats (score: {result.risk_score})",
                "findings": result.findings,
                "timestamp": datetime.now().isoformat()
            })
        
        self.analyses[analysis_id] = result
        return result
    
    def quick_memory_scan(self) -> Dict:
        """Quick memory scan without full dump (uses live memory)"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "injected_processes": [],
            "suspicious_memory": [],
            "risk_score": 0
        }
        
        # Check for common injection indicators via psutil
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                # Check memory regions for suspicious patterns
                maps = proc.memory_maps()
                
                for mmap in maps:
                    # Executable anonymous memory is suspicious
                    path_str = str(mmap.path).lower() if hasattr(mmap, 'path') else ""
                    
                    # Check for anonymous executable regions
                    if 'anon' in path_str or '[heap]' in path_str or path_str == '':
                        # This could indicate injected code
                        if mmap.rss > 1024 * 1024:  # > 1MB anonymous region
                            results["suspicious_memory"].append({
                                "pid": proc.pid,
                                "name": proc.name(),
                                "region": path_str or "[anonymous]",
                                "size": mmap.rss
                            })
                            results["risk_score"] += 5
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                pass
        
        results["risk_score"] = min(results["risk_score"], 100)
        
        return results
    
    def get_stats(self) -> Dict:
        """Get memory forensics statistics"""
        return {
            "volatility_available": self.volatility_path is not None,
            "volatility_path": self.volatility_path or "Not found",
            "analyses_count": len(self.analyses),
            "alerts_count": len(self.alerts)
        }


# =============================================================================
# CLOUD SYNC CLIENT
# =============================================================================

class CloudSyncClient:
    """
    Sync agent data with cloud dashboard
    Report events, threats, and receive commands
    """
    
    def __init__(self, api_url: str = None):
        self.api_url = api_url or CONFIG.get("api_url", "")
        self.agent_id = CONFIG.get("agent_id", hashlib.md5(platform.node().encode()).hexdigest()[:16])
        self.agent_name = CONFIG.get("agent_name", platform.node())
        self.connected = False
        self.last_sync = None
        
        if requests:
            self.session = requests.Session()
            self.session.headers.update({
                "Content-Type": "application/json",
                "X-Agent-ID": self.agent_id,
                "X-Agent-Name": self.agent_name
            })
        else:
            self.session = None
    
    def _send_event(self, event_type: str, data: Dict) -> bool:
        """Send event to cloud API"""
        if not self.session or not self.api_url:
            return False
        
        try:
            payload = {
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "event_type": event_type,
                "data": data,
                "timestamp": datetime.now().isoformat()
            }
            
            response = self.session.post(
                f"{self.api_url}/agent/event",
                json=payload,
                timeout=30
            )
            
            self.connected = response.status_code == 200
            self.last_sync = datetime.now().isoformat()
            
            return response.status_code == 200
        except Exception as e:
            self.connected = False
            return False
    
    def send_heartbeat(self, system_info: Dict) -> bool:
        """Send heartbeat with system info"""
        return self._send_event("heartbeat", system_info)
    
    def send_process_alert(self, process_info: Dict) -> bool:
        """Report suspicious process"""
        return self._send_event("suspicious_process", process_info)
    
    def send_usb_event(self, device_info: Dict) -> bool:
        """Report USB device event"""
        return self._send_event("usb_device", device_info)
    
    def send_scheduled_task_alert(self, task_info: Dict) -> bool:
        """Report suspicious scheduled task"""
        return self._send_event("suspicious_task", task_info)
    
    def send_browser_extension_alert(self, extension_info: Dict) -> bool:
        """Report suspicious browser extension"""
        return self._send_event("suspicious_extension", extension_info)
    
    def send_memory_alert(self, memory_info: Dict) -> bool:
        """Report memory forensics findings"""
        return self._send_event("memory_forensics", memory_info)
    
    def send_file_alert(self, file_info: Dict) -> bool:
        """Report suspicious file"""
        return self._send_event("suspicious_file", file_info)
    
    def send_full_scan_report(self, report: Dict) -> bool:
        """Send full scan report"""
        return self._send_event("full_scan_report", report)
    
    def get_commands(self) -> List[Dict]:
        """Get pending commands from cloud"""
        if not self.session or not self.api_url:
            return []
        
        try:
            response = self.session.get(
                f"{self.api_url}/agent/{self.agent_id}/commands",
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json().get("commands", [])
        except:
            pass
        
        return []
    
    def get_status(self) -> Dict:
        """Get cloud sync status"""
        return {
            "api_url": self.api_url or "Not configured",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "connected": self.connected,
            "last_sync": self.last_sync
        }


# =============================================================================
# MAIN AGENT
# =============================================================================

class AdvancedSecurityAgent:
    """
    Main agent that coordinates all monitoring components
    """
    
    def __init__(self, api_url: str = None):
        self.process_monitor = ProcessMonitor()
        self.user_monitor = UserPrivilegeMonitor()
        self.browser_monitor = BrowserExtensionMonitor()
        self.folder_indexer = FolderIndexer()
        self.task_monitor = ScheduledTaskMonitor()
        self.usb_monitor = USBDeviceMonitor()
        self.memory_forensics = MemoryForensics()
        self.cloud_sync = CloudSyncClient(api_url)
        
        self.running = False
        self.threads: List[threading.Thread] = []
    
    def run_full_scan(self, sync_to_cloud: bool = True) -> Dict:
        """Run a complete security scan"""
        results = {
            "scan_time": datetime.now().isoformat(),
            "agent_id": self.cloud_sync.agent_id,
            "processes": {},
            "users": {},
            "browser_extensions": {},
            "files": {},
            "scheduled_tasks": {},
            "usb_devices": {},
            "memory": {},
            "alerts": []
        }
        
        print(f"\n{'='*60}")
        print(f"ANTI-AI DEFENSE - ADVANCED SECURITY SCAN v{VERSION}")
        print(f"{'='*60}\n")
        
        # Process scan
        print("[*] Scanning processes...")
        processes = self.process_monitor.get_all_processes()
        suspicious_procs = [p for p in processes if p.risk_score > 0]
        results["processes"] = {
            "total": len(processes),
            "suspicious": len(suspicious_procs),
            "top_threats": [asdict(p) for p in suspicious_procs[:10]]
        }
        print(f"    Found {len(processes)} processes, {len(suspicious_procs)} suspicious")
        
        # User scan
        print("[*] Scanning user privileges...")
        users = self.user_monitor.get_all_users()
        alias_risks = self.user_monitor.check_alias_risks()
        results["users"] = {
            "total": len(users),
            "privileged": len([u for u in users if u.is_admin or u.sudo_access]),
            "alias_risks": alias_risks
        }
        print(f"    Found {len(users)} users, {len(alias_risks)} alias risks")
        
        # Browser extension scan
        print("[*] Scanning browser extensions...")
        extensions = self.browser_monitor.scan_all_browsers()
        risky_exts = [e for e in extensions if e.risk_score >= 30]
        results["browser_extensions"] = {
            "total": len(extensions),
            "risky": len(risky_exts),
            "details": [asdict(e) for e in risky_exts]
        }
        print(f"    Found {len(extensions)} extensions, {len(risky_exts)} risky")
        
        # Folder scan
        print("[*] Scanning user directories...")
        files = self.folder_indexer.scan_user_directories()
        suspicious_files = self.folder_indexer.get_suspicious_files()
        results["files"] = {
            "total_indexed": len(files),
            "hidden": len(self.folder_indexer.hidden_files),
            "suspicious": len(suspicious_files),
            "details": [asdict(f) for f in suspicious_files[:20]]
        }
        print(f"    Indexed {len(files)} files, {len(suspicious_files)} suspicious")
        
        # Scheduled tasks scan
        print("[*] Scanning scheduled tasks/cron jobs...")
        tasks = self.task_monitor.get_all_tasks()
        suspicious_tasks = [t for t in tasks if t.risk_score >= 30]
        results["scheduled_tasks"] = {
            "total": len(tasks),
            "suspicious": len(suspicious_tasks),
            "details": [asdict(t) for t in suspicious_tasks[:10]]
        }
        print(f"    Found {len(tasks)} tasks, {len(suspicious_tasks)} suspicious")
        
        # USB devices scan
        print("[*] Scanning USB devices...")
        usb_devices = self.usb_monitor.get_all_devices()
        suspicious_usb = [d for d in usb_devices if d.risk_score >= 30]
        results["usb_devices"] = {
            "total": len(usb_devices),
            "suspicious": len(suspicious_usb),
            "storage_devices": len([d for d in usb_devices if d.is_storage]),
            "details": [asdict(d) for d in usb_devices]
        }
        print(f"    Found {len(usb_devices)} USB devices, {len(suspicious_usb)} suspicious")
        
        # Quick memory scan
        print("[*] Scanning memory for injections...")
        memory_results = self.memory_forensics.quick_memory_scan()
        results["memory"] = {
            "volatility_available": self.memory_forensics.volatility_path is not None,
            "suspicious_regions": len(memory_results.get("suspicious_memory", [])),
            "risk_score": memory_results.get("risk_score", 0),
            "details": memory_results
        }
        print(f"    Memory scan complete, risk score: {memory_results.get('risk_score', 0)}")
        
        # Collect all alerts
        results["alerts"] = (
            list(self.process_monitor.alerts) +
            self.user_monitor.alerts +
            self.browser_monitor.alerts +
            self.folder_indexer.alerts +
            self.task_monitor.alerts +
            self.usb_monitor.alerts +
            self.memory_forensics.alerts
        )
        
        # Save report
        report_path = REPORTS_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n{'='*60}")
        print(f"Scan complete! Report saved to: {report_path}")
        print(f"Total alerts: {len(results['alerts'])}")
        print(f"{'='*60}\n")
        
        # Sync to cloud if enabled
        if sync_to_cloud and self.cloud_sync.api_url:
            print("[*] Syncing results to cloud...")
            if self.cloud_sync.send_full_scan_report(results):
                print("    Sync successful!")
            else:
                print("    Sync failed - check API URL")
        
        return results
    
    def start_monitoring(self, sync_interval: int = 60):
        """Start continuous monitoring with cloud sync"""
        self.running = True
        
        def process_monitor_loop():
            while self.running:
                suspicious = self.process_monitor.get_suspicious_processes()
                # Send alerts to cloud
                for proc in suspicious:
                    if proc.risk_score >= 50:
                        self.cloud_sync.send_process_alert(asdict(proc))
                time.sleep(5)
        
        def usb_monitor_loop():
            last_devices = set()
            while self.running:
                devices = self.usb_monitor.get_all_devices()
                current_devices = {d.device_id for d in devices}
                
                # Check for new devices
                new_devices = current_devices - last_devices
                for dev_id in new_devices:
                    dev = self.usb_monitor.devices.get(dev_id)
                    if dev:
                        self.cloud_sync.send_usb_event(asdict(dev))
                
                last_devices = current_devices
                time.sleep(10)
        
        def heartbeat_loop():
            while self.running:
                system_info = {
                    "hostname": platform.node(),
                    "os": platform.system(),
                    "os_version": platform.version(),
                    "cpu_percent": psutil.cpu_percent(),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_percent": psutil.disk_usage('/').percent
                }
                self.cloud_sync.send_heartbeat(system_info)
                time.sleep(sync_interval)
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=process_monitor_loop, daemon=True),
            threading.Thread(target=usb_monitor_loop, daemon=True),
            threading.Thread(target=heartbeat_loop, daemon=True)
        ]
        
        for t in threads:
            t.start()
            self.threads.append(t)
        
        print("[*] Monitoring started (processes, USB, heartbeat)...")
    
    def stop_monitoring(self):
        """Stop all monitoring"""
        self.running = False
        for t in self.threads:
            t.join(timeout=5)
        print("[*] Monitoring stopped")
    
    def get_dashboard_data(self) -> Dict:
        """Get data for local dashboard"""
        return {
            "process_stats": self.process_monitor.get_stats(),
            "user_stats": self.user_monitor.get_stats(),
            "browser_stats": self.browser_monitor.get_stats(),
            "file_stats": self.folder_indexer.get_stats(),
            "task_stats": self.task_monitor.get_stats(),
            "usb_stats": self.usb_monitor.get_stats(),
            "memory_stats": self.memory_forensics.get_stats(),
            "cloud_status": self.cloud_sync.get_status(),
            "recent_alerts": list(self.process_monitor.alerts)[-20:]
        }


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Anti-AI Defense Advanced Security Agent v4.0")
    parser.add_argument("--full-scan", action="store_true", help="Run full security scan")
    parser.add_argument("--process-scan", action="store_true", help="Scan processes only")
    parser.add_argument("--browser-scan", action="store_true", help="Scan browser extensions")
    parser.add_argument("--folder-scan", type=str, help="Scan specific folder")
    parser.add_argument("--user-scan", action="store_true", help="Scan user privileges")
    parser.add_argument("--task-scan", action="store_true", help="Scan scheduled tasks/cron")
    parser.add_argument("--usb-scan", action="store_true", help="Scan USB devices")
    parser.add_argument("--memory-scan", action="store_true", help="Quick memory scan")
    parser.add_argument("--memory-dump", type=str, help="Analyze memory dump file")
    parser.add_argument("--monitor", action="store_true", help="Start continuous monitoring")
    parser.add_argument("--auto-kill", action="store_true", help="Auto-kill malicious processes")
    parser.add_argument("--api-url", type=str, help="Cloud API URL for sync")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    agent = AdvancedSecurityAgent(api_url=args.api_url)
    
    if args.full_scan:
        results = agent.run_full_scan(sync_to_cloud=bool(args.api_url))
        if args.json:
            print(json.dumps(results, indent=2, default=str))
    
    elif args.process_scan:
        processes = agent.process_monitor.get_all_processes()
        suspicious = [p for p in processes if p.risk_score > 0]
        
        if args.json:
            print(json.dumps([asdict(p) for p in suspicious], indent=2))
        else:
            print(f"\n{'='*60}")
            print("PROCESS SCAN RESULTS")
            print(f"{'='*60}")
            print(f"Total processes: {len(processes)}")
            print(f"Suspicious: {len(suspicious)}\n")
            
            for p in suspicious[:20]:
                risk_color = '\033[91m' if p.risk_score >= 60 else '\033[93m'
                print(f"{risk_color}[{p.risk_score}] {p.name} (PID: {p.pid})\033[0m")
                print(f"    User: {p.username} | CPU: {p.cpu_percent}% | Mem: {p.memory_mb}MB")
                for factor in p.risk_factors:
                    print(f"    - {factor}")
                print()
    
    elif args.browser_scan:
        extensions = agent.browser_monitor.scan_all_browsers()
        risky = [e for e in extensions if e.risk_score >= 30]
        
        if args.json:
            print(json.dumps([asdict(e) for e in risky], indent=2))
        else:
            print(f"\n{'='*60}")
            print("BROWSER EXTENSION SCAN")
            print(f"{'='*60}")
            print(f"Total extensions: {len(extensions)}")
            print(f"Risky extensions: {len(risky)}\n")
            
            for e in risky:
                print(f"[{e.risk_score}] {e.name} ({e.browser})")
                print(f"    ID: {e.id}")
                for factor in e.risk_factors:
                    print(f"    - {factor}")
                print()
    
    elif args.folder_scan:
        files = agent.folder_indexer.index_directory(args.folder_scan)
        suspicious = agent.folder_indexer.get_suspicious_files()
        
        if args.json:
            print(json.dumps([asdict(f) for f in suspicious], indent=2))
        else:
            print(f"\n{'='*60}")
            print(f"FOLDER SCAN: {args.folder_scan}")
            print(f"{'='*60}")
            print(f"Total files: {len(files)}")
            print(f"Hidden files: {len(agent.folder_indexer.hidden_files)}")
            print(f"Suspicious: {len(suspicious)}\n")
            
            for f in suspicious[:20]:
                print(f"[{f.risk_score}] {f.path}")
                for flag in f.flags:
                    print(f"    - {flag}")
                print()
    
    elif args.user_scan:
        users = agent.user_monitor.get_all_users()
        risks = agent.user_monitor.check_alias_risks()
        
        if args.json:
            print(json.dumps({
                "users": [asdict(u) for u in users],
                "alias_risks": risks
            }, indent=2))
        else:
            print(f"\n{'='*60}")
            print("USER PRIVILEGE SCAN")
            print(f"{'='*60}")
            print(f"Total users: {len(users)}\n")
            
            for u in users:
                admin_tag = "[ADMIN]" if u.is_admin else "[SUDO]" if u.sudo_access else ""
                print(f"{u.username} {admin_tag}")
                print(f"    UID: {u.uid} | Groups: {', '.join(u.groups[:5])}")
                if u.aliases:
                    print(f"    Aliases: {len(u.aliases)}")
                print()
            
            if risks:
                print("\nALIAS RISKS:")
                for r in risks:
                    print(f"    [{r['severity']}] {r['username']}: {r['alias']} -> {r['command'][:50]}")
    
    elif args.task_scan:
        tasks = agent.task_monitor.get_all_tasks()
        suspicious = [t for t in tasks if t.risk_score >= 30]
        
        if args.json:
            print(json.dumps([asdict(t) for t in tasks], indent=2))
        else:
            print(f"\n{'='*60}")
            print("SCHEDULED TASK/CRON SCAN")
            print(f"{'='*60}")
            print(f"Total tasks: {len(tasks)}")
            print(f"Suspicious: {len(suspicious)}\n")
            
            for t in suspicious[:20]:
                print(f"[{t.risk_score}] {t.name}")
                print(f"    Command: {t.command[:60]}...")
                print(f"    Schedule: {t.schedule} | User: {t.user}")
                for factor in t.risk_factors:
                    print(f"    - {factor}")
                print()
    
    elif args.usb_scan:
        devices = agent.usb_monitor.get_all_devices()
        
        if args.json:
            print(json.dumps([asdict(d) for d in devices], indent=2))
        else:
            print(f"\n{'='*60}")
            print("USB DEVICE SCAN")
            print(f"{'='*60}")
            print(f"Total devices: {len(devices)}\n")
            
            for d in devices:
                risk_indicator = f"[{d.risk_score}]" if d.risk_score > 0 else ""
                storage_tag = "[STORAGE]" if d.is_storage else ""
                print(f"{risk_indicator} {d.name} {storage_tag}")
                print(f"    ID: {d.device_id}")
                for factor in d.risk_factors:
                    print(f"    - {factor}")
                print()
    
    elif args.memory_scan:
        results = agent.memory_forensics.quick_memory_scan()
        
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(f"\n{'='*60}")
            print("QUICK MEMORY SCAN")
            print(f"{'='*60}")
            print(f"Volatility available: {agent.memory_forensics.volatility_path is not None}")
            print(f"Suspicious memory regions: {len(results.get('suspicious_memory', []))}")
            print(f"Risk score: {results.get('risk_score', 0)}\n")
            
            for mem in results.get('suspicious_memory', [])[:10]:
                print(f"    PID {mem['pid']}: {mem['name']} - {mem['region']}")
    
    elif args.memory_dump:
        result = agent.memory_forensics.analyze_dump(args.memory_dump)
        
        if args.json:
            print(json.dumps(asdict(result), indent=2))
        else:
            print(f"\n{'='*60}")
            print("MEMORY DUMP ANALYSIS")
            print(f"{'='*60}")
            print(f"Analysis ID: {result.analysis_id}")
            print(f"Dump: {result.dump_path}")
            print(f"Risk Score: {result.risk_score}\n")
            
            print("Findings:")
            for finding in result.findings:
                print(f"    - {finding}")
    
    elif args.monitor:
        agent.start_monitoring()
        try:
            while True:
                time.sleep(10)
                stats = agent.process_monitor.get_stats()
                usb_stats = agent.usb_monitor.get_stats()
                cloud_status = agent.cloud_sync.get_status()
                print(f"\r[Monitoring] Processes: {stats['total_processes']} | "
                      f"USB: {usb_stats['total_devices']} | "
                      f"Cloud: {'Connected' if cloud_status['connected'] else 'Offline'} | "
                      f"Alerts: {stats['alerts_count']}", end="")
        except KeyboardInterrupt:
            agent.stop_monitoring()
    
    elif args.auto_kill:
        killed = agent.process_monitor.auto_kill_threats()
        if args.json:
            print(json.dumps(killed, indent=2))
        else:
            print(f"Auto-killed {len(killed)} malicious processes")
            for k in killed:
                print(f"    - {k['name']} (PID: {k['pid']}, Score: {k['risk_score']})")
    
    else:
        # Default: run full scan
        agent.run_full_scan()


if __name__ == "__main__":
    main()
