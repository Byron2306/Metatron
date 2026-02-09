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
# MAIN AGENT
# =============================================================================

class AdvancedSecurityAgent:
    """
    Main agent that coordinates all monitoring components
    """
    
    def __init__(self):
        self.process_monitor = ProcessMonitor()
        self.user_monitor = UserPrivilegeMonitor()
        self.browser_monitor = BrowserExtensionMonitor()
        self.folder_indexer = FolderIndexer()
        
        self.running = False
        self.threads: List[threading.Thread] = []
    
    def run_full_scan(self) -> Dict:
        """Run a complete security scan"""
        results = {
            "scan_time": datetime.now().isoformat(),
            "processes": {},
            "users": {},
            "browser_extensions": {},
            "files": {},
            "alerts": []
        }
        
        print(f"\n{'='*60}")
        print("ANTI-AI DEFENSE - ADVANCED SECURITY SCAN v{VERSION}")
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
        
        # Collect all alerts
        results["alerts"] = (
            list(self.process_monitor.alerts) +
            self.user_monitor.alerts +
            self.browser_monitor.alerts +
            self.folder_indexer.alerts
        )
        
        # Save report
        report_path = REPORTS_DIR / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n{'='*60}")
        print(f"Scan complete! Report saved to: {report_path}")
        print(f"Total alerts: {len(results['alerts'])}")
        print(f"{'='*60}\n")
        
        return results
    
    def start_monitoring(self):
        """Start continuous monitoring"""
        self.running = True
        
        def process_monitor_loop():
            while self.running:
                self.process_monitor.get_suspicious_processes()
                time.sleep(5)
        
        t = threading.Thread(target=process_monitor_loop, daemon=True)
        t.start()
        self.threads.append(t)
        
        print("[*] Monitoring started...")
    
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
            "recent_alerts": list(self.process_monitor.alerts)[-20:]
        }


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Anti-AI Defense Advanced Security Agent")
    parser.add_argument("--full-scan", action="store_true", help="Run full security scan")
    parser.add_argument("--process-scan", action="store_true", help="Scan processes only")
    parser.add_argument("--browser-scan", action="store_true", help="Scan browser extensions")
    parser.add_argument("--folder-scan", type=str, help="Scan specific folder")
    parser.add_argument("--user-scan", action="store_true", help="Scan user privileges")
    parser.add_argument("--monitor", action="store_true", help="Start continuous monitoring")
    parser.add_argument("--auto-kill", action="store_true", help="Auto-kill malicious processes")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    agent = AdvancedSecurityAgent()
    
    if args.full_scan:
        results = agent.run_full_scan()
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
    
    elif args.monitor:
        agent.start_monitoring()
        try:
            while True:
                time.sleep(10)
                stats = agent.process_monitor.get_stats()
                print(f"\r[Monitoring] Processes: {stats['total_processes']} | "
                      f"Suspicious: {stats['by_risk_level'].get('suspicious', 0)} | "
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
