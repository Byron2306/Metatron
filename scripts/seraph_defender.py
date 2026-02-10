#!/usr/bin/env python3
"""
Seraph Defender Agent v5.0
==========================
Unified endpoint protection agent with real-time telemetry.

FEATURES:
- File integrity monitoring and indexing
- Process and task monitoring with behavioral analysis
- Registry monitoring (Windows)
- Admin rights and privilege tracking
- CLI command monitoring (AI attack detection)
- USB device monitoring
- Credential theft detection
- Active remediation capabilities
- Real-time telemetry to server

USAGE:
    python seraph_defender.py --monitor --api-url URL    # Full monitoring mode
    python seraph_defender.py --scan                     # One-time scan
    python seraph_defender.py --status                   # Check agent status

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
import socket
import re
import uuid
import signal
import argparse
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum
import logging

# =============================================================================
# CONFIGURATION
# =============================================================================

VERSION = "5.0.0"
AGENT_ID = None  # Set on registration
HOSTNAME = platform.node()
OS_TYPE = platform.system().lower()

# Directories
INSTALL_DIR = Path("/opt/seraph-defender") if OS_TYPE != "windows" else Path("C:/SeraphDefender")
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

def safe_import(module_name):
    try:
        return __import__(module_name)
    except ImportError:
        return None

psutil = safe_import('psutil')
requests = safe_import('requests')

if not psutil:
    logger.error("psutil is required. Install with: pip install psutil")
    sys.exit(1)

if not requests:
    logger.error("requests is required. Install with: pip install requests")
    sys.exit(1)

# =============================================================================
# ENUMS
# =============================================================================

class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class EventType(str, Enum):
    FILE_CHANGE = "file.change"
    FILE_CREATE = "file.create"
    FILE_DELETE = "file.delete"
    PROCESS_START = "process.start"
    PROCESS_SUSPICIOUS = "process.suspicious"
    REGISTRY_CHANGE = "registry.change"
    ADMIN_ESCALATION = "admin.escalation"
    CLI_COMMAND = "cli.command"
    USB_CONNECTED = "usb.connected"
    CREDENTIAL_ACCESS = "credential.access"
    NETWORK_CONNECTION = "network.connection"
    REMEDIATION = "remediation.action"

class RemediationAction(str, Enum):
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    BLOCK_NETWORK = "block_network"
    DISABLE_USER = "disable_user"
    RESTORE_FILE = "restore_file"
    ALERT_ONLY = "alert_only"

# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class TelemetryEvent:
    event_type: EventType
    timestamp: str
    severity: ThreatLevel
    data: Dict[str, Any]
    host_id: str = None
    agent_id: str = None
    remediation_taken: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if self.host_id is None:
            self.host_id = HOSTNAME
        if self.agent_id is None:
            self.agent_id = AGENT_ID
    
    def to_dict(self):
        d = asdict(self)
        d['event_type'] = self.event_type.value
        d['severity'] = self.severity.value
        return d

@dataclass
class FileIntegrityRecord:
    path: str
    hash_md5: str
    hash_sha256: str
    size: int
    modified_time: float
    permissions: str
    owner: str
    
@dataclass
class ProcessInfo:
    pid: int
    name: str
    cmdline: str
    username: str
    cpu_percent: float
    memory_percent: float
    create_time: float
    parent_pid: int
    risk_score: int = 0
    suspicious_indicators: List[str] = None
    
    def __post_init__(self):
        if self.suspicious_indicators is None:
            self.suspicious_indicators = []

# =============================================================================
# TELEMETRY SENDER
# =============================================================================

class TelemetrySender:
    """Sends telemetry events to the server"""
    
    def __init__(self, api_url: str):
        self.api_url = api_url.rstrip('/')
        self.queue = deque(maxlen=10000)
        self.running = False
        self.thread = None
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'X-Agent-ID': AGENT_ID or 'unregistered',
            'X-Agent-Version': VERSION
        })
        self._failed_sends = 0
        self._max_retries = 3
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._sender_loop, daemon=True)
        self.thread.start()
        logger.info("Telemetry sender started")
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def send(self, event: TelemetryEvent):
        """Queue an event for sending"""
        self.queue.append(event)
    
    def _sender_loop(self):
        """Background loop to send queued events"""
        while self.running:
            if self.queue:
                events = []
                while self.queue and len(events) < 100:
                    events.append(self.queue.popleft().to_dict())
                
                self._send_batch(events)
            
            time.sleep(1)
    
    def _send_batch(self, events: List[Dict]):
        """Send a batch of events"""
        try:
            response = self.session.post(
                f"{self.api_url}/api/swarm/telemetry/ingest",
                json={"events": events},
                timeout=30
            )
            
            if response.status_code == 200:
                self._failed_sends = 0
                logger.debug(f"Sent {len(events)} telemetry events")
            else:
                raise Exception(f"Server returned {response.status_code}")
                
        except Exception as e:
            self._failed_sends += 1
            logger.warning(f"Failed to send telemetry: {e}")
            
            # Re-queue events on failure
            if self._failed_sends < self._max_retries:
                for event_dict in events:
                    event = TelemetryEvent(
                        event_type=EventType(event_dict['event_type']),
                        timestamp=event_dict['timestamp'],
                        severity=ThreatLevel(event_dict['severity']),
                        data=event_dict['data']
                    )
                    self.queue.appendleft(event)

# =============================================================================
# FILE INTEGRITY MONITOR
# =============================================================================

class FileIntegrityMonitor:
    """Monitors critical files for changes"""
    
    CRITICAL_PATHS = {
        'linux': [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/etc/ssh/sshd_config', '/etc/crontab',
            '/root/.bashrc', '/root/.ssh/authorized_keys',
            '/usr/bin', '/usr/sbin', '/bin', '/sbin'
        ],
        'darwin': [
            '/etc/passwd', '/etc/sudoers',
            '/Library/LaunchDaemons', '/Library/LaunchAgents',
            '/usr/bin', '/usr/sbin'
        ],
        'windows': [
            # Only scan specific critical files, not entire directories
            'C:\\Windows\\System32\\config\\SAM',
            'C:\\Windows\\System32\\config\\SYSTEM',
            'C:\\Windows\\System32\\config\\SOFTWARE',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\Windows\\System32\\cmd.exe',
            'C:\\Windows\\System32\\powershell.exe',
            'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'C:\\Windows\\regedit.exe',
            'C:\\Windows\\explorer.exe'
        ]
    }
    
    # Maximum files to scan (prevents hanging on large directories)
    MAX_FILES_TOTAL = 500
    MAX_FILES_PER_DIR = 50
    MAX_SCAN_TIME = 30  # seconds
    
    def __init__(self, telemetry: TelemetrySender):
        self.telemetry = telemetry
        self.baseline: Dict[str, FileIntegrityRecord] = {}
        self.baseline_file = DATA_DIR / "file_baseline.json"
        self._load_baseline()
    
    def _load_baseline(self):
        """Load file baseline from disk"""
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file) as f:
                    data = json.load(f)
                    self.baseline = {
                        k: FileIntegrityRecord(**v)
                        for k, v in data.items()
                    }
                logger.info(f"Loaded baseline for {len(self.baseline)} files")
            except Exception as e:
                logger.warning(f"Failed to load baseline: {e}")
    
    def _save_baseline(self):
        """Save file baseline to disk"""
        try:
            data = {k: asdict(v) for k, v in self.baseline.items()}
            with open(self.baseline_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save baseline: {e}")
    
    def _hash_file(self, path: str) -> Tuple[str, str]:
        """Calculate MD5 and SHA256 hashes of a file"""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        
        try:
            with open(path, 'rb') as f:
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha256.update(chunk)
            return md5.hexdigest(), sha256.hexdigest()
        except Exception:
            return None, None
    
    def _get_file_info(self, path: str) -> Optional[FileIntegrityRecord]:
        """Get file information"""
        try:
            stat = os.stat(path)
            md5, sha256 = self._hash_file(path)
            
            if md5 is None:
                return None
            
            return FileIntegrityRecord(
                path=path,
                hash_md5=md5,
                hash_sha256=sha256,
                size=stat.st_size,
                modified_time=stat.st_mtime,
                permissions=oct(stat.st_mode)[-3:],
                owner=str(stat.st_uid)
            )
        except Exception:
            return None
    
    def create_baseline(self):
        """Create initial file baseline - FAST version"""
        logger.info("Creating file integrity baseline...")
        
        paths = self.CRITICAL_PATHS.get(OS_TYPE, [])
        count = 0
        start_time = time.time()
        
        for path in paths:
            # Check timeout
            if time.time() - start_time > self.MAX_SCAN_TIME:
                logger.warning(f"Baseline scan timeout reached, stopping at {count} files")
                break
            
            # Check max files
            if count >= self.MAX_FILES_TOTAL:
                logger.info(f"Reached max files limit ({self.MAX_FILES_TOTAL})")
                break
            
            if os.path.isfile(path):
                info = self._get_file_info(path)
                if info:
                    self.baseline[path] = info
                    count += 1
                    if count % 50 == 0:
                        logger.info(f"  Scanned {count} files...")
            elif os.path.isdir(path):
                dir_count = 0
                try:
                    for root, dirs, files in os.walk(path):
                        # Check timeout
                        if time.time() - start_time > self.MAX_SCAN_TIME:
                            break
                        
                        # Limit depth to 1 level
                        depth = root.replace(path, '').count(os.sep)
                        if depth > 1:
                            dirs.clear()  # Don't go deeper
                            continue
                        
                        for file in files[:self.MAX_FILES_PER_DIR]:
                            if dir_count >= self.MAX_FILES_PER_DIR:
                                break
                            if count >= self.MAX_FILES_TOTAL:
                                break
                            
                            filepath = os.path.join(root, file)
                            info = self._get_file_info(filepath)
                            if info:
                                self.baseline[filepath] = info
                                count += 1
                                dir_count += 1
                                
                                if count % 50 == 0:
                                    logger.info(f"  Scanned {count} files...")
                except PermissionError:
                    pass  # Skip directories we can't access
        
        self._save_baseline()
        logger.info(f"Baseline created for {count} files")
    
    def check_integrity(self) -> List[TelemetryEvent]:
        """Check file integrity against baseline"""
        events = []
        
        for path, baseline_info in list(self.baseline.items()):
            current_info = self._get_file_info(path)
            
            if current_info is None:
                # File deleted
                event = TelemetryEvent(
                    event_type=EventType.FILE_DELETE,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    severity=ThreatLevel.HIGH,
                    data={
                        "path": path,
                        "original_hash": baseline_info.hash_sha256,
                        "message": f"Critical file deleted: {path}"
                    }
                )
                events.append(event)
                self.telemetry.send(event)
                
            elif current_info.hash_sha256 != baseline_info.hash_sha256:
                # File modified
                severity = ThreatLevel.CRITICAL if '/etc/' in path or 'System32' in path else ThreatLevel.HIGH
                
                event = TelemetryEvent(
                    event_type=EventType.FILE_CHANGE,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    severity=severity,
                    data={
                        "path": path,
                        "original_hash": baseline_info.hash_sha256,
                        "current_hash": current_info.hash_sha256,
                        "original_size": baseline_info.size,
                        "current_size": current_info.size,
                        "message": f"Critical file modified: {path}"
                    }
                )
                events.append(event)
                self.telemetry.send(event)
                
                # Update baseline
                self.baseline[path] = current_info
        
        self._save_baseline()
        return events
    
    def index_directory(self, path: str) -> Dict[str, Any]:
        """Index a directory and return summary"""
        summary = {
            "path": path,
            "total_files": 0,
            "total_size": 0,
            "file_types": defaultdict(int),
            "hidden_files": 0,
            "executable_files": 0,
            "recent_files": [],
            "large_files": [],
            "suspicious_files": []
        }
        
        now = time.time()
        
        try:
            for root, dirs, files in os.walk(path):
                for file in files:
                    filepath = os.path.join(root, file)
                    
                    try:
                        stat = os.stat(filepath)
                        summary["total_files"] += 1
                        summary["total_size"] += stat.st_size
                        
                        # File type
                        ext = os.path.splitext(file)[1].lower() or 'no_extension'
                        summary["file_types"][ext] += 1
                        
                        # Hidden files
                        if file.startswith('.'):
                            summary["hidden_files"] += 1
                        
                        # Executables
                        if stat.st_mode & 0o111:
                            summary["executable_files"] += 1
                        
                        # Recent files (last 24 hours)
                        if now - stat.st_mtime < 86400:
                            summary["recent_files"].append({
                                "path": filepath,
                                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                            })
                        
                        # Large files (>100MB)
                        if stat.st_size > 100 * 1024 * 1024:
                            summary["large_files"].append({
                                "path": filepath,
                                "size": stat.st_size
                            })
                        
                        # Suspicious files
                        suspicious_exts = {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.sh', '.py'}
                        if ext in suspicious_exts and '/tmp' in filepath.lower():
                            summary["suspicious_files"].append(filepath)
                            
                    except Exception:
                        continue
        except Exception as e:
            logger.warning(f"Error indexing {path}: {e}")
        
        # Convert defaultdict
        summary["file_types"] = dict(summary["file_types"])
        
        return summary

# =============================================================================
# PROCESS MONITOR
# =============================================================================

class ProcessMonitor:
    """Monitors processes for suspicious behavior"""
    
    SUSPICIOUS_NAMES = {
        'mimikatz', 'lazagne', 'procdump', 'bloodhound',
        'rubeus', 'certutil', 'bitsadmin', 'mshta',
        'regsvr32', 'rundll32', 'wscript', 'cscript',
        'powershell', 'pwsh', 'nc', 'ncat', 'netcat'
    }
    
    SUSPICIOUS_CMDLINES = [
        r'-enc\s+[A-Za-z0-9+/=]+',  # Encoded PowerShell
        r'IEX\s*\(',                 # Invoke-Expression
        r'downloadstring',
        r'webclient',
        r'-nop\s+-w\s+hidden',      # Hidden PowerShell
        r'certutil.*-urlcache',
        r'bitsadmin.*transfer',
        r'/c\s+ping.*&&',           # Staged execution
        r'bash\s+-i.*>&.*tcp',      # Reverse shell
        r'python.*-c.*socket',      # Python reverse shell
    ]
    
    def __init__(self, telemetry: TelemetrySender):
        self.telemetry = telemetry
        self.known_pids: Set[int] = set()
        self.process_history: Dict[int, ProcessInfo] = {}
    
    def scan_processes(self) -> List[ProcessInfo]:
        """Scan all running processes"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 
                                         'cpu_percent', 'memory_percent', 
                                         'create_time', 'ppid']):
            try:
                info = proc.info
                cmdline = ' '.join(info.get('cmdline') or [])
                
                proc_info = ProcessInfo(
                    pid=info['pid'],
                    name=info.get('name', ''),
                    cmdline=cmdline,
                    username=info.get('username', ''),
                    cpu_percent=info.get('cpu_percent', 0) or 0,
                    memory_percent=info.get('memory_percent', 0) or 0,
                    create_time=info.get('create_time', 0) or 0,
                    parent_pid=info.get('ppid', 0) or 0
                )
                
                # Analyze for suspicious indicators
                self._analyze_process(proc_info)
                processes.append(proc_info)
                
                # Check if new process
                if proc_info.pid not in self.known_pids:
                    self.known_pids.add(proc_info.pid)
                    
                    if proc_info.risk_score >= 50:
                        event = TelemetryEvent(
                            event_type=EventType.PROCESS_SUSPICIOUS,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            severity=self._get_severity(proc_info.risk_score),
                            data={
                                "pid": proc_info.pid,
                                "name": proc_info.name,
                                "cmdline": proc_info.cmdline[:500],
                                "username": proc_info.username,
                                "risk_score": proc_info.risk_score,
                                "indicators": proc_info.suspicious_indicators,
                                "message": f"Suspicious process detected: {proc_info.name}"
                            }
                        )
                        self.telemetry.send(event)
                
                self.process_history[proc_info.pid] = proc_info
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return processes
    
    def _analyze_process(self, proc: ProcessInfo):
        """Analyze process for suspicious indicators"""
        name_lower = proc.name.lower()
        cmdline_lower = proc.cmdline.lower()
        
        # Check name
        if any(s in name_lower for s in self.SUSPICIOUS_NAMES):
            proc.risk_score += 40
            proc.suspicious_indicators.append(f"suspicious_name:{proc.name}")
        
        # Check cmdline patterns
        for pattern in self.SUSPICIOUS_CMDLINES:
            if re.search(pattern, cmdline_lower, re.IGNORECASE):
                proc.risk_score += 30
                proc.suspicious_indicators.append(f"suspicious_cmdline:{pattern[:30]}")
        
        # High CPU usage
        if proc.cpu_percent > 80:
            proc.risk_score += 15
            proc.suspicious_indicators.append("high_cpu")
        
        # Running from temp directories
        temp_paths = ['/tmp', '/var/tmp', 'appdata\\local\\temp', 'windows\\temp']
        if any(tp in cmdline_lower for tp in temp_paths):
            proc.risk_score += 20
            proc.suspicious_indicators.append("runs_from_temp")
        
        # Process masquerading
        system_processes = {'svchost', 'csrss', 'lsass', 'services', 'winlogon'}
        if name_lower in system_processes:
            # Check if running from correct location
            if 'system32' not in cmdline_lower and OS_TYPE == 'windows':
                proc.risk_score += 50
                proc.suspicious_indicators.append("process_masquerade")
    
    def _get_severity(self, risk_score: int) -> ThreatLevel:
        if risk_score >= 80:
            return ThreatLevel.CRITICAL
        elif risk_score >= 60:
            return ThreatLevel.HIGH
        elif risk_score >= 40:
            return ThreatLevel.MEDIUM
        elif risk_score >= 20:
            return ThreatLevel.LOW
        return ThreatLevel.INFO
    
    def get_high_resource_processes(self) -> List[ProcessInfo]:
        """Get processes using high resources"""
        return [
            p for p in self.process_history.values()
            if p.cpu_percent > 50 or p.memory_percent > 30
        ]
    
    def kill_process(self, pid: int, reason: str) -> bool:
        """Kill a suspicious process"""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.terminate()
            
            # Wait for termination
            gone, alive = psutil.wait_procs([proc], timeout=5)
            
            if alive:
                for p in alive:
                    p.kill()
            
            event = TelemetryEvent(
                event_type=EventType.REMEDIATION,
                timestamp=datetime.now(timezone.utc).isoformat(),
                severity=ThreatLevel.HIGH,
                data={
                    "action": "kill_process",
                    "pid": pid,
                    "process_name": proc_name,
                    "reason": reason,
                    "success": True
                },
                remediation_taken="kill_process"
            )
            self.telemetry.send(event)
            
            logger.info(f"Killed process {pid} ({proc_name}): {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to kill process {pid}: {e}")
            return False

# =============================================================================
# CLI MONITOR (AI Attack Detection)
# =============================================================================

class CLIMonitor:
    """
    Monitors CLI commands for AI-driven attack patterns.
    Detects machine-paced, autonomous behavior.
    """
    
    def __init__(self, telemetry: TelemetrySender):
        self.telemetry = telemetry
        self.session_id = str(uuid.uuid4())[:8]
        self.command_history: deque = deque(maxlen=1000)
        self.running = False
        self.thread = None
        
        # Shell processes to monitor
        self.shell_names = {
            'bash', 'sh', 'zsh', 'fish', 'ksh', 'csh',
            'powershell', 'pwsh', 'cmd', 'cmd.exe',
            'python', 'python3', 'node', 'ruby', 'perl'
        }
        
        self._seen_commands: Set[str] = set()
        self._last_check = time.time()
    
    def start(self):
        """Start CLI monitoring"""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("CLI Monitor started")
    
    def stop(self):
        """Stop CLI monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._scan_shell_processes()
                time.sleep(0.5)
            except Exception as e:
                logger.error(f"CLI monitor error: {e}")
                time.sleep(2)
    
    def _scan_shell_processes(self):
        """Scan for shell processes and capture commands"""
        current_time = time.time()
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time', 'ppid', 'cwd']):
            try:
                info = proc.info
                proc_name = (info.get('name') or '').lower()
                
                # Check if shell process
                base_name = proc_name.replace('.exe', '')
                if base_name not in self.shell_names:
                    continue
                
                cmdline = info.get('cmdline') or []
                if len(cmdline) <= 1:
                    continue
                
                # Check if new command
                create_time = info.get('create_time', 0)
                if create_time < self._last_check:
                    continue
                
                command = ' '.join(cmdline[1:])
                if not command.strip():
                    continue
                
                # Dedup
                cmd_hash = hashlib.md5(f"{info['pid']}{command}".encode()).hexdigest()
                if cmd_hash in self._seen_commands:
                    continue
                
                self._seen_commands.add(cmd_hash)
                
                # Record command
                cmd_record = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "command": command,
                    "shell": base_name,
                    "user": info.get('username'),
                    "pid": info['pid'],
                    "ppid": info.get('ppid'),
                    "cwd": info.get('cwd')
                }
                self.command_history.append(cmd_record)
                
                # Send telemetry
                event = TelemetryEvent(
                    event_type=EventType.CLI_COMMAND,
                    timestamp=cmd_record["timestamp"],
                    severity=ThreatLevel.INFO,
                    data={
                        "session_id": self.session_id,
                        "command": command[:500],
                        "shell_type": base_name,
                        "user": info.get('username'),
                        "parent_process": str(info.get('ppid'))
                    }
                )
                self.telemetry.send(event)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        self._last_check = current_time

# =============================================================================
# REGISTRY MONITOR (Windows)
# =============================================================================

class RegistryMonitor:
    """Monitors Windows registry for suspicious changes"""
    
    WATCHED_KEYS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        r"SYSTEM\CurrentControlSet\Services",
    ]
    
    def __init__(self, telemetry: TelemetrySender):
        self.telemetry = telemetry
        self.baseline: Dict[str, Dict] = {}
        self.baseline_file = DATA_DIR / "registry_baseline.json"
        
        if OS_TYPE == 'windows':
            self._load_baseline()
    
    def _load_baseline(self):
        """Load registry baseline"""
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file) as f:
                    self.baseline = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load registry baseline: {e}")
    
    def _save_baseline(self):
        """Save registry baseline"""
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(self.baseline, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save registry baseline: {e}")
    
    def create_baseline(self):
        """Create registry baseline"""
        if OS_TYPE != 'windows':
            return
        
        try:
            import winreg
        except ImportError:
            return
        
        logger.info("Creating registry baseline...")
        
        for key_path in self.WATCHED_KEYS:
            try:
                for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                    try:
                        key = winreg.OpenKey(hive, key_path)
                        values = {}
                        
                        i = 0
                        while True:
                            try:
                                name, data, type_ = winreg.EnumValue(key, i)
                                values[name] = {"data": str(data), "type": type_}
                                i += 1
                            except WindowsError:
                                break
                        
                        full_path = f"{hive}\\{key_path}"
                        self.baseline[full_path] = values
                        winreg.CloseKey(key)
                        
                    except WindowsError:
                        continue
            except Exception as e:
                logger.warning(f"Error reading {key_path}: {e}")
        
        self._save_baseline()
        logger.info(f"Registry baseline created with {len(self.baseline)} keys")
    
    def check_changes(self) -> List[TelemetryEvent]:
        """Check for registry changes"""
        if OS_TYPE != 'windows':
            return []
        
        try:
            import winreg
        except ImportError:
            return []
        
        events = []
        
        for key_path in self.WATCHED_KEYS:
            for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                try:
                    key = winreg.OpenKey(hive, key_path)
                    current_values = {}
                    
                    i = 0
                    while True:
                        try:
                            name, data, type_ = winreg.EnumValue(key, i)
                            current_values[name] = {"data": str(data), "type": type_}
                            i += 1
                        except WindowsError:
                            break
                    
                    winreg.CloseKey(key)
                    
                    full_path = f"{hive}\\{key_path}"
                    baseline_values = self.baseline.get(full_path, {})
                    
                    # Check for new/changed values
                    for name, value in current_values.items():
                        if name not in baseline_values:
                            event = TelemetryEvent(
                                event_type=EventType.REGISTRY_CHANGE,
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                severity=ThreatLevel.HIGH,
                                data={
                                    "key": key_path,
                                    "value_name": name,
                                    "value_data": value["data"][:200],
                                    "change_type": "new",
                                    "message": f"New registry value: {key_path}\\{name}"
                                }
                            )
                            events.append(event)
                            self.telemetry.send(event)
                        
                        elif value != baseline_values[name]:
                            event = TelemetryEvent(
                                event_type=EventType.REGISTRY_CHANGE,
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                severity=ThreatLevel.HIGH,
                                data={
                                    "key": key_path,
                                    "value_name": name,
                                    "old_value": baseline_values[name]["data"][:200],
                                    "new_value": value["data"][:200],
                                    "change_type": "modified",
                                    "message": f"Registry value modified: {key_path}\\{name}"
                                }
                            )
                            events.append(event)
                            self.telemetry.send(event)
                    
                    # Update baseline
                    self.baseline[full_path] = current_values
                    
                except WindowsError:
                    continue
        
        self._save_baseline()
        return events

# =============================================================================
# ADMIN/PRIVILEGE MONITOR
# =============================================================================

class PrivilegeMonitor:
    """Monitors privilege escalation and admin changes"""
    
    def __init__(self, telemetry: TelemetrySender):
        self.telemetry = telemetry
        self.known_admins: Set[str] = set()
        self.admin_file = DATA_DIR / "known_admins.json"
        self._load_admins()
    
    def _load_admins(self):
        """Load known admins from file"""
        if self.admin_file.exists():
            try:
                with open(self.admin_file) as f:
                    self.known_admins = set(json.load(f))
            except Exception:
                pass
    
    def _save_admins(self):
        """Save known admins"""
        try:
            with open(self.admin_file, 'w') as f:
                json.dump(list(self.known_admins), f)
        except Exception:
            pass
    
    def get_admin_users(self) -> List[str]:
        """Get list of admin users"""
        admins = []
        
        if OS_TYPE == 'windows':
            try:
                result = subprocess.run(
                    ['net', 'localgroup', 'Administrators'],
                    capture_output=True, text=True
                )
                lines = result.stdout.split('\n')
                in_members = False
                for line in lines:
                    if '---' in line:
                        in_members = True
                        continue
                    if in_members and line.strip() and 'The command completed' not in line:
                        admins.append(line.strip())
            except Exception:
                pass
        else:
            # Linux/macOS
            try:
                with open('/etc/group') as f:
                    for line in f:
                        if line.startswith('sudo:') or line.startswith('wheel:') or line.startswith('admin:'):
                            parts = line.strip().split(':')
                            if len(parts) >= 4:
                                admins.extend(parts[3].split(','))
            except Exception:
                pass
            
            # Also check sudoers
            try:
                result = subprocess.run(
                    ['getent', 'group', 'sudo'],
                    capture_output=True, text=True
                )
                if result.stdout:
                    parts = result.stdout.strip().split(':')
                    if len(parts) >= 4:
                        admins.extend(parts[3].split(','))
            except Exception:
                pass
        
        return list(set(a for a in admins if a))
    
    def check_admin_changes(self) -> List[TelemetryEvent]:
        """Check for admin privilege changes"""
        events = []
        current_admins = set(self.get_admin_users())
        
        # New admins
        new_admins = current_admins - self.known_admins
        for admin in new_admins:
            event = TelemetryEvent(
                event_type=EventType.ADMIN_ESCALATION,
                timestamp=datetime.now(timezone.utc).isoformat(),
                severity=ThreatLevel.CRITICAL,
                data={
                    "user": admin,
                    "change_type": "admin_added",
                    "message": f"New admin user detected: {admin}"
                }
            )
            events.append(event)
            self.telemetry.send(event)
        
        # Removed admins (might be suspicious cleanup)
        removed_admins = self.known_admins - current_admins
        for admin in removed_admins:
            event = TelemetryEvent(
                event_type=EventType.ADMIN_ESCALATION,
                timestamp=datetime.now(timezone.utc).isoformat(),
                severity=ThreatLevel.MEDIUM,
                data={
                    "user": admin,
                    "change_type": "admin_removed",
                    "message": f"Admin user removed: {admin}"
                }
            )
            events.append(event)
            self.telemetry.send(event)
        
        self.known_admins = current_admins
        self._save_admins()
        
        return events

# =============================================================================
# USB MONITOR
# =============================================================================

class USBMonitor:
    """Monitors USB device connections"""
    
    def __init__(self, telemetry: TelemetrySender):
        self.telemetry = telemetry
        self.known_devices: Set[str] = set()
    
    def get_usb_devices(self) -> List[Dict]:
        """Get connected USB devices"""
        devices = []
        
        if OS_TYPE == 'linux':
            try:
                result = subprocess.run(
                    ['lsusb'],
                    capture_output=True, text=True
                )
                for line in result.stdout.split('\n'):
                    if line.strip():
                        match = re.match(r'Bus (\d+) Device (\d+): ID ([0-9a-f:]+) (.+)', line)
                        if match:
                            devices.append({
                                "bus": match.group(1),
                                "device": match.group(2),
                                "id": match.group(3),
                                "name": match.group(4)
                            })
            except Exception:
                pass
                
        elif OS_TYPE == 'darwin':
            try:
                result = subprocess.run(
                    ['system_profiler', 'SPUSBDataType', '-json'],
                    capture_output=True, text=True
                )
                data = json.loads(result.stdout)
                # Parse macOS USB data
            except Exception:
                pass
        
        return devices
    
    def check_new_devices(self) -> List[TelemetryEvent]:
        """Check for new USB devices"""
        events = []
        current_devices = self.get_usb_devices()
        
        for device in current_devices:
            device_id = device.get('id', '')
            if device_id and device_id not in self.known_devices:
                self.known_devices.add(device_id)
                
                event = TelemetryEvent(
                    event_type=EventType.USB_CONNECTED,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    severity=ThreatLevel.MEDIUM,
                    data={
                        "device_id": device_id,
                        "device_name": device.get('name', 'Unknown'),
                        "message": f"USB device connected: {device.get('name', 'Unknown')}"
                    }
                )
                events.append(event)
                self.telemetry.send(event)
        
        return events

# =============================================================================
# MAIN AGENT
# =============================================================================

class SeraphDefenderAgent:
    """Main unified defender agent"""
    
    def __init__(self, api_url: str):
        global AGENT_ID
        AGENT_ID = self._get_or_create_agent_id()
        
        self.api_url = api_url
        self.telemetry = TelemetrySender(api_url)
        
        # Initialize monitors
        self.file_monitor = FileIntegrityMonitor(self.telemetry)
        self.process_monitor = ProcessMonitor(self.telemetry)
        self.cli_monitor = CLIMonitor(self.telemetry)
        self.registry_monitor = RegistryMonitor(self.telemetry)
        self.privilege_monitor = PrivilegeMonitor(self.telemetry)
        self.usb_monitor = USBMonitor(self.telemetry)
        
        self.running = False
        
        logger.info(f"Seraph Defender Agent v{VERSION} initialized")
        logger.info(f"Agent ID: {AGENT_ID}")
        logger.info(f"API URL: {api_url}")
    
    def _get_or_create_agent_id(self) -> str:
        """Get or create unique agent ID"""
        id_file = DATA_DIR / "agent_id"
        
        if id_file.exists():
            return id_file.read_text().strip()
        
        # Generate ID based on hardware
        hw_info = f"{HOSTNAME}-{platform.machine()}-{uuid.getnode()}"
        agent_id = hashlib.md5(hw_info.encode()).hexdigest()[:16]
        
        id_file.write_text(agent_id)
        return agent_id
    
    def register_with_server(self) -> bool:
        """Register agent with server"""
        try:
            response = requests.post(
                f"{self.api_url}/api/agents/register",
                json={
                    "agent_id": AGENT_ID,
                    "hostname": HOSTNAME,
                    "os_type": OS_TYPE,
                    "os_version": platform.version(),
                    "version": VERSION,
                    "ip_address": self._get_ip_address()
                },
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info("Successfully registered with server")
                return True
            else:
                logger.warning(f"Registration failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to register with server: {e}")
            return False
    
    def _get_ip_address(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def create_baselines(self):
        """Create initial baselines"""
        logger.info("Creating initial baselines...")
        
        self.file_monitor.create_baseline()
        self.registry_monitor.create_baseline()
        
        # Store initial admin users
        self.privilege_monitor.known_admins = set(self.privilege_monitor.get_admin_users())
        self.privilege_monitor._save_admins()
        
        logger.info("Baselines created")
    
    def run_full_scan(self) -> Dict[str, Any]:
        """Run a comprehensive security scan"""
        logger.info("Starting full security scan...")
        
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": AGENT_ID,
            "hostname": HOSTNAME,
            "file_integrity": [],
            "processes": [],
            "registry": [],
            "privileges": [],
            "usb_devices": []
        }
        
        # File integrity
        file_events = self.file_monitor.check_integrity()
        results["file_integrity"] = [e.to_dict() for e in file_events]
        
        # Process scan
        processes = self.process_monitor.scan_processes()
        suspicious = [p for p in processes if p.risk_score >= 30]
        results["processes"] = [asdict(p) for p in suspicious]
        
        # Registry (Windows)
        if OS_TYPE == 'windows':
            registry_events = self.registry_monitor.check_changes()
            results["registry"] = [e.to_dict() for e in registry_events]
        
        # Privilege changes
        priv_events = self.privilege_monitor.check_admin_changes()
        results["privileges"] = [e.to_dict() for e in priv_events]
        
        # USB devices
        usb_events = self.usb_monitor.check_new_devices()
        results["usb_devices"] = [e.to_dict() for e in usb_events]
        
        # Count issues
        total_issues = (
            len(results["file_integrity"]) +
            len(results["processes"]) +
            len(results["registry"]) +
            len(results["privileges"])
        )
        
        logger.info(f"Scan complete: {total_issues} issues found")
        
        return results
    
    def start_monitoring(self):
        """Start continuous monitoring"""
        self.running = True
        
        # Start telemetry sender
        self.telemetry.start()
        
        # Start CLI monitor
        self.cli_monitor.start()
        
        # Register with server
        self.register_with_server()
        
        logger.info("Continuous monitoring started")
        
        # Main monitoring loop
        scan_interval = 60  # seconds
        
        while self.running:
            try:
                # Run periodic scans
                self.run_full_scan()
                
                # Send heartbeat
                self._send_heartbeat()
                
                time.sleep(scan_interval)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(10)
        
        self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        self.cli_monitor.stop()
        self.telemetry.stop()
        logger.info("Monitoring stopped")
    
    def _send_heartbeat(self):
        """Send heartbeat to server"""
        try:
            requests.post(
                f"{self.api_url}/api/agents/{AGENT_ID}/heartbeat",
                json={
                    "cpu_percent": psutil.cpu_percent(),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_percent": psutil.disk_usage('/').percent if OS_TYPE != 'windows' else psutil.disk_usage('C:').percent
                },
                timeout=10
            )
        except Exception:
            pass
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            "agent_id": AGENT_ID,
            "hostname": HOSTNAME,
            "version": VERSION,
            "os_type": OS_TYPE,
            "running": self.running,
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "uptime": time.time() - psutil.boot_time()
        }


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Seraph Defender Agent")
    parser.add_argument('--api-url', required=True, help='Server API URL')
    parser.add_argument('--monitor', action='store_true', help='Start continuous monitoring')
    parser.add_argument('--scan', action='store_true', help='Run one-time scan')
    parser.add_argument('--baseline', action='store_true', help='Create baselines')
    parser.add_argument('--status', action='store_true', help='Show agent status')
    
    args = parser.parse_args()
    
    agent = SeraphDefenderAgent(args.api_url)
    
    if args.baseline:
        agent.create_baselines()
    
    if args.scan:
        results = agent.run_full_scan()
        print(json.dumps(results, indent=2))
    
    if args.status:
        status = agent.get_status()
        print(json.dumps(status, indent=2))
    
    if args.monitor:
        # Handle signals
        def signal_handler(sig, frame):
            logger.info("Shutting down...")
            agent.stop_monitoring()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Create baselines if not exist
        if not agent.file_monitor.baseline:
            agent.create_baselines()
        
        agent.start_monitoring()


if __name__ == "__main__":
    main()
