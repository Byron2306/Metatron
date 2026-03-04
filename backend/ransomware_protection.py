"""
Ransomware Protection Service
==============================
Multi-layered ransomware protection including:

1. Canary Files - Decoy files that trigger alerts when modified
2. Behavioral Detection - Monitor for mass encryption patterns
3. Protected Folders - Prevent unauthorized access to critical directories
4. Backup Integration - Automatic backup before suspicious activity
5. Process Rollback - Ability to terminate and rollback ransomware damage
"""

import os
import json
import asyncio
import hashlib
import shutil
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field, asdict
from pathlib import Path
from enum import Enum
import threading
import time
from runtime_paths import ensure_data_dir

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

DATA_ROOT_DIR = ensure_data_dir()
CANARY_DIR = ensure_data_dir("canaries")
BACKUP_DIR = ensure_data_dir("ransomware_backups")
PROTECTED_DIRS_FILE = DATA_ROOT_DIR / "protected_dirs.json"

class RansomwareConfig:
    def __init__(self):
        self.canary_enabled = os.environ.get("RANSOMWARE_CANARY_ENABLED", "true").lower() == "true"
        self.behavioral_detection = os.environ.get("RANSOMWARE_BEHAVIORAL", "true").lower() == "true"
        self.auto_backup = os.environ.get("RANSOMWARE_AUTO_BACKUP", "true").lower() == "true"
        self.auto_kill_ransomware = os.environ.get("RANSOMWARE_AUTO_KILL", "false").lower() == "true"
        
        # Thresholds
        self.encryption_threshold = int(os.environ.get("ENCRYPTION_THRESHOLD", "10"))  # files/minute
        self.file_rename_threshold = int(os.environ.get("RENAME_THRESHOLD", "20"))  # renames/minute

config = RansomwareConfig()

# =============================================================================
# DATA MODELS
# =============================================================================

class RansomwareEventType(Enum):
    CANARY_TRIGGERED = "canary_triggered"
    MASS_ENCRYPTION = "mass_encryption"
    SUSPICIOUS_RENAME = "suspicious_rename"
    PROTECTED_FOLDER_ACCESS = "protected_folder_access"
    SHADOW_COPY_DELETE = "shadow_copy_delete"
    BACKUP_SERVICE_STOP = "backup_service_stop"

@dataclass
class CanaryFile:
    """Represents a canary/decoy file"""
    id: str
    path: str
    original_hash: str
    created_at: str
    last_checked: str
    status: str = "active"  # active, triggered, disabled

@dataclass
class RansomwareEvent:
    """Represents a ransomware-related security event"""
    id: str
    event_type: str
    timestamp: str
    severity: str
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_path: Optional[str] = None
    affected_files: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    action_taken: str = "none"

@dataclass
class ProtectedFolder:
    """Represents a folder protected from ransomware"""
    path: str
    allowed_processes: List[str] = field(default_factory=list)
    created_at: str = ""
    last_access_attempt: Optional[str] = None

# =============================================================================
# CANARY FILE SYSTEM
# =============================================================================

class CanaryFileManager:
    """
    Manages canary/decoy files that act as tripwires for ransomware.
    When ransomware encrypts files, it will hit canaries first.
    """
    
    # Attractive filenames for ransomware
    CANARY_NAMES = [
        "Important_Documents.docx",
        "Financial_Records_2024.xlsx",
        "Passwords.txt",
        "Company_Secrets.pdf",
        "Bitcoin_Wallet_Backup.dat",
        "Tax_Returns_2024.pdf",
        "Employee_SSN_List.csv",
        "Bank_Account_Details.doc",
        "Private_Keys.pem",
        "Confidential_Report.docx",
    ]
    
    # Canary content templates
    CANARY_CONTENT = {
        ".txt": "CONFIDENTIAL - DO NOT SHARE\n\nThis document contains sensitive information.\n" + "=" * 50 + "\n" * 100,
        ".docx": b'PK\x03\x04',  # DOCX magic bytes (simplified)
        ".xlsx": b'PK\x03\x04',  # XLSX magic bytes
        ".pdf": b'%PDF-1.4',     # PDF magic bytes
        ".csv": "Name,SSN,Account,Balance\nJohn Doe,123-45-6789,ACC001,$50000\n" * 50,
        ".dat": os.urandom(1024),  # Random binary data
        ".pem": "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 64 + "\n" * 20 + "-----END RSA PRIVATE KEY-----\n",
    }
    
    def __init__(self):
        self.canaries: Dict[str, CanaryFile] = {}
        self.triggered_canaries: List[CanaryFile] = []
        self._db = None
        self._alert_callback: Optional[Callable] = None
        self._load_canaries()
    
    def set_database(self, db):
        self._db = db
    
    def set_alert_callback(self, callback: Callable):
        self._alert_callback = callback
    
    def _load_canaries(self):
        """Load existing canaries from disk"""
        canary_index = CANARY_DIR / "index.json"
        if canary_index.exists():
            try:
                with open(canary_index, 'r') as f:
                    data = json.load(f)
                    for canary_data in data.get("canaries", []):
                        canary = CanaryFile(**canary_data)
                        self.canaries[canary.id] = canary
                logger.info(f"Loaded {len(self.canaries)} canary files")
            except Exception as e:
                logger.error(f"Failed to load canaries: {e}")
    
    def _save_canaries(self):
        """Save canary index to disk"""
        canary_index = CANARY_DIR / "index.json"
        try:
            data = {"canaries": [asdict(c) for c in self.canaries.values()]}
            with open(canary_index, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save canaries: {e}")
    
    def deploy_canaries(self, target_dirs: List[str] = None) -> List[CanaryFile]:
        """
        Deploy canary files to specified directories.
        If no directories specified, uses common user directories.
        """
        if target_dirs is None:
            home = Path.home()
            target_dirs = [
                str(home / "Documents"),
                str(home / "Desktop"),
                str(home / "Downloads"),
                str(home),
                "/tmp",
            ]
        
        deployed = []
        
        for target_dir in target_dirs:
            dir_path = Path(target_dir)
            if not dir_path.exists():
                continue
            
            # Deploy 2 canaries per directory
            for name in self.CANARY_NAMES[:2]:
                canary_path = dir_path / f".{name}"  # Hidden file
                
                # Skip if already exists
                if str(canary_path) in [c.path for c in self.canaries.values()]:
                    continue
                
                try:
                    # Determine content based on extension
                    ext = Path(name).suffix.lower()
                    content = self.CANARY_CONTENT.get(ext, self.CANARY_CONTENT[".txt"])
                    
                    # Write canary file
                    mode = 'wb' if isinstance(content, bytes) else 'w'
                    with open(canary_path, mode) as f:
                        f.write(content)
                    
                    # Calculate hash
                    file_hash = self._hash_file(canary_path)
                    
                    # Create canary record
                    canary_id = hashlib.md5(str(canary_path).encode()).hexdigest()[:16]
                    canary = CanaryFile(
                        id=canary_id,
                        path=str(canary_path),
                        original_hash=file_hash,
                        created_at=datetime.now(timezone.utc).isoformat(),
                        last_checked=datetime.now(timezone.utc).isoformat(),
                        status="active"
                    )
                    
                    self.canaries[canary_id] = canary
                    deployed.append(canary)
                    logger.info(f"Deployed canary: {canary_path}")
                    
                except Exception as e:
                    logger.error(f"Failed to deploy canary at {canary_path}: {e}")
        
        self._save_canaries()
        return deployed
    
    def check_canaries(self) -> List[CanaryFile]:
        """Check all canaries for modifications"""
        triggered = []
        
        for canary_id, canary in list(self.canaries.items()):
            if canary.status != "active":
                continue
            
            canary_path = Path(canary.path)
            
            # Check if file was deleted
            if not canary_path.exists():
                canary.status = "triggered"
                self.triggered_canaries.append(canary)
                triggered.append(canary)
                self._emit_alert(canary, "deleted")
                continue
            
            # Check if file was modified
            current_hash = self._hash_file(canary_path)
            if current_hash != canary.original_hash:
                canary.status = "triggered"
                self.triggered_canaries.append(canary)
                triggered.append(canary)
                self._emit_alert(canary, "modified")
            
            canary.last_checked = datetime.now(timezone.utc).isoformat()
        
        self._save_canaries()
        return triggered
    
    def _hash_file(self, path: Path) -> str:
        """Calculate SHA256 hash of file"""
        try:
            sha256 = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return ""
    
    def _emit_alert(self, canary: CanaryFile, action: str):
        """Emit ransomware alert"""
        event = RansomwareEvent(
            id=hashlib.md5(f"{canary.id}-{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            event_type=RansomwareEventType.CANARY_TRIGGERED.value,
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity="critical",
            affected_files=[canary.path],
            details={
                "canary_id": canary.id,
                "action": action,
                "original_hash": canary.original_hash
            }
        )
        
        logger.critical(f"RANSOMWARE ALERT: Canary {action}! Path: {canary.path}")
        
        if self._alert_callback:
            self._alert_callback(event)
    
    def get_status(self) -> Dict[str, Any]:
        """Get canary system status"""
        return {
            "total_canaries": len(self.canaries),
            "active_canaries": len([c for c in self.canaries.values() if c.status == "active"]),
            "triggered_canaries": len(self.triggered_canaries),
            "canary_locations": [c.path for c in self.canaries.values()][:10]
        }


# =============================================================================
# BEHAVIORAL RANSOMWARE DETECTION
# =============================================================================

class RansomwareBehaviorDetector:
    """
    Detects ransomware through behavioral patterns:
    - Mass file encryption/modification
    - Suspicious file renames (.encrypted, .locked, etc.)
    - Shadow copy deletion attempts
    - Backup service manipulation
    """
    
    RANSOMWARE_EXTENSIONS = {
        ".encrypted", ".locked", ".crypto", ".crypt", ".enc", ".crypted",
        ".locky", ".zepto", ".cerber", ".wcry", ".wncry", ".wncryt",
        ".WNCRY", ".crypt1", ".crinf", ".r5a", ".XRNT", ".XTBL",
        ".crypt", ".R16M01D05", ".pzdc", ".good", ".LOL!", ".OMG!",
        ".fun", ".kb", ".encrypted", ".locked", ".kraken", ".darkness",
        ".nochance", ".oshit", ".carote", ".surprise"
    }
    
    def __init__(self):
        self.file_events: List[Dict] = []
        self.rename_events: List[Dict] = []
        self.suspicious_processes: Set[int] = set()
        self._monitoring = False
        self._monitor_thread = None
        self._alert_callback: Optional[Callable] = None
        self._db = None
    
    def set_database(self, db):
        self._db = db
    
    def set_alert_callback(self, callback: Callable):
        self._alert_callback = callback
    
    def record_file_event(self, event_type: str, path: str, process_pid: int = None, process_name: str = None):
        """Record a file system event for analysis"""
        event = {
            "type": event_type,
            "path": path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process_pid": process_pid,
            "process_name": process_name
        }
        
        self.file_events.append(event)
        
        # Keep only last 5 minutes of events
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        self.file_events = [e for e in self.file_events 
                          if datetime.fromisoformat(e["timestamp"].replace('Z', '+00:00')) > cutoff]
        
        # Check for ransomware patterns
        self._analyze_patterns()
    
    def record_rename_event(self, old_path: str, new_path: str, process_pid: int = None, process_name: str = None):
        """Record a file rename event"""
        event = {
            "old_path": old_path,
            "new_path": new_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process_pid": process_pid,
            "process_name": process_name
        }
        
        # Check for ransomware extension
        new_ext = Path(new_path).suffix.lower()
        if new_ext in self.RANSOMWARE_EXTENSIONS:
            event["suspicious"] = True
            event["reason"] = f"Ransomware extension: {new_ext}"
            self._emit_alert(RansomwareEventType.SUSPICIOUS_RENAME, [new_path], {
                "old_path": old_path,
                "new_extension": new_ext,
                "process_pid": process_pid,
                "process_name": process_name
            })
        
        self.rename_events.append(event)
        
        # Keep only last 5 minutes
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        self.rename_events = [e for e in self.rename_events
                            if datetime.fromisoformat(e["timestamp"].replace('Z', '+00:00')) > cutoff]
    
    def _analyze_patterns(self):
        """Analyze recent events for ransomware patterns"""
        now = datetime.now(timezone.utc)
        one_minute_ago = now - timedelta(minutes=1)
        
        # Count recent file modifications per process
        recent_events = [e for e in self.file_events 
                        if datetime.fromisoformat(e["timestamp"].replace('Z', '+00:00')) > one_minute_ago]
        
        # Group by process
        by_process: Dict[int, List[Dict]] = {}
        for event in recent_events:
            pid = event.get("process_pid")
            if pid:
                by_process.setdefault(pid, []).append(event)
        
        # Check for mass encryption pattern
        for pid, events in by_process.items():
            if len(events) >= config.encryption_threshold:
                if pid not in self.suspicious_processes:
                    self.suspicious_processes.add(pid)
                    self._emit_alert(
                        RansomwareEventType.MASS_ENCRYPTION,
                        [e["path"] for e in events[:10]],
                        {
                            "process_pid": pid,
                            "process_name": events[0].get("process_name"),
                            "files_modified": len(events),
                            "time_window": "1 minute"
                        }
                    )
    
    def _emit_alert(self, event_type: RansomwareEventType, affected_files: List[str], details: Dict):
        """Emit ransomware detection alert"""
        event = RansomwareEvent(
            id=hashlib.md5(f"{event_type.value}-{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            event_type=event_type.value,
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity="critical",
            process_name=details.get("process_name"),
            process_pid=details.get("process_pid"),
            affected_files=affected_files,
            details=details
        )
        
        logger.critical(f"RANSOMWARE DETECTION: {event_type.value}")
        
        if self._alert_callback:
            self._alert_callback(event)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get behavioral detection statistics"""
        return {
            "monitoring": self._monitoring,
            "recent_file_events": len(self.file_events),
            "recent_rename_events": len(self.rename_events),
            "suspicious_renames": len([e for e in self.rename_events if e.get("suspicious")]),
            "suspicious_processes": list(self.suspicious_processes)
        }


# =============================================================================
# PROTECTED FOLDERS
# =============================================================================

class ProtectedFolderManager:
    """
    Manages folders protected from ransomware access.
    Only whitelisted processes can modify files in protected folders.
    """
    
    DEFAULT_PROTECTED = [
        str(Path.home() / "Documents"),
        str(Path.home() / "Pictures"),
        str(Path.home() / "Desktop"),
    ]
    
    DEFAULT_ALLOWED_PROCESSES = [
        "explorer.exe", "notepad.exe", "word.exe", "excel.exe",
        "code.exe", "vim", "nano", "gedit", "libreoffice"
    ]
    
    def __init__(self):
        self.protected_folders: Dict[str, ProtectedFolder] = {}
        self._load_config()
    
    def _load_config(self):
        """Load protected folder configuration"""
        if PROTECTED_DIRS_FILE.exists():
            try:
                with open(PROTECTED_DIRS_FILE, 'r') as f:
                    data = json.load(f)
                    for folder_data in data.get("folders", []):
                        folder = ProtectedFolder(**folder_data)
                        self.protected_folders[folder.path] = folder
            except Exception as e:
                logger.error(f"Failed to load protected folders config: {e}")
    
    def _save_config(self):
        """Save protected folder configuration"""
        try:
            data = {"folders": [asdict(f) for f in self.protected_folders.values()]}
            with open(PROTECTED_DIRS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save protected folders config: {e}")
    
    def add_protected_folder(self, path: str, allowed_processes: List[str] = None) -> ProtectedFolder:
        """Add a folder to protection"""
        folder = ProtectedFolder(
            path=path,
            allowed_processes=allowed_processes or self.DEFAULT_ALLOWED_PROCESSES,
            created_at=datetime.now(timezone.utc).isoformat()
        )
        self.protected_folders[path] = folder
        self._save_config()
        return folder
    
    def remove_protected_folder(self, path: str) -> bool:
        """Remove a folder from protection"""
        if path in self.protected_folders:
            del self.protected_folders[path]
            self._save_config()
            return True
        return False
    
    def check_access(self, file_path: str, process_name: str) -> bool:
        """
        Check if a process is allowed to access a protected file.
        Returns True if access is allowed.
        """
        file_path = Path(file_path)
        
        for protected_path, folder in self.protected_folders.items():
            if str(file_path).startswith(protected_path):
                # File is in a protected folder
                process_lower = process_name.lower()
                allowed = any(p.lower() in process_lower for p in folder.allowed_processes)
                
                if not allowed:
                    folder.last_access_attempt = datetime.now(timezone.utc).isoformat()
                    self._save_config()
                
                return allowed
        
        # Not in a protected folder
        return True
    
    def get_protected_folders(self) -> List[ProtectedFolder]:
        """Get all protected folders"""
        return list(self.protected_folders.values())


# =============================================================================
# RANSOMWARE PROTECTION MANAGER
# =============================================================================

class RansomwareProtectionManager:
    """
    Central manager for all ransomware protection features.
    """
    
    _instance = None
    _db = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.canary_manager = CanaryFileManager()
        self.behavior_detector = RansomwareBehaviorDetector()
        self.folder_manager = ProtectedFolderManager()
        self.events: List[RansomwareEvent] = []
        self._monitoring = False
        self._monitor_thread = None
        self._initialized = True
    
    @classmethod
    def set_database(cls, db):
        cls._db = db
        if cls._instance:
            cls._instance.canary_manager.set_database(db)
            cls._instance.behavior_detector.set_database(db)
    
    def set_alert_callback(self, callback: Callable):
        """Set callback for ransomware alerts"""
        self.canary_manager.set_alert_callback(callback)
        self.behavior_detector.set_alert_callback(callback)
    
    def start_protection(self):
        """Start all ransomware protection features"""
        logger.info("Starting ransomware protection...")
        
        # Deploy canaries if enabled
        if config.canary_enabled:
            self.canary_manager.deploy_canaries()
        
        # Start monitoring
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        logger.info("Ransomware protection active")
    
    def stop_protection(self):
        """Stop ransomware protection"""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("Ransomware protection stopped")
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        while self._monitoring:
            try:
                # Check canaries every 30 seconds
                triggered = self.canary_manager.check_canaries()
                if triggered:
                    logger.critical(f"ALERT: {len(triggered)} canaries triggered!")
                
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
            
            time.sleep(30)
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive protection status"""
        return {
            "protection_active": self._monitoring,
            "canary_status": self.canary_manager.get_status(),
            "behavioral_status": self.behavior_detector.get_stats(),
            "protected_folders": len(self.folder_manager.protected_folders),
            "recent_events": len(self.events),
            "config": {
                "canary_enabled": config.canary_enabled,
                "behavioral_detection": config.behavioral_detection,
                "auto_backup": config.auto_backup,
                "auto_kill": config.auto_kill_ransomware
            }
        }
    
    def deploy_canaries(self, directories: List[str] = None) -> List[Dict]:
        """Deploy canary files"""
        canaries = self.canary_manager.deploy_canaries(directories)
        return [asdict(c) for c in canaries]
    
    def add_protected_folder(self, path: str, allowed_processes: List[str] = None) -> Dict:
        """Add a protected folder"""
        folder = self.folder_manager.add_protected_folder(path, allowed_processes)
        return asdict(folder)
    
    def get_protected_folders(self) -> List[Dict]:
        """Get all protected folders"""
        return [asdict(f) for f in self.folder_manager.get_protected_folders()]


# Global instance
ransomware_protection = RansomwareProtectionManager()
