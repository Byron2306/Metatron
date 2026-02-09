"""
Auto-Quarantine Service - Automatic isolation of infected files
"""
import os
import shutil
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

QUARANTINE_BASE_DIR = os.environ.get("QUARANTINE_DIR", "/var/lib/anti-ai-defense/quarantine")
QUARANTINE_INDEX_FILE = os.path.join(QUARANTINE_BASE_DIR, "quarantine_index.json")
MAX_QUARANTINE_SIZE_MB = int(os.environ.get("MAX_QUARANTINE_SIZE_MB", "1000"))  # 1GB default

# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class QuarantineEntry:
    """Represents a quarantined file"""
    id: str
    original_path: str
    quarantine_path: str
    file_hash: str
    file_size: int
    threat_name: str
    threat_type: str
    detection_source: str
    agent_id: Optional[str]
    agent_name: Optional[str]
    quarantined_at: str
    status: str  # quarantined, restored, deleted
    metadata: Dict[str, Any]

# =============================================================================
# QUARANTINE INDEX MANAGEMENT
# =============================================================================

def _load_index() -> Dict[str, QuarantineEntry]:
    """Load quarantine index from disk"""
    if os.path.exists(QUARANTINE_INDEX_FILE):
        try:
            with open(QUARANTINE_INDEX_FILE, 'r') as f:
                data = json.load(f)
                return {k: QuarantineEntry(**v) for k, v in data.items()}
        except Exception as e:
            logger.error(f"Failed to load quarantine index: {e}")
    return {}

def _save_index(index: Dict[str, QuarantineEntry]):
    """Save quarantine index to disk"""
    try:
        os.makedirs(QUARANTINE_BASE_DIR, exist_ok=True)
        with open(QUARANTINE_INDEX_FILE, 'w') as f:
            json.dump({k: asdict(v) for k, v in index.items()}, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save quarantine index: {e}")

def _get_quarantine_stats() -> Dict[str, Any]:
    """Get quarantine directory statistics"""
    total_size = 0
    file_count = 0
    
    if os.path.exists(QUARANTINE_BASE_DIR):
        for root, dirs, files in os.walk(QUARANTINE_BASE_DIR):
            for f in files:
                if f != "quarantine_index.json":
                    filepath = os.path.join(root, f)
                    try:
                        total_size += os.path.getsize(filepath)
                        file_count += 1
                    except OSError:
                        pass
    
    return {
        "total_size_bytes": total_size,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
        "file_count": file_count,
        "max_size_mb": MAX_QUARANTINE_SIZE_MB,
        "usage_percent": round((total_size / (MAX_QUARANTINE_SIZE_MB * 1024 * 1024)) * 100, 2) if MAX_QUARANTINE_SIZE_MB > 0 else 0
    }

# =============================================================================
# QUARANTINE OPERATIONS
# =============================================================================

def quarantine_file(
    filepath: str,
    threat_name: str,
    threat_type: str = "unknown",
    detection_source: str = "manual",
    agent_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Optional[QuarantineEntry]:
    """
    Quarantine an infected file
    
    Args:
        filepath: Path to the infected file
        threat_name: Name of the detected threat
        threat_type: Type of threat (malware, virus, ransomware, etc.)
        detection_source: What detected the threat (yara, clamav, manual, etc.)
        agent_id: ID of the reporting agent
        agent_name: Name of the reporting agent
        metadata: Additional metadata about the detection
    
    Returns:
        QuarantineEntry if successful, None otherwise
    """
    if not os.path.exists(filepath):
        logger.warning(f"Cannot quarantine - file not found: {filepath}")
        return None
    
    # Check quarantine size limits
    stats = _get_quarantine_stats()
    if stats["usage_percent"] >= 100:
        logger.error("Quarantine directory at capacity. Cannot quarantine new files.")
        return None
    
    try:
        # Calculate file hash
        file_hash = hashlib.sha256()
        file_size = os.path.getsize(filepath)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                file_hash.update(chunk)
        file_hash = file_hash.hexdigest()
        
        # Generate unique ID
        entry_id = hashlib.md5(f"{filepath}{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        # Create quarantine subdirectory by date
        date_dir = datetime.now().strftime("%Y-%m-%d")
        quarantine_dir = os.path.join(QUARANTINE_BASE_DIR, date_dir)
        os.makedirs(quarantine_dir, exist_ok=True)
        
        # Generate quarantine filename
        original_name = os.path.basename(filepath)
        quarantine_filename = f"{entry_id}_{original_name}.quarantined"
        quarantine_path = os.path.join(quarantine_dir, quarantine_filename)
        
        # Move file to quarantine
        shutil.move(filepath, quarantine_path)
        
        # Set restrictive permissions
        os.chmod(quarantine_path, 0o400)
        
        # Create entry
        entry = QuarantineEntry(
            id=entry_id,
            original_path=filepath,
            quarantine_path=quarantine_path,
            file_hash=file_hash,
            file_size=file_size,
            threat_name=threat_name,
            threat_type=threat_type,
            detection_source=detection_source,
            agent_id=agent_id,
            agent_name=agent_name,
            quarantined_at=datetime.now(timezone.utc).isoformat(),
            status="quarantined",
            metadata=metadata or {}
        )
        
        # Update index
        index = _load_index()
        index[entry_id] = entry
        _save_index(index)
        
        logger.info(f"File quarantined: {filepath} -> {quarantine_path} (threat: {threat_name})")
        return entry
        
    except Exception as e:
        logger.error(f"Failed to quarantine file {filepath}: {e}")
        return None

def restore_file(entry_id: str, restore_path: Optional[str] = None) -> bool:
    """
    Restore a quarantined file
    
    Args:
        entry_id: ID of the quarantine entry
        restore_path: Optional path to restore to (defaults to original path)
    
    Returns:
        bool: True if successful
    """
    index = _load_index()
    
    if entry_id not in index:
        logger.warning(f"Quarantine entry not found: {entry_id}")
        return False
    
    entry = index[entry_id]
    
    if entry.status != "quarantined":
        logger.warning(f"Entry {entry_id} is not in quarantined state: {entry.status}")
        return False
    
    if not os.path.exists(entry.quarantine_path):
        logger.error(f"Quarantined file not found: {entry.quarantine_path}")
        return False
    
    try:
        target_path = restore_path or entry.original_path
        
        # Ensure target directory exists
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        
        # Restore file
        shutil.move(entry.quarantine_path, target_path)
        
        # Update entry
        entry.status = "restored"
        entry.metadata["restored_at"] = datetime.now(timezone.utc).isoformat()
        entry.metadata["restored_to"] = target_path
        index[entry_id] = entry
        _save_index(index)
        
        logger.info(f"File restored: {entry_id} -> {target_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to restore file {entry_id}: {e}")
        return False

def delete_quarantined(entry_id: str) -> bool:
    """
    Permanently delete a quarantined file
    
    Args:
        entry_id: ID of the quarantine entry
    
    Returns:
        bool: True if successful
    """
    index = _load_index()
    
    if entry_id not in index:
        logger.warning(f"Quarantine entry not found: {entry_id}")
        return False
    
    entry = index[entry_id]
    
    try:
        if os.path.exists(entry.quarantine_path):
            os.remove(entry.quarantine_path)
        
        # Update entry
        entry.status = "deleted"
        entry.metadata["deleted_at"] = datetime.now(timezone.utc).isoformat()
        index[entry_id] = entry
        _save_index(index)
        
        logger.info(f"Quarantined file deleted: {entry_id}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to delete quarantined file {entry_id}: {e}")
        return False

def list_quarantined(
    status: Optional[str] = None,
    threat_type: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = 100
) -> List[QuarantineEntry]:
    """
    List quarantined files with optional filtering
    
    Args:
        status: Filter by status (quarantined, restored, deleted)
        threat_type: Filter by threat type
        agent_id: Filter by agent ID
        limit: Maximum number of results
    
    Returns:
        List of QuarantineEntry objects
    """
    index = _load_index()
    results = []
    
    for entry in index.values():
        if status and entry.status != status:
            continue
        if threat_type and entry.threat_type != threat_type:
            continue
        if agent_id and entry.agent_id != agent_id:
            continue
        
        results.append(entry)
        if len(results) >= limit:
            break
    
    # Sort by quarantine date descending
    results.sort(key=lambda x: x.quarantined_at, reverse=True)
    return results

def get_quarantine_entry(entry_id: str) -> Optional[QuarantineEntry]:
    """Get a specific quarantine entry"""
    index = _load_index()
    return index.get(entry_id)

def get_quarantine_summary() -> Dict[str, Any]:
    """Get summary statistics for the quarantine system"""
    index = _load_index()
    stats = _get_quarantine_stats()
    
    by_status = {"quarantined": 0, "restored": 0, "deleted": 0}
    by_type = {}
    by_source = {}
    
    for entry in index.values():
        by_status[entry.status] = by_status.get(entry.status, 0) + 1
        by_type[entry.threat_type] = by_type.get(entry.threat_type, 0) + 1
        by_source[entry.detection_source] = by_source.get(entry.detection_source, 0) + 1
    
    return {
        "total_entries": len(index),
        "storage": stats,
        "by_status": by_status,
        "by_threat_type": by_type,
        "by_detection_source": by_source
    }

# =============================================================================
# CLEANUP FUNCTIONS
# =============================================================================

def cleanup_old_entries(days: int = 30) -> int:
    """
    Delete quarantine entries older than specified days
    
    Args:
        days: Number of days to keep entries
    
    Returns:
        Number of entries cleaned up
    """
    from datetime import timedelta
    
    index = _load_index()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    cleaned = 0
    
    for entry_id, entry in list(index.items()):
        try:
            entry_date = datetime.fromisoformat(entry.quarantined_at.replace('Z', '+00:00'))
            if entry_date < cutoff and entry.status == "quarantined":
                if delete_quarantined(entry_id):
                    cleaned += 1
        except (ValueError, KeyError):
            pass
    
    logger.info(f"Cleaned up {cleaned} old quarantine entries")
    return cleaned

# =============================================================================
# AUTO-QUARANTINE HANDLER (for agent integration)
# =============================================================================

async def handle_malware_detection(
    filepath: str,
    threat_name: str,
    threat_type: str,
    detection_source: str,
    agent_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    auto_quarantine: bool = True,
    notify: bool = True
) -> Dict[str, Any]:
    """
    Handle a malware detection event with optional auto-quarantine
    
    Args:
        filepath: Path to the infected file
        threat_name: Name of the detected threat
        threat_type: Type of threat
        detection_source: Detection source (yara, clamav, etc.)
        agent_id: ID of the reporting agent
        agent_name: Name of the reporting agent
        auto_quarantine: Whether to automatically quarantine
        notify: Whether to send notifications
    
    Returns:
        Dict with action results
    """
    result = {
        "filepath": filepath,
        "threat_name": threat_name,
        "threat_type": threat_type,
        "detection_source": detection_source,
        "quarantined": False,
        "quarantine_entry": None,
        "notifications_sent": {}
    }
    
    # Auto-quarantine if enabled
    if auto_quarantine:
        entry = quarantine_file(
            filepath=filepath,
            threat_name=threat_name,
            threat_type=threat_type,
            detection_source=detection_source,
            agent_id=agent_id,
            agent_name=agent_name
        )
        if entry:
            result["quarantined"] = True
            result["quarantine_entry"] = asdict(entry)
    
    # Send notifications if enabled
    if notify:
        try:
            from notifications import notify_malware_detected, notify_quarantine_action
            
            result["notifications_sent"]["malware"] = await notify_malware_detected(
                filepath=filepath,
                malware_type=f"{threat_type}: {threat_name}",
                action_taken="Auto-quarantined" if result["quarantined"] else "Detected (no action)",
                agent_name=agent_name
            )
            
            if result["quarantined"]:
                result["notifications_sent"]["quarantine"] = await notify_quarantine_action(
                    filepath=filepath,
                    threat_name=threat_name,
                    quarantine_path=result["quarantine_entry"]["quarantine_path"],
                    agent_name=agent_name
                )
        except Exception as e:
            logger.error(f"Failed to send notifications: {e}")
    
    return result
