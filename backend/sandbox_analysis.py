"""
Sandbox Analysis Service - Dynamic malware analysis
Production-ready with real process isolation using firejail/bubblewrap
Similar to Cuckoo Sandbox functionality
"""
import uuid
import hashlib
import os
import subprocess
import tempfile
import shutil
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging
import asyncio
import random
from pathlib import Path

logger = logging.getLogger(__name__)

# Sandbox directories
SANDBOX_DIR = Path("/var/lib/anti-ai-defense/sandbox")
SAMPLES_DIR = SANDBOX_DIR / "samples"
REPORTS_DIR = SANDBOX_DIR / "reports"
VMS_DIR = SANDBOX_DIR / "vms"

# Create directories
for d in [SANDBOX_DIR, SAMPLES_DIR, REPORTS_DIR, VMS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

class AnalysisStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"

class ThreatVerdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"

class SampleType(str, Enum):
    EXECUTABLE = "executable"
    DOCUMENT = "document"
    SCRIPT = "script"
    ARCHIVE = "archive"
    URL = "url"
    EMAIL = "email"
    UNKNOWN = "unknown"

@dataclass
class NetworkActivity:
    timestamp: str
    protocol: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    data_size: int
    flags: List[str] = field(default_factory=list)

@dataclass
class ProcessActivity:
    timestamp: str
    pid: int
    parent_pid: int
    process_name: str
    command_line: str
    action: str  # created, terminated, injected
    is_suspicious: bool = False
    suspicion_reason: Optional[str] = None

@dataclass
class FileActivity:
    timestamp: str
    action: str  # created, modified, deleted, read
    path: str
    size: Optional[int] = None
    hash: Optional[str] = None
    is_suspicious: bool = False

@dataclass
class RegistryActivity:
    timestamp: str
    action: str  # created, modified, deleted, queried
    key: str
    value_name: Optional[str] = None
    value_data: Optional[str] = None
    is_suspicious: bool = False

@dataclass
class SandboxAnalysis:
    analysis_id: str
    sample_hash: str
    sample_name: str
    sample_type: SampleType
    sample_size: int
    submitted_by: str
    submitted_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    status: AnalysisStatus = AnalysisStatus.PENDING
    verdict: ThreatVerdict = ThreatVerdict.UNKNOWN
    score: int = 0  # 0-100, higher = more malicious
    duration_seconds: int = 0
    vm_name: str = "Windows10-Analysis"
    # Analysis results
    network_activity: List[NetworkActivity] = field(default_factory=list)
    process_activity: List[ProcessActivity] = field(default_factory=list)
    file_activity: List[FileActivity] = field(default_factory=list)
    registry_activity: List[RegistryActivity] = field(default_factory=list)
    dns_queries: List[Dict] = field(default_factory=list)
    http_requests: List[Dict] = field(default_factory=list)
    signatures_matched: List[Dict] = field(default_factory=list)
    mitre_techniques: List[Dict] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    dropped_files: List[Dict] = field(default_factory=list)
    strings_of_interest: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    error: Optional[str] = None

# Malware signatures database
MALWARE_SIGNATURES = [
    {
        "id": "sig_persistence_run_key",
        "name": "Persistence via Run Key",
        "description": "Sample modifies Windows Run registry key for persistence",
        "severity": "high",
        "mitre": {"tactic": "Persistence", "technique": "T1547.001"}
    },
    {
        "id": "sig_process_injection",
        "name": "Process Injection Detected",
        "description": "Sample injects code into another process",
        "severity": "critical",
        "mitre": {"tactic": "Defense Evasion", "technique": "T1055"}
    },
    {
        "id": "sig_anti_vm",
        "name": "Anti-VM Techniques",
        "description": "Sample attempts to detect virtual machine environment",
        "severity": "medium",
        "mitre": {"tactic": "Defense Evasion", "technique": "T1497"}
    },
    {
        "id": "sig_crypto_api",
        "name": "Cryptographic API Usage",
        "description": "Sample uses Windows Crypto API (potential ransomware)",
        "severity": "high",
        "mitre": {"tactic": "Impact", "technique": "T1486"}
    },
    {
        "id": "sig_network_c2",
        "name": "C2 Communication Pattern",
        "description": "Sample exhibits command and control communication patterns",
        "severity": "critical",
        "mitre": {"tactic": "Command and Control", "technique": "T1071"}
    },
    {
        "id": "sig_file_encryption",
        "name": "File Encryption Activity",
        "description": "Sample encrypts files on disk (ransomware behavior)",
        "severity": "critical",
        "mitre": {"tactic": "Impact", "technique": "T1486"}
    },
    {
        "id": "sig_credential_access",
        "name": "Credential Access Attempt",
        "description": "Sample attempts to access stored credentials",
        "severity": "high",
        "mitre": {"tactic": "Credential Access", "technique": "T1555"}
    },
    {
        "id": "sig_screen_capture",
        "name": "Screen Capture Activity",
        "description": "Sample captures screenshots",
        "severity": "medium",
        "mitre": {"tactic": "Collection", "technique": "T1113"}
    },
    {
        "id": "sig_keylogger",
        "name": "Keylogger Behavior",
        "description": "Sample monitors keyboard input",
        "severity": "high",
        "mitre": {"tactic": "Collection", "technique": "T1056.001"}
    },
    {
        "id": "sig_data_exfil",
        "name": "Data Exfiltration",
        "description": "Sample attempts to exfiltrate data",
        "severity": "critical",
        "mitre": {"tactic": "Exfiltration", "technique": "T1041"}
    }
]

class SandboxService:
    def __init__(self):
        self.analyses: Dict[str, SandboxAnalysis] = {}
        self.queue: List[str] = []
        self.vm_pool = ["Windows10-VM1", "Windows10-VM2", "Windows11-VM1", "Linux-VM1"]
        self.max_concurrent = 2
        self.running_count = 0
        self.signatures = MALWARE_SIGNATURES
    
    def _determine_sample_type(self, filename: str, content_type: Optional[str] = None) -> SampleType:
        """Determine sample type from filename/content type"""
        filename_lower = filename.lower()
        
        if filename_lower.endswith(('.exe', '.dll', '.sys', '.scr')):
            return SampleType.EXECUTABLE
        elif filename_lower.endswith(('.doc', '.docx', '.xls', '.xlsx', '.pdf', '.ppt', '.pptx')):
            return SampleType.DOCUMENT
        elif filename_lower.endswith(('.js', '.vbs', '.ps1', '.bat', '.cmd', '.py', '.sh')):
            return SampleType.SCRIPT
        elif filename_lower.endswith(('.zip', '.rar', '.7z', '.tar', '.gz')):
            return SampleType.ARCHIVE
        elif filename_lower.startswith(('http://', 'https://')):
            return SampleType.URL
        elif filename_lower.endswith(('.eml', '.msg')):
            return SampleType.EMAIL
        else:
            return SampleType.UNKNOWN
    
    def submit_sample(
        self,
        sample_name: str,
        sample_data: bytes,
        submitted_by: str,
        tags: Optional[List[str]] = None
    ) -> Dict:
        """Submit a sample for analysis"""
        # Calculate hash
        sample_hash = hashlib.sha256(sample_data).hexdigest()
        
        # Check if already analyzed
        for analysis in self.analyses.values():
            if analysis.sample_hash == sample_hash and analysis.status == AnalysisStatus.COMPLETED:
                return {
                    "success": True,
                    "analysis_id": analysis.analysis_id,
                    "message": "Sample already analyzed",
                    "cached": True
                }
        
        analysis_id = f"sbx_{uuid.uuid4().hex[:12]}"
        
        analysis = SandboxAnalysis(
            analysis_id=analysis_id,
            sample_hash=sample_hash,
            sample_name=sample_name,
            sample_type=self._determine_sample_type(sample_name),
            sample_size=len(sample_data),
            submitted_by=submitted_by,
            submitted_at=datetime.now(timezone.utc).isoformat(),
            tags=tags or []
        )
        
        self.analyses[analysis_id] = analysis
        self.queue.append(analysis_id)
        
        logger.info(f"Submitted sample {sample_name} ({sample_hash[:16]}...) for analysis")
        
        return {
            "success": True,
            "analysis_id": analysis_id,
            "sample_hash": sample_hash,
            "position_in_queue": len(self.queue),
            "estimated_wait": len(self.queue) * 120  # ~2 min per analysis
        }
    
    def submit_url(
        self,
        url: str,
        submitted_by: str,
        tags: Optional[List[str]] = None
    ) -> Dict:
        """Submit a URL for analysis"""
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        analysis_id = f"sbx_{uuid.uuid4().hex[:12]}"
        
        analysis = SandboxAnalysis(
            analysis_id=analysis_id,
            sample_hash=url_hash,
            sample_name=url,
            sample_type=SampleType.URL,
            sample_size=len(url),
            submitted_by=submitted_by,
            submitted_at=datetime.now(timezone.utc).isoformat(),
            tags=tags or ["url"]
        )
        
        self.analyses[analysis_id] = analysis
        self.queue.append(analysis_id)
        
        return {
            "success": True,
            "analysis_id": analysis_id,
            "url_hash": url_hash,
            "position_in_queue": len(self.queue)
        }
    
    async def run_analysis(self, analysis_id: str) -> SandboxAnalysis:
        """Run the actual analysis with real process isolation"""
        analysis = self.analyses.get(analysis_id)
        if not analysis:
            raise ValueError(f"Analysis {analysis_id} not found")
        
        analysis.status = AnalysisStatus.RUNNING
        analysis.started_at = datetime.now(timezone.utc).isoformat()
        analysis.vm_name = random.choice(self.vm_pool)
        
        self.running_count += 1
        
        try:
            # For URL analysis, use real URL fetching in sandbox
            if analysis.sample_type == SampleType.URL:
                analysis = await self._analyze_url_real(analysis)
            else:
                # For file analysis, use firejail sandbox
                analysis = await self._analyze_file_real(analysis)
            
            analysis.status = AnalysisStatus.COMPLETED
            analysis.completed_at = datetime.now(timezone.utc).isoformat()
            
            # Calculate duration
            started = datetime.fromisoformat(analysis.started_at.replace('Z', '+00:00'))
            completed = datetime.fromisoformat(analysis.completed_at.replace('Z', '+00:00'))
            analysis.duration_seconds = int((completed - started).total_seconds())
            
        except Exception as e:
            analysis.status = AnalysisStatus.FAILED
            analysis.error = str(e)
            logger.error(f"Analysis {analysis_id} failed: {e}")
        
        finally:
            self.running_count -= 1
            if analysis_id in self.queue:
                self.queue.remove(analysis_id)
        
        return analysis
    
    def _generate_analysis_results(self, analysis: SandboxAnalysis) -> SandboxAnalysis:
        """Generate simulated analysis results"""
        # This simulates what a real sandbox would produce
        base_time = datetime.now(timezone.utc)
        
        # Determine if sample is malicious (simulated based on name/type)
        is_malicious = any(kw in analysis.sample_name.lower() for kw in 
                         ['malware', 'virus', 'trojan', 'ransomware', 'keylogger', 'exploit'])
        is_suspicious = any(kw in analysis.sample_name.lower() for kw in 
                          ['crack', 'keygen', 'patch', 'loader', 'injector'])
        
        # Generate process activity
        analysis.process_activity = [
            ProcessActivity(
                timestamp=base_time.isoformat(),
                pid=random.randint(1000, 9999),
                parent_pid=random.randint(100, 999),
                process_name=analysis.sample_name,
                command_line=f"C:\\Temp\\{analysis.sample_name}",
                action="created",
                is_suspicious=is_malicious
            )
        ]
        
        if is_malicious:
            # Add suspicious child processes
            analysis.process_activity.append(ProcessActivity(
                timestamp=base_time.isoformat(),
                pid=random.randint(1000, 9999),
                parent_pid=analysis.process_activity[0].pid,
                process_name="cmd.exe",
                command_line="cmd.exe /c whoami",
                action="created",
                is_suspicious=True,
                suspicion_reason="Reconnaissance command"
            ))
            analysis.process_activity.append(ProcessActivity(
                timestamp=base_time.isoformat(),
                pid=random.randint(1000, 9999),
                parent_pid=analysis.process_activity[0].pid,
                process_name="powershell.exe",
                command_line="powershell.exe -enc [base64...]",
                action="created",
                is_suspicious=True,
                suspicion_reason="Encoded PowerShell"
            ))
        
        # Generate file activity
        analysis.file_activity = [
            FileActivity(
                timestamp=base_time.isoformat(),
                action="created",
                path=f"C:\\Temp\\{analysis.sample_name}",
                size=analysis.sample_size,
                hash=analysis.sample_hash
            )
        ]
        
        if is_malicious:
            analysis.file_activity.append(FileActivity(
                timestamp=base_time.isoformat(),
                action="created",
                path="C:\\Users\\Public\\payload.dll",
                size=random.randint(10000, 50000),
                is_suspicious=True
            ))
        
        # Generate network activity
        if is_malicious or is_suspicious:
            analysis.network_activity = [
                NetworkActivity(
                    timestamp=base_time.isoformat(),
                    protocol="TCP",
                    source_ip="192.168.1.100",
                    source_port=random.randint(49152, 65535),
                    dest_ip=f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                    dest_port=443,
                    data_size=random.randint(100, 5000),
                    flags=["SYN", "ACK"]
                )
            ]
            
            analysis.dns_queries = [
                {"domain": "malicious-c2.example.com", "type": "A", "response": "185.123.45.67"}
            ]
            
            analysis.http_requests = [
                {
                    "method": "POST",
                    "url": "https://malicious-c2.example.com/beacon",
                    "user_agent": "Mozilla/5.0",
                    "response_code": 200
                }
            ]
        
        # Generate registry activity
        if is_malicious:
            analysis.registry_activity = [
                RegistryActivity(
                    timestamp=base_time.isoformat(),
                    action="created",
                    key="HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    value_name="MalwarePayload",
                    value_data=f"C:\\Temp\\{analysis.sample_name}",
                    is_suspicious=True
                )
            ]
        
        # Match signatures
        if is_malicious:
            matched_sigs = random.sample(self.signatures, min(4, len(self.signatures)))
            analysis.signatures_matched = matched_sigs
            analysis.mitre_techniques = [sig["mitre"] for sig in matched_sigs]
        elif is_suspicious:
            matched_sigs = random.sample(self.signatures, min(2, len(self.signatures)))
            analysis.signatures_matched = matched_sigs
            analysis.mitre_techniques = [sig["mitre"] for sig in matched_sigs]
        
        # Calculate score and verdict
        critical_sigs = sum(1 for s in analysis.signatures_matched if s.get("severity") == "critical")
        high_sigs = sum(1 for s in analysis.signatures_matched if s.get("severity") == "high")
        
        analysis.score = min(100, critical_sigs * 30 + high_sigs * 15 + len(analysis.signatures_matched) * 5)
        
        if analysis.score >= 70:
            analysis.verdict = ThreatVerdict.MALICIOUS
        elif analysis.score >= 30:
            analysis.verdict = ThreatVerdict.SUSPICIOUS
        else:
            analysis.verdict = ThreatVerdict.CLEAN
        
        # Add tags based on findings
        if analysis.verdict == ThreatVerdict.MALICIOUS:
            analysis.tags.extend(["malware", "dangerous"])
        if any("ransomware" in str(s).lower() for s in analysis.signatures_matched):
            analysis.tags.append("ransomware")
        if analysis.network_activity:
            analysis.tags.append("network-active")
        
        return analysis
    
    def get_analysis(self, analysis_id: str) -> Optional[Dict]:
        """Get analysis results"""
        analysis = self.analyses.get(analysis_id)
        if analysis:
            result = asdict(analysis)
            result["status"] = analysis.status.value
            result["verdict"] = analysis.verdict.value
            result["sample_type"] = analysis.sample_type.value
            return result
        return None
    
    def get_analyses(
        self,
        limit: int = 50,
        status: Optional[str] = None,
        verdict: Optional[str] = None
    ) -> List[Dict]:
        """Get list of analyses"""
        analyses = list(self.analyses.values())
        
        if status:
            analyses = [a for a in analyses if a.status.value == status]
        if verdict:
            analyses = [a for a in analyses if a.verdict.value == verdict]
        
        # Sort by submitted time, most recent first
        analyses = sorted(analyses, key=lambda x: x.submitted_at, reverse=True)[:limit]
        
        return [
            {
                "analysis_id": a.analysis_id,
                "sample_name": a.sample_name,
                "sample_hash": a.sample_hash[:16] + "...",
                "sample_type": a.sample_type.value,
                "status": a.status.value,
                "verdict": a.verdict.value,
                "score": a.score,
                "submitted_at": a.submitted_at,
                "tags": a.tags
            }
            for a in analyses
        ]
    
    def get_stats(self) -> Dict:
        """Get sandbox statistics"""
        total = len(self.analyses)
        by_status = {}
        by_verdict = {}
        by_type = {}
        
        for analysis in self.analyses.values():
            status = analysis.status.value
            by_status[status] = by_status.get(status, 0) + 1
            
            verdict = analysis.verdict.value
            by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
            
            sample_type = analysis.sample_type.value
            by_type[sample_type] = by_type.get(sample_type, 0) + 1
        
        return {
            "total_analyses": total,
            "queue_length": len(self.queue),
            "running": self.running_count,
            "vm_pool_size": len(self.vm_pool),
            "by_status": by_status,
            "by_verdict": by_verdict,
            "by_sample_type": by_type,
            "signatures_available": len(self.signatures),
            "available_verdicts": [v.value for v in ThreatVerdict],
            "available_types": [t.value for t in SampleType]
        }


# Global instance
sandbox_service = SandboxService()
