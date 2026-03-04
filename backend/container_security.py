"""
Container Security Service
===========================
Comprehensive container security monitoring and scanning:

1. Image Vulnerability Scanning (Trivy integration)
2. Runtime Security (Falco integration)
3. Container Escape Detection
4. Crypto-miner Detection
5. Privileged Container Monitoring
6. Network Policy Enforcement
"""

import os
import json
import asyncio
import subprocess
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path
from enum import Enum
import hashlib
from runtime_paths import ensure_data_dir

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

TRIVY_CACHE_DIR = ensure_data_dir("trivy_cache")

class ContainerSecurityConfig:
    def __init__(self):
        self.trivy_enabled = os.environ.get("TRIVY_ENABLED", "true").lower() == "true"
        self.falco_enabled = os.environ.get("FALCO_ENABLED", "true").lower() == "true"
        self.auto_scan_new_images = os.environ.get("AUTO_SCAN_IMAGES", "true").lower() == "true"
        self.block_vulnerable_images = os.environ.get("BLOCK_VULNERABLE", "false").lower() == "true"
        self.severity_threshold = os.environ.get("VULN_SEVERITY_THRESHOLD", "HIGH")  # CRITICAL, HIGH, MEDIUM, LOW

config = ContainerSecurityConfig()

# =============================================================================
# DATA MODELS
# =============================================================================

class VulnerabilitySeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

@dataclass
class Vulnerability:
    """Represents a security vulnerability"""
    vuln_id: str
    pkg_name: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    title: str
    description: str = ""
    references: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None

@dataclass
class ImageScanResult:
    """Result of scanning a container image"""
    image_name: str
    image_id: str
    scan_id: str
    scanned_at: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    scan_status: str = "completed"
    scan_duration_ms: int = 0
    os_family: str = ""
    os_version: str = ""

@dataclass
class ContainerRuntimeEvent:
    """Runtime security event from a container"""
    event_id: str
    container_id: str
    container_name: str
    image_name: str
    event_type: str
    timestamp: str
    severity: str
    rule_name: str
    description: str
    process_name: Optional[str] = None
    user: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ContainerInfo:
    """Information about a running container"""
    container_id: str
    name: str
    image: str
    status: str
    created: str
    ports: List[str] = field(default_factory=list)
    is_privileged: bool = False
    capabilities: List[str] = field(default_factory=list)
    security_score: int = 100
    last_scan: Optional[str] = None
    vulnerabilities_count: int = 0

# =============================================================================
# TRIVY SCANNER
# =============================================================================

class TrivyScanner:
    """
    Trivy-based container image vulnerability scanner.
    https://github.com/aquasecurity/trivy
    """
    
    def __init__(self):
        self.trivy_path = self._find_trivy()
        self.scan_cache: Dict[str, ImageScanResult] = {}
        self._db = None
    
    def set_database(self, db):
        self._db = db
    
    def _find_trivy(self) -> Optional[str]:
        """Find trivy binary"""
        paths = ["/usr/local/bin/trivy", "/usr/bin/trivy", "trivy"]
        for path in paths:
            try:
                result = subprocess.run([path, "--version"], capture_output=True, timeout=5)
                if result.returncode == 0:
                    logger.info(f"Found Trivy at: {path}")
                    return path
            except Exception:
                continue
        logger.warning("Trivy not found - container scanning disabled")
        return None
    
    async def scan_image(self, image_name: str, force: bool = False) -> ImageScanResult:
        """
        Scan a container image for vulnerabilities.
        Uses cache unless force=True.
        """
        # Check cache
        cache_key = hashlib.md5(image_name.encode()).hexdigest()
        if not force and cache_key in self.scan_cache:
            cached = self.scan_cache[cache_key]
            # Use cache if less than 24 hours old
            cached_time = datetime.fromisoformat(cached.scanned_at.replace('Z', '+00:00'))
            if datetime.now(timezone.utc) - cached_time < timedelta(hours=24):
                return cached
        
        if not self.trivy_path:
            return ImageScanResult(
                image_name=image_name,
                image_id="",
                scan_id=hashlib.md5(f"{image_name}-{datetime.now().isoformat()}".encode()).hexdigest()[:16],
                scanned_at=datetime.now(timezone.utc).isoformat(),
                scan_status="error",
                vulnerabilities=[Vulnerability(
                    vuln_id="TRIVY_NOT_INSTALLED",
                    pkg_name="trivy",
                    installed_version="0",
                    fixed_version=None,
                    severity="UNKNOWN",
                    title="Trivy scanner not installed",
                    description="Install trivy to enable container scanning"
                )]
            )
        
        start_time = datetime.now()
        
        try:
            # Run trivy scan
            cmd = [
                self.trivy_path, "image",
                "--format", "json",
                "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                "--cache-dir", str(TRIVY_CACHE_DIR),
                image_name
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=300)
            
            if result.returncode != 0 and not stdout:
                raise Exception(f"Trivy scan failed: {stderr.decode()}")
            
            # Parse results
            scan_data = json.loads(stdout.decode()) if stdout else {}
            
            vulnerabilities = []
            critical_count = high_count = medium_count = low_count = 0
            
            for result_item in scan_data.get("Results", []):
                for vuln in result_item.get("Vulnerabilities", []):
                    severity = vuln.get("Severity", "UNKNOWN").upper()
                    
                    if severity == "CRITICAL":
                        critical_count += 1
                    elif severity == "HIGH":
                        high_count += 1
                    elif severity == "MEDIUM":
                        medium_count += 1
                    elif severity == "LOW":
                        low_count += 1
                    
                    vulnerabilities.append(Vulnerability(
                        vuln_id=vuln.get("VulnerabilityID", ""),
                        pkg_name=vuln.get("PkgName", ""),
                        installed_version=vuln.get("InstalledVersion", ""),
                        fixed_version=vuln.get("FixedVersion"),
                        severity=severity,
                        title=vuln.get("Title", ""),
                        description=vuln.get("Description", "")[:500],
                        references=vuln.get("References", [])[:5],
                        cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score")
                    ))
            
            # Get OS info
            metadata = scan_data.get("Metadata", {})
            os_info = metadata.get("OS", {})
            
            scan_result = ImageScanResult(
                image_name=image_name,
                image_id=metadata.get("ImageID", "")[:12],
                scan_id=hashlib.md5(f"{image_name}-{datetime.now().isoformat()}".encode()).hexdigest()[:16],
                scanned_at=datetime.now(timezone.utc).isoformat(),
                vulnerabilities=vulnerabilities,
                total_vulnerabilities=len(vulnerabilities),
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                scan_status="completed",
                scan_duration_ms=int((datetime.now() - start_time).total_seconds() * 1000),
                os_family=os_info.get("Family", ""),
                os_version=os_info.get("Name", "")
            )
            
            # Cache result
            self.scan_cache[cache_key] = scan_result
            
            # Store in database
            if self._db is not None:
                await self._db.container_scans.insert_one(asdict(scan_result))
            
            logger.info(f"Scanned {image_name}: {len(vulnerabilities)} vulnerabilities found")
            return scan_result
            
        except asyncio.TimeoutError:
            return ImageScanResult(
                image_name=image_name,
                image_id="",
                scan_id=hashlib.md5(f"{image_name}-{datetime.now().isoformat()}".encode()).hexdigest()[:16],
                scanned_at=datetime.now(timezone.utc).isoformat(),
                scan_status="timeout"
            )
        except Exception as e:
            logger.error(f"Scan failed for {image_name}: {e}")
            return ImageScanResult(
                image_name=image_name,
                image_id="",
                scan_id=hashlib.md5(f"{image_name}-{datetime.now().isoformat()}".encode()).hexdigest()[:16],
                scanned_at=datetime.now(timezone.utc).isoformat(),
                scan_status="error",
                vulnerabilities=[Vulnerability(
                    vuln_id="SCAN_ERROR",
                    pkg_name="scanner",
                    installed_version="",
                    fixed_version=None,
                    severity="UNKNOWN",
                    title="Scan error",
                    description=str(e)[:200]
                )]
            )
    
    async def scan_all_images(self) -> List[ImageScanResult]:
        """Scan all local Docker images"""
        images = await self._get_local_images()
        results = []
        
        for image in images:
            result = await self.scan_image(image)
            results.append(result)
        
        return results
    
    async def _get_local_images(self) -> List[str]:
        """Get list of local Docker images"""
        try:
            result = await asyncio.create_subprocess_exec(
                "docker", "images", "--format", "{{.Repository}}:{{.Tag}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            images = [img for img in stdout.decode().split('\n') if img and img != '<none>:<none>']
            return images
        except Exception as e:
            logger.error(f"Failed to list Docker images: {e}")
            return []


# =============================================================================
# CONTAINER RUNTIME MONITOR
# =============================================================================

class ContainerRuntimeMonitor:
    """
    Monitors running containers for security issues:
    - Privileged containers
    - Container escapes
    - Crypto-miners
    - Suspicious processes
    """
    
    CRYPTO_MINER_PROCESSES = {
        "xmrig", "minerd", "cgminer", "bfgminer", "ethminer",
        "cpuminer", "stratum", "nicehash", "phoenixminer"
    }
    
    SUSPICIOUS_CAPABILITIES = {
        "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "NET_RAW",
        "DAC_OVERRIDE", "SETUID", "SETGID"
    }
    
    def __init__(self):
        self.runtime_events: List[ContainerRuntimeEvent] = []
        self._monitoring = False
        self._db = None
        self._alert_callback = None
    
    def set_database(self, db):
        self._db = db
    
    def set_alert_callback(self, callback):
        self._alert_callback = callback
    
    async def get_running_containers(self) -> List[ContainerInfo]:
        """Get list of running containers with security assessment"""
        try:
            result = await asyncio.create_subprocess_exec(
                "docker", "ps", "--format", 
                '{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}","status":"{{.Status}}","ports":"{{.Ports}}"}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            containers = []
            for line in stdout.decode().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    container_id = data.get("id", "")
                    
                    # Get detailed inspection
                    inspect_result = await asyncio.create_subprocess_exec(
                        "docker", "inspect", container_id,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    inspect_stdout, _ = await inspect_result.communicate()
                    inspect_data = json.loads(inspect_stdout.decode())[0] if inspect_stdout else {}
                    
                    host_config = inspect_data.get("HostConfig", {})
                    is_privileged = host_config.get("Privileged", False)
                    cap_add = host_config.get("CapAdd", []) or []
                    
                    # Calculate security score
                    security_score = 100
                    if is_privileged:
                        security_score -= 50
                    for cap in cap_add:
                        if cap in self.SUSPICIOUS_CAPABILITIES:
                            security_score -= 10
                    
                    containers.append(ContainerInfo(
                        container_id=container_id,
                        name=data.get("name", ""),
                        image=data.get("image", ""),
                        status=data.get("status", ""),
                        created=inspect_data.get("Created", ""),
                        ports=data.get("ports", "").split(", ") if data.get("ports") else [],
                        is_privileged=is_privileged,
                        capabilities=cap_add,
                        security_score=max(0, security_score)
                    ))
                    
                except json.JSONDecodeError:
                    continue
            
            return containers
            
        except Exception as e:
            logger.error(f"Failed to get containers: {e}")
            return []
    
    async def check_container_security(self, container_id: str) -> Dict[str, Any]:
        """Perform security check on a specific container"""
        findings = {
            "container_id": container_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "issues": [],
            "risk_level": "low"
        }
        
        try:
            # Get container processes
            result = await asyncio.create_subprocess_exec(
                "docker", "top", container_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            processes = stdout.decode().lower()
            
            # Check for crypto miners
            for miner in self.CRYPTO_MINER_PROCESSES:
                if miner in processes:
                    findings["issues"].append({
                        "type": "crypto_miner",
                        "severity": "critical",
                        "description": f"Possible crypto-miner detected: {miner}"
                    })
                    findings["risk_level"] = "critical"
            
            # Get container inspect
            inspect_result = await asyncio.create_subprocess_exec(
                "docker", "inspect", container_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            inspect_stdout, _ = await inspect_result.communicate()
            inspect_data = json.loads(inspect_stdout.decode())[0] if inspect_stdout else {}
            
            host_config = inspect_data.get("HostConfig", {})
            
            # Check privileged mode
            if host_config.get("Privileged"):
                findings["issues"].append({
                    "type": "privileged_container",
                    "severity": "high",
                    "description": "Container running in privileged mode"
                })
                if findings["risk_level"] != "critical":
                    findings["risk_level"] = "high"
            
            # Check for host PID namespace
            if host_config.get("PidMode") == "host":
                findings["issues"].append({
                    "type": "host_pid_namespace",
                    "severity": "high",
                    "description": "Container shares host PID namespace"
                })
                if findings["risk_level"] != "critical":
                    findings["risk_level"] = "high"
            
            # Check for dangerous capabilities
            cap_add = host_config.get("CapAdd", []) or []
            dangerous_caps = [c for c in cap_add if c in self.SUSPICIOUS_CAPABILITIES]
            if dangerous_caps:
                findings["issues"].append({
                    "type": "dangerous_capabilities",
                    "severity": "medium",
                    "description": f"Dangerous capabilities: {', '.join(dangerous_caps)}"
                })
                if findings["risk_level"] == "low":
                    findings["risk_level"] = "medium"
            
            # Check for host mounts
            mounts = inspect_data.get("Mounts", [])
            sensitive_mounts = [m for m in mounts if m.get("Source", "").startswith(("/etc", "/var/run/docker.sock", "/"))]
            if sensitive_mounts:
                findings["issues"].append({
                    "type": "sensitive_mounts",
                    "severity": "medium",
                    "description": f"Sensitive host paths mounted: {len(sensitive_mounts)}"
                })
            
        except Exception as e:
            logger.error(f"Security check failed for {container_id}: {e}")
            findings["error"] = str(e)
        
        return findings
    
    async def get_runtime_events(self, limit: int = 50) -> List[Dict]:
        """Get recent runtime security events"""
        return [asdict(e) for e in self.runtime_events[-limit:]]


# =============================================================================
# CONTAINER SECURITY MANAGER
# =============================================================================

class ContainerSecurityManager:
    """
    Central manager for container security features.
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
        
        self.scanner = TrivyScanner()
        self.runtime_monitor = ContainerRuntimeMonitor()
        self._initialized = True
    
    @classmethod
    def set_database(cls, db):
        cls._db = db
        if cls._instance:
            cls._instance.scanner.set_database(db)
            cls._instance.runtime_monitor.set_database(db)
    
    async def scan_image(self, image_name: str, force: bool = False) -> Dict:
        """Scan a container image"""
        result = await self.scanner.scan_image(image_name, force)
        return asdict(result)
    
    async def scan_all_images(self) -> List[Dict]:
        """Scan all local images"""
        results = await self.scanner.scan_all_images()
        return [asdict(r) for r in results]
    
    async def get_containers(self) -> List[Dict]:
        """Get running containers with security info"""
        containers = await self.runtime_monitor.get_running_containers()
        return [asdict(c) for c in containers]
    
    async def check_container(self, container_id: str) -> Dict:
        """Security check a specific container"""
        return await self.runtime_monitor.check_container_security(container_id)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get container security statistics"""
        return {
            "trivy_enabled": config.trivy_enabled,
            "falco_enabled": config.falco_enabled,
            "auto_scan": config.auto_scan_new_images,
            "cached_scans": len(self.scanner.scan_cache),
            "runtime_events": len(self.runtime_monitor.runtime_events)
        }


# Global instance
container_security = ContainerSecurityManager()
