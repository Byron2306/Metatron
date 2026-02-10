"""
Zero Trust Architecture - Security Service
Implements continuous verification and least-privilege access
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib
import logging

logger = logging.getLogger(__name__)

class TrustLevel(str, Enum):
    UNTRUSTED = "untrusted"      # 0-20: Block all access
    LOW = "low"                   # 21-40: Very limited access
    MEDIUM = "medium"             # 41-60: Standard access with MFA
    HIGH = "high"                 # 61-80: Full access to assigned resources
    TRUSTED = "trusted"           # 81-100: Admin-level access

class DeviceType(str, Enum):
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    MOBILE = "mobile"
    SERVER = "server"
    IOT = "iot"
    UNKNOWN = "unknown"

class AccessDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"  # Require additional verification

@dataclass
class DeviceTrust:
    device_id: str
    device_name: str
    device_type: DeviceType
    trust_score: int  # 0-100
    trust_level: TrustLevel
    last_verified: str
    os_info: Dict[str, str]
    security_posture: Dict[str, Any]
    is_compliant: bool
    compliance_issues: List[str]
    registered_at: str
    last_seen: str
    owner_id: Optional[str] = None

@dataclass
class AccessPolicy:
    id: str
    name: str
    description: str
    resource_pattern: str  # e.g., "/api/admin/*", "database:*"
    required_trust_level: TrustLevel
    require_mfa: bool
    allowed_device_types: List[DeviceType]
    allowed_networks: List[str]  # CIDR ranges
    time_restrictions: Optional[Dict[str, Any]] = None  # e.g., {"days": [1-5], "hours": [9, 17]}
    is_active: bool = True
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class AccessLog:
    id: str
    timestamp: str
    user_id: str
    device_id: str
    resource: str
    decision: AccessDecision
    trust_score: int
    factors: Dict[str, Any]
    policy_id: Optional[str] = None
    challenge_reason: Optional[str] = None

class ZeroTrustEngine:
    def __init__(self):
        self.devices: Dict[str, DeviceTrust] = {}
        self.policies: Dict[str, AccessPolicy] = {}
        self.access_logs: List[AccessLog] = []
        self._init_default_policies()
    
    def _init_default_policies(self):
        """Initialize default zero trust policies"""
        default_policies = [
            AccessPolicy(
                id="pol_admin_access",
                name="Admin Console Access",
                description="Requires high trust for admin operations",
                resource_pattern="/api/admin/*",
                required_trust_level=TrustLevel.HIGH,
                require_mfa=True,
                allowed_device_types=[DeviceType.WORKSTATION, DeviceType.LAPTOP],
                allowed_networks=["10.0.0.0/8", "192.168.0.0/16"]
            ),
            AccessPolicy(
                id="pol_settings_access",
                name="Settings Access",
                description="Medium trust for settings modifications",
                resource_pattern="/api/settings/*",
                required_trust_level=TrustLevel.MEDIUM,
                require_mfa=True,
                allowed_device_types=[DeviceType.WORKSTATION, DeviceType.LAPTOP, DeviceType.MOBILE],
                allowed_networks=[]  # Any network
            ),
            AccessPolicy(
                id="pol_readonly_access",
                name="Read-Only Dashboard",
                description="Low trust for read-only operations",
                resource_pattern="/api/dashboard/*",
                required_trust_level=TrustLevel.LOW,
                require_mfa=False,
                allowed_device_types=[d for d in DeviceType],
                allowed_networks=[]
            ),
            AccessPolicy(
                id="pol_threat_response",
                name="Threat Response Actions",
                description="High trust required for response actions",
                resource_pattern="/api/response/*",
                required_trust_level=TrustLevel.HIGH,
                require_mfa=True,
                allowed_device_types=[DeviceType.WORKSTATION, DeviceType.LAPTOP],
                allowed_networks=["10.0.0.0/8"]
            ),
            AccessPolicy(
                id="pol_quarantine_actions",
                name="Quarantine Actions",
                description="Medium trust for quarantine operations",
                resource_pattern="/api/quarantine/*",
                required_trust_level=TrustLevel.MEDIUM,
                require_mfa=False,
                allowed_device_types=[DeviceType.WORKSTATION, DeviceType.LAPTOP, DeviceType.SERVER],
                allowed_networks=[]
            )
        ]
        
        for policy in default_policies:
            self.policies[policy.id] = policy
    
    def calculate_trust_score(
        self,
        device_id: str,
        user_context: Dict[str, Any],
        request_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate dynamic trust score based on multiple factors"""
        score = 50  # Base score
        factors = {}
        
        # Factor 1: Device known/registered (0-20 points)
        device = self.devices.get(device_id)
        if device:
            if device.is_compliant:
                score += 20
                factors["device_registered"] = {"score": 20, "reason": "Known compliant device"}
            else:
                score += 10
                factors["device_registered"] = {"score": 10, "reason": "Known but non-compliant device"}
        else:
            score -= 10
            factors["device_registered"] = {"score": -10, "reason": "Unknown device"}
        
        # Factor 2: User authentication strength (0-15 points)
        auth_method = user_context.get("auth_method", "password")
        if auth_method == "mfa":
            score += 15
            factors["auth_method"] = {"score": 15, "reason": "MFA authenticated"}
        elif auth_method == "sso":
            score += 10
            factors["auth_method"] = {"score": 10, "reason": "SSO authenticated"}
        else:
            score += 5
            factors["auth_method"] = {"score": 5, "reason": "Password authenticated"}
        
        # Factor 3: Network location (0-15 points)
        source_ip = request_context.get("source_ip", "")
        if self._is_internal_ip(source_ip):
            score += 15
            factors["network"] = {"score": 15, "reason": "Internal network"}
        elif self._is_vpn_ip(source_ip):
            score += 10
            factors["network"] = {"score": 10, "reason": "VPN connection"}
        else:
            score += 0
            factors["network"] = {"score": 0, "reason": "External network"}
        
        # Factor 4: Time-based risk (0-10 points)
        current_hour = datetime.now(timezone.utc).hour
        if 9 <= current_hour <= 18:  # Business hours
            score += 10
            factors["time"] = {"score": 10, "reason": "Business hours"}
        elif 6 <= current_hour <= 22:  # Extended hours
            score += 5
            factors["time"] = {"score": 5, "reason": "Extended hours"}
        else:
            score -= 5
            factors["time"] = {"score": -5, "reason": "Off-hours access"}
        
        # Factor 5: User behavior anomaly (-20 to 0 points)
        anomaly_score = user_context.get("anomaly_score", 0)
        if anomaly_score > 0.8:
            score -= 20
            factors["behavior"] = {"score": -20, "reason": "High anomaly detected"}
        elif anomaly_score > 0.5:
            score -= 10
            factors["behavior"] = {"score": -10, "reason": "Moderate anomaly detected"}
        else:
            factors["behavior"] = {"score": 0, "reason": "Normal behavior"}
        
        # Factor 6: Recent security events (-15 to 0 points)
        recent_incidents = user_context.get("recent_incidents", 0)
        if recent_incidents > 3:
            score -= 15
            factors["incidents"] = {"score": -15, "reason": f"{recent_incidents} recent incidents"}
        elif recent_incidents > 0:
            score -= 5
            factors["incidents"] = {"score": -5, "reason": f"{recent_incidents} recent incident(s)"}
        else:
            factors["incidents"] = {"score": 0, "reason": "No recent incidents"}
        
        # Clamp score to 0-100
        score = max(0, min(100, score))
        
        # Determine trust level
        if score >= 81:
            trust_level = TrustLevel.TRUSTED
        elif score >= 61:
            trust_level = TrustLevel.HIGH
        elif score >= 41:
            trust_level = TrustLevel.MEDIUM
        elif score >= 21:
            trust_level = TrustLevel.LOW
        else:
            trust_level = TrustLevel.UNTRUSTED
        
        return {
            "score": score,
            "trust_level": trust_level.value,
            "factors": factors
        }
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is from internal network"""
        return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")
    
    def _is_vpn_ip(self, ip: str) -> bool:
        """Check if IP is from VPN range"""
        return ip.startswith("10.8.") or ip.startswith("10.9.")
    
    def evaluate_access(
        self,
        resource: str,
        device_id: str,
        user_context: Dict[str, Any],
        request_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluate access request against zero trust policies"""
        
        # Calculate trust score
        trust_result = self.calculate_trust_score(device_id, user_context, request_context)
        trust_score = trust_result["score"]
        trust_level = TrustLevel(trust_result["trust_level"])
        
        # Find matching policy
        matching_policy = None
        for policy in self.policies.values():
            if policy.is_active and self._matches_pattern(resource, policy.resource_pattern):
                matching_policy = policy
                break
        
        # Default decision
        decision = AccessDecision.ALLOW
        challenge_reason = None
        
        if matching_policy:
            # Check trust level
            required_level = matching_policy.required_trust_level
            if self._trust_level_value(trust_level) < self._trust_level_value(required_level):
                if self._trust_level_value(trust_level) < self._trust_level_value(TrustLevel.LOW):
                    decision = AccessDecision.DENY
                else:
                    decision = AccessDecision.CHALLENGE
                    challenge_reason = f"Trust level {trust_level.value} below required {required_level.value}"
            
            # Check MFA requirement
            if matching_policy.require_mfa and user_context.get("auth_method") != "mfa":
                decision = AccessDecision.CHALLENGE
                challenge_reason = "MFA required for this resource"
            
            # Check device type
            device = self.devices.get(device_id)
            if device and matching_policy.allowed_device_types:
                if device.device_type not in matching_policy.allowed_device_types:
                    decision = AccessDecision.DENY
        
        # Log the access attempt
        access_log = AccessLog(
            id=f"al_{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_context.get("user_id", "unknown"),
            device_id=device_id,
            resource=resource,
            decision=decision,
            trust_score=trust_score,
            factors=trust_result["factors"],
            policy_id=matching_policy.id if matching_policy else None,
            challenge_reason=challenge_reason
        )
        self.access_logs.append(access_log)
        
        # Keep only last 1000 logs
        if len(self.access_logs) > 1000:
            self.access_logs = self.access_logs[-1000:]
        
        return {
            "decision": decision.value,
            "trust_score": trust_score,
            "trust_level": trust_level.value,
            "factors": trust_result["factors"],
            "policy": matching_policy.name if matching_policy else None,
            "challenge_reason": challenge_reason,
            "log_id": access_log.id
        }
    
    def _matches_pattern(self, resource: str, pattern: str) -> bool:
        """Check if resource matches pattern (simple wildcard matching)"""
        if pattern.endswith("*"):
            return resource.startswith(pattern[:-1])
        return resource == pattern
    
    def _trust_level_value(self, level: TrustLevel) -> int:
        """Get numeric value for trust level comparison"""
        values = {
            TrustLevel.UNTRUSTED: 0,
            TrustLevel.LOW: 1,
            TrustLevel.MEDIUM: 2,
            TrustLevel.HIGH: 3,
            TrustLevel.TRUSTED: 4
        }
        return values.get(level, 0)
    
    def register_device(
        self,
        device_id: str,
        device_name: str,
        device_type: str,
        os_info: Dict[str, str],
        security_posture: Dict[str, Any],
        owner_id: Optional[str] = None
    ) -> Dict:
        """Register a new device"""
        # Calculate compliance
        compliance_issues = []
        if not security_posture.get("antivirus_enabled"):
            compliance_issues.append("Antivirus not enabled")
        if not security_posture.get("firewall_enabled"):
            compliance_issues.append("Firewall not enabled")
        if not security_posture.get("disk_encrypted"):
            compliance_issues.append("Disk not encrypted")
        if security_posture.get("os_outdated"):
            compliance_issues.append("Operating system outdated")
        
        is_compliant = len(compliance_issues) == 0
        
        # Calculate initial trust score
        trust_score = 70 if is_compliant else 40
        trust_level = TrustLevel.HIGH if is_compliant else TrustLevel.MEDIUM
        
        device = DeviceTrust(
            device_id=device_id,
            device_name=device_name,
            device_type=DeviceType(device_type),
            trust_score=trust_score,
            trust_level=trust_level,
            last_verified=datetime.now(timezone.utc).isoformat(),
            os_info=os_info,
            security_posture=security_posture,
            is_compliant=is_compliant,
            compliance_issues=compliance_issues,
            registered_at=datetime.now(timezone.utc).isoformat(),
            last_seen=datetime.now(timezone.utc).isoformat(),
            owner_id=owner_id
        )
        
        self.devices[device_id] = device
        result = asdict(device)
        result["device_type"] = device.device_type.value
        result["trust_level"] = device.trust_level.value
        return result
    
    def get_devices(self) -> List[Dict]:
        """Get all registered devices"""
        result = []
        for device in self.devices.values():
            d = asdict(device)
            d["device_type"] = device.device_type.value
            d["trust_level"] = device.trust_level.value
            result.append(d)
        return result
    
    def get_policies(self) -> List[Dict]:
        """Get all access policies"""
        result = []
        for policy in self.policies.values():
            p = asdict(policy)
            p["required_trust_level"] = policy.required_trust_level.value
            p["allowed_device_types"] = [d.value for d in policy.allowed_device_types]
            result.append(p)
        return result
    
    def create_policy(self, data: Dict) -> Dict:
        """Create a new access policy"""
        policy_id = f"pol_{uuid.uuid4().hex[:8]}"
        
        policy = AccessPolicy(
            id=policy_id,
            name=data["name"],
            description=data.get("description", ""),
            resource_pattern=data["resource_pattern"],
            required_trust_level=TrustLevel(data.get("required_trust_level", "medium")),
            require_mfa=data.get("require_mfa", False),
            allowed_device_types=[DeviceType(d) for d in data.get("allowed_device_types", [])],
            allowed_networks=data.get("allowed_networks", []),
            time_restrictions=data.get("time_restrictions")
        )
        
        self.policies[policy_id] = policy
        result = asdict(policy)
        result["required_trust_level"] = policy.required_trust_level.value
        result["allowed_device_types"] = [d.value for d in policy.allowed_device_types]
        return result
    
    def get_access_logs(self, limit: int = 50) -> List[Dict]:
        """Get recent access logs"""
        logs = sorted(self.access_logs, key=lambda x: x.timestamp, reverse=True)[:limit]
        return [asdict(l) for l in logs]
    
    def get_stats(self) -> Dict:
        """Get zero trust statistics"""
        total_devices = len(self.devices)
        compliant_devices = sum(1 for d in self.devices.values() if d.is_compliant)
        total_policies = len(self.policies)
        active_policies = sum(1 for p in self.policies.values() if p.is_active)
        
        # Access stats
        total_access = len(self.access_logs)
        allowed = sum(1 for l in self.access_logs if l.decision == AccessDecision.ALLOW)
        denied = sum(1 for l in self.access_logs if l.decision == AccessDecision.DENY)
        challenged = sum(1 for l in self.access_logs if l.decision == AccessDecision.CHALLENGE)
        
        # Average trust score
        recent_logs = self.access_logs[-100:] if self.access_logs else []
        avg_trust = sum(l.trust_score for l in recent_logs) / len(recent_logs) if recent_logs else 0
        
        return {
            "devices": {
                "total": total_devices,
                "compliant": compliant_devices,
                "non_compliant": total_devices - compliant_devices
            },
            "policies": {
                "total": total_policies,
                "active": active_policies
            },
            "access_decisions": {
                "total": total_access,
                "allowed": allowed,
                "denied": denied,
                "challenged": challenged,
                "allow_rate": round(allowed / total_access * 100, 1) if total_access > 0 else 0
            },
            "average_trust_score": round(avg_trust, 1),
            "trust_levels": [t.value for t in TrustLevel],
            "device_types": [d.value for d in DeviceType]
        }
    
    def trigger_remediation(self, device_id: str, reason: str, compliance_issues: List[str] = None) -> Dict:
        """
        Trigger a remediation command for a device that fails zero trust checks.
        Creates a pending command in the agent command system for manual approval.
        """
        device = self.devices.get(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}
        
        remediation_action = {
            "device_id": device_id,
            "device_name": device.device_name,
            "reason": reason,
            "trust_score": device.trust_score,
            "trust_level": device.trust_level.value,
            "compliance_issues": compliance_issues or device.compliance_issues,
            "triggered_at": datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Zero Trust remediation triggered for device {device_id}: {reason}")
        
        return {
            "success": True,
            "remediation": remediation_action,
            "message": "Remediation command queued for approval"
        }
    
    def block_device(self, device_id: str, reason: str = "Zero Trust violation") -> Dict:
        """Block a device and set its trust score to 0"""
        device = self.devices.get(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}
        
        # Update device trust
        device.trust_score = 0
        device.trust_level = TrustLevel.UNTRUSTED
        device.is_compliant = False
        device.compliance_issues.append(f"BLOCKED: {reason}")
        device.last_seen = datetime.now(timezone.utc).isoformat()
        
        logger.warning(f"Device {device_id} blocked: {reason}")
        
        return {
            "success": True,
            "device_id": device_id,
            "status": "blocked",
            "reason": reason
        }


# Global instance
zero_trust_engine = ZeroTrustEngine()
