"""
Automated Threat Correlation Engine
=====================================
Automatically correlates detected threats with threat intelligence feeds
and enriches threat data with:

- Attribution information
- Campaign/APT group associations
- Related indicators (IOCs)
- Recommended mitigations
- Historical context
"""

import os
import json
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib
import re

logger = logging.getLogger(__name__)

# =============================================================================
# DATA MODELS
# =============================================================================

class CorrelationConfidence(Enum):
    HIGH = "high"       # Multiple strong matches
    MEDIUM = "medium"   # Some matches
    LOW = "low"         # Weak correlation
    NONE = "none"       # No correlation found

@dataclass
class ThreatAttribution:
    """Attribution information for a threat"""
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    malware_family: Optional[str] = None
    confidence: str = "low"
    sources: List[str] = field(default_factory=list)
    
@dataclass
class RelatedIndicator:
    """Related IOC found during correlation"""
    ioc_type: str
    value: str
    relationship: str  # e.g., "same_campaign", "same_actor", "infrastructure"
    source: str
    confidence: int = 50

@dataclass
class Mitigation:
    """Recommended mitigation action"""
    action: str
    priority: str  # critical, high, medium, low
    description: str
    automated: bool = False

@dataclass
class CorrelationResult:
    """Complete correlation result for a threat"""
    threat_id: str
    correlation_id: str
    timestamp: str
    confidence: str
    attribution: ThreatAttribution
    matched_indicators: List[Dict] = field(default_factory=list)
    related_indicators: List[RelatedIndicator] = field(default_factory=list)
    mitigations: List[Mitigation] = field(default_factory=list)
    historical_context: Dict[str, Any] = field(default_factory=dict)
    enrichment_data: Dict[str, Any] = field(default_factory=dict)
    auto_actions_taken: List[str] = field(default_factory=list)

# =============================================================================
# KNOWN THREAT ACTORS & CAMPAIGNS
# =============================================================================

# APT/Threat Actor signatures and indicators
THREAT_ACTORS = {
    "apt28": {
        "names": ["APT28", "Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"],
        "ttps": ["spearphishing", "watering_hole", "zero_day"],
        "malware": ["XAgent", "Seduploader", "Zebrocy"],
        "industries": ["government", "military", "defense"],
        "origin": "Russia"
    },
    "apt29": {
        "names": ["APT29", "Cozy Bear", "The Dukes", "NOBELIUM"],
        "ttps": ["supply_chain", "cloud_exploitation", "spearphishing"],
        "malware": ["SUNBURST", "TEARDROP", "WellMess"],
        "industries": ["government", "technology", "healthcare"],
        "origin": "Russia"
    },
    "lazarus": {
        "names": ["Lazarus Group", "Hidden Cobra", "ZINC", "APT38"],
        "ttps": ["cryptocurrency_theft", "ransomware", "supply_chain"],
        "malware": ["WannaCry", "FALLCHILL", "AppleJeus"],
        "industries": ["financial", "cryptocurrency", "defense"],
        "origin": "North Korea"
    },
    "apt41": {
        "names": ["APT41", "BARIUM", "Winnti", "Double Dragon"],
        "ttps": ["supply_chain", "ransomware", "espionage"],
        "malware": ["ShadowPad", "Winnti", "PlugX"],
        "industries": ["gaming", "healthcare", "technology"],
        "origin": "China"
    },
    "fin7": {
        "names": ["FIN7", "Carbanak", "Carbon Spider"],
        "ttps": ["pos_malware", "spearphishing", "social_engineering"],
        "malware": ["Carbanak", "GRIFFON", "BIRDWATCH"],
        "industries": ["retail", "hospitality", "financial"],
        "origin": "Eastern Europe"
    }
}

# Campaign patterns
CAMPAIGN_PATTERNS = {
    "ransomware": {
        "indicators": ["encrypted", "ransom", "bitcoin", "decrypt", "locked"],
        "file_extensions": [".encrypted", ".locked", ".crypt", ".wcry"],
        "severity": "critical"
    },
    "cryptomining": {
        "indicators": ["xmrig", "monero", "stratum", "pool", "miner", "hashrate"],
        "ports": [3333, 4444, 5555, 14444, 45700],
        "severity": "high"
    },
    "botnet": {
        "indicators": ["c2", "beacon", "callback", "bot", "zombie"],
        "behaviors": ["periodic_connection", "encrypted_traffic"],
        "severity": "critical"
    },
    "data_exfiltration": {
        "indicators": ["exfil", "upload", "transfer", "staging"],
        "behaviors": ["large_outbound", "dns_tunneling"],
        "severity": "critical"
    }
}

# =============================================================================
# MITIGATION LIBRARY
# =============================================================================

MITIGATION_LIBRARY = {
    "malware": [
        Mitigation("isolate_host", "critical", "Immediately isolate the affected host from the network", True),
        Mitigation("kill_process", "critical", "Terminate the malicious process", True),
        Mitigation("quarantine_file", "high", "Move malicious file to quarantine", True),
        Mitigation("scan_related_hosts", "high", "Scan hosts that communicated with infected system", False),
        Mitigation("reset_credentials", "medium", "Reset credentials for affected users", False),
    ],
    "ransomware": [
        Mitigation("isolate_host", "critical", "Immediately isolate to prevent spread", True),
        Mitigation("disable_smb", "critical", "Disable SMB on network segment", True),
        Mitigation("backup_verify", "high", "Verify backup integrity before restoration", False),
        Mitigation("incident_response", "high", "Engage incident response team", False),
        Mitigation("law_enforcement", "medium", "Consider reporting to law enforcement", False),
    ],
    "botnet": [
        Mitigation("block_c2", "critical", "Block communication to C2 server", True),
        Mitigation("sinkhole_dns", "high", "Sinkhole malicious DNS queries", True),
        Mitigation("network_forensics", "high", "Capture network traffic for analysis", False),
        Mitigation("identify_scope", "medium", "Identify all infected hosts in network", False),
    ],
    "ai_agent": [
        Mitigation("rate_limit", "critical", "Apply aggressive rate limiting", True),
        Mitigation("block_ip", "critical", "Block source IP address", True),
        Mitigation("captcha_challenge", "high", "Require CAPTCHA for suspicious requests", False),
        Mitigation("behavioral_analysis", "medium", "Deep behavioral analysis of traffic", False),
    ],
    "phishing": [
        Mitigation("block_sender", "high", "Block sender domain/address", True),
        Mitigation("user_notification", "high", "Notify targeted users", False),
        Mitigation("credential_reset", "medium", "Reset credentials if clicked", False),
        Mitigation("awareness_training", "low", "Schedule security awareness training", False),
    ],
    "default": [
        Mitigation("investigate", "high", "Investigate threat indicators", False),
        Mitigation("monitor", "medium", "Increase monitoring on affected systems", False),
        Mitigation("document", "low", "Document findings for future reference", False),
    ]
}

# =============================================================================
# THREAT CORRELATION ENGINE
# =============================================================================

class ThreatCorrelationEngine:
    """
    Automated threat correlation and enrichment engine.
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
        
        self.threat_intel = None  # Will be set from threat_intel module
        self.correlation_cache: Dict[str, CorrelationResult] = {}
        self.auto_correlate_enabled = True
        self._initialized = True
    
    @classmethod
    def set_database(cls, db):
        cls._db = db
    
    def set_threat_intel(self, threat_intel):
        """Set threat intelligence manager reference"""
        self.threat_intel = threat_intel
    
    async def correlate_threat(self, threat: Dict) -> CorrelationResult:
        """
        Perform comprehensive correlation analysis on a threat.
        """
        threat_id = threat.get("id", "unknown")
        correlation_id = hashlib.md5(f"{threat_id}-{datetime.now().isoformat()}".encode()).hexdigest()[:16]
        
        logger.info(f"Starting correlation for threat {threat_id}")
        
        # Initialize result
        result = CorrelationResult(
            threat_id=threat_id,
            correlation_id=correlation_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            confidence=CorrelationConfidence.NONE.value,
            attribution=ThreatAttribution()
        )
        
        try:
            # Step 1: Check threat intel feeds for IOC matches
            matched_indicators = await self._check_threat_intel(threat)
            result.matched_indicators = matched_indicators
            
            # Step 2: Identify threat actor/campaign
            attribution = self._identify_attribution(threat, matched_indicators)
            result.attribution = attribution
            
            # Step 3: Find related indicators
            related = self._find_related_indicators(threat, matched_indicators)
            result.related_indicators = related
            
            # Step 4: Generate mitigations
            mitigations = self._generate_mitigations(threat, attribution)
            result.mitigations = mitigations
            
            # Step 5: Historical context
            historical = await self._get_historical_context(threat)
            result.historical_context = historical
            
            # Step 6: Enrichment data
            enrichment = self._generate_enrichment(threat, attribution, matched_indicators)
            result.enrichment_data = enrichment
            
            # Step 7: Calculate confidence
            result.confidence = self._calculate_confidence(result)
            
            # Step 8: Execute auto-actions if enabled
            if self.auto_correlate_enabled:
                actions = await self._execute_auto_actions(threat, result)
                result.auto_actions_taken = actions
            
            # Cache result
            self.correlation_cache[threat_id] = result
            
            # Store in database
            if self._db is not None:
                await self._db.threat_correlations.insert_one(asdict(result))
            
            logger.info(f"Correlation complete for {threat_id}: confidence={result.confidence}")
            
        except Exception as e:
            logger.error(f"Correlation error for {threat_id}: {e}")
            result.enrichment_data["error"] = str(e)
        
        return result
    
    async def _check_threat_intel(self, threat: Dict) -> List[Dict]:
        """Check threat against threat intelligence feeds"""
        matched = []
        
        if not self.threat_intel:
            return matched
        
        # Extract IOCs from threat
        iocs_to_check = []
        
        # Source IP
        if threat.get("source_ip"):
            iocs_to_check.append(("ip", threat["source_ip"]))
        
        # Indicators field
        for indicator in threat.get("indicators", []):
            # Try to detect type
            iocs_to_check.append((None, indicator))
        
        # Check description for IPs, domains, hashes
        description = threat.get("description", "")
        
        # IP pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        for ip in re.findall(ip_pattern, description):
            iocs_to_check.append(("ip", ip))
        
        # Hash patterns
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        for h in re.findall(md5_pattern, description):
            iocs_to_check.append(("md5", h))
        for h in re.findall(sha256_pattern, description):
            iocs_to_check.append(("sha256", h))
        
        # Check each IOC
        for ioc_type, value in iocs_to_check:
            try:
                match = self.threat_intel.check_indicator(value, ioc_type)
                if match.matched and match.indicator:
                    matched.append({
                        "value": value,
                        "type": match.query_type,
                        "source": match.indicator.source,
                        "threat_level": match.indicator.threat_level,
                        "description": match.indicator.description,
                        "confidence": match.indicator.confidence
                    })
            except Exception as e:
                logger.debug(f"IOC check failed for {value}: {e}")
        
        return matched
    
    def _identify_attribution(self, threat: Dict, matched_indicators: List[Dict]) -> ThreatAttribution:
        """Identify threat actor and campaign attribution"""
        attribution = ThreatAttribution()
        
        threat_type = threat.get("type", "").lower()
        threat_name = threat.get("name", "").lower()
        description = threat.get("description", "").lower()
        indicators = threat.get("indicators", [])
        
        combined_text = f"{threat_name} {description} {' '.join(str(i).lower() for i in indicators)}"
        
        # Check for known threat actors
        best_match = None
        best_score = 0
        
        for actor_id, actor_info in THREAT_ACTORS.items():
            score = 0
            
            # Check name matches
            for name in actor_info["names"]:
                if name.lower() in combined_text:
                    score += 30
            
            # Check malware matches
            for malware in actor_info.get("malware", []):
                if malware.lower() in combined_text:
                    score += 20
            
            # Check TTP matches
            for ttp in actor_info.get("ttps", []):
                if ttp in combined_text:
                    score += 10
            
            if score > best_score:
                best_score = score
                best_match = actor_id
        
        if best_match and best_score >= 20:
            actor_info = THREAT_ACTORS[best_match]
            attribution.threat_actor = actor_info["names"][0]
            attribution.confidence = "high" if best_score >= 50 else "medium" if best_score >= 30 else "low"
            attribution.sources = ["internal_correlation"]
        
        # Check for campaign patterns
        for campaign_id, campaign_info in CAMPAIGN_PATTERNS.items():
            for indicator in campaign_info.get("indicators", []):
                if indicator in combined_text:
                    attribution.campaign = campaign_id.title()
                    break
        
        # Check matched indicators for additional context
        for match in matched_indicators:
            if match.get("source"):
                if match["source"] not in attribution.sources:
                    attribution.sources.append(match["source"])
        
        # Try to identify malware family from threat name/description
        malware_keywords = ["ransomware", "trojan", "worm", "backdoor", "rootkit", "keylogger", "spyware"]
        for keyword in malware_keywords:
            if keyword in combined_text:
                attribution.malware_family = keyword.title()
                break
        
        return attribution
    
    def _find_related_indicators(self, threat: Dict, matched_indicators: List[Dict]) -> List[RelatedIndicator]:
        """Find related indicators based on correlation"""
        related = []
        
        # If we matched against threat feeds, check for related IOCs
        for match in matched_indicators:
            # Add the matched indicator as related
            related.append(RelatedIndicator(
                ioc_type=match.get("type", "unknown"),
                value=match.get("value", ""),
                relationship="direct_match",
                source=match.get("source", "threat_intel"),
                confidence=match.get("confidence", 50)
            ))
        
        # Check if source IP is related to other threats
        source_ip = threat.get("source_ip")
        if source_ip and self._db is not None:
            # Would query DB for other threats from same IP
            related.append(RelatedIndicator(
                ioc_type="ip",
                value=source_ip,
                relationship="source_infrastructure",
                source="internal_correlation",
                confidence=70
            ))
        
        return related[:20]  # Limit to 20 related indicators
    
    def _generate_mitigations(self, threat: Dict, attribution: ThreatAttribution) -> List[Mitigation]:
        """Generate recommended mitigations based on threat type"""
        mitigations = []
        
        threat_type = threat.get("type", "").lower()
        severity = threat.get("severity", "medium").lower()
        
        # Get type-specific mitigations
        if "ransomware" in threat_type or attribution.campaign == "Ransomware":
            mitigations.extend(MITIGATION_LIBRARY["ransomware"])
        elif "malware" in threat_type:
            mitigations.extend(MITIGATION_LIBRARY["malware"])
        elif "botnet" in threat_type or attribution.campaign == "Botnet":
            mitigations.extend(MITIGATION_LIBRARY["botnet"])
        elif "ai" in threat_type or "agent" in threat_type:
            mitigations.extend(MITIGATION_LIBRARY["ai_agent"])
        elif "phishing" in threat_type:
            mitigations.extend(MITIGATION_LIBRARY["phishing"])
        else:
            mitigations.extend(MITIGATION_LIBRARY["default"])
        
        # Prioritize based on severity
        if severity == "critical":
            for m in mitigations:
                if m.priority in ["high", "medium"]:
                    m.priority = "critical"
        
        return mitigations
    
    async def _get_historical_context(self, threat: Dict) -> Dict[str, Any]:
        """Get historical context for the threat"""
        context = {
            "first_seen": threat.get("created_at"),
            "related_threats_count": 0,
            "previous_occurrences": 0,
            "trend": "unknown"
        }
        
        if self._db is not None:
            try:
                # Count related threats by type
                threat_type = threat.get("type")
                if threat_type:
                    count = await self._db.threats.count_documents({"type": threat_type})
                    context["related_threats_count"] = count
                
                # Check for previous occurrences from same source
                source_ip = threat.get("source_ip")
                if source_ip:
                    prev_count = await self._db.threats.count_documents({"source_ip": source_ip})
                    context["previous_occurrences"] = prev_count
                    
                    if prev_count > 5:
                        context["trend"] = "increasing"
                    elif prev_count > 1:
                        context["trend"] = "recurring"
                    else:
                        context["trend"] = "new"
                        
            except Exception as e:
                logger.debug(f"Historical context error: {e}")
        
        return context
    
    def _generate_enrichment(self, threat: Dict, attribution: ThreatAttribution, matched: List[Dict]) -> Dict[str, Any]:
        """Generate enriched threat data"""
        enrichment = {
            "threat_score": self._calculate_threat_score(threat, attribution, matched),
            "kill_chain_phase": self._identify_kill_chain_phase(threat),
            "mitre_tactics": self._map_to_mitre(threat),
            "recommended_actions": [],
            "ioc_summary": {
                "total_matched": len(matched),
                "sources": list(set(m.get("source", "") for m in matched)),
                "types": list(set(m.get("type", "") for m in matched))
            }
        }
        
        # Add recommended actions based on threat score
        if enrichment["threat_score"] >= 80:
            enrichment["recommended_actions"] = ["immediate_isolation", "incident_response", "forensic_analysis"]
        elif enrichment["threat_score"] >= 60:
            enrichment["recommended_actions"] = ["enhanced_monitoring", "containment", "investigation"]
        else:
            enrichment["recommended_actions"] = ["monitoring", "documentation"]
        
        return enrichment
    
    def _calculate_threat_score(self, threat: Dict, attribution: ThreatAttribution, matched: List[Dict]) -> int:
        """Calculate overall threat score (0-100)"""
        score = 0
        
        # Base score from severity
        severity_scores = {"critical": 40, "high": 30, "medium": 20, "low": 10}
        score += severity_scores.get(threat.get("severity", "medium").lower(), 20)
        
        # Attribution confidence bonus
        if attribution.confidence == "high":
            score += 20
        elif attribution.confidence == "medium":
            score += 10
        
        # Known threat actor bonus
        if attribution.threat_actor:
            score += 15
        
        # Matched indicators bonus
        score += min(len(matched) * 5, 25)
        
        return min(100, score)
    
    def _identify_kill_chain_phase(self, threat: Dict) -> str:
        """Identify Cyber Kill Chain phase"""
        threat_type = threat.get("type", "").lower()
        description = threat.get("description", "").lower()
        
        if any(k in description for k in ["reconnaissance", "scanning", "enumeration"]):
            return "Reconnaissance"
        elif any(k in description for k in ["exploit", "vulnerability", "cve"]):
            return "Weaponization/Exploitation"
        elif any(k in description for k in ["download", "dropper", "payload"]):
            return "Delivery"
        elif any(k in description for k in ["install", "persistence", "registry"]):
            return "Installation"
        elif any(k in description for k in ["c2", "beacon", "callback", "command"]):
            return "Command & Control"
        elif any(k in description for k in ["exfil", "steal", "extract", "encrypt"]):
            return "Actions on Objectives"
        else:
            return "Unknown"
    
    def _map_to_mitre(self, threat: Dict) -> List[str]:
        """Map threat to MITRE ATT&CK tactics"""
        tactics = []
        threat_type = threat.get("type", "").lower()
        description = threat.get("description", "").lower()
        
        mitre_mapping = {
            "Initial Access": ["phishing", "exploit", "drive-by"],
            "Execution": ["script", "command", "powershell", "payload"],
            "Persistence": ["registry", "startup", "scheduled", "service"],
            "Privilege Escalation": ["escalat", "root", "admin", "sudo"],
            "Defense Evasion": ["obfuscat", "encrypt", "pack", "hide"],
            "Credential Access": ["credential", "password", "hash", "mimikatz"],
            "Discovery": ["scan", "enumerat", "discover", "recon"],
            "Lateral Movement": ["lateral", "spread", "pivot", "smb"],
            "Collection": ["collect", "keylog", "screen", "clipboard"],
            "Exfiltration": ["exfil", "upload", "transfer", "steal"],
            "Impact": ["ransomware", "encrypt", "destroy", "wipe"]
        }
        
        for tactic, keywords in mitre_mapping.items():
            for keyword in keywords:
                if keyword in description or keyword in threat_type:
                    if tactic not in tactics:
                        tactics.append(tactic)
                    break
        
        return tactics if tactics else ["Unknown"]
    
    def _calculate_confidence(self, result: CorrelationResult) -> str:
        """Calculate overall correlation confidence"""
        score = 0
        
        # Matched indicators
        score += len(result.matched_indicators) * 10
        
        # Attribution confidence
        if result.attribution.confidence == "high":
            score += 30
        elif result.attribution.confidence == "medium":
            score += 20
        elif result.attribution.confidence == "low":
            score += 10
        
        # Related indicators
        score += len(result.related_indicators) * 5
        
        # Historical context
        if result.historical_context.get("previous_occurrences", 0) > 0:
            score += 10
        
        if score >= 50:
            return CorrelationConfidence.HIGH.value
        elif score >= 30:
            return CorrelationConfidence.MEDIUM.value
        elif score >= 10:
            return CorrelationConfidence.LOW.value
        else:
            return CorrelationConfidence.NONE.value
    
    async def _execute_auto_actions(self, threat: Dict, result: CorrelationResult) -> List[str]:
        """Execute automated response actions"""
        actions_taken = []
        
        # Only execute for high-confidence, critical threats
        if result.confidence not in ["high", "medium"]:
            return actions_taken
        
        severity = threat.get("severity", "").lower()
        if severity not in ["critical", "high"]:
            return actions_taken
        
        # Auto-block source IP if matched in threat feeds
        source_ip = threat.get("source_ip")
        if source_ip and any(m.get("type") == "ip" for m in result.matched_indicators):
            # Would call threat_response.block_ip here
            actions_taken.append(f"auto_block_ip:{source_ip}")
            logger.info(f"Auto-action: Would block IP {source_ip}")
        
        # Log the correlation
        if self._db is not None:
            await self._db.auto_actions.insert_one({
                "threat_id": threat.get("id"),
                "correlation_id": result.correlation_id,
                "actions": actions_taken,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        
        return actions_taken
    
    async def correlate_all_active_threats(self) -> List[CorrelationResult]:
        """Correlate all active threats"""
        results = []
        
        if self._db is None:
            return results
        
        threats = await self._db.threats.find(
            {"status": "active"},
            {"_id": 0}
        ).to_list(100)
        
        for threat in threats:
            result = await self.correlate_threat(threat)
            results.append(result)
        
        return results
    
    def get_correlation(self, threat_id: str) -> Optional[CorrelationResult]:
        """Get cached correlation result"""
        return self.correlation_cache.get(threat_id)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get correlation engine statistics"""
        return {
            "cached_correlations": len(self.correlation_cache),
            "auto_correlate_enabled": self.auto_correlate_enabled,
            "known_threat_actors": len(THREAT_ACTORS),
            "campaign_patterns": len(CAMPAIGN_PATTERNS)
        }


# Global instance
correlation_engine = ThreatCorrelationEngine()
