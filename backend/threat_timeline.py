"""
Threat Timeline Reconstruction Service
======================================
Builds comprehensive timelines of threat events, responses, and impacts
for incident investigation and reporting.
"""
import os
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict, field
from enum import Enum

logger = logging.getLogger(__name__)

# =============================================================================
# DATA MODELS
# =============================================================================

class TimelineEventType(Enum):
    DETECTION = "detection"
    ALERT = "alert"
    RESPONSE = "response"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    FORENSICS = "forensics"
    NOTIFICATION = "notification"
    USER_ACTION = "user_action"
    ESCALATION = "escalation"
    RESOLUTION = "resolution"
    INDICATOR = "indicator"

@dataclass
class TimelineEvent:
    """A single event in the threat timeline"""
    id: str
    timestamp: str
    event_type: str
    title: str
    description: str
    severity: str
    source: str  # agent, system, user, etc.
    related_threat_id: Optional[str] = None
    related_alert_id: Optional[str] = None
    actor: Optional[str] = None
    target: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
@dataclass 
class ThreatTimeline:
    """Complete timeline for a threat incident"""
    threat_id: str
    threat_name: str
    threat_type: str
    severity: str
    status: str
    first_seen: str
    last_updated: str
    events: List[TimelineEvent] = field(default_factory=list)
    summary: Optional[str] = None
    impact_assessment: Optional[Dict[str, Any]] = None
    recommendations: List[str] = field(default_factory=list)

# =============================================================================
# TIMELINE BUILDER
# =============================================================================

class TimelineBuilder:
    """
    Builds and reconstructs threat timelines from various data sources.
    """
    
    _db = None
    
    @classmethod
    def set_database(cls, db):
        """Set the MongoDB database reference"""
        cls._db = db
    
    @classmethod
    async def build_timeline(cls, threat_id: str) -> Optional[ThreatTimeline]:
        """
        Build a complete timeline for a threat incident.
        
        Aggregates data from:
        - Threats collection
        - Alerts collection
        - Audit logs
        - Response actions
        - Quarantine entries
        - Agent events
        """
        if not cls._db:
            return None
        
        # Get the main threat
        threat = await cls._db.threats.find_one({"id": threat_id}, {"_id": 0})
        if not threat:
            return None
        
        events = []
        
        # 1. Initial detection event
        events.append(TimelineEvent(
            id=f"detection_{threat_id}",
            timestamp=threat.get("created_at", datetime.now(timezone.utc).isoformat()),
            event_type=TimelineEventType.DETECTION.value,
            title=f"Threat Detected: {threat.get('name', 'Unknown')}",
            description=threat.get("description", ""),
            severity=threat.get("severity", "medium"),
            source=threat.get("source_agent", "system"),
            related_threat_id=threat_id,
            target=threat.get("target_system"),
            details={
                "type": threat.get("type"),
                "source_ip": threat.get("source_ip"),
                "indicators": threat.get("indicators", [])
            }
        ))
        
        # 2. Related alerts
        alerts_cursor = cls._db.alerts.find(
            {"threat_id": threat_id}, {"_id": 0}
        ).sort("created_at", 1)
        async for alert in alerts_cursor:
            events.append(TimelineEvent(
                id=f"alert_{alert.get('id')}",
                timestamp=alert.get("created_at", ""),
                event_type=TimelineEventType.ALERT.value,
                title=f"Alert: {alert.get('title', 'Unknown')}",
                description=alert.get("message", ""),
                severity=alert.get("severity", "medium"),
                source=alert.get("source_agent", "system"),
                related_threat_id=threat_id,
                related_alert_id=alert.get("id"),
                details={"status": alert.get("status")}
            ))
        
        # 3. Response actions from audit logs
        response_logs = await cls._db.audit_logs.find({
            "category": "threat_response",
            "target_id": threat_id
        }, {"_id": 0}).sort("timestamp", 1).to_list(100)
        
        for log in response_logs:
            events.append(TimelineEvent(
                id=f"response_{log.get('id')}",
                timestamp=log.get("timestamp", ""),
                event_type=TimelineEventType.RESPONSE.value,
                title=f"Response: {log.get('action', 'Unknown')}",
                description=log.get("description", ""),
                severity="info",
                source=log.get("actor", "system"),
                related_threat_id=threat_id,
                details=log.get("details", {})
            ))
        
        # 4. IP blocking events
        block_logs = await cls._db.response_actions.find({
            "$or": [
                {"related_threat_id": threat_id},
                {"ip": threat.get("source_ip")}
            ],
            "action": {"$in": ["block_ip", "unblock_ip"]}
        }, {"_id": 0}).sort("timestamp", 1).to_list(50)
        
        for log in block_logs:
            events.append(TimelineEvent(
                id=f"block_{log.get('_id', '')}",
                timestamp=log.get("timestamp", ""),
                event_type=TimelineEventType.BLOCK.value,
                title=f"IP {'Blocked' if log.get('action') == 'block_ip' else 'Unblocked'}: {log.get('ip')}",
                description=log.get("reason", ""),
                severity="warning" if log.get("action") == "block_ip" else "info",
                source=log.get("performed_by", "system"),
                related_threat_id=threat_id,
                target=log.get("ip"),
                details={"duration_hours": log.get("duration_hours")}
            ))
        
        # 5. Quarantine events
        if threat.get("quarantine_info"):
            q_info = threat["quarantine_info"]
            events.append(TimelineEvent(
                id=f"quarantine_{q_info.get('id', '')}",
                timestamp=q_info.get("quarantined_at", ""),
                event_type=TimelineEventType.QUARANTINE.value,
                title=f"File Quarantined: {q_info.get('threat_name', 'Unknown')}",
                description=f"File isolated: {q_info.get('original_path', '')}",
                severity="critical",
                source="system",
                related_threat_id=threat_id,
                target=q_info.get("original_path"),
                details={
                    "quarantine_path": q_info.get("quarantine_path"),
                    "file_hash": q_info.get("file_hash")
                }
            ))
        
        # 6. User actions from audit logs
        user_logs = await cls._db.audit_logs.find({
            "category": "user_action",
            "target_id": threat_id
        }, {"_id": 0}).sort("timestamp", 1).to_list(50)
        
        for log in user_logs:
            events.append(TimelineEvent(
                id=f"user_{log.get('id')}",
                timestamp=log.get("timestamp", ""),
                event_type=TimelineEventType.USER_ACTION.value,
                title=f"User Action: {log.get('action', 'Unknown')}",
                description=log.get("description", ""),
                severity="info",
                source=log.get("actor", "unknown"),
                actor=log.get("actor"),
                related_threat_id=threat_id,
                details=log.get("details", {})
            ))
        
        # Sort events by timestamp
        events.sort(key=lambda e: e.timestamp)
        
        # Build the timeline
        timeline = ThreatTimeline(
            threat_id=threat_id,
            threat_name=threat.get("name", "Unknown"),
            threat_type=threat.get("type", "unknown"),
            severity=threat.get("severity", "medium"),
            status=threat.get("status", "active"),
            first_seen=threat.get("created_at", ""),
            last_updated=threat.get("updated_at", ""),
            events=events,
            summary=cls._generate_summary(threat, events),
            impact_assessment=cls._assess_impact(threat, events),
            recommendations=cls._generate_recommendations(threat, events)
        )
        
        return timeline
    
    @classmethod
    def _generate_summary(cls, threat: Dict, events: List[TimelineEvent]) -> str:
        """Generate a human-readable summary of the timeline"""
        event_count = len(events)
        response_count = sum(1 for e in events if e.event_type == TimelineEventType.RESPONSE.value)
        block_count = sum(1 for e in events if e.event_type == TimelineEventType.BLOCK.value)
        
        summary = f"Threat '{threat.get('name', 'Unknown')}' was detected "
        summary += f"with {event_count} related events. "
        
        if response_count:
            summary += f"{response_count} automated responses were triggered. "
        if block_count:
            summary += f"{block_count} IP blocking actions were taken. "
        
        summary += f"Current status: {threat.get('status', 'unknown')}."
        return summary
    
    @classmethod
    def _assess_impact(cls, threat: Dict, events: List[TimelineEvent]) -> Dict[str, Any]:
        """Assess the impact of the threat"""
        return {
            "severity": threat.get("severity", "unknown"),
            "affected_systems": [threat.get("target_system")] if threat.get("target_system") else [],
            "source_ips": [threat.get("source_ip")] if threat.get("source_ip") else [],
            "total_events": len(events),
            "response_time_minutes": cls._calculate_response_time(events),
            "contained": threat.get("status") in ["resolved", "quarantined", "blocked"]
        }
    
    @classmethod
    def _calculate_response_time(cls, events: List[TimelineEvent]) -> Optional[int]:
        """Calculate time from detection to first response"""
        detection = None
        first_response = None
        
        for event in events:
            if event.event_type == TimelineEventType.DETECTION.value and not detection:
                detection = event.timestamp
            elif event.event_type in [TimelineEventType.RESPONSE.value, TimelineEventType.BLOCK.value]:
                if not first_response:
                    first_response = event.timestamp
                    break
        
        if detection and first_response:
            try:
                dt1 = datetime.fromisoformat(detection.replace('Z', '+00:00'))
                dt2 = datetime.fromisoformat(first_response.replace('Z', '+00:00'))
                return int((dt2 - dt1).total_seconds() / 60)
            except Exception:
                pass
        return None
    
    @classmethod
    def _generate_recommendations(cls, threat: Dict, events: List[TimelineEvent]) -> List[str]:
        """Generate recommendations based on the threat"""
        recommendations = []
        
        severity = threat.get("severity", "medium")
        threat_type = threat.get("type", "unknown")
        status = threat.get("status", "active")
        
        if status == "active":
            recommendations.append("Threat is still active. Consider immediate containment actions.")
        
        if severity in ["critical", "high"]:
            recommendations.append("Review all systems for signs of lateral movement.")
            recommendations.append("Consider isolating affected systems from the network.")
        
        if threat_type in ["malware", "ransomware"]:
            recommendations.append("Scan all connected systems for similar indicators.")
            recommendations.append("Review backup status and recovery procedures.")
        
        if threat_type in ["intrusion", "ids_alert"]:
            recommendations.append("Review firewall rules and access controls.")
            recommendations.append("Check for unauthorized accounts or access.")
        
        if threat.get("source_ip"):
            recommendations.append(f"Consider permanent blocking of source IP: {threat['source_ip']}")
        
        recommendations.append("Update incident documentation and notify stakeholders.")
        
        return recommendations
    
    @classmethod
    async def get_recent_timelines(cls, limit: int = 10) -> List[Dict[str, Any]]:
        """Get summaries of recent threat timelines"""
        if not cls._db:
            return []
        
        threats = await cls._db.threats.find(
            {}, {"_id": 0}
        ).sort("created_at", -1).limit(limit).to_list(limit)
        
        summaries = []
        for threat in threats:
            event_count = await cls._db.alerts.count_documents({"threat_id": threat.get("id")})
            summaries.append({
                "threat_id": threat.get("id"),
                "threat_name": threat.get("name"),
                "threat_type": threat.get("type"),
                "severity": threat.get("severity"),
                "status": threat.get("status"),
                "first_seen": threat.get("created_at"),
                "event_count": event_count + 1  # +1 for detection event
            })
        
        return summaries
    
    @classmethod
    async def export_timeline(cls, threat_id: str, format: str = "json") -> Optional[str]:
        """Export timeline to specified format"""
        timeline = await cls.build_timeline(threat_id)
        if not timeline:
            return None
        
        if format == "json":
            return json.dumps(asdict(timeline), indent=2)
        elif format == "markdown":
            return cls._to_markdown(timeline)
        
        return None
    
    @classmethod
    def _to_markdown(cls, timeline: ThreatTimeline) -> str:
        """Convert timeline to Markdown format"""
        md = f"# Threat Timeline: {timeline.threat_name}\n\n"
        md += f"**ID:** {timeline.threat_id}\n"
        md += f"**Type:** {timeline.threat_type}\n"
        md += f"**Severity:** {timeline.severity.upper()}\n"
        md += f"**Status:** {timeline.status}\n"
        md += f"**First Seen:** {timeline.first_seen}\n\n"
        
        md += "## Summary\n\n"
        md += f"{timeline.summary}\n\n"
        
        if timeline.impact_assessment:
            md += "## Impact Assessment\n\n"
            for key, value in timeline.impact_assessment.items():
                md += f"- **{key.replace('_', ' ').title()}:** {value}\n"
            md += "\n"
        
        md += "## Timeline of Events\n\n"
        for event in timeline.events:
            severity_icon = "🔴" if event.severity == "critical" else \
                           "🟠" if event.severity == "high" else \
                           "🟡" if event.severity == "medium" else "🟢"
            md += f"### {severity_icon} {event.title}\n"
            md += f"**Time:** {event.timestamp}\n"
            md += f"**Type:** {event.event_type}\n"
            md += f"**Source:** {event.source}\n"
            if event.description:
                md += f"\n{event.description}\n"
            md += "\n---\n\n"
        
        if timeline.recommendations:
            md += "## Recommendations\n\n"
            for rec in timeline.recommendations:
                md += f"- {rec}\n"
        
        return md

# Global instance
timeline_builder = TimelineBuilder()
