"""
Dashboard Router
"""
from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime, timezone
from typing import List
import uuid

from .dependencies import (
    DashboardStats, ThreatResponse, AlertResponse, get_current_user, get_db
)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    db = get_db()
    
    # Get threat counts
    total_threats = await db.threats.count_documents({})
    active_threats = await db.threats.count_documents({"status": "active"})
    contained_threats = await db.threats.count_documents({"status": "contained"})
    resolved_threats = await db.threats.count_documents({"status": "resolved"})
    
    # Get critical alerts
    critical_alerts = await db.alerts.count_documents({"severity": "critical", "status": {"$ne": "resolved"}})
    
    # Threats by type aggregation
    type_pipeline = [{"$group": {"_id": "$type", "count": {"$sum": 1}}}]
    type_results = await db.threats.aggregate(type_pipeline).to_list(20)
    threats_by_type = {r["_id"]: r["count"] for r in type_results if r["_id"]}
    
    # Threats by severity
    severity_pipeline = [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
    severity_results = await db.threats.aggregate(severity_pipeline).to_list(10)
    threats_by_severity = {r["_id"]: r["count"] for r in severity_results if r["_id"]}
    
    # Recent threats
    recent_threats_data = await db.threats.find({}, {"_id": 0}).sort("created_at", -1).to_list(5)
    recent_threats = [ThreatResponse(**t) for t in recent_threats_data]
    
    # Recent alerts
    recent_alerts_data = await db.alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(5)
    recent_alerts = [AlertResponse(**a) for a in recent_alerts_data]
    
    # AI scans today
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    scan_stat = await db.scan_stats.find_one({"date": today}, {"_id": 0})
    ai_scans_today = scan_stat["count"] if scan_stat else 0
    
    # System health
    system_health = 100.0
    if total_threats > 0:
        system_health = ((contained_threats + resolved_threats) / total_threats) * 100
        system_health = min(100, max(0, system_health))
    
    return DashboardStats(
        total_threats=total_threats,
        active_threats=active_threats,
        contained_threats=contained_threats,
        resolved_threats=resolved_threats,
        critical_alerts=critical_alerts,
        threats_by_type=threats_by_type,
        threats_by_severity=threats_by_severity,
        recent_threats=recent_threats,
        recent_alerts=recent_alerts,
        ai_scans_today=ai_scans_today,
        system_health=system_health
    )

@router.post("/seed")
async def seed_data():
    """Seed initial demo data"""
    from datetime import timedelta
    db = get_db()
    
    # Check if data already exists
    existing = await db.threats.count_documents({})
    if existing > 0:
        return {"message": "Data already seeded"}
    
    # Sample threats
    sample_threats = [
        {
            "id": str(uuid.uuid4()),
            "name": "GPT-4 Autonomous Agent Attack",
            "type": "ai_agent",
            "severity": "critical",
            "status": "active",
            "source_ip": "192.168.1.105",
            "target_system": "Production API Server",
            "description": "Detected autonomous AI agent attempting to exploit API endpoints with adaptive attack patterns",
            "indicators": ["Superhuman request rate", "Adaptive payload modification", "Non-human timing patterns"],
            "ai_analysis": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Polymorphic Ransomware Variant",
            "type": "malware",
            "severity": "critical",
            "status": "contained",
            "source_ip": "10.0.0.45",
            "target_system": "File Server FS-01",
            "description": "AI-generated polymorphic ransomware detected, code mutations every 30 seconds",
            "indicators": ["Self-modifying bytecode", "Encrypted C2 communication", "Anti-sandbox techniques"],
            "ai_analysis": None,
            "created_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Adversarial ML Attack",
            "type": "ai_agent",
            "severity": "high",
            "status": "active",
            "source_ip": "172.16.0.88",
            "target_system": "ML Pipeline",
            "description": "Adversarial inputs detected attempting to poison training data in ML pipeline",
            "indicators": ["Gradient-based perturbations", "Training data injection", "Model inversion attempts"],
            "ai_analysis": None,
            "created_at": (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Botnet Command Server",
            "type": "botnet",
            "severity": "high",
            "status": "active",
            "source_ip": "45.33.32.156",
            "target_system": "Network Edge",
            "description": "AI-coordinated botnet C2 server discovered communicating with internal hosts",
            "indicators": ["Encrypted beacon traffic", "Domain generation algorithm", "P2P mesh topology"],
            "ai_analysis": None,
            "created_at": (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Deepfake Phishing Campaign",
            "type": "phishing",
            "severity": "medium",
            "status": "resolved",
            "source_ip": "unknown",
            "target_system": "Email Gateway",
            "description": "AI-generated deepfake video phishing attempt targeting executives",
            "indicators": ["Synthetic voice patterns", "Facial manipulation artifacts", "Social engineering vectors"],
            "ai_analysis": None,
            "created_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
    ]
    
    # Sample alerts
    sample_alerts = [
        {
            "id": str(uuid.uuid4()),
            "title": "Critical: AI Agent Behavior Detected",
            "type": "ai_detected",
            "severity": "critical",
            "message": "Behavioral analysis flagged non-human interaction patterns on API endpoint /api/data",
            "status": "new",
            "created_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Anomaly: Unusual Traffic Spike",
            "type": "anomaly",
            "severity": "high",
            "message": "300% increase in API calls from single source with perfect timing distribution",
            "status": "acknowledged",
            "created_at": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Signature Match: Known Malware Family",
            "type": "signature",
            "severity": "high",
            "message": "File hash matches AI-generated malware variant LockAI.B",
            "status": "new",
            "created_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "title": "Behavioral: Model Probing Detected",
            "type": "behavioral",
            "severity": "medium",
            "message": "Sequential queries suggest systematic probing of ML model decision boundaries",
            "status": "acknowledged",
            "created_at": (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        }
    ]
    
    await db.threats.insert_many(sample_threats)
    await db.alerts.insert_many(sample_alerts)
    
    return {"message": "Demo data seeded successfully", "threats": len(sample_threats), "alerts": len(sample_alerts)}
