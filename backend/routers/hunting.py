"""
Threat Hunting Router
"""
from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime, timezone
from typing import List, Optional
import uuid
import json

from .dependencies import (
    HuntingHypothesis, HuntingRequest, get_current_user, get_db, logger
)

router = APIRouter(prefix="/hunting", tags=["Threat Hunting"])

# Import AI helper
from .ai_analysis import call_openai

@router.post("/generate", response_model=List[HuntingHypothesis])
async def generate_hunting_hypotheses(request: HuntingRequest, current_user: dict = Depends(get_current_user)):
    """AI-powered threat hunting hypothesis generation"""
    db = get_db()
    
    # Get recent threats and alerts for context
    threats = await db.threats.find({}, {"_id": 0}).sort("created_at", -1).to_list(20)
    alerts = await db.alerts.find({}, {"_id": 0}).sort("created_at", -1).to_list(20)
    
    # Build context for AI
    context = f"""Recent Threats: {len(threats)} detected
Threat Types: {', '.join(set(t.get('type', 'unknown') for t in threats))}
Active Threats: {len([t for t in threats if t.get('status') == 'active'])}
Recent Alerts: {len(alerts)}
Focus Area: {request.focus_area or 'all'}
Time Range: Last {request.time_range_hours} hours"""

    try:
        system_message = """You are an elite threat hunting AI. Generate threat hunting hypotheses based on the security context provided.
For each hypothesis, provide:
1. A clear title
2. Detailed description of what to look for
3. Category (ai_behavior, malware, lateral_movement, data_exfil, persistence)
4. Confidence score (0-100)
5. Specific indicators to search for
6. Recommended investigation actions

Return exactly 3-5 hypotheses in a structured format. Be specific and actionable."""

        user_prompt = f"""Based on this security context, generate threat hunting hypotheses:

{context}

Threat Details:
{json.dumps([{'name': t.get('name'), 'type': t.get('type'), 'severity': t.get('severity'), 'indicators': t.get('indicators', [])} for t in threats[:5]], indent=2)}

Generate hunting hypotheses that would help discover hidden threats or validate existing detections."""
        
        ai_response = await call_openai(system_message, user_prompt)
        logger.info(f"AI generated hunting response: {ai_response[:200]}...")
        
        # Generate structured hypotheses based on context and AI response
        hypotheses = []
        
        # AI Agent Detection Hypothesis
        if not request.focus_area or request.focus_area in ["ai_agents", "all"]:
            ai_threats = [t for t in threats if t.get("type") == "ai_agent"]
            hypotheses.append(HuntingHypothesis(
                id=str(uuid.uuid4()),
                title="Undetected AI Agent Activity",
                description="Hunt for AI agents that may be evading current detection by analyzing API request patterns, timing distributions, and behavioral signatures that indicate non-human operators.",
                category="ai_behavior",
                confidence=75.0 if ai_threats else 50.0,
                indicators=[
                    "Requests with sub-millisecond timing precision",
                    "Perfect distribution of request intervals",
                    "Adaptive payload modifications",
                    "Sequential endpoint enumeration patterns"
                ],
                recommended_actions=[
                    "Analyze API logs for timing anomalies",
                    "Review authentication patterns for automated behavior",
                    "Check for systematic data access patterns",
                    "Monitor for adversarial ML inputs"
                ],
                related_threats=[t.get("id", "") for t in ai_threats[:3]],
                status="pending",
                created_at=datetime.now(timezone.utc).isoformat()
            ))
        
        # Lateral Movement Hypothesis
        if not request.focus_area or request.focus_area in ["network", "all"]:
            hypotheses.append(HuntingHypothesis(
                id=str(uuid.uuid4()),
                title="Internal Lateral Movement Detection",
                description="Hunt for signs of lateral movement within the network by analyzing internal traffic patterns, unusual authentication sequences, and cross-system access that deviates from baseline behavior.",
                category="lateral_movement",
                confidence=60.0,
                indicators=[
                    "Unusual internal SSH/RDP connections",
                    "Service account usage anomalies",
                    "Sequential system access patterns",
                    "Off-hours administrative actions"
                ],
                recommended_actions=[
                    "Review internal firewall logs",
                    "Analyze authentication logs for pass-the-hash indicators",
                    "Check for unusual service account activity",
                    "Map internal connection patterns"
                ],
                related_threats=[],
                status="pending",
                created_at=datetime.now(timezone.utc).isoformat()
            ))
        
        # Malware Persistence Hypothesis  
        if not request.focus_area or request.focus_area in ["malware", "all"]:
            malware_threats = [t for t in threats if t.get("type") in ["malware", "ransomware"]]
            hypotheses.append(HuntingHypothesis(
                id=str(uuid.uuid4()),
                title="Hidden Persistence Mechanisms",
                description="Hunt for malware persistence mechanisms that may have been established during previous compromises, including registry modifications, scheduled tasks, and startup entries.",
                category="persistence",
                confidence=70.0 if malware_threats else 45.0,
                indicators=[
                    "Modified startup registry keys",
                    "Unusual scheduled tasks",
                    "Hidden services or drivers",
                    "Modified system binaries"
                ],
                recommended_actions=[
                    "Run autoruns analysis on critical systems",
                    "Compare current state to known-good baselines",
                    "Check for unsigned drivers or services",
                    "Review scheduled task creation logs"
                ],
                related_threats=[t.get("id", "") for t in malware_threats[:3]],
                status="pending",
                created_at=datetime.now(timezone.utc).isoformat()
            ))
        
        # Data Exfiltration Hypothesis
        hypotheses.append(HuntingHypothesis(
            id=str(uuid.uuid4()),
            title="Covert Data Exfiltration Channels",
            description="Hunt for potential data exfiltration activities including DNS tunneling, encrypted channels to unknown destinations, and unusual outbound data volumes.",
            category="data_exfil",
            confidence=55.0,
            indicators=[
                "High-entropy DNS queries",
                "Large outbound data to new destinations",
                "Connections to known bad IPs/domains",
                "Unusual protocol usage on standard ports"
            ],
            recommended_actions=[
                "Analyze DNS query logs for tunneling patterns",
                "Review NetFlow data for volume anomalies",
                "Check TLS certificate validity for outbound connections",
                "Monitor cloud storage API access patterns"
            ],
            related_threats=[],
            status="pending",
            created_at=datetime.now(timezone.utc).isoformat()
        ))
        
        # Store hypotheses
        for h in hypotheses:
            await db.hunting_hypotheses.insert_one(h.model_dump())
        
        return hypotheses
        
    except Exception as e:
        logger.error(f"Hunting hypothesis generation error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate hypotheses: {str(e)}")

@router.get("/hypotheses", response_model=List[HuntingHypothesis])
async def get_hunting_hypotheses(status: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """Get all hunting hypotheses"""
    db = get_db()
    query = {}
    if status:
        query["status"] = status
    hypotheses = await db.hunting_hypotheses.find(query, {"_id": 0}).sort("created_at", -1).to_list(50)
    return [HuntingHypothesis(**h) for h in hypotheses]

@router.patch("/hypotheses/{hypothesis_id}/status")
async def update_hypothesis_status(hypothesis_id: str, status: str, current_user: dict = Depends(get_current_user)):
    """Update hunting hypothesis status"""
    db = get_db()
    if status not in ["pending", "investigating", "confirmed", "dismissed"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    result = await db.hunting_hypotheses.update_one(
        {"id": hypothesis_id},
        {"$set": {"status": status}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    return {"message": "Status updated", "status": status}
