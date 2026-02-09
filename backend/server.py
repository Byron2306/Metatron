from fastapi import FastAPI, APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
import asyncio
import json
import random
import io
from openai import AsyncOpenAI
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'anti-ai-defense-secret')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# OpenAI Client
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)

app = FastAPI(title="Anti-AI Defense System API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

ws_manager = ConnectionManager()

# ============ MODELS ============

class UserCreate(BaseModel):
    email: str
    password: str
    name: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: str
    name: str
    role: str = "analyst"
    created_at: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class ThreatCreate(BaseModel):
    name: str
    type: str  # ai_agent, malware, botnet, phishing, ransomware
    severity: str  # critical, high, medium, low
    source_ip: Optional[str] = None
    target_system: Optional[str] = None
    description: Optional[str] = None
    indicators: Optional[List[str]] = []

class ThreatResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    type: str
    severity: str
    status: str  # active, contained, resolved
    source_ip: Optional[str] = None
    target_system: Optional[str] = None
    description: Optional[str] = None
    indicators: List[str] = []
    ai_analysis: Optional[str] = None
    created_at: str
    updated_at: str

class AlertCreate(BaseModel):
    title: str
    type: str  # behavioral, signature, anomaly, ai_detected
    severity: str
    threat_id: Optional[str] = None
    message: str

class AlertResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    title: str
    type: str
    severity: str
    threat_id: Optional[str] = None
    message: str
    status: str  # new, acknowledged, resolved
    created_at: str

class AIAnalysisRequest(BaseModel):
    content: str
    analysis_type: str  # threat_detection, behavior_analysis, malware_scan, pattern_recognition

class AIAnalysisResponse(BaseModel):
    analysis_id: str
    analysis_type: str
    result: str
    threat_indicators: List[str]
    risk_score: float
    recommendations: List[str]
    timestamp: str

class DashboardStats(BaseModel):
    total_threats: int
    active_threats: int
    contained_threats: int
    resolved_threats: int
    critical_alerts: int
    threats_by_type: dict
    threats_by_severity: dict
    recent_threats: List[ThreatResponse]
    recent_alerts: List[AlertResponse]
    ai_scans_today: int
    system_health: float

# ============ AUTH HELPERS ============

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ============ AUTH ENDPOINTS ============

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    user_doc = {
        "id": user_id,
        "email": user_data.email,
        "password": hash_password(user_data.password),
        "name": user_data.name,
        "role": "analyst",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(user_doc)
    
    token = create_token(user_id, user_data.email)
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user_id,
            email=user_data.email,
            name=user_data.name,
            role="analyst",
            created_at=user_doc["created_at"]
        )
    )

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(user["id"], user["email"])
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user["id"],
            email=user["email"],
            name=user["name"],
            role=user.get("role", "analyst"),
            created_at=user["created_at"]
        )
    )

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(**current_user)

# ============ THREAT ENDPOINTS ============

@api_router.post("/threats", response_model=ThreatResponse)
async def create_threat(threat_data: ThreatCreate, current_user: dict = Depends(get_current_user)):
    threat_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    threat_doc = {
        "id": threat_id,
        "name": threat_data.name,
        "type": threat_data.type,
        "severity": threat_data.severity,
        "status": "active",
        "source_ip": threat_data.source_ip,
        "target_system": threat_data.target_system,
        "description": threat_data.description,
        "indicators": threat_data.indicators or [],
        "ai_analysis": None,
        "created_at": now,
        "updated_at": now,
        "created_by": current_user["id"]
    }
    await db.threats.insert_one(threat_doc)
    return ThreatResponse(**threat_doc)

@api_router.get("/threats", response_model=List[ThreatResponse])
async def get_threats(status: Optional[str] = None, severity: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    query = {}
    if status:
        query["status"] = status
    if severity:
        query["severity"] = severity
    
    threats = await db.threats.find(query, {"_id": 0}).sort("created_at", -1).to_list(100)
    return [ThreatResponse(**t) for t in threats]

@api_router.get("/threats/{threat_id}", response_model=ThreatResponse)
async def get_threat(threat_id: str, current_user: dict = Depends(get_current_user)):
    threat = await db.threats.find_one({"id": threat_id}, {"_id": 0})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return ThreatResponse(**threat)

@api_router.patch("/threats/{threat_id}/status")
async def update_threat_status(threat_id: str, status: str, current_user: dict = Depends(get_current_user)):
    if status not in ["active", "contained", "resolved"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    result = await db.threats.update_one(
        {"id": threat_id},
        {"$set": {"status": status, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Threat not found")
    return {"message": "Status updated", "status": status}

# ============ ALERT ENDPOINTS ============

@api_router.post("/alerts", response_model=AlertResponse)
async def create_alert(alert_data: AlertCreate, current_user: dict = Depends(get_current_user)):
    alert_id = str(uuid.uuid4())
    alert_doc = {
        "id": alert_id,
        "title": alert_data.title,
        "type": alert_data.type,
        "severity": alert_data.severity,
        "threat_id": alert_data.threat_id,
        "message": alert_data.message,
        "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.alerts.insert_one(alert_doc)
    return AlertResponse(**alert_doc)

@api_router.get("/alerts", response_model=List[AlertResponse])
async def get_alerts(status: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    query = {}
    if status:
        query["status"] = status
    alerts = await db.alerts.find(query, {"_id": 0}).sort("created_at", -1).to_list(100)
    return [AlertResponse(**a) for a in alerts]

@api_router.patch("/alerts/{alert_id}/status")
async def update_alert_status(alert_id: str, status: str, current_user: dict = Depends(get_current_user)):
    if status not in ["new", "acknowledged", "resolved"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    result = await db.alerts.update_one({"id": alert_id}, {"$set": {"status": status}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"message": "Alert status updated", "status": status}

# ============ AI ANALYSIS ENDPOINTS ============

async def call_openai(system_message: str, user_message: str) -> str:
    """Helper function to call OpenAI API"""
    response = await openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message}
        ],
        max_tokens=2000,
        temperature=0.7
    )
    return response.choices[0].message.content

@api_router.post("/ai/analyze", response_model=AIAnalysisResponse)
async def ai_analyze(request: AIAnalysisRequest, current_user: dict = Depends(get_current_user)):
    analysis_id = str(uuid.uuid4())
    
    system_prompts = {
        "threat_detection": """You are an elite cybersecurity AI threat detection system. Analyze the provided content for potential threats including:
- Malicious code patterns
- AI-generated attack signatures
- Behavioral anomalies
- Known attack vectors
Provide a detailed threat assessment with specific indicators, risk score (0-100), and actionable recommendations.

Format your response with clear sections:
RISK SCORE: [0-100]
THREAT INDICATORS:
- [indicator 1]
- [indicator 2]
ANALYSIS:
[detailed analysis]
RECOMMENDATIONS:
- [recommendation 1]
- [recommendation 2]""",
        
        "behavior_analysis": """You are an advanced behavioral analysis AI. Examine the provided data for:
- Non-human interaction patterns (Turing test inversion)
- Algorithmic decision-making signatures
- Superhuman speed or consistency indicators
- Automated bot behaviors
Provide behavioral assessment with confidence scores and detection methods.

Format your response with:
RISK SCORE: [0-100]
BEHAVIOR TYPE: [human/bot/ai_agent/unknown]
CONFIDENCE: [percentage]
INDICATORS:
- [indicator]
ANALYSIS:
[detailed analysis]""",
        
        "malware_scan": """You are a polymorphic malware detection AI. Analyze for:
- Obfuscated code patterns
- Self-modifying code signatures
- Zero-day exploit indicators
- AI-generated malicious code
Provide malware classification, family identification if possible, and containment recommendations.

Format your response with:
RISK SCORE: [0-100]
MALWARE FAMILY: [family name or Unknown]
CLASSIFICATION: [trojan/ransomware/worm/etc]
INDICATORS:
- [indicator]
CONTAINMENT:
- [action]""",
        
        "pattern_recognition": """You are a pattern recognition AI for cyber threat intelligence. Identify:
- Attack campaign patterns
- Threat actor signatures
- Temporal patterns in attack data
- Correlations with known threat groups
Provide pattern analysis with attribution confidence and predicted next moves.

Format your response with:
RISK SCORE: [0-100]
THREAT ACTOR: [name or Unknown]
CAMPAIGN: [campaign name or Unknown]
PATTERNS:
- [pattern]
PREDICTED ACTIONS:
- [action]"""
    }
    
    system_message = system_prompts.get(request.analysis_type, system_prompts["threat_detection"])
    
    try:
        user_prompt = f"Analyze the following content:\n\n{request.content}\n\nProvide a structured analysis."
        response = await call_openai(system_message, user_prompt)
        
        # Parse response for structured data
        risk_score = 65.0  # Default moderate risk
        response_lower = response.lower()
        
        # Extract risk score from response
        if "risk score:" in response_lower:
            try:
                score_part = response_lower.split("risk score:")[1].split("\n")[0]
                score_num = ''.join(filter(str.isdigit, score_part[:10]))
                if score_num:
                    risk_score = min(100, max(0, float(score_num)))
            except:
                pass
        elif "critical" in response_lower or "high risk" in response_lower or "malicious" in response_lower:
            risk_score = 85.0
        elif "low risk" in response_lower or "benign" in response_lower or "safe" in response_lower:
            risk_score = 25.0
        
        # Extract indicators from response
        indicators = []
        if "indicators:" in response_lower or "indicator" in response_lower:
            lines = response.split("\n")
            for line in lines:
                if line.strip().startswith("-") and len(line.strip()) > 5:
                    indicator = line.strip()[1:].strip()
                    if len(indicator) > 3 and len(indicator) < 100:
                        indicators.append(indicator)
            indicators = indicators[:5]  # Limit to 5
        
        if not indicators:
            indicators = ["Pattern analysis completed", "Behavioral signature extracted"]
        
        # Extract recommendations
        recommendations = []
        if "recommend" in response_lower:
            in_recommendations = False
            for line in response.split("\n"):
                if "recommend" in line.lower():
                    in_recommendations = True
                if in_recommendations and line.strip().startswith("-"):
                    rec = line.strip()[1:].strip()
                    if len(rec) > 3:
                        recommendations.append(rec)
        
        if not recommendations:
            recommendations = ["Continue monitoring", "Update threat signatures", "Review access logs"]
        
        # Store analysis
        analysis_doc = {
            "id": analysis_id,
            "type": request.analysis_type,
            "content": request.content[:500],
            "result": response,
            "risk_score": risk_score,
            "indicators": indicators,
            "recommendations": recommendations[:5],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": current_user["id"]
        }
        await db.ai_analyses.insert_one(analysis_doc)
        
        # Increment scan counter
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        await db.scan_stats.update_one(
            {"date": today},
            {"$inc": {"count": 1}},
            upsert=True
        )
        
        return AIAnalysisResponse(
            analysis_id=analysis_id,
            analysis_type=request.analysis_type,
            result=response,
            threat_indicators=indicators,
            risk_score=risk_score,
            recommendations=recommendations,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
    except Exception as e:
        logger.error(f"AI Analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")

@api_router.get("/ai/analyses", response_model=List[dict])
async def get_ai_analyses(current_user: dict = Depends(get_current_user)):
    analyses = await db.ai_analyses.find({}, {"_id": 0}).sort("created_at", -1).to_list(50)
    return analyses

# ============ DASHBOARD ENDPOINTS ============

@api_router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
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
    
    # System health (based on contained/resolved ratio)
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

# ============ SEED DATA ============

@api_router.post("/seed")
async def seed_data():
    """Seed initial demo data"""
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

# ============ WEBSOCKET ENDPOINT ============

@app.websocket("/ws/threats")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and listen for messages
            data = await websocket.receive_text()
            # Echo back or handle commands
            await websocket.send_json({"type": "ack", "message": "received"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# Helper to broadcast threat updates
async def broadcast_threat_update(threat_data: dict, action: str):
    await ws_manager.broadcast({
        "type": "threat_update",
        "action": action,
        "data": threat_data,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

# ============ NETWORK TOPOLOGY ENDPOINTS ============

class NetworkNode(BaseModel):
    id: str
    label: str
    type: str  # server, workstation, router, firewall, cloud, attacker
    ip: Optional[str] = None
    status: str = "normal"  # normal, compromised, suspicious, protected
    threat_count: int = 0

class NetworkLink(BaseModel):
    source: str
    target: str
    type: str = "connection"  # connection, attack, data_flow
    strength: float = 1.0

class NetworkTopology(BaseModel):
    nodes: List[NetworkNode]
    links: List[NetworkLink]

@api_router.get("/network/topology", response_model=NetworkTopology)
async def get_network_topology(current_user: dict = Depends(get_current_user)):
    """Generate network topology based on threats and system data"""
    
    # Get all threats with IPs
    threats = await db.threats.find({"status": {"$ne": "resolved"}}, {"_id": 0}).to_list(100)
    
    # Build nodes - core infrastructure
    nodes = [
        NetworkNode(id="firewall-1", label="Edge Firewall", type="firewall", ip="10.0.0.1", status="protected"),
        NetworkNode(id="router-1", label="Core Router", type="router", ip="10.0.0.2", status="normal"),
        NetworkNode(id="server-web", label="Web Server", type="server", ip="10.0.1.10", status="normal"),
        NetworkNode(id="server-api", label="API Server", type="server", ip="10.0.1.11", status="normal"),
        NetworkNode(id="server-db", label="Database", type="server", ip="10.0.1.20", status="protected"),
        NetworkNode(id="server-ml", label="ML Pipeline", type="server", ip="10.0.1.30", status="normal"),
        NetworkNode(id="server-file", label="File Server", type="server", ip="10.0.1.40", status="normal"),
        NetworkNode(id="cloud-1", label="Cloud Services", type="cloud", ip="cloud.defense.io", status="normal"),
        NetworkNode(id="ws-1", label="Analyst WS-01", type="workstation", ip="10.0.2.10", status="normal"),
        NetworkNode(id="ws-2", label="Analyst WS-02", type="workstation", ip="10.0.2.11", status="normal"),
    ]
    
    # Add attacker nodes based on threats
    attacker_ips = set()
    for threat in threats:
        if threat.get("source_ip") and threat["source_ip"] not in attacker_ips:
            attacker_ips.add(threat["source_ip"])
            severity = threat.get("severity", "medium")
            nodes.append(NetworkNode(
                id=f"attacker-{threat['source_ip'].replace('.', '-')}",
                label=f"Threat: {threat['name'][:20]}",
                type="attacker",
                ip=threat["source_ip"],
                status="compromised" if severity in ["critical", "high"] else "suspicious",
                threat_count=1
            ))
    
    # Update node statuses based on threats targeting them
    target_threats = {}
    for threat in threats:
        target = threat.get("target_system", "")
        if target:
            target_lower = target.lower()
            if "api" in target_lower:
                target_threats["server-api"] = target_threats.get("server-api", 0) + 1
            elif "web" in target_lower:
                target_threats["server-web"] = target_threats.get("server-web", 0) + 1
            elif "ml" in target_lower or "pipeline" in target_lower:
                target_threats["server-ml"] = target_threats.get("server-ml", 0) + 1
            elif "file" in target_lower:
                target_threats["server-file"] = target_threats.get("server-file", 0) + 1
            elif "database" in target_lower or "db" in target_lower:
                target_threats["server-db"] = target_threats.get("server-db", 0) + 1
    
    for node in nodes:
        if node.id in target_threats:
            node.threat_count = target_threats[node.id]
            node.status = "suspicious" if target_threats[node.id] >= 1 else node.status
            if target_threats[node.id] >= 2:
                node.status = "compromised"
    
    # Build links - infrastructure connections
    links = [
        NetworkLink(source="firewall-1", target="router-1", type="connection"),
        NetworkLink(source="router-1", target="server-web", type="connection"),
        NetworkLink(source="router-1", target="server-api", type="connection"),
        NetworkLink(source="router-1", target="server-db", type="connection"),
        NetworkLink(source="router-1", target="server-ml", type="connection"),
        NetworkLink(source="router-1", target="server-file", type="connection"),
        NetworkLink(source="server-api", target="server-db", type="data_flow"),
        NetworkLink(source="server-api", target="server-ml", type="data_flow"),
        NetworkLink(source="server-web", target="server-api", type="data_flow"),
        NetworkLink(source="cloud-1", target="firewall-1", type="connection"),
        NetworkLink(source="router-1", target="ws-1", type="connection"),
        NetworkLink(source="router-1", target="ws-2", type="connection"),
    ]
    
    # Add attack links from threats
    for threat in threats:
        if threat.get("source_ip"):
            attacker_id = f"attacker-{threat['source_ip'].replace('.', '-')}"
            target = threat.get("target_system", "").lower()
            target_id = "server-api"  # default
            if "web" in target:
                target_id = "server-web"
            elif "ml" in target or "pipeline" in target:
                target_id = "server-ml"
            elif "file" in target:
                target_id = "server-file"
            elif "database" in target or "db" in target:
                target_id = "server-db"
            
            links.append(NetworkLink(
                source=attacker_id,
                target="firewall-1",
                type="attack",
                strength=2.0 if threat.get("severity") == "critical" else 1.5
            ))
    
    return NetworkTopology(nodes=nodes, links=links)

# ============ THREAT HUNTING ENDPOINTS ============

class HuntingHypothesis(BaseModel):
    id: str
    title: str
    description: str
    category: str  # ai_behavior, malware, lateral_movement, data_exfil, persistence
    confidence: float
    indicators: List[str]
    recommended_actions: List[str]
    related_threats: List[str]
    status: str = "pending"  # pending, investigating, confirmed, dismissed
    created_at: str

class HuntingRequest(BaseModel):
    focus_area: Optional[str] = None  # ai_agents, malware, network, all
    time_range_hours: int = 24

@api_router.post("/hunting/generate", response_model=List[HuntingHypothesis])
async def generate_hunting_hypotheses(request: HuntingRequest, current_user: dict = Depends(get_current_user)):
    """AI-powered threat hunting hypothesis generation"""
    
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

@api_router.get("/hunting/hypotheses", response_model=List[HuntingHypothesis])
async def get_hunting_hypotheses(status: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """Get all hunting hypotheses"""
    query = {}
    if status:
        query["status"] = status
    hypotheses = await db.hunting_hypotheses.find(query, {"_id": 0}).sort("created_at", -1).to_list(50)
    return [HuntingHypothesis(**h) for h in hypotheses]

@api_router.patch("/hunting/hypotheses/{hypothesis_id}/status")
async def update_hypothesis_status(hypothesis_id: str, status: str, current_user: dict = Depends(get_current_user)):
    """Update hunting hypothesis status"""
    if status not in ["pending", "investigating", "confirmed", "dismissed"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    result = await db.hunting_hypotheses.update_one(
        {"id": hypothesis_id},
        {"$set": {"status": status}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Hypothesis not found")
    return {"message": "Status updated", "status": status}

# ============ ROOT ENDPOINT ============

@api_router.get("/")
async def root():
    return {"message": "Anti-AI Defense System API", "version": "1.0.0", "status": "operational"}

# Include router and middleware
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
