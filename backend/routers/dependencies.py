"""
Shared dependencies for all routers
"""
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
import uuid
import os
import logging

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'anti-ai-defense-secret')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

security = HTTPBearer()
logger = logging.getLogger(__name__)

# MongoDB connection - will be set by main app
db = None

def set_database(database):
    """Set the database instance for all routers"""
    global db
    db = database

def get_db():
    """Get the database instance"""
    global db
    return db

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

# ============ ROLE-BASED ACCESS CONTROL ============

ROLES = {
    "admin": ["read", "write", "delete", "manage_users", "manage_honeypots", "export_reports"],
    "analyst": ["read", "write", "export_reports"],
    "viewer": ["read"]
}

def check_permission(required_permission: str):
    async def permission_checker(current_user: dict = Depends(get_current_user)):
        user_role = current_user.get("role", "viewer")
        permissions = ROLES.get(user_role, [])
        if required_permission not in permissions:
            raise HTTPException(status_code=403, detail=f"Permission denied. Required: {required_permission}")
        return current_user
    return permission_checker

# ============ SHARED MODELS ============

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
    type: str
    severity: str
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
    status: str
    source_ip: Optional[str] = None
    target_system: Optional[str] = None
    description: Optional[str] = None
    indicators: List[str] = []
    ai_analysis: Optional[str] = None
    created_at: str
    updated_at: str

class AlertCreate(BaseModel):
    title: str
    type: str
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
    status: str
    created_at: str

class AIAnalysisRequest(BaseModel):
    content: str
    analysis_type: str

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

class NetworkNode(BaseModel):
    id: str
    label: str
    type: str
    ip: Optional[str] = None
    status: str = "normal"
    threat_count: int = 0

class NetworkLink(BaseModel):
    source: str
    target: str
    type: str = "connection"
    strength: float = 1.0

class NetworkTopology(BaseModel):
    nodes: List[NetworkNode]
    links: List[NetworkLink]

class HuntingHypothesis(BaseModel):
    id: str
    title: str
    description: str
    category: str
    confidence: float
    indicators: List[str]
    recommended_actions: List[str]
    related_threats: List[str]
    status: str = "pending"
    created_at: str

class HuntingRequest(BaseModel):
    focus_area: Optional[str] = None
    time_range_hours: int = 24

class HoneypotCreate(BaseModel):
    name: str
    type: str
    ip: str
    port: int
    description: Optional[str] = None

class HoneypotResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    type: str
    ip: str
    port: int
    description: Optional[str] = None
    status: str
    interactions: int
    last_interaction: Optional[str] = None
    created_at: str

class HoneypotInteraction(BaseModel):
    id: str
    honeypot_id: str
    source_ip: str
    source_port: int
    timestamp: str
    action: str
    data: Dict[str, Any]
    threat_level: str

class AgentEvent(BaseModel):
    agent_id: str
    agent_name: str
    event_type: str
    timestamp: str
    data: Dict[str, Any]

class AgentInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    ip: Optional[str] = None
    os: Optional[str] = None
    status: str = "online"
    last_heartbeat: str
    system_info: Dict[str, Any] = {}
    created_at: str

class RoleUpdate(BaseModel):
    role: str
