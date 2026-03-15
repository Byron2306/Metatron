"""Shared dependencies for all routers"""
from fastapi import HTTPException, Depends, Request, WebSocket, WebSocketException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from starlette.status import WS_1008_POLICY_VIOLATION, WS_1011_INTERNAL_ERROR
import jwt
try:
    import bcrypt
except Exception:
    bcrypt = None
import uuid
import os
import logging
import ipaddress
import hmac

logger = logging.getLogger(__name__)


def _is_production_security_mode() -> bool:
    environment = os.environ.get("ENVIRONMENT", "").strip().lower()
    strict_flag = os.environ.get("SERAPH_STRICT_SECURITY", "false").strip().lower()
    return environment in {"prod", "production"} or strict_flag in {"1", "true", "yes", "on"}


def _resolve_jwt_secret() -> str:
    configured_secret = os.environ.get("JWT_SECRET")
    weak_defaults = {
        "anti-ai-defense-secret",
        "secret",
        "changeme",
        "password",
        "default",
        "your-super-secret-jwt-key-change-in-production",
    }

    if not configured_secret:
        if _is_production_security_mode():
            raise RuntimeError(
                "JWT_SECRET is required in production/strict mode. "
                "Refusing to start without a strong secret."
            )
        generated_secret = f"ephemeral-{uuid.uuid4().hex}{uuid.uuid4().hex}"
        logger.warning(
            "JWT_SECRET is not set. Using an ephemeral in-memory secret for this process. "
            "Set a strong JWT_SECRET (>=32 chars) for persistent authentication."
        )
        return generated_secret

    if configured_secret in weak_defaults or len(configured_secret) < 32:
        message = (
            "Weak JWT_SECRET detected. Use a strong random secret with length >= 32 "
            "for secure token signing."
        )
        if _is_production_security_mode():
            raise RuntimeError(f"{message} Refusing to start in production/strict mode.")
        logger.warning(message)

    return configured_secret


# JWT Configuration
JWT_SECRET = _resolve_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

security = HTTPBearer()
optional_security = HTTPBearer(auto_error=False)

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
    if bcrypt is not None:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    # Fallback: use PBKDF2-HMAC-SHA256 for environments without bcrypt
    import hashlib, os, binascii
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
    return binascii.hexlify(salt + dk).decode('ascii')


def verify_password(password: str, hashed: str) -> bool:
    if bcrypt is not None:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    # Fallback verification for PBKDF2 hex format produced above
    import hashlib, binascii
    try:
        raw = binascii.unhexlify(hashed.encode('ascii'))
        salt = raw[:16]
        dk = raw[16:]
        check = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000)
        return hashlib.compare_digest(check, dk)
    except Exception:
        return False


def create_token(user_id: str, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _is_local_request(request: Request) -> bool:
    # Prefer X-Forwarded-For when behind reverse proxy.
    xff = request.headers.get("x-forwarded-for", "")
    client_ip = (xff.split(",")[0].strip() if xff else (request.client.host if request.client else "")).lower()
    trusted = {
        "127.0.0.1",
        "::1",
        "localhost",
        "172.17.0.1",  # common Docker host bridge address
        "host.docker.internal",
    }
    if client_ip in trusted:
        return True

    try:
        ip_obj = ipaddress.ip_address(client_ip)
        return ip_obj.is_loopback or ip_obj.is_private
    except Exception:
        return False


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        # Remote admin-only gate (for server-exposed ports): remote clients must be admin.
        remote_admin_only = os.environ.get("REMOTE_ADMIN_ONLY", "true").strip().lower() in {"1", "true", "yes", "on"}
        if remote_admin_only and not _is_local_request(request):
            allowed_admin_emails = {
                e.strip().lower()
                for e in os.environ.get("REMOTE_ADMIN_EMAILS", "").split(",")
                if e.strip()
            }
            if allowed_admin_emails:
                if user.get("email", "").lower() not in allowed_admin_emails:
                    raise HTTPException(status_code=403, detail="Remote access denied for this account")
            elif user.get("role", "viewer") != "admin":
                raise HTTPException(status_code=403, detail="Remote access requires admin role")

        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_optional_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_security),
):
    """Best-effort identity resolution. Returns None when no bearer token is provided."""
    if credentials is None:
        return None
    return await get_current_user(request=request, credentials=credentials)


# ============ ROLE-BASED ACCESS CONTROL ============

ROLES = {
    "admin": ["read", "write", "delete", "manage_users", "manage_honeypots", "export_reports"],
    "analyst": ["read", "write", "export_reports"],
    "viewer": ["read"],
}


def has_permission(user: Optional[dict], required_permission: str) -> bool:
    if not user:
        return False
    user_role = user.get("role", "viewer")
    permissions = ROLES.get(user_role, [])
    return required_permission in permissions


def check_permission(required_permission: str):
    async def permission_checker(current_user: dict = Depends(get_current_user)):
        if not has_permission(current_user, required_permission):
            raise HTTPException(status_code=403, detail=f"Permission denied. Required: {required_permission}")
        return current_user
    return permission_checker


def _resolve_machine_tokens(env_keys: List[str]) -> List[str]:
    tokens: List[str] = []
    for key in env_keys:
        raw = (os.environ.get(key) or "").strip()
        if raw:
            tokens.append(raw)
    return tokens


def machine_token_matches(token: Optional[str], env_keys: List[str]) -> bool:
    if not token:
        return False
    configured_tokens = _resolve_machine_tokens(env_keys)
    if not configured_tokens:
        return False
    provided = token.strip()
    return any(hmac.compare_digest(provided, configured) for configured in configured_tokens)


def _extract_header_token(request: Request, header_names: List[str]) -> Optional[str]:
    for name in header_names:
        value = request.headers.get(name)
        if value:
            return value.strip()
    return None


def require_machine_token(
    *,
    env_keys: List[str],
    header_names: Optional[List[str]] = None,
    subject: str = "machine",
):
    """Create a dependency that validates a shared machine token from headers."""
    resolved_headers = [h.strip() for h in (header_names or ["x-agent-token", "x-internal-token"]) if h.strip()]

    async def _checker(request: Request):
        configured_tokens = _resolve_machine_tokens(env_keys)
        if not configured_tokens:
            raise HTTPException(status_code=503, detail=f"{subject} token is not configured")

        provided = _extract_header_token(request, resolved_headers)
        if not provided:
            raise HTTPException(status_code=401, detail=f"Missing {subject} token")

        if not any(hmac.compare_digest(provided, token) for token in configured_tokens):
            raise HTTPException(status_code=401, detail=f"Invalid {subject} token")

        return {"auth": "ok", "subject": subject}

    return _checker


def optional_machine_token(
    *,
    env_keys: List[str],
    header_names: Optional[List[str]] = None,
    subject: str = "machine",
):
    """Create a dependency that validates machine token only when header is present."""
    resolved_headers = [h.strip() for h in (header_names or ["x-agent-token", "x-internal-token"]) if h.strip()]

    async def _checker(request: Request):
        provided = _extract_header_token(request, resolved_headers)
        if not provided:
            return None

        configured_tokens = _resolve_machine_tokens(env_keys)
        if not configured_tokens:
            raise HTTPException(status_code=503, detail=f"{subject} token is not configured")

        if not any(hmac.compare_digest(provided, token) for token in configured_tokens):
            raise HTTPException(status_code=401, detail=f"Invalid {subject} token")

        return {"auth": "ok", "subject": subject}

    return _checker


def verify_websocket_machine_token(
    websocket: WebSocket,
    *,
    env_keys: List[str],
    header_names: Optional[List[str]] = None,
    subject: str = "machine",
) -> Dict[str, str]:
    """Validate machine token from websocket headers."""
    configured_tokens = _resolve_machine_tokens(env_keys)
    if not configured_tokens:
        raise WebSocketException(code=WS_1011_INTERNAL_ERROR, reason=f"{subject} token is not configured")

    resolved_headers = [h.strip() for h in (header_names or ["x-agent-token", "x-internal-token"]) if h.strip()]
    provided: Optional[str] = None
    for header_name in resolved_headers:
        value = websocket.headers.get(header_name)
        if value:
            provided = value.strip()
            break

    if not provided:
        raise WebSocketException(code=WS_1008_POLICY_VIOLATION, reason=f"Missing {subject} token")
    if not any(hmac.compare_digest(provided, token) for token in configured_tokens):
        raise WebSocketException(code=WS_1008_POLICY_VIOLATION, reason=f"Invalid {subject} token")

    return {"auth": "ok", "subject": subject}

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
    last_heartbeat: Optional[str] = None
    system_info: Dict[str, Any] = {}
    created_at: Optional[str] = None

class RoleUpdate(BaseModel):
    role: str
