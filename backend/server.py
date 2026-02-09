"""
Anti-AI Defense System - Main Server
=====================================
Modular FastAPI application with comprehensive security features.

This server has been refactored from a monolithic 2700+ line file into
clean, modular routers for better maintainability.

v3.0 Features:
- Threat Intelligence Feeds
- Ransomware Protection
- Container Security (Trivy)
- VPN Integration (WireGuard)
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from datetime import datetime, timezone

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Initialize database for routers
from routers.dependencies import set_database
set_database(db)

# Initialize services with database
from audit_logging import audit
from threat_timeline import timeline_builder
from threat_intel import threat_intel
from ransomware_protection import ransomware_protection
from container_security import container_security
from vpn_integration import vpn_manager

audit.set_database(db)
timeline_builder.set_database(db)
threat_intel.set_database(db)
ransomware_protection.set_database(db)
container_security.set_database(db)
vpn_manager.set_database(db)

# Create FastAPI app
app = FastAPI(
    title="Anti-AI Defense System API",
    description="Comprehensive agentic cybersecurity platform for detecting and responding to AI-powered threats",
    version="3.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import all routers
from routers.auth import router as auth_router, users_router
from routers.threats import router as threats_router
from routers.alerts import router as alerts_router
from routers.ai_analysis import router as ai_router
from routers.dashboard import router as dashboard_router
from routers.network import router as network_router
from routers.hunting import router as hunting_router
from routers.honeypots import router as honeypots_router
from routers.reports import router as reports_router
from routers.agents import router as agents_router, agents_router as agents_list_router
from routers.quarantine import router as quarantine_router
from routers.settings import router as settings_router
from routers.response import router as response_router
from routers.audit import router as audit_router
from routers.timeline import router as timeline_router, timelines_router
from routers.websocket import router as websocket_router
from routers.openclaw import router as openclaw_router
from routers.threat_intel import router as threat_intel_router
from routers.ransomware import router as ransomware_router
from routers.containers import router as containers_router
from routers.vpn import router as vpn_router

# Register all routers with /api prefix
app.include_router(auth_router, prefix="/api")
app.include_router(users_router, prefix="/api")
app.include_router(threats_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(ai_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(network_router, prefix="/api")
app.include_router(hunting_router, prefix="/api")
app.include_router(honeypots_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(agents_router, prefix="/api")
app.include_router(agents_list_router, prefix="/api")
app.include_router(quarantine_router, prefix="/api")
app.include_router(settings_router, prefix="/api")
app.include_router(response_router, prefix="/api")
app.include_router(audit_router, prefix="/api")
app.include_router(timeline_router, prefix="/api")
app.include_router(timelines_router, prefix="/api")
app.include_router(websocket_router, prefix="/api")
app.include_router(openclaw_router, prefix="/api")
app.include_router(threat_intel_router, prefix="/api")
app.include_router(ransomware_router, prefix="/api")
app.include_router(containers_router, prefix="/api")
app.include_router(vpn_router, prefix="/api")

# ============ WEBSOCKET ENDPOINTS ============

from routers.honeypots import ws_manager
from websocket_service import realtime_ws

@app.websocket("/ws/threats")
async def websocket_threats(websocket: WebSocket):
    """WebSocket endpoint for real-time threat updates"""
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "ack", "message": "received"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

@app.websocket("/ws/agent/{agent_id}")
async def websocket_agent(websocket: WebSocket, agent_id: str):
    """WebSocket endpoint for agent real-time communication"""
    await realtime_ws.connect(websocket, agent_id)
    try:
        while True:
            data = await websocket.receive_json()
            await realtime_ws.handle_message(agent_id, data)
    except WebSocketDisconnect:
        await realtime_ws.disconnect(agent_id)

# ============ ROOT ENDPOINT ============

@app.get("/api/")
async def root():
    """API root endpoint"""
    return {
        "name": "Anti-AI Defense System API",
        "version": "3.0.0",
        "status": "operational",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "features": [
            "threat_detection",
            "ai_analysis",
            "network_topology",
            "threat_hunting",
            "honeypots",
            "quarantine",
            "auto_response",
            "audit_logging",
            "timeline_reconstruction",
            "openclaw_integration",
            "threat_intelligence_feeds",
            "ransomware_protection",
            "container_security",
            "vpn_integration"
        ]
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": "connected"
    }

# ============ SHUTDOWN HANDLER ============

@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown"""
    logger.info("Shutting down Anti-AI Defense System...")
    client.close()

# ============ MAIN ============

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
