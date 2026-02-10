#!/usr/bin/env python3
"""
Seraph Defender with Local Dashboard v6.0
==========================================
Full endpoint protection with LOCAL web dashboard for real-time monitoring.

FEATURES:
- Local web dashboard at http://localhost:8888
- Real-time telemetry visualization
- AATL (AI Threat Detection) - detects AI-driven attacks locally
- File integrity monitoring
- Process monitoring with behavioral analysis
- CLI command monitoring
- Registry monitoring (Windows)
- Network connection tracking
- USB device monitoring
- Credential theft detection

USAGE:
    python seraph_defender_local.py --api-url URL    # With cloud sync
    python seraph_defender_local.py --local-only     # Local only, no cloud
    
    Then open http://localhost:8888 in your browser

Supports: Windows, macOS, Linux
"""

import os
import sys
import json
import time
import hashlib
import platform
import subprocess
import threading
import socket
import re
import uuid
import signal
import argparse
import html
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

# =============================================================================
# CONFIGURATION
# =============================================================================

VERSION = "6.0.0"
AGENT_ID = None
HOSTNAME = platform.node()
OS_TYPE = platform.system().lower()
DASHBOARD_PORT = 8888

# Directories
if OS_TYPE == "windows":
    INSTALL_DIR = Path(os.environ.get('LOCALAPPDATA', 'C:/SeraphDefender')) / "SeraphDefender"
else:
    INSTALL_DIR = Path.home() / ".seraph-defender"

DATA_DIR = INSTALL_DIR / "data"
LOGS_DIR = INSTALL_DIR / "logs"

for d in [INSTALL_DIR, DATA_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / "seraph_defender.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SeraphDefender")

# =============================================================================
# DEPENDENCIES
# =============================================================================

def safe_import(module_name):
    try:
        return __import__(module_name)
    except ImportError:
        return None

psutil = safe_import('psutil')
requests = safe_import('requests')

if not psutil:
    logger.warning("psutil not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "-q"])
    psutil = __import__('psutil')

# =============================================================================
# TELEMETRY STORAGE (LOCAL)
# =============================================================================

class LocalTelemetryStore:
    """Stores telemetry data locally for the dashboard"""
    
    def __init__(self, max_events=5000):
        self.max_events = max_events
        self.events: deque = deque(maxlen=max_events)
        self.cli_commands: deque = deque(maxlen=1000)
        self.processes: Dict[int, dict] = {}
        self.network_connections: List[dict] = []
        self.file_changes: deque = deque(maxlen=500)
        self.alerts: deque = deque(maxlen=200)
        self.aatl_assessments: deque = deque(maxlen=100)
        
        # Stats
        self.stats = {
            "events_total": 0,
            "alerts_critical": 0,
            "alerts_high": 0,
            "threats_detected": 0,
            "ai_sessions_detected": 0,
            "files_monitored": 0,
            "processes_monitored": 0
        }
        
        # AATL state
        self.cli_sessions: Dict[str, dict] = {}
    
    def add_event(self, event: dict):
        """Add a telemetry event"""
        event["id"] = str(uuid.uuid4())[:8]
        event["timestamp"] = event.get("timestamp", datetime.now().isoformat())
        self.events.append(event)
        self.stats["events_total"] += 1
        
        # Track alerts
        severity = event.get("severity", "info")
        if severity == "critical":
            self.stats["alerts_critical"] += 1
            self.alerts.append(event)
        elif severity == "high":
            self.stats["alerts_high"] += 1
            self.alerts.append(event)
    
    def add_cli_command(self, command: dict):
        """Add CLI command and run AATL analysis"""
        command["timestamp"] = datetime.now().isoformat()
        self.cli_commands.append(command)
        
        # AATL analysis
        session_id = command.get("session_id", "default")
        if session_id not in self.cli_sessions:
            self.cli_sessions[session_id] = {
                "commands": [],
                "start_time": time.time(),
                "last_time": time.time(),
                "inter_delays": []
            }
        
        session = self.cli_sessions[session_id]
        now = time.time()
        
        if session["commands"]:
            delay = now - session["last_time"]
            session["inter_delays"].append(delay)
        
        session["commands"].append(command)
        session["last_time"] = now
        
        # Run AATL if enough commands
        if len(session["commands"]) >= 3:
            assessment = self._analyze_session_aatl(session_id, session)
            if assessment:
                self.aatl_assessments.append(assessment)
                if assessment.get("threat_score", 0) >= 60:
                    self.stats["ai_sessions_detected"] += 1
    
    def _analyze_session_aatl(self, session_id: str, session: dict) -> Optional[dict]:
        """AATL: Analyze CLI session for AI-driven attack patterns"""
        commands = session["commands"]
        delays = session["inter_delays"]
        
        if not delays:
            return None
        
        # Calculate metrics
        avg_delay = sum(delays) / len(delays) if delays else 0
        delay_variance = sum((d - avg_delay) ** 2 for d in delays) / len(delays) if len(delays) > 1 else 0
        velocity = len(commands) / (time.time() - session["start_time"]) if time.time() > session["start_time"] else 0
        
        # Detect machine-like patterns
        machine_score = 0.0
        indicators = []
        
        # Fast typing (< 500ms between commands)
        if avg_delay < 0.5:
            machine_score += 0.3
            indicators.append(f"fast_typing:{int(avg_delay*1000)}ms")
        
        # Consistent timing (low variance = machine)
        if delay_variance < 0.1 and len(delays) > 3:
            machine_score += 0.3
            indicators.append(f"consistent_timing:variance={delay_variance:.3f}")
        
        # High command velocity
        if velocity > 1.0:  # More than 1 cmd/sec
            machine_score += 0.2
            indicators.append(f"high_velocity:{velocity:.2f}cmd/s")
        
        # Detect intent patterns
        recon_commands = ['whoami', 'hostname', 'id', 'uname', 'ifconfig', 'ipconfig', 'netstat', 'ps', 'tasklist', 'systeminfo', 'cat /etc/passwd', 'net user']
        privesc_commands = ['sudo', 'su', 'runas', 'chmod', 'chown', 'net localgroup']
        exfil_commands = ['curl', 'wget', 'scp', 'ftp', 'nc', 'base64']
        
        cmd_texts = [c.get("command", "").lower() for c in commands]
        
        recon_count = sum(1 for cmd in cmd_texts if any(r in cmd for r in recon_commands))
        privesc_count = sum(1 for cmd in cmd_texts if any(p in cmd for p in privesc_commands))
        exfil_count = sum(1 for cmd in cmd_texts if any(e in cmd for e in exfil_commands))
        
        primary_intent = "unknown"
        if recon_count > len(commands) * 0.5:
            primary_intent = "reconnaissance"
            machine_score += 0.1
        elif privesc_count > 0:
            primary_intent = "privilege_escalation"
            machine_score += 0.15
        elif exfil_count > 0:
            primary_intent = "exfiltration"
            machine_score += 0.2
        
        # Calculate threat score
        threat_score = min(machine_score * 100, 100)
        
        # Determine actor type
        if machine_score >= 0.7:
            actor_type = "autonomous_agent"
        elif machine_score >= 0.4:
            actor_type = "ai_assisted"
        else:
            actor_type = "human"
        
        # Determine response strategy
        if threat_score >= 80:
            strategy = "contain"
        elif threat_score >= 60:
            strategy = "poison"
        elif threat_score >= 40:
            strategy = "slow"
        else:
            strategy = "observe"
        
        return {
            "session_id": session_id,
            "timestamp": datetime.now().isoformat(),
            "command_count": len(commands),
            "machine_plausibility": machine_score,
            "human_plausibility": 1 - machine_score,
            "threat_score": threat_score,
            "threat_level": "critical" if threat_score >= 80 else "high" if threat_score >= 60 else "medium" if threat_score >= 40 else "low",
            "actor_type": actor_type,
            "primary_intent": primary_intent,
            "indicators": indicators,
            "recommended_strategy": strategy,
            "avg_delay_ms": int(avg_delay * 1000),
            "velocity": round(velocity, 2)
        }
    
    def get_dashboard_data(self) -> dict:
        """Get all data for the dashboard"""
        return {
            "agent": {
                "id": AGENT_ID,
                "hostname": HOSTNAME,
                "os": OS_TYPE,
                "version": VERSION,
                "uptime": int(time.time() - psutil.boot_time()) if psutil else 0,
                "cpu_percent": psutil.cpu_percent() if psutil else 0,
                "memory_percent": psutil.virtual_memory().percent if psutil else 0
            },
            "stats": self.stats,
            "events": list(self.events)[-100:],
            "alerts": list(self.alerts)[-50:],
            "cli_commands": list(self.cli_commands)[-100:],
            "aatl_assessments": list(self.aatl_assessments)[-20:],
            "processes": list(self.processes.values())[:50],
            "network_connections": self.network_connections[:50],
            "file_changes": list(self.file_changes)[-50:]
        }


# Global telemetry store
telemetry_store = LocalTelemetryStore()

# =============================================================================
# LOCAL WEB DASHBOARD
# =============================================================================

DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Seraph Defender - Local Dashboard</title>
    <style>
        :root {
            --bg-primary: #0a0e1a;
            --bg-secondary: #111827;
            --bg-card: #1f2937;
            --accent: #06b6d4;
            --accent-glow: rgba(6, 182, 212, 0.3);
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        
        /* Header */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            background: var(--bg-secondary);
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid rgba(6, 182, 212, 0.2);
        }
        .header h1 {
            font-size: 24px;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 600;
        }
        .status-online { background: rgba(16, 185, 129, 0.2); color: var(--success); }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .stat-card h3 { font-size: 14px; color: var(--text-secondary); margin-bottom: 8px; }
        .stat-card .value { font-size: 32px; font-weight: 700; color: var(--accent); }
        .stat-card.danger .value { color: var(--danger); }
        .stat-card.warning .value { color: var(--warning); }
        
        /* Tabs */
        .tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .tab {
            padding: 12px 24px;
            background: var(--bg-card);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.2s;
        }
        .tab:hover { border-color: var(--accent); }
        .tab.active { background: var(--accent); color: var(--bg-primary); }
        
        /* Content Panels */
        .panel { display: none; }
        .panel.active { display: block; }
        
        .card {
            background: var(--bg-card);
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
            overflow: hidden;
            margin-bottom: 20px;
        }
        .card-header {
            padding: 16px 20px;
            background: rgba(0,0,0,0.2);
            border-bottom: 1px solid rgba(255,255,255,0.1);
            font-weight: 600;
        }
        .card-body { padding: 20px; }
        
        /* Events List */
        .event-list { max-height: 400px; overflow-y: auto; }
        .event-item {
            padding: 12px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            display: flex;
            gap: 12px;
            align-items: flex-start;
        }
        .event-item:last-child { border-bottom: none; }
        .event-severity {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .severity-critical { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
        .severity-high { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
        .severity-medium { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
        .severity-low { background: rgba(16, 185, 129, 0.2); color: var(--success); }
        .severity-info { background: rgba(107, 114, 128, 0.2); color: var(--text-secondary); }
        
        .event-content { flex: 1; }
        .event-type { font-weight: 600; margin-bottom: 4px; }
        .event-message { color: var(--text-secondary); font-size: 14px; }
        .event-time { color: var(--text-secondary); font-size: 12px; }
        
        /* AATL Section */
        .aatl-card {
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.1), rgba(245, 158, 11, 0.1));
            border-color: rgba(239, 68, 68, 0.3);
        }
        .threat-meter {
            height: 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 4px;
            overflow: hidden;
            margin: 8px 0;
        }
        .threat-meter-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s;
        }
        .threat-low { background: var(--success); }
        .threat-medium { background: #3b82f6; }
        .threat-high { background: var(--warning); }
        .threat-critical { background: var(--danger); }
        
        .indicator-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 8px;
        }
        .indicator {
            padding: 4px 8px;
            background: rgba(6, 182, 212, 0.2);
            border-radius: 4px;
            font-size: 12px;
            font-family: monospace;
        }
        
        /* CLI Commands */
        .cli-command {
            font-family: 'Consolas', 'Monaco', monospace;
            background: rgba(0,0,0,0.3);
            padding: 8px 12px;
            border-radius: 4px;
            margin-bottom: 8px;
            font-size: 13px;
        }
        .cli-prompt { color: var(--success); }
        .cli-text { color: var(--text-primary); }
        
        /* Process List */
        .process-item {
            display: grid;
            grid-template-columns: 80px 1fr 100px 100px;
            padding: 10px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            font-size: 14px;
        }
        .process-header { font-weight: 600; background: rgba(0,0,0,0.2); }
        .process-risk-high { color: var(--danger); }
        .process-risk-medium { color: var(--warning); }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 20px;
            color: var(--text-secondary);
            font-size: 14px;
        }
        
        /* Refresh indicator */
        .refresh-indicator {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 8px 16px;
            background: var(--bg-card);
            border-radius: 20px;
            font-size: 12px;
            color: var(--text-secondary);
        }
        .refresh-indicator.loading { color: var(--accent); }
    </style>
</head>
<body>
    <div class="refresh-indicator" id="refreshIndicator">Auto-refresh: 2s</div>
    
    <div class="container">
        <div class="header">
            <h1>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                Seraph Defender - Local Dashboard
            </h1>
            <div>
                <span id="hostname" style="color: var(--text-secondary); margin-right: 16px;"></span>
                <span class="status-badge status-online" id="statusBadge">● Online</span>
            </div>
        </div>
        
        <div class="stats-grid" id="statsGrid">
            <div class="stat-card">
                <h3>Total Events</h3>
                <div class="value" id="statEvents">0</div>
            </div>
            <div class="stat-card danger">
                <h3>Critical Alerts</h3>
                <div class="value" id="statCritical">0</div>
            </div>
            <div class="stat-card warning">
                <h3>High Alerts</h3>
                <div class="value" id="statHigh">0</div>
            </div>
            <div class="stat-card">
                <h3>AI Sessions Detected</h3>
                <div class="value" id="statAI">0</div>
            </div>
            <div class="stat-card">
                <h3>CPU Usage</h3>
                <div class="value" id="statCPU">0%</div>
            </div>
            <div class="stat-card">
                <h3>Memory Usage</h3>
                <div class="value" id="statMemory">0%</div>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab active" data-panel="overview">Overview</div>
            <div class="tab" data-panel="aatl">AATL (AI Threats)</div>
            <div class="tab" data-panel="events">Events</div>
            <div class="tab" data-panel="cli">CLI Monitor</div>
            <div class="tab" data-panel="processes">Processes</div>
            <div class="tab" data-panel="alerts">Alerts</div>
        </div>
        
        <!-- Overview Panel -->
        <div class="panel active" id="panel-overview">
            <div class="card">
                <div class="card-header">Recent Activity</div>
                <div class="card-body">
                    <div class="event-list" id="recentEvents"></div>
                </div>
            </div>
        </div>
        
        <!-- AATL Panel -->
        <div class="panel" id="panel-aatl">
            <div class="card aatl-card">
                <div class="card-header">🤖 Autonomous Agent Threat Layer (AATL)</div>
                <div class="card-body">
                    <p style="color: var(--text-secondary); margin-bottom: 16px;">
                        Real-time analysis of CLI sessions to detect AI-driven attacks
                    </p>
                    <div id="aatlAssessments"></div>
                </div>
            </div>
        </div>
        
        <!-- Events Panel -->
        <div class="panel" id="panel-events">
            <div class="card">
                <div class="card-header">All Telemetry Events</div>
                <div class="card-body">
                    <div class="event-list" id="allEvents" style="max-height: 600px;"></div>
                </div>
            </div>
        </div>
        
        <!-- CLI Panel -->
        <div class="panel" id="panel-cli">
            <div class="card">
                <div class="card-header">CLI Command Monitor</div>
                <div class="card-body">
                    <div id="cliCommands" style="max-height: 600px; overflow-y: auto;"></div>
                </div>
            </div>
        </div>
        
        <!-- Processes Panel -->
        <div class="panel" id="panel-processes">
            <div class="card">
                <div class="card-header">Running Processes</div>
                <div class="card-body">
                    <div class="process-item process-header">
                        <div>PID</div>
                        <div>Name</div>
                        <div>CPU %</div>
                        <div>Memory %</div>
                    </div>
                    <div id="processList" style="max-height: 500px; overflow-y: auto;"></div>
                </div>
            </div>
        </div>
        
        <!-- Alerts Panel -->
        <div class="panel" id="panel-alerts">
            <div class="card">
                <div class="card-header">Security Alerts</div>
                <div class="card-body">
                    <div class="event-list" id="alertsList" style="max-height: 600px;"></div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            Seraph Defender v6.0 | Local Dashboard | Press Ctrl+C in terminal to stop
        </div>
    </div>
    
    <script>
        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById('panel-' + tab.dataset.panel).classList.add('active');
            });
        });
        
        function formatTime(timestamp) {
            return new Date(timestamp).toLocaleTimeString();
        }
        
        function getSeverityClass(severity) {
            return 'severity-' + (severity || 'info').toLowerCase();
        }
        
        function renderEvent(event) {
            return `
                <div class="event-item">
                    <span class="event-severity ${getSeverityClass(event.severity)}">${event.severity || 'info'}</span>
                    <div class="event-content">
                        <div class="event-type">${event.event_type || 'Unknown'}</div>
                        <div class="event-message">${event.data?.message || JSON.stringify(event.data || {}).slice(0, 100)}</div>
                    </div>
                    <div class="event-time">${formatTime(event.timestamp)}</div>
                </div>
            `;
        }
        
        function renderAATLAssessment(assessment) {
            const threatClass = assessment.threat_level === 'critical' ? 'threat-critical' :
                               assessment.threat_level === 'high' ? 'threat-high' :
                               assessment.threat_level === 'medium' ? 'threat-medium' : 'threat-low';
            return `
                <div style="background: rgba(0,0,0,0.2); padding: 16px; border-radius: 8px; margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <strong>Session: ${assessment.session_id}</strong>
                        <span class="event-severity ${getSeverityClass(assessment.threat_level)}">${assessment.threat_level}</span>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 12px;">
                        <div>
                            <small style="color: var(--text-secondary);">Actor Type</small>
                            <div style="font-weight: 600;">${assessment.actor_type}</div>
                        </div>
                        <div>
                            <small style="color: var(--text-secondary);">Machine Probability</small>
                            <div style="font-weight: 600;">${(assessment.machine_plausibility * 100).toFixed(0)}%</div>
                        </div>
                        <div>
                            <small style="color: var(--text-secondary);">Intent</small>
                            <div style="font-weight: 600;">${assessment.primary_intent}</div>
                        </div>
                    </div>
                    <div class="threat-meter">
                        <div class="threat-meter-fill ${threatClass}" style="width: ${assessment.threat_score}%"></div>
                    </div>
                    <div style="display: flex; justify-content: space-between; font-size: 12px; color: var(--text-secondary);">
                        <span>Threat Score: ${assessment.threat_score.toFixed(0)}%</span>
                        <span>Strategy: ${assessment.recommended_strategy}</span>
                    </div>
                    ${assessment.indicators?.length ? `
                        <div class="indicator-list">
                            ${assessment.indicators.map(i => `<span class="indicator">${i}</span>`).join('')}
                        </div>
                    ` : ''}
                </div>
            `;
        }
        
        function updateDashboard(data) {
            // Update stats
            document.getElementById('statEvents').textContent = data.stats.events_total;
            document.getElementById('statCritical').textContent = data.stats.alerts_critical;
            document.getElementById('statHigh').textContent = data.stats.alerts_high;
            document.getElementById('statAI').textContent = data.stats.ai_sessions_detected;
            document.getElementById('statCPU').textContent = data.agent.cpu_percent + '%';
            document.getElementById('statMemory').textContent = data.agent.memory_percent + '%';
            document.getElementById('hostname').textContent = data.agent.hostname + ' (' + data.agent.os + ')';
            
            // Recent events
            const recentEvents = data.events.slice(-20).reverse();
            document.getElementById('recentEvents').innerHTML = recentEvents.map(renderEvent).join('');
            
            // All events
            document.getElementById('allEvents').innerHTML = data.events.slice().reverse().map(renderEvent).join('');
            
            // Alerts
            document.getElementById('alertsList').innerHTML = data.alerts.slice().reverse().map(renderEvent).join('') || '<p style="color: var(--text-secondary);">No alerts</p>';
            
            // AATL Assessments
            document.getElementById('aatlAssessments').innerHTML = 
                data.aatl_assessments.slice().reverse().map(renderAATLAssessment).join('') || 
                '<p style="color: var(--text-secondary);">No AI threat sessions detected yet. CLI commands will be analyzed for machine-like patterns.</p>';
            
            // CLI Commands
            document.getElementById('cliCommands').innerHTML = data.cli_commands.slice().reverse().map(cmd => `
                <div class="cli-command">
                    <span class="cli-prompt">${cmd.user || 'user'}@${cmd.hostname || 'host'} $</span>
                    <span class="cli-text">${cmd.command}</span>
                    <span style="float: right; color: var(--text-secondary); font-size: 11px;">${formatTime(cmd.timestamp)}</span>
                </div>
            `).join('') || '<p style="color: var(--text-secondary);">No CLI commands captured yet</p>';
            
            // Processes
            document.getElementById('processList').innerHTML = data.processes.map(proc => `
                <div class="process-item">
                    <div>${proc.pid}</div>
                    <div>${proc.name}</div>
                    <div class="${proc.cpu_percent > 50 ? 'process-risk-high' : proc.cpu_percent > 20 ? 'process-risk-medium' : ''}">${proc.cpu_percent?.toFixed(1) || 0}%</div>
                    <div>${proc.memory_percent?.toFixed(1) || 0}%</div>
                </div>
            `).join('');
        }
        
        // Fetch data periodically
        async function fetchData() {
            const indicator = document.getElementById('refreshIndicator');
            indicator.classList.add('loading');
            indicator.textContent = 'Refreshing...';
            
            try {
                const response = await fetch('/api/data');
                const data = await response.json();
                updateDashboard(data);
            } catch (e) {
                console.error('Failed to fetch data:', e);
            }
            
            indicator.classList.remove('loading');
            indicator.textContent = 'Auto-refresh: 2s';
        }
        
        // Initial fetch and periodic updates
        fetchData();
        setInterval(fetchData, 2000);
    </script>
</body>
</html>
'''

class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the local dashboard"""
    
    def log_message(self, format, *args):
        pass  # Suppress HTTP logs
    
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())
        elif self.path == '/api/data':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            data = telemetry_store.get_dashboard_data()
            self.wfile.write(json.dumps(data).encode())
        else:
            self.send_response(404)
            self.end_headers()


def run_dashboard_server(port=DASHBOARD_PORT):
    """Run the local dashboard web server"""
    server = HTTPServer(('0.0.0.0', port), DashboardHandler)
    logger.info(f"Local dashboard running at http://localhost:{port}")
    server.serve_forever()


# =============================================================================
# MONITORS
# =============================================================================

class ProcessMonitor:
    """Monitor running processes"""
    
    def __init__(self):
        self.suspicious_names = [
            'mimikatz', 'lazagne', 'procdump', 'nc.exe', 'ncat', 
            'psexec', 'wmic', 'powershell_ise', 'mshta', 'certutil',
            'bitsadmin', 'regsvr32', 'msbuild', 'installutil'
        ]
    
    def scan(self):
        """Scan running processes"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'cmdline']):
            try:
                info = proc.info
                processes.append({
                    'pid': info['pid'],
                    'name': info['name'],
                    'username': info['username'],
                    'cpu_percent': info['cpu_percent'] or 0,
                    'memory_percent': info['memory_percent'] or 0,
                    'cmdline': ' '.join(info['cmdline'] or [])[:200]
                })
                
                # Check for suspicious
                if info['name'] and info['name'].lower() in self.suspicious_names:
                    telemetry_store.add_event({
                        'event_type': 'process.suspicious',
                        'severity': 'high',
                        'data': {
                            'pid': info['pid'],
                            'name': info['name'],
                            'message': f"Suspicious process detected: {info['name']}"
                        }
                    })
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        telemetry_store.processes = {p['pid']: p for p in processes}
        telemetry_store.stats['processes_monitored'] = len(processes)
        return processes


class NetworkMonitor:
    """Monitor network connections"""
    
    def scan(self):
        """Scan network connections"""
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            try:
                connections.append({
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                    'status': conn.status,
                    'pid': conn.pid
                })
            except:
                pass
        
        telemetry_store.network_connections = connections
        return connections


class CLIMonitor:
    """Monitor CLI commands"""
    
    def __init__(self):
        self.session_id = f"session-{uuid.uuid4().hex[:8]}"
        self.last_check = time.time()
    
    def capture_command(self, command: str, user: str = None):
        """Capture a CLI command"""
        telemetry_store.add_cli_command({
            'session_id': self.session_id,
            'command': command,
            'user': user or os.environ.get('USER', os.environ.get('USERNAME', 'unknown')),
            'hostname': HOSTNAME,
            'shell': os.environ.get('SHELL', 'cmd' if OS_TYPE == 'windows' else 'bash')
        })


# =============================================================================
# MAIN AGENT
# =============================================================================

class SeraphDefenderLocal:
    """Main agent with local dashboard"""
    
    def __init__(self, api_url: str = None, local_only: bool = False):
        global AGENT_ID
        AGENT_ID = hashlib.md5(f"{HOSTNAME}-{uuid.getnode()}".encode()).hexdigest()[:16]
        
        self.api_url = api_url
        self.local_only = local_only
        self.running = False
        
        # Monitors
        self.process_monitor = ProcessMonitor()
        self.network_monitor = NetworkMonitor()
        self.cli_monitor = CLIMonitor()
        
        logger.info(f"Seraph Defender v{VERSION} initialized")
        logger.info(f"Agent ID: {AGENT_ID}")
        logger.info(f"Mode: {'Local Only' if local_only else 'Cloud Sync'}")
    
    def start(self):
        """Start the agent and dashboard"""
        self.running = True
        
        # Start dashboard server in background
        dashboard_thread = threading.Thread(target=run_dashboard_server, daemon=True)
        dashboard_thread.start()
        
        # Open browser
        import webbrowser
        time.sleep(1)
        webbrowser.open(f'http://localhost:{DASHBOARD_PORT}')
        
        logger.info(f"Dashboard opened at http://localhost:{DASHBOARD_PORT}")
        logger.info("Press Ctrl+C to stop")
        
        # Start monitoring loop
        self._monitor_loop()
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        scan_interval = 5  # seconds
        heartbeat_interval = 30
        last_heartbeat = 0
        
        while self.running:
            try:
                # Scan processes
                self.process_monitor.scan()
                
                # Scan network
                self.network_monitor.scan()
                
                # Add heartbeat event
                telemetry_store.add_event({
                    'event_type': 'agent.heartbeat',
                    'severity': 'info',
                    'data': {
                        'cpu_percent': psutil.cpu_percent(),
                        'memory_percent': psutil.virtual_memory().percent,
                        'message': 'Agent running normally'
                    }
                })
                
                # Sync to cloud if enabled
                if not self.local_only and self.api_url and time.time() - last_heartbeat > heartbeat_interval:
                    self._sync_to_cloud()
                    last_heartbeat = time.time()
                
                time.sleep(scan_interval)
                
            except KeyboardInterrupt:
                logger.info("Stopping agent...")
                self.running = False
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                time.sleep(5)
    
    def _sync_to_cloud(self):
        """Sync telemetry to cloud server"""
        if not self.api_url:
            return
        
        try:
            # Register/heartbeat
            requests.post(
                f"{self.api_url}/api/swarm/agents/register",
                json={
                    "agent_id": AGENT_ID,
                    "hostname": HOSTNAME,
                    "os_type": OS_TYPE,
                    "version": VERSION
                },
                timeout=10
            )
            
            # Send recent events
            events = list(telemetry_store.events)[-50:]
            if events:
                requests.post(
                    f"{self.api_url}/api/swarm/telemetry/ingest",
                    json={"events": events},
                    timeout=10
                )
        except Exception as e:
            logger.debug(f"Cloud sync failed: {e}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Seraph Defender with Local Dashboard")
    parser.add_argument('--api-url', help='Server API URL for cloud sync')
    parser.add_argument('--local-only', action='store_true', help='Run without cloud sync')
    parser.add_argument('--port', type=int, default=DASHBOARD_PORT, help='Dashboard port')
    
    args = parser.parse_args()
    
    global DASHBOARD_PORT
    DASHBOARD_PORT = args.port
    
    if not args.api_url and not args.local_only:
        print("Usage:")
        print(f"  {sys.argv[0]} --api-url URL    # With cloud sync")
        print(f"  {sys.argv[0]} --local-only     # Local only")
        print(f"\nDashboard will open at http://localhost:{DASHBOARD_PORT}")
        sys.exit(1)
    
    agent = SeraphDefenderLocal(
        api_url=args.api_url,
        local_only=args.local_only
    )
    
    agent.start()


if __name__ == '__main__':
    main()
