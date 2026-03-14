# Anti-AI Defense System - API Routers
# Modular router architecture for better maintainability

"""Router package exports.

Import sub-routers lazily and tolerate missing optional dependencies during
lightweight test runs. Tests will skip routers whose imports fail.
"""

def _try_import(name, alias):
    try:
        module = __import__(f".{name}", globals(), locals(), ["router"])
        return getattr(module, "router")
    except Exception:
        return None

auth_router = _try_import("auth", "auth_router")
threats_router = _try_import("threats", "threats_router")
alerts_router = _try_import("alerts", "alerts_router")
ai_router = _try_import("ai_analysis", "ai_router")
dashboard_router = _try_import("dashboard", "dashboard_router")
network_router = _try_import("network", "network_router")
hunting_router = _try_import("hunting", "hunting_router")
honeypots_router = _try_import("honeypots", "honeypots_router")
reports_router = _try_import("reports", "reports_router")
agents_router = _try_import("agents", "agents_router")
quarantine_router = _try_import("quarantine", "quarantine_router")
settings_router = _try_import("settings", "settings_router")
response_router = _try_import("response", "response_router")
audit_router = _try_import("audit", "audit_router")
timeline_router = _try_import("timeline", "timeline_router")
websocket_router = _try_import("websocket", "websocket_router")
openclaw_router = _try_import("openclaw", "openclaw_router")
threat_intel_router = _try_import("threat_intel", "threat_intel_router")
ransomware_router = _try_import("ransomware", "ransomware_router")
containers_router = _try_import("containers", "containers_router")
vpn_router = _try_import("vpn", "vpn_router")

__all__ = [
    'auth_router',
    'threats_router', 
    'alerts_router',
    'ai_router',
    'dashboard_router',
    'network_router',
    'hunting_router',
    'honeypots_router',
    'reports_router',
    'agents_router',
    'quarantine_router',
    'settings_router',
    'response_router',
    'audit_router',
    'timeline_router',
    'websocket_router',
    'openclaw_router',
    'threat_intel_router',
    'ransomware_router',
    'containers_router',
    'vpn_router'
]
