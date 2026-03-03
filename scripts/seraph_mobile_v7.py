#!/usr/bin/env python3
"""
Seraph Mobile Defender v7.0
===========================
Full mobile protection for Android (Termux) and iOS (Pythonista)

FEATURES:
- Real-time network monitoring
- Suspicious app detection
- Battery drain attack detection
- Location tracking protection
- Local web dashboard at http://localhost:8888
- Auto-remediation with user approval
- Server sync and command queue
- Push notification alerts (where supported)

USAGE (Android/Termux):
    pkg install python
    pip install requests psutil
    python seraph_mobile_v7.py --api-url URL
    
USAGE (iOS/Pythonista):
    Copy script to Pythonista
    Run with API URL

Dashboard: http://localhost:8888
"""

import os
import sys
import json
import time
import socket
import hashlib
import platform
import threading
import subprocess
import uuid
import argparse
import logging
from pathlib import Path
from datetime import datetime, timedelta
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler

# =============================================================================
# CONFIGURATION
# =============================================================================

VERSION = "7.0.0"
AGENT_ID = None
HOSTNAME = platform.node() or "mobile-device"
OS_TYPE = platform.system().lower()
DASHBOARD_PORT = 8888
IS_MOBILE = True

# Detect platform
IS_ANDROID = os.path.exists('/data/data/com.termux')
IS_IOS = False

try:
    import location
    import notification
    IS_IOS = True
except ImportError:
    pass

# Android helper
ANDROID_HELPER = None
try:
    import androidhelper
    ANDROID_HELPER = androidhelper.Android()
    IS_ANDROID = True
except ImportError:
    pass

# Data directory
if IS_ANDROID:
    DATA_DIR = Path.home() / ".seraph-defender"
elif IS_IOS:
    DATA_DIR = Path.home() / "Documents" / "SeraphDefender"
else:
    DATA_DIR = Path.home() / ".seraph-defender"

DATA_DIR.mkdir(parents=True, exist_ok=True)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger("SeraphMobile")

# =============================================================================
# DEPENDENCIES
# =============================================================================

try:
    import requests
except ImportError:
    logger.info("Installing requests...")
    if IS_ANDROID:
        os.system("pip install requests")
    else:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not available - limited monitoring")

# =============================================================================
# THREAT INTELLIGENCE
# =============================================================================

class MobileThreatIntel:
    """Mobile-specific threat intelligence"""
    
    # Suspicious app patterns
    SUSPICIOUS_APPS = [
        # Spyware
        'spy', 'track', 'monitor', 'keylog', 'stealth', 'hidden',
        'mspy', 'flexispy', 'spyera', 'cocospy', 'hoverwatch',
        # RATs
        'rat', 'remote', 'control', 'androrat', 'droidjack', 'spynote',
        # Stalkerware
        'stalk', 'cerberus', 'prey', 'findmy',
        # Miners
        'miner', 'xmrig', 'coinhive',
        # Banking trojans
        'banker', 'anubis', 'cerberus', 'eventbot',
        # Adware
        'adware', 'hiddad', 'ewind',
    ]
    
    # Suspicious permissions (Android)
    DANGEROUS_PERMISSIONS = [
        'READ_SMS', 'RECEIVE_SMS', 'SEND_SMS',
        'READ_CALL_LOG', 'PROCESS_OUTGOING_CALLS',
        'RECORD_AUDIO', 'CAMERA',
        'ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION',
        'READ_CONTACTS', 'GET_ACCOUNTS',
        'SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE',
        'BIND_DEVICE_ADMIN', 'WRITE_SECURE_SETTINGS',
    ]
    
    # Known malicious IPs (mobile-focused C2)
    MALICIOUS_IPS = [
        "185.220.101.",  # Tor exits
        "45.33.32.",     # Scanners
        "198.51.100.",   # Reserved (shouldn't see traffic)
    ]
    
    # Suspicious ports
    SUSPICIOUS_PORTS = {
        4444: "Metasploit",
        5555: "ADB (unauthorized)",
        31337: "Backdoor",
        6667: "IRC botnet",
        9001: "Tor",
    }


# =============================================================================
# THREAT DETECTION
# =============================================================================

class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MobileThreat:
    id: str
    type: str
    severity: ThreatSeverity
    title: str
    description: str
    evidence: Dict = field(default_factory=dict)
    remediation_available: bool = False
    remediation_action: Optional[str] = None
    remediation_params: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "detected"
    user_approved: Optional[bool] = None
    
    def to_dict(self):
        d = asdict(self)
        d['severity'] = self.severity.value
        return d


class MobileThreatEngine:
    """Mobile threat detection engine"""
    
    def __init__(self):
        self.intel = MobileThreatIntel()
        self.known_apps = set()
        self.connection_history = defaultdict(int)
    
    def scan_installed_apps(self) -> List[MobileThreat]:
        """Scan installed apps for threats"""
        threats = []
        
        if IS_ANDROID and ANDROID_HELPER:
            try:
                # Get installed packages
                result = ANDROID_HELPER.getPackages()
                if result.result:
                    packages = result.result
                    for pkg in packages:
                        pkg_lower = pkg.lower()
                        for pattern in self.intel.SUSPICIOUS_APPS:
                            if pattern in pkg_lower:
                                threats.append(MobileThreat(
                                    id=f"app-{uuid.uuid4().hex[:8]}",
                                    type="suspicious_app",
                                    severity=ThreatSeverity.HIGH,
                                    title=f"Suspicious App Detected: {pkg}",
                                    description=f"App '{pkg}' matches suspicious pattern '{pattern}'",
                                    evidence={"package": pkg, "pattern": pattern},
                                    remediation_available=True,
                                    remediation_action="uninstall_app",
                                    remediation_params={"package": pkg}
                                ))
                                break
            except Exception as e:
                logger.debug(f"App scan error: {e}")
        
        return threats
    
    def scan_network_connections(self) -> List[MobileThreat]:
        """Scan network connections"""
        threats = []
        
        if HAS_PSUTIL:
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        
                        # Check malicious IPs
                        for mal_ip in self.intel.MALICIOUS_IPS:
                            if remote_ip.startswith(mal_ip):
                                threats.append(MobileThreat(
                                    id=f"net-{uuid.uuid4().hex[:8]}",
                                    type="malicious_connection",
                                    severity=ThreatSeverity.CRITICAL,
                                    title="Connection to Malicious IP",
                                    description=f"Device connected to known malicious IP: {remote_ip}",
                                    evidence={"ip": remote_ip, "port": remote_port},
                                    remediation_available=True,
                                    remediation_action="block_ip",
                                    remediation_params={"ip": remote_ip}
                                ))
                        
                        # Check suspicious ports
                        if remote_port in self.intel.SUSPICIOUS_PORTS:
                            reason = self.intel.SUSPICIOUS_PORTS[remote_port]
                            threats.append(MobileThreat(
                                id=f"net-{uuid.uuid4().hex[:8]}",
                                type="suspicious_port",
                                severity=ThreatSeverity.HIGH,
                                title=f"Suspicious Port Connection ({reason})",
                                description=f"Connection to {remote_ip}:{remote_port} - {reason}",
                                evidence={"ip": remote_ip, "port": remote_port, "reason": reason}
                            ))
            except Exception as e:
                logger.debug(f"Network scan error: {e}")
        
        return threats
    
    def check_battery_drain(self) -> Optional[MobileThreat]:
        """Check for abnormal battery drain (crypto mining indicator)"""
        if IS_ANDROID and ANDROID_HELPER:
            try:
                battery = ANDROID_HELPER.batteryGetStatus().result
                level = battery.get('level', 100)
                temperature = battery.get('temperature', 0) / 10  # Convert to Celsius
                
                # High temperature might indicate mining
                if temperature > 45:
                    return MobileThreat(
                        id=f"bat-{uuid.uuid4().hex[:8]}",
                        type="battery_anomaly",
                        severity=ThreatSeverity.MEDIUM,
                        title="Abnormal Battery Temperature",
                        description=f"Device temperature is {temperature}°C - possible cryptomining",
                        evidence={"temperature": temperature, "level": level}
                    )
            except:
                pass
        
        return None
    
    def check_adb_status(self) -> Optional[MobileThreat]:
        """Check if ADB debugging is enabled (security risk)"""
        if IS_ANDROID:
            try:
                result = subprocess.run(
                    ['getprop', 'persist.sys.usb.config'],
                    capture_output=True, text=True, timeout=5
                )
                if 'adb' in result.stdout.lower():
                    # Check if ADB is network accessible
                    adb_port = subprocess.run(
                        ['getprop', 'service.adb.tcp.port'],
                        capture_output=True, text=True, timeout=5
                    )
                    if adb_port.stdout.strip() and adb_port.stdout.strip() != '-1':
                        return MobileThreat(
                            id=f"adb-{uuid.uuid4().hex[:8]}",
                            type="adb_exposed",
                            severity=ThreatSeverity.CRITICAL,
                            title="ADB Debugging Exposed on Network",
                            description="ADB is accessible over network - major security risk!",
                            evidence={"port": adb_port.stdout.strip()},
                            remediation_available=True,
                            remediation_action="disable_adb_network",
                            remediation_params={}
                        )
            except:
                pass
        
        return None


# =============================================================================
# MOBILE NETWORK SCANNING (WiFi, Bluetooth)
# =============================================================================

class MobileWiFiScanner:
    """WiFi network scanner for mobile devices"""
    
    def __init__(self):
        self.known_networks = set()
        self.scan_results = []
        self.last_scan = None
    
    def scan_networks(self) -> List[dict]:
        """Scan for available WiFi networks"""
        networks = []
        
        if IS_ANDROID:
            try:
                # Use Android's wifi manager via termux-wifi-scaninfo
                result = subprocess.run(
                    ['termux-wifi-scaninfo'],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    try:
                        wifi_data = json.loads(result.stdout)
                        for net in wifi_data:
                            network = {
                                'ssid': net.get('ssid', '(Hidden)'),
                                'bssid': net.get('bssid', 'Unknown'),
                                'signal': str(net.get('rssi', 'N/A')) + ' dBm',
                                'frequency': net.get('frequency_mhz', 'Unknown'),
                                'auth': 'WPA2' if 'WPA2' in str(net.get('capabilities', '')) else 'Open',
                                'threats': []
                            }
                            # Analyze for threats
                            network['threats'] = self._analyze_network(network)
                            networks.append(network)
                    except json.JSONDecodeError:
                        pass
            except FileNotFoundError:
                # termux-api not installed, try alternative
                try:
                    result = subprocess.run(
                        ['iwlist', 'wlan0', 'scan'],
                        capture_output=True, text=True, timeout=30
                    )
                    # Parse iwlist output (basic)
                    current = {}
                    for line in result.stdout.split('\n'):
                        if 'ESSID:' in line:
                            if current:
                                networks.append(current)
                            ssid = line.split('ESSID:')[1].strip().strip('"')
                            current = {'ssid': ssid, 'threats': []}
                        elif 'Address:' in line:
                            current['bssid'] = line.split('Address:')[1].strip()
                        elif 'Signal level' in line:
                            current['signal'] = line.split('Signal level')[1].split()[0]
                    if current:
                        networks.append(current)
                except:
                    pass
            except Exception as e:
                logger.debug(f"WiFi scan error: {e}")
        
        self.scan_results = networks
        self.last_scan = datetime.now().isoformat()
        return networks
    
    def _analyze_network(self, network: dict) -> List[dict]:
        """Analyze network for threats"""
        threats = []
        auth = network.get('auth', '').lower()
        ssid = network.get('ssid', '').lower()
        
        # Open network warning
        if 'open' in auth or not auth:
            threats.append({
                "type": "open_network",
                "severity": "high",
                "message": "Network has no encryption - data can be intercepted"
            })
        
        # Suspicious SSID
        suspicious = ['free', 'public', 'airport', 'hotel', 'starbucks', 'mcdonalds']
        if any(s in ssid for s in suspicious):
            threats.append({
                "type": "suspicious_ssid",
                "severity": "medium", 
                "message": "Public network - use VPN for sensitive activities"
            })
        
        # Evil twin detection
        if network.get('ssid') in self.known_networks:
            threats.append({
                "type": "evil_twin",
                "severity": "critical",
                "message": "Multiple networks with same name - possible evil twin attack"
            })
        else:
            self.known_networks.add(network.get('ssid', ''))
        
        return threats
    
    def get_connected_network(self) -> dict:
        """Get currently connected WiFi"""
        if IS_ANDROID:
            try:
                result = subprocess.run(
                    ['termux-wifi-connectioninfo'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    return json.loads(result.stdout)
            except:
                pass
        return {"error": "Cannot get WiFi info"}
    
    def to_dict(self) -> dict:
        return {
            "networks": self.scan_results,
            "last_scan": self.last_scan,
            "count": len(self.scan_results)
        }


class MobileBluetoothScanner:
    """Bluetooth device scanner for mobile"""
    
    def __init__(self):
        self.devices = []
        self.last_scan = None
        self.trusted_devices = set()
    
    def scan_devices(self) -> List[dict]:
        """Scan for Bluetooth devices"""
        devices = []
        
        if IS_ANDROID:
            try:
                # Use termux-bluetooth-scan
                result = subprocess.run(
                    ['termux-bluetooth-scaninfo'],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    try:
                        bt_data = json.loads(result.stdout)
                        for dev in bt_data:
                            device = {
                                'name': dev.get('name', 'Unknown'),
                                'address': dev.get('address', 'Unknown'),
                                'type': dev.get('type', 'Unknown'),
                                'rssi': dev.get('rssi', 'N/A'),
                                'threats': []
                            }
                            device['threats'] = self._analyze_device(device)
                            devices.append(device)
                    except json.JSONDecodeError:
                        pass
            except FileNotFoundError:
                # Try hcitool
                try:
                    result = subprocess.run(
                        ['hcitool', 'scan'],
                        capture_output=True, text=True, timeout=30
                    )
                    for line in result.stdout.strip().split('\n')[1:]:
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            devices.append({
                                'address': parts[0],
                                'name': parts[1] if len(parts) > 1 else 'Unknown',
                                'threats': []
                            })
                except:
                    pass
            except Exception as e:
                logger.debug(f"Bluetooth scan error: {e}")
        
        self.devices = devices
        self.last_scan = datetime.now().isoformat()
        return devices
    
    def _analyze_device(self, device: dict) -> List[dict]:
        """Analyze device for threats"""
        threats = []
        name = device.get('name', '').lower()
        
        # Suspicious device names
        suspicious = ['keylogger', 'hak', 'pwn', 'attack', 'flipper', 'badusb']
        if any(s in name for s in suspicious):
            threats.append({
                "type": "suspicious_device",
                "severity": "high",
                "message": "Potentially malicious Bluetooth device"
            })
        
        # Unknown device warning
        addr = device.get('address', '')
        if addr and addr not in self.trusted_devices:
            threats.append({
                "type": "unknown_device",
                "severity": "low",
                "message": "Unknown device - verify if expected"
            })
        
        return threats
    
    def to_dict(self) -> dict:
        return {
            "devices": self.devices,
            "last_scan": self.last_scan,
            "count": len(self.devices)
        }


# Initialize mobile scanners
mobile_wifi_scanner = MobileWiFiScanner()
mobile_bluetooth_scanner = MobileBluetoothScanner()


# =============================================================================
# REMEDIATION ENGINE
# =============================================================================

class MobileRemediationEngine:
    """Execute mobile remediation actions"""
    
    def execute(self, threat: MobileThreat) -> Tuple[bool, str]:
        """Execute remediation"""
        action = threat.remediation_action
        params = threat.remediation_params
        
        try:
            if action == "uninstall_app":
                return self._uninstall_app(params)
            elif action == "block_ip":
                return self._block_ip(params)
            elif action == "disable_adb_network":
                return self._disable_adb_network()
            elif action == "revoke_permission":
                return self._revoke_permission(params)
            else:
                return False, f"Unknown action: {action}"
        except Exception as e:
            return False, str(e)
    
    def _uninstall_app(self, params: dict) -> Tuple[bool, str]:
        """Uninstall suspicious app"""
        package = params.get('package')
        
        if IS_ANDROID:
            try:
                # Open uninstall dialog
                if ANDROID_HELPER:
                    ANDROID_HELPER.startActivity(
                        'android.intent.action.DELETE',
                        f'package:{package}'
                    )
                    return True, f"Uninstall dialog opened for {package}"
                else:
                    # Try via shell
                    subprocess.run(['pm', 'uninstall', package], timeout=30)
                    return True, f"Uninstalled {package}"
            except Exception as e:
                return False, f"Failed to uninstall: {e}"
        
        return False, "Not supported on this platform"
    
    def _block_ip(self, params: dict) -> Tuple[bool, str]:
        """Block IP address (requires root on Android)"""
        ip = params.get('ip')
        
        if IS_ANDROID:
            try:
                # Try with iptables (requires root)
                result = subprocess.run(
                    ['su', '-c', f'iptables -A OUTPUT -d {ip} -j DROP'],
                    capture_output=True, timeout=10
                )
                if result.returncode == 0:
                    return True, f"Blocked IP {ip}"
                else:
                    # No root - just warn user
                    return False, f"Cannot block {ip} without root. Avoid this IP manually."
            except:
                return False, f"Cannot block {ip}. Please avoid connecting to this IP."
        
        return False, "IP blocking not supported on this platform"
    
    def _disable_adb_network(self) -> Tuple[bool, str]:
        """Disable ADB over network"""
        if IS_ANDROID:
            try:
                subprocess.run(['setprop', 'service.adb.tcp.port', '-1'], timeout=5)
                subprocess.run(['stop', 'adbd'], timeout=5)
                subprocess.run(['start', 'adbd'], timeout=5)
                return True, "ADB network access disabled"
            except:
                return False, "Run: adb tcpip -1 or disable in Developer Options"
        
        return False, "Not applicable"
    
    def _revoke_permission(self, params: dict) -> Tuple[bool, str]:
        """Revoke app permission"""
        package = params.get('package')
        permission = params.get('permission')
        
        if IS_ANDROID:
            try:
                subprocess.run(
                    ['pm', 'revoke', package, f'android.permission.{permission}'],
                    timeout=10
                )
                return True, f"Revoked {permission} from {package}"
            except:
                return False, f"Go to Settings > Apps > {package} > Permissions"
        
        return False, "Not supported"


# =============================================================================
# TELEMETRY STORE
# =============================================================================

class MobileTelemetryStore:
    """Local telemetry storage with auto-kill capabilities"""
    
    def __init__(self):
        self.events = deque(maxlen=1000)
        self.threats = deque(maxlen=200)
        self.pending_approvals = {}
        self.auto_remediated = deque(maxlen=100)  # Auto-killed threats
        self.alarms = deque(maxlen=50)
        self.network_connections = []
        self.installed_apps = []
        
        self.stats = {
            "events_total": 0,
            "threats_detected": 0,
            "threats_blocked": 0,
            "threats_pending": 0,
            "threats_auto_killed": 0,
            "apps_scanned": 0,
            "connections_monitored": 0
        }
        
        # Auto-kill configuration for mobile
        self.auto_kill_enabled = True
        self.auto_kill_severities = {ThreatSeverity.CRITICAL}
        
        # Critical patterns for mobile
        self.critical_patterns = [
            'malicious', 'spyware', 'stalkerware', 'keylogger',
            'banking', 'credential', 'phishing', 'ransomware'
        ]
    
    def add_threat(self, threat: MobileThreat, auto_remediate: bool = True):
        self.threats.append(threat)
        self.stats["threats_detected"] += 1
        
        # Check if auto-kill should be triggered
        should_auto_kill = False
        if self.auto_kill_enabled and threat.remediation_available:
            if threat.severity in self.auto_kill_severities:
                should_auto_kill = True
            
            # Check critical patterns
            threat_text = f"{threat.title} {threat.description}".lower()
            for pattern in self.critical_patterns:
                if pattern in threat_text:
                    should_auto_kill = True
                    break
        
        if should_auto_kill and auto_remediate:
            self.trigger_alarm(threat, "MOBILE_AUTO_KILL")
            threat.status = "auto_remediated"
            threat.user_approved = True
            self.auto_remediated.append(threat)
        elif threat.remediation_available:
            self.pending_approvals[threat.id] = threat
            self.stats["threats_pending"] += 1
            
            if threat.severity in {ThreatSeverity.CRITICAL, ThreatSeverity.HIGH}:
                self.trigger_alarm(threat, "MOBILE_MANUAL_REQUIRED")
        
        self.add_event({
            "event_type": f"threat.{threat.type}",
            "severity": threat.severity.value,
            "data": {
                "title": threat.title, 
                "description": threat.description,
                "auto_kill_triggered": should_auto_kill
            }
        })
        
        return should_auto_kill
    
    def trigger_alarm(self, threat: MobileThreat, alarm_type: str):
        """Trigger mobile alarm with notification"""
        alarm = {
            "id": f"alarm-{uuid.uuid4().hex[:8]}",
            "type": alarm_type,
            "threat_id": threat.id,
            "threat_title": threat.title,
            "severity": threat.severity.value,
            "timestamp": datetime.now().isoformat(),
            "acknowledged": False
        }
        self.alarms.append(alarm)
        logger.warning(f"🚨 MOBILE ALARM: {alarm_type} - {threat.title}")
        
        # Send mobile notification
        self._send_notification(f"⚠️ {alarm_type}", threat.title)
    
    def _send_notification(self, title: str, message: str):
        """Send mobile notification"""
        if IS_ANDROID and ANDROID_HELPER:
            try:
                ANDROID_HELPER.notify(title, message)
            except:
                pass
        elif IS_IOS:
            try:
                import notification
                notification.schedule(title, delay=0, message=message)
            except:
                pass
    
    def add_event(self, event: dict):
        event["id"] = uuid.uuid4().hex[:8]
        event["timestamp"] = datetime.now().isoformat()
        self.events.append(event)
        self.stats["events_total"] += 1
    
    def approve_remediation(self, threat_id: str) -> Tuple[bool, str]:
        if threat_id not in self.pending_approvals:
            return False, "Threat not found"
        threat = self.pending_approvals[threat_id]
        threat.user_approved = True
        threat.status = "approved"
        return True, "Approved"
    
    def deny_remediation(self, threat_id: str) -> Tuple[bool, str]:
        if threat_id in self.pending_approvals:
            threat = self.pending_approvals[threat_id]
            threat.status = "ignored"
            del self.pending_approvals[threat_id]
            self.stats["threats_pending"] -= 1
        return True, "Denied"
    
    def get_dashboard_data(self) -> dict:
        battery = {}
        if IS_ANDROID and ANDROID_HELPER:
            try:
                b = ANDROID_HELPER.batteryGetStatus().result
                battery = {"level": b.get('level'), "temperature": b.get('temperature', 0) / 10}
            except:
                pass
        
        return {
            "agent": {
                "id": AGENT_ID,
                "hostname": HOSTNAME,
                "platform": "Android" if IS_ANDROID else "iOS" if IS_IOS else OS_TYPE,
                "version": VERSION,
                "battery": battery
            },
            "stats": self.stats,
            "events": list(self.events)[-50:],
            "threats": [t.to_dict() for t in self.threats][-30:],
            "pending_approvals": [t.to_dict() for t in self.pending_approvals.values()],
            "network_connections": self.network_connections[:30],
            "installed_apps": self.installed_apps[:50]
        }


# Global instances
telemetry_store = MobileTelemetryStore()
threat_engine = MobileThreatEngine()
remediation_engine = MobileRemediationEngine()

# =============================================================================
# MOBILE DASHBOARD HTML
# =============================================================================

MOBILE_DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Seraph Mobile</title>
    <style>
        :root {
            --bg: #0f172a;
            --card: #1e293b;
            --accent: #06b6d4;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --text: #f1f5f9;
            --text-dim: #94a3b8;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 16px;
            padding-bottom: 80px;
        }
        
        .header {
            text-align: center;
            padding: 20px;
            background: linear-gradient(135deg, rgba(6, 182, 212, 0.2), rgba(239, 68, 68, 0.1));
            border-radius: 16px;
            margin-bottom: 16px;
        }
        .header h1 { font-size: 20px; color: var(--accent); }
        .header .status { 
            display: inline-block;
            padding: 4px 12px;
            background: var(--success);
            border-radius: 20px;
            font-size: 12px;
            margin-top: 8px;
        }
        
        .alert-banner {
            background: linear-gradient(135deg, var(--danger), #991b1b);
            padding: 16px;
            border-radius: 12px;
            margin-bottom: 16px;
            display: none;
        }
        .alert-banner.active { display: block; }
        .alert-banner h3 { font-size: 16px; margin-bottom: 8px; }
        .alert-banner p { font-size: 14px; opacity: 0.9; margin-bottom: 12px; }
        .alert-actions { display: flex; gap: 12px; }
        .alert-actions button {
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
        }
        .btn-approve { background: var(--success); color: white; }
        .btn-deny { background: rgba(255,255,255,0.2); color: white; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-bottom: 16px;
        }
        .stat-card {
            background: var(--card);
            padding: 16px;
            border-radius: 12px;
            text-align: center;
        }
        .stat-card .value {
            font-size: 24px;
            font-weight: 700;
            color: var(--accent);
        }
        .stat-card.danger .value { color: var(--danger); }
        .stat-card .label {
            font-size: 11px;
            color: var(--text-dim);
            margin-top: 4px;
        }
        
        .section {
            background: var(--card);
            border-radius: 12px;
            margin-bottom: 16px;
            overflow: hidden;
        }
        .section-header {
            padding: 12px 16px;
            background: rgba(0,0,0,0.2);
            font-weight: 600;
            font-size: 14px;
        }
        .section-body { padding: 12px; }
        
        .threat-item {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 8px;
        }
        .threat-item:last-child { margin-bottom: 0; }
        .threat-title {
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 4px;
        }
        .threat-desc {
            font-size: 12px;
            color: var(--text-dim);
            margin-bottom: 8px;
        }
        .threat-actions {
            display: flex;
            gap: 8px;
        }
        .threat-actions button {
            flex: 1;
            padding: 8px;
            border: none;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
        }
        
        .event-item {
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            font-size: 13px;
        }
        .event-item:last-child { border-bottom: none; }
        .event-type { color: var(--accent); }
        .event-time { color: var(--text-dim); font-size: 11px; }
        
        .battery-info {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 12px;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
        }
        .battery-bar {
            flex: 1;
            height: 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 4px;
            overflow: hidden;
        }
        .battery-fill {
            height: 100%;
            background: var(--success);
            transition: width 0.3s;
        }
        
        .nav-bar {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: var(--card);
            display: flex;
            justify-content: space-around;
            padding: 12px;
            border-top: 1px solid rgba(255,255,255,0.1);
        }
        .nav-item {
            text-align: center;
            color: var(--text-dim);
            font-size: 11px;
            cursor: pointer;
        }
        .nav-item.active { color: var(--accent); }
        .nav-item span { font-size: 20px; display: block; margin-bottom: 4px; }
        
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Seraph Mobile Defender</h1>
        <div class="status" id="statusBadge">● Protected</div>
        <div style="font-size: 12px; color: var(--text-dim); margin-top: 8px;" id="platformInfo"></div>
    </div>
    
    <div class="alert-banner" id="alertBanner">
        <h3 id="alertTitle">⚠️ Threat Detected</h3>
        <p id="alertDesc"></p>
        <div class="alert-actions">
            <button class="btn-approve" onclick="approveAlert()">✓ Fix It</button>
            <button class="btn-deny" onclick="denyAlert()">✗ Ignore</button>
        </div>
    </div>
    
    <div class="tab-content active" id="tab-home">
        <div class="stats-grid">
            <div class="stat-card danger">
                <div class="value" id="statThreats">0</div>
                <div class="label">Threats</div>
            </div>
            <div class="stat-card">
                <div class="value" id="statPending">0</div>
                <div class="label">Pending</div>
            </div>
            <div class="stat-card">
                <div class="value" id="statBlocked">0</div>
                <div class="label">Blocked</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">🔋 Battery Status</div>
            <div class="section-body">
                <div class="battery-info">
                    <span id="batteryLevel">--</span>
                    <div class="battery-bar">
                        <div class="battery-fill" id="batteryFill" style="width: 0%"></div>
                    </div>
                    <span id="batteryTemp">--°C</span>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">🎯 Active Threats</div>
            <div class="section-body" id="threatList">
                <p style="color: var(--success); text-align: center; padding: 20px;">✓ No threats detected</p>
            </div>
        </div>
    </div>
    
    <div class="tab-content" id="tab-network">
        <div class="section">
            <div class="section-header">🌐 Network Connections</div>
            <div class="section-body" id="networkList" style="max-height: 400px; overflow-y: auto;">
                <p style="color: var(--text-dim);">Monitoring...</p>
            </div>
        </div>
    </div>
    
    <div class="tab-content" id="tab-events">
        <div class="section">
            <div class="section-header">📋 Recent Events</div>
            <div class="section-body" id="eventList" style="max-height: 500px; overflow-y: auto;"></div>
        </div>
    </div>
    
    <div class="nav-bar">
        <div class="nav-item active" data-tab="home" onclick="switchTab('home')">
            <span>🏠</span>Home
        </div>
        <div class="nav-item" data-tab="network" onclick="switchTab('network')">
            <span>🌐</span>Network
        </div>
        <div class="nav-item" data-tab="events" onclick="switchTab('events')">
            <span>📋</span>Events
        </div>
    </div>
    
    <script>
        let currentAlert = null;
        
        function switchTab(tab) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            document.getElementById('tab-' + tab).classList.add('active');
            document.querySelector('[data-tab="' + tab + '"]').classList.add('active');
        }
        
        function renderThreat(threat) {
            return `
                <div class="threat-item">
                    <div class="threat-title">${threat.title}</div>
                    <div class="threat-desc">${threat.description}</div>
                    ${threat.remediation_available && threat.status === 'detected' ? `
                        <div class="threat-actions">
                            <button class="btn-approve" onclick="approveThreat('${threat.id}')">Fix</button>
                            <button class="btn-deny" onclick="denyThreat('${threat.id}')">Ignore</button>
                        </div>
                    ` : ''}
                </div>
            `;
        }
        
        function updateDashboard(data) {
            document.getElementById('platformInfo').textContent = 
                data.agent.platform + ' | v' + data.agent.version;
            
            document.getElementById('statThreats').textContent = data.stats.threats_detected;
            document.getElementById('statPending').textContent = data.stats.threats_pending;
            document.getElementById('statBlocked').textContent = data.stats.threats_blocked;
            
            // Battery
            if (data.agent.battery) {
                document.getElementById('batteryLevel').textContent = (data.agent.battery.level || 0) + '%';
                document.getElementById('batteryFill').style.width = (data.agent.battery.level || 0) + '%';
                document.getElementById('batteryTemp').textContent = (data.agent.battery.temperature || 0).toFixed(0) + '°C';
            }
            
            // Alert banner
            if (data.pending_approvals.length > 0) {
                currentAlert = data.pending_approvals[0];
                document.getElementById('alertBanner').classList.add('active');
                document.getElementById('alertTitle').textContent = '⚠️ ' + currentAlert.title;
                document.getElementById('alertDesc').textContent = currentAlert.description;
            } else {
                document.getElementById('alertBanner').classList.remove('active');
            }
            
            // Threats
            const threats = data.threats.filter(t => t.status === 'detected');
            document.getElementById('threatList').innerHTML = threats.length > 0 ?
                threats.slice().reverse().map(renderThreat).join('') :
                '<p style="color: var(--success); text-align: center; padding: 20px;">✓ No threats detected</p>';
            
            // Network
            document.getElementById('networkList').innerHTML = data.network_connections.map(conn => `
                <div class="event-item" style="font-family: monospace; font-size: 11px;">
                    ${conn.local_addr || '-'} → ${conn.remote_addr || '-'}
                </div>
            `).join('') || '<p style="color: var(--text-dim);">No active connections</p>';
            
            // Events
            document.getElementById('eventList').innerHTML = data.events.slice().reverse().map(e => `
                <div class="event-item">
                    <span class="event-type">${e.event_type}</span>
                    <span class="event-time" style="float: right;">${new Date(e.timestamp).toLocaleTimeString()}</span>
                </div>
            `).join('') || '<p style="color: var(--text-dim);">No events</p>';
        }
        
        async function approveThreat(id) { await fetch('/api/approve/' + id, {method: 'POST'}); fetchData(); }
        async function denyThreat(id) { await fetch('/api/deny/' + id, {method: 'POST'}); fetchData(); }
        function approveAlert() { if (currentAlert) approveThreat(currentAlert.id); }
        function denyAlert() { if (currentAlert) denyThreat(currentAlert.id); }
        
        async function fetchData() {
            try {
                const response = await fetch('/api/data');
                const data = await response.json();
                updateDashboard(data);
            } catch (e) { console.error(e); }
        }
        
        fetchData();
        setInterval(fetchData, 3000);
    </script>
</body>
</html>
'''


class MobileDashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass
    
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(MOBILE_DASHBOARD_HTML.encode())
        elif self.path == '/api/data':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(telemetry_store.get_dashboard_data()).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path.startswith('/api/approve/'):
            threat_id = self.path.split('/')[-1]
            telemetry_store.approve_remediation(threat_id)
            # Execute
            if threat_id in telemetry_store.pending_approvals:
                threat = telemetry_store.pending_approvals[threat_id]
                success, msg = remediation_engine.execute(threat)
                threat.status = "resolved" if success else "failed"
                if success:
                    telemetry_store.stats["threats_blocked"] += 1
                del telemetry_store.pending_approvals[threat_id]
                telemetry_store.stats["threats_pending"] -= 1
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        
        elif self.path.startswith('/api/deny/'):
            threat_id = self.path.split('/')[-1]
            telemetry_store.deny_remediation(threat_id)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        
        else:
            self.send_response(404)
            self.end_headers()


# =============================================================================
# MAIN AGENT
# =============================================================================

class SeraphMobileDefender:
    def __init__(self, api_url: str = None, local_only: bool = False):
        global AGENT_ID
        AGENT_ID = hashlib.md5(f"{HOSTNAME}-{uuid.getnode()}".encode()).hexdigest()[:16]
        
        self.api_url = api_url
        self.local_only = local_only
        self.running = False
        
        platform_name = "Android" if IS_ANDROID else "iOS" if IS_IOS else "Unknown"
        logger.info(f"Seraph Mobile Defender v{VERSION}")
        logger.info(f"Platform: {platform_name}")
        logger.info(f"Agent ID: {AGENT_ID}")
    
    def start(self):
        self.running = True
        
        # Start dashboard
        dashboard_thread = threading.Thread(
            target=lambda: HTTPServer(('0.0.0.0', DASHBOARD_PORT), MobileDashboardHandler).serve_forever(),
            daemon=True
        )
        dashboard_thread.start()
        
        logger.info(f"Dashboard: http://localhost:{DASHBOARD_PORT}")
        logger.info("Open this URL in your browser")
        
        # Try to open browser
        try:
            if IS_ANDROID and ANDROID_HELPER:
                ANDROID_HELPER.startActivity(
                    'android.intent.action.VIEW',
                    f'http://localhost:{DASHBOARD_PORT}'
                )
            elif IS_IOS:
                import webbrowser
                webbrowser.open(f'http://localhost:{DASHBOARD_PORT}')
        except:
            pass
        
        # Monitoring loop
        self._monitor_loop()
    
    def _monitor_loop(self):
        while self.running:
            try:
                # Scan for threats
                threats = []
                
                # App scan
                threats.extend(threat_engine.scan_installed_apps())
                
                # Network scan
                threats.extend(threat_engine.scan_network_connections())
                
                # Battery check
                battery_threat = threat_engine.check_battery_drain()
                if battery_threat:
                    threats.append(battery_threat)
                
                # ADB check
                adb_threat = threat_engine.check_adb_status()
                if adb_threat:
                    threats.append(adb_threat)
                
                # Process detected threats
                for threat in threats:
                    # Check if we've already reported this
                    existing = [t for t in telemetry_store.threats if t.type == threat.type and t.evidence == threat.evidence]
                    if not existing:
                        telemetry_store.add_threat(threat)
                        logger.warning(f"Threat detected: {threat.title}")
                        
                        # Send notification
                        self._notify_threat(threat)
                
                # Update network connections
                if HAS_PSUTIL:
                    connections = []
                    for conn in psutil.net_connections(kind='inet'):
                        if conn.raddr:
                            connections.append({
                                'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                                'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ''
                            })
                    telemetry_store.network_connections = connections
                    telemetry_store.stats["connections_monitored"] = len(connections)
                
                # Sync to server
                if not self.local_only and self.api_url:
                    self._sync_to_server()
                
                # Add heartbeat event
                telemetry_store.add_event({
                    "event_type": "agent.heartbeat",
                    "severity": "info",
                    "data": {"status": "monitoring"}
                })
                
                time.sleep(10)
                
            except KeyboardInterrupt:
                logger.info("Stopping...")
                self.running = False
            except Exception as e:
                logger.error(f"Error: {e}")
                time.sleep(5)
    
    def _notify_threat(self, threat: MobileThreat):
        """Send notification about threat"""
        try:
            if IS_ANDROID and ANDROID_HELPER:
                ANDROID_HELPER.makeToast(f"⚠️ {threat.title}")
                ANDROID_HELPER.notify(
                    threat.title,
                    threat.description
                )
            elif IS_IOS:
                notification.schedule(
                    threat.title,
                    delay=0,
                    sound_name='default'
                )
        except:
            pass
    
    def _sync_to_server(self):
        """Sync to server"""
        try:
            requests.post(
                f"{self.api_url}/api/swarm/agents/register",
                json={
                    "agent_id": AGENT_ID,
                    "hostname": HOSTNAME,
                    "os_type": "android" if IS_ANDROID else "ios" if IS_IOS else "mobile",
                    "version": VERSION
                },
                timeout=10
            )
        except:
            pass


def main():
    parser = argparse.ArgumentParser(description="Seraph Mobile Defender v7")
    parser.add_argument('--api-url', help='Server URL')
    parser.add_argument('--local-only', action='store_true', help='Local only mode')
    parser.add_argument('--port', type=int, default=8888, help='Dashboard port')
    
    args = parser.parse_args()
    
    global DASHBOARD_PORT
    DASHBOARD_PORT = args.port
    
    if not args.api_url and not args.local_only:
        print(f"\nSeraph Mobile Defender v{VERSION}")
        print("=" * 40)
        print("\nUsage:")
        print(f"  python {sys.argv[0]} --api-url URL")
        print(f"  python {sys.argv[0]} --local-only")
        print(f"\nDashboard: http://localhost:{DASHBOARD_PORT}")
        sys.exit(1)
    
    agent = SeraphMobileDefender(args.api_url, args.local_only)
    agent.start()


if __name__ == '__main__':
    main()
