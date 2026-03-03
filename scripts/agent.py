#!/usr/bin/env python3
"""
Anti-AI Defense System - Local Security Agent with Dashboard
=============================================================
Complete local security monitoring with web-based dashboard.

Features:
- Local web dashboard at http://localhost:5000
- Network scanning (nmap)
- Packet capture (scapy)
- Malware scanning (YARA)
- Process monitoring
- Suricata IDS integration
- Real-time cloud sync

Usage:
    sudo python agent.py                    # Start with all features
    sudo python agent.py --no-dashboard     # Headless mode
    sudo python agent.py --port 8080        # Custom dashboard port

Author: Anti-AI Defense System
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
import argparse
from datetime import datetime
from pathlib import Path
from collections import deque

# =============================================================================
# CONFIGURATION
# =============================================================================

# Default configuration - will be overridden by config.json if exists
DEFAULT_CONFIG = {
    "api_url": "https://agentic-armor.preview.emergentagent.com/api",
    "agent_key": "local-agent",
    "agent_name": platform.node() or "local-agent",
    "local_dashboard_port": 5000,
    "network_interface": None,
    "scan_subnet": None,
    "suricata_log_path": "/var/log/suricata/eve.json",
    "yara_rules_dir": str(Path.home() / ".anti-ai-defense" / "yara_rules"),
    "scan_directories": [
        str(Path.home() / "Downloads"),
        "/tmp" if platform.system() != "Windows" else str(Path.home() / "AppData" / "Local" / "Temp"),
    ],
    "heartbeat_interval": 30,
    "network_scan_interval": 300,
    "yara_scan_interval": 600,
    "features": {
        "packet_capture": True,
        "network_scan": True,
        "yara_scan": True,
        "process_monitor": True,
        "suricata_monitor": True,
        "local_dashboard": True,
    }
}

# =============================================================================
# IMPORTS - Check and install missing packages
# =============================================================================

def check_and_import(module_name, package_name=None):
    """Try to import a module, return None if not available"""
    try:
        return __import__(module_name)
    except ImportError:
        return None

# Core dependencies
requests = check_and_import('requests')
psutil = check_and_import('psutil')

if not requests or not psutil:
    print("ERROR: Core dependencies missing. Run install.py first.")
    print("  pip install requests psutil")
    sys.exit(1)

# Optional dependencies
flask = check_and_import('flask')
flask_cors = check_and_import('flask_cors')
flask_socketio = check_and_import('flask_socketio')
scapy_module = check_and_import('scapy.all')
yara = check_and_import('yara')
nmap = check_and_import('nmap')
netifaces = check_and_import('netifaces')

# Import Flask components if available
if flask:
    from flask import Flask, render_template_string, jsonify, request
    from flask_cors import CORS
    FLASK_AVAILABLE = True
else:
    FLASK_AVAILABLE = False
    print("WARNING: Flask not available. Local dashboard disabled.")

if flask_socketio:
    from flask_socketio import SocketIO, emit
    SOCKETIO_AVAILABLE = True
else:
    SOCKETIO_AVAILABLE = False

if scapy_module:
    from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP
    SCAPY_AVAILABLE = True
else:
    SCAPY_AVAILABLE = False
    print("WARNING: Scapy not available. Packet capture disabled.")

YARA_AVAILABLE = yara is not None
if not YARA_AVAILABLE:
    print("WARNING: YARA not available. Malware scanning disabled.")

NMAP_AVAILABLE = nmap is not None
if not NMAP_AVAILABLE:
    print("WARNING: Nmap not available. Network scanning disabled.")

# =============================================================================
# GLOBAL STATE
# =============================================================================

class AgentState:
    def __init__(self):
        self.running = True
        self.events = deque(maxlen=1000)
        self.alerts = deque(maxlen=100)
        self.threats = deque(maxlen=100)
        self.discovered_hosts = {}
        self.packet_stats = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "suspicious": 0
        }
        self.scan_results = {}
        self.system_info = {}
        self.last_heartbeat = None
        self.cloud_connected = False

state = AgentState()

# =============================================================================
# API CLIENT
# =============================================================================

class CloudAPIClient:
    def __init__(self, config):
        self.api_url = config.get("api_url", DEFAULT_CONFIG["api_url"])
        self.agent_id = hashlib.md5(platform.node().encode()).hexdigest()[:16]
        self.agent_name = config.get("agent_name", DEFAULT_CONFIG["agent_name"])
        self.session = requests.Session()
        self.session.headers.update({
            "X-Agent-Key": config.get("agent_key", "local-agent"),
            "X-Agent-ID": self.agent_id,
            "Content-Type": "application/json"
        })
    
    def send_event(self, event_type, data):
        """Send event to cloud"""
        payload = {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        }
        
        # Store locally
        state.events.append({
            "type": event_type,
            "data": data,
            "timestamp": datetime.now().isoformat()
        })
        
        # Send to cloud
        try:
            response = self.session.post(
                f"{self.api_url}/agent/event",
                json=payload,
                timeout=10
            )
            state.cloud_connected = response.status_code == 200
            return response.status_code == 200
        except Exception as e:
            state.cloud_connected = False
            return False

# =============================================================================
# MONITORING MODULES
# =============================================================================

class SystemMonitor:
    """Monitor system resources and processes"""
    
    @staticmethod
    def get_system_info():
        info = {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "cpu_count": psutil.cpu_count(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_total": psutil.virtual_memory().total,
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent if platform.system() != 'Windows' else psutil.disk_usage('C:\\').percent,
            "network_interfaces": [],
            "uptime_seconds": time.time() - psutil.boot_time(),
        }
        
        # Get network interfaces
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    info["network_interfaces"].append({
                        "name": name,
                        "ip": addr.address,
                        "netmask": addr.netmask
                    })
        
        state.system_info = info
        return info
    
    @staticmethod
    def get_suspicious_processes():
        """Find suspicious processes"""
        suspicious = []
        patterns = [
            'nc -l', 'ncat -l', '/dev/tcp/', 'python -c "import socket',
            'base64 -d', 'curl | bash', 'wget | bash', 'cryptominer', 'xmrig'
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                for pattern in patterns:
                    if pattern.lower() in cmdline:
                        suspicious.append({
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "cmdline": cmdline[:200],
                            "pattern": pattern,
                            "username": proc.info['username']
                        })
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return suspicious


class NetworkScanner:
    """Network discovery using nmap"""
    
    def __init__(self):
        self.previous_hosts = set()
    
    def get_local_subnet(self):
        """Auto-detect local subnet"""
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    parts = addr.address.split('.')
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return None
    
    def scan(self):
        """Perform network scan"""
        if not NMAP_AVAILABLE:
            return []
        
        subnet = self.get_local_subnet()
        if not subnet:
            return []
        
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=subnet, arguments='-sn -T4')
            
            hosts = []
            for host in nm.all_hosts():
                host_info = {
                    "ip": host,
                    "hostname": nm[host].hostname() or "unknown",
                    "state": nm[host].state(),
                    "mac": nm[host]['addresses'].get('mac'),
                    "vendor": list(nm[host].get('vendor', {}).values())[0] if nm[host].get('vendor') else None,
                    "last_seen": datetime.now().isoformat()
                }
                hosts.append(host_info)
                state.discovered_hosts[host] = host_info
            
            # Detect new hosts
            current = set(h["ip"] for h in hosts)
            new_hosts = current - self.previous_hosts
            self.previous_hosts = current
            
            return hosts, list(new_hosts)
        except Exception as e:
            print(f"Network scan error: {e}")
            return [], []


class PacketCapture:
    """Capture and analyze network packets"""
    
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 6667, 31337, 12345, 12346, 1337, 9001}
    
    def __init__(self):
        self.running = False
        self.port_scan_tracker = {}
    
    def analyze_packet(self, packet):
        """Analyze a single packet"""
        state.packet_stats["total"] += 1
        
        if not packet.haslayer(IP):
            return None
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if packet.haslayer(TCP):
            state.packet_stats["tcp"] += 1
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Check suspicious ports
            if dst_port in self.SUSPICIOUS_PORTS or src_port in self.SUSPICIOUS_PORTS:
                state.packet_stats["suspicious"] += 1
                return {
                    "type": "suspicious_port",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "reason": f"Suspicious port {dst_port}"
                }
            
            # Port scan detection
            if src_ip not in self.port_scan_tracker:
                self.port_scan_tracker[src_ip] = set()
            self.port_scan_tracker[src_ip].add(dst_port)
            
            if len(self.port_scan_tracker[src_ip]) > 20:
                state.packet_stats["suspicious"] += 1
                ports = list(self.port_scan_tracker[src_ip])[:10]
                self.port_scan_tracker[src_ip] = set()  # Reset
                return {
                    "type": "port_scan",
                    "src_ip": src_ip,
                    "ports_scanned": len(ports),
                    "sample_ports": ports
                }
        
        elif packet.haslayer(UDP):
            state.packet_stats["udp"] += 1
        
        return None
    
    def start(self, interface=None):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            return
        
        self.running = True
        
        def capture_loop():
            try:
                sniff(
                    iface=interface,
                    prn=lambda p: self._handle_packet(p),
                    store=False,
                    stop_filter=lambda x: not self.running
                )
            except Exception as e:
                print(f"Packet capture error: {e}")
        
        thread = threading.Thread(target=capture_loop, daemon=True)
        thread.start()
        return thread
    
    def _handle_packet(self, packet):
        result = self.analyze_packet(packet)
        if result:
            state.alerts.append({
                **result,
                "timestamp": datetime.now().isoformat()
            })
    
    def stop(self):
        self.running = False


class YaraScanner:
    """Scan files for malware using YARA rules"""
    
    def __init__(self, rules_dir):
        self.rules_dir = Path(rules_dir)
        self.rules = None
        self.scanned_files = {}
    
    def load_rules(self):
        """Load YARA rules"""
        if not YARA_AVAILABLE:
            return False
        
        if not self.rules_dir.exists():
            return False
        
        try:
            rule_files = {}
            for f in self.rules_dir.iterdir():
                if f.suffix in ['.yar', '.yara']:
                    rule_files[f.name] = str(f)
            
            if rule_files:
                self.rules = yara.compile(filepaths=rule_files)
                return True
        except Exception as e:
            print(f"Error loading YARA rules: {e}")
        
        return False
    
    def scan_file(self, filepath):
        """Scan a single file"""
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(filepath)
            return [
                {
                    "rule": match.rule,
                    "meta": match.meta,
                }
                for match in matches
            ]
        except Exception:
            return []
    
    def scan_directory(self, directory):
        """Scan a directory"""
        if not self.rules:
            return []
        
        results = []
        try:
            for root, dirs, files in os.walk(directory):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for filename in files:
                    filepath = os.path.join(root, filename)
                    
                    try:
                        if os.path.getsize(filepath) > 50 * 1024 * 1024:
                            continue
                        
                        mtime = os.path.getmtime(filepath)
                        if filepath in self.scanned_files and self.scanned_files[filepath] == mtime:
                            continue
                        self.scanned_files[filepath] = mtime
                    except:
                        continue
                    
                    matches = self.scan_file(filepath)
                    if matches:
                        result = {
                            "filepath": filepath,
                            "matches": matches,
                            "timestamp": datetime.now().isoformat()
                        }
                        results.append(result)
                        state.threats.append(result)
        except Exception as e:
            print(f"Error scanning {directory}: {e}")
        
        return results


class SuricataMonitor:
    """Monitor Suricata IDS logs"""
    
    def __init__(self, log_path):
        self.log_path = log_path
        self.last_position = 0
        self.running = False
    
    def parse_logs(self):
        """Parse new Suricata alerts"""
        if not os.path.exists(self.log_path):
            return []
        
        alerts = []
        try:
            with open(self.log_path, 'r') as f:
                f.seek(self.last_position)
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        if event.get('event_type') == 'alert':
                            alert = {
                                "timestamp": event.get('timestamp'),
                                "src_ip": event.get('src_ip'),
                                "dest_ip": event.get('dest_ip'),
                                "signature": event.get('alert', {}).get('signature'),
                                "severity": event.get('alert', {}).get('severity'),
                                "category": event.get('alert', {}).get('category'),
                            }
                            alerts.append(alert)
                            state.alerts.append(alert)
                    except json.JSONDecodeError:
                        continue
                self.last_position = f.tell()
        except Exception as e:
            print(f"Error reading Suricata logs: {e}")
        
        return alerts
    
    def start(self):
        """Start monitoring"""
        self.running = True
        
        def monitor_loop():
            while self.running:
                self.parse_logs()
                time.sleep(5)
        
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        return thread
    
    def stop(self):
        self.running = False

# =============================================================================
# LOCAL WEB DASHBOARD
# =============================================================================

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anti-AI Defense System - Local Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'IBM Plex Sans', sans-serif; background: #020617; color: #F8FAFC; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        .glow-blue { box-shadow: 0 0 20px rgba(59, 130, 246, 0.4); }
        .glow-green { box-shadow: 0 0 20px rgba(16, 185, 129, 0.4); }
        .glow-red { box-shadow: 0 0 20px rgba(239, 68, 68, 0.4); }
        .card { background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); }
    </style>
</head>
<body class="min-h-screen p-6">
    <div class="max-w-7xl mx-auto">
        <!-- Header -->
        <div class="flex items-center justify-between mb-8">
            <div class="flex items-center gap-4">
                <div class="w-12 h-12 rounded bg-blue-500/20 flex items-center justify-center">
                    <svg class="w-7 h-7 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                    </svg>
                </div>
                <div>
                    <h1 class="text-2xl font-mono font-bold">DEFENDER</h1>
                    <p class="text-sm text-slate-400">Local Security Agent</p>
                </div>
            </div>
            <div class="flex items-center gap-4">
                <div id="cloud-status" class="flex items-center gap-2 px-3 py-2 rounded bg-slate-800">
                    <div class="w-2 h-2 rounded-full bg-slate-500"></div>
                    <span class="text-xs text-slate-400">Cloud: Checking...</span>
                </div>
                <div class="flex items-center gap-2 px-3 py-2 rounded bg-green-500/20 border border-green-500/30">
                    <div class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                    <span class="text-xs text-green-400 font-mono">ACTIVE</span>
                </div>
            </div>
        </div>

        <!-- Stats Grid -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div class="card rounded-lg p-4">
                <div class="flex items-center gap-2 mb-2">
                    <svg class="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
                    </svg>
                    <span class="text-slate-400 text-sm">Total Packets</span>
                </div>
                <p id="stat-packets" class="text-2xl font-mono font-bold text-cyan-400">0</p>
            </div>
            <div class="card rounded-lg p-4">
                <div class="flex items-center gap-2 mb-2">
                    <svg class="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                    </svg>
                    <span class="text-slate-400 text-sm">Suspicious</span>
                </div>
                <p id="stat-suspicious" class="text-2xl font-mono font-bold text-red-400">0</p>
            </div>
            <div class="card rounded-lg p-4">
                <div class="flex items-center gap-2 mb-2">
                    <svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path>
                    </svg>
                    <span class="text-slate-400 text-sm">Hosts Found</span>
                </div>
                <p id="stat-hosts" class="text-2xl font-mono font-bold text-blue-400">0</p>
            </div>
            <div class="card rounded-lg p-4">
                <div class="flex items-center gap-2 mb-2">
                    <svg class="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"></path>
                    </svg>
                    <span class="text-slate-400 text-sm">Alerts</span>
                </div>
                <p id="stat-alerts" class="text-2xl font-mono font-bold text-amber-400">0</p>
            </div>
        </div>

        <!-- Main Content -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <!-- System Info -->
            <div class="card rounded-lg p-4">
                <h3 class="font-mono font-semibold mb-4 flex items-center gap-2">
                    <svg class="w-5 h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                    </svg>
                    System Info
                </h3>
                <div id="system-info" class="space-y-3 text-sm">
                    <p class="text-slate-400">Loading...</p>
                </div>
            </div>

            <!-- Network Traffic Chart -->
            <div class="card rounded-lg p-4 lg:col-span-2">
                <h3 class="font-mono font-semibold mb-4 flex items-center gap-2">
                    <svg class="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"></path>
                    </svg>
                    Network Traffic
                </h3>
                <canvas id="traffic-chart" height="150"></canvas>
            </div>

            <!-- Discovered Hosts -->
            <div class="card rounded-lg p-4">
                <h3 class="font-mono font-semibold mb-4 flex items-center gap-2">
                    <svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path>
                    </svg>
                    Discovered Hosts
                </h3>
                <div id="hosts-list" class="space-y-2 max-h-64 overflow-y-auto">
                    <p class="text-slate-500 text-sm">No hosts discovered yet</p>
                </div>
            </div>

            <!-- Recent Alerts -->
            <div class="card rounded-lg p-4 lg:col-span-2">
                <h3 class="font-mono font-semibold mb-4 flex items-center gap-2">
                    <svg class="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                    </svg>
                    Recent Alerts
                </h3>
                <div id="alerts-list" class="space-y-2 max-h-64 overflow-y-auto">
                    <p class="text-slate-500 text-sm">No alerts</p>
                </div>
            </div>

            <!-- Malware Threats -->
            <div class="card rounded-lg p-4 lg:col-span-3">
                <h3 class="font-mono font-semibold mb-4 flex items-center gap-2">
                    <svg class="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                    </svg>
                    Malware Detections (YARA)
                </h3>
                <div id="threats-list" class="space-y-2">
                    <p class="text-slate-500 text-sm">No malware detected</p>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class="mt-8 text-center text-slate-500 text-sm">
            <p>Anti-AI Defense System - Local Agent v1.0</p>
            <p class="text-xs mt-1">Cloud Dashboard: <a href="{{ cloud_url }}" target="_blank" class="text-blue-400 hover:underline">{{ cloud_url }}</a></p>
        </div>
    </div>

    <script>
        // Traffic chart
        const ctx = document.getElementById('traffic-chart').getContext('2d');
        const trafficData = {
            labels: [],
            datasets: [
                {
                    label: 'TCP',
                    data: [],
                    borderColor: '#3B82F6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true
                },
                {
                    label: 'UDP',
                    data: [],
                    borderColor: '#10B981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    fill: true
                },
                {
                    label: 'Suspicious',
                    data: [],
                    borderColor: '#EF4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    fill: true
                }
            ]
        };
        
        const chart = new Chart(ctx, {
            type: 'line',
            data: trafficData,
            options: {
                responsive: true,
                scales: {
                    x: { display: true, grid: { color: '#1E293B' } },
                    y: { display: true, grid: { color: '#1E293B' }, beginAtZero: true }
                },
                plugins: { legend: { labels: { color: '#94A3B8' } } }
            }
        });

        // Update data
        let prevTcp = 0, prevUdp = 0, prevSuspicious = 0;
        
        async function updateDashboard() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                
                // Update stats
                document.getElementById('stat-packets').textContent = data.packet_stats.total.toLocaleString();
                document.getElementById('stat-suspicious').textContent = data.packet_stats.suspicious;
                document.getElementById('stat-hosts').textContent = Object.keys(data.discovered_hosts).length;
                document.getElementById('stat-alerts').textContent = data.alerts.length;
                
                // Update cloud status
                const cloudStatus = document.getElementById('cloud-status');
                if (data.cloud_connected) {
                    cloudStatus.innerHTML = '<div class="w-2 h-2 rounded-full bg-green-500"></div><span class="text-xs text-green-400">Cloud: Connected</span>';
                } else {
                    cloudStatus.innerHTML = '<div class="w-2 h-2 rounded-full bg-red-500"></div><span class="text-xs text-red-400">Cloud: Offline</span>';
                }
                
                // Update system info
                const sysInfo = data.system_info;
                document.getElementById('system-info').innerHTML = `
                    <div class="flex justify-between"><span class="text-slate-500">Hostname</span><span>${sysInfo.hostname || 'N/A'}</span></div>
                    <div class="flex justify-between"><span class="text-slate-500">OS</span><span>${sysInfo.os || 'N/A'}</span></div>
                    <div class="flex justify-between"><span class="text-slate-500">CPU</span><span class="text-cyan-400">${sysInfo.cpu_percent || 0}%</span></div>
                    <div class="flex justify-between"><span class="text-slate-500">Memory</span><span class="text-cyan-400">${sysInfo.memory_percent || 0}%</span></div>
                    <div class="flex justify-between"><span class="text-slate-500">Disk</span><span class="text-cyan-400">${sysInfo.disk_percent || 0}%</span></div>
                    <div class="mt-2 pt-2 border-t border-slate-700">
                        <span class="text-slate-500 text-xs">Network Interfaces:</span>
                        ${(sysInfo.network_interfaces || []).map(i => `<div class="flex justify-between text-xs"><span class="text-slate-400">${i.name}</span><span class="font-mono">${i.ip}</span></div>`).join('')}
                    </div>
                `;
                
                // Update chart
                const now = new Date().toLocaleTimeString();
                trafficData.labels.push(now);
                trafficData.datasets[0].data.push(data.packet_stats.tcp - prevTcp);
                trafficData.datasets[1].data.push(data.packet_stats.udp - prevUdp);
                trafficData.datasets[2].data.push(data.packet_stats.suspicious - prevSuspicious);
                prevTcp = data.packet_stats.tcp;
                prevUdp = data.packet_stats.udp;
                prevSuspicious = data.packet_stats.suspicious;
                
                if (trafficData.labels.length > 20) {
                    trafficData.labels.shift();
                    trafficData.datasets.forEach(d => d.data.shift());
                }
                chart.update();
                
                // Update hosts list
                const hosts = Object.values(data.discovered_hosts);
                document.getElementById('hosts-list').innerHTML = hosts.length ? 
                    hosts.map(h => `
                        <div class="p-2 bg-slate-800/50 rounded text-sm">
                            <div class="flex justify-between">
                                <span class="font-mono text-white">${h.ip}</span>
                                <span class="text-slate-500">${h.vendor || 'Unknown'}</span>
                            </div>
                            <div class="text-xs text-slate-500">${h.hostname || 'N/A'} | ${h.mac || 'N/A'}</div>
                        </div>
                    `).join('') : '<p class="text-slate-500 text-sm">No hosts discovered yet</p>';
                
                // Update alerts list
                document.getElementById('alerts-list').innerHTML = data.alerts.length ?
                    data.alerts.slice(-10).reverse().map(a => `
                        <div class="p-2 bg-red-500/10 border-l-2 border-red-500 rounded-r text-sm">
                            <div class="font-medium text-white">${a.type || a.signature || 'Alert'}</div>
                            <div class="text-xs text-slate-400">${a.src_ip || ''} ${a.reason || ''}</div>
                            <div class="text-xs text-slate-500">${a.timestamp || ''}</div>
                        </div>
                    `).join('') : '<p class="text-slate-500 text-sm">No alerts</p>';
                
                // Update threats list
                document.getElementById('threats-list').innerHTML = data.threats.length ?
                    data.threats.map(t => `
                        <div class="p-3 bg-red-500/10 border border-red-500/30 rounded text-sm">
                            <div class="font-medium text-red-400">${t.matches.map(m => m.rule).join(', ')}</div>
                            <div class="text-xs text-slate-400 mt-1">${t.filepath}</div>
                            <div class="text-xs text-slate-500">${t.timestamp}</div>
                        </div>
                    `).join('') : '<p class="text-slate-500 text-sm">No malware detected</p>';
                    
            } catch (err) {
                console.error('Update error:', err);
            }
        }
        
        // Update every 2 seconds
        setInterval(updateDashboard, 2000);
        updateDashboard();
    </script>
</body>
</html>
'''

def create_dashboard_app(config):
    """Create Flask dashboard application"""
    if not FLASK_AVAILABLE:
        return None
    
    app = Flask(__name__)
    CORS(app)
    
    @app.route('/')
    def index():
        return render_template_string(
            DASHBOARD_HTML,
            cloud_url=config.get("api_url", "").replace("/api", "")
        )
    
    @app.route('/api/status')
    def status():
        return jsonify({
            "packet_stats": state.packet_stats,
            "discovered_hosts": state.discovered_hosts,
            "alerts": list(state.alerts)[-20:],
            "threats": list(state.threats)[-10:],
            "system_info": state.system_info,
            "cloud_connected": state.cloud_connected,
            "events_count": len(state.events)
        })
    
    @app.route('/api/scan/network', methods=['POST'])
    def trigger_network_scan():
        # Trigger network scan
        return jsonify({"status": "scan triggered"})
    
    return app

# =============================================================================
# MAIN AGENT
# =============================================================================

class SecurityAgent:
    def __init__(self, config):
        self.config = config
        self.api = CloudAPIClient(config)
        self.network_scanner = NetworkScanner()
        self.packet_capture = PacketCapture()
        self.yara_scanner = YaraScanner(config.get("yara_rules_dir", DEFAULT_CONFIG["yara_rules_dir"]))
        self.suricata_monitor = SuricataMonitor(config.get("suricata_log_path", DEFAULT_CONFIG["suricata_log_path"]))
        self.threads = []
        self.dashboard_app = None
    
    def heartbeat_loop(self):
        """Send periodic heartbeats"""
        while state.running:
            system_info = SystemMonitor.get_system_info()
            self.api.send_event("heartbeat", system_info)
            state.last_heartbeat = datetime.now().isoformat()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Heartbeat - CPU: {system_info['cpu_percent']:.1f}%, Mem: {system_info['memory_percent']:.1f}%")
            time.sleep(self.config.get("heartbeat_interval", 30))
    
    def network_scan_loop(self):
        """Periodic network scanning"""
        while state.running:
            if self.config.get("features", {}).get("network_scan", True):
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting network scan...")
                hosts, new_hosts = self.network_scanner.scan()
                if hosts:
                    self.api.send_event("network_scan", {"hosts": hosts})
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(hosts)} hosts, {len(new_hosts)} new")
                    for new_ip in new_hosts:
                        self.api.send_event("alert", {
                            "alert_type": "new_host",
                            "severity": "low",
                            "title": f"New host detected: {new_ip}",
                            "details": {"ip": new_ip}
                        })
            time.sleep(self.config.get("network_scan_interval", 300))
    
    def yara_scan_loop(self):
        """Periodic YARA malware scanning"""
        while state.running:
            if self.config.get("features", {}).get("yara_scan", True):
                if self.yara_scanner.load_rules():
                    for directory in self.config.get("scan_directories", DEFAULT_CONFIG["scan_directories"]):
                        if os.path.exists(directory):
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] YARA scanning: {directory}")
                            results = self.yara_scanner.scan_directory(directory)
                            for result in results:
                                self.api.send_event("yara_match", result)
                                print(f"[!] YARA MATCH: {result['filepath']}")
            time.sleep(self.config.get("yara_scan_interval", 600))
    
    def process_monitor_loop(self):
        """Monitor for suspicious processes"""
        while state.running:
            if self.config.get("features", {}).get("process_monitor", True):
                suspicious = SystemMonitor.get_suspicious_processes()
                for proc in suspicious:
                    state.alerts.append({
                        "type": "suspicious_process",
                        **proc,
                        "timestamp": datetime.now().isoformat()
                    })
                    self.api.send_event("alert", {
                        "alert_type": "suspicious_process",
                        "severity": "high",
                        "title": f"Suspicious process: {proc.get('name')}",
                        "details": proc
                    })
            time.sleep(30)
    
    def start(self, dashboard_port=5000, no_dashboard=False):
        """Start all monitoring"""
        print()
        print("=" * 60)
        print("  ANTI-AI DEFENSE SYSTEM - LOCAL SECURITY AGENT")
        print("=" * 60)
        print(f"  Agent Name: {self.config.get('agent_name', 'unknown')}")
        print(f"  Cloud API: {self.config.get('api_url', 'N/A')}")
        print(f"  Dashboard: http://localhost:{dashboard_port}")
        print("=" * 60)
        print()
        
        # Start heartbeat
        t = threading.Thread(target=self.heartbeat_loop, daemon=True)
        t.start()
        self.threads.append(t)
        print("[+] Heartbeat started")
        
        # Start network scanner
        if NMAP_AVAILABLE and self.config.get("features", {}).get("network_scan", True):
            t = threading.Thread(target=self.network_scan_loop, daemon=True)
            t.start()
            self.threads.append(t)
            print("[+] Network scanner started")
        
        # Start packet capture
        if SCAPY_AVAILABLE and self.config.get("features", {}).get("packet_capture", True):
            t = self.packet_capture.start(self.config.get("network_interface"))
            if t:
                self.threads.append(t)
                print("[+] Packet capture started")
        
        # Start YARA scanner
        if YARA_AVAILABLE and self.config.get("features", {}).get("yara_scan", True):
            t = threading.Thread(target=self.yara_scan_loop, daemon=True)
            t.start()
            self.threads.append(t)
            print("[+] YARA scanner started")
        
        # Start process monitor
        if self.config.get("features", {}).get("process_monitor", True):
            t = threading.Thread(target=self.process_monitor_loop, daemon=True)
            t.start()
            self.threads.append(t)
            print("[+] Process monitor started")
        
        # Start Suricata monitor
        if os.path.exists(self.config.get("suricata_log_path", "")) and self.config.get("features", {}).get("suricata_monitor", True):
            t = self.suricata_monitor.start()
            if t:
                self.threads.append(t)
                print("[+] Suricata monitor started")
        
        print()
        
        # Start dashboard
        if FLASK_AVAILABLE and not no_dashboard:
            self.dashboard_app = create_dashboard_app(self.config)
            print(f"[+] Local dashboard starting at http://localhost:{dashboard_port}")
            print()
            print("Press Ctrl+C to stop")
            print()
            self.dashboard_app.run(host='0.0.0.0', port=dashboard_port, debug=False, use_reloader=False)
        else:
            print("[*] Running in headless mode. Press Ctrl+C to stop.")
            try:
                while state.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        
        self.stop()
    
    def stop(self):
        """Stop all monitoring"""
        print("\n[*] Stopping agent...")
        state.running = False
        self.packet_capture.stop()
        self.suricata_monitor.stop()
        print("[*] Agent stopped")


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description='Anti-AI Defense System - Local Security Agent')
    parser.add_argument('--port', type=int, default=5000, help='Dashboard port (default: 5000)')
    parser.add_argument('--no-dashboard', action='store_true', help='Run without local dashboard')
    parser.add_argument('--config', type=str, help='Path to config.json')
    args = parser.parse_args()
    
    # Load configuration
    config = DEFAULT_CONFIG.copy()
    
    config_paths = [
        args.config,
        Path.home() / ".anti-ai-defense" / "config.json",
        Path(__file__).parent / "config.json",
    ]
    
    for config_path in config_paths:
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                loaded_config = json.load(f)
                config.update(loaded_config)
            print(f"[*] Loaded config from {config_path}")
            break
    
    # Check permissions
    if platform.system() != "Windows" and os.geteuid() != 0:
        print("WARNING: Not running as root. Some features may not work.")
        print("Run with: sudo python agent.py")
        print()
    
    # Start agent
    agent = SecurityAgent(config)
    
    try:
        agent.start(dashboard_port=args.port, no_dashboard=args.no_dashboard)
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
