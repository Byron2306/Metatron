#!/usr/bin/env python3
"""
Anti-AI Defense System - Quick Start Bundle
============================================
Single-file installer and agent launcher.

Just run: python anti_ai_defense.py

This will:
1. Install all required dependencies
2. Set up YARA malware rules
3. Start the local security agent with dashboard

Requirements: Python 3.8+

Author: Anti-AI Defense System
"""

import os
import sys
import platform
import subprocess
import json
import time
import socket
import hashlib
import threading
from datetime import datetime
from pathlib import Path
from collections import deque

# =============================================================================
# CONFIGURATION
# =============================================================================

CLOUD_API_URL = "https://agentic-armor.preview.emergentagent.com/api"
DASHBOARD_PORT = 5000
AGENT_NAME = platform.node() or "local-agent"
AGENT_ID = hashlib.md5(platform.node().encode()).hexdigest()[:16]

INSTALL_DIR = Path.home() / ".anti-ai-defense"
RULES_DIR = INSTALL_DIR / "yara_rules"

# Python packages to install
REQUIRED_PACKAGES = [
    "requests",
    "psutil",
    "flask",
    "flask-cors",
]

OPTIONAL_PACKAGES = [
    "scapy",
    "yara-python",
    "python-nmap",
]

# =============================================================================
# INSTALLER
# =============================================================================

def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║       █████╗ ███╗   ██╗████████╗██╗      █████╗ ██╗               ║
║      ██╔══██╗████╗  ██║╚══██╔══╝██║     ██╔══██╗██║               ║
║      ███████║██╔██╗ ██║   ██║   ██║     ███████║██║               ║
║      ██╔══██║██║╚██╗██║   ██║   ██║     ██╔══██║██║               ║
║      ██║  ██║██║ ╚████║   ██║   ██║     ██║  ██║██║               ║
║      ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝               ║
║                                                                   ║
║              DEFENSE SYSTEM - QUICK START BUNDLE                  ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """)

def install_packages():
    """Install required Python packages"""
    print("[*] Installing required packages...")
    
    for package in REQUIRED_PACKAGES:
        print(f"    Installing {package}...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-q", package],
                check=True,
                capture_output=True
            )
            print(f"    ✓ {package}")
        except subprocess.CalledProcessError:
            print(f"    ✗ {package} failed")
            return False
    
    print("[*] Installing optional packages (may require admin)...")
    for package in OPTIONAL_PACKAGES:
        print(f"    Installing {package}...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-q", package],
                check=False,
                capture_output=True
            )
            print(f"    ✓ {package}")
        except:
            print(f"    - {package} skipped (non-critical)")
    
    return True

def create_yara_rules():
    """Create default YARA rules"""
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    
    rules = '''
rule SuspiciousScript {
    meta:
        description = "Detects suspicious script patterns"
        severity = "medium"
    strings:
        $s1 = "eval(base64_decode" nocase
        $s2 = "exec(base64" nocase
        $s3 = "powershell -enc" nocase
        $s4 = "/dev/tcp/" nocase
        $s5 = "nc -e /bin" nocase
    condition:
        any of them
}

rule CryptoMiner {
    meta:
        description = "Detects cryptocurrency miners"
        severity = "high"
    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "xmrig" nocase
        $s3 = "cryptonight" nocase
    condition:
        any of them
}

rule WebShell {
    meta:
        description = "Detects web shells"
        severity = "critical"
    strings:
        $s1 = "<?php eval($_" nocase
        $s2 = "<?php system($_" nocase
        $s3 = "Runtime.getRuntime().exec" nocase
    condition:
        any of them
}

rule ReverseShell {
    meta:
        description = "Detects reverse shells"
        severity = "critical"
    strings:
        $s1 = "bash -i >& /dev/tcp" nocase
        $s2 = "nc -e /bin/bash" nocase
        $s3 = "python -c \\'import socket" nocase
    condition:
        any of them
}
'''
    
    with open(RULES_DIR / "default.yar", "w") as f:
        f.write(rules)
    print(f"[✓] YARA rules created at {RULES_DIR}")

def check_system_tools():
    """Check for system tools"""
    import shutil
    
    tools = {
        "nmap": "Network scanning",
        "suricata": "IDS (optional)",
    }
    
    print("[*] Checking system tools...")
    for tool, desc in tools.items():
        if shutil.which(tool):
            print(f"    ✓ {tool} - {desc}")
        else:
            print(f"    - {tool} not found - {desc}")
            if tool == "nmap":
                if platform.system() == "Darwin":
                    print("      Install with: brew install nmap")
                elif platform.system() == "Linux":
                    print("      Install with: sudo apt install nmap")
                else:
                    print("      Download from: https://nmap.org/download.html")

# =============================================================================
# AGENT CODE
# =============================================================================

# Global state
class State:
    running = True
    events = deque(maxlen=1000)
    alerts = deque(maxlen=100)
    threats = deque(maxlen=100)
    hosts = {}
    packets = {"total": 0, "tcp": 0, "udp": 0, "suspicious": 0}
    system = {}
    cloud_ok = False

state = State()

# Import after install
requests = None
psutil = None
flask_app = None
Flask = None
CORS = None
nmap_module = None
scapy_module = None
yara_module = None

def load_modules():
    """Load modules after installation"""
    global requests, psutil, Flask, CORS, nmap_module, scapy_module, yara_module
    
    import requests as req
    import psutil as ps
    requests = req
    psutil = ps
    
    try:
        from flask import Flask as Fl, jsonify, render_template_string
        from flask_cors import CORS as C
        Flask = Fl
        CORS = C
    except ImportError:
        print("[!] Flask not available - dashboard disabled")
    
    try:
        import nmap
        nmap_module = nmap
    except ImportError:
        pass
    
    try:
        from scapy.all import sniff, IP, TCP, UDP
        scapy_module = True
    except ImportError:
        pass
    
    try:
        import yara
        yara_module = yara
    except ImportError:
        pass

def get_system_info():
    """Get system information"""
    info = {
        "hostname": platform.node(),
        "os": platform.system(),
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent if platform.system() != 'Windows' else psutil.disk_usage('C:\\').percent,
        "network_interfaces": []
    }
    
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                info["network_interfaces"].append({
                    "name": name,
                    "ip": addr.address,
                    "netmask": addr.netmask
                })
    
    state.system = info
    return info

def send_to_cloud(event_type, data):
    """Send event to cloud API"""
    try:
        response = requests.post(
            f"{CLOUD_API_URL}/agent/event",
            json={
                "agent_id": AGENT_ID,
                "agent_name": AGENT_NAME,
                "event_type": event_type,
                "timestamp": datetime.utcnow().isoformat(),
                "data": data
            },
            headers={
                "X-Agent-Key": "local-agent",
                "X-Agent-ID": AGENT_ID,
                "Content-Type": "application/json"
            },
            timeout=10
        )
        state.cloud_ok = response.status_code == 200
        return response.status_code == 200
    except:
        state.cloud_ok = False
        return False

def heartbeat_loop():
    """Send heartbeats"""
    while state.running:
        info = get_system_info()
        send_to_cloud("heartbeat", info)
        ts = datetime.now().strftime('%H:%M:%S')
        print(f"[{ts}] Heartbeat - CPU: {info['cpu_percent']:.1f}%, Mem: {info['memory_percent']:.1f}%")
        time.sleep(30)

def network_scan_loop():
    """Scan network"""
    if not nmap_module:
        return
    
    prev_hosts = set()
    
    while state.running:
        try:
            # Get subnet
            subnet = None
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        parts = addr.address.split('.')
                        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                        break
                if subnet:
                    break
            
            if subnet:
                ts = datetime.now().strftime('%H:%M:%S')
                print(f"[{ts}] Scanning network: {subnet}")
                
                nm = nmap_module.PortScanner()
                nm.scan(hosts=subnet, arguments='-sn -T4')
                
                hosts = []
                current = set()
                for host in nm.all_hosts():
                    current.add(host)
                    host_info = {
                        "ip": host,
                        "hostname": nm[host].hostname() or "unknown",
                        "mac": nm[host]['addresses'].get('mac'),
                        "vendor": list(nm[host].get('vendor', {}).values())[0] if nm[host].get('vendor') else None,
                        "last_seen": datetime.now().isoformat()
                    }
                    hosts.append(host_info)
                    state.hosts[host] = host_info
                
                # New hosts
                new_hosts = current - prev_hosts
                prev_hosts = current
                
                if hosts:
                    send_to_cloud("network_scan", {"hosts": hosts})
                    print(f"[{ts}] Found {len(hosts)} hosts, {len(new_hosts)} new")
                    
                    for new_ip in new_hosts:
                        state.alerts.append({
                            "type": "new_host",
                            "ip": new_ip,
                            "timestamp": datetime.now().isoformat()
                        })
        except Exception as e:
            print(f"[!] Network scan error: {e}")
        
        time.sleep(300)

def yara_scan_loop():
    """Scan for malware"""
    if not yara_module:
        return
    
    scanned = {}
    
    while state.running:
        try:
            # Load rules
            rules = None
            if RULES_DIR.exists():
                rule_files = {}
                for f in RULES_DIR.iterdir():
                    if f.suffix in ['.yar', '.yara']:
                        rule_files[f.name] = str(f)
                if rule_files:
                    rules = yara_module.compile(filepaths=rule_files)
            
            if rules:
                scan_dirs = [
                    str(Path.home() / "Downloads"),
                    "/tmp" if platform.system() != "Windows" else str(Path.home() / "AppData" / "Local" / "Temp"),
                ]
                
                for scan_dir in scan_dirs:
                    if os.path.exists(scan_dir):
                        ts = datetime.now().strftime('%H:%M:%S')
                        print(f"[{ts}] YARA scanning: {scan_dir}")
                        
                        for root, dirs, files in os.walk(scan_dir):
                            dirs[:] = [d for d in dirs if not d.startswith('.')]
                            
                            for fname in files:
                                fpath = os.path.join(root, fname)
                                try:
                                    if os.path.getsize(fpath) > 50 * 1024 * 1024:
                                        continue
                                    
                                    mtime = os.path.getmtime(fpath)
                                    if fpath in scanned and scanned[fpath] == mtime:
                                        continue
                                    scanned[fpath] = mtime
                                    
                                    matches = rules.match(fpath)
                                    if matches:
                                        result = {
                                            "filepath": fpath,
                                            "matches": [{"rule": m.rule} for m in matches],
                                            "timestamp": datetime.now().isoformat()
                                        }
                                        state.threats.append(result)
                                        send_to_cloud("yara_match", result)
                                        print(f"[!] MALWARE DETECTED: {fpath}")
                                except:
                                    pass
        except Exception as e:
            print(f"[!] YARA scan error: {e}")
        
        time.sleep(600)

def process_monitor_loop():
    """Monitor processes"""
    patterns = ['nc -l', 'ncat -l', '/dev/tcp/', 'base64 -d', 'xmrig', 'cryptominer']
    
    while state.running:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                    for pattern in patterns:
                        if pattern.lower() in cmdline:
                            alert = {
                                "type": "suspicious_process",
                                "pid": proc.info['pid'],
                                "name": proc.info['name'],
                                "pattern": pattern,
                                "timestamp": datetime.now().isoformat()
                            }
                            state.alerts.append(alert)
                            send_to_cloud("alert", {
                                "alert_type": "suspicious_process",
                                "severity": "high",
                                "title": f"Suspicious process: {proc.info['name']}",
                                "details": alert
                            })
                            print(f"[!] Suspicious process: {proc.info['name']}")
                            break
                except:
                    pass
        except Exception as e:
            pass
        
        time.sleep(30)

# Dashboard HTML
DASHBOARD_HTML = '''
<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Anti-AI Defense - Local Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>body{font-family:system-ui;background:#020617;color:#F8FAFC}</style>
</head><body class="p-6">
<div class="max-w-6xl mx-auto">
<div class="flex items-center justify-between mb-6">
<div class="flex items-center gap-3">
<div class="w-10 h-10 rounded bg-blue-500/20 flex items-center justify-center">
<svg class="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
</svg></div>
<div><h1 class="text-xl font-bold">DEFENDER</h1><p class="text-xs text-slate-400">Local Agent</p></div>
</div>
<div class="flex items-center gap-2 px-3 py-2 rounded bg-green-500/20 border border-green-500/30">
<div class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
<span class="text-xs text-green-400">ACTIVE</span>
</div>
</div>
<div class="grid grid-cols-4 gap-4 mb-6">
<div class="bg-slate-900/50 rounded p-4 border border-slate-800">
<p class="text-slate-400 text-sm">Packets</p><p id="s1" class="text-2xl font-bold text-cyan-400">0</p></div>
<div class="bg-slate-900/50 rounded p-4 border border-slate-800">
<p class="text-slate-400 text-sm">Suspicious</p><p id="s2" class="text-2xl font-bold text-red-400">0</p></div>
<div class="bg-slate-900/50 rounded p-4 border border-slate-800">
<p class="text-slate-400 text-sm">Hosts</p><p id="s3" class="text-2xl font-bold text-blue-400">0</p></div>
<div class="bg-slate-900/50 rounded p-4 border border-slate-800">
<p class="text-slate-400 text-sm">Alerts</p><p id="s4" class="text-2xl font-bold text-amber-400">0</p></div>
</div>
<div class="grid grid-cols-3 gap-4">
<div class="bg-slate-900/50 rounded p-4 border border-slate-800">
<h3 class="font-semibold mb-3">System</h3><div id="sys" class="text-sm space-y-1"></div></div>
<div class="bg-slate-900/50 rounded p-4 border border-slate-800">
<h3 class="font-semibold mb-3">Hosts</h3><div id="hosts" class="text-sm space-y-1 max-h-48 overflow-y-auto"></div></div>
<div class="bg-slate-900/50 rounded p-4 border border-slate-800">
<h3 class="font-semibold mb-3">Alerts</h3><div id="alerts" class="text-sm space-y-1 max-h-48 overflow-y-auto"></div></div>
</div>
<div class="mt-4 bg-slate-900/50 rounded p-4 border border-slate-800">
<h3 class="font-semibold mb-3">Malware Detections</h3><div id="threats" class="text-sm"></div></div>
<p class="text-center text-slate-500 text-xs mt-6">Cloud: <a href="''' + CLOUD_API_URL.replace('/api','') + '''" class="text-blue-400">''' + CLOUD_API_URL.replace('/api','') + '''</a></p>
</div>
<script>
async function update(){
try{const r=await fetch('/api/status');const d=await r.json();
document.getElementById('s1').textContent=d.packets.total;
document.getElementById('s2').textContent=d.packets.suspicious;
document.getElementById('s3').textContent=Object.keys(d.hosts).length;
document.getElementById('s4').textContent=d.alerts.length;
document.getElementById('sys').innerHTML=`
<div class="flex justify-between"><span class="text-slate-500">Host</span><span>${d.system.hostname||'N/A'}</span></div>
<div class="flex justify-between"><span class="text-slate-500">CPU</span><span class="text-cyan-400">${(d.system.cpu_percent||0).toFixed(1)}%</span></div>
<div class="flex justify-between"><span class="text-slate-500">Mem</span><span class="text-cyan-400">${(d.system.memory_percent||0).toFixed(1)}%</span></div>
`;
document.getElementById('hosts').innerHTML=Object.values(d.hosts).map(h=>`<div class="p-1 bg-slate-800/50 rounded mb-1"><span class="font-mono">${h.ip}</span> - ${h.hostname||'unknown'}</div>`).join('')||'<span class="text-slate-500">None</span>';
document.getElementById('alerts').innerHTML=d.alerts.slice(-5).reverse().map(a=>`<div class="p-1 bg-red-500/10 border-l-2 border-red-500 rounded-r mb-1">${a.type}: ${a.ip||a.name||''}</div>`).join('')||'<span class="text-slate-500">None</span>';
document.getElementById('threats').innerHTML=d.threats.map(t=>`<div class="p-2 bg-red-500/10 border border-red-500/30 rounded mb-2"><strong class="text-red-400">${t.matches.map(m=>m.rule).join(', ')}</strong><br><span class="text-xs text-slate-400">${t.filepath}</span></div>`).join('')||'<span class="text-slate-500">No malware detected</span>';
}catch(e){console.error(e)}}
setInterval(update,2000);update();
</script></body></html>
'''

def start_dashboard():
    """Start local dashboard"""
    if not Flask:
        return
    
    app = Flask(__name__)
    CORS(app)
    
    @app.route('/')
    def index():
        from flask import render_template_string
        return render_template_string(DASHBOARD_HTML)
    
    @app.route('/api/status')
    def status():
        from flask import jsonify
        return jsonify({
            "packets": state.packets,
            "hosts": state.hosts,
            "alerts": list(state.alerts)[-20:],
            "threats": list(state.threats),
            "system": state.system,
            "cloud_ok": state.cloud_ok
        })
    
    print(f"[+] Dashboard running at http://localhost:{DASHBOARD_PORT}")
    app.run(host='0.0.0.0', port=DASHBOARD_PORT, debug=False, use_reloader=False)

# =============================================================================
# MAIN
# =============================================================================

def main():
    print_banner()
    
    # Install packages
    if not install_packages():
        print("[!] Installation failed")
        return
    
    # Load modules
    load_modules()
    
    # Create YARA rules
    create_yara_rules()
    
    # Check system tools
    check_system_tools()
    
    print()
    print("=" * 60)
    print("  STARTING SECURITY AGENT")
    print("=" * 60)
    print(f"  Agent: {AGENT_NAME}")
    print(f"  Cloud: {CLOUD_API_URL}")
    print(f"  Dashboard: http://localhost:{DASHBOARD_PORT}")
    print("=" * 60)
    print()
    
    # Check permissions
    if platform.system() != "Windows" and os.geteuid() != 0:
        print("[!] WARNING: Not running as root. Some features limited.")
        print("    Run with: sudo python anti_ai_defense.py")
        print()
    
    # Start threads
    threads = []
    
    t = threading.Thread(target=heartbeat_loop, daemon=True)
    t.start()
    threads.append(t)
    print("[+] Heartbeat started")
    
    if nmap_module:
        t = threading.Thread(target=network_scan_loop, daemon=True)
        t.start()
        threads.append(t)
        print("[+] Network scanner started")
    
    if yara_module:
        t = threading.Thread(target=yara_scan_loop, daemon=True)
        t.start()
        threads.append(t)
        print("[+] YARA scanner started")
    
    t = threading.Thread(target=process_monitor_loop, daemon=True)
    t.start()
    threads.append(t)
    print("[+] Process monitor started")
    
    print()
    print("[*] Press Ctrl+C to stop")
    print()
    
    # Start dashboard (blocking)
    if Flask:
        start_dashboard()
    else:
        try:
            while state.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    
    print("\n[*] Agent stopped")

if __name__ == "__main__":
    main()
