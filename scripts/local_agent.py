"""
Anti-AI Defense System - Local Network Security Agent
======================================================
This agent runs on your local machine and sends security data to the cloud dashboard.

INSTALLATION:
1. Install dependencies:
   pip install requests psutil scapy yara-python python-nmap watchdog

2. Install Suricata (optional but recommended):
   - Ubuntu/Debian: sudo apt install suricata
   - macOS: brew install suricata
   - Windows: Download from https://suricata.io/download/

3. Configure your API endpoint and key below

4. Run with sudo/admin privileges:
   sudo python local_agent.py

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
from datetime import datetime
from pathlib import Path

# Check for required modules
REQUIRED_MODULES = {
    'requests': 'requests',
    'psutil': 'psutil',
}

OPTIONAL_MODULES = {
    'scapy': 'scapy',
    'yara': 'yara-python',
    'nmap': 'python-nmap',
}

missing_required = []
for module, package in REQUIRED_MODULES.items():
    try:
        __import__(module)
    except ImportError:
        missing_required.append(package)

if missing_required:
    print(f"ERROR: Missing required packages: {', '.join(missing_required)}")
    print(f"Install with: pip install {' '.join(missing_required)}")
    sys.exit(1)

import requests
import psutil

# Optional imports
try:
    from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: scapy not installed. Network sniffing disabled.")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("WARNING: yara-python not installed. Malware scanning disabled.")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("WARNING: python-nmap not installed. Network discovery disabled.")


# =============================================================================
# CONFIGURATION - EDIT THESE VALUES
# =============================================================================

CONFIG = {
    # Your Anti-AI Defense System API endpoint
    "API_URL": "https://sentinel-ai-37.preview.emergentagent.com/api",
    
    # Agent authentication (get this from your dashboard)
    "AGENT_KEY": "local-agent-key-change-me",
    
    # Agent identification
    "AGENT_NAME": platform.node() or "local-agent",
    "AGENT_ID": hashlib.md5(platform.node().encode()).hexdigest()[:16],
    
    # Scanning configuration
    "NETWORK_INTERFACE": None,  # None = auto-detect, or specify like "eth0", "en0"
    "SCAN_SUBNET": None,  # None = auto-detect, or specify like "192.168.1.0/24"
    
    # Suricata configuration
    "SURICATA_LOG_PATH": "/var/log/suricata/eve.json",  # Linux default
    # "SURICATA_LOG_PATH": "/usr/local/var/log/suricata/eve.json",  # macOS
    # "SURICATA_LOG_PATH": "C:\\Program Files\\Suricata\\log\\eve.json",  # Windows
    
    # Nginx log path (if you have nginx)
    "NGINX_LOG_PATH": "/var/log/nginx/access.log",
    
    # YARA rules directory
    "YARA_RULES_DIR": "./yara_rules",
    
    # Scan directories for malware
    "SCAN_DIRECTORIES": [
        str(Path.home() / "Downloads"),
        "/tmp",
    ],
    
    # Intervals (seconds)
    "HEARTBEAT_INTERVAL": 30,
    "NETWORK_SCAN_INTERVAL": 300,  # 5 minutes
    "YARA_SCAN_INTERVAL": 600,  # 10 minutes
    "LOG_CHECK_INTERVAL": 5,
    
    # Enable/disable features
    "ENABLE_PACKET_CAPTURE": True,
    "ENABLE_NETWORK_SCAN": True,
    "ENABLE_YARA_SCAN": True,
    "ENABLE_SURICATA": True,
    "ENABLE_NGINX_MONITOR": False,
    "ENABLE_PROCESS_MONITOR": True,
}


# =============================================================================
# API CLIENT
# =============================================================================

class APIClient:
    def __init__(self, config):
        self.api_url = config["API_URL"]
        self.agent_key = config["AGENT_KEY"]
        self.agent_id = config["AGENT_ID"]
        self.agent_name = config["AGENT_NAME"]
        self.session = requests.Session()
        self.session.headers.update({
            "X-Agent-Key": self.agent_key,
            "X-Agent-ID": self.agent_id,
            "Content-Type": "application/json"
        })
    
    def send_event(self, event_type, data):
        """Send security event to the cloud dashboard"""
        payload = {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        }
        try:
            response = self.session.post(
                f"{self.api_url}/agent/event",
                json=payload,
                timeout=10
            )
            if response.status_code == 200:
                return True
            else:
                print(f"API Error: {response.status_code} - {response.text[:100]}")
                return False
        except Exception as e:
            print(f"Failed to send event: {e}")
            return False
    
    def send_heartbeat(self, system_info):
        """Send agent heartbeat"""
        return self.send_event("heartbeat", system_info)
    
    def send_alert(self, alert_type, severity, title, details):
        """Send security alert"""
        return self.send_event("alert", {
            "alert_type": alert_type,
            "severity": severity,
            "title": title,
            "details": details
        })
    
    def send_network_scan(self, hosts):
        """Send network scan results"""
        return self.send_event("network_scan", {"hosts": hosts})
    
    def send_suricata_alert(self, alert):
        """Send Suricata IDS alert"""
        return self.send_event("suricata_alert", alert)
    
    def send_yara_match(self, match):
        """Send YARA malware match"""
        return self.send_event("yara_match", match)
    
    def send_suspicious_packet(self, packet_info):
        """Send suspicious packet info"""
        return self.send_event("suspicious_packet", packet_info)


# =============================================================================
# SYSTEM MONITOR
# =============================================================================

class SystemMonitor:
    def __init__(self, api_client):
        self.api = api_client
    
    def get_system_info(self):
        """Collect system information"""
        return {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "cpu_count": psutil.cpu_count(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_total": psutil.virtual_memory().total,
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent if platform.system() != 'Windows' else psutil.disk_usage('C:\\').percent,
            "network_interfaces": self.get_network_interfaces(),
            "uptime_seconds": time.time() - psutil.boot_time(),
        }
    
    def get_network_interfaces(self):
        """Get network interface information"""
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interfaces.append({
                        "name": name,
                        "ip": addr.address,
                        "netmask": addr.netmask
                    })
        return interfaces
    
    def monitor_processes(self):
        """Monitor running processes for suspicious activity"""
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'connections']):
            try:
                # Check for suspicious indicators
                cmdline = ' '.join(proc.info['cmdline'] or [])
                
                # Suspicious patterns
                patterns = [
                    'nc -l',  # Netcat listener
                    'ncat -l',
                    '/dev/tcp/',  # Bash reverse shell
                    'python -c "import socket',  # Python reverse shell
                    'base64 -d',  # Encoded payload
                    'curl | bash',  # Remote code execution
                    'wget | bash',
                    'cryptominer',
                    'xmrig',
                ]
                
                for pattern in patterns:
                    if pattern.lower() in cmdline.lower():
                        suspicious.append({
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "cmdline": cmdline[:200],
                            "pattern": pattern,
                            "username": proc.info['username']
                        })
                        break
                
                # Check for processes with many network connections
                conns = proc.info.get('connections', [])
                if conns and len(conns) > 50:
                    suspicious.append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "reason": f"High connection count: {len(conns)}",
                        "username": proc.info['username']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return suspicious


# =============================================================================
# NETWORK SCANNER (using nmap)
# =============================================================================

class NetworkScanner:
    def __init__(self, api_client, config):
        self.api = api_client
        self.config = config
        self.previous_hosts = set()
    
    def get_local_subnet(self):
        """Auto-detect local subnet"""
        if self.config["SCAN_SUBNET"]:
            return self.config["SCAN_SUBNET"]
        
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    # Convert to subnet (assuming /24)
                    parts = addr.address.split('.')
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return None
    
    def scan_network(self):
        """Perform network discovery scan"""
        if not NMAP_AVAILABLE:
            print("Nmap not available, skipping network scan")
            return []
        
        subnet = self.get_local_subnet()
        if not subnet:
            print("Could not determine subnet")
            return []
        
        print(f"Scanning network: {subnet}")
        
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=subnet, arguments='-sn -T4')  # Ping scan, fast timing
            
            hosts = []
            current_hosts = set()
            
            for host in nm.all_hosts():
                current_hosts.add(host)
                host_info = {
                    "ip": host,
                    "hostname": nm[host].hostname() or "unknown",
                    "state": nm[host].state(),
                    "mac": None,
                    "vendor": None
                }
                
                # Try to get MAC address
                if 'mac' in nm[host]['addresses']:
                    host_info['mac'] = nm[host]['addresses']['mac']
                if 'vendor' in nm[host] and nm[host]['vendor']:
                    host_info['vendor'] = list(nm[host]['vendor'].values())[0]
                
                hosts.append(host_info)
            
            # Detect new hosts
            new_hosts = current_hosts - self.previous_hosts
            if new_hosts and self.previous_hosts:  # Don't alert on first scan
                for new_ip in new_hosts:
                    self.api.send_alert(
                        "network_discovery",
                        "medium",
                        f"New device detected: {new_ip}",
                        {"ip": new_ip, "subnet": subnet}
                    )
            
            self.previous_hosts = current_hosts
            return hosts
            
        except Exception as e:
            print(f"Network scan error: {e}")
            return []


# =============================================================================
# PACKET CAPTURE (using scapy)
# =============================================================================

class PacketCapture:
    def __init__(self, api_client, config):
        self.api = api_client
        self.config = config
        self.running = False
        self.packet_count = 0
        self.suspicious_ips = set()
        
        # Known malicious ports
        self.suspicious_ports = {
            4444,   # Metasploit default
            5555,   # Android debug
            6666, 6667,  # IRC (botnet C2)
            31337,  # Back Orifice
            12345, 12346,  # NetBus
            1337,   # Common backdoor
            9001,   # Tor
        }
        
        # Port scan detection
        self.connection_tracker = {}  # IP -> set of ports
    
    def analyze_packet(self, packet):
        """Analyze captured packet for suspicious activity"""
        self.packet_count += 1
        
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check for suspicious ports
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            if dst_port in self.suspicious_ports or src_port in self.suspicious_ports:
                self.api.send_suspicious_packet({
                    "reason": "Suspicious port detected",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": "TCP"
                })
            
            # Port scan detection
            if src_ip not in self.connection_tracker:
                self.connection_tracker[src_ip] = set()
            self.connection_tracker[src_ip].add(dst_port)
            
            # Alert if scanning many ports
            if len(self.connection_tracker[src_ip]) > 20:
                if src_ip not in self.suspicious_ips:
                    self.suspicious_ips.add(src_ip)
                    self.api.send_alert(
                        "port_scan",
                        "high",
                        f"Port scan detected from {src_ip}",
                        {
                            "source_ip": src_ip,
                            "ports_scanned": len(self.connection_tracker[src_ip]),
                            "sample_ports": list(self.connection_tracker[src_ip])[:10]
                        }
                    )
        
        # Check for ARP spoofing
        if packet.haslayer(ARP):
            if packet[ARP].op == 2:  # ARP reply
                # Could implement ARP cache poisoning detection here
                pass
    
    def start_capture(self, interface=None):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            print("Scapy not available, skipping packet capture")
            return
        
        self.running = True
        print(f"Starting packet capture on {interface or 'default interface'}...")
        
        try:
            sniff(
                iface=interface,
                prn=self.analyze_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"Packet capture error: {e}")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False


# =============================================================================
# SURICATA LOG MONITOR
# =============================================================================

class SuricataMonitor:
    def __init__(self, api_client, config):
        self.api = api_client
        self.log_path = config["SURICATA_LOG_PATH"]
        self.last_position = 0
        self.running = False
    
    def check_suricata_installed(self):
        """Check if Suricata is installed"""
        try:
            result = subprocess.run(['suricata', '--build-info'], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def parse_eve_log(self):
        """Parse Suricata EVE JSON log"""
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
                            alerts.append({
                                "timestamp": event.get('timestamp'),
                                "src_ip": event.get('src_ip'),
                                "src_port": event.get('src_port'),
                                "dest_ip": event.get('dest_ip'),
                                "dest_port": event.get('dest_port'),
                                "protocol": event.get('proto'),
                                "signature": event.get('alert', {}).get('signature'),
                                "signature_id": event.get('alert', {}).get('signature_id'),
                                "severity": event.get('alert', {}).get('severity'),
                                "category": event.get('alert', {}).get('category'),
                            })
                    except json.JSONDecodeError:
                        continue
                self.last_position = f.tell()
        except Exception as e:
            print(f"Error reading Suricata log: {e}")
        
        return alerts
    
    def monitor_loop(self):
        """Continuously monitor Suricata logs"""
        self.running = True
        while self.running:
            alerts = self.parse_eve_log()
            for alert in alerts:
                print(f"Suricata Alert: {alert.get('signature')}")
                self.api.send_suricata_alert(alert)
            time.sleep(CONFIG["LOG_CHECK_INTERVAL"])
    
    def stop(self):
        self.running = False


# =============================================================================
# YARA MALWARE SCANNER
# =============================================================================

class YaraScanner:
    def __init__(self, api_client, config):
        self.api = api_client
        self.config = config
        self.rules = None
        self.rules_dir = config["YARA_RULES_DIR"]
        self.scan_dirs = config["SCAN_DIRECTORIES"]
        self.scanned_files = {}  # filepath -> last_modified
    
    def load_rules(self):
        """Load YARA rules from directory"""
        if not YARA_AVAILABLE:
            print("YARA not available")
            return False
        
        # Create default rules if directory doesn't exist
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            self.create_default_rules()
        
        try:
            rule_files = {}
            for f in os.listdir(self.rules_dir):
                if f.endswith('.yar') or f.endswith('.yara'):
                    rule_files[f] = os.path.join(self.rules_dir, f)
            
            if rule_files:
                self.rules = yara.compile(filepaths=rule_files)
                print(f"Loaded {len(rule_files)} YARA rule files")
                return True
            else:
                print("No YARA rules found")
                return False
        except Exception as e:
            print(f"Error loading YARA rules: {e}")
            return False
    
    def create_default_rules(self):
        """Create default YARA rules for common threats"""
        default_rules = '''
rule SuspiciousScript {
    meta:
        description = "Detects suspicious script patterns"
        severity = "medium"
    strings:
        $s1 = "eval(base64_decode" nocase
        $s2 = "exec(base64" nocase
        $s3 = "powershell -enc" nocase
        $s4 = "IEX (New-Object" nocase
        $s5 = "/dev/tcp/" nocase
        $s6 = "nc -e /bin" nocase
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
        $s3 = "minerd" nocase
        $s4 = "cryptonight" nocase
        $s5 = "monero" nocase
    condition:
        any of them
}

rule WebShell {
    meta:
        description = "Detects potential web shells"
        severity = "critical"
    strings:
        $php1 = "<?php eval($_" nocase
        $php2 = "<?php system($_" nocase
        $php3 = "<?php passthru" nocase
        $asp1 = "<%eval request" nocase
        $jsp1 = "Runtime.getRuntime().exec" nocase
    condition:
        any of them
}

rule ReverseShell {
    meta:
        description = "Detects reverse shell patterns"
        severity = "critical"
    strings:
        $s1 = "bash -i >& /dev/tcp" nocase
        $s2 = "nc -e /bin/bash" nocase
        $s3 = "python -c 'import socket,subprocess" nocase
        $s4 = "perl -e 'use Socket" nocase
        $s5 = "ruby -rsocket -e" nocase
    condition:
        any of them
}
'''
        rules_file = os.path.join(self.rules_dir, "default_rules.yar")
        with open(rules_file, 'w') as f:
            f.write(default_rules)
        print(f"Created default YARA rules at {rules_file}")
    
    def scan_file(self, filepath):
        """Scan a single file with YARA rules"""
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(filepath)
            return [
                {
                    "rule": match.rule,
                    "meta": match.meta,
                    "strings": [(s[0], s[1], s[2].decode('utf-8', errors='ignore')[:50]) 
                               for s in match.strings[:5]]
                }
                for match in matches
            ]
        except Exception as e:
            return []
    
    def scan_directory(self, directory):
        """Scan a directory for malware"""
        if not self.rules:
            return []
        
        results = []
        try:
            for root, dirs, files in os.walk(directory):
                # Skip hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for filename in files:
                    filepath = os.path.join(root, filename)
                    
                    # Skip large files
                    try:
                        if os.path.getsize(filepath) > 50 * 1024 * 1024:  # 50MB
                            continue
                    except:
                        continue
                    
                    # Check if file was modified since last scan
                    try:
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
                            "file_size": os.path.getsize(filepath),
                            "file_modified": datetime.fromtimestamp(mtime).isoformat()
                        }
                        results.append(result)
                        print(f"YARA Match: {filepath} - {[m['rule'] for m in matches]}")
        except Exception as e:
            print(f"Error scanning directory {directory}: {e}")
        
        return results
    
    def run_full_scan(self):
        """Run full YARA scan on configured directories"""
        if not self.load_rules():
            return []
        
        all_results = []
        for directory in self.scan_dirs:
            if os.path.exists(directory):
                print(f"Scanning directory: {directory}")
                results = self.scan_directory(directory)
                all_results.extend(results)
        
        return all_results


# =============================================================================
# MAIN AGENT
# =============================================================================

class SecurityAgent:
    def __init__(self, config):
        self.config = config
        self.api = APIClient(config)
        self.system_monitor = SystemMonitor(self.api)
        self.network_scanner = NetworkScanner(self.api, config)
        self.packet_capture = PacketCapture(self.api, config)
        self.suricata_monitor = SuricataMonitor(self.api, config)
        self.yara_scanner = YaraScanner(self.api, config)
        self.running = False
        self.threads = []
    
    def heartbeat_loop(self):
        """Send periodic heartbeats"""
        while self.running:
            system_info = self.system_monitor.get_system_info()
            self.api.send_heartbeat(system_info)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Heartbeat sent - CPU: {system_info['cpu_percent']}%, Mem: {system_info['memory_percent']}%")
            time.sleep(self.config["HEARTBEAT_INTERVAL"])
    
    def network_scan_loop(self):
        """Periodic network scanning"""
        while self.running:
            if self.config["ENABLE_NETWORK_SCAN"]:
                hosts = self.network_scanner.scan_network()
                if hosts:
                    self.api.send_network_scan(hosts)
                    print(f"Network scan complete: {len(hosts)} hosts found")
            time.sleep(self.config["NETWORK_SCAN_INTERVAL"])
    
    def yara_scan_loop(self):
        """Periodic YARA malware scanning"""
        while self.running:
            if self.config["ENABLE_YARA_SCAN"]:
                results = self.yara_scanner.run_full_scan()
                for result in results:
                    self.api.send_yara_match(result)
            time.sleep(self.config["YARA_SCAN_INTERVAL"])
    
    def process_monitor_loop(self):
        """Monitor processes for suspicious activity"""
        while self.running:
            if self.config["ENABLE_PROCESS_MONITOR"]:
                suspicious = self.system_monitor.monitor_processes()
                for proc in suspicious:
                    self.api.send_alert(
                        "suspicious_process",
                        "high",
                        f"Suspicious process: {proc.get('name')}",
                        proc
                    )
            time.sleep(30)  # Check every 30 seconds
    
    def start(self):
        """Start all monitoring threads"""
        self.running = True
        
        print("=" * 60)
        print("Anti-AI Defense System - Local Network Security Agent")
        print("=" * 60)
        print(f"Agent ID: {self.config['AGENT_ID']}")
        print(f"Agent Name: {self.config['AGENT_NAME']}")
        print(f"API Endpoint: {self.config['API_URL']}")
        print("=" * 60)
        
        # Start heartbeat thread
        t = threading.Thread(target=self.heartbeat_loop, daemon=True)
        t.start()
        self.threads.append(t)
        print("[+] Heartbeat thread started")
        
        # Start network scan thread
        if self.config["ENABLE_NETWORK_SCAN"] and NMAP_AVAILABLE:
            t = threading.Thread(target=self.network_scan_loop, daemon=True)
            t.start()
            self.threads.append(t)
            print("[+] Network scanner thread started")
        
        # Start YARA scan thread
        if self.config["ENABLE_YARA_SCAN"] and YARA_AVAILABLE:
            t = threading.Thread(target=self.yara_scan_loop, daemon=True)
            t.start()
            self.threads.append(t)
            print("[+] YARA scanner thread started")
        
        # Start process monitor thread
        if self.config["ENABLE_PROCESS_MONITOR"]:
            t = threading.Thread(target=self.process_monitor_loop, daemon=True)
            t.start()
            self.threads.append(t)
            print("[+] Process monitor thread started")
        
        # Start Suricata monitor thread
        if self.config["ENABLE_SURICATA"]:
            if self.suricata_monitor.check_suricata_installed():
                t = threading.Thread(target=self.suricata_monitor.monitor_loop, daemon=True)
                t.start()
                self.threads.append(t)
                print("[+] Suricata monitor thread started")
            else:
                print("[-] Suricata not installed, skipping")
        
        # Start packet capture (runs in foreground)
        if self.config["ENABLE_PACKET_CAPTURE"] and SCAPY_AVAILABLE:
            print("[+] Starting packet capture (Ctrl+C to stop)...")
            try:
                self.packet_capture.start_capture(self.config["NETWORK_INTERFACE"])
            except KeyboardInterrupt:
                pass
        else:
            # Keep main thread alive
            print("[*] Agent running. Press Ctrl+C to stop.")
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        
        self.stop()
    
    def stop(self):
        """Stop all monitoring"""
        print("\n[*] Stopping agent...")
        self.running = False
        self.packet_capture.stop_capture()
        self.suricata_monitor.stop()
        print("[*] Agent stopped")


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # Check for root/admin privileges
    if platform.system() != 'Windows':
        if os.geteuid() != 0:
            print("WARNING: Running without root privileges. Some features may not work.")
            print("Run with: sudo python local_agent.py")
    
    agent = SecurityAgent(CONFIG)
    agent.start()
