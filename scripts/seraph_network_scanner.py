#!/usr/bin/env python3
"""
Seraph Network Scanner & Deployment Agent
=========================================
Run this on a machine INSIDE your network to:
1. Discover all devices on your LAN
2. Report them to Seraph AI server
3. Deploy Seraph Defender agents to discovered devices

This is the REAL scanner that runs on YOUR network.
"""

import os
import sys
import json
import time
import socket
import struct
import subprocess
import argparse
import platform
import threading
import ipaddress
from datetime import datetime
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("Installing requests...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

try:
    import nmap
except ImportError:
    print("Installing python-nmap...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-nmap", "-q"])
    import nmap

try:
    import paramiko
except ImportError:
    print("Installing paramiko...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko", "-q"])
    import paramiko


class SeraphNetworkScanner:
    """
    Network scanner that runs on YOUR network and reports to Seraph AI server.
    """
    
    def __init__(self, api_url: str, scan_interval: int = 300):
        self.api_url = api_url.rstrip('/')
        self.scan_interval = scan_interval
        self.scanner_id = f"scanner-{socket.gethostname()}-{os.getpid()}"
        self.discovered_devices: Dict[str, dict] = {}
        self.running = False
        
        # Get local network info
        self.local_ip = self._get_local_ip()
        self.network_cidr = self._get_network_cidr()
        
        print(f"[*] Seraph Network Scanner initialized")
        print(f"[*] Scanner ID: {self.scanner_id}")
        print(f"[*] Local IP: {self.local_ip}")
        print(f"[*] Network: {self.network_cidr}")
        print(f"[*] API URL: {self.api_url}")
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def _get_network_cidr(self) -> str:
        """Get the local network CIDR"""
        try:
            # Try to determine network from local IP
            ip = self.local_ip
            parts = ip.split('.')
            
            # Common home/office networks
            if parts[0] == '192' and parts[1] == '168':
                return f"192.168.{parts[2]}.0/24"
            elif parts[0] == '10':
                return f"10.{parts[1]}.{parts[2]}.0/24"
            elif parts[0] == '172' and 16 <= int(parts[1]) <= 31:
                return f"172.{parts[1]}.{parts[2]}.0/24"
            else:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return "192.168.1.0/24"
    
    def scan_network(self, network: str = None) -> List[dict]:
        """
        Scan network using multiple methods for comprehensive discovery
        """
        network = network or self.network_cidr
        devices = []
        
        print(f"\n[*] Starting network scan: {network}")
        print(f"[*] Time: {datetime.now().isoformat()}")
        
        # Method 1: ARP scan (fastest, most reliable for local network)
        arp_devices = self._arp_scan(network)
        print(f"[+] ARP scan found: {len(arp_devices)} devices")
        
        # Method 2: Nmap ping scan
        nmap_devices = self._nmap_scan(network)
        print(f"[+] Nmap scan found: {len(nmap_devices)} devices")
        
        # Method 3: mDNS/Bonjour discovery (for Apple devices, Chromecasts, etc.)
        mdns_devices = self._mdns_scan()
        print(f"[+] mDNS scan found: {len(mdns_devices)} devices")
        
        # Merge all results
        seen_ips = set()
        for device in arp_devices + nmap_devices + mdns_devices:
            ip = device.get('ip_address')
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                devices.append(device)
        
        # Enrich devices with port scan for key devices
        devices = self._enrich_devices(devices)
        
        print(f"\n[*] Total unique devices found: {len(devices)}")
        return devices
    
    def _arp_scan(self, network: str) -> List[dict]:
        """ARP scan using arping or reading ARP cache"""
        devices = []
        
        try:
            # First ping sweep to populate ARP cache
            network_obj = ipaddress.ip_network(network, strict=False)
            
            # Quick ping sweep using threading
            def ping_host(ip):
                try:
                    if platform.system() == "Windows":
                        result = subprocess.run(
                            ["ping", "-n", "1", "-w", "100", str(ip)],
                            capture_output=True, timeout=2
                        )
                    else:
                        result = subprocess.run(
                            ["ping", "-c", "1", "-W", "1", str(ip)],
                            capture_output=True, timeout=2
                        )
                    return result.returncode == 0
                except:
                    return False
            
            # Parallel ping sweep
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(ping_host, ip): ip for ip in network_obj.hosts()}
                for future in as_completed(futures, timeout=30):
                    pass  # Just populate ARP cache
            
            # Read ARP cache
            if platform.system() == "Windows":
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    if 'dynamic' in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1].replace('-', ':').lower()
                            if self._is_valid_ip(ip) and self._ip_in_network(ip, network):
                                devices.append({
                                    'ip_address': ip,
                                    'mac_address': mac,
                                    'discovery_method': 'arp'
                                })
            else:
                result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] != '(incomplete)':
                        ip = parts[0]
                        mac = parts[2].lower()
                        if self._is_valid_ip(ip) and self._ip_in_network(ip, network):
                            devices.append({
                                'ip_address': ip,
                                'mac_address': mac,
                                'discovery_method': 'arp'
                            })
        except Exception as e:
            print(f"[-] ARP scan error: {e}")
        
        return devices
    
    def _nmap_scan(self, network: str) -> List[dict]:
        """Nmap scan for comprehensive discovery"""
        devices = []
        
        try:
            nm = nmap.PortScanner()
            
            # Try privileged scan first, fall back to unprivileged
            try:
                nm.scan(hosts=network, arguments='-sn -T4 --min-rate=500')
            except nmap.PortScannerError:
                # Unprivileged scan
                nm.scan(hosts=network, arguments='-sn -T4')
            
            for host in nm.all_hosts():
                device = {
                    'ip_address': host,
                    'discovery_method': 'nmap'
                }
                
                # Get MAC and vendor
                if 'mac' in nm[host].get('addresses', {}):
                    device['mac_address'] = nm[host]['addresses']['mac'].lower()
                
                if nm[host].get('vendor'):
                    device['vendor'] = list(nm[host]['vendor'].values())[0] if nm[host]['vendor'] else None
                
                # Get hostname
                if nm[host].get('hostnames'):
                    for h in nm[host]['hostnames']:
                        if h.get('name'):
                            device['hostname'] = h['name']
                            break
                
                devices.append(device)
                
        except Exception as e:
            print(f"[-] Nmap scan error: {e}")
        
        return devices
    
    def _mdns_scan(self) -> List[dict]:
        """mDNS/Bonjour discovery for Apple devices, Chromecasts, etc."""
        devices = []
        
        try:
            # Use dns-sd or avahi-browse if available
            if platform.system() == "Darwin":  # macOS
                result = subprocess.run(
                    ["dns-sd", "-B", "_services._dns-sd._udp", "local."],
                    capture_output=True, text=True, timeout=5
                )
            elif platform.system() == "Linux":
                result = subprocess.run(
                    ["avahi-browse", "-at", "--resolve", "-p"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if line.startswith('='):
                        parts = line.split(';')
                        if len(parts) >= 8:
                            try:
                                ip = parts[7]
                                hostname = parts[3]
                                if self._is_valid_ip(ip):
                                    devices.append({
                                        'ip_address': ip,
                                        'hostname': hostname,
                                        'discovery_method': 'mdns'
                                    })
                            except:
                                pass
        except Exception as e:
            pass  # mDNS is optional
        
        return devices
    
    def _enrich_devices(self, devices: List[dict]) -> List[dict]:
        """Enrich devices with additional info like OS, open ports"""
        
        def enrich_single(device):
            ip = device['ip_address']
            
            # Quick port scan for OS identification
            common_ports = {
                22: ('ssh', 'Linux/Unix'),
                3389: ('rdp', 'Windows'),
                445: ('smb', 'Windows'),
                548: ('afp', 'macOS'),
                5353: ('mdns', 'Apple/Android'),
                62078: ('iphone-sync', 'iOS'),
                8008: ('chromecast', 'Chromecast'),
                9100: ('printer', 'Printer'),
            }
            
            open_ports = []
            os_hints = []
            
            for port, (service, os_hint) in common_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    if result == 0:
                        open_ports.append({'port': port, 'service': service})
                        os_hints.append(os_hint)
                except:
                    pass
            
            device['open_ports'] = open_ports
            
            # Determine device type
            if 'iOS' in os_hints or 'iphone-sync' in [p['service'] for p in open_ports]:
                device['device_type'] = 'mobile'
                device['os'] = 'iOS'
            elif 'Android' in str(os_hints) or device.get('hostname', '').lower().startswith('android'):
                device['device_type'] = 'mobile'
                device['os'] = 'Android'
            elif 'Windows' in os_hints:
                device['device_type'] = 'workstation'
                device['os'] = 'Windows'
            elif 'Linux/Unix' in os_hints:
                device['device_type'] = 'server'
                device['os'] = 'Linux'
            elif 'macOS' in os_hints:
                device['device_type'] = 'workstation'
                device['os'] = 'macOS'
            elif 'Chromecast' in os_hints:
                device['device_type'] = 'iot'
                device['os'] = 'ChromeOS'
            elif 'Printer' in os_hints:
                device['device_type'] = 'iot'
                device['os'] = 'Embedded'
            else:
                device['device_type'] = 'unknown'
            
            # Calculate deployability
            device['deployable'] = device.get('os') in ['Linux', 'Windows', 'macOS']
            device['mobile_manageable'] = device.get('os') in ['iOS', 'Android']
            
            return device
        
        # Parallel enrichment
        enriched = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(enrich_single, d): d for d in devices}
            for future in as_completed(futures, timeout=60):
                try:
                    enriched.append(future.result())
                except:
                    enriched.append(futures[future])
        
        return enriched
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP is valid"""
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    
    def _ip_in_network(self, ip: str, network: str) -> bool:
        """Check if IP is in network"""
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
        except:
            return False
    
    def report_devices(self, devices: List[dict]) -> bool:
        """Report discovered devices to Seraph AI server"""
        try:
            payload = {
                'scanner_id': self.scanner_id,
                'network': self.network_cidr,
                'scan_time': datetime.now().isoformat(),
                'devices': devices
            }
            
            response = requests.post(
                f"{self.api_url}/api/swarm/scanner/report",
                json=payload,
                timeout=30
            )
            
            if response.ok:
                result = response.json()
                print(f"[+] Reported {len(devices)} devices to server")
                print(f"[+] Server response: {result.get('message', 'OK')}")
                return True
            else:
                print(f"[-] Failed to report devices: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[-] Error reporting to server: {e}")
            return False
    
    def deploy_to_device(self, device: dict, credentials: dict) -> bool:
        """Deploy Seraph Defender agent to a device"""
        ip = device['ip_address']
        os_type = device.get('os', 'unknown')
        
        print(f"\n[*] Deploying to {ip} ({os_type})...")
        
        if os_type in ['Linux', 'macOS']:
            return self._deploy_ssh(ip, credentials)
        elif os_type == 'Windows':
            return self._deploy_winrm(ip, credentials)
        else:
            print(f"[-] Unsupported OS: {os_type}")
            return False
    
    def _deploy_ssh(self, ip: str, credentials: dict) -> bool:
        """Deploy via SSH"""
        username = credentials.get('username', 'root')
        password = credentials.get('password')
        key_path = credentials.get('key_path')
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': ip,
                'username': username,
                'timeout': 30,
            }
            
            if key_path and os.path.exists(key_path):
                connect_kwargs['key_filename'] = key_path
            elif password:
                connect_kwargs['password'] = password
            else:
                connect_kwargs['look_for_keys'] = True
            
            client.connect(**connect_kwargs)
            
            # Download and install agent
            commands = f'''
set -e
echo "[*] Installing Seraph Defender Agent..."
mkdir -p /opt/seraph-defender
curl -sL "{self.api_url}/api/agent/download/linux" -o /opt/seraph-defender/seraph_defender.py
chmod +x /opt/seraph-defender/seraph_defender.py

# Install dependencies
pip3 install psutil requests 2>/dev/null || pip install psutil requests 2>/dev/null || true

# Create systemd service
cat > /etc/systemd/system/seraph-defender.service << 'EOF'
[Unit]
Description=Seraph Defender Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/seraph-defender/seraph_defender.py --monitor --api-url {self.api_url}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable seraph-defender
systemctl start seraph-defender
echo "[+] Seraph Defender installed successfully!"
'''
            
            stdin, stdout, stderr = client.exec_command(commands, timeout=120)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode() + stderr.read().decode()
            
            client.close()
            
            if exit_code == 0:
                print(f"[+] Successfully deployed to {ip}")
                return True
            else:
                print(f"[-] Deployment failed: {output[-500:]}")
                return False
                
        except Exception as e:
            print(f"[-] SSH deployment error: {e}")
            return False
    
    def _deploy_winrm(self, ip: str, credentials: dict) -> bool:
        """Deploy via WinRM"""
        try:
            import winrm
            
            username = credentials.get('username', 'Administrator')
            password = credentials.get('password')
            
            if not password:
                print("[-] Password required for Windows deployment")
                return False
            
            session = winrm.Session(ip, auth=(username, password))
            
            # Download and install agent via PowerShell
            ps_script = f'''
$ErrorActionPreference = "Stop"
Write-Host "[*] Installing Seraph Defender Agent..."

# Create directory
New-Item -ItemType Directory -Force -Path "C:\\SeraphDefender" | Out-Null

# Download agent
Invoke-WebRequest -Uri "{self.api_url}/api/agent/download/windows" -OutFile "C:\\SeraphDefender\\seraph_defender.py"

# Install Python if needed
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {{
    Write-Host "[*] Installing Python..."
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe" -OutFile "$env:TEMP\\python.exe"
    Start-Process -FilePath "$env:TEMP\\python.exe" -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait
}}

# Install dependencies
python -m pip install psutil requests --quiet

# Create scheduled task to run agent
$action = New-ScheduledTaskAction -Execute "python.exe" -Argument "C:\\SeraphDefender\\seraph_defender.py --monitor --api-url {self.api_url}"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "SeraphDefender" -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -Force

# Start immediately
Start-ScheduledTask -TaskName "SeraphDefender"

Write-Host "[+] Seraph Defender installed successfully!"
'''
            
            result = session.run_ps(ps_script)
            
            if result.status_code == 0:
                print(f"[+] Successfully deployed to {ip}")
                return True
            else:
                print(f"[-] Deployment failed: {result.std_err.decode()[:500]}")
                return False
                
        except Exception as e:
            print(f"[-] WinRM deployment error: {e}")
            return False
    
    def run_continuous(self):
        """Run continuous scanning and reporting"""
        self.running = True
        print(f"\n[*] Starting continuous scan (interval: {self.scan_interval}s)")
        print("[*] Press Ctrl+C to stop\n")
        
        while self.running:
            try:
                devices = self.scan_network()
                self.report_devices(devices)
                self.discovered_devices = {d['ip_address']: d for d in devices}
                
                # Wait for next scan
                for _ in range(self.scan_interval):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print("\n[*] Stopping scanner...")
                self.running = False
            except Exception as e:
                print(f"[-] Scan error: {e}")
                time.sleep(30)
    
    def stop(self):
        """Stop the scanner"""
        self.running = False


def main():
    parser = argparse.ArgumentParser(description='Seraph Network Scanner')
    parser.add_argument('--api-url', required=True, help='Seraph AI server URL')
    parser.add_argument('--network', help='Network CIDR to scan (default: auto-detect)')
    parser.add_argument('--interval', type=int, default=300, help='Scan interval in seconds')
    parser.add_argument('--once', action='store_true', help='Run single scan and exit')
    parser.add_argument('--deploy', help='Deploy to specific IP')
    parser.add_argument('--deploy-user', default='root', help='Username for deployment')
    parser.add_argument('--deploy-pass', help='Password for deployment')
    parser.add_argument('--deploy-key', help='SSH key path for deployment')
    
    args = parser.parse_args()
    
    scanner = SeraphNetworkScanner(args.api_url, args.interval)
    
    if args.network:
        scanner.network_cidr = args.network
    
    if args.deploy:
        # Deploy to specific device
        credentials = {
            'username': args.deploy_user,
            'password': args.deploy_pass,
            'key_path': args.deploy_key
        }
        device = {'ip_address': args.deploy, 'os': 'Linux'}  # Assume Linux
        scanner.deploy_to_device(device, credentials)
    elif args.once:
        # Single scan
        devices = scanner.scan_network()
        scanner.report_devices(devices)
        
        print("\n" + "="*60)
        print("DISCOVERED DEVICES:")
        print("="*60)
        for d in devices:
            print(f"  {d['ip_address']:15} | {d.get('mac_address', 'N/A'):17} | {d.get('os', 'unknown'):10} | {d.get('hostname', 'N/A')}")
    else:
        # Continuous scanning
        scanner.run_continuous()


if __name__ == '__main__':
    main()
