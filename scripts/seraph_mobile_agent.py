#!/usr/bin/env python3
"""
Seraph Mobile Monitor Agent
============================
Lightweight agent for iOS/Android devices that can be run via:
- Pythonista (iOS)
- Termux (Android)
- QPython (Android)

Features:
- Network connection monitoring
- Running apps detection
- Location tracking (opt-in)
- Battery and system status
- Suspicious app detection
"""

import os
import sys
import json
import time
import socket
import platform
import threading
from datetime import datetime
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    print("Installing requests...")
    os.system(f"{sys.executable} -m pip install requests")
    import requests

# Try to import platform-specific modules
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# iOS-specific (Pythonista)
try:
    import location
    import notification
    HAS_IOS = True
except ImportError:
    HAS_IOS = False

# Android-specific (Termux/QPython)
try:
    import androidhelper
    ANDROID_HELPER = androidhelper.Android()
    HAS_ANDROID = True
except ImportError:
    HAS_ANDROID = False


class SeraphMobileAgent:
    """
    Mobile monitoring agent for iOS/Android
    """
    
    def __init__(self, api_url: str, device_name: str = None):
        self.api_url = api_url.rstrip('/')
        self.device_name = device_name or socket.gethostname()
        self.host_id = f"mobile-{self.device_name}-{self._get_device_id()}"
        self.running = False
        self.platform = self._detect_platform()
        
        print(f"[*] Seraph Mobile Agent initialized")
        print(f"[*] Host ID: {self.host_id}")
        print(f"[*] Platform: {self.platform}")
        print(f"[*] API URL: {self.api_url}")
    
    def _get_device_id(self) -> str:
        """Get a unique device identifier"""
        try:
            if HAS_ANDROID:
                return ANDROID_HELPER.getDeviceId().result[:8]
            elif HAS_IOS:
                import keychain
                device_id = keychain.get_password('seraph', 'device_id')
                if not device_id:
                    import uuid
                    device_id = str(uuid.uuid4())[:8]
                    keychain.set_password('seraph', 'device_id', device_id)
                return device_id
            else:
                import uuid
                return str(uuid.uuid4())[:8]
        except:
            return "unknown"
    
    def _detect_platform(self) -> str:
        """Detect the mobile platform"""
        if HAS_IOS:
            return "iOS"
        elif HAS_ANDROID:
            return "Android"
        else:
            system = platform.system()
            if 'Darwin' in system:
                return "iOS"  # Likely Pythonista
            elif 'Linux' in system:
                return "Android"  # Likely Termux
            return "Unknown"
    
    def collect_telemetry(self) -> Dict:
        """Collect system telemetry"""
        telemetry = {
            "timestamp": datetime.now().isoformat(),
            "host_id": self.host_id,
            "platform": self.platform,
            "device_name": self.device_name
        }
        
        # Battery info
        try:
            if HAS_ANDROID:
                battery = ANDROID_HELPER.batteryGetStatus().result
                telemetry["battery"] = {
                    "level": battery.get("level"),
                    "status": battery.get("status"),
                    "plugged": battery.get("plugged")
                }
            elif HAS_PSUTIL:
                battery = psutil.sensors_battery()
                if battery:
                    telemetry["battery"] = {
                        "level": battery.percent,
                        "plugged": battery.power_plugged
                    }
        except:
            pass
        
        # Network info
        try:
            telemetry["network"] = {
                "local_ip": self._get_local_ip(),
                "hostname": socket.gethostname()
            }
            
            if HAS_ANDROID:
                wifi = ANDROID_HELPER.wifiGetConnectionInfo().result
                telemetry["network"]["wifi_ssid"] = wifi.get("ssid")
                telemetry["network"]["wifi_bssid"] = wifi.get("bssid")
        except:
            pass
        
        # Running processes/apps
        try:
            if HAS_PSUTIL:
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'username']):
                    try:
                        processes.append(proc.info)
                    except:
                        pass
                telemetry["running_processes"] = len(processes)
            
            if HAS_ANDROID:
                apps = ANDROID_HELPER.getRunningPackages().result
                telemetry["running_apps"] = apps
        except:
            pass
        
        # Location (opt-in)
        try:
            if HAS_IOS:
                loc = location.get_location()
                if loc:
                    telemetry["location"] = {
                        "latitude": loc["latitude"],
                        "longitude": loc["longitude"],
                        "accuracy": loc.get("horizontal_accuracy")
                    }
            elif HAS_ANDROID:
                loc = ANDROID_HELPER.getLastKnownLocation().result
                if loc:
                    telemetry["location"] = {
                        "latitude": loc.get("latitude"),
                        "longitude": loc.get("longitude"),
                        "accuracy": loc.get("accuracy")
                    }
        except:
            pass
        
        return telemetry
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "unknown"
    
    def check_suspicious_apps(self) -> List[Dict]:
        """Check for suspicious applications"""
        suspicious = []
        
        # Known suspicious app patterns
        suspicious_patterns = [
            "spy", "track", "monitor", "keylog", "stealth",
            "hidden", "invisible", "remote", "rat", "trojan"
        ]
        
        try:
            if HAS_ANDROID:
                packages = ANDROID_HELPER.getRunningPackages().result
                for pkg in packages:
                    pkg_lower = pkg.lower()
                    for pattern in suspicious_patterns:
                        if pattern in pkg_lower:
                            suspicious.append({
                                "type": "suspicious_app",
                                "package": pkg,
                                "pattern_matched": pattern,
                                "severity": "high"
                            })
                            break
            
            if HAS_PSUTIL:
                for proc in psutil.process_iter(['name', 'cmdline']):
                    try:
                        name = proc.info['name'].lower()
                        for pattern in suspicious_patterns:
                            if pattern in name:
                                suspicious.append({
                                    "type": "suspicious_process",
                                    "name": proc.info['name'],
                                    "pattern_matched": pattern,
                                    "severity": "high"
                                })
                                break
                    except:
                        pass
        except:
            pass
        
        return suspicious
    
    def send_telemetry(self, events: List[Dict]) -> bool:
        """Send telemetry to server"""
        try:
            response = requests.post(
                f"{self.api_url}/api/swarm/telemetry/ingest",
                json={"events": events},
                timeout=30
            )
            return response.ok
        except Exception as e:
            print(f"[-] Failed to send telemetry: {e}")
            return False
    
    def register_device(self) -> bool:
        """Register this mobile device with the server"""
        try:
            device_info = {
                "ip_address": self._get_local_ip(),
                "hostname": self.device_name,
                "os": self.platform,
                "device_type": "mobile",
                "deployable": False,
                "mobile_manageable": True,
                "agent_version": "1.0.0"
            }
            
            response = requests.post(
                f"{self.api_url}/api/swarm/scanner/report",
                json={
                    "scanner_id": f"mobile-{self.host_id}",
                    "network": "mobile",
                    "scan_time": datetime.now().isoformat(),
                    "devices": [device_info]
                },
                timeout=30
            )
            
            if response.ok:
                print(f"[+] Device registered successfully")
                return True
            else:
                print(f"[-] Failed to register device: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[-] Registration error: {e}")
            return False
    
    def run(self, interval: int = 60):
        """Run the mobile agent"""
        self.running = True
        print(f"\n[*] Starting mobile agent (interval: {interval}s)")
        print("[*] Press Ctrl+C to stop\n")
        
        # Register device
        self.register_device()
        
        while self.running:
            try:
                # Collect telemetry
                telemetry = self.collect_telemetry()
                
                events = [{
                    "event_type": "mobile.heartbeat",
                    "host_id": self.host_id,
                    "timestamp": telemetry["timestamp"],
                    "severity": "info",
                    "data": telemetry
                }]
                
                # Check for suspicious apps
                suspicious = self.check_suspicious_apps()
                for s in suspicious:
                    events.append({
                        "event_type": "mobile.suspicious_app",
                        "host_id": self.host_id,
                        "timestamp": datetime.now().isoformat(),
                        "severity": s["severity"],
                        "data": s
                    })
                
                # Send telemetry
                if self.send_telemetry(events):
                    print(f"[+] Sent {len(events)} events")
                
                # Wait for next cycle
                time.sleep(interval)
                
            except KeyboardInterrupt:
                print("\n[*] Stopping agent...")
                self.running = False
            except Exception as e:
                print(f"[-] Error: {e}")
                time.sleep(30)
    
    def stop(self):
        """Stop the agent"""
        self.running = False


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Seraph Mobile Agent')
    parser.add_argument('--api-url', required=True, help='Seraph AI server URL')
    parser.add_argument('--device-name', help='Device name')
    parser.add_argument('--interval', type=int, default=60, help='Telemetry interval')
    
    args = parser.parse_args()
    
    agent = SeraphMobileAgent(args.api_url, args.device_name)
    agent.run(args.interval)


if __name__ == '__main__':
    main()
