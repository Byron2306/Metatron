"""
Test VPN and Network Scanning Features - Iteration 22
Tests:
- GET /api/swarm/vpn/server-config - VPN server config with split_tunnel=true
- POST /api/swarm/vpn/register-agent - Register agent for VPN access
- GET /api/swarm/vpn/agents - List registered VPN agents
- GET /api/swarm/agent/download/v7 - Agent script with network scanning classes
- Verify seraph_defender_v7.py contains NetworkScanner, WiFiScanner, BluetoothScanner, WireGuardVPN
- Verify seraph_mobile_v7.py contains MobileWiFiScanner, MobileBluetoothScanner
"""

import pytest
import requests
import os
import re

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestVPNEndpoints:
    """Test VPN configuration and registration endpoints"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures"""
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        # Login to get auth token
        login_response = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": "test@defender.io",
            "password": "test123"
        })
        if login_response.status_code == 200:
            token = login_response.json().get("access_token")
            self.session.headers.update({"Authorization": f"Bearer {token}"})
    
    def test_vpn_server_config_returns_split_tunnel(self):
        """GET /api/swarm/vpn/server-config should return split_tunnel=true"""
        response = self.session.get(f"{BASE_URL}/api/swarm/vpn/server-config")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        
        data = response.json()
        # Verify split tunnel mode is enabled
        assert data.get("split_tunnel") == True, f"Expected split_tunnel=True, got {data.get('split_tunnel')}"
        # Verify allowed_ips is only Seraph network (not 0.0.0.0/0)
        assert data.get("allowed_ips") == "10.200.200.0/24", f"Expected 10.200.200.0/24, got {data.get('allowed_ips')}"
        # Verify note mentions split tunnel
        assert "split tunnel" in data.get("note", "").lower() or "not affected" in data.get("note", "").lower(), \
            f"Note should mention split tunnel: {data.get('note')}"
        print(f"✓ VPN server config: split_tunnel={data.get('split_tunnel')}, allowed_ips={data.get('allowed_ips')}")
    
    def test_vpn_register_agent(self):
        """POST /api/swarm/vpn/register-agent should register agent and assign IP"""
        test_agent_id = "test-vpn-agent-001"
        test_public_key = "test-public-key-base64=="
        
        response = self.session.post(f"{BASE_URL}/api/swarm/vpn/register-agent", json={
            "agent_id": test_agent_id,
            "agent_public_key": test_public_key
        })
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        
        data = response.json()
        assert data.get("status") == "registered", f"Expected status=registered, got {data.get('status')}"
        assert data.get("agent_id") == test_agent_id, f"Expected agent_id={test_agent_id}, got {data.get('agent_id')}"
        # Verify assigned IP is in the 10.200.200.x range
        assigned_ip = data.get("assigned_ip", "")
        assert assigned_ip.startswith("10.200.200."), f"Expected IP in 10.200.200.x range, got {assigned_ip}"
        print(f"✓ VPN agent registered: agent_id={test_agent_id}, assigned_ip={assigned_ip}")
    
    def test_vpn_list_agents(self):
        """GET /api/swarm/vpn/agents should list registered VPN agents"""
        response = self.session.get(f"{BASE_URL}/api/swarm/vpn/agents")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        
        data = response.json()
        assert "agents" in data, "Response should contain 'agents' key"
        assert "count" in data, "Response should contain 'count' key"
        assert isinstance(data["agents"], list), "agents should be a list"
        print(f"✓ VPN agents list: count={data.get('count')}")


class TestAgentDownloadV7:
    """Test agent download endpoint returns script with network scanning"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures"""
        self.session = requests.Session()
    
    def test_agent_download_v7_returns_script(self):
        """GET /api/swarm/agent/download/v7 should return Python script"""
        response = self.session.get(f"{BASE_URL}/api/swarm/agent/download/v7")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        
        # Check content type
        content_type = response.headers.get("Content-Type", "")
        assert "text/x-python" in content_type or "application/octet-stream" in content_type or "text/plain" in content_type, \
            f"Expected Python content type, got {content_type}"
        
        script_content = response.text
        assert len(script_content) > 1000, "Script should be substantial"
        print(f"✓ Agent v7 download: {len(script_content)} bytes")
    
    def test_agent_v7_contains_network_scanner(self):
        """Agent v7 should contain NetworkScanner class"""
        response = self.session.get(f"{BASE_URL}/api/swarm/agent/download/v7")
        assert response.status_code == 200
        
        script = response.text
        assert "class NetworkScanner:" in script, "Script should contain NetworkScanner class"
        assert "def scan_port" in script, "NetworkScanner should have scan_port method"
        assert "def scan_router" in script, "NetworkScanner should have scan_router method"
        assert "def get_gateway" in script, "NetworkScanner should have get_gateway method"
        print("✓ NetworkScanner class found with scan_port, scan_router, get_gateway methods")
    
    def test_agent_v7_contains_wifi_scanner(self):
        """Agent v7 should contain WiFiScanner class"""
        response = self.session.get(f"{BASE_URL}/api/swarm/agent/download/v7")
        assert response.status_code == 200
        
        script = response.text
        assert "class WiFiScanner:" in script, "Script should contain WiFiScanner class"
        assert "def scan_networks" in script, "WiFiScanner should have scan_networks method"
        print("✓ WiFiScanner class found with scan_networks method")
    
    def test_agent_v7_contains_bluetooth_scanner(self):
        """Agent v7 should contain BluetoothScanner class"""
        response = self.session.get(f"{BASE_URL}/api/swarm/agent/download/v7")
        assert response.status_code == 200
        
        script = response.text
        assert "class BluetoothScanner:" in script, "Script should contain BluetoothScanner class"
        assert "def scan_devices" in script, "BluetoothScanner should have scan_devices method"
        print("✓ BluetoothScanner class found with scan_devices method")
    
    def test_agent_v7_contains_wireguard_vpn(self):
        """Agent v7 should contain WireGuardVPN class with split tunnel"""
        response = self.session.get(f"{BASE_URL}/api/swarm/agent/download/v7")
        assert response.status_code == 200
        
        script = response.text
        assert "class WireGuardVPN:" in script, "Script should contain WireGuardVPN class"
        assert "split tunnel" in script.lower() or "split_tunnel" in script.lower(), \
            "WireGuardVPN should mention split tunnel mode"
        assert "10.200.200" in script, "WireGuardVPN should use 10.200.200.x subnet"
        assert "def auto_configure" in script, "WireGuardVPN should have auto_configure method"
        assert "def connect" in script, "WireGuardVPN should have connect method"
        assert "def disconnect" in script, "WireGuardVPN should have disconnect method"
        print("✓ WireGuardVPN class found with split tunnel mode, auto_configure, connect, disconnect methods")
    
    def test_agent_v7_dashboard_has_new_tabs(self):
        """Agent v7 dashboard should have Port/Router Scan, WiFi, Bluetooth, VPN tabs"""
        response = self.session.get(f"{BASE_URL}/api/swarm/agent/download/v7")
        assert response.status_code == 200
        
        script = response.text
        # Check for dashboard tabs
        assert "Port/Router Scan" in script or "netscan" in script, "Dashboard should have Port/Router Scan tab"
        assert "WiFi Networks" in script or "wifi" in script, "Dashboard should have WiFi Networks tab"
        assert "Bluetooth" in script or "bluetooth" in script, "Dashboard should have Bluetooth tab"
        assert "VPN" in script or "vpn" in script, "Dashboard should have VPN tab"
        print("✓ Dashboard has Port/Router Scan, WiFi Networks, Bluetooth, VPN tabs")
    
    def test_agent_v7_has_perform_network_scans(self):
        """Agent v7 should have _perform_network_scans method in monitoring loop"""
        response = self.session.get(f"{BASE_URL}/api/swarm/agent/download/v7")
        assert response.status_code == 200
        
        script = response.text
        assert "_perform_network_scans" in script, "Script should have _perform_network_scans method"
        assert "def _perform_network_scans" in script, "Should define _perform_network_scans method"
        print("✓ _perform_network_scans method found in agent monitoring loop")


class TestSeraphDefenderV7File:
    """Test seraph_defender_v7.py file directly"""
    
    def test_file_exists(self):
        """seraph_defender_v7.py should exist"""
        assert os.path.exists("/app/scripts/seraph_defender_v7.py"), "seraph_defender_v7.py should exist"
        print("✓ seraph_defender_v7.py exists")
    
    def test_network_scanner_class(self):
        """seraph_defender_v7.py should have NetworkScanner class"""
        with open("/app/scripts/seraph_defender_v7.py", "r") as f:
            content = f.read()
        
        assert "class NetworkScanner:" in content, "Should have NetworkScanner class"
        assert "network_scanner = NetworkScanner()" in content, "Should instantiate network_scanner"
        print("✓ NetworkScanner class defined and instantiated")
    
    def test_wifi_scanner_class(self):
        """seraph_defender_v7.py should have WiFiScanner class"""
        with open("/app/scripts/seraph_defender_v7.py", "r") as f:
            content = f.read()
        
        assert "class WiFiScanner:" in content, "Should have WiFiScanner class"
        assert "wifi_scanner = WiFiScanner()" in content, "Should instantiate wifi_scanner"
        print("✓ WiFiScanner class defined and instantiated")
    
    def test_bluetooth_scanner_class(self):
        """seraph_defender_v7.py should have BluetoothScanner class"""
        with open("/app/scripts/seraph_defender_v7.py", "r") as f:
            content = f.read()
        
        assert "class BluetoothScanner:" in content, "Should have BluetoothScanner class"
        assert "bluetooth_scanner = BluetoothScanner()" in content, "Should instantiate bluetooth_scanner"
        print("✓ BluetoothScanner class defined and instantiated")
    
    def test_wireguard_vpn_class(self):
        """seraph_defender_v7.py should have WireGuardVPN class with split tunnel"""
        with open("/app/scripts/seraph_defender_v7.py", "r") as f:
            content = f.read()
        
        assert "class WireGuardVPN:" in content, "Should have WireGuardVPN class"
        assert "wireguard_vpn = WireGuardVPN()" in content, "Should instantiate wireguard_vpn"
        # Verify split tunnel mode
        assert "split tunnel" in content.lower() or "split_tunnel" in content.lower(), \
            "WireGuardVPN should mention split tunnel"
        assert "10.200.200" in content, "Should use 10.200.200.x subnet for VPN"
        # Verify it doesn't route all traffic
        assert "0.0.0.0/0" not in content or "not all traffic" in content.lower() or "only route" in content.lower(), \
            "VPN should NOT route all traffic (0.0.0.0/0)"
        print("✓ WireGuardVPN class with split tunnel mode (10.200.200.0/24)")
    
    def test_perform_network_scans_method(self):
        """seraph_defender_v7.py should have _perform_network_scans in monitoring loop"""
        with open("/app/scripts/seraph_defender_v7.py", "r") as f:
            content = f.read()
        
        assert "def _perform_network_scans" in content, "Should have _perform_network_scans method"
        assert "_perform_network_scans()" in content, "Should call _perform_network_scans in loop"
        print("✓ _perform_network_scans method defined and called in monitoring loop")
    
    def test_dashboard_tabs(self):
        """seraph_defender_v7.py dashboard should have new tabs"""
        with open("/app/scripts/seraph_defender_v7.py", "r") as f:
            content = f.read()
        
        # Check for tab definitions in HTML
        assert "Port/Router Scan" in content or 'data-panel="netscan"' in content, \
            "Dashboard should have Port/Router Scan tab"
        assert "WiFi Networks" in content or 'data-panel="wifi"' in content, \
            "Dashboard should have WiFi Networks tab"
        assert "Bluetooth" in content or 'data-panel="bluetooth"' in content, \
            "Dashboard should have Bluetooth tab"
        assert "VPN" in content or 'data-panel="vpn"' in content, \
            "Dashboard should have VPN tab"
        print("✓ Dashboard has Port/Router Scan, WiFi Networks, Bluetooth, VPN tabs")


class TestSeraphMobileV7File:
    """Test seraph_mobile_v7.py file directly"""
    
    def test_file_exists(self):
        """seraph_mobile_v7.py should exist"""
        assert os.path.exists("/app/scripts/seraph_mobile_v7.py"), "seraph_mobile_v7.py should exist"
        print("✓ seraph_mobile_v7.py exists")
    
    def test_mobile_wifi_scanner_class(self):
        """seraph_mobile_v7.py should have MobileWiFiScanner class"""
        with open("/app/scripts/seraph_mobile_v7.py", "r") as f:
            content = f.read()
        
        assert "class MobileWiFiScanner:" in content, "Should have MobileWiFiScanner class"
        assert "mobile_wifi_scanner = MobileWiFiScanner()" in content, "Should instantiate mobile_wifi_scanner"
        print("✓ MobileWiFiScanner class defined and instantiated")
    
    def test_mobile_bluetooth_scanner_class(self):
        """seraph_mobile_v7.py should have MobileBluetoothScanner class"""
        with open("/app/scripts/seraph_mobile_v7.py", "r") as f:
            content = f.read()
        
        assert "class MobileBluetoothScanner:" in content, "Should have MobileBluetoothScanner class"
        assert "mobile_bluetooth_scanner = MobileBluetoothScanner()" in content, "Should instantiate mobile_bluetooth_scanner"
        print("✓ MobileBluetoothScanner class defined and instantiated")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
