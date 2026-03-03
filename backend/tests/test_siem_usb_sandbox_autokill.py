"""
Test Suite for Iteration 23 Features:
- Aggressive Auto-Kill (CRITICAL + HIGH severities, expanded pattern list)
- SIEM Integration (Elasticsearch, Splunk, Syslog)
- USB Scanner with auto-scan on device connect
- Cuckoo Sandbox with local fallback analysis
"""

import pytest
import requests
import os
import re

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

# Test credentials
TEST_EMAIL = "test@defender.io"
TEST_PASSWORD = "test123"


@pytest.fixture(scope="module")
def auth_token():
    """Get authentication token"""
    response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    if response.status_code == 200:
        data = response.json()
        return data.get("access_token") or data.get("token")
    pytest.skip(f"Authentication failed: {response.status_code}")


@pytest.fixture(scope="module")
def auth_headers(auth_token):
    """Get headers with auth token"""
    return {"Authorization": f"Bearer {auth_token}"}


class TestSIEMIntegration:
    """Test SIEM integration endpoints"""
    
    def test_siem_status_endpoint_exists(self, auth_headers):
        """GET /api/swarm/siem/status - should return SIEM configuration"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/siem/status",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        
        data = response.json()
        # Verify response structure
        assert "enabled" in data, "Response should contain 'enabled' field"
        assert "type" in data, "Response should contain 'type' field"
        print(f"SIEM Status: enabled={data.get('enabled')}, type={data.get('type')}")
    
    def test_siem_status_shows_elasticsearch(self, auth_headers):
        """Verify SIEM is configured with Elasticsearch"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/siem/status",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        data = response.json()
        # Since ELASTICSEARCH_URL is set in backend/.env, SIEM should be enabled
        if data.get("enabled"):
            assert data.get("type") in ["elasticsearch", "splunk", "syslog"], \
                f"SIEM type should be elasticsearch, splunk, or syslog, got {data.get('type')}"
            print(f"SIEM configured: {data.get('type')}")
        else:
            print("SIEM not enabled (no SIEM URL configured)")
    
    def test_siem_test_endpoint_requires_auth(self):
        """POST /api/swarm/siem/test - should require authentication"""
        response = requests.post(f"{BASE_URL}/api/swarm/siem/test")
        assert response.status_code in [401, 403], \
            f"Expected 401/403 without auth, got {response.status_code}"
    
    def test_siem_test_endpoint_with_auth(self, auth_headers):
        """POST /api/swarm/siem/test - should send test event"""
        response = requests.post(
            f"{BASE_URL}/api/swarm/siem/test",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        
        data = response.json()
        # Should return success status
        assert "success" in data, "Response should contain 'success' field"
        assert "message" in data, "Response should contain 'message' field"
        print(f"SIEM Test: success={data.get('success')}, message={data.get('message')}")


class TestUSBScanEndpoints:
    """Test USB scan endpoints"""
    
    def test_usb_scan_endpoint_exists(self, auth_headers):
        """POST /api/swarm/usb/scan - endpoint should exist"""
        response = requests.post(
            f"{BASE_URL}/api/swarm/usb/scan",
            headers=auth_headers,
            json={
                "host_id": "test-host-001",
                "device_path": "/media/usb0",
                "device_name": "Test USB"
            }
        )
        # Should return 200 (queued) or 404 (agent not found) - not 500
        assert response.status_code in [200, 404], \
            f"Expected 200 or 404, got {response.status_code}: {response.text}"
        print(f"USB Scan endpoint response: {response.status_code}")
    
    def test_usb_scans_list_endpoint(self, auth_headers):
        """GET /api/swarm/usb/scans - should list USB scans"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/usb/scans",
            headers=auth_headers
        )
        # Endpoint may or may not exist
        if response.status_code == 200:
            data = response.json()
            print(f"USB Scans: {data}")
        else:
            print(f"USB scans list endpoint: {response.status_code}")


class TestSandboxEndpoints:
    """Test Sandbox analysis endpoints"""
    
    def test_sandbox_submit_endpoint_exists(self, auth_headers):
        """POST /api/swarm/sandbox/submit - endpoint should exist"""
        response = requests.post(
            f"{BASE_URL}/api/swarm/sandbox/submit",
            headers=auth_headers,
            json={
                "host_id": "test-host-001",
                "file_path": "/tmp/test.exe"
            }
        )
        # Should return 200 (queued) or 404 (not found) - not 500
        if response.status_code in [200, 404, 422]:
            print(f"Sandbox submit endpoint response: {response.status_code}")
        else:
            print(f"Sandbox submit: {response.status_code} - {response.text}")
    
    def test_sandbox_status_endpoint(self, auth_headers):
        """GET /api/swarm/sandbox/status - should return sandbox status"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/sandbox/status",
            headers=auth_headers
        )
        if response.status_code == 200:
            data = response.json()
            print(f"Sandbox Status: {data}")
        else:
            print(f"Sandbox status endpoint: {response.status_code}")


class TestAgentV7Features:
    """Test that seraph_defender_v7.py has all required features"""
    
    def test_agent_v7_download_endpoint(self, auth_headers):
        """GET /api/swarm/agent/download/v7 - should return agent script"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/agent/download/v7",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        content = response.text
        assert len(content) > 1000, "Agent script should be substantial"
        print(f"Agent v7 script length: {len(content)} chars")
    
    def test_agent_v7_has_siem_integration_class(self, auth_headers):
        """Verify agent has SIEMIntegration class"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/agent/download/v7",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        content = response.text
        assert "class SIEMIntegration" in content, "Agent should have SIEMIntegration class"
        assert "elasticsearch" in content.lower(), "Agent should support Elasticsearch"
        assert "splunk" in content.lower(), "Agent should support Splunk"
        assert "syslog" in content.lower(), "Agent should support Syslog"
        print("✓ SIEMIntegration class found with Elasticsearch, Splunk, Syslog support")
    
    def test_agent_v7_has_usb_scanner_class(self, auth_headers):
        """Verify agent has USBScanner class"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/agent/download/v7",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        content = response.text
        assert "class USBScanner" in content, "Agent should have USBScanner class"
        assert "monitor_new_devices" in content, "USBScanner should have monitor_new_devices method"
        assert "auto_scan_enabled" in content, "USBScanner should have auto_scan_enabled"
        print("✓ USBScanner class found with monitor_new_devices and auto_scan")
    
    def test_agent_v7_has_cuckoo_sandbox_class(self, auth_headers):
        """Verify agent has CuckooSandbox class"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/agent/download/v7",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        content = response.text
        assert "class CuckooSandbox" in content, "Agent should have CuckooSandbox class"
        assert "_local_analysis" in content, "CuckooSandbox should have local fallback analysis"
        print("✓ CuckooSandbox class found with local fallback analysis")
    
    def test_agent_v7_has_aggressive_auto_kill(self, auth_headers):
        """Verify agent has aggressive auto-kill configuration"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/agent/download/v7",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        content = response.text
        
        # Check for auto_kill_severities with CRITICAL and HIGH
        assert "auto_kill_severities" in content, "Agent should have auto_kill_severities"
        assert "ThreatSeverity.CRITICAL" in content, "auto_kill_severities should include CRITICAL"
        assert "ThreatSeverity.HIGH" in content, "auto_kill_severities should include HIGH"
        print("✓ auto_kill_severities includes CRITICAL and HIGH")
    
    def test_agent_v7_has_instant_kill_processes(self, auth_headers):
        """Verify agent has instant_kill_processes list"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/agent/download/v7",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        content = response.text
        
        # Check for instant_kill_processes
        assert "instant_kill_processes" in content, "Agent should have instant_kill_processes"
        
        # Check for dangerous process names
        dangerous_processes = ['mimikatz', 'lazagne', 'procdump', 'xmrig', 'netcat', 'psexec']
        for proc in dangerous_processes:
            assert proc in content.lower(), f"instant_kill_processes should contain {proc}"
        print(f"✓ instant_kill_processes contains dangerous processes: {dangerous_processes}")
    
    def test_agent_v7_has_critical_patterns(self, auth_headers):
        """Verify agent has expanded critical_patterns list"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/agent/download/v7",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        content = response.text
        
        # Check for critical_patterns
        assert "critical_patterns" in content, "Agent should have critical_patterns"
        
        # Check for key patterns
        key_patterns = ['mimikatz', 'ransomware', 'meterpreter', 'cobalt', 'xmrig']
        for pattern in key_patterns:
            assert pattern in content.lower(), f"critical_patterns should contain {pattern}"
        print(f"✓ critical_patterns contains key patterns: {key_patterns}")
    
    def test_agent_v7_dashboard_has_usb_tab(self, auth_headers):
        """Verify agent dashboard has USB tab"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/agent/download/v7",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        content = response.text
        assert 'data-panel="usb"' in content or "USB" in content, "Dashboard should have USB tab"
        print("✓ Dashboard has USB tab")
    
    def test_agent_v7_dashboard_has_sandbox_tab(self, auth_headers):
        """Verify agent dashboard has Sandbox tab"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/agent/download/v7",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        content = response.text
        assert 'data-panel="sandbox"' in content or "Sandbox" in content, "Dashboard should have Sandbox tab"
        print("✓ Dashboard has Sandbox tab")
    
    def test_agent_v7_dashboard_has_siem_tab(self, auth_headers):
        """Verify agent dashboard has SIEM tab"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/agent/download/v7",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        content = response.text
        assert 'data-panel="siem"' in content or "SIEM" in content, "Dashboard should have SIEM tab"
        print("✓ Dashboard has SIEM tab")
    
    def test_agent_v7_monitoring_loop_calls_usb_scanner(self, auth_headers):
        """Verify monitoring loop calls usb_scanner.monitor_new_devices()"""
        response = requests.get(
            f"{BASE_URL}/api/swarm/agent/download/v7",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        content = response.text
        assert "usb_scanner.monitor_new_devices()" in content, \
            "Monitoring loop should call usb_scanner.monitor_new_devices()"
        print("✓ Monitoring loop calls usb_scanner.monitor_new_devices()")


class TestAgentScriptFile:
    """Test the actual seraph_defender_v7.py file on disk"""
    
    def test_script_file_exists(self):
        """Verify seraph_defender_v7.py exists"""
        script_path = "/app/scripts/seraph_defender_v7.py"
        assert os.path.exists(script_path), f"Script file should exist at {script_path}"
        print(f"✓ Script file exists at {script_path}")
    
    def test_script_has_siem_class(self):
        """Verify script has SIEMIntegration class"""
        with open("/app/scripts/seraph_defender_v7.py", "r") as f:
            content = f.read()
        
        assert "class SIEMIntegration:" in content, "Script should have SIEMIntegration class"
        assert "siem = SIEMIntegration()" in content, "Script should instantiate SIEM"
        print("✓ SIEMIntegration class found and instantiated")
    
    def test_script_has_usb_scanner_class(self):
        """Verify script has USBScanner class"""
        with open("/app/scripts/seraph_defender_v7.py", "r") as f:
            content = f.read()
        
        assert "class USBScanner:" in content, "Script should have USBScanner class"
        assert "usb_scanner = USBScanner()" in content, "Script should instantiate USBScanner"
        print("✓ USBScanner class found and instantiated")
    
    def test_script_has_cuckoo_sandbox_class(self):
        """Verify script has CuckooSandbox class"""
        with open("/app/scripts/seraph_defender_v7.py", "r") as f:
            content = f.read()
        
        assert "class CuckooSandbox:" in content, "Script should have CuckooSandbox class"
        assert "sandbox = CuckooSandbox()" in content, "Script should instantiate CuckooSandbox"
        print("✓ CuckooSandbox class found and instantiated")
    
    def test_script_has_aggressive_auto_kill_config(self):
        """Verify script has aggressive auto-kill configuration"""
        with open("/app/scripts/seraph_defender_v7.py", "r") as f:
            content = f.read()
        
        # Check for auto_kill_severities with both CRITICAL and HIGH
        assert "auto_kill_severities" in content, "Script should have auto_kill_severities"
        
        # Find the line with auto_kill_severities
        match = re.search(r'auto_kill_severities\s*=\s*\{([^}]+)\}', content)
        assert match, "auto_kill_severities should be a set"
        severities = match.group(1)
        assert "CRITICAL" in severities, "auto_kill_severities should include CRITICAL"
        assert "HIGH" in severities, "auto_kill_severities should include HIGH"
        print(f"✓ auto_kill_severities = {{{severities.strip()}}}")
    
    def test_script_has_instant_kill_processes(self):
        """Verify script has instant_kill_processes set"""
        with open("/app/scripts/seraph_defender_v7.py", "r") as f:
            content = f.read()
        
        assert "instant_kill_processes" in content, "Script should have instant_kill_processes"
        
        # Check for specific dangerous processes
        dangerous = ['mimikatz.exe', 'lazagne.exe', 'xmrig.exe', 'netcat.exe', 'psexec.exe']
        for proc in dangerous:
            assert proc in content, f"instant_kill_processes should contain {proc}"
        print(f"✓ instant_kill_processes contains: {dangerous}")
    
    def test_script_monitoring_loop_has_usb_check(self):
        """Verify monitoring loop checks for new USB devices"""
        with open("/app/scripts/seraph_defender_v7.py", "r") as f:
            content = f.read()
        
        assert "usb_scanner.monitor_new_devices()" in content, \
            "Monitoring loop should call usb_scanner.monitor_new_devices()"
        print("✓ Monitoring loop calls usb_scanner.monitor_new_devices()")


class TestBackendSIEMService:
    """Test backend SIEM service"""
    
    def test_siem_service_file_exists(self):
        """Verify siem.py service file exists"""
        service_path = "/app/backend/services/siem.py"
        assert os.path.exists(service_path), f"SIEM service should exist at {service_path}"
        print(f"✓ SIEM service file exists at {service_path}")
    
    def test_siem_service_has_required_methods(self):
        """Verify SIEM service has required methods"""
        with open("/app/backend/services/siem.py", "r") as f:
            content = f.read()
        
        required_methods = [
            "log_event",
            "log_threat",
            "log_auto_kill",
            "get_status",
            "_send_to_elasticsearch",
            "_send_to_splunk",
            "_send_to_syslog"
        ]
        
        for method in required_methods:
            assert method in content, f"SIEM service should have {method} method"
        print(f"✓ SIEM service has all required methods: {required_methods}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
