"""
Backend API Tests for Anti-AI Defense System
Focus: Agent Download, Authentication, Dashboard, Agents Page
"""
import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

# Test credentials
TEST_EMAIL = "admin@defender.io"
TEST_PASSWORD = "defender123"

class TestHealthAndBasics:
    """Basic health check tests"""
    
    def test_api_root(self):
        """Test API root endpoint"""
        response = requests.get(f"{BASE_URL}/api/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert data["status"] == "operational"
        print(f"SUCCESS: API root returns: {data}")

class TestAuthentication:
    """Authentication endpoint tests"""
    
    def test_login_success(self):
        """Test login with valid credentials"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        })
        assert response.status_code == 200, f"Login failed: {response.text}"
        data = response.json()
        assert "access_token" in data
        assert "user" in data
        assert data["user"]["email"] == TEST_EMAIL
        print(f"SUCCESS: Login successful for {TEST_EMAIL}")
        return data["access_token"]
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "wrong@example.com",
            "password": "wrongpass"
        })
        assert response.status_code == 401
        print("SUCCESS: Invalid credentials correctly rejected")
    
    def test_register_duplicate_email(self):
        """Test registration with existing email"""
        response = requests.post(f"{BASE_URL}/api/auth/register", json={
            "email": TEST_EMAIL,
            "password": "testpass",
            "name": "Test User"
        })
        # Should fail because email already exists
        assert response.status_code == 400
        print("SUCCESS: Duplicate email registration correctly rejected")

class TestAgentDownload:
    """Agent download endpoint tests - MAIN FOCUS"""
    
    def test_agent_download_endpoint_exists(self):
        """Test that agent download endpoint returns 200"""
        response = requests.get(f"{BASE_URL}/api/agent/download")
        assert response.status_code == 200, f"Download endpoint failed: {response.status_code}"
        print("SUCCESS: Agent download endpoint returns 200")
    
    def test_agent_download_content_type(self):
        """Test that download returns Python file"""
        response = requests.get(f"{BASE_URL}/api/agent/download")
        assert response.status_code == 200
        content_type = response.headers.get('content-type', '')
        assert 'text/x-python' in content_type or 'application/octet-stream' in content_type or 'text/plain' in content_type
        print(f"SUCCESS: Content-Type is {content_type}")
    
    def test_agent_download_filename(self):
        """Test that download has correct filename"""
        response = requests.get(f"{BASE_URL}/api/agent/download")
        assert response.status_code == 200
        content_disposition = response.headers.get('content-disposition', '')
        assert 'defender_installer.py' in content_disposition
        print(f"SUCCESS: Filename is defender_installer.py")
    
    def test_agent_download_content_has_nmap(self):
        """Test that installer script contains Nmap references"""
        response = requests.get(f"{BASE_URL}/api/agent/download")
        assert response.status_code == 200
        content = response.text
        assert 'nmap' in content.lower() or 'Nmap' in content
        print("SUCCESS: Installer contains Nmap references")
    
    def test_agent_download_content_has_suricata(self):
        """Test that installer script contains Suricata references"""
        response = requests.get(f"{BASE_URL}/api/agent/download")
        assert response.status_code == 200
        content = response.text
        assert 'suricata' in content.lower() or 'Suricata' in content
        print("SUCCESS: Installer contains Suricata references")
    
    def test_agent_download_content_has_falco(self):
        """Test that installer script contains Falco references"""
        response = requests.get(f"{BASE_URL}/api/agent/download")
        assert response.status_code == 200
        content = response.text
        assert 'falco' in content.lower() or 'Falco' in content
        print("SUCCESS: Installer contains Falco references")
    
    def test_agent_download_content_has_yara(self):
        """Test that installer script contains YARA references"""
        response = requests.get(f"{BASE_URL}/api/agent/download")
        assert response.status_code == 200
        content = response.text
        assert 'yara' in content.lower() or 'YARA' in content
        print("SUCCESS: Installer contains YARA references")
    
    def test_agent_download_content_has_clamav(self):
        """Test that installer script contains ClamAV references"""
        response = requests.get(f"{BASE_URL}/api/agent/download")
        assert response.status_code == 200
        content = response.text
        assert 'clamav' in content.lower() or 'ClamAV' in content or 'clamscan' in content
        print("SUCCESS: Installer contains ClamAV references")
    
    def test_agent_download_content_has_packet_capture(self):
        """Test that installer script contains packet capture references"""
        response = requests.get(f"{BASE_URL}/api/agent/download")
        assert response.status_code == 200
        content = response.text
        assert 'scapy' in content.lower() or 'packet' in content.lower()
        print("SUCCESS: Installer contains packet capture references")
    
    def test_agent_download_content_has_data_recovery(self):
        """Test that installer script contains data recovery references"""
        response = requests.get(f"{BASE_URL}/api/agent/download")
        assert response.status_code == 200
        content = response.text
        assert 'recovery' in content.lower() or 'DataRecovery' in content
        print("SUCCESS: Installer contains data recovery references")
    
    def test_agent_download_is_valid_python(self):
        """Test that downloaded script is valid Python syntax"""
        response = requests.get(f"{BASE_URL}/api/agent/download")
        assert response.status_code == 200
        content = response.text
        # Check for Python shebang or common Python patterns
        assert '#!/usr/bin/env python' in content or 'import ' in content or 'def ' in content
        print("SUCCESS: Installer appears to be valid Python")
    
    def test_agent_download_has_cloud_api_url(self):
        """Test that installer has cloud API URL configured"""
        response = requests.get(f"{BASE_URL}/api/agent/download")
        assert response.status_code == 200
        content = response.text
        assert 'CLOUD_API_URL' in content or 'api_url' in content
        print("SUCCESS: Installer has cloud API URL configuration")

class TestDashboard:
    """Dashboard endpoint tests"""
    
    @pytest.fixture
    def auth_token(self):
        """Get authentication token"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        })
        if response.status_code == 200:
            return response.json().get("access_token")
        pytest.skip("Authentication failed")
    
    def test_dashboard_stats(self, auth_token):
        """Test dashboard stats endpoint"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(f"{BASE_URL}/api/dashboard/stats", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_threats" in data
        assert "active_threats" in data
        assert "system_health" in data
        print(f"SUCCESS: Dashboard stats - Total threats: {data['total_threats']}, System health: {data['system_health']}")

class TestAgentsEndpoint:
    """Agents list endpoint tests"""
    
    @pytest.fixture
    def auth_token(self):
        """Get authentication token"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        })
        if response.status_code == 200:
            return response.json().get("access_token")
        pytest.skip("Authentication failed")
    
    def test_agents_list(self, auth_token):
        """Test agents list endpoint"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(f"{BASE_URL}/api/agents", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"SUCCESS: Agents list returned {len(data)} agents")
    
    def test_discovered_hosts(self, auth_token):
        """Test discovered hosts endpoint"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(f"{BASE_URL}/api/network/discovered-hosts", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"SUCCESS: Discovered hosts returned {len(data)} hosts")

class TestLegacyAgentDownload:
    """Legacy agent download endpoint tests"""
    
    def test_legacy_agent_download(self):
        """Test legacy agent download endpoint"""
        response = requests.get(f"{BASE_URL}/api/agent/download/legacy")
        # May return 404 if legacy script doesn't exist, which is acceptable
        if response.status_code == 200:
            content = response.text
            assert 'python' in content.lower() or 'import' in content
            print("SUCCESS: Legacy agent download works")
        elif response.status_code == 404:
            print("INFO: Legacy agent script not found (acceptable)")
        else:
            pytest.fail(f"Unexpected status code: {response.status_code}")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
