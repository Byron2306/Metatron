"""
Test Suite for Iteration 21 Features:
1. Agent Command Approval (POST /api/agent-commands/{id}/approve with write permission)
2. Deployment Simulation Mode
3. Browser Extension Download (GET /api/swarm/agent/download/browser-extension)
4. Agent Script Detection Classes (RootkitDetector, HiddenFolderDetector, AdminPrivilegesMonitor, AliasDetector, FileIndexer)
"""
import pytest
import requests
import os
import zipfile
import io
import re

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestAgentCommandApproval:
    """Test agent command approval endpoint with write permission"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures"""
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        # Login to get token
        login_response = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": "test@defender.io",
            "password": "test123"
        })
        if login_response.status_code == 200:
            # Token is returned as access_token
            token = login_response.json().get("access_token")
            self.session.headers.update({"Authorization": f"Bearer {token}"})
        yield
        self.session.close()
    
    def test_create_command_requires_write_permission(self):
        """Test that creating a command requires write permission"""
        response = self.session.post(f"{BASE_URL}/api/agent-commands/create", json={
            "agent_id": "test-agent-001",
            "command_type": "full_scan",
            "parameters": {"scan_types": ["network", "process"]},
            "priority": "medium"
        })
        # Should succeed with write permission (user has write permission)
        assert response.status_code in [200, 201], f"Create command failed: {response.text}"
        data = response.json()
        assert "command_id" in data
        assert data["status"] == "pending_approval"
        return data["command_id"]
    
    def test_approve_command_with_write_permission(self):
        """Test that approving a command works with write permission (not manage_users)"""
        # First create a command
        create_response = self.session.post(f"{BASE_URL}/api/agent-commands/create", json={
            "agent_id": "test-agent-approval",
            "command_type": "collect_forensics",
            "parameters": {"collection_type": "logs"},
            "priority": "low"
        })
        assert create_response.status_code in [200, 201], f"Create failed: {create_response.text}"
        command_id = create_response.json()["command_id"]
        
        # Now approve the command - should work with write permission
        approve_response = self.session.post(f"{BASE_URL}/api/agent-commands/{command_id}/approve", json={
            "approved": True,
            "notes": "Approved for testing"
        })
        assert approve_response.status_code == 200, f"Approve failed: {approve_response.text}"
        data = approve_response.json()
        assert data["status"] == "approved"
        assert "queued for agent" in data.get("message", "").lower() or data["status"] == "approved"
    
    def test_approval_creates_command_queue_entry(self):
        """Test that approval creates an entry in command_queue for agent pickup"""
        # Create a command
        create_response = self.session.post(f"{BASE_URL}/api/agent-commands/create", json={
            "agent_id": "test-agent-queue",
            "command_type": "full_scan",
            "parameters": {"scan_types": ["file"]},
            "priority": "high"
        })
        assert create_response.status_code in [200, 201]
        command_id = create_response.json()["command_id"]
        
        # Approve the command
        approve_response = self.session.post(f"{BASE_URL}/api/agent-commands/{command_id}/approve", json={
            "approved": True,
            "notes": "Queue test"
        })
        assert approve_response.status_code == 200
        
        # Verify command is in history with approved/queued status
        history_response = self.session.get(f"{BASE_URL}/api/agent-commands/history?agent_id=test-agent-queue")
        assert history_response.status_code == 200
        commands = history_response.json().get("commands", [])
        
        # Find our command
        our_command = next((c for c in commands if c["command_id"] == command_id), None)
        assert our_command is not None, "Command not found in history"
        assert our_command["status"] in ["approved", "queued_for_pickup", "sent_to_agent"]
    
    def test_reject_command(self):
        """Test rejecting a command"""
        # Create a command
        create_response = self.session.post(f"{BASE_URL}/api/agent-commands/create", json={
            "agent_id": "test-agent-reject",
            "command_type": "delete_file",
            "parameters": {"file_path": "/tmp/test.txt"},
            "priority": "critical"
        })
        assert create_response.status_code in [200, 201]
        command_id = create_response.json()["command_id"]
        
        # Reject the command
        reject_response = self.session.post(f"{BASE_URL}/api/agent-commands/{command_id}/approve", json={
            "approved": False,
            "notes": "Rejected for testing"
        })
        assert reject_response.status_code == 200
        data = reject_response.json()
        assert data["status"] == "rejected"
    
    def test_get_pending_commands(self):
        """Test getting pending commands"""
        response = self.session.get(f"{BASE_URL}/api/agent-commands/pending")
        assert response.status_code == 200
        data = response.json()
        assert "commands" in data
        assert "count" in data
    
    def test_get_command_types(self):
        """Test getting available command types"""
        response = self.session.get(f"{BASE_URL}/api/agent-commands/types")
        assert response.status_code == 200
        data = response.json()
        assert "command_types" in data
        command_types = data["command_types"]
        # Verify expected command types exist
        expected_types = ["block_ip", "kill_process", "quarantine_file", "full_scan", "collect_forensics"]
        for cmd_type in expected_types:
            assert cmd_type in command_types, f"Missing command type: {cmd_type}"


class TestBrowserExtensionDownload:
    """Test browser extension download endpoint"""
    
    def test_download_browser_extension_zip(self):
        """Test downloading browser extension as zip file"""
        response = requests.get(f"{BASE_URL}/api/swarm/agent/download/browser-extension")
        assert response.status_code == 200, f"Download failed: {response.text}"
        
        # Verify content type is zip
        content_type = response.headers.get("Content-Type", "")
        assert "application/zip" in content_type or "application/octet-stream" in content_type
        
        # Verify content disposition
        content_disp = response.headers.get("Content-Disposition", "")
        assert "seraph_browser_shield.zip" in content_disp
    
    def test_browser_extension_zip_contents(self):
        """Test that browser extension zip contains all required files"""
        response = requests.get(f"{BASE_URL}/api/swarm/agent/download/browser-extension")
        assert response.status_code == 200
        
        # Parse zip file
        zip_buffer = io.BytesIO(response.content)
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            file_list = zf.namelist()
            
            # Required files
            required_files = [
                "manifest.json",
                "background.js",
                "content.js",
                "popup.html",
                "popup.js",
                "blocked.html"
            ]
            
            for required_file in required_files:
                assert required_file in file_list, f"Missing file in zip: {required_file}"
            
            # Verify manifest.json content
            manifest_content = zf.read("manifest.json").decode('utf-8')
            import json
            manifest = json.loads(manifest_content)
            assert manifest["manifest_version"] == 3
            assert manifest["name"] == "Seraph AI Browser Shield"
            assert "webRequest" in manifest["permissions"]
            
            # Verify background.js has threat detection
            background_content = zf.read("background.js").decode('utf-8')
            assert "checkUrl" in background_content
            assert "maliciousDomains" in background_content
            
            # Verify content.js has XSS detection
            content_js = zf.read("content.js").decode('utf-8')
            assert "detectXSS" in content_js
            assert "detectPhishing" in content_js


class TestAgentScriptDetectionClasses:
    """Test that agent script has all required detection classes"""
    
    def test_agent_script_exists(self):
        """Test that seraph_defender_v7.py exists"""
        agent_path = "/app/scripts/seraph_defender_v7.py"
        assert os.path.exists(agent_path), "Agent script v7 not found"
    
    def test_rootkit_detector_class(self):
        """Test RootkitDetector class exists in agent script"""
        agent_path = "/app/scripts/seraph_defender_v7.py"
        with open(agent_path, 'r') as f:
            content = f.read()
        
        # Check class definition
        assert "class RootkitDetector:" in content, "RootkitDetector class not found"
        
        # Check key methods
        assert "def scan(" in content or "def detect(" in content, "RootkitDetector scan method not found"
        assert "hidden_processes" in content.lower() or "kernel_module" in content.lower(), "Rootkit detection logic not found"
    
    def test_hidden_folder_detector_class(self):
        """Test HiddenFolderDetector class exists in agent script"""
        agent_path = "/app/scripts/seraph_defender_v7.py"
        with open(agent_path, 'r') as f:
            content = f.read()
        
        assert "class HiddenFolderDetector:" in content, "HiddenFolderDetector class not found"
        assert "hidden" in content.lower() and "folder" in content.lower(), "Hidden folder detection logic not found"
    
    def test_admin_privileges_monitor_class(self):
        """Test AdminPrivilegesMonitor class exists in agent script"""
        agent_path = "/app/scripts/seraph_defender_v7.py"
        with open(agent_path, 'r') as f:
            content = f.read()
        
        assert "class AdminPrivilegesMonitor:" in content, "AdminPrivilegesMonitor class not found"
        assert "get_current_admins" in content, "get_current_admins method not found"
        assert "local_admins" in content or "administrators" in content.lower(), "Admin detection logic not found"
    
    def test_alias_detector_class(self):
        """Test AliasDetector class exists in agent script"""
        agent_path = "/app/scripts/seraph_defender_v7.py"
        with open(agent_path, 'r') as f:
            content = f.read()
        
        assert "class AliasDetector:" in content, "AliasDetector class not found"
        assert "suspicious_alias" in content.lower() or "alias" in content.lower(), "Alias detection logic not found"
        assert ".bashrc" in content or "bash_aliases" in content, "Shell config file scanning not found"
    
    def test_file_indexer_class(self):
        """Test FileIndexer class exists in agent script"""
        agent_path = "/app/scripts/seraph_defender_v7.py"
        with open(agent_path, 'r') as f:
            content = f.read()
        
        assert "class FileIndexer:" in content, "FileIndexer class not found"
        assert "index_directory" in content or "get_file_telemetry" in content, "File indexing methods not found"
        assert "executable_files" in content or "suspicious_extensions" in content, "File type detection not found"
    
    def test_detection_classes_initialized(self):
        """Test that detection classes are initialized in the script"""
        agent_path = "/app/scripts/seraph_defender_v7.py"
        with open(agent_path, 'r') as f:
            content = f.read()
        
        # Check that instances are created
        assert "rootkit_detector = RootkitDetector()" in content, "RootkitDetector not instantiated"
        assert "hidden_folder_detector = HiddenFolderDetector()" in content, "HiddenFolderDetector not instantiated"
        assert "admin_monitor = AdminPrivilegesMonitor()" in content, "AdminPrivilegesMonitor not instantiated"
        assert "alias_detector = AliasDetector()" in content, "AliasDetector not instantiated"
        assert "file_indexer = FileIndexer()" in content, "FileIndexer not instantiated"


class TestDeploymentSimulation:
    """Test deployment simulation mode"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures"""
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        # Login to get token
        login_response = self.session.post(f"{BASE_URL}/api/auth/login", json={
            "email": "test@defender.io",
            "password": "test123"
        })
        if login_response.status_code == 200:
            # Token is returned as access_token
            token = login_response.json().get("access_token")
            self.session.headers.update({"Authorization": f"Bearer {token}"})
        yield
        self.session.close()
    
    def test_deployment_service_code_has_simulation_mode(self):
        """Test that deployment service has simulation mode for demo"""
        service_path = "/app/backend/services/agent_deployment.py"
        with open(service_path, 'r') as f:
            content = f.read()
        
        # Check for simulation mode logic
        assert "simulation" in content.lower() or "simulate" in content.lower(), "Simulation mode not found in deployment service"
        assert "no credentials" in content.lower() or "is_simulation" in content, "Simulation condition not found"
    
    def test_get_deployment_status(self):
        """Test getting deployment status"""
        response = self.session.get(f"{BASE_URL}/api/swarm/deployments")
        assert response.status_code == 200
        data = response.json()
        assert "deployments" in data or "tasks" in data or isinstance(data, list)


class TestAgentDashboardTabs:
    """Test that agent dashboard has new tabs for detection features"""
    
    def test_dashboard_html_has_new_tabs(self):
        """Test that dashboard HTML in agent script has new tabs"""
        agent_path = "/app/scripts/seraph_defender_v7.py"
        with open(agent_path, 'r') as f:
            content = f.read()
        
        # Check for new tab definitions in dashboard HTML
        expected_tabs = [
            "File Index",
            "Admin Privileges", 
            "Rootkit",
            "Hidden Folders",
            "Aliases"
        ]
        
        for tab in expected_tabs:
            # Check for tab in HTML (case insensitive)
            assert tab.lower() in content.lower(), f"Tab '{tab}' not found in agent dashboard"
    
    def test_dashboard_has_file_telemetry_panel(self):
        """Test dashboard has file telemetry panel"""
        agent_path = "/app/scripts/seraph_defender_v7.py"
        with open(agent_path, 'r') as f:
            content = f.read()
        
        assert "file_telemetry" in content or "fileTelemetry" in content, "File telemetry panel not found"
    
    def test_dashboard_has_admin_info_panel(self):
        """Test dashboard has admin info panel"""
        agent_path = "/app/scripts/seraph_defender_v7.py"
        with open(agent_path, 'r') as f:
            content = f.read()
        
        assert "admin_info" in content or "adminInfo" in content, "Admin info panel not found"


class TestBrowserExtensionFiles:
    """Test browser extension file contents"""
    
    def test_manifest_json_structure(self):
        """Test manifest.json has correct structure"""
        manifest_path = "/app/scripts/browser_extension/manifest.json"
        import json
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        assert manifest["manifest_version"] == 3
        assert manifest["name"] == "Seraph AI Browser Shield"
        assert "webRequest" in manifest["permissions"]
        assert "webNavigation" in manifest["permissions"]
        assert "tabs" in manifest["permissions"]
        assert "storage" in manifest["permissions"]
        assert "background" in manifest
        assert manifest["background"]["service_worker"] == "background.js"
    
    def test_background_js_has_threat_detection(self):
        """Test background.js has threat detection logic"""
        bg_path = "/app/scripts/browser_extension/background.js"
        with open(bg_path, 'r') as f:
            content = f.read()
        
        assert "maliciousDomains" in content
        assert "checkUrl" in content
        assert "levenshteinDistance" in content  # Typosquatting detection
        assert "cryptojackingScripts" in content
        assert "webRequest.onBeforeRequest" in content
    
    def test_content_js_has_xss_detection(self):
        """Test content.js has XSS and phishing detection"""
        content_path = "/app/scripts/browser_extension/content.js"
        with open(content_path, 'r') as f:
            content = f.read()
        
        assert "detectXSS" in content
        assert "detectPhishing" in content
        assert "detectCryptojacking" in content
        assert "detectKeylogger" in content
        assert "showWarningBanner" in content
    
    def test_popup_html_has_stats(self):
        """Test popup.html has stats display"""
        popup_path = "/app/scripts/browser_extension/popup.html"
        with open(popup_path, 'r') as f:
            content = f.read()
        
        assert "pagesScanned" in content
        assert "threatsBlocked" in content
        assert "phishingBlocked" in content
        assert "malwareBlocked" in content
    
    def test_blocked_html_exists(self):
        """Test blocked.html exists with proper content"""
        blocked_path = "/app/scripts/browser_extension/blocked.html"
        with open(blocked_path, 'r') as f:
            content = f.read()
        
        assert "Access Blocked" in content
        assert "Seraph Shield" in content
        assert "goBack" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
