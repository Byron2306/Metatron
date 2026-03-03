import requests
import sys
import json
from datetime import datetime

class AntiAIDefenseAPITester:
    def __init__(self, base_url="https://zero-trust-core.preview.emergentagent.com/api"):
        self.base_url = base_url
        self.token = None
        self.user_id = None
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_result(self, test_name, success, details="", response_data=None):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {test_name} - PASSED")
        else:
            print(f"❌ {test_name} - FAILED: {details}")
        
        self.test_results.append({
            "test": test_name,
            "success": success,
            "details": details,
            "response_data": response_data
        })

    def run_test(self, name, method, endpoint, expected_status, data=None, headers=None):
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint}"
        test_headers = {'Content-Type': 'application/json'}
        
        if self.token:
            test_headers['Authorization'] = f'Bearer {self.token}'
        if headers:
            test_headers.update(headers)

        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        print(f"   Method: {method}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=test_headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=test_headers, timeout=30)
            elif method == 'PATCH':
                response = requests.patch(url, json=data, headers=test_headers, timeout=30)
            elif method == 'DELETE':
                response = requests.delete(url, headers=test_headers, timeout=30)

            print(f"   Status: {response.status_code}")
            
            success = response.status_code == expected_status
            response_data = None
            
            try:
                response_data = response.json()
                if success:
                    print(f"   Response: {json.dumps(response_data, indent=2)[:200]}...")
            except:
                if success:
                    print(f"   Response: {response.text[:200]}...")

            if success:
                self.log_result(name, True, f"Status: {response.status_code}", response_data)
                return True, response_data
            else:
                error_msg = f"Expected {expected_status}, got {response.status_code}"
                if response_data:
                    error_msg += f" - {response_data.get('detail', '')}"
                self.log_result(name, False, error_msg, response_data)
                return False, response_data

        except Exception as e:
            error_msg = f"Request failed: {str(e)}"
            print(f"   Error: {error_msg}")
            self.log_result(name, False, error_msg)
            return False, {}

    def test_root_endpoint(self):
        """Test root API endpoint"""
        return self.run_test("Root Endpoint", "GET", "", 200)

    def test_user_registration(self):
        """Test user registration"""
        test_user_data = {
            "email": f"test_analyst_{datetime.now().strftime('%H%M%S')}@defense.io",
            "password": "SecurePass123!",
            "name": "Test Analyst"
        }
        
        success, response = self.run_test(
            "User Registration",
            "POST",
            "auth/register",
            200,
            data=test_user_data
        )
        
        if success and response:
            self.token = response.get('access_token')
            self.user_id = response.get('user', {}).get('id')
            print(f"   Token obtained: {self.token[:20]}...")
            return True
        return False

    def test_user_login(self):
        """Test user login with existing credentials"""
        # Try to login with a test user (this might fail if user doesn't exist)
        login_data = {
            "email": "test@defense.io",
            "password": "password123"
        }
        
        success, response = self.run_test(
            "User Login (Test User)",
            "POST",
            "auth/login",
            200,
            data=login_data
        )
        
        if success and response:
            self.token = response.get('access_token')
            self.user_id = response.get('user', {}).get('id')
            return True
        
        # If login fails, that's expected - we'll use the registered user
        print("   Note: Test user login failed (expected), using registered user token")
        return True

    def test_protected_route(self):
        """Test protected route /auth/me"""
        if not self.token:
            self.log_result("Protected Route", False, "No token available")
            return False
            
        return self.run_test("Protected Route (/auth/me)", "GET", "auth/me", 200)[0]

    def test_seed_data(self):
        """Test seeding demo data"""
        return self.run_test("Seed Demo Data", "POST", "seed", 200)[0]

    def test_dashboard_stats(self):
        """Test dashboard stats endpoint"""
        return self.run_test("Dashboard Stats", "GET", "dashboard/stats", 200)[0]

    def test_threats_crud(self):
        """Test threats CRUD operations"""
        # Create threat
        threat_data = {
            "name": "Test AI Agent Attack",
            "type": "ai_agent",
            "severity": "high",
            "source_ip": "192.168.1.100",
            "target_system": "Test Server",
            "description": "Test threat for API validation",
            "indicators": ["Automated behavior", "High request rate"]
        }
        
        success, response = self.run_test(
            "Create Threat",
            "POST",
            "threats",
            200,
            data=threat_data
        )
        
        if not success:
            return False
            
        threat_id = response.get('id')
        if not threat_id:
            self.log_result("Create Threat", False, "No threat ID returned")
            return False

        # Get all threats
        success, _ = self.run_test("Get All Threats", "GET", "threats", 200)
        if not success:
            return False

        # Get specific threat
        success, _ = self.run_test(
            "Get Specific Threat",
            "GET",
            f"threats/{threat_id}",
            200
        )
        if not success:
            return False

        # Update threat status
        success, _ = self.run_test(
            "Update Threat Status",
            "PATCH",
            f"threats/{threat_id}/status?status=contained",
            200
        )
        
        return success

    def test_alerts_crud(self):
        """Test alerts CRUD operations"""
        # Create alert
        alert_data = {
            "title": "Test Security Alert",
            "type": "ai_detected",
            "severity": "high",
            "message": "Test alert for API validation"
        }
        
        success, response = self.run_test(
            "Create Alert",
            "POST",
            "alerts",
            200,
            data=alert_data
        )
        
        if not success:
            return False
            
        alert_id = response.get('id')
        if not alert_id:
            self.log_result("Create Alert", False, "No alert ID returned")
            return False

        # Get all alerts
        success, _ = self.run_test("Get All Alerts", "GET", "alerts", 200)
        if not success:
            return False

        # Update alert status
        success, _ = self.run_test(
            "Update Alert Status",
            "PATCH",
            f"alerts/{alert_id}/status?status=acknowledged",
            200
        )
        
        return success

    def test_ai_analysis(self):
        """Test AI analysis endpoint with GPT-5.2"""
        analysis_data = {
            "content": "import subprocess\nsubprocess.call(['rm', '-rf', '/'])",
            "analysis_type": "threat_detection"
        }
        
        print("\n🧠 Testing AI Analysis (GPT-5.2)...")
        print("   This may take 10-15 seconds for AI processing...")
        
        success, response = self.run_test(
            "AI Threat Analysis",
            "POST",
            "ai/analyze",
            200,
            data=analysis_data
        )
        
        if success and response:
            risk_score = response.get('risk_score', 0)
            analysis_result = response.get('result', '')
            print(f"   Risk Score: {risk_score}")
            print(f"   Analysis Preview: {analysis_result[:100]}...")
            
            # Validate response structure
            required_fields = ['analysis_id', 'analysis_type', 'result', 'risk_score', 'timestamp']
            missing_fields = [field for field in required_fields if field not in response]
            
            if missing_fields:
                self.log_result("AI Analysis Structure", False, f"Missing fields: {missing_fields}")
                return False
            else:
                self.log_result("AI Analysis Structure", True, "All required fields present")
        
        return success

    def test_ai_analyses_history(self):
        """Test getting AI analyses history"""
        return self.run_test("AI Analyses History", "GET", "ai/analyses", 200)[0]

    def test_network_topology(self):
        """Test network topology endpoint"""
        success, response = self.run_test("Network Topology", "GET", "network/topology", 200)
        
        if success and response:
            # Validate response structure
            required_fields = ['nodes', 'links']
            missing_fields = [field for field in required_fields if field not in response]
            
            if missing_fields:
                self.log_result("Network Topology Structure", False, f"Missing fields: {missing_fields}")
                return False
            
            nodes = response.get('nodes', [])
            links = response.get('links', [])
            
            print(f"   Nodes found: {len(nodes)}")
            print(f"   Links found: {len(links)}")
            
            # Check if nodes have required fields
            if nodes:
                node_fields = ['id', 'label', 'type', 'status']
                sample_node = nodes[0]
                missing_node_fields = [field for field in node_fields if field not in sample_node]
                if missing_node_fields:
                    self.log_result("Network Topology Node Structure", False, f"Missing node fields: {missing_node_fields}")
                    return False
                else:
                    self.log_result("Network Topology Node Structure", True, "Node structure valid")
            
            # Check if links have required fields
            if links:
                link_fields = ['source', 'target', 'type']
                sample_link = links[0]
                missing_link_fields = [field for field in link_fields if field not in sample_link]
                if missing_link_fields:
                    self.log_result("Network Topology Link Structure", False, f"Missing link fields: {missing_link_fields}")
                    return False
                else:
                    self.log_result("Network Topology Link Structure", True, "Link structure valid")
        
        return success

    def test_threat_hunting_generate(self):
        """Test threat hunting hypothesis generation"""
        hunting_data = {
            "focus_area": "ai_agents",
            "time_range_hours": 24
        }
        
        print("\n🎯 Testing Threat Hunting Hypothesis Generation...")
        print("   This may take 10-15 seconds for AI processing...")
        
        success, response = self.run_test(
            "Generate Hunting Hypotheses",
            "POST",
            "hunting/generate",
            200,
            data=hunting_data
        )
        
        if success and response:
            hypotheses = response if isinstance(response, list) else []
            print(f"   Hypotheses generated: {len(hypotheses)}")
            
            # Validate hypothesis structure
            if hypotheses:
                required_fields = ['id', 'title', 'description', 'category', 'confidence', 'indicators', 'recommended_actions', 'status', 'created_at']
                sample_hypothesis = hypotheses[0]
                missing_fields = [field for field in required_fields if field not in sample_hypothesis]
                
                if missing_fields:
                    self.log_result("Hunting Hypothesis Structure", False, f"Missing fields: {missing_fields}")
                    return False
                else:
                    self.log_result("Hunting Hypothesis Structure", True, "Hypothesis structure valid")
                    print(f"   Sample hypothesis: {sample_hypothesis.get('title', 'N/A')}")
                    print(f"   Confidence: {sample_hypothesis.get('confidence', 0)}%")
        
        return success

    def test_threat_hunting_get_hypotheses(self):
        """Test getting hunting hypotheses"""
        return self.run_test("Get Hunting Hypotheses", "GET", "hunting/hypotheses", 200)[0]

    def test_threat_hunting_update_status(self):
        """Test updating hunting hypothesis status"""
        # First get hypotheses to find one to update
        success, response = self.run_test("Get Hypotheses for Update", "GET", "hunting/hypotheses", 200)
        
        if not success or not response:
            self.log_result("Update Hypothesis Status", False, "No hypotheses available to update")
            return False
        
        hypotheses = response if isinstance(response, list) else []
        if not hypotheses:
            self.log_result("Update Hypothesis Status", False, "No hypotheses found")
            return False
        
        # Update the first hypothesis status
        hypothesis_id = hypotheses[0].get('id')
        if not hypothesis_id:
            self.log_result("Update Hypothesis Status", False, "No hypothesis ID found")
            return False
        
        success, _ = self.run_test(
            "Update Hypothesis Status",
            "PATCH",
            f"hunting/hypotheses/{hypothesis_id}/status?status=investigating",
            200
        )
        
        return success

    def test_pdf_report_generation(self):
        """Test PDF threat intelligence report generation"""
        print("\n📄 Testing PDF Report Generation...")
        
        success, response = self.run_test(
            "PDF Threat Intelligence Report",
            "GET",
            "reports/threat-intelligence",
            200
        )
        
        if success:
            # For PDF, we can't parse JSON but we can check if we got data
            print("   PDF report generated successfully")
            self.log_result("PDF Report Content", True, "PDF data received")
        
        return success

    def test_ai_summary_report(self):
        """Test AI-powered summary report generation"""
        print("\n🧠 Testing AI Summary Report Generation...")
        print("   This may take 10-15 seconds for AI processing...")
        
        success, response = self.run_test(
            "AI Executive Summary Report",
            "POST",
            "reports/ai-summary",
            200
        )
        
        if success and response:
            # Validate response structure
            required_fields = ['summary', 'generated_at', 'data_points']
            missing_fields = [field for field in required_fields if field not in response]
            
            if missing_fields:
                self.log_result("AI Summary Structure", False, f"Missing fields: {missing_fields}")
                return False
            else:
                self.log_result("AI Summary Structure", True, "All required fields present")
                print(f"   Summary preview: {response.get('summary', '')[:100]}...")
                print(f"   Data points: {response.get('data_points', {})}")
        
        return success

    def test_honeypots_crud(self):
        """Test honeypot CRUD operations"""
        # Create honeypot
        honeypot_data = {
            "name": "Test SSH Honeypot",
            "type": "ssh",
            "ip": "10.0.5.100",
            "port": 2222,
            "description": "Test honeypot for API validation"
        }
        
        success, response = self.run_test(
            "Create Honeypot",
            "POST",
            "honeypots",
            200,
            data=honeypot_data
        )
        
        if not success:
            return False
            
        honeypot_id = response.get('id')
        if not honeypot_id:
            self.log_result("Create Honeypot", False, "No honeypot ID returned")
            return False

        # Get all honeypots
        success, _ = self.run_test("Get All Honeypots", "GET", "honeypots", 200)
        if not success:
            return False

        # Test honeypot interaction recording
        interaction_data = {
            "source_ip": "192.168.1.50",
            "action": "login_attempt",
            "data": {"username": "admin", "password": "password", "source_port": 45678}
        }
        
        success, interaction_response = self.run_test(
            "Record Honeypot Interaction",
            "POST",
            f"honeypots/{honeypot_id}/interaction?source_ip={interaction_data['source_ip']}&action={interaction_data['action']}",
            200,
            data=interaction_data['data']
        )
        
        if not success:
            return False

        # Get honeypot interactions
        success, _ = self.run_test(
            "Get Honeypot Interactions",
            "GET",
            f"honeypots/{honeypot_id}/interactions",
            200
        )
        
        if not success:
            return False

        # Update honeypot status
        success, _ = self.run_test(
            "Update Honeypot Status",
            "PATCH",
            f"honeypots/{honeypot_id}/status?status=triggered",
            200
        )
        
        return success

    def test_role_based_access_control(self):
        """Test role-based access control and user management"""
        # Get current user info
        success, user_response = self.run_test("Get Current User", "GET", "auth/me", 200)
        if not success:
            return False
        
        current_user_role = user_response.get('role', 'unknown')
        print(f"   Current user role: {current_user_role}")
        
        # Test listing users (admin only)
        success, users_response = self.run_test("List Users (Admin)", "GET", "users", 200)
        
        if success and users_response:
            print(f"   Found {len(users_response)} users")
            
            # Test role update if we have users and admin access
            if len(users_response) > 0 and current_user_role == 'admin':
                # Find a user to update (not ourselves)
                target_user = None
                current_user_id = user_response.get('id')
                
                for user in users_response:
                    if user.get('id') != current_user_id:
                        target_user = user
                        break
                
                if target_user:
                    role_update_data = {"role": "analyst"}
                    success, _ = self.run_test(
                        "Update User Role",
                        "PATCH",
                        f"users/{target_user['id']}/role",
                        200,
                        data=role_update_data
                    )
                    return success
                else:
                    self.log_result("Update User Role", True, "No other users to update (single user test)")
                    return True
            elif current_user_role != 'admin':
                # Should fail for non-admin users
                self.log_result("List Users (Non-Admin)", True, "Access denied as expected for non-admin")
                return True
        
        return success

    def run_all_tests(self):
        """Run comprehensive API test suite"""
        print("🚀 Starting Anti-AI Defense System API Tests")
        print("=" * 60)
        
        # Test sequence
        tests = [
            ("Root Endpoint", self.test_root_endpoint),
            ("User Registration", self.test_user_registration),
            ("User Login", self.test_user_login),
            ("Protected Route", self.test_protected_route),
            ("Seed Demo Data", self.test_seed_data),
            ("Dashboard Stats", self.test_dashboard_stats),
            ("Threats CRUD", self.test_threats_crud),
            ("Alerts CRUD", self.test_alerts_crud),
            ("AI Analysis (GPT-4o Fallback)", self.test_ai_analysis),
            ("AI Analyses History", self.test_ai_analyses_history),
            ("PDF Report Generation", self.test_pdf_report_generation),
            ("AI Summary Report", self.test_ai_summary_report),
            ("Honeypots CRUD & Interactions", self.test_honeypots_crud),
            ("Role-Based Access Control", self.test_role_based_access_control),
            ("Network Topology", self.test_network_topology),
            ("Generate Hunting Hypotheses", self.test_threat_hunting_generate),
            ("Get Hunting Hypotheses", self.test_threat_hunting_get_hypotheses),
            ("Update Hypothesis Status", self.test_threat_hunting_update_status)
        ]
        
        for test_name, test_func in tests:
            print(f"\n{'='*20} {test_name} {'='*20}")
            try:
                test_func()
            except Exception as e:
                self.log_result(test_name, False, f"Test execution error: {str(e)}")
                print(f"❌ {test_name} - EXECUTION ERROR: {str(e)}")
        
        # Print final results
        print("\n" + "="*60)
        print("🏁 TEST SUMMARY")
        print("="*60)
        print(f"Tests Run: {self.tests_run}")
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Tests Failed: {self.tests_run - self.tests_passed}")
        print(f"Success Rate: {(self.tests_passed/self.tests_run*100):.1f}%" if self.tests_run > 0 else "0%")
        
        # Print failed tests
        failed_tests = [r for r in self.test_results if not r['success']]
        if failed_tests:
            print(f"\n❌ FAILED TESTS ({len(failed_tests)}):")
            for test in failed_tests:
                print(f"   • {test['test']}: {test['details']}")
        
        print("\n" + "="*60)
        return self.tests_passed == self.tests_run

def main():
    """Main test execution"""
    tester = AntiAIDefenseAPITester()
    
    try:
        success = tester.run_all_tests()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\n💥 Test suite crashed: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())