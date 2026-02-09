import requests
import sys
import json
from datetime import datetime

class AntiAIDefenseAPITester:
    def __init__(self, base_url="https://aidefender-21.preview.emergentagent.com/api"):
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
            ("AI Analysis (GPT-5.2)", self.test_ai_analysis),
            ("AI Analyses History", self.test_ai_analyses_history)
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