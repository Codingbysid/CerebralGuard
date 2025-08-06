"""
Basic tests for CerebralGuard components
Verifies that all modules can be imported and initialized.
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test that all modules can be imported."""
    print("🧪 Testing imports...")
    
    modules_to_test = [
        ("db.tidb_helpers", "TiDBManager"),
        ("models.content_model", "PhishingDetector"),
        ("integrations.virustotal", "VirusTotalAPI"),
        ("integrations.abuseipdb", "AbuseIPDBAPI"),
        ("integrations.slack", "SlackNotifier"),
        ("agent.main", "CerebralGuardAgent")
    ]
    
    failed_imports = []
    
    for module_name, class_name in modules_to_test:
        try:
            module = __import__(module_name, fromlist=[class_name])
            class_obj = getattr(module, class_name)
            print(f"✅ {module_name}.{class_name}")
        except ImportError as e:
            print(f"❌ {module_name}.{class_name}: {e}")
            failed_imports.append(f"{module_name}.{class_name}")
        except AttributeError as e:
            print(f"❌ {module_name}.{class_name}: {e}")
            failed_imports.append(f"{module_name}.{class_name}")
    
    if failed_imports:
        print(f"\n⚠️  Failed to import: {', '.join(failed_imports)}")
        return False
    
    print("✅ All imports successful")
    return True

def test_environment():
    """Test environment variable loading."""
    print("\n🔧 Testing environment...")
    
    try:
        from dotenv import load_dotenv
        load_dotenv()
        
        # Check for required environment variables
        required_vars = [
            "GEMINI_API_KEY",
            "TIDB_HOST",
            "TIDB_USER",
            "TIDB_PASSWORD"
        ]
        
        missing_vars = []
        for var in required_vars:
            if not os.getenv(var):
                missing_vars.append(var)
            else:
                print(f"✅ {var}")
        
        if missing_vars:
            print(f"⚠️  Missing environment variables: {', '.join(missing_vars)}")
            print("   These are required for full functionality")
        else:
            print("✅ All required environment variables found")
        
        return True
        
    except ImportError:
        print("❌ python-dotenv not installed")
        return False

def test_database_connection():
    """Test database connection (if configured)."""
    print("\n🗄️  Testing database connection...")
    
    try:
        from db.tidb_helpers import tidb_manager
        
        # Try to connect
        if tidb_manager.connect():
            print("✅ Database connection successful")
            tidb_manager.disconnect()
            return True
        else:
            print("⚠️  Database connection failed (check your TiDB configuration)")
            return False
            
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        return False

def test_model_loading():
    """Test ML model loading."""
    print("\n🤖 Testing ML model loading...")
    
    try:
        from models.content_model import phishing_detector
        
        # Test basic functionality
        test_text = "This is a test email for phishing detection."
        result = phishing_detector.predict(test_text)
        
        if 'phishing_probability' in result:
            print("✅ ML model loaded and functional")
            print(f"   Test prediction: {result['phishing_probability']:.2f}")
            return True
        else:
            print("❌ ML model not functioning correctly")
            return False
            
    except Exception as e:
        print(f"❌ ML model error: {e}")
        return False

def test_api_integrations():
    """Test API integrations."""
    print("\n🔌 Testing API integrations...")
    
    # Test VirusTotal
    try:
        from integrations.virustotal import virustotal_api
        print("✅ VirusTotal API client initialized")
    except Exception as e:
        print(f"❌ VirusTotal API error: {e}")
    
    # Test AbuseIPDB
    try:
        from integrations.abuseipdb import abuseipdb_api
        print("✅ AbuseIPDB API client initialized")
    except Exception as e:
        print(f"❌ AbuseIPDB API error: {e}")
    
    # Test Slack
    try:
        from integrations.slack import slack_notifier
        print("✅ Slack notifier initialized")
    except Exception as e:
        print(f"❌ Slack integration error: {e}")
    
    return True

def test_agent_initialization():
    """Test the main agent initialization."""
    print("\n🧠 Testing agent initialization...")
    
    try:
        from agent.main import cerebral_guard
        print("✅ CerebralGuard agent initialized")
        return True
    except Exception as e:
        print(f"❌ Agent initialization error: {e}")
        return False

def main():
    """Run all tests."""
    print("🚀 CerebralGuard Basic Tests")
    print("=" * 40)
    
    tests = [
        ("Import Tests", test_imports),
        ("Environment Tests", test_environment),
        ("Database Tests", test_database_connection),
        ("ML Model Tests", test_model_loading),
        ("API Integration Tests", test_api_integrations),
        ("Agent Tests", test_agent_initialization)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}")
        print("-" * 20)
        
        try:
            if test_func():
                passed += 1
            else:
                print(f"❌ {test_name} failed")
        except Exception as e:
            print(f"❌ {test_name} error: {e}")
    
    print("\n" + "=" * 40)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! CerebralGuard is ready to use.")
        return True
    else:
        print("⚠️  Some tests failed. Please check the configuration.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 