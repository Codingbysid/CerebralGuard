"""
Setup script for CerebralGuard
Handles installation, configuration, and initialization.
"""

import os
import sys
from pathlib import Path
import subprocess
import shutil
from dotenv import load_dotenv

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 11):
        print("❌ Error: Python 3.11 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version}")
    return True

def install_dependencies():
    """Install required dependencies."""
    print("📦 Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def create_directories():
    """Create necessary directories."""
    directories = [
        "models/saved",
        "data",
        "logs",
        "db"
    ]
    
    print("📁 Creating directories...")
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created: {directory}")
    
    return True

def setup_environment():
    """Set up environment variables."""
    env_file = Path(".env")
    env_example = Path("env.example")
    
    if not env_file.exists():
        if env_example.exists():
            print("🔧 Setting up environment variables...")
            shutil.copy(env_example, env_file)
            print("✅ Created .env file from template")
            print("⚠️  Please edit .env file with your API keys and configuration")
        else:
            print("❌ env.example file not found")
            return False
    else:
        print("✅ .env file already exists")
    
    return True

def initialize_database():
    """Initialize the database tables."""
    print("🗄️  Initializing database...")
    try:
        from db.tidb_helpers import tidb_manager
        success = tidb_manager.initialize_database()
        if success:
            print("✅ Database initialized successfully")
        else:
            print("⚠️  Database initialization failed (check your TiDB configuration)")
        return success
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        return False

def test_imports():
    """Test if all modules can be imported."""
    print("🧪 Testing imports...")
    
    modules_to_test = [
        "fastapi",
        "torch",
        "transformers",
        "google.generativeai",
        "mysql.connector",
        "requests",
        "loguru"
    ]
    
    failed_imports = []
    
    for module in modules_to_test:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError:
            print(f"❌ {module}")
            failed_imports.append(module)
    
    if failed_imports:
        print(f"⚠️  Failed to import: {', '.join(failed_imports)}")
        return False
    
    return True

def check_api_keys():
    """Check if required API keys are configured."""
    print("🔑 Checking API keys...")
    
    load_dotenv()
    
    required_keys = [
        "GEMINI_API_KEY",
        "TIDB_HOST",
        "TIDB_USER",
        "TIDB_PASSWORD"
    ]
    
    optional_keys = [
        "VIRUSTOTAL_API_KEY",
        "ABUSEIPDB_API_KEY",
        "SLACK_WEBHOOK_URL"
    ]
    
    missing_required = []
    missing_optional = []
    
    for key in required_keys:
        if not os.getenv(key):
            missing_required.append(key)
        else:
            print(f"✅ {key}")
    
    for key in optional_keys:
        if not os.getenv(key):
            missing_optional.append(key)
        else:
            print(f"✅ {key}")
    
    if missing_required:
        print(f"❌ Missing required API keys: {', '.join(missing_required)}")
        return False
    
    if missing_optional:
        print(f"⚠️  Missing optional API keys: {', '.join(missing_optional)}")
        print("   These are not required but provide additional functionality")
    
    return True

def run_tests():
    """Run basic tests."""
    print("🧪 Running basic tests...")
    
    try:
        # Test API health
        import requests
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print("✅ API health check passed")
            return True
        else:
            print("❌ API health check failed")
            return False
    except requests.exceptions.ConnectionError:
        print("⚠️  API not running (start with 'python app.py')")
        return True  # Not a setup failure
    except Exception as e:
        print(f"❌ Test error: {e}")
        return False

def main():
    """Main setup function."""
    print("🚀 CerebralGuard Setup")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        return False
    
    print()
    
    # Install dependencies
    if not install_dependencies():
        return False
    
    print()
    
    # Create directories
    if not create_directories():
        return False
    
    print()
    
    # Setup environment
    if not setup_environment():
        return False
    
    print()
    
    # Test imports
    if not test_imports():
        return False
    
    print()
    
    # Check API keys
    if not check_api_keys():
        print("\n⚠️  Please configure your API keys in the .env file")
        print("   Required: GEMINI_API_KEY, TIDB_HOST, TIDB_USER, TIDB_PASSWORD")
        print("   Optional: VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, SLACK_WEBHOOK_URL")
        return False
    
    print()
    
    # Initialize database
    initialize_database()
    
    print()
    
    # Run tests
    run_tests()
    
    print()
    print("🎉 Setup completed!")
    print()
    print("Next steps:")
    print("1. Edit .env file with your API keys")
    print("2. Start the application: python app.py")
    print("3. Run the demo: python demo.py")
    print("4. Access the API at: http://localhost:8000")
    print("5. View API docs at: http://localhost:8000/docs")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 