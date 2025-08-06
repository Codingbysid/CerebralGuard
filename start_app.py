#!/usr/bin/env python3
"""
CerebralGuard Startup Script
Quick and easy way to start the application
"""

import os
import sys
import subprocess
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def install_dependencies():
    """Install required dependencies."""
    print("📦 Installing dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                      check=True, capture_output=True)
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def check_env_file():
    """Check if .env file exists and create example if not."""
    env_file = Path(".env")
    if not env_file.exists():
        print("⚠️  No .env file found. Creating example...")
        try:
            with open("env.example", "r") as example:
                with open(".env", "w") as env:
                    env.write(example.read())
            print("✅ Created .env file from example")
            print("⚠️  Please update .env with your API keys before running")
        except FileNotFoundError:
            print("❌ env.example not found")
            return False
    else:
        print("✅ .env file found")
    return True

def start_application():
    """Start the FastAPI application."""
    print("🚀 Starting CerebralGuard...")
    print("=" * 50)
    print("🌐 Web Interface: http://localhost:8000")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("🔧 Health Check: http://localhost:8000/health")
    print("=" * 50)
    print("Press Ctrl+C to stop the server")
    print()
    
    try:
        # Start the FastAPI app
        subprocess.run([sys.executable, "app.py"])
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting application: {e}")

def main():
    """Main startup function."""
    print("🧠 CerebralGuard - Autonomous AI Phishing Detection")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        return
    
    # Check for .env file
    if not check_env_file():
        return
    
    # Ask user if they want to install dependencies
    print("\n📦 Dependencies check:")
    try:
        import fastapi
        import uvicorn
        print("✅ Core dependencies already installed")
    except ImportError:
        print("❌ Missing dependencies")
        install = input("Install dependencies now? (y/n): ").lower().strip()
        if install == 'y':
            if not install_dependencies():
                return
        else:
            print("❌ Cannot start without dependencies")
            return
    
    # Start the application
    start_application()

if __name__ == "__main__":
    main() 