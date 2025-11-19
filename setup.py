#!/usr/bin/env python3
"""
Setup script for Chatter application dependencies
"""

import subprocess
import sys

def install_requirements():
    """Install required packages"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ All dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def test_imports():
    """Test that all required modules can be imported"""
    required_modules = [
        'flask',
        'flask_socketio', 
        'werkzeug',
        'requests',
        'markdown',
        'bleach'
    ]
    
    failed_imports = []
    for module in required_modules:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError:
            print(f"❌ {module}")
            failed_imports.append(module)
    
    return len(failed_imports) == 0

if __name__ == "__main__":
    print("🚀 Setting up Chatter application...")
    
    if install_requirements():
        print("\n📦 Testing imports...")
        if test_imports():
            print("\n🎉 Setup complete! You can now run chatter.py")
        else:
            print("\n⚠️ Some imports failed. Please check the error messages above.")
    else:
        print("\n❌ Setup failed. Please install dependencies manually.")
