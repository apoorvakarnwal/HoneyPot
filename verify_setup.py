#!/usr/bin/env python3
"""
Verification script to check if all components are working
"""

import sys
import os
import importlib

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

def test_imports():
    """Test if all required modules can be imported"""
    print("🔍 Testing imports...")
    
    modules_to_test = [
        'honeypot.config',
        'honeypot.logger',
        'honeypot.services.simple_dashboard',
        'honeypot.services.http_service',
        'honeypot.services.ssh_service',
        'honeypot.services.ftp_service',
    ]
    
    failed_imports = []
    
    for module in modules_to_test:
        try:
            importlib.import_module(module)
            print(f"  ✅ {module}")
        except ImportError as e:
            print(f"  ❌ {module} - {e}")
            failed_imports.append(module)
    
    return len(failed_imports) == 0

def test_dependencies():
    """Test if required dependencies are available"""
    print("\n🔍 Testing dependencies...")
    
    dependencies = [
        'flask',
        'requests',
        'psutil'
    ]
    
    failed_deps = []
    
    for dep in dependencies:
        try:
            importlib.import_module(dep)
            print(f"  ✅ {dep}")
        except ImportError as e:
            print(f"  ❌ {dep} - {e}")
            failed_deps.append(dep)
    
    return len(failed_deps) == 0

def test_configuration():
    """Test configuration values"""
    print("\n🔍 Testing configuration...")
    
    try:
        from honeypot.config import DASHBOARD_PORT, HTTP_PORT, SSH_PORT
        print(f"  ✅ Dashboard Port: {DASHBOARD_PORT}")
        print(f"  ✅ HTTP Port: {HTTP_PORT}")
        print(f"  ✅ SSH Port: {SSH_PORT}")
        return True
    except Exception as e:
        print(f"  ❌ Configuration error: {e}")
        return False

def test_dashboard():
    """Test if dashboard can be initialized"""
    print("\n🔍 Testing dashboard initialization...")
    
    try:
        from honeypot.services.simple_dashboard import run_simple_dashboard
        print("  ✅ Simple dashboard can be imported")
        
        # Test Flask app creation
        from honeypot.services.simple_dashboard import app
        print("  ✅ Flask app created successfully")
        
        return True
    except Exception as e:
        print(f"  ❌ Dashboard test failed: {e}")
        return False

def main():
    print("🍯 Honeypot Setup Verification")
    print("=" * 50)
    
    all_tests_passed = True
    
    # Run all tests
    all_tests_passed &= test_imports()
    all_tests_passed &= test_dependencies()
    all_tests_passed &= test_configuration()
    all_tests_passed &= test_dashboard()
    
    print("\n" + "=" * 50)
    
    if all_tests_passed:
        print("🎉 All tests passed! Your honeypot is ready to run.")
        print("\n📋 Next steps:")
        print("1. Start the dashboard: python test_dashboard.py")
        print("2. Access dashboard at: http://localhost:5123")
        print("3. Start full honeypot: python -m honeypot.main")
        print("4. Run attacks: python attacker_sim/simulate.py --target 127.0.0.1")
    else:
        print("❌ Some tests failed. Please check the errors above.")
        print("\n🔧 Common fixes:")
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Make sure you're in the project directory")
        print("3. Check Python version (requires Python 3.7+)")
    
    return 0 if all_tests_passed else 1

if __name__ == '__main__':
    sys.exit(main())
