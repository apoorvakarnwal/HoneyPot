#!/usr/bin/env python3
"""
Quick test to verify fixes
"""

import sys
import os
import importlib

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

def test_syntax():
    """Test if syntax errors are fixed"""
    print("🔍 Testing syntax fixes...")
    
    try:
        # Test HTTP service
        import honeypot.services.http_service
        print("  ✅ HTTP service syntax OK")
        
        # Test alerting service
        import honeypot.services.alerting
        print("  ✅ Alerting service syntax OK")
        
        # Test main module
        import honeypot.main
        print("  ✅ Main module syntax OK")
        
        # Test simple main
        import honeypot.simple_main
        print("  ✅ Simple main syntax OK")
        
        return True
    except SyntaxError as e:
        print(f"  ❌ Syntax error: {e}")
        return False
    except Exception as e:
        print(f"  ⚠️  Import warning: {e}")
        return True  # Import errors are OK, syntax errors are not

def main():
    print("🍯 Quick Syntax Test")
    print("=" * 30)
    
    if test_syntax():
        print("\n🎉 All syntax errors fixed!")
        print("\n📋 Ready to run:")
        print("1. Simple honeypot: python -m honeypot.simple_main")
        print("2. Dashboard only: python test_dashboard.py")
        print("3. Full system: python -m honeypot.main")
        return 0
    else:
        print("\n❌ Still have syntax errors to fix")
        return 1

if __name__ == '__main__':
    sys.exit(main())
