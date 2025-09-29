#!/usr/bin/env python3
"""
Quick test script to start the simple dashboard
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

def main():
    print("🍯 Starting Honeypot Simple Dashboard...")
    print("This dashboard works independently of other services")
    print("Access it at: http://localhost:5123")
    print("Press Ctrl+C to stop")
    
    try:
        from honeypot.services.simple_dashboard import run_simple_dashboard
        run_simple_dashboard(host='0.0.0.0', port=5123, debug=False)
    except ImportError as e:
        print(f"Import error: {e}")
        print("Make sure you're in the project directory")
    except KeyboardInterrupt:
        print("\nDashboard stopped")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
