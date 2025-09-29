"""
Simple main entry point without complex dependencies.
Runs only the core honeypot services.
"""

import threading
import signal
import sys
import os

def main():
    print("[*] Starting Simple Honeypot System...")
    
    threads = []
    
    # Core honeypot services - only import what we need
    try:
        from honeypot.services.http_service import run_http_server
        t_http = threading.Thread(target=run_http_server, kwargs={}, daemon=True)
        threads.append(t_http)
        print("[+] HTTP honeypot ready")
    except Exception as e:
        print(f"[!] HTTP service failed: {e}")
    
    try:
        from honeypot.services.ssh_service import run_ssh_like
        t_ssh = threading.Thread(target=run_ssh_like, kwargs={}, daemon=True)
        threads.append(t_ssh)
        print("[+] SSH honeypot ready")
    except Exception as e:
        print(f"[!] SSH service failed: {e}")
    
    try:
        from honeypot.services.ftp_service import run_ftp_server
        t_ftp = threading.Thread(target=run_ftp_server, kwargs={}, daemon=True)
        threads.append(t_ftp)
        print("[+] FTP honeypot ready")
    except Exception as e:
        print(f"[!] FTP service failed: {e}")
    
    # Optional services - fail gracefully
    try:
        from honeypot.services.smtp_service import run_smtp_server
        t_smtp = threading.Thread(target=run_smtp_server, kwargs={}, daemon=True)
        threads.append(t_smtp)
        print("[+] SMTP honeypot ready")
    except Exception as e:
        print(f"[!] SMTP service failed: {e}")
    
    try:
        from honeypot.services.dns_service import run_dns_server
        t_dns = threading.Thread(target=run_dns_server, kwargs={}, daemon=True)
        threads.append(t_dns)
        print("[+] DNS honeypot ready")
    except Exception as e:
        print(f"[!] DNS service failed: {e}")
    
    # Simple dashboard
    dashboard_enabled = os.getenv('ENABLE_DASHBOARD', 'true').lower() == 'true'
    if dashboard_enabled:
        try:
            from honeypot.services.simple_dashboard import run_simple_dashboard
            t_dashboard = threading.Thread(target=run_simple_dashboard, kwargs={'host': '0.0.0.0', 'port': 5123}, daemon=True)
            threads.append(t_dashboard)
            print("[+] Dashboard ready")
        except Exception as e:
            print(f"[!] Dashboard failed: {e}")

    # Start all services
    for t in threads:
        try:
            t.start()
        except Exception as e:
            print(f"[!] Failed to start service thread: {e}")

    print(f"[*] Started {len(threads)} services successfully!")
    print(f"[*] Services: HTTP:8080, SSH:2222, FTP:2121, SMTP:25, DNS:53")
    if dashboard_enabled:
        print(f"[*] Web Dashboard: http://localhost:5123")
    print("[*] Press Ctrl+C to stop.")
    
    def _stop(sig, frame):
        print("\n[*] Shutting down honeypot system...")
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.pause()

if __name__ == "__main__":
    main()
