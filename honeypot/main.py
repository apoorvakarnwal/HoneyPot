import threading
import signal
import sys
import os
from honeypot.services.http_service import run_http_server
from honeypot.services.ssh_service import run_ssh_like
from honeypot.services.ftp_service import run_ftp_server
from honeypot.services.smtp_service import run_smtp_server
from honeypot.services.dns_service import run_dns_server
try:
    from honeypot.services.dashboard import run_dashboard
except ImportError:
    from honeypot.services.simple_dashboard import run_simple_dashboard as run_dashboard
try:
    from honeypot.services.alerting import initialize_alerting
    ALERTING_AVAILABLE = True
except ImportError:
    ALERTING_AVAILABLE = False
    def initialize_alerting():
        print("[!] Alerting system not available")
try:
    from honeypot.services.metrics import metrics_collector
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False
    class MockMetricsCollector:
        def log_metrics(self):
            pass
    metrics_collector = MockMetricsCollector()

def main():
    print("[*] Starting Enhanced Honeypot System...")
    
    # Initialize alerting system
    initialize_alerting()
    
    # Start all honeypot services
    threads = []
    
    # Core honeypot services
    t_http = threading.Thread(target=run_http_server, kwargs={}, daemon=True)
    t_ssh  = threading.Thread(target=run_ssh_like, kwargs={}, daemon=True)
    t_ftp  = threading.Thread(target=run_ftp_server, kwargs={}, daemon=True)
    
    # Additional protocol honeypots
    t_smtp = threading.Thread(target=run_smtp_server, kwargs={}, daemon=True)
    t_dns  = threading.Thread(target=run_dns_server, kwargs={}, daemon=True)
    
    # Web dashboard (optional - only if not running in headless mode)
    dashboard_enabled = os.getenv('ENABLE_DASHBOARD', 'true').lower() == 'true'
    if dashboard_enabled:
        try:
            t_dashboard = threading.Thread(target=run_dashboard, kwargs={'host': '0.0.0.0', 'port': 5123}, daemon=True)
            threads.append(t_dashboard)
        except Exception as e:
            print(f"[!] Dashboard initialization failed: {e}")
            print(f"[!] Dashboard will not be available")
    
    threads.extend([t_http, t_ssh, t_ftp, t_smtp, t_dns])

    # Start all services
    for t in threads:
        try:
            t.start()
        except Exception as e:
            print(f"[!] Failed to start service thread: {e}")

    print("[*] All honeypot services started successfully!")
    print(f"[*] Services running: HTTP:8080, SSH:2222, FTP:2121, SMTP:25, DNS:53")
    if dashboard_enabled:
        print(f"[*] Web Dashboard: http://localhost:5123")
    print("[*] Press Ctrl+C to stop.")
    
    # Start metrics collection timer
    def log_metrics_periodically():
        while True:
            try:
                threading.Event().wait(300)  # 5 minutes
                metrics_collector.log_metrics()
            except:
                break
    
    metrics_thread = threading.Thread(target=log_metrics_periodically, daemon=True)
    metrics_thread.start()
    
    def _stop(sig, frame):
        print("\n[*] Shutting down honeypot system...")
        # services are daemon threads; exiting process suffices
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.pause()

if __name__ == "__main__":
    main()
