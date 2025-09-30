import threading
import signal
import sys
from honeypot.services.http_service import run_http_server
from honeypot.services.ssh_service import run_ssh_like
from honeypot.services.ftp_service import run_ftp_server
from honeypot.services.smtp_service import run_smtp_server
from honeypot.services.mysql_service import run_mysql_server
from honeypot.services.redis_service import run_redis_server
from honeypot.services.telnet_service import run_telnet_server
from honeypot.services.vnc_service import run_vnc_server

def main():
    threads = []
    
    # Original services
    t_http = threading.Thread(target=run_http_server, kwargs={}, daemon=True)
    t_ssh  = threading.Thread(target=run_ssh_like, kwargs={}, daemon=True)
    t_ftp  = threading.Thread(target=run_ftp_server, kwargs={}, daemon=True)
    
    # New enhanced services
    t_smtp = threading.Thread(target=run_smtp_server, kwargs={}, daemon=True)
    t_mysql = threading.Thread(target=run_mysql_server, kwargs={}, daemon=True)
    t_redis = threading.Thread(target=run_redis_server, kwargs={}, daemon=True)
    t_telnet = threading.Thread(target=run_telnet_server, kwargs={}, daemon=True)
    t_vnc = threading.Thread(target=run_vnc_server, kwargs={}, daemon=True)
    
    threads.extend([t_http, t_ssh, t_ftp, t_smtp, t_mysql, t_redis, t_telnet, t_vnc])

    for t in threads:
        t.start()

    print("[*] Enhanced Honeypot running with 8 services:")
    print("    • HTTP (8080) - Web application attacks")
    print("    • SSH-like (2222) - SSH brute force")
    print("    • FTP (2121) - File transfer attacks")
    print("    • SMTP (25) - Email security testing")
    print("    • MySQL (3306) - Database attacks")
    print("    • Redis (6379) - NoSQL attacks")
    print("    • Telnet (23) - Remote access attacks")
    print("    • VNC (5900) - Remote desktop attacks")
    print("[*] Press Ctrl+C to stop.")
    
    def _stop(sig, frame):
        print("\n[*] Shutting down enhanced honeypot.")
        # services are daemon threads; exiting process suffices
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.pause()

if __name__ == "__main__":
    main()
