"""
Entry point for running all honeypot services.
Starts HTTP and SSH-like services in background threads.
"""

import threading
import signal
import sys
from honeypot.services.http_service import run_http_server
from honeypot.services.ssh_service import run_ssh_like

def main():
    threads = []
    t_http = threading.Thread(target=run_http_server, kwargs={}, daemon=True)
    t_ssh  = threading.Thread(target=run_ssh_like, kwargs={}, daemon=True)
    threads.extend([t_http, t_ssh])

    for t in threads:
        t.start()

    print("[*] Honeypot running. Press Ctrl+C to stop.")
    def _stop(sig, frame):
        print("[*] Shutting down honeypot.")
        # services are daemon threads; exiting process suffices
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.pause()

if __name__ == "__main__":
    main()
