"""
SSH-like TCP honeypot.
Not implementting ssh real protocol 
"""

import socket
import threading
import time
from honeypot.logger import log_event
from honeypot.config import SSH_PORT, BIND_IP, SSH_RECV_BUFFER, SSH_SESSION_TIMEOUT

BANNER = b"SSH-2.0-OpenSSH_8.9p1 Debian-1\r\n"
DECOY_PROMPT = b"last login: Fri Sep 19 12:34:56 2025 from 10.0.0.1\r\n$ "

def _handle_conn(conn: socket.socket, addr):
    peer = addr[0]
    session = {
        "service": "ssh-like",
        "peer": peer,
        "banner": None,
        "events": [],
        "start_ts": time.time(),
    }
    try:
        conn.settimeout(SSH_SESSION_TIMEOUT)
        conn.sendall(BANNER)
        session["banner"] = BANNER.decode("utf-8", errors="replace")
        while True:
            try:
                data = conn.recv(SSH_RECV_BUFFER)
            except socket.timeout:
                session["events"].append({"ts": time.time(), "note": "timeout"})
                break
            if not data:
                session["events"].append({"ts": time.time(), "note": "client_closed"})
                break
            # record the received bytes (safe: no execution)
            session["events"].append({"ts": time.time(), "recv": data.decode("utf-8", errors="replace")})
            # reply with decoy prompt to keep attacker engaged
            try:
                conn.sendall(DECOY_PROMPT)
            except Exception:
                break
    except Exception as exc:
        session["events"].append({"ts": time.time(), "error": str(exc)})
    finally:
        session["end_ts"] = time.time()
        log_event(session)
        try:
            conn.close()
        except Exception:
            pass

def run_ssh_like(bind: str = BIND_IP, port: int = SSH_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    s.listen(50)
    print(f"[+] SSH-like honeypot listening on {bind}:{port}")
    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=_handle_conn, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        s.close()
