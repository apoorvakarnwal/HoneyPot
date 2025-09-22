"""
Safe attack simulation script.
Performs a set of benign probes (HTTP GETs, basic port scan, fake SSH-text inputs)
ONLY against allowed targets (localhost or private IP ranges). It includes an
explicit safety check to avoid targeting public hosts.
"""

import os
import sys
# Allow running this script directly by ensuring project root is on sys.path
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import socket
import time
import requests
import argparse
from honeypot.config import HTTP_PORT, SSH_PORT, ALLOWED_ATTACK_TARGETS
from honeypot.utils.helpers import is_private_or_local

# Safety: require an explicit --target when not using default and check it's private/local
DEFAULT_TARGET = "127.0.0.1"

def check_target_safety(target):
    if target in ALLOWED_ATTACK_TARGETS:
        return True
    return is_private_or_local(target)

def simple_port_scan(target, ports=(22, 80, 2222, 8080, 3306), timeout=0.8):
    results = {}
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((target, p))
            results[p] = "OPEN"
            s.close()
        except Exception:
            results[p] = "CLOSED"
    return results

def http_probe(target, port=HTTP_PORT):
    paths = ["/", "/admin", "/login", "/wp-admin", "/.env"]
    results = []
    for p in paths:
        url = f"http://{target}:{port}{p}"
        try:
            r = requests.get(url, timeout=3)
            results.append((url, r.status_code, len(r.content)))
        except Exception as e:
            results.append((url, "ERR", str(e)))
        time.sleep(0.4)
    return results

def ssh_simulate_text(target, port=SSH_PORT, attempts=4):
    results = []
    for _ in range(attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            banner = s.recv(2048)
            # send plain-text lines to the fake ssh port (harmless)
            creds = [b"root:toor\n", b"admin:admin\n", b"user:password\n"]
            for c in creds:
                try:
                    s.sendall(c)
                    time.sleep(0.2)
                except Exception:
                    break
            s.close()
            results.append(("OK", banner.decode(errors="replace").strip()))
        except Exception as e:
            results.append(("ERR", str(e)))
        time.sleep(0.3)
    return results

def main(target):
    if not check_target_safety(target):
        print("[!] Target appears public or unsafe. Aborting. Only localhost/private networks allowed.")
        return

    print("[*] Running safe port scan...")
    scan = simple_port_scan(target)
    for p,st in scan.items():
        print(f"  port {p}: {st}")

    print("[*] Running HTTP probes...")
    for url, status, info in http_probe(target):
        print(f"  {url} -> {status}  ({info})")

    print("[*] Running SSH-like text interactions...")
    for res in ssh_simulate_text(target):
        print("  ssh_sim:", res)

    print("[*] Simulation complete. Check honeypot logs for captured events.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Safe honeypot attack simulator (lab-only).")
    parser.add_argument("--target", "-t", default=DEFAULT_TARGET, help="Target hostname/IP (must be private/local).")
    args = parser.parse_args()
    main(args.target)
