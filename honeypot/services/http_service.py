from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from honeypot.logger import log_event
from honeypot.config import HTTP_PORT, BIND_IP, MAX_HTTP_BODY
import time
import threading

class HoneypotHTTPRequestHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.54 (Unix)"
    sys_version = ""

    def _record_request(self):
        length = int(self.headers.get("Content-Length", 0))
        to_read = min(length, MAX_HTTP_BODY)
        body = b""
        if to_read:
            body = self.rfile.read(to_read)
            # if body was truncated, note it
            if length > to_read:
                body += b"...[truncated]"
        try:
            body_text = body.decode("utf-8", errors="replace")
        except Exception:
            body_text = repr(body)

        entry = {
            "service": "http",
            "peer": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body_text,
            "response_code": None
        }
        return entry

    def do_GET(self):
        entry = self._record_request()
        
        # Analyze for attack patterns
        entry["attack_indicators"] = self._analyze_attack_patterns(entry)
        
        # Respond based on path to create more realistic interactions
        if self.path in ["/admin", "/administrator", "/wp-admin"]:
            content = b"""<html><head><title>Admin Login</title></head>
                <body><h1>Administrator Login</h1>
                <form method="post" action="/login">
                <input type="text" name="username" placeholder="Username"><br>
                <input type="password" name="password" placeholder="Password"><br>
                <input type="submit" value="Login">
                </form></body></html>"""
        elif self.path == "/robots.txt":
            content = b"""User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /config/
Disallow: /private/"""
        elif "php" in self.path or "shell" in self.path:
            # Suspicious file requests - return 404 but still log
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            content = b"<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>"
            self.wfile.write(content)
            entry["response_code"] = 404
            entry["timestamp"] = time.time()
            log_event(entry)
            return
        else:
            content = b"""<html><head><title>Welcome</title></head>
                <body><h1>Index</h1><p>Apache/2.4.54 (Unix)</p>
                <a href="/admin">Admin Panel</a> | <a href="/login">Login</a>
                </body></html>"""
        
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)
        entry["response_code"] = 200
        entry["timestamp"] = time.time()
        log_event(entry)

    def do_POST(self):
        entry = self._record_request()
        
        # Analyze for different attack patterns
        entry["attack_indicators"] = self._analyze_attack_patterns(entry)
        
        # Respond based on path to create more realistic interactions
        if "/login" in self.path:
            self.send_response(401)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            msg = b"<html><head><title>Login Failed</title></head><body><h1>Invalid credentials</h1></body></html>"
        elif "/search" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            msg = b"<html><head><title>Search Results</title></head><body><h1>No results found</h1></body></html>"
        else:
            # Default response for other POST requests
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            msg = b"Internal Server Error\n"
        
        self.wfile.write(msg)
        entry["response_code"] = getattr(self, '_response_code', 500)
        entry["timestamp"] = time.time()
        log_event(entry)

    def send_response(self, code, message=None):
        super().send_response(code, message)
        self._response_code = code
    
    def _analyze_attack_patterns(self, entry):
        """Analyze request for common attack patterns"""
        indicators = []
        
        # Check for SQL injection patterns
        body_lower = entry.get("body", "").lower()
        path_lower = entry.get("path", "").lower()
        headers = entry.get("headers", {})
        
        # Enhanced SQL injection detection
        sql_patterns = [
            "union select", "drop table", "' or '1'='1", "order by", "information_schema",
            "union all select", "concat(", "group_concat(", "having 1=1", "and 1=1",
            "or 1=1", "waitfor delay", "benchmark(", "sleep(", "pg_sleep(",
            "extractvalue(", "updatexml(", "load_file(", "into outfile", "load data infile"
        ]
        if any(pattern in body_lower or pattern in path_lower for pattern in sql_patterns):
            indicators.append("sql_injection")
        
        # Enhanced XSS patterns
        xss_patterns = [
            "<script", "javascript:", "onerror=", "onload=", "alert(",
            "<iframe", "<object", "<embed", "<svg", "<img", "onmouseover=",
            "onclick=", "onfocus=", "onblur=", "eval(", "expression(",
            "vbscript:", "data:text/html", "data:application"
        ]
        if any(pattern in body_lower or pattern in path_lower for pattern in xss_patterns):
            indicators.append("xss_attempt")
        
        # Enhanced directory traversal
        traversal_patterns = [
            "../", "..\\", "%2e%2e", "....//", "%252e%252e", "%c0%ae%c0%ae",
            "\\u002e\\u002e", "\\uff0e\\uff0e", "..%252f", "..%5c", "..%2f"
        ]
        if any(pattern in body_lower or pattern in path_lower for pattern in traversal_patterns):
            indicators.append("directory_traversal")
        
        # Enhanced malware/webshell indicators
        malware_patterns = [
            "shell.php", "cmd.php", "eval(", "system(", "exec(", "passthru(",
            "shell.jsp", "cmd.asp", "webshell", "backdoor", "c99.php", "r57.php",
            "wso.php", "b374k.php", "shell_exec(", "proc_open(", "popen(",
            "file_get_contents(", "file_put_contents(", "fwrite(", "fopen("
        ]
        if any(pattern in body_lower or pattern in path_lower for pattern in malware_patterns):
            indicators.append("malware_attempt")
        
        # API attack patterns
        api_patterns = [
            "/api/", "/graphql", "/swagger", "/openapi", "/actuator/",
            "/rest/api", "/v1/", "/v2/", "/_api/", "/json-rpc"
        ]
        if any(pattern in path_lower for pattern in api_patterns):
            indicators.append("api_probe")
        
        # IoT attack patterns
        iot_patterns = [
            "/cgi-bin/", "/goform/", "/web/cgi-bin/", "/setup/", "/upnp/",
            "param.cgi", "machine.cgi", "deviceinfo", "factory_reset"
        ]
        if any(pattern in path_lower for pattern in iot_patterns):
            indicators.append("iot_exploit")
        
        # Evasion technique detection
        evasion_patterns = [
            "%00", "%0d%0a", "%252e", "%252f", "%c0%ae", "\\u002e", "\\uff0e"
        ]
        if any(pattern in path_lower for pattern in evasion_patterns):
            indicators.append("evasion_technique")
        
        # Check User-Agent for suspicious patterns
        user_agent = headers.get("User-Agent", "").lower()
        suspicious_agents = [
            "masscan", "nmap", "sqlmap", "dirb", "gobuster", "nikto",
            "metasploit", "cobalt strike", "empire", "poshc2", "sliver",
            "api-scanner", "mirai-botnet", "iot-scanner", "routerhunter",
            "criminalbot", "hacktool", "exploitkit", "malwaredropper"
        ]
        if any(agent in user_agent for agent in suspicious_agents):
            indicators.append("scanner_tool")
        
        # Advanced header analysis
        suspicious_headers = ["x-command", "x-payload", "x-originating-ip", "x-forwarded-for"]
        for header_name in headers:
            if header_name.lower() in suspicious_headers:
                indicators.append("suspicious_headers")
                break
        
        # JWT/Token analysis
        auth_header = headers.get("Authorization", "")
        if "bearer" in auth_header.lower() and ("invalid" in auth_header.lower() or "none" in auth_header):
            indicators.append("jwt_manipulation")
        
        # Command injection patterns
        cmd_patterns = [
            "; cat", "| cat", "& cat", "$(", "`", "&& cat", "|| cat",
            "; id", "| id", "& id", "; whoami", "| whoami", "& whoami",
            "; uname", "| uname", "& uname", "; ls", "| ls", "& ls"
        ]
        if any(pattern in body_lower or pattern in path_lower for pattern in cmd_patterns):
            indicators.append("command_injection")
        
        # LDAP injection
        ldap_patterns = ["*)(", "*)|(", "*(", "*", "admin*)", "user*)"]
        if any(pattern in body_lower for pattern in ldap_patterns):
            indicators.append("ldap_injection")
        
        # NoSQL injection
        nosql_patterns = ["$where", "$ne", "$gt", "$lt", "$in", "$nin", "$or", "$and"]
        if any(pattern in body_lower for pattern in nosql_patterns):
            indicators.append("nosql_injection")
        
        return indicators

    def log_message(self, format, *args):
        # suppress default console logging; we prefer our structured log
        return

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

def run_http_server(bind: str = BIND_IP, port: int = HTTP_PORT):
    server = ThreadedHTTPServer((bind, port), HoneypotHTTPRequestHandler)
    print(f"[+] HTTP honeypot listening on {bind}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
