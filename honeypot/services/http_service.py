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
        
        sql_patterns = ["union select", "drop table", "' or '1'='1", "order by", "information_schema"]
        if any(pattern in body_lower or pattern in path_lower for pattern in sql_patterns):
            indicators.append("sql_injection")
        
        # Check for XSS patterns
        xss_patterns = ["<script", "javascript:", "onerror=", "onload=", "alert("]
        if any(pattern in body_lower or pattern in path_lower for pattern in xss_patterns):
            indicators.append("xss_attempt")
        
        # Check for directory traversal
        traversal_patterns = ["../", "..\\", "%2e%2e", "....//"]
        if any(pattern in body_lower or pattern in path_lower for pattern in traversal_patterns):
            indicators.append("directory_traversal")
        
        # Check for malware/webshell indicators
        malware_patterns = ["shell.php", "cmd.php", "eval(", "system(", "exec(", "passthru("]
        if any(pattern in body_lower or pattern in path_lower for pattern in malware_patterns):
            indicators.append("malware_attempt")
        
        # Check User-Agent for suspicious patterns
        user_agent = entry.get("headers", {}).get("User-Agent", "").lower()
        suspicious_agents = ["masscan", "nmap", "sqlmap", "dirb", "gobuster", "nikto"]
        if any(agent in user_agent for agent in suspicious_agents):
            indicators.append("scanner_tool")
        
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
