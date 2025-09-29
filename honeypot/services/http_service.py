from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from honeypot.logger import log_event
from honeypot.config import HTTP_PORT, BIND_IP, MAX_HTTP_BODY
import time
import threading
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

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

        # Parse URL components
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        entry["query"] = {k: v if len(v) > 1 else (v[0] if v else "") for k, v in query.items()}

        # Analyze for attack patterns
        entry["attack_indicators"] = self._analyze_attack_patterns(entry)

        # Respond based on path to create more realistic interactions
        if path in ["/admin", "/administrator", "/wp-admin"]:
            content = b"""<html><head><title>Admin Login</title></head>
                <body><h1>Administrator Login</h1>
                <form method="post" action="/login">
                <input type="text" name="username" placeholder="Username"><br>
                <input type="password" name="password" placeholder="Password"><br>
                <input type="submit" value="Login">
                </form></body></html>"""
            self._send_html(entry, 200, content)
            return
        
        if path == "/robots.txt":
            content = b"""User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /config/
Disallow: /private/"""
            self._send_text(entry, 200, content, content_type="text/plain")
            return

        if path == "/fetch":
            # SSRF decoy endpoint - never actually fetch
            target_url = str(entry.get("query", {}).get("url", ""))
            entry.setdefault("extras", {})["fetch_url"] = target_url
            self._send_text(entry, 500, b"Unable to fetch resource\n")
            return

        if path == "/redirect":
            # Open redirect decoy
            next_url = str(entry.get("query", {}).get("next", ""))
            self.send_response(302)
            self.send_header("Location", next_url if next_url else "/")
            self.end_headers()
            entry["response_code"] = 302
            entry["timestamp"] = time.time()
            log_event(entry)
            return

        if path == "/file":
            # LFI/traversal decoy
            self._send_text(entry, 403, b"Access denied\n")
            return

        if path == "/upload":
            # Simple upload form
            content = b"""<html><body><h1>Upload</h1>
                <form method=post enctype=multipart/form-data action="/upload">
                <input type=file name=file><input type=submit value=Upload>
                </form></body></html>"""
            self._send_html(entry, 200, content)
            return

        if path.startswith("/api"):
            # Fake API JSON
            body = b'{"status":"ok", "data": {"message": "sample"}}'
            self._send_json(entry, 200, body)
            return

        if "php" in path or "shell" in path:
            # Suspicious file requests - return 404 but still log
            content = b"<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>"
            self._send_html(entry, 404, content)
            return

        # Default index
        content = b"""<html><head><title>Welcome</title></head>
            <body><h1>Index</h1><p>Apache/2.4.54 (Unix)</p>
            <a href="/admin">Admin Panel</a> | <a href="/login">Login</a> | <a href="/upload">Upload</a>
            </body></html>"""
        self._send_html(entry, 200, content)

    def do_POST(self):
        entry = self._record_request()

        # Analyze for different attack patterns
        entry["attack_indicators"] = self._analyze_attack_patterns(entry)

        parsed = urlparse(self.path)
        path = parsed.path

        # Respond based on path to create more realistic interactions
        if path == "/login":
            # Track brute force attempts by source
            username = None
            try:
                # naive form parse
                form = dict(x.split("=") for x in entry.get("body", "").split("&") if "=" in x)
                username = form.get("username")
            except Exception:
                pass
            entry.setdefault("extras", {})["username"] = username
            self._increment_failed_login(entry.get("peer"))
            self._send_html(entry, 401, b"<html><head><title>Login Failed</title></head><body><h1>Invalid credentials</h1></body></html>")
            return

        if path == "/search":
            self._send_html(entry, 200, b"<html><head><title>Search Results</title></head><body><h1>No results found</h1></body></html>")
            return

        if path == "/upload":
            upload_size = len(entry.get("body", "").encode("utf-8", errors="ignore"))
            entry.setdefault("extras", {})["upload_size"] = upload_size
            self._send_text(entry, 200, b"Upload received\n")
            return

        # Default response for other POST requests
        self._send_text(entry, 500, b"Internal Server Error\n")

    def send_response(self, code, message=None):
        super().send_response(code, message)
        self._response_code = code
    
    def _analyze_attack_patterns(self, entry):
        """Analyze request for common attack patterns"""
        indicators = []
        
        # Check for SQL injection patterns
        body_lower = entry.get("body", "").lower()
        path_lower = entry.get("path", "").lower()
        headers_lower = {k.lower(): str(v).lower() for k, v in entry.get("headers", {}).items()}
        query_dict = entry.get("query", {}) if isinstance(entry.get("query", {}), dict) else {}
        query_concat = (" ".join([str(v) for v in query_dict.values()])).lower()
        
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

        # Local File Inclusion (LFI) hints
        lfi_patterns = ["etc/passwd", "windows\\system32", "..%2f..%2f", "%252fetc%252fpasswd"]
        if any(p in body_lower or p in path_lower for p in lfi_patterns):
            indicators.append("lfi_attempt")
        
        # Check for malware/webshell indicators
        malware_patterns = ["shell.php", "cmd.php", "eval(", "system(", "exec(", "passthru("]
        if any(pattern in body_lower or pattern in path_lower for pattern in malware_patterns):
            indicators.append("malware_attempt")
        
        # Check User-Agent for suspicious patterns
        user_agent = entry.get("headers", {}).get("User-Agent", "").lower()
        suspicious_agents = ["masscan", "nmap", "sqlmap", "dirb", "gobuster", "nikto"]
        if any(agent in user_agent for agent in suspicious_agents):
            indicators.append("scanner_tool")

        # Command injection indicators
        rce_patterns = [";", "&&", "||", "|", "`", "$(", "bash -c", "wget ", "curl ", "nc "]
        if any(p in body_lower or p in path_lower for p in rce_patterns):
            indicators.append("command_injection")

        # SSRF indicators via /fetch?url=
        if "url" in query_dict:
            url_val = str(query_dict.get("url", "")).lower()
            if any(scheme in url_val for scheme in ["http://", "https://", "file://", "gopher://"]) or "169.254.169.254" in url_val or "127.0.0.1" in url_val or "localhost" in url_val:
                indicators.append("ssrf_attempt")

        # Open redirect indicators via /redirect?next=
        if "next" in query_dict:
            next_val = str(query_dict.get("next", "")).lower()
            if next_val.startswith("http://") or next_val.startswith("https://"):
                indicators.append("open_redirect")

        # Header injection/abuse hints
        if any("\r\n" in v for v in headers_lower.values()):
            indicators.append("header_injection")
        
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

# In-memory tracking for simple brute-force detection signals
_failed_login_counter = defaultdict(int)
_failed_login_lock = threading.Lock()

def _increment_failed_login(peer: str):
    with _failed_login_lock:
        _failed_login_counter[peer] += 1

# Monkey-patch into the handler for simplicity without global state exposure
setattr(HoneypotHTTPRequestHandler, "_increment_failed_login", staticmethod(_increment_failed_login))

def _send_common(handler: HoneypotHTTPRequestHandler, entry: dict, code: int, body: bytes, content_type: str):
    handler.send_response(code)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    try:
        handler.wfile.write(body)
    except Exception:
        pass
    entry["response_code"] = code
    entry["timestamp"] = time.time()
    # Add brute force indicator if many failed logins from same peer
    if code == 401 and entry.get("path", "").startswith("/login"):
        peer = entry.get("peer")
        with _failed_login_lock:
            if _failed_login_counter.get(peer, 0) >= 5:
                entry.setdefault("attack_indicators", []).append("brute_force")
    log_event(entry)

def _send_html(handler: HoneypotHTTPRequestHandler, entry: dict, code: int, body: bytes):
    _send_common(handler, entry, code, body, "text/html")

def _send_text(handler: HoneypotHTTPRequestHandler, entry: dict, code: int, body: bytes, content_type: str = "text/plain"):
    _send_common(handler, entry, code, body, content_type)

def _send_json(handler: HoneypotHTTPRequestHandler, entry: dict, code: int, body: bytes):
    _send_common(handler, entry, code, body, "application/json")

# Bind helper methods to class to keep single-file simplicity
setattr(HoneypotHTTPRequestHandler, "_send_html", lambda self, e, c, b: _send_html(self, e, c, b))
setattr(HoneypotHTTPRequestHandler, "_send_text", lambda self, e, c, b, content_type="text/plain": _send_text(self, e, c, b, content_type))
setattr(HoneypotHTTPRequestHandler, "_send_json", lambda self, e, c, b: _send_json(self, e, c, b))
