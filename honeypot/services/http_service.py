"""
HTTP honeypot service.
Runs a threaded HTTPServer, records requests to JSONL via logger.log_event.
Note: This returns static decoy HTML and does NOT execute received payloads.
"""

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
        content = b"""<html><head><title>Welcome</title></head>
            <body><h1>Index</h1><p>Apache/2.4.54 (Unix)</p></body></html>"""
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
        # intentionally respond with 500 to create interesting logs
        self.send_response(500)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        msg = b"Internal Server Error\n"
        self.wfile.write(msg)
        entry["response_code"] = 500
        entry["timestamp"] = time.time()
        log_event(entry)

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
