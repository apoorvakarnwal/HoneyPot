"""
Configuration for honeypot project.
Adjust ports and bind IPs as required for your isolated lab.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Bind settings
BIND_IP = "0.0.0.0"   # listens on all interfaces inside container/VM; in docker-compose we bind to localhost
HTTP_PORT = 8080
SSH_PORT = 2222
FTP_PORT = 2121
SMTP_PORT = 25
DNS_PORT = 53
DASHBOARD_PORT = 5123

# Logging rotation (bytes). If None, uses simple append-only JSONL
LOG_ROTATE_BYTES = 5 * 1024 * 1024  # 5 MB

# Logging filename
LOG_FILE = LOG_DIR / "honeypot_events.jsonl"

# Limits for services
MAX_HTTP_BODY = 1024 * 10  # 10 KB read for body (safety)
SSH_RECV_BUFFER = 4096
SSH_SESSION_TIMEOUT = 10.0  # seconds

# Attack simulation safety
ALLOWED_ATTACK_TARGETS = ["127.0.0.1", "localhost"]  # attacker_sim.py also allows private CIDRs
