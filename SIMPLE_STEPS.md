# SIMPLE STEPS

Follow these minimal steps to run the honeypot, send quick attacks, and see simple analysis.

## 1) Setup (one time)
```bash
# Create a clean Python env (optional for local scripts)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2) Run with Docker
```bash
# Build and start the honeypot
docker compose up -d

# Check status
docker compose ps

# Tail runtime logs
docker compose logs -f --tail=50
```

Exposed ports on localhost: 8080(HTTP), 2222(SSH), 2121(FTP), 25(SMTP), 3306(MySQL), 6379(Redis), 23(Telnet), 5900(VNC)

## 3) Generate quick events (simple attacks)
```bash
# HTTP
curl -sS http://127.0.0.1:8080/
curl -sS "http://127.0.0.1:8080/admin"
curl -sS -A "sqlmap/1.0" "http://127.0.0.1:8080/search?q=%27%20OR%201%3D1--"

# SSH (banner)
nc -v 127.0.0.1 2222 </dev/null

# FTP (login attempt)
printf "USER admin\r\nPASS password\r\nQUIT\r\n" | nc -v 127.0.0.1 2121

# SMTP (EHLO/auth poke)
printf "EHLO test\r\nAUTH PLAIN\r\nQUIT\r\n" | nc -v 127.0.0.1 25

# MySQL (banner)
nc -v 127.0.0.1 3306 </dev/null

# Redis (PING)
printf "*1\r\n$4\r\nPING\r\n" | nc -v 127.0.0.1 6379

# Telnet (connect & type)
nc -v 127.0.0.1 23

# VNC (banner)
nc -v 127.0.0.1 5900 </dev/null
```

## 4) Where logs are
- Main events (JSONL): `logs/honeypot_events.jsonl`

Useful commands:
```bash
# Live tail
tail -f logs/honeypot_events.jsonl

# Start fresh
rm -f logs/honeypot_events.jsonl
```

## 5) Simple analysis (one command)
```bash
python - <<'PY'
import json, collections, os
p="logs/honeypot_events.jsonl"
if not os.path.exists(p): 
    print("No logs yet. Generate traffic first."); raise SystemExit()
events=[]
with open(p,"r",encoding="utf-8") as f:
    for line in f:
        line=line.strip()
        if not line: continue
        try: events.append(json.loads(line))
        except: pass
svc=collections.Counter(e.get("service","?") for e in events)
ips=collections.Counter(e.get("peer","?") for e in events)
http_paths=collections.Counter(e.get("path","?") for e in events if e.get("service")=="http")
attk=collections.Counter(a for e in events for a in e.get("attack_indicators",[]))
print("=== SIMPLE HONEYPOT SUMMARY ===")
print(f"Total events: {len(events)}")
print("\nBy service:")
for k,v in svc.most_common(): print(f"  {k}: {v}")
print("\nTop IPs:")
for k,v in ips.most_common(5): print(f"  {k}: {v}")
if http_paths:
    print("\nTop HTTP paths:")
    for k,v in http_paths.most_common(5): print(f"  {k}: {v}")
if attk:
    print("\nAttack indicators:")
    for k,v in attk.most_common(10): print(f"  {k}: {v}")
print("\nLast 5 events (service → ip → brief):")
for e in events[-5:]:
    s=e.get("service","?"); ip=e.get("peer","?")
    brief=e.get("path") or e.get("method") or list(e.get("attack_indicators",[]))[:1] or ["-"]
    print(f"  {s:8} → {ip:15} → {brief}")
PY
```

## 6) Optional: static dashboard
```bash
open analysis/security_dashboard.html
```

## 7) Stop
```bash
docker compose down
```
