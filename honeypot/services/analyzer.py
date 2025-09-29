import json
from collections import Counter, defaultdict
from honeypot.config import LOG_FILE
import math
import argparse

def read_events(limit=None):
    events = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if limit and i >= limit:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except Exception:
                    continue
    except FileNotFoundError:
        return []
    return events

def summarize(events):
    summary = {}
    summary['total_events'] = len(events)
    by_service = Counter([e.get("service") for e in events if e.get("service")])
    summary['by_service'] = dict(by_service)

    peers = Counter([e.get("peer") for e in events if e.get("peer")])
    summary['top_peers'] = peers.most_common(10)

    methods = Counter()
    paths = Counter()
    durations = []
    attack_indicators = Counter()
    user_agents = Counter()
    
    for e in events:
        if e.get("service") == "http":
            methods[e.get("method")] += 1
            paths[e.get("path")] += 1
            
            # Count attack indicators
            indicators = e.get("attack_indicators", [])
            for indicator in indicators:
                attack_indicators[indicator] += 1
            
            # Count user agents
            ua = e.get("headers", {}).get("User-Agent", "Unknown")
            user_agents[ua] += 1
            
        if e.get("service") == "ssh-like":
            if e.get("start_ts") and e.get("end_ts"):
                durations.append(max(0, e["end_ts"] - e["start_ts"]))

    summary['http_methods'] = dict(methods)
    summary['http_paths'] = dict(paths)
    summary['attack_indicators'] = dict(attack_indicators)
    summary['top_user_agents'] = user_agents.most_common(10)
    summary['total_attacks'] = sum(attack_indicators.values())
    
    if durations:
        summary['ssh_session_count'] = len(durations)
        summary['ssh_session_avg'] = sum(durations) / len(durations)
        summary['ssh_session_stddev'] = math.sqrt(sum((d - summary['ssh_session_avg'])**2 for d in durations)/len(durations)) if len(durations)>0 else 0
    else:
        summary['ssh_session_count'] = 0
        summary['ssh_session_avg'] = 0.0
        summary['ssh_session_stddev'] = 0.0
    return summary

def build_mitigation_advice(attack_summary: dict) -> dict:
    """Map attack indicators to categories, severity, and mitigations."""
    indicator_catalog = {
        "sql_injection": {
            "category": "Injection",
            "severity": "high",
            "mitigations": [
                "Use parameterized queries and ORM bindings",
                "Apply server-side input validation and encoding",
                "Enforce least-privilege DB accounts",
                "Deploy a WAF rule set for SQLi"
            ]
        },
        "xss_attempt": {
            "category": "Cross-Site Scripting",
            "severity": "high",
            "mitigations": [
                "Context-aware output encoding",
                "Set Content-Security-Policy",
                "Sanitize user input and HTML",
                "Use HttpOnly and SameSite cookies"
            ]
        },
        "directory_traversal": {
            "category": "Path Traversal",
            "severity": "medium",
            "mitigations": [
                "Normalize and validate file paths",
                "Disallow `..` and encoded variants",
                "Serve files from whitelisted directories only"
            ]
        },
        "lfi_attempt": {
            "category": "Local File Inclusion",
            "severity": "high",
            "mitigations": [
                "Disallow dynamic file includes from user input",
                "Use allowlists for file access",
                "Disable remote file wrappers"
            ]
        },
        "malware_attempt": {
            "category": "Webshell/Upload",
            "severity": "high",
            "mitigations": [
                "Block dangerous file types and double extensions",
                "Validate MIME and scan uploads",
                "Store uploads outside webroot"
            ]
        },
        "scanner_tool": {
            "category": "Reconnaissance",
            "severity": "low",
            "mitigations": [
                "Rate-limit suspicious clients",
                "Honeypot tarpitting and deception",
                "Block abusive IPs at edge/WAF"
            ]
        },
        "command_injection": {
            "category": "RCE/Command Injection",
            "severity": "critical",
            "mitigations": [
                "Avoid shell invocation; use safe libraries",
                "Strict input validation and allowlists",
                "Escape shell arguments with subprocess APIs",
                "Drop privileges and apply seccomp/AppArmor"
            ]
        },
        "ssrf_attempt": {
            "category": "SSRF",
            "severity": "high",
            "mitigations": [
                "Block access to metadata/IP ranges (169.254.169.254, 127.0.0.1)",
                "Use URL allowlists and DNS pinning",
                "Force HTTP library to disallow redirects and non-HTTP schemes"
            ]
        },
        "open_redirect": {
            "category": "Open Redirect",
            "severity": "medium",
            "mitigations": [
                "Validate redirect targets against allowlists",
                "Use relative paths and signed tokens"
            ]
        },
        "header_injection": {
            "category": "Header Injection",
            "severity": "medium",
            "mitigations": [
                "Strip CR/LF from inputs used in headers",
                "Normalize and validate header values"
            ]
        },
        "brute_force": {
            "category": "Auth Brute Force",
            "severity": "medium",
            "mitigations": [
                "Enforce login throttling and IP-based rate limits",
                "Add CAPTCHA after failed attempts",
                "Enable MFA on critical accounts"
            ]
        },
    }

    advice = {}
    for indicator, count in attack_summary.items():
        meta = indicator_catalog.get(indicator)
        if not meta:
            continue
        advice[indicator] = {
            "count": count,
            "category": meta["category"],
            "severity": meta["severity"],
            "mitigations": meta["mitigations"],
        }
    return advice

def print_advisory(events, limit=None):
    s = summarize(events)
    advice = build_mitigation_advice(s.get('attack_indicators', {}))
    if not advice:
        print("No attack indicators to advise on.")
        return
    print("=== ATTACK CLASSIFICATION & MITIGATION ADVICE ===")
    for indicator, meta in sorted(advice.items(), key=lambda x: (x[1]['severity'], -x[1]['count'])):
        print(f"- {indicator} | {meta['category']} | severity={meta['severity']} | count={meta['count']}")
        for m in meta['mitigations']:
            print(f"    * {m}")
    print()

def print_report(limit=None):
    events = read_events(limit=limit)
    s = summarize(events)
    print("=" * 60)
    print("=== HONEYPOT ANALYSIS REPORT ===")
    print("=" * 60)
    print(f"Total events captured: {s['total_events']}")
    print(f"Total attack indicators: {s['total_attacks']}")
    print()
    
    print("📊 Events by Service:")
    for k,v in s['by_service'].items():
        print(f"  {k}: {v}")
    print()
    
    print("🌐 Top Source IPs:")
    for peer,count in s['top_peers']:
        print(f"  {peer}: {count} requests")
    print()
    
    print("🔍 HTTP Methods:")
    for m,c in s['http_methods'].items():
        print(f"  {m}: {c}")
    print()
    
    print("📁 Top HTTP Paths (sample):")
    for p,c in sorted(s['http_paths'].items(), key=lambda x:-x[1])[:10]:
        print(f"  {p}: {c}")
    print()
    
    if s['attack_indicators']:
        print("⚠️  Attack Indicators Detected:")
        for indicator, count in sorted(s['attack_indicators'].items(), key=lambda x:-x[1]):
            print(f"  {indicator}: {count} attempts")
        print()
    
    if s['top_user_agents']:
        print("🤖 Top User Agents:")
        for ua, count in s['top_user_agents'][:5]:
            ua_short = ua[:50] + "..." if len(ua) > 50 else ua
            print(f"  {ua_short}: {count}")
        print()
    
    if s['ssh_session_count']>0:
        print("🔐 SSH-like Sessions:")
        print(f"  Sessions: {s['ssh_session_count']}")
        print(f"  Avg duration: {s['ssh_session_avg']:.2f}s")
        print(f"  Std deviation: {s['ssh_session_stddev']:.2f}s")
        print()
    
    print("=" * 60)
    if s['total_attacks'] > 0:
        print(f"🚨 SUMMARY: Detected {s['total_attacks']} attack attempts from {len(s['top_peers'])} unique IPs")
    else:
        print("✅ No suspicious activity detected")
    print("=" * 60)
    print()
    print_advisory(events)

def main():
    parser = argparse.ArgumentParser(description="Offline analyzer for honeypot JSONL logs")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of log lines to read")
    parser.add_argument("--advice-only", action="store_true", help="Only show mitigation advice")
    args = parser.parse_args()
    if args.advice_only:
        events = read_events(limit=args.limit)
        print_advisory(events)
    else:
        print_report(limit=args.limit)

if __name__ == "__main__":
    main()
