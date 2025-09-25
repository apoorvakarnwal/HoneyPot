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

def main():
    parser = argparse.ArgumentParser(description="Offline analyzer for honeypot JSONL logs")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of log lines to read")
    args = parser.parse_args()
    print_report(limit=args.limit)

if __name__ == "__main__":
    main()
