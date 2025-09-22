"""
Simple offline log analyzer for honeypot_events.jsonl
Produces summary counts and small heuristics useful for demo slides.
This is intentionally simple and runs against the JSONL log file.
"""

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
    for e in events:
        if e.get("service") == "http":
            methods[e.get("method")] += 1
            paths[e.get("path")] += 1
        if e.get("service") == "ssh-like":
            if e.get("start_ts") and e.get("end_ts"):
                durations.append(max(0, e["end_ts"] - e["start_ts"]))

    summary['http_methods'] = dict(methods)
    summary['http_paths'] = dict(paths)
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
    print("=== Honeypot Analysis Report ===")
    print(f"Total events: {s['total_events']}")
    print("By service:")
    for k,v in s['by_service'].items():
        print(f"  {k}: {v}")
    print("Top peers:")
    for peer,count in s['top_peers']:
        print(f"  {peer}: {count}")
    print("HTTP methods:")
    for m,c in s['http_methods'].items():
        print(f"  {m}: {c}")
    print("Top HTTP paths (sample):")
    for p,c in sorted(s['http_paths'].items(), key=lambda x:-x[1])[:10]:
        print(f"  {p}: {c}")
    if s['ssh_session_count']>0:
        print(f"SSH sessions: {s['ssh_session_count']}  avg duration: {s['ssh_session_avg']:.2f}s  stddev: {s['ssh_session_stddev']:.2f}s")

def main():
    parser = argparse.ArgumentParser(description="Offline analyzer for honeypot JSONL logs")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of log lines to read")
    args = parser.parse_args()
    print_report(limit=args.limit)

if __name__ == "__main__":
    main()
