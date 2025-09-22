"""
Central logging utility. Writes JSON lines to LOG_FILE in config.
Implements a simple rotation by file size.
"""

import json
import datetime
import os
import threading
from honeypot.config import LOG_FILE, LOG_ROTATE_BYTES

_lock = threading.Lock()

def now_iso():
    return datetime.datetime.utcnow().isoformat() + "Z"

def _rotate_if_needed():
    try:
        if LOG_ROTATE_BYTES is None:
            return
        if LOG_FILE.exists() and LOG_FILE.stat().st_size >= LOG_ROTATE_BYTES:
            # rotate
            ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
            new_name = LOG_FILE.with_name(f"honeypot_events.{ts}.jsonl")
            os.rename(LOG_FILE, new_name)
    except Exception:
        # rotation failure should not crash service
        pass

def log_event(entry: dict):
    """
    entry is a dict that will be augmented with a 'logged_at' timestamp
    and written as one JSON line.
    """
    entry = dict(entry)  # shallow copy
    entry.setdefault("logged_at", now_iso())
    with _lock:
        _rotate_if_needed()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
