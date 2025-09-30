import json
import datetime
import os
import threading
from honeypot.config import LOG_FILE, LOG_ROTATE_BYTES

# Import enhanced logging
try:
    from honeypot.enhanced_logger import log_enhanced_event
    ENHANCED_LOGGING = True
except ImportError:
    ENHANCED_LOGGING = False

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
    Enhanced event logging with dual output:
    1. Original format for compatibility
    2. Enhanced structured logging for advanced analysis
    """
    entry = dict(entry)  # shallow copy
    entry.setdefault("logged_at", now_iso())
    
    # Original logging for compatibility
    with _lock:
        _rotate_if_needed()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    
    # Enhanced logging if available
    if ENHANCED_LOGGING:
        try:
            log_enhanced_event(entry)
        except Exception as e:
            # Don't let enhanced logging failures crash the service
            print(f"[!] Enhanced logging error: {e}")
    
    # Real-time console output for high-threat events
    threat_score = entry.get("threat_score", 0)
    if threat_score > 7.0:
        print(f"[!] HIGH THREAT DETECTED: Score {threat_score:.1f} from {entry.get('peer', 'unknown')} on {entry.get('service', 'unknown')}")
        if entry.get("attack_indicators"):
            print(f"    Attack types: {', '.join(entry['attack_indicators'])}")
        if entry.get("vulnerabilities_tested"):
            print(f"    Vulnerabilities tested: {', '.join(entry['vulnerabilities_tested'])}")
