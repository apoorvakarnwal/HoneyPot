import json
import time
import os
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta
from honeypot.config import LOG_FILE

class HoneypotMonitor:
    def __init__(self, alert_threshold=5, time_window=60):
        self.alert_threshold = alert_threshold
        self.time_window = time_window
        self.event_history = deque()
        self.attack_counts = defaultdict(int)
        self.ip_counts = defaultdict(int)
        self.last_position = 0
        
    def get_file_position(self):
        """Get current file size to track new content"""
        if LOG_FILE.exists():
            return LOG_FILE.stat().st_size
        return 0
    
    def read_new_events(self):
        """Read only new events since last check"""
        if not LOG_FILE.exists():
            return []
        
        current_size = self.get_file_position()
        if current_size <= self.last_position:
            return []
        
        events = []
        try:
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                f.seek(self.last_position)
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            event = json.loads(line)
                            events.append(event)
                        except json.JSONDecodeError:
                            continue
                
                self.last_position = f.tell()
        except Exception as e:
            print(f"[!] Error reading log file: {e}")
        
        return events
    
    def analyze_event(self, event):
        """Analyze a single event for threats"""
        current_time = datetime.now()
        
        # Clean old events outside time window
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        while self.event_history and self.event_history[0]['timestamp'] < cutoff_time:
            old_event = self.event_history.popleft()
            # Decrease counts for expired events
            if 'attack_indicators' in old_event:
                for indicator in old_event['attack_indicators']:
                    self.attack_counts[indicator] = max(0, self.attack_counts[indicator] - 1)
            if 'peer' in old_event:
                self.ip_counts[old_event['peer']] = max(0, self.ip_counts[old_event['peer']] - 1)
        
        # Add timestamp to event for tracking
        event['timestamp'] = current_time
        self.event_history.append(event)
        
        # Count attacks and IPs
        alerts = []
        
        if 'attack_indicators' in event and event['attack_indicators']:
            for indicator in event['attack_indicators']:
                self.attack_counts[indicator] += 1
                if self.attack_counts[indicator] >= self.alert_threshold:
                    alerts.append(f"HIGH FREQUENCY {indicator.upper()}: {self.attack_counts[indicator]} attempts in {self.time_window}s")
        
        if 'peer' in event:
            self.ip_counts[event['peer']] += 1
            if self.ip_counts[event['peer']] >= self.alert_threshold:
                alerts.append(f"HIGH FREQUENCY IP {event['peer']}: {self.ip_counts[event['peer']]} requests in {self.time_window}s")
        
        return alerts
    
    def format_event_summary(self, event):
        """Format event for display"""
        service = event.get('service', 'unknown')
        peer = event.get('peer', 'unknown')
        timestamp = event.get('logged_at', 'unknown')
        
        if service == 'http':
            method = event.get('method', '?')
            path = event.get('path', '?')
            response = event.get('response_code', '?')
            indicators = event.get('attack_indicators', [])
            
            summary = f"HTTP {method} {path} -> {response} from {peer}"
            if indicators:
                summary += f" [ATTACKS: {', '.join(indicators)}]"
                
        elif service == 'ssh-like':
            events_count = len(event.get('events', []))
            duration = event.get('duration', 0)
            summary = f"SSH session from {peer} - {events_count} events, {duration:.1f}s duration"
            
        elif service == 'ftp':
            auth_attempts = len(event.get('auth_attempts', []))
            commands = len(event.get('commands', []))
            summary = f"FTP session from {peer} - {auth_attempts} auth attempts, {commands} commands"
            
        else:
            summary = f"{service.upper()} event from {peer}"
        
        return f"[{timestamp[:19]}] {summary}"
    
    def monitor(self, interval=2):
        """Main monitoring loop"""
        print("🍯 HoneyPot Real-time Monitor Started")
        print("="*60)
        print(f"⚙️  Alert threshold: {self.alert_threshold} events in {self.time_window}s")
        print(f"📁 Monitoring: {LOG_FILE}")
        print("="*60)
        
        # Initialize position
        self.last_position = self.get_file_position()
        
        try:
            while True:
                new_events = self.read_new_events()
                
                for event in new_events:
                    # Display event
                    print(self.format_event_summary(event))
                    
                    # Check for alerts
                    alerts = self.analyze_event(event)
                    for alert in alerts:
                        print(f"🚨 ALERT: {alert}")
                
                if new_events:
                    print(f"📊 Active IPs: {len([ip for ip, count in self.ip_counts.items() if count > 0])}")
                    print("-" * 40)
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n⏹️  Monitoring stopped by user")
        except Exception as e:
            print(f"\n❌ Monitor error: {e}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Real-time honeypot event monitor")
    parser.add_argument("--threshold", type=int, default=5, help="Alert threshold (events per time window)")
    parser.add_argument("--window", type=int, default=60, help="Time window in seconds")
    parser.add_argument("--interval", type=float, default=2, help="Check interval in seconds")
    
    args = parser.parse_args()
    
    monitor = HoneypotMonitor(alert_threshold=args.threshold, time_window=args.window)
    monitor.monitor(interval=args.interval)

if __name__ == "__main__":
    main()
