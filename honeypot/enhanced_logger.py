"""
Enhanced Logging System with Structured Data and Real-time Metrics
"""

import json
import datetime
import os
import threading
import time
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, Any, List
import sqlite3
import pickle
import gzip

from honeypot.config import LOG_DIR, LOG_ROTATE_BYTES

class EnhancedLogger:
    def __init__(self):
        self.lock = threading.Lock()
        self.metrics_lock = threading.Lock()
        
        # Create enhanced log directories
        self.log_dir = LOG_DIR
        self.structured_log_dir = self.log_dir / "structured"
        self.metrics_dir = self.log_dir / "metrics"
        self.archive_dir = self.log_dir / "archive"
        
        for directory in [self.structured_log_dir, self.metrics_dir, self.archive_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Log files
        self.main_log = self.log_dir / "honeypot_events.jsonl"
        self.structured_log = self.structured_log_dir / "structured_events.jsonl"
        self.metrics_log = self.metrics_dir / "real_time_metrics.jsonl"
        self.attack_patterns_log = self.structured_log_dir / "attack_patterns.jsonl"
        # Threat intelligence log removed as ML/TI features are disabled
        
        # In-memory metrics for real-time analysis
        self.real_time_metrics = {
            "total_events": 0,
            "events_by_service": defaultdict(int),
            "attacks_by_type": defaultdict(int),
            "unique_ips": set(),
            "attack_timeline": deque(maxlen=1000),
            "threat_scores": defaultdict(float),
            "geographic_data": defaultdict(int),
            "session_durations": deque(maxlen=500),
            "vulnerability_tests": defaultdict(int)
        }
        
        # Advanced threat scoring weights
        self.threat_weights = {
            "sql_injection": 8.5,
            "command_injection": 9.0,
            "malware_attempt": 9.5,
            "scanner_tool": 6.0,
            "brute_force": 7.0,
            "directory_traversal": 7.5,
            "xss_attempt": 6.5,
            "api_probe": 7.0,
            "iot_exploit": 8.0,
            "evasion_technique": 8.5,
            "nosql_injection": 8.0,
            "ldap_injection": 7.5,
            "authentication_bypass": 9.0,
            "weak_password_attempt": 5.0,
            "system_reconnaissance": 6.5,
            "data_exfiltration": 9.5,
            "privilege_escalation": 9.0
        }
        
        # Initialize SQLite database for advanced queries
        self.init_database()
        
        # Start background tasks
        self.start_background_tasks()
    
    def init_database(self):
        """Initialize SQLite database for structured storage"""
        self.db_path = self.log_dir / "honeypot_analysis.db"
        
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.cursor()
                
                # Events table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    service TEXT,
                    source_ip TEXT,
                    attack_types TEXT,
                    threat_score REAL,
                    session_duration REAL,
                    vulnerability_tests TEXT,
                    raw_data TEXT,
                    processed_at REAL,
                    geographic_region TEXT,
                    INDEX(timestamp),
                    INDEX(service),
                    INDEX(source_ip),
                    INDEX(threat_score)
                )
                ''')
                
                # Attack patterns table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_type TEXT,
                    pattern_data TEXT,
                    frequency INTEGER,
                    last_seen REAL,
                    threat_level TEXT,
                    INDEX(pattern_type),
                    INDEX(last_seen)
                )
                ''')
                
                # Real-time metrics table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS metrics_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    total_events INTEGER,
                    unique_ips INTEGER,
                    avg_threat_score REAL,
                    top_attack_types TEXT,
                    metrics_data TEXT,
                    INDEX(timestamp)
                )
                ''')
                
                conn.commit()
                print("[+] Enhanced logging database initialized")
                
        except Exception as e:
            print(f"[!] Database initialization error: {e}")
    
    def log_event(self, event: Dict[str, Any]):
        """Enhanced event logging with structured data and real-time analysis"""
        enhanced_event = self._enhance_event(event)
        
        # Advanced ML/TI analysis disabled; proceed with enhanced_event as-is
        
        # Write to multiple log formats
        with self.lock:
            # Original format
            self._write_original_log(enhanced_event)
            
            # Structured format
            self._write_structured_log(enhanced_event)
            
            # Update real-time metrics
            self._update_real_time_metrics(enhanced_event)
            
            # Store in database
            self._store_in_database(enhanced_event)
            
            # Check for rotation
            self._rotate_logs_if_needed()
            
            # Real-time alerting for critical threats
            self._check_for_critical_threats(enhanced_event)
    
    def _enhance_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance event with additional metadata and analysis"""
        enhanced = dict(event)
        
        # Add timestamps
        enhanced.setdefault("logged_at", self._now_iso())
        enhanced["processed_at"] = time.time()
        
        # Extract and enhance attack information
        attack_indicators = event.get("attack_indicators", [])
        vulnerability_tests = event.get("vulnerabilities_tested", [])
        
        # Calculate threat score
        threat_score = self._calculate_threat_score(attack_indicators, vulnerability_tests, event)
        enhanced["threat_score"] = threat_score
        
        # Classify attack sophistication
        enhanced["attack_sophistication"] = self._classify_sophistication(event, threat_score)
        
        # Add geographic estimation (simplified)
        enhanced["estimated_region"] = self._estimate_region(event.get("peer", ""))
        
        # Session analysis
        if "start_ts" in event and "end_ts" in event:
            enhanced["session_duration"] = event["end_ts"] - event["start_ts"]
        
        # Protocol analysis
        enhanced["protocol_compliance"] = self._analyze_protocol_compliance(event)
        
        # Add attack vector classification
        enhanced["attack_vectors"] = self._classify_attack_vectors(event)
        
        return enhanced
    
    def _calculate_threat_score(self, attack_indicators: List[str], 
                               vulnerability_tests: List[str], event: Dict[str, Any]) -> float:
        """Calculate comprehensive threat score"""
        base_score = 1.0
        
        # Score from attack indicators
        for indicator in attack_indicators:
            base_score += self.threat_weights.get(indicator, 2.0)
        
        # Score from vulnerability tests
        for vuln in vulnerability_tests:
            base_score += self.threat_weights.get(vuln, 1.5)
        
        # Service-specific scoring
        service = event.get("service", "")
        if service in ["mysql", "redis"]:
            base_score += 2.0  # Database attacks are more serious
        elif service in ["smtp", "telnet"]:
            base_score += 1.5
        
        # Authentication attempts scoring
        auth_attempts = event.get("auth_attempts", [])
        if len(auth_attempts) > 3:
            base_score += min(len(auth_attempts) * 0.5, 5.0)
        
        # Command complexity scoring
        commands = event.get("commands", [])
        if len(commands) > 10:
            base_score += 2.0
        
        # Cap at 10.0
        return min(base_score, 10.0)
    
    def _classify_sophistication(self, event: Dict[str, Any], threat_score: float) -> str:
        """Classify attack sophistication level"""
        if threat_score <= 2.0:
            return "basic_reconnaissance"
        elif threat_score <= 4.0:
            return "automated_scanning"
        elif threat_score <= 6.0:
            return "targeted_probing"
        elif threat_score <= 8.0:
            return "advanced_attack"
        else:
            return "apt_level_threat"
    
    def _estimate_region(self, ip: str) -> str:
        """Simplified geographic estimation"""
        if ip.startswith("127.") or ip == "localhost":
            return "localhost"
        elif ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "private_network"
        else:
            # In real implementation, use GeoIP database
            return "external"
    
    def _analyze_protocol_compliance(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze protocol compliance and anomalies"""
        service = event.get("service", "")
        compliance = {"service": service, "anomalies": []}
        
        if service == "http":
            headers = event.get("headers", {})
            if not headers.get("User-Agent"):
                compliance["anomalies"].append("missing_user_agent")
            if "X-Command" in headers or "X-Payload" in headers:
                compliance["anomalies"].append("suspicious_headers")
        
        elif service == "smtp":
            commands = event.get("commands", [])
            if any("VRFY" in str(cmd) for cmd in commands):
                compliance["anomalies"].append("user_enumeration")
        
        elif service in ["mysql", "redis"]:
            if event.get("auth_attempts") and not event.get("authenticated"):
                compliance["anomalies"].append("failed_authentication")
        
        return compliance
    
    def _classify_attack_vectors(self, event: Dict[str, Any]) -> List[str]:
        """Classify attack vectors present in the event"""
        vectors = []
        
        attack_indicators = event.get("attack_indicators", [])
        vulnerability_tests = event.get("vulnerabilities_tested", [])
        
        # Network-based vectors
        if any(indicator in ["scanner_tool", "port_scan"] for indicator in attack_indicators):
            vectors.append("network_reconnaissance")
        
        # Application-layer vectors
        if any(indicator in ["sql_injection", "xss_attempt", "command_injection"] 
               for indicator in attack_indicators):
            vectors.append("application_exploitation")
        
        # Authentication vectors
        if event.get("auth_attempts") or "brute_force" in attack_indicators:
            vectors.append("credential_attacks")
        
        # Protocol-specific vectors
        service = event.get("service", "")
        if service in ["mysql", "redis"] and vulnerability_tests:
            vectors.append("database_exploitation")
        
        # Social engineering (email-based)
        if service == "smtp" and vulnerability_tests:
            vectors.append("social_engineering")
        
        return vectors
    
    def _add_advanced_analysis(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Deprecated: ML and TI analysis removed. Return event unchanged."""
        return event
    
    def _check_for_critical_threats(self, event: Dict[str, Any]):
        """Check for critical threats and generate real-time alerts"""
        try:
            threat_score = event.get('threat_score', 0)
            source_ip = event.get('peer', 'unknown')
            service = event.get('service', 'unknown')
            
            # Critical threat conditions
            is_critical = False
            alert_reasons = []
            
            # High threat score
            if threat_score >= 8.0:
                is_critical = True
                alert_reasons.append(f"High threat score: {threat_score:.1f}")
            
            # ML/TI hooks removed; rely on indicators and threat score only
            
            # Multiple attack indicators
            attack_indicators = event.get('attack_indicators', [])
            if len(attack_indicators) >= 3:
                is_critical = True
                alert_reasons.append(f"Multiple attack types: {', '.join(attack_indicators)}")
            
            # Generate alert if critical
            if is_critical:
                alert = {
                    'timestamp': time.time(),
                    'alert_type': 'CRITICAL_THREAT',
                    'source_ip': source_ip,
                    'service': service,
                    'threat_score': threat_score,
                    'reasons': alert_reasons,
                    'event_id': event.get('event_id', 'unknown'),
                    'recommendations': []
                }
                
                # Log critical alert
                alert_file = self.log_dir / "critical_alerts.jsonl"
                with open(alert_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(alert, ensure_ascii=False, default=str) + "\n")
                
                # Console alert
                print(f"\n🚨 CRITICAL THREAT ALERT 🚨")
                print(f"Time: {datetime.datetime.fromtimestamp(alert['timestamp']).isoformat()}")
                print(f"Source: {source_ip} -> {service}")
                print(f"Threat Score: {threat_score:.1f}/10.0")
                print(f"Reasons: {', '.join(alert_reasons)}")
                if alert['recommendations']:
                    print(f"Actions: {', '.join(alert['recommendations'][:3])}")
                print("="*60)
                
        except Exception as e:
            print(f"[!] Critical threat check error: {e}")
    
    def _write_original_log(self, event: Dict[str, Any]):
        """Write to original format log"""
        with open(self.main_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
    
    def _write_structured_log(self, event: Dict[str, Any]):
        """Write to structured log with enhanced fields"""
        structured_event = {
            "timestamp": event.get("processed_at", time.time()),
            "event_id": f"{event.get('service', 'unknown')}_{int(time.time() * 1000)}",
            "service": event.get("service"),
            "source_ip": event.get("peer"),
            "threat_score": event.get("threat_score", 0),
            "sophistication": event.get("attack_sophistication"),
            "attack_indicators": event.get("attack_indicators", []),
            "vulnerability_tests": event.get("vulnerabilities_tested", []),
            "attack_vectors": event.get("attack_vectors", []),
            "geographic_region": event.get("estimated_region"),
            "protocol_compliance": event.get("protocol_compliance", {}),
            "session_duration": event.get("session_duration"),
            "raw_event": event
        }
        
        with open(self.structured_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(structured_event, ensure_ascii=False, default=str) + "\n")
    
    def _update_real_time_metrics(self, event: Dict[str, Any]):
        """Update real-time metrics"""
        with self.metrics_lock:
            self.real_time_metrics["total_events"] += 1
            
            service = event.get("service", "unknown")
            self.real_time_metrics["events_by_service"][service] += 1
            
            # Track unique IPs
            ip = event.get("peer")
            if ip:
                self.real_time_metrics["unique_ips"].add(ip)
            
            # Track attack types
            for indicator in event.get("attack_indicators", []):
                self.real_time_metrics["attacks_by_type"][indicator] += 1
            
            for vuln in event.get("vulnerabilities_tested", []):
                self.real_time_metrics["vulnerability_tests"][vuln] += 1
            
            # Track threat scores
            threat_score = event.get("threat_score", 0)
            self.real_time_metrics["threat_scores"][ip] = max(
                self.real_time_metrics["threat_scores"][ip], threat_score
            )
            
            # Attack timeline
            self.real_time_metrics["attack_timeline"].append({
                "timestamp": time.time(),
                "service": service,
                "threat_score": threat_score,
                "ip": ip
            })
            
            # Session duration
            duration = event.get("session_duration")
            if duration:
                self.real_time_metrics["session_durations"].append(duration)
            
            # Geographic tracking
            region = event.get("estimated_region", "unknown")
            self.real_time_metrics["geographic_data"][region] += 1
    
    def _store_in_database(self, event: Dict[str, Any]):
        """Store event in SQLite database for advanced queries"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                INSERT INTO events (
                    timestamp, service, source_ip, attack_types, threat_score,
                    session_duration, vulnerability_tests, raw_data, processed_at,
                    geographic_region
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.get("processed_at", time.time()),
                    event.get("service"),
                    event.get("peer"),
                    json.dumps(event.get("attack_indicators", [])),
                    event.get("threat_score", 0),
                    event.get("session_duration"),
                    json.dumps(event.get("vulnerabilities_tested", [])),
                    json.dumps(event, default=str),
                    time.time(),
                    event.get("estimated_region")
                ))
                
                conn.commit()
        except Exception as e:
            print(f"[!] Database storage error: {e}")
    
    def _rotate_logs_if_needed(self):
        """Rotate logs if they exceed size limit"""
        try:
            if LOG_ROTATE_BYTES is None:
                return
            
            for log_file in [self.main_log, self.structured_log]:
                if log_file.exists() and log_file.stat().st_size >= LOG_ROTATE_BYTES:
                    # Create compressed archive
                    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
                    archive_name = self.archive_dir / f"{log_file.stem}_{timestamp}.jsonl.gz"
                    
                    with open(log_file, 'rb') as f_in:
                        with gzip.open(archive_name, 'wb') as f_out:
                            f_out.writelines(f_in)
                    
                    # Clear original file
                    log_file.unlink()
                    
        except Exception as e:
            print(f"[!] Log rotation error: {e}")
    
    def get_real_time_metrics(self) -> Dict[str, Any]:
        """Get current real-time metrics"""
        with self.metrics_lock:
            # Convert sets to counts for JSON serialization
            metrics = dict(self.real_time_metrics)
            metrics["unique_ips"] = len(metrics["unique_ips"])
            metrics["attack_timeline"] = list(metrics["attack_timeline"])
            metrics["session_durations"] = list(metrics["session_durations"])
            
            # Add computed metrics
            if metrics["total_events"] > 0:
                metrics["avg_threat_score"] = sum(self.real_time_metrics["threat_scores"].values()) / len(self.real_time_metrics["threat_scores"]) if self.real_time_metrics["threat_scores"] else 0
                metrics["attacks_per_minute"] = len([e for e in self.real_time_metrics["attack_timeline"] if time.time() - e["timestamp"] < 60])
            
            return metrics
    
    def start_background_tasks(self):
        """Start background tasks for metrics collection"""
        def metrics_collector():
            while True:
                try:
                    time.sleep(60)  # Collect metrics every minute
                    metrics = self.get_real_time_metrics()
                    
                    # Write metrics snapshot
                    with open(self.metrics_log, "a", encoding="utf-8") as f:
                        f.write(json.dumps({
                            "timestamp": time.time(),
                            "metrics": metrics
                        }, ensure_ascii=False, default=str) + "\n")
                    
                    # Store metrics snapshot in database
                    try:
                        with sqlite3.connect(str(self.db_path)) as conn:
                            cursor = conn.cursor()
                            cursor.execute('''
                            INSERT INTO metrics_snapshots (
                                timestamp, total_events, unique_ips, avg_threat_score,
                                top_attack_types, metrics_data
                            ) VALUES (?, ?, ?, ?, ?, ?)
                            ''', (
                                time.time(),
                                metrics["total_events"],
                                metrics["unique_ips"],
                                metrics.get("avg_threat_score", 0),
                                json.dumps(dict(list(metrics["attacks_by_type"].items())[:5])),
                                json.dumps(metrics, default=str)
                            ))
                            conn.commit()
                    except Exception as e:
                        print(f"[!] Metrics database error: {e}")
                        
                except Exception as e:
                    print(f"[!] Metrics collection error: {e}")
        
        # Start metrics collection thread
        metrics_thread = threading.Thread(target=metrics_collector, daemon=True)
        metrics_thread.start()
    
    def _now_iso(self):
        """Get current time in ISO format"""
        return datetime.datetime.utcnow().isoformat() + "Z"

# Global enhanced logger instance
_enhanced_logger = None

def get_enhanced_logger():
    """Get the global enhanced logger instance"""
    global _enhanced_logger
    if _enhanced_logger is None:
        _enhanced_logger = EnhancedLogger()
    return _enhanced_logger

def log_enhanced_event(event: dict):
    """Log an event using the enhanced logger"""
    logger = get_enhanced_logger()
    logger.log_event(event)
