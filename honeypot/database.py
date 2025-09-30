"""
Advanced Database Backend for Honeypot Data Storage and Analysis
Provides high-performance storage and querying capabilities
"""

import sqlite3
import json
import time
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import hashlib
import gzip

class HoneypotDatabase:
    def __init__(self, db_path: str = None):
        if db_path is None:
            from honeypot.config import LOG_DIR
            self.db_path = LOG_DIR / "honeypot_advanced.db"
        else:
            self.db_path = Path(db_path)
        
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_database()
        
        # Cache for frequent queries
        self._cache = {}
        self._cache_ttl = {}
        self._cache_timeout = 300  # 5 minutes
        
    def _init_database(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Main events table with enhanced schema
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_hash TEXT UNIQUE,
                timestamp REAL NOT NULL,
                logged_at TEXT,
                service TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                target_port INTEGER,
                threat_score REAL DEFAULT 0,
                attack_sophistication TEXT,
                session_duration REAL,
                geographic_region TEXT,
                attack_indicators TEXT,  -- JSON array
                vulnerability_tests TEXT,  -- JSON array
                attack_vectors TEXT,  -- JSON array
                protocol_compliance TEXT,  -- JSON object
                raw_event_data TEXT,  -- Complete JSON
                processed_at REAL
            )
            ''')
            
            # Attack patterns table for ML training
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_hash TEXT UNIQUE,
                pattern_type TEXT NOT NULL,
                pattern_signature TEXT NOT NULL,
                frequency INTEGER DEFAULT 1,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                threat_level TEXT,
                confidence_score REAL DEFAULT 0,
                false_positive_rate REAL DEFAULT 0,
                geographic_distribution TEXT,  -- JSON
                time_distribution TEXT,  -- JSON
                service_distribution TEXT  -- JSON
            )
            ''')
            
            # Attack sessions for correlation analysis
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_hash TEXT UNIQUE,
                source_ip TEXT NOT NULL,
                start_time REAL NOT NULL,
                end_time REAL,
                duration REAL,
                services_targeted TEXT,  -- JSON array
                total_requests INTEGER DEFAULT 0,
                unique_attack_types INTEGER DEFAULT 0,
                max_threat_score REAL DEFAULT 0,
                attack_progression TEXT,  -- JSON array
                success_indicators TEXT  -- JSON array
            )
            ''')
            
            # Threat intelligence IOCs
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,  -- ip, domain, hash, pattern
                ioc_value TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                source TEXT,
                description TEXT,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                confidence INTEGER DEFAULT 50,
                active BOOLEAN DEFAULT 1
            )
            ''')
            
            # Real-time metrics snapshots
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                metric_type TEXT NOT NULL,
                metric_data TEXT NOT NULL,  -- JSON
                aggregation_period INTEGER  -- seconds
            )
            ''')
            
            # ML model performance tracking
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS ml_models (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL,
                model_version TEXT NOT NULL,
                training_data_hash TEXT,
                accuracy REAL,
                precision_score REAL,
                recall_score REAL,
                f1_score REAL,
                training_time REAL,
                created_at REAL NOT NULL,
                active BOOLEAN DEFAULT 0
            )
            ''')
            
            # Geolocation cache
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS geolocation_cache (
                ip_address TEXT PRIMARY KEY,
                country TEXT,
                region TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                asn INTEGER,
                org TEXT,
                cached_at REAL NOT NULL
            )
            ''')
            
            # Create indexes for performance
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_events_service ON events(service)",
                "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)",
                "CREATE INDEX IF NOT EXISTS idx_events_threat_score ON events(threat_score)",
                "CREATE INDEX IF NOT EXISTS idx_patterns_type ON attack_patterns(pattern_type)",
                "CREATE INDEX IF NOT EXISTS idx_patterns_last_seen ON attack_patterns(last_seen)",
                "CREATE INDEX IF NOT EXISTS idx_iocs_type ON threat_iocs(ioc_type)",
                "CREATE INDEX IF NOT EXISTS idx_iocs_value ON threat_iocs(ioc_value)",
                "CREATE INDEX IF NOT EXISTS idx_sessions_ip ON attack_sessions(source_ip)",
                "CREATE INDEX IF NOT EXISTS idx_sessions_start ON attack_sessions(start_time)"
            ]
            
            for index_sql in indexes:
                try:
                    cursor.execute(index_sql)
                except Exception:
                    pass  # Index might already exist
            
            conn.commit()
    
    def _get_connection(self):
        """Get database connection with optimizations"""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=10000")
        conn.execute("PRAGMA temp_store=MEMORY")
        return conn
    
    def _generate_hash(self, data: str) -> str:
        """Generate hash for data deduplication"""
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def store_event(self, event: Dict[str, Any]) -> bool:
        """Store event with deduplication and validation"""
        try:
            with self._lock:
                # Generate event hash for deduplication
                event_str = json.dumps(event, sort_keys=True, default=str)
                event_hash = self._generate_hash(event_str)
                
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Check if event already exists
                    cursor.execute("SELECT id FROM events WHERE event_hash = ?", (event_hash,))
                    if cursor.fetchone():
                        return False  # Duplicate event
                    
                    # Extract and prepare data
                    timestamp = event.get('timestamp', time.time())
                    if isinstance(timestamp, str):
                        timestamp = datetime.fromisoformat(timestamp.replace('Z', '')).timestamp()
                    
                    # Insert event
                    cursor.execute('''
                    INSERT INTO events (
                        event_hash, timestamp, logged_at, service, source_ip,
                        source_port, target_port, threat_score, attack_sophistication,
                        session_duration, geographic_region, attack_indicators,
                        vulnerability_tests, attack_vectors, protocol_compliance,
                        raw_event_data, processed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        event_hash,
                        timestamp,
                        event.get('logged_at'),
                        event.get('service'),
                        event.get('peer'),
                        event.get('source_port'),
                        event.get('target_port'),
                        event.get('threat_score', 0),
                        event.get('attack_sophistication'),
                        event.get('session_duration'),
                        event.get('estimated_region'),
                        json.dumps(event.get('attack_indicators', [])),
                        json.dumps(event.get('vulnerabilities_tested', [])),
                        json.dumps(event.get('attack_vectors', [])),
                        json.dumps(event.get('protocol_compliance', {})),
                        event_str,
                        time.time()
                    ))
                    
                    conn.commit()
                    return True
                    
        except Exception as e:
            print(f"[!] Database storage error: {e}")
            return False
    
    def store_attack_pattern(self, pattern_type: str, signature: str, 
                           threat_level: str = "medium", confidence: float = 0.5) -> bool:
        """Store or update attack pattern"""
        try:
            with self._lock:
                pattern_hash = self._generate_hash(f"{pattern_type}:{signature}")
                current_time = time.time()
                
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Check if pattern exists
                    cursor.execute("""
                    SELECT id, frequency FROM attack_patterns WHERE pattern_hash = ?
                    """, (pattern_hash,))
                    
                    existing = cursor.fetchone()
                    if existing:
                        # Update existing pattern
                        cursor.execute("""
                        UPDATE attack_patterns 
                        SET frequency = frequency + 1, last_seen = ?, confidence_score = ?
                        WHERE pattern_hash = ?
                        """, (current_time, confidence, pattern_hash))
                    else:
                        # Insert new pattern
                        cursor.execute("""
                        INSERT INTO attack_patterns (
                            pattern_hash, pattern_type, pattern_signature,
                            first_seen, last_seen, threat_level, confidence_score
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (pattern_hash, pattern_type, signature, current_time, 
                             current_time, threat_level, confidence))
                    
                    conn.commit()
                    return True
                    
        except Exception as e:
            print(f"[!] Pattern storage error: {e}")
            return False
    
    def get_attack_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive attack statistics"""
        cache_key = f"stats_{hours}"
        
        # Check cache
        if self._is_cached(cache_key):
            return self._cache[cache_key]
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cutoff_time = time.time() - (hours * 3600)
                
                stats = {}
                
                # Total events
                cursor.execute("SELECT COUNT(*) FROM events WHERE timestamp > ?", (cutoff_time,))
                stats['total_events'] = cursor.fetchone()[0]
                
                # Unique IPs
                cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM events WHERE timestamp > ?", (cutoff_time,))
                stats['unique_ips'] = cursor.fetchone()[0]
                
                # Services targeted
                cursor.execute("""
                SELECT service, COUNT(*) FROM events 
                WHERE timestamp > ? GROUP BY service ORDER BY COUNT(*) DESC
                """, (cutoff_time,))
                stats['services_targeted'] = dict(cursor.fetchall())
                
                # Threat score distribution
                cursor.execute("""
                SELECT 
                    AVG(threat_score) as avg_score,
                    MAX(threat_score) as max_score,
                    COUNT(CASE WHEN threat_score > 7 THEN 1 END) as high_threat_events
                FROM events WHERE timestamp > ?
                """, (cutoff_time,))
                score_stats = cursor.fetchone()
                stats['threat_scores'] = {
                    'average': score_stats[0] or 0,
                    'maximum': score_stats[1] or 0,
                    'high_threat_count': score_stats[2]
                }
                
                # Top attack types
                cursor.execute("""
                SELECT attack_indicators, COUNT(*) FROM events 
                WHERE timestamp > ? AND attack_indicators != '[]' 
                GROUP BY attack_indicators ORDER BY COUNT(*) DESC LIMIT 10
                """, (cutoff_time,))
                attack_data = cursor.fetchall()
                top_attacks = {}
                for indicators_json, count in attack_data:
                    try:
                        indicators = json.loads(indicators_json)
                        for indicator in indicators:
                            top_attacks[indicator] = top_attacks.get(indicator, 0) + count
                    except:
                        continue
                stats['top_attack_types'] = dict(sorted(top_attacks.items(), 
                                                       key=lambda x: x[1], reverse=True)[:10])
                
                # Geographic distribution
                cursor.execute("""
                SELECT geographic_region, COUNT(*) FROM events 
                WHERE timestamp > ? GROUP BY geographic_region
                """, (cutoff_time,))
                stats['geographic_distribution'] = dict(cursor.fetchall())
                
                # Time-based analysis
                cursor.execute("""
                SELECT 
                    strftime('%H', datetime(timestamp, 'unixepoch')) as hour,
                    COUNT(*) 
                FROM events 
                WHERE timestamp > ? 
                GROUP BY hour ORDER BY hour
                """, (cutoff_time,))
                stats['hourly_distribution'] = dict(cursor.fetchall())
                
                # Cache results
                self._cache[cache_key] = stats
                self._cache_ttl[cache_key] = time.time() + self._cache_timeout
                
                return stats
                
        except Exception as e:
            print(f"[!] Statistics query error: {e}")
            return {}
    
    def get_top_attackers(self, limit: int = 20, hours: int = 24) -> List[Dict[str, Any]]:
        """Get top attacking IPs with detailed analysis"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cutoff_time = time.time() - (hours * 3600)
                
                cursor.execute("""
                SELECT 
                    source_ip,
                    COUNT(*) as total_attempts,
                    COUNT(DISTINCT service) as services_targeted,
                    AVG(threat_score) as avg_threat_score,
                    MAX(threat_score) as max_threat_score,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    geographic_region
                FROM events 
                WHERE timestamp > ?
                GROUP BY source_ip 
                ORDER BY total_attempts DESC, max_threat_score DESC
                LIMIT ?
                """, (cutoff_time, limit))
                
                attackers = []
                for row in cursor.fetchall():
                    attacker = {
                        'ip': row[0],
                        'total_attempts': row[1],
                        'services_targeted': row[2],
                        'avg_threat_score': round(row[3] or 0, 2),
                        'max_threat_score': row[4] or 0,
                        'first_seen': datetime.fromtimestamp(row[5]).isoformat(),
                        'last_seen': datetime.fromtimestamp(row[6]).isoformat(),
                        'region': row[7],
                        'duration': row[6] - row[5]
                    }
                    attackers.append(attacker)
                
                return attackers
                
        except Exception as e:
            print(f"[!] Top attackers query error: {e}")
            return []
    
    def search_events(self, filters: Dict[str, Any], limit: int = 100) -> List[Dict[str, Any]]:
        """Advanced event search with filters"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Build dynamic query
                where_clauses = []
                params = []
                
                if 'service' in filters:
                    where_clauses.append("service = ?")
                    params.append(filters['service'])
                
                if 'source_ip' in filters:
                    where_clauses.append("source_ip = ?")
                    params.append(filters['source_ip'])
                
                if 'min_threat_score' in filters:
                    where_clauses.append("threat_score >= ?")
                    params.append(filters['min_threat_score'])
                
                if 'attack_type' in filters:
                    where_clauses.append("attack_indicators LIKE ?")
                    params.append(f'%"{filters["attack_type"]}"%')
                
                if 'time_range' in filters:
                    start_time, end_time = filters['time_range']
                    where_clauses.append("timestamp BETWEEN ? AND ?")
                    params.extend([start_time, end_time])
                
                where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
                
                query = f"""
                SELECT * FROM events 
                WHERE {where_sql}
                ORDER BY timestamp DESC 
                LIMIT ?
                """
                params.append(limit)
                
                cursor.execute(query, params)
                
                events = []
                for row in cursor.fetchall():
                    event = {
                        'id': row[0],
                        'timestamp': row[2],
                        'service': row[4],
                        'source_ip': row[5],
                        'threat_score': row[7],
                        'attack_indicators': json.loads(row[12] or '[]'),
                        'vulnerability_tests': json.loads(row[13] or '[]'),
                        'raw_data': json.loads(row[16] or '{}')
                    }
                    events.append(event)
                
                return events
                
        except Exception as e:
            print(f"[!] Event search error: {e}")
            return []
    
    def get_ml_training_data(self, attack_type: str = None, limit: int = 10000) -> List[Dict[str, Any]]:
        """Get training data for ML models"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                where_clause = ""
                params = []
                
                if attack_type:
                    where_clause = "WHERE attack_indicators LIKE ?"
                    params.append(f'%"{attack_type}"%')
                
                query = f"""
                SELECT 
                    service, source_ip, threat_score, attack_sophistication,
                    attack_indicators, vulnerability_tests, attack_vectors,
                    session_duration, geographic_region
                FROM events 
                {where_clause}
                ORDER BY RANDOM() 
                LIMIT ?
                """
                params.append(limit)
                
                cursor.execute(query, params)
                
                training_data = []
                for row in cursor.fetchall():
                    data = {
                        'service': row[0],
                        'source_ip': row[1],
                        'threat_score': row[2],
                        'attack_sophistication': row[3],
                        'attack_indicators': json.loads(row[4] or '[]'),
                        'vulnerability_tests': json.loads(row[5] or '[]'),
                        'attack_vectors': json.loads(row[6] or '[]'),
                        'session_duration': row[7],
                        'geographic_region': row[8]
                    }
                    training_data.append(data)
                
                return training_data
                
        except Exception as e:
            print(f"[!] ML training data error: {e}")
            return []
    
    def _is_cached(self, key: str) -> bool:
        """Check if data is cached and not expired"""
        return (key in self._cache and 
                key in self._cache_ttl and 
                time.time() < self._cache_ttl[key])
    
    def cleanup_old_data(self, days: int = 30):
        """Clean up old data to maintain performance"""
        try:
            with self._lock:
                cutoff_time = time.time() - (days * 24 * 3600)
                
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Archive old events before deletion
                    cursor.execute("SELECT COUNT(*) FROM events WHERE timestamp < ?", (cutoff_time,))
                    old_count = cursor.fetchone()[0]
                    
                    if old_count > 0:
                        print(f"[*] Archiving {old_count} old events...")
                        
                        # Delete old events
                        cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_time,))
                        
                        # Clean up patterns
                        cursor.execute("DELETE FROM attack_patterns WHERE last_seen < ?", (cutoff_time,))
                        
                        # Vacuum database
                        cursor.execute("VACUUM")
                        
                        conn.commit()
                        print(f"[*] Cleanup complete, removed {old_count} old records")
                
        except Exception as e:
            print(f"[!] Cleanup error: {e}")
    
    def export_data(self, format_type: str = "json", filename: str = None) -> str:
        """Export data for analysis or backup"""
        try:
            if filename is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"honeypot_export_{timestamp}.{format_type}"
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM events ORDER BY timestamp DESC")
                
                if format_type == "json":
                    # Export as JSON
                    events = []
                    for row in cursor.fetchall():
                        event = {
                            'id': row[0],
                            'timestamp': row[2],
                            'service': row[4],
                            'source_ip': row[5],
                            'threat_score': row[7],
                            'raw_data': json.loads(row[16] or '{}')
                        }
                        events.append(event)
                    
                    with open(filename, 'w') as f:
                        json.dump(events, f, indent=2, default=str)
                
                elif format_type == "csv":
                    # Export as CSV
                    import csv
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['timestamp', 'service', 'source_ip', 'threat_score', 'attack_indicators'])
                        
                        for row in cursor.fetchall():
                            writer.writerow([row[2], row[4], row[5], row[7], row[12]])
                
                return filename
                
        except Exception as e:
            print(f"[!] Export error: {e}")
            return ""

# Global database instance
_honeypot_db = None

def get_database() -> HoneypotDatabase:
    """Get global database instance"""
    global _honeypot_db
    if _honeypot_db is None:
        _honeypot_db = HoneypotDatabase()
    return _honeypot_db
