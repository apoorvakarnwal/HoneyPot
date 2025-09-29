"""
Database integration for honeypot event storage and querying.
Provides both SQLite (default) and PostgreSQL support for production.
"""

import sqlite3
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from pathlib import Path
import os

from honeypot.config import BASE_DIR

@dataclass
class AttackEvent:
    """Structured representation of an attack event"""
    id: Optional[int] = None
    timestamp: str = ""
    service: str = ""
    source_ip: str = ""
    attack_types: List[str] = None
    severity: str = "low"
    method: str = ""
    path: str = ""
    headers: Dict[str, str] = None
    body: str = ""
    response_code: int = 0
    session_id: str = ""
    country: str = ""
    user_agent: str = ""
    raw_data: Dict[str, Any] = None

class HoneypotDatabase:
    """Database abstraction layer for honeypot events"""
    
    def __init__(self, db_type: str = "sqlite", connection_string: str = None):
        self.db_type = db_type
        self.connection_string = connection_string or self._get_default_connection()
        self.lock = threading.Lock()
        self._initialize_database()
    
    def _get_default_connection(self) -> str:
        """Get default connection string based on db_type"""
        if self.db_type == "sqlite":
            db_path = BASE_DIR / "logs" / "honeypot.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            return str(db_path)
        elif self.db_type == "postgresql":
            return os.getenv("DATABASE_URL", "postgresql://honeypot:password@localhost/honeypot")
        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")
    
    def _get_connection(self):
        """Get database connection based on type"""
        if self.db_type == "sqlite":
            return sqlite3.connect(self.connection_string, timeout=30.0)
        elif self.db_type == "postgresql":
            try:
                import psycopg2
                import psycopg2.extras
                return psycopg2.connect(self.connection_string)
            except ImportError:
                print("[!] PostgreSQL support requires psycopg2-binary. Falling back to SQLite.")
                self.db_type = "sqlite"
                self.connection_string = self._get_default_connection()
                return sqlite3.connect(self.connection_string, timeout=30.0)
        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")
    
    def _initialize_database(self):
        """Create database tables if they don't exist"""
        with self.lock:
            conn = self._get_connection()
            try:
                if self.db_type == "sqlite":
                    self._create_sqlite_tables(conn)
                elif self.db_type == "postgresql":
                    self._create_postgresql_tables(conn)
                conn.commit()
            finally:
                conn.close()
    
    def _create_sqlite_tables(self, conn):
        """Create SQLite tables"""
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS attack_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                service TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                attack_types TEXT,  -- JSON array
                severity TEXT DEFAULT 'low',
                method TEXT,
                path TEXT,
                headers TEXT,  -- JSON object
                body TEXT,
                response_code INTEGER,
                session_id TEXT,
                country TEXT,
                user_agent TEXT,
                raw_data TEXT,  -- JSON object
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_timestamp ON attack_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_source_ip ON attack_events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_service ON attack_events(service);
            CREATE INDEX IF NOT EXISTS idx_attack_types ON attack_events(attack_types);
            
            CREATE TABLE IF NOT EXISTS session_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                requests_per_minute REAL,
                active_connections INTEGER,
                attack_rate REAL,
                response_time_avg REAL,
                error_rate REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                cpu_percent REAL,
                memory_percent REAL,
                disk_usage_percent REAL,
                network_connections INTEGER,
                log_file_size_mb REAL,
                uptime_hours REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip_address TEXT PRIMARY KEY,
                country TEXT,
                is_malicious BOOLEAN DEFAULT FALSE,
                threat_types TEXT,  -- JSON array
                first_seen TEXT,
                last_seen TEXT,
                attack_count INTEGER DEFAULT 0,
                reputation_score INTEGER DEFAULT 0  -- 0-100, higher = more malicious
            );
        """)
    
    def _create_postgresql_tables(self, conn):
        """Create PostgreSQL tables"""
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS attack_events (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP NOT NULL,
                    service VARCHAR(50) NOT NULL,
                    source_ip INET NOT NULL,
                    attack_types JSONB,
                    severity VARCHAR(20) DEFAULT 'low',
                    method VARCHAR(10),
                    path TEXT,
                    headers JSONB,
                    body TEXT,
                    response_code INTEGER,
                    session_id VARCHAR(100),
                    country VARCHAR(2),
                    user_agent TEXT,
                    raw_data JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX IF NOT EXISTS idx_attack_events_timestamp ON attack_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_attack_events_source_ip ON attack_events(source_ip);
                CREATE INDEX IF NOT EXISTS idx_attack_events_service ON attack_events(service);
                CREATE INDEX IF NOT EXISTS idx_attack_events_attack_types ON attack_events USING GIN(attack_types);
                
                CREATE TABLE IF NOT EXISTS session_metrics (
                    id SERIAL PRIMARY KEY,
                    service VARCHAR(50) NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    requests_per_minute REAL,
                    active_connections INTEGER,
                    attack_rate REAL,
                    response_time_avg REAL,
                    error_rate REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP NOT NULL,
                    cpu_percent REAL,
                    memory_percent REAL,
                    disk_usage_percent REAL,
                    network_connections INTEGER,
                    log_file_size_mb REAL,
                    uptime_hours REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip_address INET PRIMARY KEY,
                    country VARCHAR(2),
                    is_malicious BOOLEAN DEFAULT FALSE,
                    threat_types JSONB,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    attack_count INTEGER DEFAULT 0,
                    reputation_score INTEGER DEFAULT 0
                );
            """)
    
    def insert_attack_event(self, event: AttackEvent) -> int:
        """Insert an attack event and return the ID"""
        with self.lock:
            conn = self._get_connection()
            try:
                if self.db_type == "sqlite":
                    cur = conn.cursor()
                    cur.execute("""
                        INSERT INTO attack_events 
                        (timestamp, service, source_ip, attack_types, severity, method, path, 
                         headers, body, response_code, session_id, country, user_agent, raw_data)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.timestamp, event.service, event.source_ip,
                        json.dumps(event.attack_types or []), event.severity,
                        event.method, event.path, json.dumps(event.headers or {}),
                        event.body, event.response_code, event.session_id,
                        event.country, event.user_agent, json.dumps(event.raw_data or {})
                    ))
                    event_id = cur.lastrowid
                elif self.db_type == "postgresql":
                    with conn.cursor() as cur:
                        cur.execute("""
                            INSERT INTO attack_events 
                            (timestamp, service, source_ip, attack_types, severity, method, path, 
                             headers, body, response_code, session_id, country, user_agent, raw_data)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            RETURNING id
                        """, (
                            event.timestamp, event.service, event.source_ip,
                            json.dumps(event.attack_types or []), event.severity,
                            event.method, event.path, json.dumps(event.headers or {}),
                            event.body, event.response_code, event.session_id,
                            event.country, event.user_agent, json.dumps(event.raw_data or {})
                        ))
                        event_id = cur.fetchone()[0]
                
                conn.commit()
                return event_id
            finally:
                conn.close()
    
    def get_events(self, limit: int = 100, service: str = None, 
                   since: datetime = None, attack_only: bool = False) -> List[AttackEvent]:
        """Retrieve attack events with optional filtering"""
        with self.lock:
            conn = self._get_connection()
            try:
                query = "SELECT * FROM attack_events"
                params = []
                conditions = []
                
                if service:
                    conditions.append("service = ?")
                    params.append(service)
                
                if since:
                    conditions.append("timestamp >= ?")
                    params.append(since.isoformat())
                
                if attack_only:
                    conditions.append("attack_types != '[]' AND attack_types IS NOT NULL")
                
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                if self.db_type == "postgresql":
                    query = query.replace("?", "%s")
                
                cur = conn.cursor()
                cur.execute(query, params)
                rows = cur.fetchall()
                
                events = []
                for row in rows:
                    events.append(AttackEvent(
                        id=row[0], timestamp=row[1], service=row[2], source_ip=row[3],
                        attack_types=json.loads(row[4] or "[]"), severity=row[5],
                        method=row[6], path=row[7], headers=json.loads(row[8] or "{}"),
                        body=row[9], response_code=row[10], session_id=row[11],
                        country=row[12], user_agent=row[13], raw_data=json.loads(row[14] or "{}")
                    ))
                
                return events
            finally:
                conn.close()
    
    def get_attack_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get attack statistics for the specified time period"""
        since = datetime.now() - timedelta(hours=hours)
        
        with self.lock:
            conn = self._get_connection()
            try:
                cur = conn.cursor()
                
                # Total attacks by type
                placeholder = "?" if self.db_type == "sqlite" else "%s"
                cur.execute(f"""
                    SELECT attack_types, COUNT(*) as count
                    FROM attack_events 
                    WHERE timestamp >= {placeholder} AND attack_types != '[]'
                    GROUP BY attack_types
                    ORDER BY count DESC
                """, (since.isoformat(),))
                
                attack_types = {}
                for row in cur.fetchall():
                    types = json.loads(row[0] or "[]")
                    for attack_type in types:
                        attack_types[attack_type] = attack_types.get(attack_type, 0) + row[1]
                
                # Top attacking IPs
                cur.execute(f"""
                    SELECT source_ip, COUNT(*) as count
                    FROM attack_events 
                    WHERE timestamp >= {placeholder}
                    GROUP BY source_ip
                    ORDER BY count DESC
                    LIMIT 10
                """, (since.isoformat(),))
                top_ips = dict(cur.fetchall())
                
                # Attacks by service
                cur.execute(f"""
                    SELECT service, COUNT(*) as count
                    FROM attack_events 
                    WHERE timestamp >= {placeholder} AND attack_types != '[]'
                    GROUP BY service
                """, (since.isoformat(),))
                by_service = dict(cur.fetchall())
                
                return {
                    'period_hours': hours,
                    'attack_types': attack_types,
                    'top_attacking_ips': top_ips,
                    'attacks_by_service': by_service,
                    'total_attacks': sum(attack_types.values()),
                    'unique_attackers': len(top_ips)
                }
            finally:
                conn.close()
    
    def update_ip_reputation(self, ip: str, country: str = None, 
                           is_malicious: bool = False, threat_types: List[str] = None):
        """Update IP reputation information"""
        with self.lock:
            conn = self._get_connection()
            try:
                placeholder = "?" if self.db_type == "sqlite" else "%s"
                
                # Check if IP exists
                cur = conn.cursor()
                cur.execute(f"SELECT attack_count FROM ip_reputation WHERE ip_address = {placeholder}", (ip,))
                row = cur.fetchone()
                
                now = datetime.now().isoformat()
                
                if row:
                    # Update existing
                    attack_count = row[0] + 1
                    reputation_score = min(100, attack_count * 5)  # Simple scoring
                    
                    cur.execute(f"""
                        UPDATE ip_reputation 
                        SET last_seen = {placeholder}, attack_count = {placeholder}, 
                            reputation_score = {placeholder}, is_malicious = {placeholder}
                        WHERE ip_address = {placeholder}
                    """, (now, attack_count, reputation_score, is_malicious, ip))
                else:
                    # Insert new
                    cur.execute(f"""
                        INSERT INTO ip_reputation 
                        (ip_address, country, is_malicious, threat_types, 
                         first_seen, last_seen, attack_count, reputation_score)
                        VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, 
                                {placeholder}, {placeholder}, 1, 5)
                    """, (ip, country, is_malicious, json.dumps(threat_types or []), 
                          now, now))
                
                conn.commit()
            finally:
                conn.close()

# Global database instance
database = HoneypotDatabase()

def log_to_database(event_data: Dict[str, Any]):
    """Convert honeypot log event to database record"""
    try:
        attack_event = AttackEvent(
            timestamp=event_data.get('logged_at', datetime.now().isoformat()),
            service=event_data.get('service', ''),
            source_ip=event_data.get('peer', ''),
            attack_types=event_data.get('attack_indicators', []),
            method=event_data.get('method', ''),
            path=event_data.get('path', ''),
            headers=event_data.get('headers', {}),
            body=event_data.get('body', ''),
            response_code=event_data.get('response_code', 0),
            user_agent=event_data.get('headers', {}).get('User-Agent', ''),
            raw_data=event_data
        )
        
        # Determine severity based on attack types
        if attack_event.attack_types:
            critical_attacks = ['command_injection', 'sql_injection', 'lfi_attempt']
            if any(attack in critical_attacks for attack in attack_event.attack_types):
                attack_event.severity = 'critical'
            elif len(attack_event.attack_types) > 2:
                attack_event.severity = 'high'
            else:
                attack_event.severity = 'medium'
        
        event_id = database.insert_attack_event(attack_event)
        
        # Update IP reputation
        if attack_event.source_ip and attack_event.attack_types:
            database.update_ip_reputation(
                attack_event.source_ip,
                is_malicious=len(attack_event.attack_types) > 0,
                threat_types=attack_event.attack_types
            )
        
        return event_id
    except Exception as e:
        print(f"Error logging to database: {e}")
        return None
