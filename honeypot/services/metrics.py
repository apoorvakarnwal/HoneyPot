"""
Performance metrics and monitoring for honeypot services.
Tracks service health, performance, and attack statistics.
"""

import time
import threading
import psutil
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from honeypot.logger import log_event

@dataclass
class ServiceMetrics:
    """Metrics for a specific honeypot service"""
    service_name: str
    requests_per_minute: float = 0.0
    active_connections: int = 0
    total_requests: int = 0
    error_rate: float = 0.0
    avg_response_time: float = 0.0
    attack_attempts: int = 0
    last_activity: Optional[str] = None

@dataclass
class SystemMetrics:
    """System-level performance metrics"""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_usage_percent: float = 0.0
    network_connections: int = 0
    log_file_size_mb: float = 0.0
    uptime_hours: float = 0.0

class MetricsCollector:
    """Centralized metrics collection and reporting"""
    
    def __init__(self):
        self.start_time = time.time()
        self.request_history = defaultdict(lambda: deque(maxlen=60))  # 60 minutes of data
        self.service_metrics = {}
        self.system_metrics = SystemMetrics()
        self.lock = threading.Lock()
        
        # Attack pattern tracking
        self.attack_trends = defaultdict(lambda: deque(maxlen=24))  # 24 hours
        self.geographic_stats = defaultdict(int)
        self.top_attackers = defaultdict(int)
        
    def record_request(self, service: str, processing_time: float = 0.0, 
                      is_attack: bool = False, attack_types: List[str] = None):
        """Record a service request with timing and attack info"""
        with self.lock:
            current_minute = int(time.time() // 60)
            self.request_history[service].append({
                'timestamp': current_minute,
                'processing_time': processing_time,
                'is_attack': is_attack,
                'attack_types': attack_types or []
            })
            
            # Update service metrics
            if service not in self.service_metrics:
                self.service_metrics[service] = ServiceMetrics(service_name=service)
            
            metrics = self.service_metrics[service]
            metrics.total_requests += 1
            metrics.last_activity = datetime.now().isoformat()
            
            if is_attack:
                metrics.attack_attempts += 1
                for attack_type in (attack_types or []):
                    current_hour = int(time.time() // 3600)
                    self.attack_trends[attack_type].append(current_hour)
    
    def record_connection(self, service: str, connected: bool = True):
        """Track active connections per service"""
        with self.lock:
            if service not in self.service_metrics:
                self.service_metrics[service] = ServiceMetrics(service_name=service)
            
            if connected:
                self.service_metrics[service].active_connections += 1
            else:
                self.service_metrics[service].active_connections = max(0, 
                    self.service_metrics[service].active_connections - 1)
    
    def record_attacker(self, ip: str, country: str = None):
        """Track attacker statistics"""
        with self.lock:
            self.top_attackers[ip] += 1
            if country:
                self.geographic_stats[country] += 1
    
    def calculate_service_metrics(self) -> Dict[str, ServiceMetrics]:
        """Calculate current metrics for all services"""
        with self.lock:
            current_minute = int(time.time() // 60)
            
            for service, metrics in self.service_metrics.items():
                recent_requests = [
                    req for req in self.request_history[service]
                    if req['timestamp'] >= current_minute - 1  # Last minute
                ]
                
                metrics.requests_per_minute = len(recent_requests)
                
                if recent_requests:
                    response_times = [req['processing_time'] for req in recent_requests]
                    metrics.avg_response_time = sum(response_times) / len(response_times)
                    
                    error_count = sum(1 for req in recent_requests if req['processing_time'] > 5.0)
                    metrics.error_rate = error_count / len(recent_requests) if recent_requests else 0
            
            return dict(self.service_metrics)
    
    def calculate_system_metrics(self) -> SystemMetrics:
        """Calculate current system performance metrics"""
        try:
            self.system_metrics.cpu_percent = psutil.cpu_percent(interval=0.1)
            self.system_metrics.memory_percent = psutil.virtual_memory().percent
            self.system_metrics.disk_usage_percent = psutil.disk_usage('/').percent
            self.system_metrics.network_connections = len(psutil.net_connections())
            self.system_metrics.uptime_hours = (time.time() - self.start_time) / 3600
            
            # Log file size
            from honeypot.config import LOG_FILE
            if LOG_FILE.exists():
                self.system_metrics.log_file_size_mb = LOG_FILE.stat().st_size / (1024 * 1024)
        except Exception as e:
            print(f"Error calculating system metrics: {e}")
        
        return self.system_metrics
    
    def get_attack_trends(self) -> Dict[str, List[int]]:
        """Get hourly attack trends for the last 24 hours"""
        with self.lock:
            trends = {}
            current_hour = int(time.time() // 3600)
            
            for attack_type, hours in self.attack_trends.items():
                hourly_counts = [0] * 24
                for hour in hours:
                    if hour >= current_hour - 24:
                        index = hour - (current_hour - 23)
                        if 0 <= index < 24:
                            hourly_counts[index] += 1
                trends[attack_type] = hourly_counts
            
            return trends
    
    def get_geographic_distribution(self) -> Dict[str, int]:
        """Get attack distribution by country"""
        with self.lock:
            return dict(self.geographic_stats)
    
    def get_top_attackers(self, limit: int = 10) -> List[tuple]:
        """Get top attacking IPs"""
        with self.lock:
            return sorted(self.top_attackers.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def export_metrics(self) -> Dict:
        """Export all metrics as JSON-serializable dict"""
        service_metrics = {k: asdict(v) for k, v in self.calculate_service_metrics().items()}
        system_metrics = asdict(self.calculate_system_metrics())
        
        return {
            'timestamp': datetime.now().isoformat(),
            'uptime_hours': system_metrics['uptime_hours'],
            'services': service_metrics,
            'system': system_metrics,
            'attack_trends': self.get_attack_trends(),
            'geographic_distribution': self.get_geographic_distribution(),
            'top_attackers': dict(self.get_top_attackers()),
            'summary': {
                'total_requests': sum(m.total_requests for m in self.service_metrics.values()),
                'total_attacks': sum(m.attack_attempts for m in self.service_metrics.values()),
                'active_connections': sum(m.active_connections for m in self.service_metrics.values()),
                'attack_rate': self._calculate_attack_rate()
            }
        }
    
    def _calculate_attack_rate(self) -> float:
        """Calculate current attack rate (attacks per minute)"""
        total_requests = sum(m.total_requests for m in self.service_metrics.values())
        total_attacks = sum(m.attack_attempts for m in self.service_metrics.values())
        return (total_attacks / max(total_requests, 1)) * 100
    
    def log_metrics(self):
        """Log current metrics to honeypot logs"""
        metrics_data = self.export_metrics()
        log_event({
            'service': 'metrics',
            'event_type': 'metrics_snapshot',
            'metrics': metrics_data
        })

# Global metrics collector instance
metrics_collector = MetricsCollector()

def record_request(service: str, processing_time: float = 0.0, 
                  is_attack: bool = False, attack_types: List[str] = None):
    """Convenience function to record service requests"""
    metrics_collector.record_request(service, processing_time, is_attack, attack_types)

def record_connection(service: str, connected: bool = True):
    """Convenience function to track connections"""
    metrics_collector.record_connection(service, connected)

def record_attacker(ip: str, country: str = None):
    """Convenience function to track attackers"""
    metrics_collector.record_attacker(ip, country)
