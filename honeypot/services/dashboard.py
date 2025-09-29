"""
Web dashboard for honeypot monitoring and visualization.
Provides real-time attack analytics, metrics, and system health monitoring.
"""

from flask import Flask, render_template, jsonify, request
import json
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
import os

try:
    from honeypot.database import database
    from honeypot.services.metrics import metrics_collector
    from honeypot.config import LOG_FILE
except ImportError:
    # Fallback for standalone testing
    database = None
    metrics_collector = None
    LOG_FILE = None

# Create Flask app with proper template path
template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

# Configure Flask for security
app.config['SECRET_KEY'] = 'honeypot-dashboard-secret-key-change-in-production'
app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for API endpoints

class DashboardData:
    """Data provider for dashboard visualizations"""
    
    def __init__(self):
        self.cache = {}
        self.cache_timeout = 30  # seconds
        self.last_update = {}
    
    def _is_cache_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        return (key in self.last_update and 
                time.time() - self.last_update[key] < self.cache_timeout)
    
    def _update_cache(self, key: str, data: Any):
        """Update cache with new data"""
        self.cache[key] = data
        self.last_update[key] = time.time()
    
    def get_real_time_stats(self) -> Dict[str, Any]:
        """Get real-time statistics for dashboard"""
        if self._is_cache_valid('real_time_stats'):
            return self.cache['real_time_stats']
        
        stats = {
            'timestamp': datetime.now().isoformat(),
            'total_attacks_today': 0,
            'active_sessions': 0,
            'top_attack_types': [],
            'attack_rate_per_hour': [{'hour': i, 'attacks': 0} for i in range(24)],
            'geographic_distribution': {},
            'service_status': {
                'http': {'status': 'healthy', 'requests_per_minute': 0, 'active_connections': 0, 'attack_attempts': 0, 'last_activity': None},
                'ssh': {'status': 'healthy', 'requests_per_minute': 0, 'active_connections': 0, 'attack_attempts': 0, 'last_activity': None},
                'ftp': {'status': 'healthy', 'requests_per_minute': 0, 'active_connections': 0, 'attack_attempts': 0, 'last_activity': None},
                'smtp': {'status': 'healthy', 'requests_per_minute': 0, 'active_connections': 0, 'attack_attempts': 0, 'last_activity': None},
                'dns': {'status': 'healthy', 'requests_per_minute': 0, 'active_connections': 0, 'attack_attempts': 0, 'last_activity': None}
            },
            'system_health': {
                'cpu_percent': 0.0,
                'memory_percent': 0.0,
                'disk_usage_percent': 0.0,
                'uptime_hours': 0.0
            }
        }
        
        try:
            # Get database statistics if available
            if database:
                db_stats = database.get_attack_statistics(hours=24)
                stats['total_attacks_today'] = db_stats.get('total_attacks', 0)
                stats['top_attack_types'] = [
                    {'name': k, 'count': v} 
                    for k, v in list(db_stats.get('attack_types', {}).items())[:5]
                ]
                stats['geographic_distribution'] = db_stats.get('attacks_by_country', {})
            
            # Get metrics if available
            if metrics_collector:
                service_metrics = metrics_collector.calculate_service_metrics()
                system_metrics = metrics_collector.calculate_system_metrics()
                
                stats['active_sessions'] = sum(
                    m.active_connections for m in service_metrics.values()
                )
                
                stats['service_status'] = {
                    name: {
                        'status': 'healthy' if m.requests_per_minute >= 0 else 'error',
                        'requests_per_minute': m.requests_per_minute,
                        'active_connections': m.active_connections,
                        'attack_attempts': m.attack_attempts,
                        'last_activity': m.last_activity
                    }
                    for name, m in service_metrics.items()
                }
                
                stats['system_health'] = {
                    'cpu_percent': system_metrics.cpu_percent,
                    'memory_percent': system_metrics.memory_percent,
                    'disk_usage_percent': system_metrics.disk_usage_percent,
                    'uptime_hours': system_metrics.uptime_hours
                }
                
                # Get attack trends
                attack_trends = metrics_collector.get_attack_trends()
                stats['attack_rate_per_hour'] = [
                    {'hour': i, 'attacks': sum(hourly_data[i] for hourly_data in attack_trends.values())}
                    for i in range(24)
                ]
        
        except Exception as e:
            print(f"Error getting real-time stats: {e}")
        
        self._update_cache('real_time_stats', stats)
        return stats
    
    def get_attack_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get attack timeline for the specified hours"""
        cache_key = f'attack_timeline_{hours}'
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]
        
        timeline = []
        
        try:
            if database:
                since = datetime.now() - timedelta(hours=hours)
                events = database.get_events(limit=500, since=since, attack_only=True)
                
                timeline = [
                    {
                        'timestamp': event.timestamp,
                        'service': event.service,
                        'source_ip': event.source_ip,
                        'attack_types': event.attack_types,
                        'severity': event.severity,
                        'method': event.method,
                        'path': event.path,
                        'country': event.country
                    }
                    for event in events
                ]
        except Exception as e:
            print(f"Error getting attack timeline: {e}")
        
        self._update_cache(cache_key, timeline)
        return timeline
    
    def get_threat_intelligence(self) -> Dict[str, Any]:
        """Get threat intelligence summary"""
        if self._is_cache_valid('threat_intelligence'):
            return self.cache['threat_intelligence']
        
        intelligence = {
            'top_malicious_ips': [],
            'emerging_threats': [],
            'attack_patterns': {},
            'risk_assessment': 'low'
        }
        
        try:
            if database:
                # Get top attacking IPs with reputation scores
                conn = database._get_connection()
                try:
                    cur = conn.cursor()
                    placeholder = "?" if database.db_type == "sqlite" else "%s"
                    
                    cur.execute(f"""
                        SELECT ip_address, attack_count, reputation_score, country, threat_types
                        FROM ip_reputation 
                        WHERE attack_count > 0
                        ORDER BY reputation_score DESC, attack_count DESC
                        LIMIT 10
                    """)
                    
                    for row in cur.fetchall():
                        intelligence['top_malicious_ips'].append({
                            'ip': row[0],
                            'attack_count': row[1],
                            'reputation_score': row[2],
                            'country': row[3] or 'Unknown',
                            'threat_types': json.loads(row[4] or '[]')
                        })
                    
                    # Calculate risk assessment
                    total_attacks = sum(ip['attack_count'] for ip in intelligence['top_malicious_ips'])
                    if total_attacks > 100:
                        intelligence['risk_assessment'] = 'high'
                    elif total_attacks > 50:
                        intelligence['risk_assessment'] = 'medium'
                    
                finally:
                    conn.close()
                    
        except Exception as e:
            print(f"Error getting threat intelligence: {e}")
        
        self._update_cache('threat_intelligence', intelligence)
        return intelligence

dashboard_data = DashboardData()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    """API endpoint for real-time statistics"""
    return jsonify(dashboard_data.get_real_time_stats())

@app.route('/api/timeline')
def api_timeline():
    """API endpoint for attack timeline"""
    hours = request.args.get('hours', 24, type=int)
    return jsonify(dashboard_data.get_attack_timeline(hours))

@app.route('/api/threats')
def api_threats():
    """API endpoint for threat intelligence"""
    return jsonify(dashboard_data.get_threat_intelligence())

@app.route('/api/metrics')
def api_metrics():
    """API endpoint for system metrics"""
    if metrics_collector:
        return jsonify(metrics_collector.export_metrics())
    return jsonify({'error': 'Metrics not available'})

@app.route('/api/services/<service_name>')
def api_service_details(service_name):
    """API endpoint for specific service details"""
    try:
        if database:
            events = database.get_events(limit=100, service=service_name)
            return jsonify([
                {
                    'timestamp': event.timestamp,
                    'source_ip': event.source_ip,
                    'attack_types': event.attack_types,
                    'method': event.method,
                    'path': event.path,
                    'response_code': event.response_code
                }
                for event in events
            ])
    except Exception as e:
        return jsonify({'error': str(e)})
    
    return jsonify([])

def run_dashboard(host='0.0.0.0', port=5000, debug=False):
    """Run the dashboard web server"""
    print(f"[+] Starting honeypot dashboard on http://{host}:{port}")
    print(f"[+] Access dashboard at: http://localhost:{port}")
    try:
        app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)
    except Exception as e:
        print(f"[!] Dashboard failed to start: {e}")
        print(f"[!] Try checking if port {port} is already in use")

if __name__ == '__main__':
    run_dashboard(debug=True)
