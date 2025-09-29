"""
Simple standalone dashboard for honeypot monitoring.
Works without database or complex dependencies.
"""

from flask import Flask, render_template_string, jsonify
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

app = Flask(__name__)

# Simple HTML template embedded in code
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🍯 Honeypot Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .header {
            background: rgba(255, 255, 255, 0.95);
            padding: 1rem 2rem;
            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
        }
        .header h1 {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 1.8rem;
            color: #2c3e50;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }
        .card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        .card:hover { transform: translateY(-5px); }
        .card h2 { color: #2c3e50; margin-bottom: 1rem; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
        }
        .stat-item {
            text-align: center;
            padding: 1rem;
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            border-radius: 10px;
        }
        .stat-value { font-size: 2rem; font-weight: bold; color: #495057; }
        .stat-label { font-size: 0.9rem; color: #6c757d; margin-top: 0.25rem; }
        .chart-container { position: relative; height: 300px; margin-top: 1rem; }
        .alert { padding: 0.75rem; margin: 0.5rem 0; border-radius: 8px; }
        .alert-info { background: #d1ecf1; border: 1px solid #b6d4ea; color: #0c5460; }
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 0.5rem; }
        .status-healthy { background: #28a745; }
        .loading { text-align: center; color: #6c757d; font-style: italic; }
        .wide-card { grid-column: span 2; }
        @media (max-width: 768px) {
            .wide-card { grid-column: span 1; }
            .container { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🍯 Honeypot Security Dashboard</h1>
    </div>
    
    <div class="container">
        <!-- System Status -->
        <div class="card">
            <h2>📊 System Status</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value" id="totalEvents">-</div>
                    <div class="stat-label">Total Events</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="activeServices">5</div>
                    <div class="stat-label">Services Running</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" id="uptime">-</div>
                    <div class="stat-label">Uptime (hrs)</div>
                </div>
            </div>
        </div>
        
        <!-- Service Health -->
        <div class="card">
            <h2>🔧 Service Health</h2>
            <div id="serviceHealth">
                <div><span class="status-indicator status-healthy"></span><strong>HTTP</strong> - Port 8080</div>
                <div><span class="status-indicator status-healthy"></span><strong>SSH</strong> - Port 2222</div>
                <div><span class="status-indicator status-healthy"></span><strong>FTP</strong> - Port 2121</div>
                <div><span class="status-indicator status-healthy"></span><strong>SMTP</strong> - Port 25</div>
                <div><span class="status-indicator status-healthy"></span><strong>DNS</strong> - Port 53</div>
            </div>
        </div>
        
        <!-- Recent Activity -->
        <div class="card wide-card">
            <h2>🚨 Recent Activity</h2>
            <div id="recentActivity">
                <div class="alert alert-info">Dashboard is monitoring for honeypot events...</div>
                <div class="alert alert-info">Access honeypot services to see real-time data</div>
            </div>
        </div>
        
        <!-- Log Stats -->
        <div class="card">
            <h2>📋 Log Statistics</h2>
            <div id="logStats" class="loading">Loading log data...</div>
        </div>
        
        <!-- Quick Actions -->
        <div class="card">
            <h2>⚡ Quick Actions</h2>
            <div>
                <p><strong>Test HTTP:</strong> curl http://localhost:8080/</p>
                <p><strong>Test SSH:</strong> telnet localhost 2222</p>
                <p><strong>Test FTP:</strong> telnet localhost 2121</p>
                <p><strong>Run Attacks:</strong> python attacker_sim/simulate.py</p>
                <p><strong>View Logs:</strong> tail -f logs/honeypot_events.jsonl</p>
            </div>
        </div>
    </div>
    
    <script>
        function updateDashboard() {
            // Update stats from API
            $.get('/api/simple_stats', function(data) {
                $('#totalEvents').text(data.total_events || 0);
                $('#uptime').text((data.uptime_hours || 0).toFixed(1));
                
                // Update log stats
                if (data.log_stats) {
                    let html = '<div class="stats-grid">';
                    html += `<div class="stat-item"><div class="stat-value">${data.log_stats.file_size_mb}</div><div class="stat-label">Log Size (MB)</div></div>`;
                    html += `<div class="stat-item"><div class="stat-value">${data.log_stats.recent_events}</div><div class="stat-label">Recent Events</div></div>`;
                    html += '</div>';
                    $('#logStats').html(html);
                } else {
                    $('#logStats').html('<div class="alert alert-info">No log data available</div>');
                }
                
                // Update recent activity
                if (data.recent_activity && data.recent_activity.length > 0) {
                    let html = '';
                    data.recent_activity.forEach(function(event) {
                        html += `<div class="alert alert-info">[${event.time}] ${event.description}</div>`;
                    });
                    $('#recentActivity').html(html);
                }
            }).fail(function() {
                $('#logStats').html('<div class="alert alert-info">API unavailable - check if honeypot is running</div>');
            });
        }
        
        // Initialize dashboard
        $(document).ready(function() {
            updateDashboard();
            setInterval(updateDashboard, 30000); // Update every 30 seconds
        });
    </script>
</body>
</html>
"""

def read_log_file():
    """Read honeypot log file and extract basic stats"""
    log_file = Path(__file__).parent.parent.parent / "logs" / "honeypot_events.jsonl"
    
    stats = {
        'total_events': 0,
        'file_size_mb': 0,
        'recent_events': 0,
        'last_event_time': None
    }
    
    try:
        if log_file.exists():
            stats['file_size_mb'] = round(log_file.stat().st_size / (1024 * 1024), 2)
            
            # Read last 100 lines for recent stats
            with open(log_file, 'r') as f:
                lines = f.readlines()
                stats['total_events'] = len(lines)
                
                # Count recent events (last hour)
                one_hour_ago = datetime.now() - timedelta(hours=1)
                recent_count = 0
                recent_events = []
                
                for line in lines[-50:]:  # Check last 50 events
                    try:
                        event = json.loads(line.strip())
                        event_time = datetime.fromisoformat(event.get('logged_at', '').replace('Z', ''))
                        if event_time > one_hour_ago:
                            recent_count += 1
                            recent_events.append({
                                'time': event_time.strftime('%H:%M:%S'),
                                'description': f"{event.get('service', 'unknown')} from {event.get('peer', 'unknown')}"
                            })
                    except:
                        continue
                
                stats['recent_events'] = recent_count
                stats['recent_activity'] = recent_events[-10:]  # Last 10 events
                
                if lines:
                    stats['last_event_time'] = 'Recent'
    
    except Exception as e:
        print(f"Error reading log file: {e}")
    
    return stats

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template_string(DASHBOARD_TEMPLATE)

@app.route('/api/simple_stats')
def api_simple_stats():
    """Simple API endpoint for basic stats"""
    log_stats = read_log_file()
    
    # Calculate uptime (approximate)
    uptime_hours = time.time() % (24 * 3600) / 3600  # Simple uptime simulation
    
    return jsonify({
        'total_events': log_stats['total_events'],
        'uptime_hours': uptime_hours,
        'log_stats': {
            'file_size_mb': log_stats['file_size_mb'],
            'recent_events': log_stats['recent_events']
        },
        'recent_activity': log_stats.get('recent_activity', []),
        'timestamp': datetime.now().isoformat()
    })

def run_simple_dashboard(host='127.0.0.1', port=5123, debug=False):
    """Run the simple dashboard"""
    print(f"[+] Starting Simple Honeypot Dashboard")
    print(f"[+] Access at: http://localhost:{port}")
    print(f"[+] This dashboard works independently of database/metrics")
    
    try:
        app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)
    except Exception as e:
        print(f"[!] Dashboard failed to start: {e}")
        if "Address already in use" in str(e):
            print(f"[!] Port {port} is already in use. Try a different port:")
            print(f"[!] python -c \"from honeypot.services.simple_dashboard import run_simple_dashboard; run_simple_dashboard(port=5001)\"")

if __name__ == '__main__':
    run_simple_dashboard(host='0.0.0.0', debug=True)
