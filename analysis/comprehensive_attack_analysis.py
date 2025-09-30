#!/usr/bin/env python3
"""
Comprehensive Attack Analysis Suite
Analyzes honeypot logs with multiple visualization types and detailed insights
"""

import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import urllib.parse
import re
from pathlib import Path
import sys

# Set style for better looking plots
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

class ComprehensiveAttackAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.events = []
        self.df = None
        self.load_logs()
        
    def load_logs(self):
        """Load and parse honeypot logs"""
        print(f"Loading logs from {self.log_file}...")
        try:
            with open(self.log_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        event = json.loads(line.strip())
                        if event:
                            self.events.append(event)
                    except json.JSONDecodeError as e:
                        print(f"Warning: Skipping malformed JSON on line {line_num}: {e}")
            print(f"Loaded {len(self.events)} events")
            self.create_dataframe()
        except FileNotFoundError:
            print(f"Error: Log file {self.log_file} not found")
            sys.exit(1)
    
    def create_dataframe(self):
        """Convert events to pandas DataFrame for easier analysis"""
        processed_events = []
        
        for event in self.events:
            processed_event = {
                'service': event.get('service', 'unknown'),
                'peer_ip': event.get('peer', 'unknown'),
                'timestamp': self.parse_timestamp(event),
                'logged_at': event.get('logged_at'),
                'raw_event': event
            }
            
            # Service-specific processing
            if event.get('service') == 'http':
                processed_event.update({
                    'http_method': event.get('method'),
                    'http_path': event.get('path'),
                    'response_code': event.get('response_code'),
                    'user_agent': event.get('headers', {}).get('User-Agent', ''),
                    'attack_indicators': event.get('attack_indicators', []),
                    'body_length': len(event.get('body', '')),
                    'has_body': bool(event.get('body', '').strip()),
                })
                
                # Detect attack types from HTTP data
                processed_event['attack_type'] = self.classify_http_attack(event)
                
            elif event.get('service') == 'ssh-like':
                processed_event.update({
                    'ssh_banner': event.get('banner'),
                    'connection_duration': event.get('end_ts', 0) - event.get('start_ts', 0),
                    'attack_type': 'ssh_probe'
                })
                
            elif event.get('service') == 'ftp':
                processed_event.update({
                    'ftp_auth_attempts': len(event.get('auth_attempts', [])),
                    'ftp_authenticated': event.get('authenticated', False),
                    'connection_duration': event.get('duration', 0),
                    'attack_type': 'ftp_probe'
                })
            
            processed_events.append(processed_event)
        
        self.df = pd.DataFrame(processed_events)
        if not self.df.empty and 'timestamp' in self.df.columns:
            self.df = self.df.sort_values('timestamp').reset_index(drop=True)
        print(f"Created DataFrame with {len(self.df)} processed events")
    
    def parse_timestamp(self, event):
        """Parse timestamp from various formats"""
        if 'timestamp' in event:
            return datetime.fromtimestamp(event['timestamp'])
        elif 'start_ts' in event:
            return datetime.fromtimestamp(event['start_ts'])
        elif 'logged_at' in event:
            try:
                return datetime.fromisoformat(event['logged_at'].replace('Z', '+00:00'))
            except:
                pass
        return datetime.now()
    
    def classify_http_attack(self, event):
        """Classify HTTP attacks based on path, method, and body content"""
        path = event.get('path', '').lower()
        method = event.get('method', '').upper()
        body = event.get('body', '').lower()
        headers = event.get('headers', {})
        attack_indicators = event.get('attack_indicators', [])
        
        # Use attack indicators if available (from enhanced detection)
        if attack_indicators:
            primary_indicator = attack_indicators[0]  # Use the first/primary indicator
            indicator_mapping = {
                'sql_injection': 'sql_injection',
                'xss_attempt': 'xss_attempt',
                'directory_traversal': 'directory_traversal',
                'malware_attempt': 'webshell_attempt',
                'scanner_tool': 'automated_scanning',
                'api_probe': 'api_attack',
                'iot_exploit': 'iot_exploitation',
                'evasion_technique': 'evasion_attempt',
                'suspicious_headers': 'header_manipulation',
                'jwt_manipulation': 'authentication_bypass',
                'command_injection': 'command_injection',
                'ldap_injection': 'ldap_injection',
                'nosql_injection': 'nosql_injection'
            }
            return indicator_mapping.get(primary_indicator, 'advanced_attack')
        
        # Fallback to original classification logic
        # Enhanced SQL Injection patterns
        sql_patterns = ['union select', 'or 1=1', 'drop table', 'information_schema', 
                       'union all select', 'concat(', 'group_concat(', 'waitfor delay']
        if any(pattern in body or pattern in path for pattern in sql_patterns):
            return 'sql_injection'
        
        # Enhanced XSS patterns
        xss_patterns = ['<script', 'alert(', 'javascript:', '<img', '<iframe', 
                       '<object', '<embed', '<svg', 'onerror=', 'onload=']
        if any(pattern in path + body for pattern in xss_patterns):
            return 'xss_attempt'
        
        # Enhanced directory traversal
        traversal_patterns = ['../', '..\\', '%2e%2e', '%252e%252e', '%c0%ae%c0%ae']
        if any(pattern in path for pattern in traversal_patterns):
            return 'directory_traversal'
        
        # API attack detection
        api_patterns = ['/api/', '/graphql', '/swagger', '/openapi', '/actuator/', '/rest/api']
        if any(pattern in path for pattern in api_patterns):
            return 'api_attack'
        
        # IoT exploitation
        iot_patterns = ['/cgi-bin/', '/goform/', '/web/cgi-bin/', '/setup/', '/upnp/']
        if any(pattern in path for pattern in iot_patterns):
            return 'iot_exploitation'
        
        # Command injection
        cmd_patterns = ['; cat', '| cat', '& cat', '$(', '`', '&& cat']
        if any(pattern in body or pattern in path for pattern in cmd_patterns):
            return 'command_injection'
        
        # Admin panel discovery
        admin_patterns = ['/admin', '/administrator', '/wp-admin', '/phpmyadmin', '/management']
        if any(pattern in path for pattern in admin_patterns):
            return 'admin_discovery'
        
        # Config file discovery
        config_patterns = ['.env', 'config.php', 'wp-config', '.conf', 'configuration.php']
        if any(pattern in path for pattern in config_patterns):
            return 'config_discovery'
        
        # Advanced webshell attempts
        shell_patterns = ['shell.php', 'cmd.php', 'webshell', 'backdoor', 'c99.php', 
                         'r57.php', 'wso.php', 'b374k.php', 'shell.jsp', 'cmd.asp']
        if any(pattern in path for pattern in shell_patterns):
            return 'webshell_attempt'
        
        # Evasion techniques
        evasion_patterns = ['%00', '%0d%0a', '%252e', '%252f', '%c0%ae']
        if any(pattern in path for pattern in evasion_patterns):
            return 'evasion_attempt'
        
        # Scanner detection via User-Agent
        user_agent = headers.get('User-Agent', '').lower()
        scanner_agents = ['nmap', 'masscan', 'sqlmap', 'nikto', 'dirb', 'gobuster', 
                         'metasploit', 'mirai-botnet', 'iot-scanner']
        if any(agent in user_agent for agent in scanner_agents):
            return 'automated_scanning'
        
        # Brute force login
        if method == 'POST' and '/login' in path:
            return 'brute_force_login'
        
        # General reconnaissance
        if path in ['/', '/robots.txt', '/sitemap.xml']:
            return 'reconnaissance'
        
        return 'general_probe'
    
    def generate_attack_timeline(self):
        """Generate attack timeline visualization"""
        if self.df.empty:
            print("No data available for timeline analysis")
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Attack Timeline Analysis', fontsize=16, fontweight='bold')
        
        # 1. Attacks over time
        self.df['hour'] = self.df['timestamp'].dt.hour
        self.df['minute'] = self.df['timestamp'].dt.minute
        
        # Timeline by service
        service_timeline = self.df.groupby(['service', pd.Grouper(key='timestamp', freq='1Min')]).size().unstack(level=0, fill_value=0)
        service_timeline.plot(ax=axes[0, 0], kind='line', marker='o')
        axes[0, 0].set_title('Attack Frequency by Service Over Time')
        axes[0, 0].set_xlabel('Time')
        axes[0, 0].set_ylabel('Number of Attacks')
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)
        
        # 2. Attack types over time
        if 'attack_type' in self.df.columns:
            attack_counts = self.df.groupby(['attack_type', pd.Grouper(key='timestamp', freq='1Min')]).size().unstack(level=0, fill_value=0)
            attack_counts.plot(ax=axes[0, 1], kind='area', stacked=True, alpha=0.7)
            axes[0, 1].set_title('Attack Types Distribution Over Time')
            axes[0, 1].set_xlabel('Time')
            axes[0, 1].set_ylabel('Number of Attacks')
            axes[0, 1].legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        
        # 3. Hourly attack pattern
        hourly_attacks = self.df.groupby('hour').size()
        axes[1, 0].bar(hourly_attacks.index, hourly_attacks.values, color='skyblue', alpha=0.8)
        axes[1, 0].set_title('Attack Distribution by Hour')
        axes[1, 0].set_xlabel('Hour of Day')
        axes[1, 0].set_ylabel('Number of Attacks')
        axes[1, 0].grid(True, alpha=0.3)
        
        # 4. Service distribution pie chart
        service_counts = self.df['service'].value_counts()
        axes[1, 1].pie(service_counts.values, labels=service_counts.index, autopct='%1.1f%%', startangle=90)
        axes[1, 1].set_title('Attack Distribution by Service')
        
        plt.tight_layout()
        plt.savefig('analysis/charts/attack_timeline_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("✓ Attack timeline chart saved")
    
    def generate_http_analysis(self):
        """Detailed HTTP attack analysis"""
        http_df = self.df[self.df['service'] == 'http'].copy()
        
        if http_df.empty:
            print("No HTTP data available for analysis")
            return
        
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('HTTP Attack Analysis', fontsize=16, fontweight='bold')
        
        # 1. Most targeted paths
        path_counts = http_df['http_path'].value_counts().head(15)
        axes[0, 0].barh(range(len(path_counts)), path_counts.values)
        axes[0, 0].set_yticks(range(len(path_counts)))
        axes[0, 0].set_yticklabels(path_counts.index)
        axes[0, 0].set_title('Most Targeted HTTP Paths')
        axes[0, 0].set_xlabel('Number of Requests')
        
        # 2. Response codes distribution
        response_counts = http_df['response_code'].value_counts()
        colors = ['green' if code < 400 else 'orange' if code < 500 else 'red' for code in response_counts.index]
        axes[0, 1].bar(range(len(response_counts)), response_counts.values, color=colors, alpha=0.7)
        axes[0, 1].set_xticks(range(len(response_counts)))
        axes[0, 1].set_xticklabels(response_counts.index)
        axes[0, 1].set_title('HTTP Response Code Distribution')
        axes[0, 1].set_ylabel('Number of Requests')
        
        # 3. HTTP Methods
        method_counts = http_df['http_method'].value_counts()
        axes[0, 2].pie(method_counts.values, labels=method_counts.index, autopct='%1.1f%%')
        axes[0, 2].set_title('HTTP Methods Distribution')
        
        # 4. Attack types
        if 'attack_type' in http_df.columns:
            attack_type_counts = http_df['attack_type'].value_counts()
            axes[1, 0].bar(range(len(attack_type_counts)), attack_type_counts.values, 
                          color=sns.color_palette("viridis", len(attack_type_counts)))
            axes[1, 0].set_xticks(range(len(attack_type_counts)))
            axes[1, 0].set_xticklabels(attack_type_counts.index, rotation=45, ha='right')
            axes[1, 0].set_title('HTTP Attack Types')
            axes[1, 0].set_ylabel('Number of Attacks')
        
        # 5. User Agent analysis
        user_agents = http_df['user_agent'].value_counts().head(10)
        if not user_agents.empty:
            axes[1, 1].barh(range(len(user_agents)), user_agents.values)
            axes[1, 1].set_yticks(range(len(user_agents)))
            axes[1, 1].set_yticklabels([ua[:50] + '...' if len(ua) > 50 else ua for ua in user_agents.index])
            axes[1, 1].set_title('Top User Agents')
            axes[1, 1].set_xlabel('Number of Requests')
        
        # 6. Request body analysis
        body_stats = {
            'With Body': http_df['has_body'].sum(),
            'Without Body': len(http_df) - http_df['has_body'].sum()
        }
        axes[1, 2].pie(body_stats.values(), labels=body_stats.keys(), autopct='%1.1f%%')
        axes[1, 2].set_title('Requests with/without Body')
        
        plt.tight_layout()
        plt.savefig('analysis/charts/http_attack_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("✓ HTTP attack analysis chart saved")
    
    def generate_attack_patterns(self):
        """Analyze and visualize attack patterns"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Attack Pattern Analysis', fontsize=16, fontweight='bold')
        
        # 1. Attack intensity heatmap (by hour and service)
        if not self.df.empty:
            self.df['hour'] = self.df['timestamp'].dt.hour
            pivot_data = self.df.groupby(['hour', 'service']).size().unstack(fill_value=0)
            
            if not pivot_data.empty:
                sns.heatmap(pivot_data.T, annot=True, fmt='d', cmap='YlOrRd', ax=axes[0, 0])
                axes[0, 0].set_title('Attack Intensity by Hour and Service')
                axes[0, 0].set_xlabel('Hour of Day')
                axes[0, 0].set_ylabel('Service')
        
        # 2. Sequential attack pattern analysis
        if 'attack_type' in self.df.columns:
            # Find common attack sequences
            sequences = []
            for i in range(len(self.df) - 1):
                current_attack = self.df.iloc[i]['attack_type']
                next_attack = self.df.iloc[i + 1]['attack_type']
                time_diff = (self.df.iloc[i + 1]['timestamp'] - self.df.iloc[i]['timestamp']).total_seconds()
                
                # Only consider attacks within 60 seconds as part of a sequence
                if time_diff <= 60:
                    sequences.append(f"{current_attack} → {next_attack}")
            
            if sequences:
                sequence_counts = Counter(sequences).most_common(10)
                if sequence_counts:
                    seq_names, seq_counts = zip(*sequence_counts)
                    axes[0, 1].barh(range(len(seq_names)), seq_counts)
                    axes[0, 1].set_yticks(range(len(seq_names)))
                    axes[0, 1].set_yticklabels([name[:40] + '...' if len(name) > 40 else name for name in seq_names])
                    axes[0, 1].set_title('Common Attack Sequences')
                    axes[0, 1].set_xlabel('Frequency')
        
        # 3. Attack volume by IP (even though we only have localhost, show the concept)
        ip_counts = self.df['peer_ip'].value_counts().head(10)
        axes[1, 0].bar(range(len(ip_counts)), ip_counts.values, color='coral', alpha=0.7)
        axes[1, 0].set_xticks(range(len(ip_counts)))
        axes[1, 0].set_xticklabels(ip_counts.index, rotation=45)
        axes[1, 0].set_title('Attack Volume by Source IP')
        axes[1, 0].set_ylabel('Number of Attacks')
        
        # 4. Attack persistence analysis
        self.df['time_since_start'] = (self.df['timestamp'] - self.df['timestamp'].min()).dt.total_seconds()
        
        # Create bins for time analysis
        time_bins = pd.cut(self.df['time_since_start'], bins=20)
        time_attack_counts = self.df.groupby(time_bins).size()
        
        bin_centers = [interval.mid for interval in time_attack_counts.index]
        axes[1, 1].plot(bin_centers, time_attack_counts.values, marker='o', linewidth=2, markersize=6)
        axes[1, 1].set_title('Attack Persistence Over Time')
        axes[1, 1].set_xlabel('Time Since First Attack (seconds)')
        axes[1, 1].set_ylabel('Number of Attacks')
        axes[1, 1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig('analysis/charts/attack_patterns_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("✓ Attack patterns analysis chart saved")
    
    def generate_security_insights(self):
        """Generate security insights and threat assessment"""
        print("\n" + "="*60)
        print("SECURITY INSIGHTS & THREAT ASSESSMENT")
        print("="*60)
        
        total_events = len(self.df)
        unique_ips = self.df['peer_ip'].nunique()
        services_attacked = self.df['service'].nunique()
        
        print(f"\n📊 ATTACK SUMMARY:")
        print(f"   • Total Attack Events: {total_events}")
        print(f"   • Unique Source IPs: {unique_ips}")
        print(f"   • Services Targeted: {services_attacked}")
        
        # Time analysis
        if not self.df.empty:
            attack_duration = (self.df['timestamp'].max() - self.df['timestamp'].min()).total_seconds()
            attack_rate = total_events / attack_duration if attack_duration > 0 else 0
            print(f"   • Attack Duration: {attack_duration:.1f} seconds")
            print(f"   • Attack Rate: {attack_rate:.2f} events/second")
        
        # Service breakdown
        print(f"\n🎯 SERVICE TARGETING:")
        for service, count in self.df['service'].value_counts().items():
            percentage = (count / total_events) * 100
            print(f"   • {service.upper()}: {count} events ({percentage:.1f}%)")
        
        # HTTP-specific analysis
        http_df = self.df[self.df['service'] == 'http']
        if not http_df.empty:
            print(f"\n🌐 HTTP ATTACK ANALYSIS:")
            
            # Most targeted paths
            top_paths = http_df['http_path'].value_counts().head(5)
            print("   Top Targeted Paths:")
            for path, count in top_paths.items():
                print(f"     - {path}: {count} requests")
            
            # Attack types
            if 'attack_type' in http_df.columns:
                attack_types = http_df['attack_type'].value_counts()
                print("   Attack Type Distribution:")
                for attack_type, count in attack_types.items():
                    percentage = (count / len(http_df)) * 100
                    print(f"     - {attack_type.replace('_', ' ').title()}: {count} ({percentage:.1f}%)")
            
            # Response analysis
            error_responses = http_df[http_df['response_code'] >= 400]
            if not error_responses.empty:
                error_rate = (len(error_responses) / len(http_df)) * 100
                print(f"   HTTP Error Rate: {error_rate:.1f}% ({len(error_responses)}/{len(http_df)})")
        
        # Security recommendations
        print(f"\n🛡️  SECURITY RECOMMENDATIONS:")
        
        if http_df['response_code'].value_counts().get(200, 0) > 0:
            print("   ⚠️  Many requests returned 200 OK - consider more restrictive responses")
        
        if 'sql_injection' in self.df.get('attack_type', pd.Series()).values:
            print("   🚨 SQL injection attempts detected - ensure input validation")
        
        if 'xss_attempt' in self.df.get('attack_type', pd.Series()).values:
            print("   🚨 XSS attempts detected - implement output encoding")
        
        if self.df['service'].value_counts().get('ssh-like', 0) > 0:
            print("   🔐 SSH probing detected - consider fail2ban or rate limiting")
        
        if self.df['service'].value_counts().get('ftp', 0) > 0:
            print("   📁 FTP probing detected - consider disabling if not needed")
        
        print("\n" + "="*60)
    
    def run_comprehensive_analysis(self):
        """Run all analyses"""
        print("Starting Comprehensive Attack Analysis...")
        print("="*50)
        
        if self.df.empty:
            print("No data available for analysis")
            return
        
        # Generate all visualizations
        print("\n1. Generating attack timeline analysis...")
        self.generate_attack_timeline()
        
        print("2. Generating HTTP attack analysis...")
        self.generate_http_analysis()
        
        print("3. Generating attack pattern analysis...")
        self.generate_attack_patterns()
        
        print("4. Generating security insights...")
        self.generate_security_insights()
        
        print(f"\n✅ Analysis complete! Generated visualizations:")
        print("   - attack_timeline_analysis.png")
        print("   - http_attack_analysis.png")
        print("   - attack_patterns_analysis.png")


def main():
    if len(sys.argv) != 2:
        print("Usage: python comprehensive_attack_analysis.py <log_file.jsonl>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    analyzer = ComprehensiveAttackAnalyzer(log_file)
    analyzer.run_comprehensive_analysis()


if __name__ == "__main__":
    main()