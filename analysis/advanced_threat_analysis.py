#!/usr/bin/env python3
"""
Advanced Threat Analysis for Honeypot Data
==========================================

This script provides advanced analysis capabilities including:
1. MITRE ATT&CK technique classification
2. Behavioral heatmaps
3. Anomaly detection
4. Attack sophistication scoring
5. Threat intelligence correlation
"""

import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import sys
import os
from urllib.parse import unquote
import re

# Set style for better visualization
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

class AdvancedThreatAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.df = None
        self.mitre_techniques = self.load_mitre_mapping()
        
    def load_mitre_mapping(self):
        """Map attack patterns to MITRE ATT&CK techniques"""
        return {
            # Initial Access
            'T1190': {
                'name': 'Exploit Public-Facing Application',
                'patterns': ['/admin', '/wp-admin', '/phpmyadmin', '/config', '/.env'],
                'methods': ['GET', 'POST']
            },
            'T1133': {
                'name': 'External Remote Services',
                'patterns': ['ssh', 'ftp', 'telnet'],
                'ports': [21, 22, 23, 2121, 2222]
            },
            
            # Discovery
            'T1046': {
                'name': 'Network Service Scanning',
                'patterns': ['port_scan', 'service_discovery'],
                'indicators': ['multiple_ports', 'rapid_connections']
            },
            'T1083': {
                'name': 'File and Directory Discovery',
                'patterns': ['/etc/passwd', '/windows/system32', '../', '..\\', 'directory_traversal'],
                'methods': ['GET']
            },
            'T1018': {
                'name': 'Remote System Discovery',
                'patterns': ['ping', 'nmap', 'scan'],
                'indicators': ['reconnaissance']
            },
            
            # Credential Access
            'T1110': {
                'name': 'Brute Force',
                'patterns': ['login', 'auth', 'brute_force'],
                'indicators': ['multiple_login_attempts', 'common_passwords']
            },
            'T1212': {
                'name': 'Exploitation for Credential Access',
                'patterns': ['sql_injection', 'sqli', 'union', 'select'],
                'methods': ['POST', 'GET']
            },
            
            # Persistence
            'T1505': {
                'name': 'Server Software Component',
                'patterns': ['webshell', 'shell.php', 'cmd.php', 'backdoor'],
                'methods': ['POST', 'GET']
            },
            
            # Defense Evasion
            'T1140': {
                'name': 'Deobfuscate/Decode Files or Information',
                'patterns': ['base64', 'url_encode', '%2e%2e', 'encode'],
                'indicators': ['encoded_payloads']
            },
            'T1055': {
                'name': 'Process Injection',
                'patterns': ['script', 'javascript:', 'eval', 'exec'],
                'methods': ['GET', 'POST']
            },
            
            # Impact
            'T1486': {
                'name': 'Data Encrypted for Impact',
                'patterns': ['ransomware', 'encrypt', 'crypto'],
                'indicators': ['suspicious_files']
            },
            'T1565': {
                'name': 'Data Manipulation',
                'patterns': ['drop', 'delete', 'truncate', 'alter'],
                'methods': ['POST', 'GET']
            }
        }
    
    def load_and_process_data(self):
        """Load and process honeypot log data"""
        print(f"Loading logs from {self.log_file}...")
        
        events = []
        with open(self.log_file, 'r') as f:
            for line in f:
                try:
                    events.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
        
        print(f"Loaded {len(events)} events")
        
        # Process events into DataFrame
        processed_events = []
        for event in events:
            processed_event = {
                'timestamp': event.get('timestamp', ''),
                'service': event.get('service', ''),
                'source_ip': event.get('source_ip', ''),
                'source_port': event.get('source_port', 0),
                'target_port': event.get('target_port', 0),
                'method': event.get('method', ''),
                'path': event.get('path', ''),
                'user_agent': event.get('user_agent', ''),
                'status_code': event.get('status_code', 0),
                'content_length': event.get('content_length', 0),
                'body': event.get('body', ''),
                'attack_type': event.get('attack_type', ''),
                'severity': event.get('severity', 'low'),
                'raw_data': str(event)
            }
            
            # Parse timestamp
            if processed_event['timestamp']:
                try:
                    processed_event['datetime'] = pd.to_datetime(processed_event['timestamp'])
                except:
                    processed_event['datetime'] = pd.NaT
            else:
                processed_event['datetime'] = pd.NaT
                
            processed_events.append(processed_event)
        
        self.df = pd.DataFrame(processed_events)
        if not self.df.empty:
            self.df = self.df.sort_values('datetime')
            
        print(f"Created DataFrame with {len(self.df)} processed events")
        return self.df
    
    def classify_mitre_techniques(self):
        """Classify attacks according to MITRE ATT&CK framework"""
        print("Classifying attacks using MITRE ATT&CK framework...")
        
        technique_matches = defaultdict(list)
        
        for idx, row in self.df.iterrows():
            path = str(row.get('path', '')).lower()
            method = str(row.get('method', '')).upper()
            service = str(row.get('service', '')).lower()
            attack_type = str(row.get('attack_type', '')).lower()
            body = str(row.get('body', '')).lower()
            user_agent = str(row.get('user_agent', '')).lower()
            
            # Check each MITRE technique
            for technique_id, technique_info in self.mitre_techniques.items():
                score = 0
                reasons = []
                
                # Check path patterns
                for pattern in technique_info.get('patterns', []):
                    if pattern.lower() in path or pattern.lower() in body or pattern.lower() in attack_type:
                        score += 2
                        reasons.append(f"Pattern '{pattern}' found")
                
                # Check method match
                if method in technique_info.get('methods', []):
                    score += 1
                    reasons.append(f"Method '{method}' matches")
                
                # Check port match
                target_port = row.get('target_port', 0)
                if target_port in technique_info.get('ports', []):
                    score += 1
                    reasons.append(f"Port {target_port} matches")
                
                # Check service match
                if service in technique_info.get('patterns', []):
                    score += 1
                    reasons.append(f"Service '{service}' matches")
                
                if score > 0:
                    technique_matches[technique_id].append({
                        'event_idx': idx,
                        'score': score,
                        'reasons': reasons,
                        'timestamp': row['datetime'],
                        'details': f"{method} {path}"
                    })
        
        return technique_matches
    
    def generate_mitre_heatmap(self, technique_matches):
        """Generate MITRE ATT&CK heatmap"""
        print("Generating MITRE ATT&CK technique heatmap...")
        
        # Prepare data for heatmap
        techniques = list(technique_matches.keys())
        technique_names = [self.mitre_techniques[t]['name'][:30] for t in techniques]
        
        if not techniques:
            print("No MITRE techniques detected")
            return
        
        # Count events per technique per hour
        time_slots = []
        if not self.df['datetime'].isna().all():
            start_time = self.df['datetime'].min()
            end_time = self.df['datetime'].max()
            
            # Create hourly time slots
            current_time = start_time
            while current_time <= end_time:
                time_slots.append(current_time)
                current_time += timedelta(hours=1)
        
        if not time_slots:
            time_slots = [datetime.now()]  # Fallback
        
        # Create heatmap data
        heatmap_data = np.zeros((len(techniques), len(time_slots)))
        
        for i, technique_id in enumerate(techniques):
            for match in technique_matches[technique_id]:
                if pd.notna(match['timestamp']):
                    # Find closest time slot
                    for j, time_slot in enumerate(time_slots):
                        if abs((match['timestamp'] - time_slot).total_seconds()) < 3600:  # Within 1 hour
                            heatmap_data[i][j] += match['score']
                            break
        
        # Create the heatmap
        plt.figure(figsize=(15, 8))
        
        if len(time_slots) > 1:
            time_labels = [t.strftime('%H:%M') for t in time_slots]
        else:
            time_labels = ['All Time']
            heatmap_data = heatmap_data.sum(axis=1).reshape(-1, 1)
        
        sns.heatmap(heatmap_data, 
                   yticklabels=[f"{tid}: {name}" for tid, name in zip(techniques, technique_names)],
                   xticklabels=time_labels,
                   annot=True, 
                   fmt='.0f', 
                   cmap='Reds',
                   cbar_kws={'label': 'Attack Intensity'})
        
        plt.title('MITRE ATT&CK Techniques Detection Heatmap')
        plt.xlabel('Time')
        plt.ylabel('MITRE ATT&CK Techniques')
        plt.xticks(rotation=45)
        plt.yticks(rotation=0)
        plt.tight_layout()
        plt.savefig('analysis/charts/mitre_attack_heatmap.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("✓ MITRE ATT&CK heatmap saved")
    
    def generate_behavioral_analysis(self):
        """Generate behavioral analysis charts"""
        print("Generating behavioral analysis...")
        
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        
        # 1. Request size distribution
        if 'content_length' in self.df.columns:
            content_lengths = self.df['content_length'].replace(0, np.nan).dropna()
            if not content_lengths.empty:
                axes[0, 0].hist(content_lengths, bins=30, alpha=0.7, edgecolor='black')
                axes[0, 0].set_title('Request Size Distribution')
                axes[0, 0].set_xlabel('Content Length (bytes)')
                axes[0, 0].set_ylabel('Frequency')
                axes[0, 0].set_yscale('log')
        
        # 2. Attack sophistication scoring
        sophistication_scores = []
        for _, row in self.df.iterrows():
            score = 1  # Base score
            
            # Increase score for encoded payloads
            path = str(row.get('path', ''))
            if any(x in path for x in ['%', 'base64', 'encode']):
                score += 2
                
            # Increase score for SQL injection
            if any(x in str(row.get('body', '')).lower() for x in ['union', 'select', 'drop', 'insert']):
                score += 3
                
            # Increase score for webshells
            if any(x in path.lower() for x in ['shell', 'cmd', 'exec', 'eval']):
                score += 4
                
            # Increase score for directory traversal
            if '../' in path or '..\\' in path:
                score += 2
                
            sophistication_scores.append(score)
        
        axes[0, 1].hist(sophistication_scores, bins=10, alpha=0.7, edgecolor='black')
        axes[0, 1].set_title('Attack Sophistication Distribution')
        axes[0, 1].set_xlabel('Sophistication Score')
        axes[0, 1].set_ylabel('Number of Attacks')
        
        # 3. Service targeting patterns
        service_counts = self.df['service'].value_counts()
        colors = plt.cm.Set3(np.linspace(0, 1, len(service_counts)))
        axes[0, 2].pie(service_counts.values, labels=service_counts.index, autopct='%1.1f%%', colors=colors)
        axes[0, 2].set_title('Service Targeting Distribution')
        
        # 4. Attack timing patterns
        if not self.df['datetime'].isna().all():
            self.df['hour'] = self.df['datetime'].dt.hour
            hourly_attacks = self.df['hour'].value_counts().sort_index()
            axes[1, 0].bar(hourly_attacks.index, hourly_attacks.values, alpha=0.7)
            axes[1, 0].set_title('Attack Timing by Hour')
            axes[1, 0].set_xlabel('Hour of Day')
            axes[1, 0].set_ylabel('Number of Attacks')
            axes[1, 0].set_xticks(range(0, 24, 2))
        
        # 5. Path length analysis
        path_lengths = [len(str(path)) for path in self.df['path']]
        axes[1, 1].hist(path_lengths, bins=20, alpha=0.7, edgecolor='black')
        axes[1, 1].set_title('Request Path Length Distribution')
        axes[1, 1].set_xlabel('Path Length (characters)')
        axes[1, 1].set_ylabel('Frequency')
        
        # 6. User agent diversity
        user_agents = self.df['user_agent'].value_counts().head(10)
        if not user_agents.empty:
            axes[1, 2].barh(range(len(user_agents)), user_agents.values)
            axes[1, 2].set_yticks(range(len(user_agents)))
            axes[1, 2].set_yticklabels([ua[:30] + '...' if len(ua) > 30 else ua for ua in user_agents.index])
            axes[1, 2].set_title('Top User Agents')
            axes[1, 2].set_xlabel('Frequency')
        
        plt.tight_layout()
        plt.savefig('analysis/charts/behavioral_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("✓ Behavioral analysis chart saved")
    
    def generate_threat_intelligence_report(self, technique_matches):
        """Generate detailed threat intelligence report"""
        print("Generating threat intelligence report...")
        
        total_events = len(self.df)
        unique_ips = self.df['source_ip'].nunique()
        services_targeted = self.df['service'].nunique()
        
        if not self.df['datetime'].isna().all():
            attack_duration = (self.df['datetime'].max() - self.df['datetime'].min()).total_seconds()
            attack_rate = total_events / max(attack_duration, 1)
        else:
            attack_duration = 0
            attack_rate = 0
        
        report = f"""
============================================================
ADVANCED THREAT INTELLIGENCE REPORT
============================================================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📈 ATTACK STATISTICS:
   • Total Events Analyzed: {total_events:,}
   • Unique Source IPs: {unique_ips:,}
   • Services Targeted: {services_targeted}
   • Attack Duration: {attack_duration:.1f} seconds
   • Attack Rate: {attack_rate:.4f} events/second

🎯 MITRE ATT&CK TECHNIQUE DETECTION:
"""
        
        if technique_matches:
            for technique_id, matches in sorted(technique_matches.items(), 
                                              key=lambda x: len(x[1]), reverse=True):
                technique_name = self.mitre_techniques[technique_id]['name']
                total_matches = len(matches)
                avg_score = np.mean([m['score'] for m in matches])
                
                report += f"   • {technique_id}: {technique_name}\n"
                report += f"     - Detections: {total_matches}\n"
                report += f"     - Avg Confidence: {avg_score:.1f}/5\n"
                
                # Show top reasons
                all_reasons = []
                for match in matches:
                    all_reasons.extend(match['reasons'])
                reason_counts = Counter(all_reasons)
                top_reasons = reason_counts.most_common(3)
                
                for reason, count in top_reasons:
                    report += f"     - {reason}: {count} times\n"
                report += "\n"
        else:
            report += "   • No MITRE ATT&CK techniques detected\n\n"
        
        # Attack sophistication analysis
        sophistication_scores = []
        for _, row in self.df.iterrows():
            score = self._calculate_sophistication_score(row)
            sophistication_scores.append(score)
        
        if sophistication_scores:
            avg_sophistication = np.mean(sophistication_scores)
            max_sophistication = max(sophistication_scores)
            
            report += f"""🔍 SOPHISTICATION ANALYSIS:
   • Average Sophistication Score: {avg_sophistication:.2f}/10
   • Maximum Sophistication Score: {max_sophistication}/10
   • Threat Level: {self._get_threat_level(avg_sophistication)}

"""
        
        # Top attack patterns
        attack_types = self.df['attack_type'].value_counts().head(10)
        if not attack_types.empty:
            report += "🚨 TOP ATTACK PATTERNS:\n"
            for attack_type, count in attack_types.items():
                percentage = (count / total_events) * 100
                report += f"   • {attack_type}: {count} ({percentage:.1f}%)\n"
            report += "\n"
        
        # Security recommendations
        report += """🛡️ SECURITY RECOMMENDATIONS:
   • Implement Web Application Firewall (WAF) rules
   • Deploy intrusion detection/prevention system (IDS/IPS)
   • Enable detailed logging for all services
   • Implement rate limiting and IP blocking
   • Regular security patches and updates
   • Monitor for privilege escalation attempts
   • Implement network segmentation
   • Deploy deception technologies

============================================================
"""
        
        # Save report
        with open('analysis/charts/threat_intelligence_report.txt', 'w', encoding='utf-8') as f:
            f.write(report)
        
        print("✓ Threat intelligence report saved")
        print(report)
    
    def _calculate_sophistication_score(self, row):
        """Calculate sophistication score for an attack"""
        score = 1  # Base score
        
        path = str(row.get('path', '')).lower()
        body = str(row.get('body', '')).lower()
        user_agent = str(row.get('user_agent', '')).lower()
        
        # Encoding/obfuscation
        if any(x in path for x in ['%2e', '%2f', 'base64']):
            score += 2
        
        # SQL injection complexity
        if any(x in body for x in ['union', 'information_schema', 'concat']):
            score += 3
        
        # Advanced webshells
        if any(x in path for x in ['eval', 'exec', 'system']):
            score += 4
        
        # Custom user agents (not common browsers)
        common_agents = ['mozilla', 'chrome', 'safari', 'edge']
        if not any(agent in user_agent for agent in common_agents) and user_agent:
            score += 1
        
        # Directory traversal depth
        traversal_count = path.count('../') + path.count('..\\')
        if traversal_count > 3:
            score += min(traversal_count, 3)
        
        return min(score, 10)  # Cap at 10
    
    def _get_threat_level(self, avg_score):
        """Determine threat level based on sophistication score"""
        if avg_score < 2:
            return "LOW - Basic reconnaissance"
        elif avg_score < 4:
            return "MEDIUM - Automated scanning"
        elif avg_score < 6:
            return "HIGH - Targeted attacks"
        else:
            return "CRITICAL - Advanced persistent threat"
    
    def run_advanced_analysis(self):
        """Run complete advanced threat analysis"""
        print("Starting Advanced Threat Analysis...")
        print("=" * 50)
        
        # Load data
        self.load_and_process_data()
        
        if self.df.empty:
            print("No data to analyze")
            return
        
        # Classify MITRE techniques
        technique_matches = self.classify_mitre_techniques()
        
        # Generate visualizations
        self.generate_mitre_heatmap(technique_matches)
        self.generate_behavioral_analysis()
        
        # Generate report
        self.generate_threat_intelligence_report(technique_matches)
        
        print("\n✅ Advanced analysis complete! Generated files:")
        print("   - mitre_attack_heatmap.png")
        print("   - behavioral_analysis.png")
        print("   - threat_intelligence_report.txt")


def main():
    if len(sys.argv) != 2:
        print("Usage: python advanced_threat_analysis.py <log_file>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    if not os.path.exists(log_file):
        print(f"Error: Log file {log_file} not found")
        sys.exit(1)
    
    analyzer = AdvancedThreatAnalyzer(log_file)
    analyzer.run_advanced_analysis()


if __name__ == "__main__":
    main()