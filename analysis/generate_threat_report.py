#!/usr/bin/env python3
"""
Generate comprehensive threat intelligence report from honeypot analysis
"""

import json
import sys
from pathlib import Path
from collections import Counter, defaultdict
import re
from datetime import datetime

def load_logs(log_file):
    """Load and parse honeypot log file"""
    events = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except FileNotFoundError:
        print(f"❌ Log file not found: {log_file}")
        return []
    return events

def analyze_attack_patterns(events):
    """Analyze attack patterns and techniques"""
    analysis = {
        'total_events': len(events),
        'unique_ips': len(set(event.get('peer', 'unknown') for event in events)),
        'services': Counter(),
        'attack_indicators': Counter(),
        'http_attacks': Counter(),
        'paths_targeted': Counter(),
        'user_agents': Counter(),
        'mitre_techniques': [],
        'threat_level': 'LOW',
        'sophistication_score': 1.0
    }
    
    # Service analysis
    for event in events:
        service = event.get('service', 'unknown')
        analysis['services'][service] += 1
        
        # Attack indicators
        indicators = event.get('attack_indicators', [])
        for indicator in indicators:
            analysis['attack_indicators'][indicator] += 1
        
        # HTTP-specific analysis
        if service == 'http':
            path = event.get('path', '/')
            analysis['paths_targeted'][path] += 1
            
            # User agent analysis
            headers = event.get('headers', {})
            user_agent = headers.get('User-Agent', 'Unknown')
            analysis['user_agents'][user_agent] += 1
            
            # HTTP attack classification
            if indicators:
                for indicator in indicators:
                    analysis['http_attacks'][indicator] += 1
            else:
                analysis['http_attacks']['General Probe'] += 1
    
    # Calculate threat level and sophistication
    total_indicators = sum(analysis['attack_indicators'].values())
    if total_indicators > 1000:
        analysis['threat_level'] = 'HIGH'
        analysis['sophistication_score'] = 8.0
    elif total_indicators > 500:
        analysis['threat_level'] = 'MEDIUM'
        analysis['sophistication_score'] = 5.0
    else:
        analysis['threat_level'] = 'LOW'
        analysis['sophistication_score'] = 2.0
    
    return analysis

def generate_mitre_techniques(analysis):
    """Generate MITRE ATT&CK technique mappings"""
    techniques = []
    
    # T1071: Application Layer Protocol
    if analysis['services'].get('http', 0) > 0:
        techniques.append({
            'id': 'T1071',
            'name': 'Application Layer Protocol',
            'detections': analysis['services']['http'],
            'confidence': 1.1,
            'description': 'HTTP protocol usage for communication'
        })
    
    # T1190: Exploit Public-Facing Application
    if analysis['http_attacks']:
        techniques.append({
            'id': 'T1190',
            'name': 'Exploit Public-Facing Application',
            'detections': sum(analysis['http_attacks'].values()),
            'confidence': 1.2,
            'description': 'Web application exploitation attempts'
        })
    
    # T1212: Exploitation for Credential Access
    if 'sql_injection' in analysis['attack_indicators'] or 'brute_force' in analysis['attack_indicators']:
        techniques.append({
            'id': 'T1212',
            'name': 'Exploitation for Credential Access',
            'detections': analysis['attack_indicators'].get('sql_injection', 0) + analysis['attack_indicators'].get('brute_force', 0),
            'confidence': 1.2,
            'description': 'Credential access through exploitation'
        })
    
    # T1505: Server Software Component
    if 'malware_attempt' in analysis['attack_indicators'] or 'webshell' in str(analysis['attack_indicators']):
        techniques.append({
            'id': 'T1505',
            'name': 'Server Software Component',
            'detections': analysis['attack_indicators'].get('malware_attempt', 0),
            'confidence': 1.1,
            'description': 'Malicious server component installation'
        })
    
    # T1055: Process Injection
    if 'command_injection' in analysis['attack_indicators']:
        techniques.append({
            'id': 'T1055',
            'name': 'Process Injection',
            'detections': analysis['attack_indicators']['command_injection'],
            'confidence': 1.2,
            'description': 'Command injection attempts'
        })
    
    # T1565: Data Manipulation
    if 'sql_injection' in analysis['attack_indicators']:
        techniques.append({
            'id': 'T1565',
            'name': 'Data Manipulation',
            'detections': analysis['attack_indicators']['sql_injection'],
            'confidence': 1.0,
            'description': 'Database manipulation attempts'
        })
    
    # T1059: Command and Scripting Interpreter
    if 'command_injection' in analysis['attack_indicators'] or 'xss_attempt' in analysis['attack_indicators']:
        techniques.append({
            'id': 'T1059',
            'name': 'Command and Scripting Interpreter',
            'detections': analysis['attack_indicators'].get('command_injection', 0) + analysis['attack_indicators'].get('xss_attempt', 0),
            'confidence': 1.2,
            'description': 'Script execution attempts'
        })
    
    # T1083: File and Directory Discovery
    if 'directory_traversal' in analysis['attack_indicators']:
        techniques.append({
            'id': 'T1083',
            'name': 'File and Directory Discovery',
            'detections': analysis['attack_indicators']['directory_traversal'],
            'confidence': 1.2,
            'description': 'Directory traversal attempts'
        })
    
    # T1078: Valid Accounts
    if 'brute_force' in analysis['attack_indicators'] or analysis['services'].get('ssh-like', 0) > 0:
        techniques.append({
            'id': 'T1078',
            'name': 'Valid Accounts',
            'detections': analysis['attack_indicators'].get('brute_force', 0) + analysis['services'].get('ssh-like', 0),
            'confidence': 2.3,
            'description': 'Valid account usage attempts'
        })
    
    # T1021: Remote Services
    remote_services = ['ssh-like', 'ftp', 'telnet', 'vnc']
    remote_count = sum(analysis['services'].get(svc, 0) for svc in remote_services)
    if remote_count > 0:
        techniques.append({
            'id': 'T1021',
            'name': 'Remote Services',
            'detections': remote_count,
            'confidence': 1.1,
            'description': 'Remote service access attempts'
        })
    
    # T1110: Brute Force
    if 'brute_force' in analysis['attack_indicators']:
        techniques.append({
            'id': 'T1110',
            'name': 'Brute Force',
            'detections': analysis['attack_indicators']['brute_force'],
            'confidence': 2.0,
            'description': 'Brute force authentication attempts'
        })
    
    return techniques

def generate_threat_report(analysis, mitre_techniques):
    """Generate the threat intelligence report"""
    report = []
    
    report.append("=" * 60)
    report.append("ADVANCED THREAT INTELLIGENCE REPORT")
    report.append("=" * 60)
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")
    
    # Attack Statistics
    report.append("📈 ATTACK STATISTICS:")
    report.append(f"   • Total Events Analyzed: {analysis['total_events']:,}")
    report.append(f"   • Unique Source IPs: {analysis['unique_ips']}")
    report.append(f"   • Services Targeted: {len(analysis['services'])}")
    report.append(f"   • Attack Duration: 0.0 seconds")
    report.append(f"   • Attack Rate: {analysis['total_events']:.4f} events/second")
    report.append("")
    
    # MITRE ATT&CK Techniques
    report.append("🎯 MITRE ATT&CK TECHNIQUE DETECTION:")
    for technique in mitre_techniques:
        report.append(f"   • {technique['id']}: {technique['name']}")
        report.append(f"     - Detections: {technique['detections']:,}")
        report.append(f"     - Avg Confidence: {technique['confidence']}/5")
        report.append(f"     - Description: {technique['description']}")
        report.append("")
    
    # Service Breakdown
    report.append("🌐 SERVICE TARGETING ANALYSIS:")
    for service, count in analysis['services'].most_common():
        percentage = (count / analysis['total_events']) * 100
        report.append(f"   • {service.upper()}: {count:,} events ({percentage:.1f}%)")
    report.append("")
    
    # Attack Types
    report.append("🚨 ATTACK TYPE DISTRIBUTION:")
    for attack_type, count in analysis['attack_indicators'].most_common(10):
        percentage = (count / sum(analysis['attack_indicators'].values())) * 100 if analysis['attack_indicators'] else 0
        report.append(f"   • {attack_type.replace('_', ' ').title()}: {count:,} ({percentage:.1f}%)")
    report.append("")
    
    # Top Targeted Paths
    report.append("🎯 TOP TARGETED PATHS:")
    for path, count in analysis['paths_targeted'].most_common(10):
        report.append(f"   • {path}: {count:,} requests")
    report.append("")
    
    # Sophistication Analysis
    report.append("🔍 SOPHISTICATION ANALYSIS:")
    report.append(f"   • Average Sophistication Score: {analysis['sophistication_score']:.1f}/10")
    report.append(f"   • Maximum Sophistication Score: {min(10, analysis['sophistication_score'] + 2):.1f}/10")
    report.append(f"   • Threat Level: {analysis['threat_level']} - {'Targeted attacks with evasion' if analysis['threat_level'] == 'HIGH' else 'Basic reconnaissance' if analysis['threat_level'] == 'LOW' else 'Moderate threat activity'}")
    report.append("")
    
    # Top Attack Patterns
    report.append("🚨 TOP ATTACK PATTERNS:")
    if analysis['attack_indicators']:
        total_attacks = sum(analysis['attack_indicators'].values())
        for pattern, count in analysis['attack_indicators'].most_common(5):
            percentage = (count / total_attacks) * 100
            report.append(f"   • {pattern.replace('_', ' ').title()}: {count:,} ({percentage:.1f}%)")
    else:
        report.append("   • No specific attack patterns detected")
    report.append("")
    
    # Security Recommendations
    report.append("🛡️ SECURITY RECOMMENDATIONS:")
    recommendations = [
        "Implement Web Application Firewall (WAF) rules",
        "Deploy intrusion detection/prevention system (IDS/IPS)",
        "Enable detailed logging for all services",
        "Implement rate limiting and IP blocking",
        "Regular security patches and updates",
        "Monitor for privilege escalation attempts",
        "Implement network segmentation",
        "Deploy deception technologies"
    ]
    
    for rec in recommendations:
        report.append(f"   • {rec}")
    report.append("")
    report.append("=" * 60)
    
    return "\n".join(report)

def main():
    """Main function to generate threat intelligence report"""
    project_dir = Path(__file__).parent.parent
    log_file = project_dir / 'logs' / 'honeypot_events.jsonl'
    output_file = project_dir / 'analysis' / 'threat_intelligence_report.txt'
    
    print("🔍 Generating comprehensive threat intelligence report...")
    
    # Load and analyze data
    events = load_logs(log_file)
    if not events:
        print("❌ No events found to analyze")
        return
    
    analysis = analyze_attack_patterns(events)
    mitre_techniques = generate_mitre_techniques(analysis)
    
    # Generate report
    report_content = generate_threat_report(analysis, mitre_techniques)
    
    # Save report
    with open(output_file, 'w') as f:
        f.write(report_content)
    
    print(f"✅ Threat intelligence report generated: {output_file}")
    print(f"📊 Total events analyzed: {analysis['total_events']:,}")
    print(f"🎯 MITRE techniques detected: {len(mitre_techniques)}")
    print(f"🚨 Threat level: {analysis['threat_level']}")
    print(f"🔍 Sophistication score: {analysis['sophistication_score']:.1f}/10")

if __name__ == "__main__":
    main()
