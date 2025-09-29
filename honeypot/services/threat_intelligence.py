"""
Threat Intelligence and Geolocation integration for enhanced attack analysis.
Provides IP geolocation, threat feed integration, and intelligence correlation.
"""

import requests
import json
import time
import threading
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict
import ipaddress

class ThreatIntelligence:
    """Threat intelligence aggregation and analysis"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.cache = {}
        self.cache_timeout = 3600  # 1 hour cache
        self.lock = threading.Lock()
        
        # API Keys and endpoints
        self.ipinfo_token = self.config.get('ipinfo_token', '')
        self.virustotal_api_key = self.config.get('virustotal_api_key', '')
        self.abuseipdb_api_key = self.config.get('abuseipdb_api_key', '')
        
        # Rate limiting
        self.api_calls = defaultdict(list)
        self.rate_limits = {
            'ipinfo': 50000,  # per month
            'virustotal': 4,  # per minute
            'abuseipdb': 1000  # per day
        }
    
    def _is_cache_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        return (key in self.cache and 
                time.time() - self.cache[key].get('timestamp', 0) < self.cache_timeout)
    
    def _rate_limit_check(self, api_name: str, limit_per_minute: int = None) -> bool:
        """Check if we can make an API call within rate limits"""
        current_time = time.time()
        minute_ago = current_time - 60
        
        # Clean old calls
        self.api_calls[api_name] = [
            call_time for call_time in self.api_calls[api_name] 
            if call_time > minute_ago
        ]
        
        # Check rate limit
        if limit_per_minute and len(self.api_calls[api_name]) >= limit_per_minute:
            return False
        
        return True
    
    def get_ip_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation information for an IP address"""
        cache_key = f"geo_{ip}"
        
        with self.lock:
            if self._is_cache_valid(cache_key):
                return self.cache[cache_key]['data']
        
        geo_info = {
            'ip': ip,
            'country': 'Unknown',
            'country_code': 'XX',
            'region': 'Unknown',
            'city': 'Unknown',
            'org': 'Unknown',
            'timezone': 'Unknown',
            'location': {'lat': 0.0, 'lng': 0.0},
            'is_vpn': False,
            'is_proxy': False,
            'is_tor': False,
            'is_hosting': False
        }
        
        try:
            # Try IPInfo.io first (most reliable free tier)
            if self.ipinfo_token and self._rate_limit_check('ipinfo', 1000):
                url = f"https://ipinfo.io/{ip}/json?token={self.ipinfo_token}"
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    geo_info.update({
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('country', 'XX'),
                        'region': data.get('region', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'timezone': data.get('timezone', 'Unknown')
                    })
                    
                    # Parse location
                    if 'loc' in data:
                        lat, lng = data['loc'].split(',')
                        geo_info['location'] = {'lat': float(lat), 'lng': float(lng)}
                    
                    # Check for hosting/VPN indicators
                    if 'hosting' in data.get('org', '').lower():
                        geo_info['is_hosting'] = True
                    
                    self.api_calls['ipinfo'].append(time.time())
            
            # Fallback to free IP-API service
            else:
                url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,city,org,timezone,lat,lon,proxy,hosting"
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        geo_info.update({
                            'country': data.get('country', 'Unknown'),
                            'country_code': data.get('countryCode', 'XX'),
                            'region': data.get('region', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'org': data.get('org', 'Unknown'),
                            'timezone': data.get('timezone', 'Unknown'),
                            'location': {
                                'lat': data.get('lat', 0.0),
                                'lng': data.get('lon', 0.0)
                            },
                            'is_proxy': data.get('proxy', False),
                            'is_hosting': data.get('hosting', False)
                        })
        
        except Exception as e:
            print(f"Geolocation lookup failed for {ip}: {e}")
        
        # Cache the result
        with self.lock:
            self.cache[cache_key] = {
                'data': geo_info,
                'timestamp': time.time()
            }
        
        return geo_info
    
    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation using multiple threat intelligence sources"""
        cache_key = f"reputation_{ip}"
        
        with self.lock:
            if self._is_cache_valid(cache_key):
                return self.cache[cache_key]['data']
        
        reputation = {
            'ip': ip,
            'is_malicious': False,
            'threat_types': [],
            'confidence': 0,
            'sources': [],
            'last_seen': None,
            'threat_score': 0  # 0-100 scale
        }
        
        try:
            # Check if IP is in private ranges (always clean)
            if ipaddress.ip_address(ip).is_private:
                reputation['confidence'] = 100
                reputation['sources'] = ['private_ip']
                return reputation
            
            # VirusTotal IP check
            if self.virustotal_api_key and self._rate_limit_check('virustotal', 4):
                vt_result = self._check_virustotal_ip(ip)
                if vt_result:
                    reputation['sources'].append('virustotal')
                    if vt_result['malicious_count'] > 0:
                        reputation['is_malicious'] = True
                        reputation['threat_score'] += min(50, vt_result['malicious_count'] * 10)
                        reputation['threat_types'].extend(vt_result['threat_types'])
            
            # AbuseIPDB check
            if self.abuseipdb_api_key and self._rate_limit_check('abuseipdb', 1000):
                abuse_result = self._check_abuseipdb(ip)
                if abuse_result:
                    reputation['sources'].append('abuseipdb')
                    if abuse_result['abuse_confidence'] > 25:
                        reputation['is_malicious'] = True
                        reputation['threat_score'] += abuse_result['abuse_confidence']
                        reputation['threat_types'].extend(abuse_result['usage_types'])
                        reputation['last_seen'] = abuse_result['last_reported']
            
            # Local reputation database (if available)
            local_rep = self._check_local_reputation(ip)
            if local_rep:
                reputation['sources'].append('local_db')
                reputation['threat_score'] += local_rep['score']
                if local_rep['is_malicious']:
                    reputation['is_malicious'] = True
                    reputation['threat_types'].extend(local_rep['threat_types'])
            
            # Calculate final confidence based on sources
            reputation['confidence'] = min(100, len(reputation['sources']) * 30)
            reputation['threat_score'] = min(100, reputation['threat_score'])
        
        except Exception as e:
            print(f"Reputation check failed for {ip}: {e}")
        
        # Cache the result
        with self.lock:
            self.cache[cache_key] = {
                'data': reputation,
                'timestamp': time.time()
            }
        
        return reputation
    
    def _check_virustotal_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP against VirusTotal database"""
        try:
            headers = {'x-apikey': self.virustotal_api_key}
            url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {'ip': ip, 'apikey': self.virustotal_api_key}
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                detected_urls = data.get('detected_urls', [])
                detected_samples = data.get('detected_communicating_samples', [])
                
                malicious_count = len([url for url in detected_urls if url.get('positives', 0) > 0])
                malicious_count += len([sample for sample in detected_samples if sample.get('positives', 0) > 0])
                
                threat_types = []
                if detected_urls:
                    threat_types.append('malicious_urls')
                if detected_samples:
                    threat_types.append('malware_communication')
                
                self.api_calls['virustotal'].append(time.time())
                
                return {
                    'malicious_count': malicious_count,
                    'threat_types': threat_types,
                    'detected_urls': len(detected_urls),
                    'detected_samples': len(detected_samples)
                }
        
        except Exception as e:
            print(f"VirusTotal check failed: {e}")
        
        return None
    
    def _check_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP against AbuseIPDB"""
        try:
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            url = 'https://api.abuseipdb.com/api/v2/check'
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                usage_types = []
                for category in data.get('usageType', '').split(','):
                    if category.strip():
                        usage_types.append(category.strip().lower())
                
                self.api_calls['abuseipdb'].append(time.time())
                
                return {
                    'abuse_confidence': data.get('abuseConfidencePercentage', 0),
                    'usage_types': usage_types,
                    'is_public': data.get('isPublic', True),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'country_code': data.get('countryCode', ''),
                    'last_reported': data.get('lastReportedAt', '')
                }
        
        except Exception as e:
            print(f"AbuseIPDB check failed: {e}")
        
        return None
    
    def _check_local_reputation(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check against local reputation database"""
        try:
            from honeypot.database import database
            
            conn = database._get_connection()
            try:
                cur = conn.cursor()
                placeholder = "?" if database.db_type == "sqlite" else "%s"
                
                cur.execute(f"""
                    SELECT reputation_score, is_malicious, threat_types, attack_count
                    FROM ip_reputation 
                    WHERE ip_address = {placeholder}
                """, (ip,))
                
                row = cur.fetchone()
                if row:
                    return {
                        'score': row[0],
                        'is_malicious': row[1],
                        'threat_types': json.loads(row[2] or '[]'),
                        'attack_count': row[3]
                    }
            finally:
                conn.close()
        
        except Exception as e:
            print(f"Local reputation check failed: {e}")
        
        return None
    
    def analyze_attack_campaign(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze multiple events to identify coordinated attack campaigns"""
        campaign_analysis = {
            'is_campaign': False,
            'campaign_type': 'unknown',
            'indicators': [],
            'severity': 'low',
            'recommendations': []
        }
        
        if len(events) < 2:
            return campaign_analysis
        
        # Group events by various attributes
        by_ip = defaultdict(list)
        by_attack_type = defaultdict(list)
        by_user_agent = defaultdict(list)
        by_country = defaultdict(list)
        
        for event in events:
            ip = event.get('peer', '')
            if ip:
                by_ip[ip].append(event)
            
            attack_types = event.get('attack_indicators', [])
            for attack_type in attack_types:
                by_attack_type[attack_type].append(event)
            
            ua = event.get('headers', {}).get('User-Agent', '')
            if ua:
                by_user_agent[ua].append(event)
        
        # Detect coordinated attacks
        if len(by_ip) > 5 and any(len(events) > 3 for events in by_ip.values()):
            campaign_analysis['is_campaign'] = True
            campaign_analysis['campaign_type'] = 'distributed_attack'
            campaign_analysis['indicators'].append('multiple_coordinated_ips')
            campaign_analysis['severity'] = 'high'
        
        # Detect botnet activity
        if len(set(by_user_agent.keys())) < 3 and len(by_ip) > 10:
            campaign_analysis['is_campaign'] = True
            campaign_analysis['campaign_type'] = 'botnet_activity'
            campaign_analysis['indicators'].append('uniform_user_agents')
            campaign_analysis['severity'] = 'critical'
        
        # Detect scanning campaigns
        if 'scanner_tool' in by_attack_type and len(by_attack_type['scanner_tool']) > 10:
            campaign_analysis['is_campaign'] = True
            campaign_analysis['campaign_type'] = 'reconnaissance_campaign'
            campaign_analysis['indicators'].append('automated_scanning')
            campaign_analysis['severity'] = 'medium'
        
        # Generate recommendations
        if campaign_analysis['is_campaign']:
            campaign_analysis['recommendations'] = [
                'Implement IP-based rate limiting',
                'Deploy geographic access controls',
                'Enable advanced DDoS protection',
                'Consider threat intelligence feeds',
                'Implement behavioral analysis'
            ]
        
        return campaign_analysis
    
    def get_threat_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Generate comprehensive threat intelligence summary"""
        try:
            from honeypot.database import database
            
            since = datetime.now() - timedelta(hours=hours)
            events = database.get_events(limit=1000, since=since, attack_only=True)
            
            summary = {
                'period_hours': hours,
                'total_events': len(events),
                'unique_ips': len(set(e.source_ip for e in events)),
                'countries': defaultdict(int),
                'threat_types': defaultdict(int),
                'high_risk_ips': [],
                'campaign_analysis': None,
                'geographic_hotspots': [],
                'recommendations': []
            }
            
            # Analyze each IP
            for event in events:
                if event.source_ip and not ipaddress.ip_address(event.source_ip).is_private:
                    # Get geolocation
                    geo = self.get_ip_geolocation(event.source_ip)
                    summary['countries'][geo['country']] += 1
                    
                    # Get reputation
                    rep = self.check_ip_reputation(event.source_ip)
                    if rep['threat_score'] > 50:
                        summary['high_risk_ips'].append({
                            'ip': event.source_ip,
                            'threat_score': rep['threat_score'],
                            'country': geo['country'],
                            'threat_types': rep['threat_types']
                        })
                
                # Count threat types
                for threat_type in event.attack_types:
                    summary['threat_types'][threat_type] += 1
            
            # Campaign analysis
            if len(events) > 5:
                summary['campaign_analysis'] = self.analyze_attack_campaign([
                    {
                        'peer': e.source_ip,
                        'attack_indicators': e.attack_types,
                        'headers': e.headers or {},
                        'timestamp': e.timestamp
                    } for e in events
                ])
            
            # Identify geographic hotspots
            summary['geographic_hotspots'] = [
                {'country': country, 'attack_count': count}
                for country, count in sorted(summary['countries'].items(), 
                                           key=lambda x: x[1], reverse=True)[:5]
            ]
            
            # Generate recommendations based on analysis
            if summary['campaign_analysis'] and summary['campaign_analysis']['is_campaign']:
                summary['recommendations'].extend(summary['campaign_analysis']['recommendations'])
            
            if len(summary['high_risk_ips']) > 10:
                summary['recommendations'].append('Consider implementing IP reputation blocking')
            
            if summary['unique_ips'] > 50:
                summary['recommendations'].append('Deploy advanced bot detection mechanisms')
            
            return summary
        
        except Exception as e:
            print(f"Threat summary generation failed: {e}")
            return {}

# Global threat intelligence instance
threat_intel = ThreatIntelligence()

def initialize_threat_intelligence(config: Dict[str, Any] = None):
    """Initialize threat intelligence with configuration"""
    global threat_intel
    threat_intel = ThreatIntelligence(config)
    print("[+] Threat intelligence system initialized")

def enrich_event_with_intelligence(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich attack event with threat intelligence data"""
    ip = event_data.get('peer')
    if not ip:
        return event_data
    
    try:
        # Add geolocation
        geo_info = threat_intel.get_ip_geolocation(ip)
        event_data['geolocation'] = geo_info
        
        # Add reputation data
        reputation = threat_intel.check_ip_reputation(ip)
        event_data['reputation'] = reputation
        
        # Update attack indicators based on reputation
        if reputation['is_malicious'] and 'known_malicious_ip' not in event_data.get('attack_indicators', []):
            event_data.setdefault('attack_indicators', []).append('known_malicious_ip')
    
    except Exception as e:
        print(f"Event enrichment failed: {e}")
    
    return event_data
