"""
Comprehensive test suite for the enhanced honeypot system.
Tests all services, attack detection, and intelligence features.
"""

import unittest
import requests
import socket
import time
import json
import threading
from unittest.mock import patch, MagicMock
import tempfile
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from honeypot.services.http_service import HoneypotHTTPRequestHandler
from honeypot.services.metrics import metrics_collector, record_request
from honeypot.database import HoneypotDatabase, AttackEvent
from honeypot.services.threat_intelligence import ThreatIntelligence
from honeypot.services.alerting import AlertManager
from honeypot.logger import log_event

class TestHTTPHoneypot(unittest.TestCase):
    """Test HTTP honeypot functionality"""
    
    @classmethod
    def setUpClass(cls):
        """Start HTTP honeypot for testing"""
        from honeypot.services.http_service import run_http_server
        cls.server_thread = threading.Thread(
            target=run_http_server, 
            kwargs={'bind': '127.0.0.1', 'port': 8081}, 
            daemon=True
        )
        cls.server_thread.start()
        time.sleep(1)  # Wait for server to start
    
    def test_basic_http_request(self):
        """Test basic HTTP functionality"""
        response = requests.get('http://127.0.0.1:8081/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Index', response.text)
    
    def test_admin_page(self):
        """Test admin page functionality"""
        response = requests.get('http://127.0.0.1:8081/admin')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Administrator Login', response.text)
        self.assertIn('form', response.text)
    
    def test_sql_injection_detection(self):
        """Test SQL injection attack detection"""
        payload = "' OR '1'='1"
        response = requests.post('http://127.0.0.1:8081/login', 
                               data={'username': payload, 'password': 'test'})
        self.assertEqual(response.status_code, 401)
    
    def test_xss_detection(self):
        """Test XSS attack detection"""
        payload = "<script>alert('XSS')</script>"
        response = requests.get(f'http://127.0.0.1:8081/search?q={payload}')
        self.assertEqual(response.status_code, 200)
    
    def test_directory_traversal_detection(self):
        """Test directory traversal attack detection"""
        payload = "../../../etc/passwd"
        response = requests.get(f'http://127.0.0.1:8081/file?path={payload}')
        self.assertEqual(response.status_code, 403)
    
    def test_ssrf_detection(self):
        """Test SSRF attack detection"""
        payload = "http://169.254.169.254/latest/meta-data/"
        response = requests.get(f'http://127.0.0.1:8081/fetch?url={payload}')
        self.assertEqual(response.status_code, 500)
    
    def test_upload_functionality(self):
        """Test file upload endpoint"""
        files = {'file': ('test.txt', 'test content', 'text/plain')}
        response = requests.post('http://127.0.0.1:8081/upload', files=files)
        self.assertEqual(response.status_code, 200)

class TestSSHHoneypot(unittest.TestCase):
    """Test SSH-like honeypot functionality"""
    
    @classmethod
    def setUpClass(cls):
        """Start SSH honeypot for testing"""
        from honeypot.services.ssh_service import run_ssh_like
        cls.server_thread = threading.Thread(
            target=run_ssh_like, 
            kwargs={'bind': '127.0.0.1', 'port': 2223}, 
            daemon=True
        )
        cls.server_thread.start()
        time.sleep(1)
    
    def test_ssh_banner(self):
        """Test SSH banner response"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', 2223))
            banner = sock.recv(1024)
            self.assertIn(b'SSH-2.0', banner)
        finally:
            sock.close()
    
    def test_ssh_interaction(self):
        """Test SSH interaction logging"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', 2223))
            banner = sock.recv(1024)
            
            # Send fake credentials
            sock.send(b"admin:password123\n")
            response = sock.recv(1024)
            self.assertIn(b'$', response)  # Should get prompt
        finally:
            sock.close()

class TestFTPHoneypot(unittest.TestCase):
    """Test FTP honeypot functionality"""
    
    @classmethod
    def setUpClass(cls):
        """Start FTP honeypot for testing"""
        from honeypot.services.ftp_service import run_ftp_server
        cls.server_thread = threading.Thread(
            target=run_ftp_server, 
            kwargs={'bind': '127.0.0.1', 'port': 2122}, 
            daemon=True
        )
        cls.server_thread.start()
        time.sleep(1)
    
    def test_ftp_banner(self):
        """Test FTP banner response"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', 2122))
            banner = sock.recv(1024)
            self.assertIn(b'220', banner)
            self.assertIn(b'ready', banner.lower())
        finally:
            sock.close()
    
    def test_ftp_authentication(self):
        """Test FTP authentication attempts"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', 2122))
            banner = sock.recv(1024)
            
            # Send USER command
            sock.send(b"USER admin\r\n")
            response = sock.recv(1024)
            self.assertIn(b'331', response)  # Password required
            
            # Send PASS command
            sock.send(b"PASS password\r\n")
            response = sock.recv(1024)
            self.assertIn(b'530', response)  # Login incorrect
        finally:
            sock.close()

class TestSMTPHoneypot(unittest.TestCase):
    """Test SMTP honeypot functionality"""
    
    @classmethod
    def setUpClass(cls):
        """Start SMTP honeypot for testing"""
        from honeypot.services.smtp_service import run_smtp_server
        cls.server_thread = threading.Thread(
            target=run_smtp_server, 
            kwargs={'bind': '127.0.0.1', 'port': 2525}, 
            daemon=True
        )
        cls.server_thread.start()
        time.sleep(1)
    
    def test_smtp_banner(self):
        """Test SMTP banner response"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', 2525))
            banner = sock.recv(1024)
            self.assertIn(b'220', banner)
            self.assertIn(b'ESMTP', banner)
        finally:
            sock.close()
    
    def test_smtp_commands(self):
        """Test SMTP command handling"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', 2525))
            banner = sock.recv(1024)
            
            # EHLO command
            sock.send(b"EHLO test.com\r\n")
            response = sock.recv(1024)
            self.assertIn(b'250', response)
            
            # MAIL FROM command
            sock.send(b"MAIL FROM:<test@example.com>\r\n")
            response = sock.recv(1024)
            self.assertIn(b'250', response)
        finally:
            sock.close()

class TestDNSHoneypot(unittest.TestCase):
    """Test DNS honeypot functionality"""
    
    @classmethod
    def setUpClass(cls):
        """Start DNS honeypot for testing"""
        from honeypot.services.dns_service import run_dns_server
        cls.server_thread = threading.Thread(
            target=run_dns_server, 
            kwargs={'bind': '127.0.0.1', 'port': 5353}, 
            daemon=True
        )
        cls.server_thread.start()
        time.sleep(1)
    
    def test_dns_query(self):
        """Test DNS query handling"""
        # Create a simple DNS query packet for google.com
        query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(query, ('127.0.0.1', 5353))
            sock.settimeout(5)
            response, addr = sock.recvfrom(1024)
            self.assertGreater(len(response), 12)  # Should have DNS header + data
        finally:
            sock.close()

class TestMetricsSystem(unittest.TestCase):
    """Test metrics collection and analysis"""
    
    def test_request_recording(self):
        """Test request metrics recording"""
        initial_count = len(metrics_collector.service_metrics)
        record_request('test_service', 0.1, True, ['test_attack'])
        
        # Verify metrics were recorded
        self.assertIn('test_service', metrics_collector.service_metrics)
        service_metrics = metrics_collector.service_metrics['test_service']
        self.assertEqual(service_metrics.total_requests, 1)
        self.assertEqual(service_metrics.attack_attempts, 1)
    
    def test_metrics_export(self):
        """Test metrics export functionality"""
        record_request('export_test', 0.2, False, [])
        metrics_data = metrics_collector.export_metrics()
        
        self.assertIn('services', metrics_data)
        self.assertIn('system', metrics_data)
        self.assertIn('timestamp', metrics_data)
        self.assertIn('summary', metrics_data)

class TestDatabaseIntegration(unittest.TestCase):
    """Test database storage and retrieval"""
    
    def setUp(self):
        """Set up test database"""
        self.test_db = HoneypotDatabase('sqlite', ':memory:')
    
    def test_attack_event_storage(self):
        """Test storing and retrieving attack events"""
        event = AttackEvent(
            timestamp='2023-01-01T00:00:00Z',
            service='test',
            source_ip='192.168.1.100',
            attack_types=['sql_injection', 'xss_attempt'],
            method='POST',
            path='/login',
            body='test payload'
        )
        
        event_id = self.test_db.insert_attack_event(event)
        self.assertIsNotNone(event_id)
        
        # Retrieve events
        events = self.test_db.get_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].source_ip, '192.168.1.100')
        self.assertIn('sql_injection', events[0].attack_types)
    
    def test_attack_statistics(self):
        """Test attack statistics generation"""
        # Insert test events
        for i in range(5):
            event = AttackEvent(
                timestamp='2023-01-01T00:00:00Z',
                service='test',
                source_ip=f'192.168.1.{100+i}',
                attack_types=['test_attack'],
                method='GET',
                path='/'
            )
            self.test_db.insert_attack_event(event)
        
        stats = self.test_db.get_attack_statistics(hours=24)
        self.assertEqual(stats['total_attacks'], 5)
        self.assertIn('test_attack', stats['attack_types'])

class TestThreatIntelligence(unittest.TestCase):
    """Test threat intelligence integration"""
    
    def setUp(self):
        """Set up threat intelligence"""
        self.threat_intel = ThreatIntelligence()
    
    @patch('requests.get')
    def test_geolocation_lookup(self, mock_get):
        """Test IP geolocation lookup"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'country': 'United States',
            'region': 'California',
            'city': 'Mountain View',
            'org': 'Google LLC',
            'loc': '37.4056,-122.0775'
        }
        mock_get.return_value = mock_response
        
        geo_info = self.threat_intel.get_ip_geolocation('8.8.8.8')
        self.assertEqual(geo_info['country'], 'United States')
        self.assertEqual(geo_info['city'], 'Mountain View')
    
    def test_private_ip_handling(self):
        """Test private IP address handling"""
        reputation = self.threat_intel.check_ip_reputation('192.168.1.1')
        self.assertFalse(reputation['is_malicious'])
        self.assertEqual(reputation['confidence'], 100)
    
    def test_campaign_analysis(self):
        """Test attack campaign detection"""
        events = [
            {
                'peer': f'192.168.1.{i}',
                'attack_indicators': ['sql_injection'],
                'headers': {'User-Agent': 'AttackBot/1.0'},
                'timestamp': '2023-01-01T00:00:00Z'
            }
            for i in range(10)
        ]
        
        analysis = self.threat_intel.analyze_attack_campaign(events)
        self.assertTrue(analysis['is_campaign'])
        self.assertIn('multiple_coordinated_ips', analysis['indicators'])

class TestAlertingSystem(unittest.TestCase):
    """Test alerting and notification system"""
    
    def setUp(self):
        """Set up alert manager"""
        self.alert_manager = AlertManager({
            'email': {'recipients': ['test@example.com']},
            'throttle_minutes': 1
        })
    
    def test_alert_throttling(self):
        """Test alert throttling mechanism"""
        # First alert should go through
        self.assertTrue(self.alert_manager.should_alert('test_alert', 'key1'))
        
        # Second alert immediately should be throttled
        self.assertFalse(self.alert_manager.should_alert('test_alert', 'key1'))
        
        # Different key should not be throttled
        self.assertTrue(self.alert_manager.should_alert('test_alert', 'key2'))
    
    @patch('smtplib.SMTP')
    def test_email_alert(self, mock_smtp):
        """Test email alert functionality"""
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        
        self.alert_manager.sender_email = 'test@example.com'
        self.alert_manager.sender_password = 'password'
        
        result = self.alert_manager.send_email_alert(
            'Test Alert', 
            'This is a test alert message'
        )
        
        # Email sending should be attempted
        mock_smtp.assert_called_once()
    
    @patch('requests.post')
    def test_webhook_alert(self, mock_post):
        """Test webhook alert functionality"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        self.alert_manager.webhook_urls = ['http://example.com/webhook']
        
        result = self.alert_manager.send_webhook_alert({
            'type': 'test_alert',
            'message': 'Test webhook alert'
        })
        
        self.assertTrue(result)
        mock_post.assert_called_once()

class TestAttackDetection(unittest.TestCase):
    """Test attack pattern detection across services"""
    
    def test_http_attack_classification(self):
        """Test HTTP attack classification"""
        # This would test the _analyze_attack_patterns method
        # from HTTP service with various payloads
        pass
    
    def test_cross_service_correlation(self):
        """Test correlation of attacks across multiple services"""
        # This would test detection of coordinated attacks
        # across HTTP, SSH, FTP, etc.
        pass

class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system"""
    
    def test_end_to_end_attack_flow(self):
        """Test complete attack detection and response flow"""
        # This would test:
        # 1. Attack occurs
        # 2. Detection triggers
        # 3. Event logged to database
        # 4. Metrics updated
        # 5. Alert generated
        # 6. Intelligence enrichment
        pass
    
    def test_dashboard_data_flow(self):
        """Test data flow to dashboard"""
        # This would test that attacks properly flow
        # through to dashboard visualization
        pass

if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestHTTPHoneypot,
        TestSSHHoneypot,
        TestFTPHoneypot,
        TestSMTPHoneypot,
        TestDNSHoneypot,
        TestMetricsSystem,
        TestDatabaseIntegration,
        TestThreatIntelligence,
        TestAlertingSystem,
        TestAttackDetection,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with error code if tests failed
    sys.exit(0 if result.wasSuccessful() else 1)
