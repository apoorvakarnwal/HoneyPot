"""
DNS honeypot service.
Captures DNS queries, detects DNS tunneling, cache poisoning attempts, and malicious domains.
"""

import socket
import threading
import time
import struct
from honeypot.logger import log_event
from honeypot.config import BIND_IP

# DNS Configuration
DNS_PORT = 53

class DNSQuery:
    """Simple DNS query parser"""
    
    def __init__(self, data):
        self.data = data
        self.domain = ""
        self.query_type = 0
        self.query_class = 0
        self.transaction_id = 0
        self.flags = 0
        self.questions = 0
        self.answers = 0
        self.authority = 0
        self.additional = 0
        
        self._parse()
    
    def _parse(self):
        """Parse DNS query packet"""
        try:
            if len(self.data) < 12:
                return
            
            # DNS Header (12 bytes)
            header = struct.unpack('>HHHHHH', self.data[:12])
            self.transaction_id = header[0]
            self.flags = header[1]
            self.questions = header[2]
            self.answers = header[3]
            self.authority = header[4]
            self.additional = header[5]
            
            # Parse question section
            if self.questions > 0:
                offset = 12
                self.domain, offset = self._parse_domain_name(self.data, offset)
                
                if offset + 4 <= len(self.data):
                    query_info = struct.unpack('>HH', self.data[offset:offset+4])
                    self.query_type = query_info[0]
                    self.query_class = query_info[1]
                    
        except Exception as e:
            print(f"DNS parsing error: {e}")
    
    def _parse_domain_name(self, data, offset):
        """Parse domain name from DNS packet"""
        domain_parts = []
        original_offset = offset
        jumped = False
        
        while offset < len(data):
            length = data[offset]
            
            if length == 0:
                offset += 1
                break
            elif length & 0xC0 == 0xC0:  # Compression pointer
                if not jumped:
                    original_offset = offset + 2
                    jumped = True
                offset = ((length & 0x3F) << 8) | data[offset + 1]
                if offset >= len(data):
                    break
            else:
                offset += 1
                if offset + length > len(data):
                    break
                domain_parts.append(data[offset:offset+length].decode('utf-8', errors='replace'))
                offset += length
        
        domain = '.'.join(domain_parts)
        return domain, original_offset if jumped else offset

def _create_dns_response(query: DNSQuery, client_addr):
    """Create a DNS response packet"""
    if not query.domain:
        return b""
    
    try:
        # DNS Header - mark as response
        response_flags = 0x8180  # Standard query response, no error
        header = struct.pack('>HHHHHH', 
                           query.transaction_id,
                           response_flags,
                           1,  # 1 question
                           1,  # 1 answer
                           0,  # 0 authority
                           0)  # 0 additional
        
        # Question section (copy from original query)
        question_data = query.data[12:]
        question_end = 12
        
        # Find end of question section
        try:
            offset = 12
            while offset < len(query.data) and query.data[offset] != 0:
                length = query.data[offset]
                if length & 0xC0 == 0xC0:  # Compression pointer
                    offset += 2
                    break
                else:
                    offset += length + 1
            offset += 1  # Skip null terminator
            offset += 4  # Skip QTYPE and QCLASS
            question_end = offset
            
            question_section = query.data[12:question_end]
        except:
            # Fallback - just use a reasonable chunk
            question_section = query.data[12:min(len(query.data), 50)]
        
        # Answer section - respond with honeypot IP
        answer_section = b""
        if query.query_type == 1:  # A record request
            # Domain name pointer (compression)
            answer_section += b'\xc0\x0c'  # Pointer to question name
            # Type A, Class IN, TTL 300, Data length 4
            answer_section += struct.pack('>HHLH', 1, 1, 300, 4)
            # IP address (honeypot IP - 127.0.0.1)
            answer_section += socket.inet_aton('127.0.0.1')
        elif query.query_type == 28:  # AAAA record request (IPv6)
            answer_section += b'\xc0\x0c'
            answer_section += struct.pack('>HHLH', 28, 1, 300, 16)
            # IPv6 loopback
            answer_section += socket.inet_pton(socket.AF_INET6, '::1')
        else:
            # For other query types, return NXDOMAIN
            response_flags = 0x8183  # Name error
            header = struct.pack('>HHHHHH', 
                               query.transaction_id,
                               response_flags,
                               1, 0, 0, 0)  # No answers
        
        return header + question_section + answer_section
        
    except Exception as e:
        print(f"DNS response creation error: {e}")
        return b""

def _analyze_dns_query(query: DNSQuery, client_addr) -> list:
    """Analyze DNS query for suspicious patterns"""
    indicators = []
    domain = query.domain.lower()
    
    # DNS Tunneling detection
    if len(domain) > 100:  # Unusually long domain
        indicators.append("dns_tunneling_long_domain")
    
    # Check for base64-like patterns in subdomain
    domain_parts = domain.split('.')
    for part in domain_parts:
        if len(part) > 20 and all(c.isalnum() or c in 'abcdefghijklmnopqrstuvwxyz0123456789+/=' for c in part):
            indicators.append("dns_tunneling_base64")
            break
    
    # Excessive subdomains
    if len(domain_parts) > 6:
        indicators.append("dns_tunneling_many_subdomains")
    
    # DGA (Domain Generation Algorithm) detection
    if any(len(part) > 15 and not any(vowel in part for vowel in 'aeiou') for part in domain_parts):
        indicators.append("dga_domain")
    
    # Known malicious TLDs
    malicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit']
    if any(domain.endswith(tld) for tld in malicious_tlds):
        indicators.append("suspicious_tld")
    
    # Fast flux detection (many queries for same domain)
    # This would require tracking across requests in a real implementation
    
    # Query type analysis
    if query.query_type == 16:  # TXT records often used for tunneling
        indicators.append("txt_record_query")
    elif query.query_type in [12, 15]:  # PTR, MX records
        indicators.append("reconnaissance_query")
    
    # Check for known C2 domains (simplified list)
    c2_patterns = [
        'pastebin.com', 'github.com', 'raw.githubusercontent.com',
        'amazonaws.com', 'duckdns.org', 'no-ip.com'
    ]
    if any(pattern in domain for pattern in c2_patterns):
        indicators.append("potential_c2_communication")
    
    # Homograph/typosquatting detection (simplified)
    legitimate_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com']
    for legit in legitimate_domains:
        if domain != legit and _calculate_similarity(domain, legit) > 0.8:
            indicators.append("typosquatting_attempt")
            break
    
    return indicators

def _calculate_similarity(s1: str, s2: str) -> float:
    """Calculate simple string similarity (Levenshtein-based)"""
    if len(s1) == 0 or len(s2) == 0:
        return 0.0
    
    # Simple character-based similarity
    matches = sum(1 for a, b in zip(s1, s2) if a == b)
    max_len = max(len(s1), len(s2))
    return matches / max_len if max_len > 0 else 0.0

def _handle_dns_query(data, addr, sock):
    """Handle individual DNS query"""
    peer = addr[0]
    
    try:
        query = DNSQuery(data)
        
        # Create session record
        session = {
            "service": "dns",
            "peer": peer,
            "timestamp": time.time(),
            "transaction_id": query.transaction_id,
            "domain": query.domain,
            "query_type": query.query_type,
            "query_class": query.query_class,
            "flags": query.flags,
            "packet_size": len(data),
            "raw_packet": data.hex()[:200]  # First 100 bytes as hex
        }
        
        # Analyze for suspicious patterns
        attack_indicators = _analyze_dns_query(query, addr)
        if attack_indicators:
            session["attack_indicators"] = attack_indicators
        
        # Map query type to human readable
        query_type_map = {
            1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 
            15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"
        }
        session["query_type_name"] = query_type_map.get(query.query_type, f"TYPE{query.query_type}")
        
        # Create and send response
        response = _create_dns_response(query, addr)
        if response:
            sock.sendto(response, addr)
            session["response_sent"] = True
            session["response_size"] = len(response)
        else:
            session["response_sent"] = False
        
        # Log the session
        log_event(session)
        
    except Exception as e:
        error_session = {
            "service": "dns",
            "peer": peer,
            "timestamp": time.time(),
            "error": str(e),
            "packet_size": len(data),
            "raw_packet": data.hex()[:200]
        }
        log_event(error_session)

def run_dns_server(bind: str = BIND_IP, port: int = DNS_PORT):
    """Run the DNS honeypot server"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind((bind, port))
        print(f"[+] DNS honeypot listening on {bind}:{port}")
        
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                # Handle each query in a separate thread for better performance
                thread = threading.Thread(
                    target=_handle_dns_query, 
                    args=(data, addr, sock), 
                    daemon=True
                )
                thread.start()
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] DNS server error: {e}")
                
    except Exception as e:
        print(f"[!] Failed to start DNS server: {e}")
    finally:
        sock.close()
