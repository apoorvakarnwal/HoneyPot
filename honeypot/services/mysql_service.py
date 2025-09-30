"""
MySQL Honeypot Service
Simulates a MySQL database server to capture database attacks
"""

import socket
import threading
import time
import struct
import hashlib
import random
from honeypot.logger import log_event
from honeypot.config import BIND_IP, SSH_SESSION_TIMEOUT

MYSQL_PORT = 3306

def mysql_hash_password(password: str, salt: bytes) -> bytes:
    """Create MySQL-style password hash"""
    if not password:
        return b""
    
    # MySQL 4.1+ hashing
    hash1 = hashlib.sha1(password.encode()).digest()
    hash2 = hashlib.sha1(hash1).digest()
    hash3 = hashlib.sha1(salt + hash2).digest()
    
    result = bytes(a ^ b for a, b in zip(hash1, hash3))
    return result

def create_mysql_packet(packet_id: int, data: bytes) -> bytes:
    """Create a MySQL protocol packet"""
    length = len(data)
    header = struct.pack('<I', length)[:-1] + struct.pack('B', packet_id)
    return header + data

def _handle_mysql_connection(conn: socket.socket, addr):
    peer = addr[0]
    session = {
        "service": "mysql",
        "peer": peer,
        "start_ts": time.time(),
        "commands": [],
        "auth_attempts": [],
        "queries": [],
        "vulnerabilities_tested": [],
        "authenticated": False,
        "username": None,
        "database": None
    }
    
    try:
        conn.settimeout(SSH_SESSION_TIMEOUT * 2)
        
        # Generate random salt for authentication
        salt = bytes([random.randint(0, 255) for _ in range(20)])
        
        # Send MySQL handshake packet
        handshake = struct.pack('<B', 10)  # Protocol version 10
        handshake += b"5.7.33-0ubuntu0.18.04.1\x00"  # Server version
        handshake += struct.pack('<I', 12345)  # Connection ID
        handshake += salt[:8]  # Auth plugin data part 1
        handshake += b"\x00"  # Filler
        handshake += struct.pack('<H', 0xFFFF)  # Server capabilities
        handshake += struct.pack('<B', 0x21)  # Server charset
        handshake += struct.pack('<H', 0x0002)  # Server status
        handshake += struct.pack('<H', 0x0000)  # Extended capabilities
        handshake += struct.pack('<B', 21)  # Auth plugin data length
        handshake += b"\x00" * 10  # Reserved
        handshake += salt[8:]  # Auth plugin data part 2
        handshake += b"\x00"  # Null terminator
        handshake += b"mysql_native_password\x00"  # Auth plugin name
        
        handshake_packet = create_mysql_packet(0, handshake)
        conn.sendall(handshake_packet)
        session["handshake_sent"] = True
        
        while True:
            try:
                # Read packet header (4 bytes)
                header = conn.recv(4)
                if len(header) < 4:
                    session["commands"].append({"ts": time.time(), "note": "incomplete_header"})
                    break
                
                # Parse header
                length = struct.unpack('<I', header[:3] + b'\x00')[0]
                packet_id = header[3]
                
                if length > 16777215:  # Max packet size
                    session["commands"].append({"ts": time.time(), "note": "packet_too_large"})
                    break
                
                # Read packet data
                data = b""
                while len(data) < length:
                    chunk = conn.recv(min(length - len(data), 4096))
                    if not chunk:
                        break
                    data += chunk
                
                if len(data) < length:
                    session["commands"].append({"ts": time.time(), "note": "incomplete_packet"})
                    break
                
                session["commands"].append({
                    "ts": time.time(),
                    "packet_id": packet_id,
                    "length": length,
                    "data_preview": data[:100].hex()
                })
                
                # Handle authentication packet
                if packet_id == 1 and not session["authenticated"]:
                    if len(data) > 32:  # Minimum auth packet size
                        try:
                            # Parse client auth packet
                            pos = 0
                            client_flags = struct.unpack('<I', data[pos:pos+4])[0]
                            pos += 4
                            max_packet = struct.unpack('<I', data[pos:pos+4])[0]
                            pos += 4
                            charset = data[pos]
                            pos += 1
                            pos += 23  # Reserved bytes
                            
                            # Extract username
                            username_end = data.find(b'\x00', pos)
                            if username_end == -1:
                                username_end = len(data)
                            username = data[pos:username_end].decode('utf-8', errors='replace')
                            pos = username_end + 1
                            
                            # Extract password hash length and data
                            if pos < len(data):
                                auth_length = data[pos] if pos < len(data) else 0
                                pos += 1
                                auth_data = data[pos:pos+auth_length] if auth_length > 0 else b""
                                pos += auth_length
                                
                                # Extract database name if present
                                database = ""
                                if pos < len(data):
                                    db_end = data.find(b'\x00', pos)
                                    if db_end == -1:
                                        db_end = len(data)
                                    database = data[pos:db_end].decode('utf-8', errors='replace')
                                
                                session["auth_attempts"].append({
                                    "username": username,
                                    "auth_data": auth_data.hex() if auth_data else "",
                                    "database": database,
                                    "timestamp": time.time(),
                                    "success": False
                                })
                                session["username"] = username
                                session["database"] = database
                                
                                # Detect common attack patterns
                                if username.lower() in ['root', 'admin', 'user', 'test', 'mysql']:
                                    session["vulnerabilities_tested"].append("common_username_attack")
                                
                                if len(auth_data) == 0:  # Empty password attempt
                                    session["vulnerabilities_tested"].append("empty_password_attack")
                        
                        except Exception as e:
                            session["commands"].append({"ts": time.time(), "auth_parse_error": str(e)})
                    
                    # Always deny authentication
                    error_packet = struct.pack('<H', 0xFFFF)  # Error code
                    error_packet += struct.pack('<B', ord('#'))  # SQL state marker
                    error_packet += b"28000"  # SQL state
                    error_packet += b"Access denied for user '" + username.encode() + b"'@'" + peer.encode() + b"' (using password: YES)"
                    
                    error_response = create_mysql_packet(2, error_packet)
                    conn.sendall(error_response)
                    break
                
                # Handle SQL queries (if somehow authenticated)
                elif packet_id > 0 and len(data) > 0:
                    command_type = data[0]
                    
                    if command_type == 0x03:  # COM_QUERY
                        query = data[1:].decode('utf-8', errors='replace')
                        session["queries"].append({
                            "query": query,
                            "timestamp": time.time()
                        })
                        
                        # Analyze query for SQL injection patterns
                        query_lower = query.lower()
                        if any(pattern in query_lower for pattern in [
                            'union select', 'or 1=1', 'drop table', 'drop database',
                            'information_schema', 'show databases', 'show tables',
                            'load_file', 'into outfile', 'into dumpfile'
                        ]):
                            session["vulnerabilities_tested"].append("sql_injection")
                        
                        if 'benchmark(' in query_lower or 'sleep(' in query_lower:
                            session["vulnerabilities_tested"].append("time_based_sqli")
                        
                        if 'user()' in query_lower or 'version()' in query_lower:
                            session["vulnerabilities_tested"].append("information_gathering")
                        
                        # Send generic error response
                        error_packet = struct.pack('<H', 0x03E8)  # Error 1000
                        error_packet += struct.pack('<B', ord('#'))
                        error_packet += b"HY000"
                        error_packet += b"Unknown error"
                        
                        error_response = create_mysql_packet(packet_id + 1, error_packet)
                        conn.sendall(error_response)
                    
                    elif command_type == 0x01:  # COM_QUIT
                        break
                    
                    else:
                        # Unknown command
                        session["commands"].append({
                            "ts": time.time(),
                            "unknown_command": command_type
                        })
                        
                        # Send error for unknown command
                        error_packet = struct.pack('<H', 0x03E8)
                        error_packet += struct.pack('<B', ord('#'))
                        error_packet += b"HY000"
                        error_packet += b"Unknown command"
                        
                        error_response = create_mysql_packet(packet_id + 1, error_packet)
                        conn.sendall(error_response)
                
            except socket.timeout:
                session["commands"].append({"ts": time.time(), "note": "timeout"})
                break
            except Exception as e:
                session["commands"].append({"ts": time.time(), "error": str(e)})
                break
                
    except Exception as exc:
        session["connection_error"] = str(exc)
    finally:
        session["end_ts"] = time.time()
        session["duration"] = session["end_ts"] - session["start_ts"]
        log_event(session)
        try:
            conn.close()
        except Exception:
            pass

def run_mysql_server(bind: str = BIND_IP, port: int = MYSQL_PORT):
    """Run the MySQL honeypot server"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((bind, port))
        s.listen(5)
        print(f"[+] MySQL honeypot listening on {bind}:{port}")
        
        while True:
            try:
                conn, addr = s.accept()
                thread = threading.Thread(target=_handle_mysql_connection, args=(conn, addr), daemon=True)
                thread.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] MySQL server error: {e}")
                
    except Exception as e:
        print(f"[!] Failed to start MySQL server: {e}")
    finally:
        s.close()
