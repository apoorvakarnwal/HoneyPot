"""
VNC Honeypot Service
Simulates a VNC (Virtual Network Computing) server to capture remote desktop attacks
"""

import socket
import threading
import time
import hashlib
import random
from honeypot.logger import log_event
from honeypot.config import BIND_IP, SSH_SESSION_TIMEOUT

VNC_PORT = 5900

def des_encrypt_password(password: bytes, challenge: bytes) -> bytes:
    """Simplified VNC password encryption (for demonstration)"""
    # In real VNC, this uses DES with a specific key arrangement
    # For honeypot purposes, we'll use a simple XOR
    key = b"23456789"  # VNC uses a fixed 8-byte key
    encrypted = bytes(a ^ b for a, b in zip(password[:8].ljust(8, b'\x00'), key))
    return encrypted

def _handle_vnc_connection(conn: socket.socket, addr):
    peer = addr[0]
    session = {
        "service": "vnc",
        "peer": peer,
        "start_ts": time.time(),
        "commands": [],
        "auth_attempts": [],
        "protocol_version": None,
        "vulnerabilities_tested": [],
        "authenticated": False,
        "screen_requests": 0,
        "input_events": []
    }
    
    try:
        conn.settimeout(SSH_SESSION_TIMEOUT * 2)
        
        # Send VNC protocol version
        protocol_version = b"RFB 003.008\n"
        conn.sendall(protocol_version)
        session["protocol_version_sent"] = protocol_version.decode().strip()
        
        # Receive client protocol version
        client_version = conn.recv(12)
        if len(client_version) >= 12:
            session["client_protocol_version"] = client_version.decode('utf-8', errors='replace').strip()
            session["commands"].append({
                "ts": time.time(),
                "client_version": session["client_protocol_version"]
            })
        
        # Send security types (we'll offer VNC authentication)
        security_types = bytes([1, 2])  # Number of types, VNC auth
        conn.sendall(security_types)
        
        # Receive client's chosen security type
        chosen_security = conn.recv(1)
        if len(chosen_security) == 1:
            security_type = chosen_security[0]
            session["commands"].append({
                "ts": time.time(),
                "chosen_security_type": security_type
            })
            
            if security_type == 1:  # No authentication
                session["vulnerabilities_tested"].append("no_auth_attempt")
                # Send security result (failed)
                conn.sendall(bytes([0, 0, 0, 1]))  # Authentication failed
                
                # Send reason
                reason = b"Authentication required"
                reason_length = len(reason).to_bytes(4, 'big')
                conn.sendall(reason_length + reason)
                
            elif security_type == 2:  # VNC authentication
                # Generate random challenge
                challenge = bytes([random.randint(0, 255) for _ in range(16)])
                conn.sendall(challenge)
                session["auth_challenge_sent"] = challenge.hex()
                
                # Receive encrypted response
                response = conn.recv(16)
                if len(response) == 16:
                    session["auth_attempts"].append({
                        "challenge": challenge.hex(),
                        "response": response.hex(),
                        "timestamp": time.time(),
                        "success": False
                    })
                    
                    # Try to detect weak passwords by testing common ones
                    common_passwords = [
                        b"", b"password", b"123456", b"admin", b"vnc", b"user",
                        b"guest", b"1234", b"qwerty", b"root", b"test"
                    ]
                    
                    for pwd in common_passwords:
                        expected = des_encrypt_password(pwd, challenge)
                        if response == expected:
                            session["vulnerabilities_tested"].append("weak_vnc_password")
                            session["auth_attempts"][-1]["detected_password"] = pwd.decode()
                            break
                    
                    # Check for brute force patterns
                    if len(session["auth_attempts"]) > 1:
                        session["vulnerabilities_tested"].append("vnc_brute_force")
                
                # Always send authentication failure
                conn.sendall(bytes([0, 0, 0, 1]))  # Authentication failed
                
                # Send failure reason
                reason = b"Authentication failed"
                reason_length = len(reason).to_bytes(4, 'big')
                conn.sendall(reason_length + reason)
                
            else:
                # Unsupported security type
                session["commands"].append({
                    "ts": time.time(),
                    "unsupported_security": security_type
                })
                conn.sendall(bytes([0, 0, 0, 1]))  # Failed
                reason = b"Security type not supported"
                reason_length = len(reason).to_bytes(4, 'big')
                conn.sendall(reason_length + reason)
        
        # If somehow authentication succeeds (it shouldn't), handle VNC protocol
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                
                # Parse VNC client messages
                if len(data) >= 1:
                    message_type = data[0]
                    session["commands"].append({
                        "ts": time.time(),
                        "vnc_message_type": message_type,
                        "data_length": len(data)
                    })
                    
                    if message_type == 0:  # SetPixelFormat
                        session["vulnerabilities_tested"].append("pixel_format_manipulation")
                    
                    elif message_type == 2:  # SetEncodings
                        session["vulnerabilities_tested"].append("encoding_manipulation")
                        # Parse encoding types
                        if len(data) >= 4:
                            num_encodings = int.from_bytes(data[2:4], 'big')
                            session["commands"].append({
                                "ts": time.time(),
                                "num_encodings": num_encodings
                            })
                    
                    elif message_type == 3:  # FramebufferUpdateRequest
                        session["screen_requests"] += 1
                        session["vulnerabilities_tested"].append("screen_scraping_attempt")
                        
                        # Don't send actual framebuffer data
                        
                    elif message_type == 4:  # KeyEvent
                        if len(data) >= 8:
                            down_flag = data[1]
                            key_sym = int.from_bytes(data[4:8], 'big')
                            session["input_events"].append({
                                "type": "key",
                                "down": bool(down_flag),
                                "key": key_sym,
                                "timestamp": time.time()
                            })
                        session["vulnerabilities_tested"].append("key_injection")
                    
                    elif message_type == 5:  # PointerEvent
                        if len(data) >= 6:
                            button_mask = data[1]
                            x_pos = int.from_bytes(data[2:4], 'big')
                            y_pos = int.from_bytes(data[4:6], 'big')
                            session["input_events"].append({
                                "type": "pointer",
                                "buttons": button_mask,
                                "x": x_pos,
                                "y": y_pos,
                                "timestamp": time.time()
                            })
                        session["vulnerabilities_tested"].append("mouse_injection")
                    
                    elif message_type == 6:  # ClientCutText
                        if len(data) >= 8:
                            text_length = int.from_bytes(data[4:8], 'big')
                            if len(data) >= 8 + text_length:
                                clipboard_text = data[8:8+text_length].decode('utf-8', errors='replace')
                                session["commands"].append({
                                    "ts": time.time(),
                                    "clipboard_data": clipboard_text[:200]  # Limit log size
                                })
                                
                                # Check for malicious clipboard content
                                if any(pattern in clipboard_text.lower() for pattern in [
                                    '<script', 'javascript:', 'eval(', 'system(',
                                    'powershell', 'cmd.exe', '/bin/sh'
                                ]):
                                    session["vulnerabilities_tested"].append("malicious_clipboard_injection")
                        
                        session["vulnerabilities_tested"].append("clipboard_access")
                    
                    else:
                        session["commands"].append({
                            "ts": time.time(),
                            "unknown_vnc_message": message_type
                        })
                
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

def run_vnc_server(bind: str = BIND_IP, port: int = VNC_PORT):
    """Run the VNC honeypot server"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((bind, port))
        s.listen(5)
        print(f"[+] VNC honeypot listening on {bind}:{port}")
        
        while True:
            try:
                conn, addr = s.accept()
                thread = threading.Thread(target=_handle_vnc_connection, args=(conn, addr), daemon=True)
                thread.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] VNC server error: {e}")
                
    except Exception as e:
        print(f"[!] Failed to start VNC server: {e}")
    finally:
        s.close()
