"""
SMTP honeypot service.
Simulates an SMTP mail server to capture spam, phishing attempts, and email-based attacks.
"""

import socket
import threading
import time
import base64
from honeypot.logger import log_event
from honeypot.config import BIND_IP

# SMTP Configuration
SMTP_PORT = 25
SMTP_SSL_PORT = 465
SMTP_SUBMISSION_PORT = 587

# SMTP Response Messages
SMTP_BANNER = b"220 mail.example.com ESMTP Postfix\r\n"
SMTP_EHLO_RESPONSE = b"""250-mail.example.com
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-AUTH PLAIN LOGIN
250-AUTH=PLAIN LOGIN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250 DSN\r\n"""

SMTP_OK = b"250 OK\r\n"
SMTP_AUTH_CHALLENGE = b"334 VXNlcm5hbWU6\r\n"  # Base64 for "Username:"
SMTP_AUTH_PASSWORD = b"334 UGFzc3dvcmQ6\r\n"   # Base64 for "Password:"
SMTP_AUTH_SUCCESS = b"235 Authentication successful\r\n"
SMTP_AUTH_FAILED = b"535 Authentication failed\r\n"
SMTP_DATA_START = b"354 End data with <CR><LF>.<CR><LF>\r\n"
SMTP_QUIT = b"221 Bye\r\n"
SMTP_ERROR = b"500 Command unrecognized\r\n"

def _handle_smtp_connection(conn: socket.socket, addr):
    """Handle individual SMTP connection"""
    peer = addr[0]
    session = {
        "service": "smtp",
        "peer": peer,
        "start_ts": time.time(),
        "commands": [],
        "auth_attempts": [],
        "messages": [],
        "from_address": None,
        "to_addresses": [],
        "authenticated": False
    }
    
    try:
        conn.settimeout(30.0)
        
        # Send banner
        conn.sendall(SMTP_BANNER)
        session["banner_sent"] = True
        
        current_state = "INIT"
        message_data = []
        
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    session["commands"].append({"ts": time.time(), "note": "client_disconnected"})
                    break
                
                command_line = data.decode('utf-8', errors='replace').strip()
                session["commands"].append({"ts": time.time(), "command": command_line})
                
                # Parse SMTP command
                parts = command_line.split(' ', 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""
                
                if cmd == "EHLO" or cmd == "HELO":
                    current_state = "GREETED"
                    session["client_hostname"] = arg
                    if cmd == "EHLO":
                        conn.sendall(SMTP_EHLO_RESPONSE)
                    else:
                        conn.sendall(b"250 mail.example.com\r\n")
                
                elif cmd == "AUTH":
                    # Handle authentication attempts
                    auth_parts = arg.split()
                    auth_method = auth_parts[0].upper() if auth_parts else ""
                    
                    if auth_method == "PLAIN":
                        if len(auth_parts) > 1:
                            # AUTH PLAIN with credentials in same line
                            try:
                                creds = base64.b64decode(auth_parts[1]).decode('utf-8', errors='replace')
                                # Format: \0username\0password
                                cred_parts = creds.split('\0')
                                if len(cred_parts) >= 3:
                                    username = cred_parts[1]
                                    password = cred_parts[2]
                                    session["auth_attempts"].append({
                                        "method": "PLAIN",
                                        "username": username,
                                        "password": password,
                                        "timestamp": time.time(),
                                        "success": False
                                    })
                            except Exception:
                                pass
                        else:
                            # Multi-step PLAIN auth
                            conn.sendall(SMTP_AUTH_CHALLENGE)
                            current_state = "AUTH_PLAIN"
                            continue
                        
                        conn.sendall(SMTP_AUTH_FAILED)
                    
                    elif auth_method == "LOGIN":
                        conn.sendall(SMTP_AUTH_CHALLENGE)
                        current_state = "AUTH_LOGIN_USER"
                        continue
                    
                    else:
                        conn.sendall(b"504 Unrecognized authentication type\r\n")
                
                elif current_state == "AUTH_LOGIN_USER":
                    # Username for LOGIN auth
                    try:
                        username = base64.b64decode(command_line).decode('utf-8', errors='replace')
                        session["temp_username"] = username
                        conn.sendall(SMTP_AUTH_PASSWORD)
                        current_state = "AUTH_LOGIN_PASS"
                        continue
                    except Exception:
                        conn.sendall(SMTP_AUTH_FAILED)
                        current_state = "GREETED"
                
                elif current_state == "AUTH_LOGIN_PASS":
                    # Password for LOGIN auth
                    try:
                        password = base64.b64decode(command_line).decode('utf-8', errors='replace')
                        session["auth_attempts"].append({
                            "method": "LOGIN",
                            "username": session.get("temp_username", ""),
                            "password": password,
                            "timestamp": time.time(),
                            "success": False
                        })
                    except Exception:
                        pass
                    
                    conn.sendall(SMTP_AUTH_FAILED)
                    current_state = "GREETED"
                
                elif current_state == "AUTH_PLAIN":
                    # PLAIN auth credentials
                    try:
                        creds = base64.b64decode(command_line).decode('utf-8', errors='replace')
                        cred_parts = creds.split('\0')
                        if len(cred_parts) >= 3:
                            username = cred_parts[1]
                            password = cred_parts[2]
                            session["auth_attempts"].append({
                                "method": "PLAIN",
                                "username": username,
                                "password": password,
                                "timestamp": time.time(),
                                "success": False
                            })
                    except Exception:
                        pass
                    
                    conn.sendall(SMTP_AUTH_FAILED)
                    current_state = "GREETED"
                
                elif cmd == "MAIL":
                    if current_state in ["GREETED", "MAIL_SENT"]:
                        # Extract FROM address
                        if arg.upper().startswith("FROM:"):
                            from_addr = arg[5:].strip().strip('<>')
                            session["from_address"] = from_addr
                            conn.sendall(SMTP_OK)
                            current_state = "MAIL_SENT"
                        else:
                            conn.sendall(b"501 Syntax error in parameters\r\n")
                    else:
                        conn.sendall(b"503 Bad sequence of commands\r\n")
                
                elif cmd == "RCPT":
                    if current_state in ["MAIL_SENT", "RCPT_SENT"]:
                        # Extract TO address
                        if arg.upper().startswith("TO:"):
                            to_addr = arg[3:].strip().strip('<>')
                            session["to_addresses"].append(to_addr)
                            conn.sendall(SMTP_OK)
                            current_state = "RCPT_SENT"
                        else:
                            conn.sendall(b"501 Syntax error in parameters\r\n")
                    else:
                        conn.sendall(b"503 Bad sequence of commands\r\n")
                
                elif cmd == "DATA":
                    if current_state == "RCPT_SENT":
                        conn.sendall(SMTP_DATA_START)
                        current_state = "DATA"
                        message_data = []
                        continue
                    else:
                        conn.sendall(b"503 Bad sequence of commands\r\n")
                
                elif current_state == "DATA":
                    # Collect message data until we see "."
                    if command_line == ".":
                        # End of message
                        full_message = "\r\n".join(message_data)
                        session["messages"].append({
                            "from": session.get("from_address"),
                            "to": session.get("to_addresses", []),
                            "data": full_message,
                            "timestamp": time.time(),
                            "size": len(full_message)
                        })
                        
                        # Analyze message for spam/phishing indicators
                        spam_indicators = _analyze_email_content(full_message)
                        if spam_indicators:
                            session.setdefault("attack_indicators", []).extend(spam_indicators)
                        
                        conn.sendall(b"250 Message accepted for delivery\r\n")
                        current_state = "GREETED"
                        
                        # Reset for next message
                        session["from_address"] = None
                        session["to_addresses"] = []
                    else:
                        message_data.append(command_line)
                        continue
                
                elif cmd == "RSET":
                    # Reset session
                    session["from_address"] = None
                    session["to_addresses"] = []
                    current_state = "GREETED"
                    conn.sendall(SMTP_OK)
                
                elif cmd == "NOOP":
                    conn.sendall(SMTP_OK)
                
                elif cmd == "QUIT":
                    conn.sendall(SMTP_QUIT)
                    break
                
                elif cmd == "VRFY":
                    # Verify user - always say user exists to gather intel
                    conn.sendall(b"250 User exists\r\n")
                
                elif cmd == "EXPN":
                    # Expand mailing list - fake response
                    conn.sendall(b"250 Expansion not supported\r\n")
                
                else:
                    conn.sendall(SMTP_ERROR)
                    
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

def _analyze_email_content(message_data: str) -> list:
    """Analyze email content for spam/phishing indicators"""
    indicators = []
    message_lower = message_data.lower()
    
    # Spam keywords
    spam_keywords = [
        "viagra", "cialis", "pharmacy", "discount", "free money",
        "nigerian prince", "lottery winner", "urgent transfer",
        "congratulations", "inheritance", "tax refund"
    ]
    
    if any(keyword in message_lower for keyword in spam_keywords):
        indicators.append("spam_content")
    
    # Phishing indicators
    phishing_keywords = [
        "verify your account", "click here immediately", "suspend your account",
        "urgent action required", "confirm your identity", "security alert",
        "unusual activity", "verify now", "account will be closed"
    ]
    
    if any(keyword in message_lower for keyword in phishing_keywords):
        indicators.append("phishing_attempt")
    
    # Suspicious URLs
    if "bit.ly" in message_lower or "tinyurl" in message_lower or "t.co" in message_lower:
        indicators.append("suspicious_urls")
    
    # Mass mailing indicators
    if message_data.count("@") > 10:  # Multiple recipients
        indicators.append("mass_mailing")
    
    # Malware indicators
    malware_keywords = [
        "download attachment", "run this file", "install software",
        ".exe", ".scr", ".bat", ".com", ".pif"
    ]
    
    if any(keyword in message_lower for keyword in malware_keywords):
        indicators.append("malware_distribution")
    
    return indicators

def run_smtp_server(bind: str = BIND_IP, port: int = SMTP_PORT):
    """Run the SMTP honeypot server"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((bind, port))
        s.listen(5)
        print(f"[+] SMTP honeypot listening on {bind}:{port}")
        
        while True:
            try:
                conn, addr = s.accept()
                thread = threading.Thread(target=_handle_smtp_connection, args=(conn, addr), daemon=True)
                thread.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] SMTP server error: {e}")
                
    except Exception as e:
        print(f"[!] Failed to start SMTP server: {e}")
    finally:
        s.close()
