"""
SMTP Honeypot Service
Simulates an SMTP server to capture email-based attacks
"""

import socket
import threading
import time
import base64
from honeypot.logger import log_event
from honeypot.config import BIND_IP, SSH_SESSION_TIMEOUT

SMTP_PORT = 25
SMTP_SUBMISSION_PORT = 587
SMTP_SSL_PORT = 465

SMTP_BANNER = b"220 mail.company.com ESMTP Postfix (Ubuntu)\r\n"
SMTP_HELP = b"214-2.0.0 This is Postfix\r\n214-2.0.0 See http://www.postfix.org/\r\n214 2.0.0 End of HELP info\r\n"
SMTP_QUIT = b"221 2.0.0 Bye\r\n"

def _handle_smtp_connection(conn: socket.socket, addr, port):
    peer = addr[0]
    session = {
        "service": "smtp",
        "peer": peer,
        "port": port,
        "start_ts": time.time(),
        "commands": [],
        "auth_attempts": [],
        "emails": [],
        "vulnerabilities_tested": [],
        "authenticated": False,
        "username": None
    }
    
    try:
        conn.settimeout(SSH_SESSION_TIMEOUT * 2)  # SMTP sessions can be longer
        
        # Send banner
        conn.sendall(SMTP_BANNER)
        session["banner_sent"] = True
        
        current_email = {}
        data_mode = False
        
        while True:
            try:
                if data_mode:
                    # In DATA mode, read until we see a line with just "."
                    email_data = b""
                    while True:
                        line = conn.recv(1024)
                        if not line:
                            break
                        email_data += line
                        if b"\r\n.\r\n" in email_data or b"\n.\n" in email_data:
                            break
                    
                    current_email["data"] = email_data.decode('utf-8', errors='replace')
                    session["emails"].append(current_email.copy())
                    current_email = {}
                    data_mode = False
                    
                    # Analyze email for attacks
                    if any(pattern in email_data.decode('utf-8', errors='replace').lower() 
                           for pattern in ['<script', 'javascript:', 'eval(', 'exec(']):
                        session["vulnerabilities_tested"].append("email_xss")
                    
                    if any(pattern in email_data.decode('utf-8', errors='replace').lower() 
                           for pattern in ['drop table', 'union select', 'or 1=1']):
                        session["vulnerabilities_tested"].append("email_sql_injection")
                    
                    conn.sendall(b"250 2.0.0 Ok: queued\r\n")
                    continue
                
                data = conn.recv(1024)
                if not data:
                    session["commands"].append({"ts": time.time(), "note": "client_disconnected"})
                    break
                
                command_line = data.decode('utf-8', errors='replace').strip()
                session["commands"].append({"ts": time.time(), "command": command_line})
                
                # Parse SMTP commands
                parts = command_line.split(' ', 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""
                
                if cmd == "HELO" or cmd == "EHLO":
                    if cmd == "EHLO":
                        response = b"250-mail.company.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-ETRN\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250-AUTH=PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8\r\n"
                    else:
                        response = b"250 mail.company.com\r\n"
                    conn.sendall(response)
                    
                elif cmd == "AUTH":
                    auth_type = arg.split()[0].upper() if arg else "UNKNOWN"
                    if auth_type == "PLAIN":
                        conn.sendall(b"334 \r\n")  # Request auth data
                        auth_data = conn.recv(1024)
                        try:
                            decoded = base64.b64decode(auth_data.strip()).decode('utf-8')
                            parts = decoded.split('\x00')
                            if len(parts) >= 3:
                                username = parts[1]
                                password = parts[2]
                                session["auth_attempts"].append({
                                    "method": "PLAIN",
                                    "username": username,
                                    "password": password,
                                    "timestamp": time.time(),
                                    "success": False
                                })
                                session["username"] = username
                        except:
                            pass
                        conn.sendall(b"535 5.7.8 Authentication failed\r\n")
                    
                    elif auth_type == "LOGIN":
                        conn.sendall(b"334 VXNlcm5hbWU6\r\n")  # "Username:" in base64
                        username_data = conn.recv(1024)
                        conn.sendall(b"334 UGFzc3dvcmQ6\r\n")  # "Password:" in base64
                        password_data = conn.recv(1024)
                        
                        try:
                            username = base64.b64decode(username_data.strip()).decode('utf-8')
                            password = base64.b64decode(password_data.strip()).decode('utf-8')
                            session["auth_attempts"].append({
                                "method": "LOGIN",
                                "username": username,
                                "password": password,
                                "timestamp": time.time(),
                                "success": False
                            })
                            session["username"] = username
                        except:
                            pass
                        conn.sendall(b"535 5.7.8 Authentication failed\r\n")
                    
                    else:
                        conn.sendall(b"504 5.5.4 Unrecognized authentication type\r\n")
                
                elif cmd == "MAIL":
                    if "FROM:" in arg.upper():
                        from_addr = arg.upper().replace("FROM:", "").strip()
                        current_email["from"] = from_addr
                        
                        # Test for SMTP injection
                        if any(char in from_addr for char in ['\r', '\n', '\x00']):
                            session["vulnerabilities_tested"].append("smtp_injection")
                        
                        conn.sendall(b"250 2.1.0 Ok\r\n")
                    else:
                        conn.sendall(b"501 5.5.4 Syntax error\r\n")
                
                elif cmd == "RCPT":
                    if "TO:" in arg.upper():
                        to_addr = arg.upper().replace("TO:", "").strip()
                        if "to" not in current_email:
                            current_email["to"] = []
                        current_email["to"].append(to_addr)
                        
                        # Test for recipient enumeration
                        if any(pattern in to_addr.lower() for pattern in ['admin', 'test', 'user', 'guest']):
                            session["vulnerabilities_tested"].append("recipient_enumeration")
                        
                        conn.sendall(b"250 2.1.5 Ok\r\n")
                    else:
                        conn.sendall(b"501 5.5.4 Syntax error\r\n")
                
                elif cmd == "DATA":
                    conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    data_mode = True
                
                elif cmd == "VRFY":
                    # Email enumeration attempt
                    email = arg.strip()
                    session["vulnerabilities_tested"].append("email_enumeration")
                    session["commands"].append({"ts": time.time(), "vrfy_target": email})
                    conn.sendall(b"252 2.0.0 Cannot VRFY user, but will accept message\r\n")
                
                elif cmd == "EXPN":
                    # Mailing list enumeration
                    session["vulnerabilities_tested"].append("mailing_list_enumeration")
                    conn.sendall(b"502 5.5.1 EXPN not implemented\r\n")
                
                elif cmd == "HELP":
                    conn.sendall(SMTP_HELP)
                
                elif cmd == "NOOP":
                    conn.sendall(b"250 2.0.0 Ok\r\n")
                
                elif cmd == "RSET":
                    current_email = {}
                    conn.sendall(b"250 2.0.0 Ok\r\n")
                
                elif cmd == "QUIT":
                    conn.sendall(SMTP_QUIT)
                    break
                
                else:
                    conn.sendall(b"502 5.5.1 Command not implemented\r\n")
                    
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
                thread = threading.Thread(target=_handle_smtp_connection, args=(conn, addr, port), daemon=True)
                thread.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] SMTP server error: {e}")
                
    except Exception as e:
        print(f"[!] Failed to start SMTP server: {e}")
    finally:
        s.close()

def run_smtp_submission_server(bind: str = BIND_IP):
    """Run SMTP submission service on port 587"""
    run_smtp_server(bind, SMTP_SUBMISSION_PORT)

def run_smtp_ssl_server(bind: str = BIND_IP):
    """Run SMTP SSL service on port 465"""
    run_smtp_server(bind, SMTP_SSL_PORT)
