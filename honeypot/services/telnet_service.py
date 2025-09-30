"""
Telnet Honeypot Service
Simulates a Telnet server to capture remote access attacks
"""

import socket
import threading
import time
from honeypot.logger import log_event
from honeypot.config import BIND_IP, SSH_SESSION_TIMEOUT

TELNET_PORT = 23

# Telnet protocol constants
IAC = 255  # Interpret As Command
WILL = 251
WONT = 252
DO = 253
DONT = 254

def _handle_telnet_connection(conn: socket.socket, addr):
    peer = addr[0]
    session = {
        "service": "telnet",
        "peer": peer,
        "start_ts": time.time(),
        "commands": [],
        "auth_attempts": [],
        "login_prompts": [],
        "vulnerabilities_tested": [],
        "authenticated": False,
        "username": None,
        "system_info_requested": False
    }
    
    try:
        conn.settimeout(SSH_SESSION_TIMEOUT * 2)
        
        # Send initial telnet negotiations
        negotiations = [
            bytes([IAC, WILL, 1]),  # Echo
            bytes([IAC, WILL, 3]),  # Suppress Go Ahead
            bytes([IAC, DO, 24]),   # Terminal Type
            bytes([IAC, DO, 31]),   # Window Size
        ]
        
        for neg in negotiations:
            conn.sendall(neg)
        
        # Send banner and login prompt
        banner = b"\r\nUbuntu 20.04.3 LTS\r\n"
        banner += b"server01 login: "
        conn.sendall(banner)
        
        session["banner_sent"] = True
        state = "username"
        username = ""
        password_attempt = ""
        command_buffer = ""
        
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    session["commands"].append({"ts": time.time(), "note": "client_disconnected"})
                    break
                
                # Handle telnet protocol commands
                processed_data = b""
                i = 0
                while i < len(data):
                    if data[i] == IAC and i + 2 < len(data):
                        # Skip telnet commands
                        session["commands"].append({
                            "ts": time.time(),
                            "telnet_command": [data[i], data[i+1], data[i+2]]
                        })
                        i += 3
                    else:
                        processed_data += bytes([data[i]])
                        i += 1
                
                # Process actual user input
                text_input = processed_data.decode('utf-8', errors='replace')
                
                for char in text_input:
                    if char == '\r' or char == '\n':
                        if state == "username":
                            username = command_buffer.strip()
                            session["login_prompts"].append({
                                "ts": time.time(),
                                "username": username
                            })
                            
                            if username:
                                conn.sendall(b"Password: ")
                                state = "password"
                                command_buffer = ""
                            else:
                                conn.sendall(b"server01 login: ")
                                command_buffer = ""
                        
                        elif state == "password":
                            password_attempt = command_buffer.strip()
                            
                            # Log authentication attempt
                            session["auth_attempts"].append({
                                "username": username,
                                "password": password_attempt,
                                "timestamp": time.time(),
                                "success": False
                            })
                            session["username"] = username
                            
                            # Analyze for common attack patterns
                            if username.lower() in ['root', 'admin', 'administrator', 'user', 'guest', 'test']:
                                session["vulnerabilities_tested"].append("common_username_brute_force")
                            
                            if password_attempt.lower() in ['', 'password', '123456', 'admin', 'root', username.lower()]:
                                session["vulnerabilities_tested"].append("weak_password_attempt")
                            
                            if len(password_attempt) > 50:
                                session["vulnerabilities_tested"].append("buffer_overflow_attempt")
                            
                            # Always deny login
                            conn.sendall(b"\r\nLogin incorrect\r\n")
                            time.sleep(2)  # Simulate authentication delay
                            conn.sendall(b"server01 login: ")
                            state = "username"
                            command_buffer = ""
                            username = ""
                        
                        elif state == "shell":
                            # If somehow authenticated (shouldn't happen), handle commands
                            command = command_buffer.strip()
                            session["commands"].append({
                                "ts": time.time(),
                                "shell_command": command
                            })
                            
                            # Analyze commands for malicious activity
                            cmd_lower = command.lower()
                            if any(pattern in cmd_lower for pattern in [
                                'cat /etc/passwd', 'cat /etc/shadow', 'ls -la /',
                                'whoami', 'id', 'uname -a', 'ps aux', 'netstat',
                                'wget', 'curl', 'nc ', 'ncat', 'bash', 'sh',
                                'python', 'perl', 'ruby', 'gcc', 'make'
                            ]):
                                session["vulnerabilities_tested"].append("system_reconnaissance")
                            
                            if any(pattern in cmd_lower for pattern in [
                                'rm -rf', 'dd if=', 'mkfs', 'fdisk', 'crontab',
                                'sudo', 'su -', 'passwd', 'useradd', 'usermod'
                            ]):
                                session["vulnerabilities_tested"].append("system_modification_attempt")
                            
                            # Send fake response
                            if 'ls' in cmd_lower:
                                conn.sendall(b"bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\r\n")
                            elif 'whoami' in cmd_lower:
                                conn.sendall(b"user\r\n")
                            elif 'pwd' in cmd_lower:
                                conn.sendall(b"/home/user\r\n")
                            elif 'cat /etc/passwd' in cmd_lower:
                                session["vulnerabilities_tested"].append("passwd_file_access")
                                conn.sendall(b"root:x:0:0:root:/root:/bin/bash\r\nuser:x:1000:1000:user:/home/user:/bin/bash\r\n")
                            elif 'uname' in cmd_lower:
                                conn.sendall(b"Linux server01 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux\r\n")
                            elif command:
                                conn.sendall(f"{command}: command not found\r\n".encode())
                            
                            conn.sendall(b"user@server01:~$ ")
                            command_buffer = ""
                    
                    elif char == '\x08' or char == '\x7f':  # Backspace or DEL
                        if command_buffer:
                            command_buffer = command_buffer[:-1]
                    
                    elif char == '\x03':  # Ctrl+C
                        session["commands"].append({"ts": time.time(), "interrupt": "ctrl_c"})
                        if state == "shell":
                            conn.sendall(b"\r\nuser@server01:~$ ")
                        command_buffer = ""
                    
                    elif char == '\x04':  # Ctrl+D (EOF)
                        session["commands"].append({"ts": time.time(), "interrupt": "ctrl_d"})
                        break
                    
                    elif ord(char) >= 32 and ord(char) <= 126:  # Printable characters
                        command_buffer += char
                        
                        # Echo character back (except for password)
                        if state != "password":
                            conn.sendall(char.encode())
                
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

def run_telnet_server(bind: str = BIND_IP, port: int = TELNET_PORT):
    """Run the Telnet honeypot server"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((bind, port))
        s.listen(5)
        print(f"[+] Telnet honeypot listening on {bind}:{port}")
        
        while True:
            try:
                conn, addr = s.accept()
                thread = threading.Thread(target=_handle_telnet_connection, args=(conn, addr), daemon=True)
                thread.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Telnet server error: {e}")
                
    except Exception as e:
        print(f"[!] Failed to start Telnet server: {e}")
    finally:
        s.close()
