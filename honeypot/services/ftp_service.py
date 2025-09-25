import socket
import threading
import time
from honeypot.logger import log_event
from honeypot.config import BIND_IP, FTP_PORT, SSH_SESSION_TIMEOUT

FTP_BANNER = b"220 ProFTPD 1.3.6 Server ready.\r\n"
FTP_READY = b"331 Password required for {}.\r\n"
FTP_AUTH_FAILED = b"530 Login incorrect.\r\n"
FTP_AUTH_SUCCESS = b"230 User {} logged in.\r\n"
FTP_PWD_RESPONSE = b"257 \"/\" is current directory.\r\n"
FTP_LIST_RESPONSE = b"150 Opening ASCII mode data connection for file list.\r\n226 Transfer complete.\r\n"
FTP_UNKNOWN = b"500 Unknown command.\r\n"

def _handle_ftp_connection(conn: socket.socket, addr):
    peer = addr[0]
    session = {
        "service": "ftp",
        "peer": peer,
        "start_ts": time.time(),
        "commands": [],
        "auth_attempts": [],
        "username": None,
        "authenticated": False
    }
    
    current_user = None
    
    try:
        conn.settimeout(SSH_SESSION_TIMEOUT)
        # Send welcome banner
        conn.sendall(FTP_BANNER)
        session["banner_sent"] = True
        
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    session["commands"].append({"ts": time.time(), "note": "client_disconnected"})
                    break
                
                command = data.decode('utf-8', errors='replace').strip()
                session["commands"].append({"ts": time.time(), "command": command})
                
                # Parse FTP commands
                parts = command.split(' ', 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""
                
                if cmd == "USER":
                    current_user = arg
                    session["username"] = arg
                    response = FTP_READY.format(arg.encode())
                    conn.sendall(response)
                    
                elif cmd == "PASS":
                    auth_attempt = {
                        "username": current_user or "unknown",
                        "password": arg,
                        "timestamp": time.time(),
                        "success": False
                    }
                    session["auth_attempts"].append(auth_attempt)
                    
                    # Always fail authentication but log the attempt
                    conn.sendall(FTP_AUTH_FAILED)
                    
                elif cmd == "PWD":
                    conn.sendall(FTP_PWD_RESPONSE)
                    
                elif cmd == "LIST" or cmd == "NLST":
                    conn.sendall(FTP_LIST_RESPONSE)
                    
                elif cmd == "CWD":
                    conn.sendall(b"250 CWD command successful.\r\n")
                    
                elif cmd == "TYPE":
                    conn.sendall(b"200 Type set to {}.\r\n".format(arg.encode()))
                    
                elif cmd == "PASV":
                    conn.sendall(b"227 Entering passive mode (127,0,0,1,20,21).\r\n")
                    
                elif cmd == "QUIT":
                    conn.sendall(b"221 Goodbye.\r\n")
                    break
                    
                else:
                    conn.sendall(FTP_UNKNOWN)
                    
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

def run_ftp_server(bind: str = BIND_IP, port: int = FTP_PORT):
    """Run the FTP honeypot server"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((bind, port))
        s.listen(5)
        print(f"[+] FTP honeypot listening on {bind}:{port}")
        
        while True:
            try:
                conn, addr = s.accept()
                thread = threading.Thread(target=_handle_ftp_connection, args=(conn, addr), daemon=True)
                thread.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] FTP server error: {e}")
                
    except Exception as e:
        print(f"[!] Failed to start FTP server: {e}")
    finally:
        s.close()
