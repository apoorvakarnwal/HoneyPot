"""
Redis Honeypot Service
Simulates a Redis database server to capture NoSQL attacks
"""

import socket
import threading
import time
from honeypot.logger import log_event
from honeypot.config import BIND_IP, SSH_SESSION_TIMEOUT

REDIS_PORT = 6379

def _handle_redis_connection(conn: socket.socket, addr):
    peer = addr[0]
    session = {
        "service": "redis",
        "peer": peer,
        "start_ts": time.time(),
        "commands": [],
        "auth_attempts": [],
        "vulnerabilities_tested": [],
        "authenticated": False,
        "database": 0
    }
    
    # Fake Redis data store
    fake_keys = {
        "user:1": '{"username":"admin","password":"hash123","role":"admin"}',
        "user:2": '{"username":"guest","password":"guest123","role":"user"}',
        "session:abc123": '{"user_id":"1","expires":"2025-12-31"}',
        "config:app": '{"debug":false,"secret_key":"supersecret123"}',
        "cache:stats": '{"visits":1234,"users":56}',
        "queue:jobs": "job1,job2,job3"
    }
    
    try:
        conn.settimeout(SSH_SESSION_TIMEOUT * 2)
        
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    session["commands"].append({"ts": time.time(), "note": "client_disconnected"})
                    break
                
                # Parse Redis protocol (RESP)
                commands_raw = data.decode('utf-8', errors='replace').strip()
                session["commands"].append({
                    "ts": time.time(),
                    "raw_command": commands_raw[:200]  # Limit log size
                })
                
                # Simple RESP parser for basic commands
                lines = commands_raw.split('\r\n')
                if not lines:
                    continue
                
                # Handle array format (*n\r\n$len\r\ncommand\r\n...)
                if lines[0].startswith('*'):
                    try:
                        num_elements = int(lines[0][1:])
                        command_parts = []
                        line_idx = 1
                        
                        for i in range(num_elements):
                            if line_idx < len(lines) and lines[line_idx].startswith('$'):
                                line_idx += 1  # Skip length indicator
                                if line_idx < len(lines):
                                    command_parts.append(lines[line_idx])
                                line_idx += 1
                        
                        if command_parts:
                            cmd = command_parts[0].upper()
                            args = command_parts[1:] if len(command_parts) > 1 else []
                        else:
                            continue
                            
                    except (ValueError, IndexError):
                        conn.sendall(b"-ERR Protocol error\r\n")
                        continue
                else:
                    # Simple format (command arg1 arg2...)
                    parts = commands_raw.split()
                    if not parts:
                        continue
                    cmd = parts[0].upper()
                    args = parts[1:]
                
                # Process Redis commands
                if cmd == "PING":
                    conn.sendall(b"+PONG\r\n")
                
                elif cmd == "AUTH":
                    password = args[0] if args else ""
                    session["auth_attempts"].append({
                        "password": password,
                        "timestamp": time.time(),
                        "success": False
                    })
                    
                    # Test for common passwords
                    if password.lower() in ['', 'redis', 'password', '123456', 'admin']:
                        session["vulnerabilities_tested"].append("weak_password_attempt")
                    
                    # Always deny authentication
                    conn.sendall(b"-ERR invalid password\r\n")
                
                elif cmd == "INFO":
                    # Simulate Redis INFO response with fake data
                    info_response = """# Server
redis_version:6.2.7
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:1234567890
redis_mode:standalone
os:Linux 5.4.0-42-generic x86_64
arch_bits:64
multiplexing_api:epoll
gcc_version:9.4.0
process_id:1234
run_id:abcd1234567890
tcp_port:6379
uptime_in_seconds:86400
uptime_in_days:1

# Clients
connected_clients:5
client_longest_output_list:0
client_biggest_input_buf:0
blocked_clients:0

# Memory
used_memory:1048576
used_memory_human:1.00M
used_memory_rss:2097152
used_memory_peak:1572864

# Stats
total_connections_received:123
total_commands_processed:456
instantaneous_ops_per_sec:0
rejected_connections:0
"""
                    response = f"${len(info_response)}\r\n{info_response}\r\n"
                    conn.sendall(response.encode())
                    session["vulnerabilities_tested"].append("information_disclosure")
                
                elif cmd == "CONFIG":
                    if args and args[0].upper() == "GET":
                        # Dangerous CONFIG GET attempt
                        session["vulnerabilities_tested"].append("config_extraction")
                        conn.sendall(b"*0\r\n")  # Empty array response
                    elif args and args[0].upper() == "SET":
                        # Dangerous CONFIG SET attempt
                        session["vulnerabilities_tested"].append("config_modification")
                        conn.sendall(b"-ERR Configuration is read-only\r\n")
                    else:
                        conn.sendall(b"-ERR Unknown CONFIG subcommand\r\n")
                
                elif cmd == "EVAL" or cmd == "EVALSHA":
                    # Lua script execution attempt - very dangerous
                    script = args[0] if args else ""
                    session["vulnerabilities_tested"].append("lua_code_injection")
                    session["commands"].append({
                        "ts": time.time(),
                        "lua_script": script[:500]  # Log script content
                    })
                    
                    # Check for dangerous Lua patterns
                    if any(pattern in script.lower() for pattern in [
                        'os.execute', 'io.popen', 'loadfile', 'dofile', 'require'
                    ]):
                        session["vulnerabilities_tested"].append("system_command_injection")
                    
                    conn.sendall(b"-ERR Script execution disabled\r\n")
                
                elif cmd == "FLUSHDB" or cmd == "FLUSHALL":
                    session["vulnerabilities_tested"].append("data_destruction_attempt")
                    conn.sendall(b"-ERR Command disabled\r\n")
                
                elif cmd == "SHUTDOWN":
                    session["vulnerabilities_tested"].append("service_disruption")
                    conn.sendall(b"-ERR Command disabled\r\n")
                
                elif cmd == "SLAVEOF" or cmd == "REPLICAOF":
                    # Replication takeover attempt
                    session["vulnerabilities_tested"].append("replication_hijack")
                    conn.sendall(b"-ERR Replication disabled\r\n")
                
                elif cmd == "MIGRATE":
                    session["vulnerabilities_tested"].append("data_migration_attempt")
                    conn.sendall(b"-ERR Migration disabled\r\n")
                
                elif cmd == "RESTORE":
                    session["vulnerabilities_tested"].append("data_restoration_attempt")
                    conn.sendall(b"-ERR Restore disabled\r\n")
                
                elif cmd == "DEBUG":
                    session["vulnerabilities_tested"].append("debug_command_attempt")
                    conn.sendall(b"-ERR Debug commands disabled\r\n")
                
                elif cmd == "GET":
                    key = args[0] if args else ""
                    if key in fake_keys:
                        value = fake_keys[key]
                        response = f"${len(value)}\r\n{value}\r\n"
                        conn.sendall(response.encode())
                        
                        # Log sensitive data access attempts
                        if any(pattern in key.lower() for pattern in ['user', 'admin', 'password', 'secret', 'config']):
                            session["vulnerabilities_tested"].append("sensitive_data_access")
                    else:
                        conn.sendall(b"$-1\r\n")  # Null response
                
                elif cmd == "SET":
                    key = args[0] if args else ""
                    value = args[1] if len(args) > 1 else ""
                    
                    # Check for malicious payloads
                    if any(pattern in value.lower() for pattern in [
                        '<script', 'javascript:', 'eval(', 'system(', 'exec('
                    ]):
                        session["vulnerabilities_tested"].append("malicious_payload_injection")
                    
                    conn.sendall(b"+OK\r\n")
                
                elif cmd == "KEYS":
                    pattern = args[0] if args else "*"
                    session["vulnerabilities_tested"].append("key_enumeration")
                    
                    # Return some fake keys based on pattern
                    if pattern == "*":
                        keys = list(fake_keys.keys())[:5]  # Limit response
                    else:
                        keys = [k for k in fake_keys.keys() if pattern.replace('*', '') in k][:5]
                    
                    response = f"*{len(keys)}\r\n"
                    for key in keys:
                        response += f"${len(key)}\r\n{key}\r\n"
                    conn.sendall(response.encode())
                
                elif cmd == "SCAN":
                    session["vulnerabilities_tested"].append("database_scanning")
                    # Return cursor 0 (end of scan) and some fake keys
                    response = "*2\r\n$1\r\n0\r\n*3\r\n$6\r\nuser:1\r\n$6\r\nuser:2\r\n$10\r\nconfig:app\r\n"
                    conn.sendall(response.encode())
                
                elif cmd == "MONITOR":
                    session["vulnerabilities_tested"].append("traffic_monitoring")
                    conn.sendall(b"+OK\r\n")
                    # Don't actually monitor - just acknowledge
                
                elif cmd == "CLIENT":
                    if args and args[0].upper() == "LIST":
                        session["vulnerabilities_tested"].append("client_enumeration")
                        # Fake client list
                        clients = "id=1 addr=127.0.0.1:52345 fd=7 name= age=123 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=0 qbuf-free=32768 obl=0 oll=0 omem=0 events=r cmd=ping\r\n"
                        response = f"${len(clients)}\r\n{clients}\r\n"
                        conn.sendall(response.encode())
                    else:
                        conn.sendall(b"-ERR Unknown CLIENT subcommand\r\n")
                
                elif cmd == "QUIT":
                    conn.sendall(b"+OK\r\n")
                    break
                
                else:
                    # Unknown command
                    session["commands"].append({
                        "ts": time.time(),
                        "unknown_command": cmd,
                        "args": args[:5]  # Limit args logged
                    })
                    conn.sendall(f"-ERR unknown command '{cmd}'\r\n".encode())
                
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

def run_redis_server(bind: str = BIND_IP, port: int = REDIS_PORT):
    """Run the Redis honeypot server"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind((bind, port))
        s.listen(5)
        print(f"[+] Redis honeypot listening on {bind}:{port}")
        
        while True:
            try:
                conn, addr = s.accept()
                thread = threading.Thread(target=_handle_redis_connection, args=(conn, addr), daemon=True)
                thread.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Redis server error: {e}")
                
    except Exception as e:
        print(f"[!] Failed to start Redis server: {e}")
    finally:
        s.close()
