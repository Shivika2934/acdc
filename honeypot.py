#!/usr/bin/env python3
"""
Honeypot/Deception Module
A comprehensive honeypot system that simulates common services to detect and log intrusion attempts.
"""

import socket
import threading
import logging
import datetime
import json
import time
import random
import argparse
from typing import Dict, List, Tuple
import sys
import signal

class HoneypotLogger:
    """Enhanced logging system for honeypot events"""
    
    def __init__(self, log_file="honeypot.log", json_log_file="honeypot_events.json"):
        self.log_file = log_file
        self.json_log_file = json_log_file
        self.events = []
        
        # Setup text logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def log_connection(self, service: str, client_ip: str, client_port: int, data: str = ""):
        """Log connection attempt with detailed information"""
        timestamp = datetime.datetime.now().isoformat()
        
        # Text log
        log_msg = f"[{service}] Connection from {client_ip}:{client_port}"
        if data:
            log_msg += f" - Data: {repr(data)}"
        self.logger.info(log_msg)
        
        # JSON log for structured analysis
        event = {
            "timestamp": timestamp,
            "service": service,
            "client_ip": client_ip,
            "client_port": client_port,
            "data": data,
            "event_type": "connection"
        }
        self.events.append(event)
        self._save_json_log()
    
    def log_attack_attempt(self, service: str, client_ip: str, attack_type: str, payload: str):
        """Log potential attack attempts"""
        timestamp = datetime.datetime.now().isoformat()
        
        log_msg = f"[{service}] ATTACK DETECTED from {client_ip} - Type: {attack_type} - Payload: {repr(payload)}"
        self.logger.warning(log_msg)
        
        event = {
            "timestamp": timestamp,
            "service": service,
            "client_ip": client_ip,
            "attack_type": attack_type,
            "payload": payload,
            "event_type": "attack_attempt"
        }
        self.events.append(event)
        self._save_json_log()
    
    def _save_json_log(self):
        """Save events to JSON file"""
        try:
            with open(self.json_log_file, 'w') as f:
                json.dump(self.events, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save JSON log: {e}")

class BaseHoneypot:
    """Base class for all honeypot services"""
    
    def __init__(self, port: int, service_name: str, logger: HoneypotLogger):
        self.port = port
        self.service_name = service_name
        self.logger = logger
        self.socket = None
        self.running = False
        self.thread = None
    
    def start(self):
        """Start the honeypot service"""
        self.running = True
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()
        print(f"[+] {self.service_name} honeypot started on port {self.port}")
    
    def stop(self):
        """Stop the honeypot service"""
        self.running = False
        if self.socket:
            self.socket.close()
        print(f"[-] {self.service_name} honeypot stopped")
    
    def _run_server(self):
        """Main server loop"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(5)
            
            while self.running:
                try:
                    client_socket, client_address = self.socket.accept()
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                except OSError:
                    break
                    
        except Exception as e:
            self.logger.logger.error(f"{self.service_name} server error: {e}")
    
    def _handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        """Handle individual client connections - to be overridden by subclasses"""
        pass

class SSHHoneypot(BaseHoneypot):
    """SSH Honeypot simulation"""
    
    def __init__(self, port: int, logger: HoneypotLogger):
        super().__init__(port, "SSH", logger)
        self.banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    
    def _handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        client_ip, client_port = client_address
        
        try:
            # Send SSH banner
            client_socket.send((self.banner + "\r\n").encode())
            self.logger.log_connection("SSH", client_ip, client_port, f"Banner sent: {self.banner}")
            
            # Receive and log any data
            client_socket.settimeout(10)
            data = client_socket.recv(1024).decode('utf-8', errors='ignore')
            
            if data:
                self.logger.log_connection("SSH", client_ip, client_port, data)
                
                # Check for common SSH attack patterns
                if any(pattern in data.lower() for pattern in ['brute', 'force', 'password', 'login']):
                    self.logger.log_attack_attempt("SSH", client_ip, "Brute Force", data)
                
                # Send fake authentication failure
                client_socket.send(b"Permission denied (publickey,password).\r\n")
        
        except Exception as e:
            self.logger.log_connection("SSH", client_ip, client_port, f"Error: {str(e)}")
        finally:
            client_socket.close()

class FTPHoneypot(BaseHoneypot):
    """FTP Honeypot simulation"""
    
    def __init__(self, port: int, logger: HoneypotLogger):
        super().__init__(port, "FTP", logger)
        self.banner = "220 ProFTPD 1.3.6 Server ready."
    
    def _handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        client_ip, client_port = client_address
        
        try:
            # Send FTP welcome banner
            client_socket.send((self.banner + "\r\n").encode())
            self.logger.log_connection("FTP", client_ip, client_port, f"Banner sent: {self.banner}")
            
            client_socket.settimeout(30)
            
            while True:
                try:
                    data = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                    if not data:
                        break
                    
                    self.logger.log_connection("FTP", client_ip, client_port, data)
                    
                    # Parse FTP commands
                    command = data.split()[0].upper() if data.split() else ""
                    
                    if command == "USER":
                        username = data.split()[1] if len(data.split()) > 1 else "anonymous"
                        client_socket.send(f"331 Password required for {username}.\r\n".encode())
                        if username.lower() in ['admin', 'root', 'administrator']:
                            self.logger.log_attack_attempt("FTP", client_ip, "Suspicious Login", data)
                    
                    elif command == "PASS":
                        password = data.split()[1] if len(data.split()) > 1 else ""
                        client_socket.send(b"530 Login incorrect.\r\n")
                        self.logger.log_attack_attempt("FTP", client_ip, "Password Attempt", data)
                    
                    elif command == "QUIT":
                        client_socket.send(b"221 Goodbye.\r\n")
                        break
                    
                    else:
                        client_socket.send(b"500 Unknown command.\r\n")
                
                except socket.timeout:
                    break
                except Exception:
                    break
        
        except Exception as e:
            self.logger.log_connection("FTP", client_ip, client_port, f"Error: {str(e)}")
        finally:
            client_socket.close()

class TelnetHoneypot(BaseHoneypot):
    """Telnet Honeypot simulation"""
    
    def __init__(self, port: int, logger: HoneypotLogger):
        super().__init__(port, "Telnet", logger)
    
    def _handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        client_ip, client_port = client_address
        
        try:
            # Send telnet login prompt
            client_socket.send(b"Ubuntu 20.04.3 LTS\r\nlogin: ")
            self.logger.log_connection("Telnet", client_ip, client_port, "Login prompt sent")
            
            client_socket.settimeout(30)
            attempts = 0
            
            while attempts < 3:
                try:
                    data = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                    if not data:
                        break
                    
                    self.logger.log_connection("Telnet", client_ip, client_port, data)
                    
                    if attempts == 0:
                        # Username received
                        client_socket.send(b"Password: ")
                        if data.lower() in ['admin', 'root', 'administrator', 'guest']:
                            self.logger.log_attack_attempt("Telnet", client_ip, "Suspicious Username", data)
                    else:
                        # Password received
                        client_socket.send(b"Login incorrect\r\nlogin: ")
                        self.logger.log_attack_attempt("Telnet", client_ip, "Password Attempt", data)
                    
                    attempts += 1
                
                except socket.timeout:
                    break
                except Exception:
                    break
            
            client_socket.send(b"Too many login attempts.\r\n")
        
        except Exception as e:
            self.logger.log_connection("Telnet", client_ip, client_port, f"Error: {str(e)}")
        finally:
            client_socket.close()

class HTTPHoneypot(BaseHoneypot):
    """HTTP Honeypot simulation"""
    
    def __init__(self, port: int, logger: HoneypotLogger):
        super().__init__(port, "HTTP", logger)
        self.attack_patterns = {
            'SQL Injection': [
                'union select', 'union all select', 
                'information_schema', 'sysdatabases',
                'substring(', 'concat(', 'group_concat',
                'having', 'when then', 'sleep(',
                '@@version', 'load_file', 'benchmark(',
                'hex(', 'unhex(', 'cast(', 'convert(',
            ],
            'XSS': [
                '<script', 'javascript:', 'vbscript:',
                'onerror=', 'onload=', 'eval(',
                'document.cookie', 'document.domain',
                'document.write', 'innerHTML',
                'fromcharcode', 'onclick=', 'onmouseover=',
                'onfocus=', 'onsubmit=', 'base64',
            ],
            'Path Traversal': [
                '../', '..\\', './/', '.\\\\',
                '/etc/passwd', '/etc/shadow',
                '/proc/self/', 'c:\\windows\\',
                'boot.ini', '/var/log/',
                '.htaccess', 'web.config',
            ],
            'Command Injection': [
                '&&', '||', '|', ';', '`',
                '$(',  '${', 'wget ', 'curl ',
                'nc ', 'bash', '/bin/sh',
                'chmod ', 'chown ', '>/dev/null',
                'ping ', 'nmap ', '/dev/tcp/',
            ],
            'File Upload': [
                '.php', '.jsp', '.asp', '.aspx',
                '.exe', '.dll', '.sh', '.pl',
                '.cgi', '.py', '.rb', '.htaccess',
                'multipart/form-data', 'content-type:',
            ],
            'Directory Scanning': [
                '/admin/', '/config/', '/backup/',
                '/wp-admin', '/phpmy', '/manager/',
                '/.git/', '/.env', '/install/',
                '/setup/', '/console/', '/debug/',
            ]
        }
    
    def _handle_client(self, client_socket: socket.socket, client_address: Tuple[str, int]):
        client_ip, client_port = client_address
        
        try:
            client_socket.settimeout(10)
            data = client_socket.recv(4096).decode('utf-8', errors='ignore')
            
            if data:
                self.logger.log_connection("HTTP", client_ip, client_port, data)
                
                # Check for attack patterns
                data_lower = data.lower()
                for attack_type, patterns in self.attack_patterns.items():
                    for pattern in patterns:
                        if pattern.lower() in data_lower:
                            self.logger.log_attack_attempt("HTTP", client_ip, attack_type, 
                                f"Pattern matched: {pattern}\nPayload: {data[:500]}")
                            break
                
                # Send fake HTTP response
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Server: Apache/2.4.41 (Ubuntu)\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: 157\r\n"
                    "\r\n"
                    "<html><head><title>Welcome</title></head>"
                    "<body><h1>Server Status</h1><p>System operational.</p>"
                    "<p>Last updated: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "</p>"
                    "</body></html>"
                )
                client_socket.send(response.encode())
        
        except Exception as e:
            self.logger.log_connection("HTTP", client_ip, client_port, f"Error: {str(e)}")
        finally:
            client_socket.close()

class HoneypotManager:
    """Main manager for all honeypot services"""
    
    COMMON_PORTS = {
        20: ('FTP-DATA', FTPHoneypot),
        21: ('FTP', FTPHoneypot),
        22: ('SSH', SSHHoneypot),
        23: ('TELNET', TelnetHoneypot),
        80: ('HTTP', HTTPHoneypot),
        443: ('HTTPS', HTTPHoneypot),
        2121: ('FTP-ALT', FTPHoneypot),
        2222: ('SSH-ALT', SSHHoneypot),
        2323: ('TELNET-ALT', TelnetHoneypot),
        8080: ('HTTP-ALT', HTTPHoneypot),
        8443: ('HTTPS-ALT', HTTPHoneypot)
    }

    # Add attack pattern to port mapping
    ATTACK_PORT_PATTERNS = {
        'SSH': {
            'patterns': ['ssh', 'openssh', 'sshd', 'authorized_keys', 'id_rsa', 'known_hosts'],
            'ports': [22, 2222]
        },
        'FTP': {
            'patterns': ['ftp', 'vsftpd', 'ftpd', 'anonymous', 'upload', 'download', 'pasv'],
            'ports': [21, 20, 2121]
        },
        'HTTP': {
            'patterns': [
                'get /', 'post /', 'head /', 'put /', 'delete /',
                'php', 'cgi', 'asp', 'jsp', '.htaccess', 'apache',
                'nginx', 'http://', 'https://'
            ],
            'ports': [80, 443, 8080, 8443]
        },
        'TELNET': {
            'patterns': ['telnet', 'telnetd', 'login:', 'password:'],
            'ports': [23, 2323]
        }
    }

    def __init__(self):
        self.logger = HoneypotLogger()
        self.honeypots = []
        self.running = False
    
    def identify_service(self, port: int):
        """Identify service type based on port number"""
        if port in self.COMMON_PORTS:
            return self.COMMON_PORTS[port]
        
        # Identify port ranges
        if 20 <= port <= 25:
            return ('STANDARD-SERVICE', HTTPHoneypot)
        elif 80 <= port <= 90:
            return ('HTTP-RANGE', HTTPHoneypot)
        elif 440 <= port <= 450:
            return ('HTTPS-RANGE', HTTPHoneypot)
        elif 8000 <= port <= 8999:
            return ('WEB-RANGE', HTTPHoneypot)
        
        return ('UNKNOWN', HTTPHoneypot)  # Default to HTTP honeypot for unknown ports
    
    def add_honeypot(self, port: int):
        """Add a honeypot service based on port"""
        try:
            service_name, honeypot_class = self.identify_service(port)
            honeypot = honeypot_class(port, self.logger)
            self.honeypots.append(honeypot)
            print(f"[+] Added {service_name} honeypot on port {port}")
            return True
        except Exception as e:
            print(f"Failed to create honeypot on port {port}: {e}")
            return False
    
    def start_all(self):
        """Start all honeypot services"""
        print("[+] Starting Honeypot Deception System")
        print("=" * 50)
        
        for honeypot in self.honeypots:
            try:
                honeypot.start()
            except Exception as e:
                print(f"Failed to start {honeypot.service_name}: {e}")
        
        self.running = True
        print("=" * 50)
        print("[+] All honeypots started. Monitoring for connections...")
        print("[!] Press Ctrl+C to stop")
    
    def stop_all(self):
        """Stop all honeypot services"""
        print("\n[!] Stopping all honeypots...")
        self.running = False
        
        for honeypot in self.honeypots:
            honeypot.stop()
        
        print("[+] All honeypots stopped")
        print(f"[+] Logs saved to: {self.logger.log_file} and {self.logger.json_log_file}")
    
    def identify_attack_target(self, data: str) -> List[int]:
        """Identify likely target ports based on attack patterns"""
        data_lower = data.lower()
        target_ports = set()
        
        for service, info in self.ATTACK_PORT_PATTERNS.items():
            if any(pattern in data_lower for pattern in info['patterns']):
                target_ports.update(info['ports'])
        
        return sorted(list(target_ports))
    
    def show_stats(self):
        """Display statistics about captured events"""
        if not self.logger.events:
            print("No events recorded yet.")
            return
        
        print("\n" + "=" * 50)
        print("HONEYPOT STATISTICS")
        print("=" * 50)
        
        # Count events by service
        service_counts = {}
        attack_counts = {}
        port_attack_map = {}  # Track attacks by targeted ports
        unique_ips = set()
        
        for event in self.logger.events:
            service = event['service']
            service_counts[service] = service_counts.get(service, 0) + 1
            
            if 'client_ip' in event:
                unique_ips.add(event['client_ip'])
            
            if event['event_type'] == 'attack_attempt':
                attack_type = event.get('attack_type', 'Unknown')
                attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
                
                # Analyze attack patterns to identify targeted ports
                if 'data' in event:
                    target_ports = self.identify_attack_target(event['data'])
                    for port in target_ports:
                        if port not in port_attack_map:
                            port_attack_map[port] = {'total': 0, 'types': {}}
                        port_attack_map[port]['total'] += 1
                        port_attack_map[port]['types'][attack_type] = \
                            port_attack_map[port]['types'].get(attack_type, 0) + 1
        
        print(f"Total Events: {len(self.logger.events)}")
        print(f"Unique IP Addresses: {len(unique_ips)}")
        print(f"Attack Attempts: {sum(1 for e in self.logger.events if e['event_type'] == 'attack_attempt')}")
        
        print("\nConnections by Service:")
        for service, count in sorted(service_counts.items()):
            print(f"  {service}: {count}")
        
        if attack_counts:
            print("\nAttack Types:")
            for attack_type, count in sorted(attack_counts.items()):
                print(f"  {attack_type}: {count}")
        
        if port_attack_map:
            print("\nAttacks by Target Port:")
            for port in sorted(port_attack_map.keys()):
                port_info = port_attack_map[port]
                service_name = self.COMMON_PORTS.get(port, ('Unknown',))[0]
                print(f"\n  Port {port} ({service_name}):")
                print(f"    Total Attacks: {port_info['total']}")
                print("    Attack Types:")
                for attack_type, count in sorted(port_info['types'].items()):
                    print(f"      {attack_type}: {count}")
        
        print("=" * 50)

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[!] Received interrupt signal")
    if 'manager' in globals():
        manager.stop_all()
    sys.exit(0)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Honeypot Deception System")
    parser.add_argument("--ports", type=int, nargs="+", default=[21, 22, 23, 80, 8080],
                      help="List of ports to monitor (default: 21 22 23 80 8080)")
    parser.add_argument("--stats-interval", type=int, default=300,
                      help="Stats display interval in seconds (default: 300)")
    
    args = parser.parse_args()
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create manager and add honeypots
    global manager
    manager = HoneypotManager()
    
    print("Setting up honeypots...")
    for port in args.ports:
        manager.add_honeypot(port)
    
    # Start all services
    manager.start_all()
    
    # Main monitoring loop
    try:
        last_stats_time = time.time()
        while True:
            time.sleep(1)
            
            # Show periodic stats
            if time.time() - last_stats_time > args.stats_interval:
                manager.show_stats()
                last_stats_time = time.time()
                
    except KeyboardInterrupt:
        pass
    finally:
        manager.stop_all()

if __name__ == "__main__":
    main()