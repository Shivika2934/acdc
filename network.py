#!/usr/bin/env python3
"""
Advanced Network Traffic Analysis Module
Comprehensive network monitoring and threat detection system using Scapy
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, get_if_list, conf
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
import os
import threading
import time
import argparse
import sys
import signal
import ipaddress
import re
from typing import Dict, List, Set, Optional, Tuple
import sqlite3
import geoip2.database
import hashlib

class NetworkAnalyzer:
    """Advanced network traffic analyzer with multiple detection algorithms"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'arp_packets': 0,
            'alerts_generated': 0,
            'start_time': datetime.now()
        }
        
        # Tracking structures
        self.syn_attempts = defaultdict(lambda: deque(maxlen=1000))
        self.port_scans = defaultdict(lambda: {'ports': set(), 'timestamps': deque(maxlen=1000)})
        self.failed_connections = defaultdict(lambda: deque(maxlen=500))
        self.bandwidth_usage = defaultdict(lambda: {'bytes': 0, 'packets': 0, 'last_reset': datetime.now()})
        self.connection_states = defaultdict(dict)
        self.dns_queries = defaultdict(list)
        self.suspicious_payloads = []
        
        # Whitelist and blacklist
        self.whitelist_ips = set(config.get('whitelist_ips', []))
        self.blacklist_ips = set(config.get('blacklist_ips', []))
        
        # Initialize database
        self.init_database()
        
        # Threading controls
        self.running = False
        self.analysis_thread = None
        self.cleanup_thread = None
        
        print(f"[+] Network Analyzer initialized")
        print(f"[+] Monitoring interface: {config.get('interface', 'auto')}")
        print(f"[+] Log file: {config.get('log_file', 'network_analysis.json')}")
    
    def init_database(self):
        """Initialize SQLite database for efficient storage and querying"""
        self.db_file = self.config.get('db_file', 'network_analysis.db')
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        self.db_lock = threading.Lock()
        
        cursor = self.conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                flags TEXT,
                payload_size INTEGER,
                payload_hash TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                severity TEXT,
                description TEXT,
                metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                metric_name TEXT,
                metric_value TEXT
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
        
        self.conn.commit()
    
    def log_packet(self, packet_data: Dict):
        """Log packet data to database"""
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, 
                                   protocol, flags, payload_size, payload_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet_data['timestamp'],
                packet_data['src_ip'],
                packet_data['dst_ip'],
                packet_data.get('src_port'),
                packet_data.get('dst_port'),
                packet_data['protocol'],
                packet_data.get('flags', ''),
                packet_data.get('payload_size', 0),
                packet_data.get('payload_hash', '')
            ))
            self.conn.commit()
    
    def log_alert(self, alert_type: str, src_ip: str, dst_ip: str, severity: str, 
                  description: str, metadata: Dict = None):
        """Log security alert"""
        timestamp = datetime.now().isoformat()
        
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (timestamp, alert_type, src_ip, dst_ip, severity, description, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp, alert_type, src_ip, dst_ip, severity, description,
                json.dumps(metadata) if metadata else ''
            ))
            self.conn.commit()
        
        self.stats['alerts_generated'] += 1
        
        # Also log to JSON file for real-time monitoring
        alert_entry = {
            'timestamp': timestamp,
            'alert_type': alert_type,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'severity': severity,
            'description': description,
            'metadata': metadata or {}
        }
        
        self.save_json_log(alert_entry)
        
        # Print alert to console
        print(f"[!] {severity.upper()} ALERT: {alert_type}")
        print(f"    Source: {src_ip} -> Destination: {dst_ip}")
        print(f"    Description: {description}")
        if metadata:
            print(f"    Metadata: {metadata}")
        print()
    
    def save_json_log(self, entry: Dict):
        """Append entry to JSON log file"""
        log_file = self.config.get('log_file', 'network_analysis.json')
        
        try:
            # Read existing logs
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    try:
                        logs = json.load(f)
                        if not isinstance(logs, list):
                            logs = []
                    except:
                        logs = []
            else:
                logs = []
            
            logs.append(entry)
            
            # Keep only recent logs to prevent file from growing too large
            max_logs = self.config.get('max_json_logs', 10000)
            if len(logs) > max_logs:
                logs = logs[-max_logs:]
            
            with open(log_file, 'w') as f:
                json.dump(logs, f, indent=2)
                
        except Exception as e:
            print(f"Error saving JSON log: {e}")
    
    def detect_port_scan(self, src_ip: str, dst_ip: str, dst_port: int):
        """Detect port scanning activity"""
        if src_ip in self.whitelist_ips:
            return
        
        now = datetime.now()
        scan_data = self.port_scans[src_ip]
        
        # Add port to set
        scan_data['ports'].add(dst_port)
        scan_data['timestamps'].append(now)
        
        # Clean old timestamps
        time_window = timedelta(seconds=self.config.get('port_scan_time_window', 60))
        while scan_data['timestamps'] and (now - scan_data['timestamps'][0]) > time_window:
            scan_data['timestamps'].popleft()
        
        # Check thresholds
        unique_ports = len(scan_data['ports'])
        recent_attempts = len(scan_data['timestamps'])
        
        port_threshold = self.config.get('port_scan_threshold', 10)
        
        if unique_ports >= port_threshold:
            self.log_alert(
                'Port Scan',
                src_ip,
                dst_ip,
                'HIGH',
                f'Port scan detected: {unique_ports} unique ports scanned',
                {
                    'unique_ports': unique_ports,
                    'recent_attempts': recent_attempts,
                    'scanned_ports': list(scan_data['ports'])[-20:]  # Last 20 ports
                }
            )
            
            # Reset to avoid spam
            scan_data['ports'].clear()
    
    def detect_syn_flood(self, src_ip: str, dst_ip: str):
        """Detect SYN flood attacks"""
        if src_ip in self.whitelist_ips:
            return
        
        now = datetime.now()
        self.syn_attempts[src_ip].append(now)
        
        # Count recent SYN attempts
        time_window = timedelta(seconds=self.config.get('syn_flood_time_window', 10))
        recent_syns = sum(1 for t in self.syn_attempts[src_ip] if (now - t) <= time_window)
        
        syn_threshold = self.config.get('syn_flood_threshold', 50)
        
        if recent_syns >= syn_threshold:
            self.log_alert(
                'SYN Flood',
                src_ip,
                dst_ip,
                'CRITICAL',
                f'SYN flood detected: {recent_syns} SYN packets in {time_window.seconds} seconds',
                {'syn_count': recent_syns, 'time_window': time_window.seconds}
            )
    
    def detect_bandwidth_anomaly(self, src_ip: str, packet_size: int):
        """Detect unusual bandwidth usage"""
        if src_ip in self.whitelist_ips:
            return
        
        now = datetime.now()
        bw_data = self.bandwidth_usage[src_ip]
        
        # Reset bandwidth counter every minute
        if (now - bw_data['last_reset']).seconds >= 60:
            bw_data['bytes'] = 0
            bw_data['packets'] = 0
            bw_data['last_reset'] = now
        
        bw_data['bytes'] += packet_size
        bw_data['packets'] += 1
        
        # Check thresholds
        bandwidth_threshold_mb = self.config.get('bandwidth_threshold_mb', 10)
        packet_threshold = self.config.get('packet_threshold', 1000)
        
        if bw_data['bytes'] > (bandwidth_threshold_mb * 1024 * 1024):
            self.log_alert(
                'Bandwidth Anomaly',
                src_ip,
                '',
                'MEDIUM',
                f'High bandwidth usage: {bw_data["bytes"] / (1024*1024):.2f} MB in 60 seconds',
                {'bytes': bw_data['bytes'], 'packets': bw_data['packets']}
            )
            bw_data['bytes'] = 0  # Reset to avoid spam
        
        elif bw_data['packets'] > packet_threshold:
            self.log_alert(
                'Packet Flood',
                src_ip,
                '',
                'MEDIUM',
                f'High packet rate: {bw_data["packets"]} packets in 60 seconds',
                {'packets': bw_data['packets']}
            )
            bw_data['packets'] = 0  # Reset to avoid spam
    
    def analyze_payload(self, payload: bytes, src_ip: str, dst_ip: str, dst_port: int):
        """Analyze packet payload for suspicious content"""
        if not payload:
            return
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
        except:
            return
        
        # Suspicious patterns
        patterns = {
            'SQL Injection': [r'union\s+select', r'drop\s+table', r'insert\s+into', r'delete\s+from'],
            'Command Injection': [r'[;&|`]', r'wget\s+', r'curl\s+', r'nc\s+-', r'/bin/sh', r'/bin/bash'],
            'Directory Traversal': [r'\.\./', r'\.\.\\', r'/etc/passwd', r'/windows/system32'],
            'XSS': [r'<script', r'javascript:', r'alert\(', r'document\.cookie'],
            'Malware Signatures': [r'metasploit', r'meterpreter', r'reverse_tcp', r'bind_tcp']
        }
        
        for attack_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, payload_str):
                    payload_hash = hashlib.md5(payload).hexdigest()
                    
                    self.log_alert(
                        f'Suspicious Payload - {attack_type}',
                        src_ip,
                        dst_ip,
                        'HIGH',
                        f'{attack_type} pattern detected in payload',
                        {
                            'dst_port': dst_port,
                            'pattern': pattern,
                            'payload_hash': payload_hash,
                            'payload_preview': payload_str[:200]
                        }
                    )
                    
                    self.suspicious_payloads.append({
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'attack_type': attack_type,
                        'payload_hash': payload_hash
                    })
                    return
    
    def detect_connection_anomalies(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: str):
        """Detect unusual connection patterns"""
        connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        
        # Track connection states
        if flags == 'S':  # SYN
            self.connection_states[connection_key] = {'state': 'SYN_SENT', 'timestamp': datetime.now()}
        elif flags == 'SA':  # SYN-ACK
            if connection_key in self.connection_states:
                self.connection_states[connection_key]['state'] = 'SYN_RECEIVED'
        elif flags == 'A':  # ACK
            if connection_key in self.connection_states:
                self.connection_states[connection_key]['state'] = 'ESTABLISHED'
        elif flags == 'F' or flags == 'FA':  # FIN
            if connection_key in self.connection_states:
                del self.connection_states[connection_key]
        elif flags == 'R':  # RST
            if connection_key in self.connection_states:
                del self.connection_states[connection_key]
                
                # Log failed connection
                self.failed_connections[src_ip].append(datetime.now())
                
                # Check for excessive failed connections
                time_window = timedelta(minutes=5)
                now = datetime.now()
                recent_failures = sum(1 for t in self.failed_connections[src_ip] if (now - t) <= time_window)
                
                if recent_failures >= self.config.get('failed_connection_threshold', 20):
                    self.log_alert(
                        'Excessive Failed Connections',
                        src_ip,
                        dst_ip,
                        'MEDIUM',
                        f'{recent_failures} failed connections in 5 minutes',
                        {'failed_count': recent_failures}
                    )
    
    def packet_callback(self, packet):
        """Main packet processing callback"""
        try:
            self.stats['total_packets'] += 1
            
            # Basic packet info
            timestamp = datetime.now().isoformat()
            packet_data = {'timestamp': timestamp}
            
            # IP layer analysis
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_size = len(packet)
                
                packet_data.update({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'packet_size': packet_size,
                    'protocol': packet[IP].proto
                })
                
                # Skip if source IP is in whitelist
                if src_ip not in self.whitelist_ips:
                    self.detect_bandwidth_anomaly(src_ip, packet_size)
                
                # TCP analysis
                if TCP in packet:
                    self.stats['tcp_packets'] += 1
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = packet[TCP].flags
                    
                    packet_data.update({
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'flags': str(flags),
                        'protocol': 'TCP'
                    })
                    
                    # Convert flags to string representation
                    flag_str = ''
                    if flags & 0x02: flag_str += 'S'  # SYN
                    if flags & 0x10: flag_str += 'A'  # ACK
                    if flags & 0x01: flag_str += 'F'  # FIN
                    if flags & 0x04: flag_str += 'R'  # RST
                    if flags & 0x08: flag_str += 'P'  # PSH
                    if flags & 0x20: flag_str += 'U'  # URG
                    
                    # Detection algorithms
                    if src_ip not in self.whitelist_ips:
                        if flag_str == 'S':  # SYN packet
                            self.detect_syn_flood(src_ip, dst_ip)
                            self.detect_port_scan(src_ip, dst_ip, dst_port)
                        
                        self.detect_connection_anomalies(src_ip, dst_ip, src_port, dst_port, flag_str)
                    
                    # Payload analysis
                    if Raw in packet:
                        payload = bytes(packet[Raw])
                        payload_hash = hashlib.md5(payload).hexdigest()
                        packet_data.update({
                            'payload_size': len(payload),
                            'payload_hash': payload_hash
                        })
                        
                        if src_ip not in self.whitelist_ips:
                            self.analyze_payload(payload, src_ip, dst_ip, dst_port)
                
                # UDP analysis
                elif UDP in packet:
                    self.stats['udp_packets'] += 1
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    
                    packet_data.update({
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': 'UDP'
                    })
                    
                    # Payload analysis for UDP
                    if Raw in packet and src_ip not in self.whitelist_ips:
                        payload = bytes(packet[Raw])
                        payload_hash = hashlib.md5(payload).hexdigest()
                        packet_data.update({
                            'payload_size': len(payload),
                            'payload_hash': payload_hash
                        })
                        
                        self.analyze_payload(payload, src_ip, dst_ip, dst_port)
                
                # ICMP analysis
                elif ICMP in packet:
                    self.stats['icmp_packets'] += 1
                    packet_data['protocol'] = 'ICMP'
                    
                    # Detect ICMP floods
                    if src_ip not in self.whitelist_ips:
                        # Simple ICMP flood detection could be added here
                        pass
            
            # ARP analysis
            elif ARP in packet:
                self.stats['arp_packets'] += 1
                packet_data.update({
                    'src_ip': packet[ARP].psrc,
                    'dst_ip': packet[ARP].pdst,
                    'protocol': 'ARP',
                    'arp_op': packet[ARP].op
                })
                
                # ARP spoofing detection could be added here
            
            # Log packet data (sample only to avoid overwhelming the database)
            if self.stats['total_packets'] % self.config.get('log_sample_rate', 100) == 0:
                self.log_packet(packet_data)
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def start_analysis_thread(self):
        """Start background analysis thread"""
        def analysis_worker():
            while self.running:
                try:
                    # Periodic cleanup and analysis
                    self.cleanup_old_data()
                    self.generate_periodic_stats()
                    time.sleep(60)  # Run every minute
                except Exception as e:
                    print(f"Analysis thread error: {e}")
        
        self.analysis_thread = threading.Thread(target=analysis_worker, daemon=True)
        self.analysis_thread.start()
    
    def cleanup_old_data(self):
        """Clean up old tracking data to prevent memory issues"""
        cutoff_time = datetime.now() - timedelta(hours=1)
        
        # Clean up connection states
        expired_connections = [
            key for key, data in self.connection_states.items()
            if data['timestamp'] < cutoff_time
        ]
        for key in expired_connections:
            del self.connection_states[key]
        
        # Clean up old port scan data
        for ip in list(self.port_scans.keys()):
            scan_data = self.port_scans[ip]
            # Keep only recent timestamps
            while scan_data['timestamps'] and (datetime.now() - scan_data['timestamps'][0]).seconds > 3600:
                scan_data['timestamps'].popleft()
            
            # Remove if no recent activity
            if not scan_data['timestamps']:
                del self.port_scans[ip]
    
    def generate_periodic_stats(self):
        """Generate and save periodic statistics"""
        now = datetime.now()
        uptime = now - self.stats['start_time']
        
        stats_data = {
            'timestamp': now.isoformat(),
            'uptime_seconds': uptime.total_seconds(),
            'total_packets': self.stats['total_packets'],
            'tcp_packets': self.stats['tcp_packets'],
            'udp_packets': self.stats['udp_packets'],
            'icmp_packets': self.stats['icmp_packets'],
            'arp_packets': self.stats['arp_packets'],
            'alerts_generated': self.stats['alerts_generated'],
            'tracked_ips': len(self.syn_attempts),
            'active_connections': len(self.connection_states),
            'suspicious_payloads': len(self.suspicious_payloads)
        }
        
        # Save to database
        with self.db_lock:
            cursor = self.conn.cursor()
            for metric, value in stats_data.items():
                if metric != 'timestamp':
                    cursor.execute('''
                        INSERT INTO statistics (timestamp, metric_name, metric_value)
                        VALUES (?, ?, ?)
                    ''', (stats_data['timestamp'], metric, str(value)))
            self.conn.commit()
    
    def start_monitoring(self, interface: str = None, packet_filter: str = ""):
        """Start network monitoring"""
        self.running = True
        self.start_analysis_thread()
        
        print(f"[+] Starting network traffic analysis...")
        print(f"[+] Filter: {packet_filter if packet_filter else 'All traffic'}")
        print(f"[+] Interface: {interface if interface else 'Default'}")
        print(f"[+] Press Ctrl+C to stop")
        print("=" * 60)
        
        try:
            if interface:
                conf.iface = interface
            
            sniff(
                iface=interface,
                filter=packet_filter,
                prn=self.packet_callback,
                store=0
            )
        except KeyboardInterrupt:
            print("\n[!] Monitoring stopped by user")
        except Exception as e:
            print(f"[!] Error during monitoring: {e}")
        finally:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop network monitoring and cleanup"""
        self.running = False
        
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=5)
        
        # Final statistics
        self.print_final_stats()
        
        # Close database connection
        if hasattr(self, 'conn'):
            self.conn.close()
        
        print("[+] Network analysis stopped")
    
    def print_final_stats(self):
        """Print final statistics"""
        uptime = datetime.now() - self.stats['start_time']
        
        print("\n" + "=" * 60)
        print("FINAL NETWORK ANALYSIS STATISTICS")
        print("=" * 60)
        print(f"Monitoring Duration: {uptime}")
        print(f"Total Packets Processed: {self.stats['total_packets']:,}")
        print(f"  - TCP: {self.stats['tcp_packets']:,}")
        print(f"  - UDP: {self.stats['udp_packets']:,}")
        print(f"  - ICMP: {self.stats['icmp_packets']:,}")
        print(f"  - ARP: {self.stats['arp_packets']:,}")
        print(f"Total Alerts Generated: {self.stats['alerts_generated']}")
        print(f"Unique IPs Tracked: {len(self.syn_attempts)}")
        print(f"Suspicious Payloads Detected: {len(self.suspicious_payloads)}")
        print(f"Database File: {self.db_file}")
        print(f"JSON Log File: {self.config.get('log_file', 'network_analysis.json')}")
        
        if self.stats['total_packets'] > 0:
            pps = self.stats['total_packets'] / uptime.total_seconds()
            print(f"Average Packets/Second: {pps:.2f}")
        
        print("=" * 60)

def load_config(config_file: str) -> Dict:
    """Load configuration from JSON file"""
    default_config = {
        'interface': None,
        'log_file': 'network_analysis.json',
        'db_file': 'network_analysis.db',
        'packet_filter': '',
        'whitelist_ips': ['127.0.0.1', '::1'],
        'blacklist_ips': [],
        'port_scan_threshold': 10,
        'port_scan_time_window': 60,
        'syn_flood_threshold': 50,  
        'syn_flood_time_window': 10,
        'bandwidth_threshold_mb': 10,
        'packet_threshold': 1000,
        'failed_connection_threshold': 20,
        'log_sample_rate': 100,
        'max_json_logs': 10000
    }
    
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                default_config.update(config)
        except Exception as e:
            print(f"Error loading config file: {e}")
            print("Using default configuration")
    
    return default_config

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[!] Received interrupt signal")
    if 'analyzer' in globals():
        analyzer.stop_monitoring()
    sys.exit(0)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Advanced Network Traffic Analysis Module")
    parser.add_argument("-i", "--interface", help="Network interface to monitor")
    parser.add_argument("-f", "--filter", default="", help="BPF packet filter")
    parser.add_argument("-c", "--config", default="network_config.json", help="Configuration file")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces")
    parser.add_argument("--whitelist", nargs="+", help="IP addresses to whitelist")
    parser.add_argument("--blacklist", nargs="+", help="IP addresses to blacklist")
    
    args = parser.parse_args()
    
    # List interfaces if requested
    if args.list_interfaces:
        print("Available network interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        return
    
    # Load configuration
    config = load_config(args.config)
    
    # Override config with command line arguments
    if args.interface:
        config['interface'] = args.interface
    if args.filter:
        config['packet_filter'] = args.filter
    if args.whitelist:
        config['whitelist_ips'].extend(args.whitelist)
    if args.blacklist:
        config['blacklist_ips'].extend(args.blacklist)
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create and start analyzer
    global analyzer
    analyzer = NetworkAnalyzer(config)
    
    try:
        analyzer.start_monitoring(
            interface=config.get('interface'),
            packet_filter=config.get('packet_filter', '')
        )
    except PermissionError:
        print("[!] Error: Root privileges required for packet capture")
        print("    Please run with sudo: sudo python3 network_analyzer.py")
    except Exception as e:
        print(f"[!] Error starting analyzer: {e}")

if __name__ == "__main__":
    main()