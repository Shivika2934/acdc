#!/usr/bin/env python3
"""
Advanced Endpoint Security File System Monitor
Monitors file system changes across the entire system or specific directories
with detailed logging, threat detection, and real-time alerts.
"""

import os
import sys
import time
import json
import hashlib
import sqlite3
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque

try:
    from watchdog.observers import Observer
    from watchdog.observers.polling import PollingObserver
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
except ImportError:
    print("Installing required dependencies...")
    os.system("pip install watchdog psutil")
    from watchdog.observers import Observer
    from watchdog.observers.polling import PollingObserver
    from watchdog.events import FileSystemEventHandler, FileSystemEvent

try:
    import psutil
except ImportError:
    os.system("pip install psutil")
    import psutil


@dataclass
class FileEvent:
    """Data class for file system events"""
    timestamp: str
    event_type: str
    file_path: str
    file_size: Optional[int]
    file_hash: Optional[str]
    process_name: Optional[str]
    process_pid: Optional[int]
    user: Optional[str]
    is_suspicious: bool
    threat_level: str
    details: Dict


class ThreatDetector:
    """Advanced threat detection engine"""
    
    def __init__(self):
        self.suspicious_extensions = {
            '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js', 
            '.jar', '.ps1', '.psm1', '.psd1', '.sh', '.py', '.pl', '.php'
        }
        
        self.critical_directories = {
            # Windows
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64',
            'C:\\Program Files',
            'C:\\Program Files (x86)',
            'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu',
            # Linux
            '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc', '/boot',
            '/lib', '/lib64', '/usr/lib', '/var/log',
            # macOS
            '/System', '/Applications', '/Library', '/usr/bin', '/usr/sbin'
        }
        
        self.malware_patterns = [
            'temp', 'tmp', 'cache', 'svchost', 'winlogon', 'explorer',
            'system32', 'kernel', 'driver', 'service', 'update'
        ]
        
        self.event_frequency = defaultdict(lambda: deque(maxlen=100))
        self.process_activity = defaultdict(int)
    
    def analyze_event(self, event: FileEvent) -> Tuple[bool, str, Dict]:
        """Analyze event for threats"""
        threat_indicators = []
        threat_level = "LOW"
        details = {}
        
        # Check file extension
        if event.file_path:
            ext = Path(event.file_path).suffix.lower()
            if ext in self.suspicious_extensions:
                threat_indicators.append(f"Suspicious file extension: {ext}")
        
        # Check critical directory access
        for critical_dir in self.critical_directories:
            if '*' in critical_dir:
                pattern = critical_dir.replace('*', '')
                if pattern in event.file_path:
                    threat_indicators.append(f"Critical directory access: {critical_dir}")
                    threat_level = "HIGH"
            elif event.file_path.startswith(critical_dir):
                threat_indicators.append(f"Critical directory access: {critical_dir}")
                threat_level = "HIGH"
        
        # Check for rapid file operations
        current_time = time.time()
        self.event_frequency[event.file_path].append(current_time)
        
        recent_events = [t for t in self.event_frequency[event.file_path] 
                        if current_time - t < 60]  # Last minute
        
        if len(recent_events) > 10:
            threat_indicators.append(f"Rapid file operations: {len(recent_events)} in 60s")
            threat_level = "HIGH"
        
        # Check for suspicious patterns in filename
        filename = Path(event.file_path).name.lower()
        for pattern in self.malware_patterns:
            if pattern in filename and not any(legit in filename for legit in ['backup', 'log', 'config']):
                threat_indicators.append(f"Suspicious filename pattern: {pattern}")
                threat_level = "MEDIUM"
        
        # Process-based analysis
        if event.process_name:
            self.process_activity[event.process_name] += 1
            if self.process_activity[event.process_name] > 50:  # High activity threshold
                threat_indicators.append(f"High activity process: {event.process_name}")
                threat_level = "MEDIUM"
        
        details = {
            'indicators': threat_indicators,
            'analysis_time': datetime.now().isoformat(),
            'risk_factors': len(threat_indicators)
        }
        
        is_suspicious = len(threat_indicators) > 0
        return is_suspicious, threat_level, details


class DatabaseManager:
    """SQLite database manager for event storage and JSON log for web UI"""
    
    def __init__(self, db_path: str = "security_monitor.db", json_log_path: str = "security_monitor.json"):
        self.db_path = db_path
        self.json_log_path = json_log_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                file_hash TEXT,
                process_name TEXT,
                process_pid INTEGER,
                user TEXT,
                is_suspicious BOOLEAN,
                threat_level TEXT,
                details TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON file_events(timestamp);
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_suspicious ON file_events(is_suspicious);
        ''')
        
        conn.commit()
        conn.close()
    
    def store_event(self, event: FileEvent):
        """Store event in database and append to JSON log file"""
        # Store in SQLite
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO file_events 
            (timestamp, event_type, file_path, file_size, file_hash, 
             process_name, process_pid, user, is_suspicious, threat_level, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.timestamp, event.event_type, event.file_path, event.file_size,
            event.file_hash, event.process_name, event.process_pid, event.user,
            event.is_suspicious, event.threat_level, json.dumps(event.details)
        ))
        conn.commit()
        conn.close()

        # Also append to JSON log file (keep last 1000 events)
        try:
            if os.path.exists(self.json_log_path):
                with open(self.json_log_path, "r", encoding="utf-8") as f:
                    try:
                        logs = json.load(f)
                        if not isinstance(logs, list):
                            logs = []
                    except Exception:
                        logs = []
            else:
                logs = []
            logs.append(asdict(event))
            if len(logs) > 1000:
                logs = logs[-1000:]
            with open(self.json_log_path, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to write to JSON log: {e}")

    def get_recent_events(self, hours: int = 24, suspicious_only: bool = False) -> List[FileEvent]:
        """Retrieve recent events from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = '''
            SELECT * FROM file_events 
            WHERE datetime(timestamp) > datetime('now', '-{} hours')
        '''.format(hours)
        
        if suspicious_only:
            query += ' AND is_suspicious = 1'
        
        query += ' ORDER BY timestamp DESC LIMIT 1000'
        
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            event = FileEvent(
                timestamp=row[1], event_type=row[2], file_path=row[3],
                file_size=row[4], file_hash=row[5], process_name=row[6],
                process_pid=row[7], user=row[8], is_suspicious=row[9],
                threat_level=row[10], details=json.loads(row[11])
            )
            events.append(event)
        
        return events


class AdvancedFileSystemHandler(FileSystemEventHandler):
    """Advanced file system event handler"""
    
    def __init__(self, monitor):
        super().__init__()
        self.monitor = monitor
        self.threat_detector = ThreatDetector()
        self.last_events = defaultdict(float)
        self.ignored_paths = {'.git', '__pycache__', '.tmp', 'Temp', 'temp'}
    
    def should_ignore_path(self, path: str) -> bool:
        """Check if path should be ignored"""
        path_lower = path.lower()
        return any(ignored in path_lower for ignored in self.ignored_paths)
    
    def get_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate file hash"""
        try:
            if os.path.isfile(file_path) and os.path.getsize(file_path) < 100 * 1024 * 1024:  # < 100MB
                hasher = hashlib.sha256()
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hasher.update(chunk)
                return hasher.hexdigest()
        except Exception:
            pass
        return None
    
    def get_process_info(self) -> Tuple[Optional[str], Optional[int]]:
        """Get current process information"""
        try:
            current_process = psutil.Process()
            return current_process.name(), current_process.pid
        except Exception:
            return None, None
    
    def get_user_info(self) -> Optional[str]:
        """Get current user information"""
        try:
            return psutil.Process().username()
        except Exception:
            return None
    
    def create_event(self, event_type: str, file_path: str) -> FileEvent:
        """Create FileEvent object"""
        # Avoid duplicate events in rapid succession
        event_key = f"{event_type}:{file_path}"
        current_time = time.time()
        
        if current_time - self.last_events[event_key] < 0.1:  # 100ms debounce
            return None
        
        self.last_events[event_key] = current_time
        
        # Gather file information
        file_size = None
        file_hash = None
        
        try:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                file_size = os.path.getsize(file_path)
                if event_type in ['created', 'modified']:
                    file_hash = self.get_file_hash(file_path)
        except Exception:
            pass
        
        # Get process and user info
        process_name, process_pid = self.get_process_info()
        user = self.get_user_info()
        
        # Create event
        event = FileEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            file_path=file_path,
            file_size=file_size,
            file_hash=file_hash,
            process_name=process_name,
            process_pid=process_pid,
            user=user,
            is_suspicious=False,
            threat_level="LOW",
            details={}
        )
        
        # Analyze for threats
        is_suspicious, threat_level, details = self.threat_detector.analyze_event(event)
        event.is_suspicious = is_suspicious
        event.threat_level = threat_level
        event.details = details
        
        return event
    
    def on_created(self, event: FileSystemEvent):
        if not event.is_directory and not self.should_ignore_path(event.src_path):
            file_event = self.create_event('created', event.src_path)
            if file_event:
                self.monitor.handle_event(file_event)
    
    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory and not self.should_ignore_path(event.src_path):
            file_event = self.create_event('modified', event.src_path)
            if file_event:
                self.monitor.handle_event(file_event)
    
    def on_deleted(self, event: FileSystemEvent):
        if not event.is_directory and not self.should_ignore_path(event.src_path):
            file_event = self.create_event('deleted', event.src_path)
            if file_event:
                self.monitor.handle_event(file_event)
    
    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            if not self.should_ignore_path(event.src_path):
                file_event = self.create_event('moved_from', event.src_path)
                if file_event:
                    self.monitor.handle_event(file_event)
            
            if hasattr(event, 'dest_path') and not self.should_ignore_path(event.dest_path):
                file_event = self.create_event('moved_to', event.dest_path)
                if file_event:
                    self.monitor.handle_event(file_event)


class EndpointSecurityMonitor:
    """Main endpoint security monitoring system"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        json_log_path = self.config.get('json_log_path', 'security_monitor.json')
        self.observers = []
        self.db_manager = DatabaseManager(self.config.get('db_path', 'security_monitor.db'), json_log_path)
        self.setup_logging()
        self.event_count = 0
        self.suspicious_count = 0
        self.start_time = time.time()
        self.is_running = False
        
        # Alert thresholds
        self.alert_threshold = self.config.get('alert_threshold', 5)
        self.alert_window = self.config.get('alert_window', 300)  # 5 minutes
        self.recent_alerts = deque(maxlen=100)
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_level = self.config.get('log_level', 'INFO')
        log_file = self.config.get('log_file', 'security_monitor.log')
        
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def handle_event(self, event: FileEvent):
        """Handle file system event"""
        self.event_count += 1
        
        # Store in database
        self.db_manager.store_event(event)
        
        # Log the event
        if event.is_suspicious:
            self.suspicious_count += 1
            self.logger.warning(f"SUSPICIOUS: {event.event_type} - {event.file_path} "
                              f"[{event.threat_level}] - Process: {event.process_name}")
            
            # Check for alert conditions
            self.check_alert_conditions(event)
        else:
            self.logger.info(f"{event.event_type}: {event.file_path}")
        
        # Console output for real-time monitoring
        if self.config.get('console_output', True):
            self.print_event(event)
    
    def check_alert_conditions(self, event: FileEvent):
        """Check if alert conditions are met"""
        current_time = time.time()
        self.recent_alerts.append(current_time)
        
        # Count recent alerts
        recent_count = sum(1 for t in self.recent_alerts 
                          if current_time - t < self.alert_window)
        
        if recent_count >= self.alert_threshold:
            self.trigger_alert(event, recent_count)
    
    def trigger_alert(self, event: FileEvent, alert_count: int):
        """Trigger security alert"""
        alert_msg = (f"SECURITY ALERT: {alert_count} suspicious events in "
                    f"{self.alert_window}s. Latest: {event.event_type} - "
                    f"{event.file_path} [{event.threat_level}]")
        
        self.logger.critical(alert_msg)
        print(f"\n{'='*80}")
        print(f"🚨 {alert_msg}")
        print(f"{'='*80}\n")
    
    def print_event(self, event: FileEvent):
        """Print event to console"""
        color = ""
        reset = ""
        
        if sys.platform != "win32":  # ANSI colors for Unix-like systems
            if event.threat_level == "HIGH":
                color = "\033[91m"  # Red
            elif event.threat_level == "MEDIUM":
                color = "\033[93m"  # Yellow
            elif event.is_suspicious:
                color = "\033[94m"  # Blue
            reset = "\033[0m"
        
        status = "🔍 SUSPICIOUS" if event.is_suspicious else "✓"
        
        print(f"{color}[{event.timestamp}] {status} {event.event_type.upper()}: "
              f"{event.file_path}")
        
        if event.is_suspicious:
            print(f"  └─ Threat Level: {event.threat_level}")
            if event.details.get('indicators'):
                for indicator in event.details['indicators'][:2]:  # Show first 2
                    print(f"  └─ {indicator}")
        
        print(f"{reset}", end="")
    
    def add_watch_path(self, path: str, recursive: bool = True):
        """Add a path to monitor"""
        if not os.path.exists(path):
            self.logger.error(f"Path does not exist: {path}")
            return False
        
        try:
            # Use polling observer for network drives or if regular observer fails
            use_polling = self.config.get('use_polling', False)
            observer = PollingObserver() if use_polling else Observer()
            
            handler = AdvancedFileSystemHandler(self)
            observer.schedule(handler, path, recursive=recursive)
            observer.start()
            
            self.observers.append(observer)
            self.logger.info(f"Started monitoring: {path} (recursive: {recursive})")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to monitor {path}: {e}")
            return False
    
    def monitor_system_drives(self):
        """Monitor all available system drives"""
        drives = []
        
        if sys.platform == "win32":
            # Windows drives
            import string
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    drives.append(drive)
        else:
            # Unix-like systems
            drives = ["/"]
        
        for drive in drives:
            self.add_watch_path(drive, recursive=True)
        
        return len(drives)
    
    def start_monitoring(self, paths: List[str] = None, monitor_system: bool = False):
        """Start the monitoring system"""
        self.logger.info("Starting Endpoint Security Monitor...")
        self.is_running = True
        
        if monitor_system:
            drive_count = self.monitor_system_drives()
            self.logger.info(f"Monitoring {drive_count} system drives")
        elif paths:
            for path in paths:
                self.add_watch_path(path)
        else:
            # Default to current directory
            self.add_watch_path(os.getcwd())
        
        if not self.observers:
            self.logger.error("No valid paths to monitor!")
            return
        
        self.logger.info(f"Monitoring started with {len(self.observers)} observers")
        
        try:
            while self.is_running:
                time.sleep(1)
                
                # Print stats every 60 seconds
                if int(time.time()) % 60 == 0:
                    self.print_stats()
                    
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        finally:
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop the monitoring system"""
        self.is_running = False
        
        for observer in self.observers:
            observer.stop()
            observer.join()
        
        self.observers.clear()
        self.logger.info("Monitoring stopped")
    
    def print_stats(self):
        """Print monitoring statistics"""
        runtime = int(time.time() - self.start_time)
        hours = runtime // 3600
        minutes = (runtime % 3600) // 60
        
        print(f"\n📊 Stats - Runtime: {hours:02d}:{minutes:02d}:{runtime%60:02d} | "
              f"Events: {self.event_count} | Suspicious: {self.suspicious_count}")
    
    def generate_report(self, hours: int = 24) -> Dict:
        """Generate security report"""
        events = self.db_manager.get_recent_events(hours)
        suspicious_events = [e for e in events if e.is_suspicious]
        
        # Analyze events
        event_types = defaultdict(int)
        threat_levels = defaultdict(int)
        processes = defaultdict(int)
        
        for event in events:
            event_types[event.event_type] += 1
            if event.is_suspicious:
                threat_levels[event.threat_level] += 1
            if event.process_name:
                processes[event.process_name] += 1
        
        report = {
            'period_hours': hours,
            'total_events': len(events),
            'suspicious_events': len(suspicious_events),
            'threat_percentage': (len(suspicious_events) / len(events) * 100) if events else 0,
            'event_types': dict(event_types),
            'threat_levels': dict(threat_levels),
            'top_processes': dict(sorted(processes.items(), key=lambda x: x[1], reverse=True)[:10]),
            'generated_at': datetime.now().isoformat()
        }
        
        return report


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced Endpoint Security File System Monitor')
    parser.add_argument('--paths', nargs='+', help='Specific paths to monitor')
    parser.add_argument('--system', action='store_true', help='Monitor entire system')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--report', type=int, help='Generate report for last N hours')
    parser.add_argument('--db', default='security_monitor.db', help='Database file path')
    parser.add_argument('--json', default='security_monitor.json', help='JSON log file path')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {'db_path': args.db, 'json_log_path': args.json}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config.update(json.load(f))
    
    monitor = EndpointSecurityMonitor(config)
    
    if args.report:
        # Generate report
        report = monitor.generate_report(args.report)
        print(json.dumps(report, indent=2))
        return
    
    print("🔒 Advanced Endpoint Security Monitor")
    print("=====================================")
    print("Monitoring file system changes with threat detection...")
    print("Press Ctrl+C to stop\n")
    
    # Start monitoring
    monitor.start_monitoring(paths=args.paths, monitor_system=args.system)


if __name__ == "__main__":
    main()