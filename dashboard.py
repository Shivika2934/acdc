'''dashboard.py'''
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional
import threading
import queue
import json
import time
import string
import os
import signal
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler



# Import our modules
import endpoint
import honeypot
import network
from cryptanalysis import xor_encrypt, xor_decrypt, monoalpha_encrypt, monoalpha_decrypt, validate_alphabet



app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app)

# Global state
module_states = {
    'endpoint': {'running': False, 'instance': None, 'log_queue': queue.Queue()},
    'honeypot': {'running': False, 'instance': None, 'log_queue': queue.Queue()},
    'network': {'running': False, 'instance': None, 'log_queue': queue.Queue()},
    'cryptanalysis': {'running': False, 'instance': None, 'log_queue': queue.Queue()}
}

# Update LOG_FILES dictionary
LOG_FILES = {
    'endpoint': {'path': 'security_monitor.log', 'type': 'text'},
    'honeypot': {'path': 'honeypot_events.json', 'type': 'json'},
    'network': {'path': 'network_analysis.json', 'type': 'json'},
    'crypto': {'path': 'crypto_audit.log', 'type': 'text'}
}

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, module_name, log_queue):
        self.module_name = module_name
        self.log_queue = log_queue
        
    def on_modified(self, event):
        if not event.is_directory:
            try:
                log_info = LOG_FILES[self.module_name]
                if log_info['type'] == 'json':
                    with open(event.src_path, 'r') as f:
                        logs = json.load(f)
                        if isinstance(logs, list):
                            for entry in logs[-10:]:  # Get last 10 entries
                                self.log_queue.put(json.dumps(entry))
            except Exception as e:
                print(f"Error reading log file: {e}")

def parse_log_entry(log_entry: str) -> dict:
    """Parse a log entry into structured format"""
    try:
        # Check if entry is JSON
        if log_entry.startswith('{'):
            data = json.loads(log_entry)
            return {
                'timestamp': data.get('timestamp', ''),
                'level': data.get('event_type', 'INFO').upper(),
                'message': format_json_log(data)
            }
        
        # Try to parse timestamp and level
        parts = log_entry.split(' - ', 2)
        if len(parts) >= 3:
            return {
                'timestamp': parts[0],
                'level': parts[1],
                'message': parts[2]
            }
        return {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
            'level': 'INFO',
            'message': log_entry
        }
    except Exception:
        return {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3],
            'level': 'INFO',
            'message': log_entry
        }

def format_json_log(data: dict) -> str:
    """Format JSON log entry for display"""
    if 'service' in data:  # Honeypot log
        return f"{data['service']} - {data.get('client_ip', 'unknown')}:{data.get('client_port', '')} - {data.get('data', '')}"
    elif 'alert_type' in data:  # Network log
        return f"{data['alert_type']} - {data.get('description', '')} - {data.get('src_ip', '')} -> {data.get('dst_ip', '')}"
    else:
        return json.dumps(data)

def log_monitor(module_name, log_queue):
    """Monitor log files and emit updates via WebSocket"""
    while module_states[module_name]['running']:
        try:
            log_entry = log_queue.get(timeout=1)
            parsed_entry = parse_log_entry(log_entry)
            socketio.emit(f'{module_name}_log', {
                'data': log_entry,
                'parsed': parsed_entry
            })
        except queue.Empty:
            continue

def monitor_log_file(module_name, log_queue):
    """Monitor a log file and send updates to the queue"""
    log_info = LOG_FILES.get(module_name)
    if not log_info:
        return

    log_path = os.path.join(os.path.dirname(__file__), log_info['path'])
    
    try:
        # First read existing content
        if log_info['type'] == 'json':
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    logs = json.load(f)
                    if isinstance(logs, list):
                        for entry in logs:
                            log_queue.put(json.dumps(entry))
        else:
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    for line in f.readlines():
                        log_queue.put(line.strip())

        # Set up file monitoring
        observer = Observer()
        handler = LogFileHandler(module_name, log_queue)
        observer.schedule(handler, os.path.dirname(log_path), recursive=False)
        observer.start()
        
        return observer
            
    except Exception as e:
        print(f"Error monitoring {module_name} log: {e}")

def start_log_monitoring(module_name):
    """Start monitoring logs for a module"""
    thread = threading.Thread(
        target=monitor_log_file,
        args=(module_name, module_states[module_name]['log_queue'])
    )
    thread.daemon = True
    thread.start()
    return thread

@dataclass
class ModuleState:
    running: bool
    start_time: Optional[datetime]
    uptime: str = "00:00:00"
    status: str = "stopped"
    logs: List[Dict] = None

    def __post_init__(self):
        self.logs = []

class DashboardManager:
    def __init__(self):
        self.modules = {
            'endpoint': ModuleState(False, None),
            'network': ModuleState(False, None),
            'honeypot': ModuleState(False, None),
            'cryptanalysis': ModuleState(False, None)
        }
    
    def update_module_state(self, module: str, running: bool):
        """Update module running state"""
        if module not in self.modules:
            return
        
        state = self.modules[module]
        state.running = running
        state.status = "running" if running else "stopped"
        
        if running:
            state.start_time = datetime.now()
        else:
            state.start_time = None
            state.uptime = "00:00:00"
    
    def add_log(self, module: str, message: str, level: str = "INFO"):
        """Add log entry to module"""
        if module not in self.modules:
            return
        
        self.modules[module].logs.append({
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'level': level
        })
        
        # Keep only last 1000 logs
        if len(self.modules[module].logs) > 1000:
            self.modules[module].logs = self.modules[module].logs[-1000:]
    
    def get_module_status(self, module: str) -> Dict:
        """Get module status"""
        if module not in self.modules:
            return {}
        
        state = self.modules[module]
        if state.running and state.start_time:
            uptime = datetime.now() - state.start_time
            state.uptime = str(uptime).split('.')[0]  # Remove microseconds
        
        return {
            'running': state.running,
            'status': state.status,
            'uptime': state.uptime,
            'start_time': state.start_time.isoformat() if state.start_time else None
        }
    
    def get_recent_logs(self, module: str, count: int = 100) -> List[Dict]:
        """Get recent logs for module"""
        if module not in self.modules:
            return []
        
        return self.modules[module].logs[-count:]

@app.route('/')
def index():
    return render_template('dashboard.html', states=module_states)

@app.route('/api/start/<module>')
def start_module(module):
    if module not in module_states:
        return jsonify({'status': 'error', 'message': 'Invalid module'})

    if module_states[module]['running']:
        return jsonify({'status': 'error', 'message': 'Already running'})

    try:
        if module == 'endpoint':
            instance = endpoint.EndpointSecurityMonitor()
            thread = threading.Thread(target=instance.start_monitoring)
        elif module == 'honeypot':
            instance = honeypot.HoneypotManager()
            thread = threading.Thread(target=instance.start_all)
        elif module == 'network':
            config = network.load_config('network_config.json')
            instance = network.NetworkAnalyzer(config)
            thread = threading.Thread(target=instance.start_monitoring)

        thread.daemon = True
        thread.start()

        module_states[module].update({
            'running': True,
            'instance': instance,
            'start_time': datetime.now().isoformat(),
            'thread': thread
        })

        # Start log monitor thread
        log_thread = threading.Thread(
            target=log_monitor,
            args=(module, module_states[module]['log_queue'])
        )
        log_thread.daemon = True
        log_thread.start()

        # Start file monitoring
        file_monitor_thread = start_log_monitoring(module)
        module_states[module]['log_monitor_thread'] = file_monitor_thread
        
        return jsonify({
            'status': 'success',
            'message': f'{module.title()} module started'
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to start {module}: {str(e)}'
        })

@app.route('/api/stop/<module>')
def stop_module(module):
    if module not in module_states:
        return jsonify({'status': 'error', 'message': 'Invalid module'})

    if not module_states[module]['running']:
        return jsonify({'status': 'error', 'message': 'Not running'})

    try:
        instance = module_states[module]['instance']
        if module == 'endpoint':
            instance.stop_monitoring()
        elif module == 'honeypot':
            instance.stop_all()
        elif module == 'network':
            instance.stop_monitoring()

        module_states[module].update({
            'running': False,
            'instance': None,
            'stop_time': datetime.now().isoformat()
        })

        return jsonify({
            'status': 'success',
            'message': f'{module.title()} module stopped'
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to stop {module}: {str(e)}'
        })

@app.route('/api/status')
def get_status():
    return jsonify({
        module: {
            'running': state['running'],
            'start_time': state.get('start_time'),
            'stop_time': state.get('stop_time')
        }
        for module, state in module_states.items()
    })

@app.route('/api/logs/<module>')
def get_module_logs(module):
    """Get recent logs for a module"""
    if module not in LOG_FILES:
        return jsonify({'status': 'error', 'message': 'Invalid module'})
    
    try:
        log_file = LOG_FILES[module]
        log_path = os.path.join(os.path.dirname(__file__), log_file['path'])
        
        if not os.path.exists(log_path):
            return jsonify({'logs': []})
        
        with open(log_path, 'r') as f:
            # Get last 1000 lines
            if log_file['type'] == 'json':
                logs = json.load(f)
                if isinstance(logs, list):
                    lines = logs[-1000:]
                    logs = [json.dumps(entry) for entry in lines]
            else:
                lines = f.readlines()[-1000:]
                logs = [parse_log_entry(line.strip()) for line in lines]
            
            return jsonify({'logs': logs})
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})
@app.route('/cryptanalysis', methods=['GET', 'POST'])
def cryptanalysis_console():
    result = None

    if request.method == 'POST':
        method = request.form['method']
        mode = request.form['mode']
        key = request.form['key']
        message = request.form['message']

        if method == 'xor':
            try:
                if mode == 'encrypt':
                    result = xor_encrypt(message, key, output_encoding='base64')
                else:
                    result = xor_decrypt(message, key, input_encoding='base64')
            except Exception as e:
                result = f"Error: {str(e)}"

        elif method == 'mono':
            if not validate_alphabet(key):
                result = "Error: Invalid monoalphabetic key! Must be 26 unique lowercase letters."
            else:
                try:
                    if mode == 'encrypt':
                        key_map = dict(zip(string.ascii_lowercase, key))
                        result = monoalpha_encrypt(message, key_map)
                    else:
                        reverse_key_map = dict(zip(key, string.ascii_lowercase))
                        result = monoalpha_decrypt(message, reverse_key_map)
                except Exception as e:
                    result = f"Error: {str(e)}"
        else:
            result = "Invalid cipher method selected."

        # Log result if valid
        if result and not result.startswith("Error"):
            with open('crypto_audit.log', 'a') as log_file:
                log_file.write(
                    f"{datetime.now().isoformat()} - {mode.upper()} - {method.upper()} - "
                    f"Key: {key} - Message: {message} - Result: {result}\n"
                )

    return render_template('cryptanalysis.html', result=result)


def signal_handler(sig, frame):
    """Handle graceful shutdown"""
    print("\nShutting down all modules...")
    for module in module_states:
        if module_states[module]['running']:
            stop_module(module)
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
