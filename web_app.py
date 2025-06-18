from flask import Flask, render_template, jsonify, send_file, request
from flask_socketio import SocketIO, emit
import threading
from typing import Dict
from datetime import datetime
import os
import json

# Import module controllers
from endpoint import EndpointSecurityMonitor
from network import NetworkAnalyzer
from honeypot import HoneypotManager

app = Flask(__name__)
socketio = SocketIO(app)

# Module state and instances
modules = {
    'endpoint': None,
    'network': None,
    'honeypot': None
}
module_states = {
    'endpoint': {'running': False, 'start_time': None},
    'network': {'running': False, 'start_time': None},
    'honeypot': {'running': False, 'start_time': None}
}

# Log file locations
LOG_FILES = {
    'endpoint': 'security_monitor.log',
    'endpoint_json': 'security_monitor.json',
    'network': 'network_analysis.json',
    'honeypot': 'honeypot_events.json'
}

# --- Utility functions ---

def ensure_json_file(filepath):
    """Ensure a JSON file exists and is a list."""
    if not os.path.exists(filepath):
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump([], f)
    else:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, list):
                raise ValueError
        except Exception:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump([], f)

def get_recent_json_logs(filepath, limit=1000):
    ensure_json_file(filepath)
    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            logs = json.load(f)
            if not isinstance(logs, list):
                return []
            return logs[-limit:]
        except Exception:
            return []

def get_recent_text_logs(filepath, limit=1000):
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()[-limit:]
    return [line.strip() for line in lines]

# --- Flask routes ---

@app.route('/')
def dashboard():
    """Render main dashboard"""
    return render_template('dashboard.html')

@app.route('/api/status')
def api_status():
    """Get status of all modules"""
    return jsonify(module_states)

@app.route('/api/start/<module>')
def api_start_module(module):
    """Start a security module"""
    if module not in modules:
        return jsonify({'status': 'error', 'message': 'Invalid module'})
    
    try:
        if module == 'endpoint':
            modules[module] = EndpointSecurityMonitor()
            thread = threading.Thread(target=modules[module].start_monitoring)
        elif module == 'network':
            modules[module] = NetworkAnalyzer({})
            thread = threading.Thread(target=modules[module].start_monitoring)
        elif module == 'honeypot':
            modules[module] = HoneypotManager()
            thread = threading.Thread(target=modules[module].start_all)
        
        thread.daemon = True
        thread.start()
        
        module_states[module] = {
            'running': True,
            'start_time': datetime.now().isoformat()
        }
        socketio.emit('module_status', {'module': module, 'running': True})
        
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/stop/<module>')
def api_stop_module(module):
    """Stop a security module"""
    if module not in modules or not modules[module]:
        return jsonify({'status': 'error', 'message': 'Module not running'})
    
    try:
        if module == 'endpoint':
            modules[module].stop_monitoring()
        elif module == 'network':
            modules[module].stop_monitoring()
        elif module == 'honeypot':
            modules[module].stop_all()
        
        modules[module] = None
        module_states[module]['running'] = False
        module_states[module]['start_time'] = None
        socketio.emit('module_status', {'module': module, 'running': False})
        
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/logs/<module>')
def api_logs(module):
    """Return recent logs for the requested module in a dashboard-friendly format."""
    if module == 'endpoint':
        logs = get_recent_json_logs(LOG_FILES['endpoint_json'])
        return jsonify({'logs': logs})
    elif module == 'network':
        logs = get_recent_json_logs(LOG_FILES['network'])
        return jsonify({'logs': logs})
    elif module == 'honeypot':
        logs = get_recent_json_logs(LOG_FILES['honeypot'])
        return jsonify({'logs': logs})
    else:
        return jsonify({'logs': []})

@app.route('/security_monitor.json')
def serve_endpoint_json():
    ensure_json_file(LOG_FILES['endpoint_json'])
    return send_file(LOG_FILES['endpoint_json'], mimetype='application/json')

@app.route('/honeypot_events.json')
def serve_honeypot_json():
    ensure_json_file(LOG_FILES['honeypot'])
    return send_file(LOG_FILES['honeypot'], mimetype='application/json')

@app.route('/network_analysis.json')
def serve_network_json():
    ensure_json_file(LOG_FILES['network'])
    return send_file(LOG_FILES['network'], mimetype='application/json')

# --- WebSocket events ---

@socketio.on('connect')
def ws_connect():
    """Handle client connection"""
    print(f"Client connected: {request.sid}")
    # Send initial module states
    socketio.emit('module_states', module_states)

@socketio.on('disconnect')
def ws_disconnect():
    """Handle client disconnection"""
    print(f"Client disconnected: {request.sid}")

def broadcast_log(module, message, level="INFO"):
    """Broadcast log message to all connected clients"""
    socketio.emit('log_event', {
        'module': module,
        'message': message,
        'level': level,
        'timestamp': datetime.now().isoformat()
    })

# --- Main ---

if __name__ == '__main__':
    # Ensure all JSON log files exist
    for key in ['endpoint_json', 'network', 'honeypot']:
        ensure_json_file(LOG_FILES[key])
    socketio.run(app, debug=True)
