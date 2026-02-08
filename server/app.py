from flask import Flask, request, jsonify, render_template
import json
import datetime
import os
from collections import Counter

app = Flask(__name__)

# File to store the intrusion logs
LOG_FILE = 'intrusion_logs.json'

# Ensure log file exists
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w') as f:
        json.dump([], f)

def save_logs(logs):
    """Writes logs to the JSON file"""
    try:
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=4)
    except Exception as e:
        print(f"Error saving logs: {e}")

def load_logs():
    """Reads logs from the JSON file"""
    try:
        with open(LOG_FILE, 'r') as f:
            return json.load(f)
    except: return []

@app.route('/')
def dashboard():
    """Module 4: Incident Response Console (Distributed Ready)"""
    all_logs = load_logs()
    
    # 1. Filter Active Threats (Unresolved Critical/Warning)
    active_threats = [
        l for l in all_logs 
        if l.get('acknowledged') == False and l.get('severity') in ['CRITICAL', 'WARNING']
    ]
    
    # 2. Filter Resolved Threats
    resolved_threats = [
        l for l in all_logs 
        if l.get('acknowledged') == True
    ]

    # Calculate Stats
    stats = {
        "total": len(all_logs),
        "active": len(active_threats),
        "critical": sum(1 for log in all_logs if log.get('severity') == 'CRITICAL'),
        "last_seen": all_logs[-1]['timestamp'] if all_logs else "-"
    }

    # Chart Data
    attack_counts = Counter([log['attack_type'] for log in all_logs])
    
    # RENDER TEMPLATE
    # We use list() wrappers to prevent the 'iterator' crash
    return render_template('dashboard.html', 
                         logs=list(reversed(all_logs[-50:])), 
                         active_threats=list(reversed(active_threats)), 
                         resolved_threats=list(reversed(resolved_threats)),
                         stats=stats,
                         chart_labels=list(attack_counts.keys()),
                         chart_data=list(attack_counts.values()))

@app.route('/api/alert', methods=['POST'])
def webhook():
    """Receives alerts from the Sensor (Agent)"""
    data = request.json
    
    # Add Server Timestamp
    data['timestamp'] = datetime.datetime.now().strftime("%H:%M:%S")
    
    # Default status is "Unread"
    data['acknowledged'] = False 
    
    logs = load_logs()
    logs.append(data)
    save_logs(logs)
    
    print(f"[+] Alert Received: {data['attack_type']} from {data['source_ip']}")
    return jsonify({"status": "logged"}), 200

@app.route('/api/resolve', methods=['POST'])
def resolve_threat():
    """Marks an IP or Attack as 'Resolved'"""
    target_ip = request.json.get('source_ip')
    
    logs = load_logs()
    # Find all logs from this IP and mark them as acknowledged
    for log in logs:
        if log.get('source_ip') == target_ip:
            log['acknowledged'] = True
            
    save_logs(logs)
    return jsonify({"status": "resolved"}), 200

@app.route('/api/reset', methods=['POST'])
def reset_logs():
    """Clears the database for a fresh demo"""
    save_logs([])
    return jsonify({"status": "cleared"}), 200

if __name__ == '__main__':
    # HOST='0.0.0.0' allows connections from other machines (Distributed Mode)
    print("[*] Server running on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
