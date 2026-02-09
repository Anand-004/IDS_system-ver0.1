from flask import Flask, request, jsonify, render_template
import json
import datetime
import time
import os
from collections import Counter

app = Flask(__name__)

# ================= CONFIGURATION =================
LOG_FILE = 'intrusion_logs.json'

# Global variable to prevent log spam (Deduplication)
last_alert_signature = ""
last_alert_time = 0

# ANSI Colors for Terminal Output (Makes the demo look cool)
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

# Ensure log file exists
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w') as f:
        json.dump([], f)

# ================= HELPER FUNCTIONS =================

def save_logs(logs):
    """Writes logs to the JSON file safely"""
    try:
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=4)
    except Exception as e:
        print(f"{RED}[!] Error saving logs: {e}{RESET}")

def load_logs():
    """Reads logs from the JSON file"""
    try:
        with open(LOG_FILE, 'r') as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except: 
        return []

# ================= ROUTES =================

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

    # 3. Get Online Sensors (Asset Management)
    # Filter out "Unknown" IPs so we only count real machines
    online_sensors = []
    if all_logs:
        online_sensors = list(set(
            log.get('victim_ip') for log in all_logs 
            if log.get('victim_ip') and log.get('victim_ip') != "Unknown"
        ))

    # 4. Calculate Stats
    stats = {
        "total": len(all_logs),
        "active": len(active_threats),
        "critical": sum(1 for log in all_logs if log.get('severity') == 'CRITICAL'),
        "last_seen": all_logs[-1]['timestamp'] if all_logs else "-",
        "online_count": len(online_sensors)
    }

    # 5. Chart Data
    attack_counts = Counter([log.get('attack_type', 'Unknown') for log in all_logs])
    
    return render_template('dashboard.html', 
                           logs=list(reversed(all_logs[-50:])), 
                           active_threats=list(reversed(active_threats)), 
                           resolved_threats=list(reversed(resolved_threats)),
                           stats=stats,
                           online_sensors=online_sensors,
                           chart_labels=list(attack_counts.keys()),
                           chart_data=list(attack_counts.values()))

@app.route('/api/alert', methods=['POST'])
def webhook():
    """Receives alerts from the Sensor (Agent)"""
    global last_alert_signature, last_alert_time
    
    data = request.json
    
    # --- 1. SPAM PREVENTION (Deduplication) ---
    # Create a unique signature for this alert (Source IP + Attack Type)
    current_signature = f"{data.get('source_ip')}-{data.get('attack_type')}"
    current_time = time.time()
    
    # If the same attack happens within 2 seconds, ignore it (Prevent spam)
    if current_signature == last_alert_signature and (current_time - last_alert_time) < 2.0:
        print(f"{YELLOW}[!] Duplicate alert suppressed: {data.get('attack_type')}{RESET}")
        return jsonify({"status": "suppressed"}), 200

    # Update spam tracker
    last_alert_signature = current_signature
    last_alert_time = current_time

    # --- 2. PROCESS ALERT ---
    # Add Timestamp
    data['timestamp'] = datetime.datetime.now().strftime("%H:%M:%S")
    data['acknowledged'] = False 
    if 'victim_ip' not in data: data['victim_ip'] = "Unknown"
    
    # Save to Database
    logs = load_logs()
    logs.append(data)
    save_logs(logs)
    
    # --- 3. COOL TERMINAL OUTPUT ---
    if data.get('severity') == 'CRITICAL':
        print(f"{RED}[🚨 CRITICAL] {data.get('attack_type')} detected from {data.get('source_ip')}!{RESET}")
    elif data.get('severity') == 'WARNING':
        print(f"{YELLOW}[⚠️  WARNING] {data.get('attack_type')} detected from {data.get('source_ip')}{RESET}")
    else:
        print(f"{BLUE}[+] Info: {data.get('attack_type')}{RESET}")

    return jsonify({"status": "logged"}), 200

@app.route('/api/resolve', methods=['POST'])
def resolve_threat():
    """Marks an IP or Attack as 'Resolved'"""
    target_ip = request.json.get('source_ip')
    
    logs = load_logs()
    resolved_count = 0
    
    for log in logs:
        if log.get('source_ip') == target_ip:
            log['acknowledged'] = True
            resolved_count += 1
            
    save_logs(logs)
    print(f"{GREEN}[✔] Resolved {resolved_count} incidents for IP {target_ip}{RESET}")
    return jsonify({"status": "resolved"}), 200

@app.route('/api/reset', methods=['POST'])
def reset_logs():
    """Clears the database"""
    save_logs([])
    print(f"{RED}[!] DATABASE CLEARED{RESET}")
    return jsonify({"status": "cleared"}), 200

if __name__ == '__main__':
    print(f"{GREEN}[*] Server running on http://0.0.0.0:5000{RESET}")
    print(f"{BLUE}[*] Waiting for Sensors (Lubuntu/Kali)...{RESET}")
    app.run(host='0.0.0.0', port=5000, debug=True)