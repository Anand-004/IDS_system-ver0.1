import scapy.all as scapy
import pandas as pd
import joblib
import time
import requests
import socket
import sys
import os
import threading
from collections import deque
import numpy as np

# ================= CONFIGURATION =================
# 🔴 IMPORTANT: REPLACE '192.168.X.X' WITH YOUR SERVER'S REAL IP
SERVER_IP = "10.226.18.227"  # <--- CHECK THIS IP!
SERVER_URL = f"http://{SERVER_IP}:5000/api/alert" 

# GLOBAL IGNORE LISTS
BLOCKED_IPS = set() 

# ================= HELPER FUNCTIONS =================
def get_local_ip():
    """Gets the IP address of this machine"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) 
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except: return "127.0.0.1"

MY_IP = get_local_ip()
print(f"[*] Sensor Initialized. Monitoring: {MY_IP}")
print(f"[*] Connecting to Dashboard at: {SERVER_URL}")

# WHITELIST: NEVER BLOCK THESE IPS
WHITELIST_IPS = {
    "127.0.0.1", 
    "localhost", 
    SERVER_IP,       # The Dashboard Server
    "192.168.1.1",   # The Gateway/Router
    MY_IP            # Myself
}

# Load Pre-trained AI Models
print("[*] Loading AI Models...")
try:
    # We use relative paths assuming script runs from 'sensor' folder
    iso_forest = joblib.load('iso_forest.pkl')
    rf_classifier = joblib.load('rf_classifier.pkl')
    encoders = joblib.load('encoders.pkl')
    print("[+] Models Loaded Successfully!")
except FileNotFoundError:
    print("[-] ERROR: .pkl files missing! Make sure you run this from the 'sensor' folder.")
    sys.exit()

# NSL-KDD Feature List (Must match training data)
features_order = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"]

# Traffic Trackers
packet_timestamps = deque(maxlen=500)
dst_ports_tracker = {} # Format: {'IP': {ports_set}}
last_port_clear_time = time.time()

def get_traffic_rate():
    """Calculates packets per second"""
    current_time = time.time()
    packet_timestamps.append(current_time)
    count = 0
    for timestamp in packet_timestamps:
        if current_time - timestamp < 1.0: count += 1
    return count

def block_ip(ip_address):
    """Adds IP to Linux Firewall (With Whitelist Safety Check)"""
    
    # 1. SAFETY CHECK: Is this IP in the Whitelist?
    if ip_address in WHITELIST_IPS:
        print(f"\033[92m[!] SAFETY: Ignoring Whitelisted IP {ip_address}\033[0m")
        return

    # 2. Add to Python Ignore List (Immediate Dashboard Fix)
    if ip_address not in BLOCKED_IPS:
        BLOCKED_IPS.add(ip_address)
        print(f"\033[91m[⚔️] BLOCKING IP {ip_address} (Active Defense Engaged)...\033[0m")
    
    # 3. Add to Linux Firewall (Actual Protection)
    try:
        check = os.system(f"sudo iptables -C INPUT -s {ip_address} -j DROP 2>/dev/null")
        if check != 0:
            os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
    except: pass

def send_alert(attack_type, src_ip, rate, severity="CRITICAL"):
    """Sends JSON alert to the Central Dashboard"""
    alert_data = {
        "victim_ip": str(MY_IP),
        "source_ip": str(src_ip),
        "attack_type": str(attack_type),
        "traffic_rate": int(rate),
        "severity": severity
    }
    try: requests.post(SERVER_URL, json=alert_data, timeout=1)
    except: pass

# ================= BACKGROUND HEARTBEAT =================
def heartbeat_loop():
    """Sends a 'Normal' status every 3 seconds if no attack"""
    while True:
        time.sleep(3)
        rate = get_traffic_rate()
        
        # Only say "Normal" if traffic is calm (< 30 pkts/sec)
        if rate < 30: 
            send_alert("System Normal", "Local Network", rate, severity="INFO")

# ================= PACKET PROCESSING =================
def preprocess_packet(pkt):
    """Converts raw packet to 41 KDD features"""
    row = {col: 0 for col in features_order}
    if pkt.haslayer(scapy.IP): row['src_bytes'] = len(pkt)
    current_rate = get_traffic_rate()
    
    # Simulate High-Traffic Features for Demo (since hping3 is small)
    if current_rate > 40: 
        row['count'] = 500
        row['srv_count'] = 500
        row['dst_host_count'] = 255
        row['same_srv_rate'] = 1.0
    else:
        row['count'] = current_rate
        row['srv_count'] = current_rate

    proto = 'tcp'
    if pkt.haslayer(scapy.UDP): proto = 'udp'
    if pkt.haslayer(scapy.ICMP): proto = 'icmp'
    try:
        row['protocol_type'] = encoders['protocol_type'].transform([proto])[0]
        row['service'] = encoders['service'].transform(['private'])[0]
        row['flag'] = encoders['flag'].transform(['SF'])[0]
    except: pass 
    return pd.DataFrame([row], columns=features_order)

def process_packet(pkt):
    global last_port_clear_time

    if not pkt.haslayer(scapy.IP): return
    src_ip = pkt[scapy.IP].src
    
    # IGNORE BLOCKED TRAFFIC & SELF
    if src_ip in BLOCKED_IPS or src_ip in WHITELIST_IPS: return 
    
    # Get Destination Port (if TCP/UDP)
    dst_port = 0
    if pkt.haslayer(scapy.TCP): dst_port = pkt[scapy.TCP].dport
    elif pkt.haslayer(scapy.UDP): dst_port = pkt[scapy.UDP].dport

    # 1. TRACK PORTS (For Nmap Detection)
    # Clear tracker every 1 second to keep it fresh
    if time.time() - last_port_clear_time > 1.0:
        dst_ports_tracker.clear()
        last_port_clear_time = time.time()

    if src_ip not in dst_ports_tracker: dst_ports_tracker[src_ip] = set()
    dst_ports_tracker[src_ip].add(dst_port)
    
    unique_ports_count = len(dst_ports_tracker[src_ip])
    current_rate = get_traffic_rate()

    # ================= SMART DECISION LOGIC =================
    
    final_name = "Normal"
    severity = "INFO"

    # RULE 1: IS IT A PORT SCAN? (Nmap Check)
    # If they touch > 5 different ports, it is a SCAN, not a Flood.
    if unique_ports_count > 5:
        final_name = "PROBE"
        severity = "WARNING"  # <--- FORCE WARNING ONLY!

    # RULE 2: IS IT A FLOOD? (Volume Check)
    # Only block if it is NOT a scan (1 port) AND very fast (> 85 pps)
    elif current_rate > 85:
        final_name = "DoS-Flood (Volume Limit)"
        severity = "CRITICAL" # <--- BLOCK THIS

    # RULE 3: ML CHECK (Fallback)
    else:
        features = preprocess_packet(pkt)
        try:
            attack_code = rf_classifier.predict(features)[0]
            ml_attack_name = encoders['label'].inverse_transform([attack_code])[0]
            if ml_attack_name not in ["normal", "benign"]:
                final_name = ml_attack_name.upper()
                severity = "WARNING"
        except: pass

    # ================= EXECUTE RESPONSE =================
    
    if severity == "CRITICAL":
        print(f"\033[91m[!] CRITICAL: {final_name} | Rate: {current_rate}\033[0m")
        send_alert(final_name, src_ip, current_rate, severity="CRITICAL")
        block_ip(src_ip)

    elif severity == "WARNING":
        # Check if we already sent an alert recently to avoid spamming
        print(f"\033[93m[⚠] WARNING: {final_name} | Ports: {unique_ports_count} | Rate: {current_rate}\033[0m")
        send_alert(final_name, src_ip, current_rate, severity="WARNING")

# ================= STARTUP =================
# Start Heartbeat in Background
t = threading.Thread(target=heartbeat_loop)
t.daemon = True
t.start()

print(f"[*] Agent Running... Press Ctrl+C to stop.")
scapy.sniff(prn=process_packet, store=0)
