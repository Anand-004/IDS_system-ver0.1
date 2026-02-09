import scapy.all as scapy
import pandas as pd
import joblib
import time
import requests
import socket
import sys
import os
import threading
from collections import deque, defaultdict
import numpy as np
from urllib.parse import unquote  # <--- CRITICAL for Web Attacks

# ================= CONFIGURATION =================
# 🔴 IMPORTANT: REPLACE '192.168.X.X' WITH YOUR SERVER'S REAL IP
SERVER_IP = "192.x.x.x"  
SERVER_URL = f"http://{SERVER_IP}:5000/api/alert" 

# THRESHOLDS
DOS_THRESHOLD = 150         # Packets per second
BRUTE_FORCE_THRESHOLD = 4   # Attempts per window
BRUTE_FORCE_WINDOW = 10.0   # Seconds
SCAN_THRESHOLD = 15         # Unique ports
SCAN_WINDOW = 2.0           # Seconds

# GLOBAL STATE
BLOCKED_IPS = set() 
packet_timestamps = deque(maxlen=500)
auth_tracker = defaultdict(lambda: {"timestamp": 0, "count": 0})
scan_tracker = defaultdict(lambda: {"timestamp": 0, "ports": set()})

# ================= HELPER FUNCTIONS =================
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) 
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except: return "127.0.0.1"

MY_IP = get_local_ip()

# WHITELIST
WHITELIST_IPS = {
    "127.0.0.1", "localhost", SERVER_IP, "192.168.1.1", MY_IP
}

# ================= LOAD AI MODELS =================
print("[*] Loading AI Models...")
try:
    # We use relative paths assuming script runs from 'sensor' folder
    # iso_forest = joblib.load('iso_forest.pkl') # Optional
    rf_classifier = joblib.load('rf_classifier.pkl')
    encoders = joblib.load('encoders.pkl')
    print("[+] Models Loaded Successfully!")
    AI_ENABLED = True
except FileNotFoundError:
    print("[-] WARNING: .pkl files missing! Running in Signature-Only Mode.")
    AI_ENABLED = False

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

# ================= UTILITIES (OPTIMIZED) =================

def get_traffic_rate():
    current_time = time.time()
    packet_timestamps.append(current_time)
    count = 0
    for timestamp in packet_timestamps:
        if current_time - timestamp < 1.0: count += 1
    return count

def block_ip(ip_address):
    """Adds IP to Linux Firewall (Threaded & Instant)"""
    if ip_address in WHITELIST_IPS: return
    
    # 1. Instant Memory Block (Prevents spamming the system command)
    if ip_address in BLOCKED_IPS: return
    BLOCKED_IPS.add(ip_address)
    
    print(f"\033[91m[⚔️] BLOCKING IP {ip_address} (Active Defense)...\033[0m")
    
    # 2. Run slow iptables command in background
    def _run_iptables():
        try: os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
        except: pass
        
    t = threading.Thread(target=_run_iptables)
    t.daemon = True
    t.start()

def _send_alert_thread(data):
    """Worker function to send alert in background"""
    try:
        requests.post(SERVER_URL, json=data, timeout=1)
    except Exception:
        pass

def send_alert(attack_type, src_ip, rate, severity="CRITICAL"):
    """Starts the alert worker without blocking the main script"""
    alert_data = {
        "victim_ip": str(MY_IP),
        "source_ip": str(src_ip),
        "attack_type": str(attack_type),
        "traffic_rate": int(rate),
        "severity": severity
    }
    # Fire and Forget! 🚀
    t = threading.Thread(target=_send_alert_thread, args=(alert_data,))
    t.daemon = True # Kills thread if script ends
    t.start()

def preprocess_packet(pkt):
    """Converts raw packet to 41 KDD features for ML Model"""
    row = {col: 0 for col in features_order}
    if pkt.haslayer(scapy.IP): row['src_bytes'] = len(pkt)
    current_rate = get_traffic_rate()
    
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

# ================= CORE LOGIC =================
def process_packet(pkt):
    if not pkt.haslayer(scapy.IP): return
    
    src_ip = pkt[scapy.IP].src
    current_time = time.time()
    
    # IGNORE TRAFFIC (Instant check)
    if src_ip in BLOCKED_IPS or src_ip in WHITELIST_IPS: return 

    current_rate = get_traffic_rate()

    # --- 1. U2R DETECTION (New Signature) ---
    if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw):
        try:
            payload = pkt[scapy.Raw].load.decode('utf-8', errors='ignore')
            if "uid=0(root)" in payload:
                print(f"\033[95m[👑] CRITICAL: U2R Attack (Root Access) from {src_ip}\033[0m")
                send_alert("U2R (Privilege Escalation)", src_ip, current_rate, "CRITICAL")
                block_ip(src_ip)
                return
        except: pass

    # --- 2. BRUTE FORCE DETECTION (New Signature) ---
    if pkt.haslayer(scapy.TCP):
        dst_port = pkt[scapy.TCP].dport
        flags = pkt[scapy.TCP].flags
        if dst_port in [22, 21, 3389] and flags == "S":
            tracker = auth_tracker[src_ip]
            if current_time - tracker["timestamp"] > BRUTE_FORCE_WINDOW:
                tracker["count"] = 0
                tracker["timestamp"] = current_time
            tracker["count"] += 1
            if tracker["count"] > BRUTE_FORCE_THRESHOLD:
                print(f"\033[91m[🔐] CRITICAL: Brute Force on Port {dst_port} from {src_ip}\033[0m")
                send_alert(f"Brute Force (Port {dst_port})", src_ip, current_rate, "CRITICAL")
                tracker["count"] = 0 
                return

    # --- 3. WEB ATTACK DETECTION (New Signature + Unquote) ---
    if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw):
        dst_port = pkt[scapy.TCP].dport
        if dst_port == 80 or dst_port == 8080:
            try:
                payload = pkt[scapy.Raw].load.decode('utf-8', errors='ignore')
                payload = unquote(payload).upper()
                sqli_patterns = ["UNION SELECT", "OR 1=1", "DROP TABLE", "SCRIPT>"]
                if any(p in payload for p in sqli_patterns):
                    print(f"\033[91m[💉] CRITICAL: Web Attack Detected from {src_ip}\033[0m")
                    send_alert("Web Attack (SQLi/XSS)", src_ip, current_rate, "CRITICAL")
                    return
            except: pass

    # --- 4. PORT SCAN DETECTION (Signature) ---
    if pkt.haslayer(scapy.TCP) or pkt.haslayer(scapy.UDP):
        dst_port = pkt[scapy.TCP].dport if pkt.haslayer(scapy.TCP) else pkt[scapy.UDP].dport
        scan_track = scan_tracker[src_ip]
        if current_time - scan_track["timestamp"] > SCAN_WINDOW:
            scan_track["ports"] = set()
            scan_track["timestamp"] = current_time
        scan_track["ports"].add(dst_port)
        if len(scan_track["ports"]) > SCAN_THRESHOLD:
            print(f"\033[93m[⚠️] WARNING: Port Scan Detected from {src_ip}\033[0m")
            send_alert("Nmap Scan (Recon)", src_ip, current_rate, "WARNING")
            scan_track["ports"] = set()
            return

    # --- 5. DOS FLOOD DETECTION (Signature) ---
    if current_rate > DOS_THRESHOLD:
        print(f"\033[91m[🔥] CRITICAL: DoS Flood | Rate: {current_rate}\033[0m")
        send_alert("DoS-Flood (Volume)", src_ip, current_rate, "CRITICAL")
        block_ip(src_ip)
        return

    # --- 6. ML MODEL DETECTION (Fallback / AI Check) ---
    if AI_ENABLED and current_rate < DOS_THRESHOLD:
        try:
            features = preprocess_packet(pkt)
            attack_code = rf_classifier.predict(features)[0]
            ml_attack_name = encoders['label'].inverse_transform([attack_code])[0]
            
            if ml_attack_name not in ["normal", "benign"]:
                print(f"\033[93m[🤖] ML DETECTED: {ml_attack_name.upper()} from {src_ip}\033[0m")
                send_alert(f"ML: {ml_attack_name}", src_ip, current_rate, "WARNING")
        except: pass

# ================= BACKGROUND HEARTBEAT =================
def heartbeat_loop():
    while True:
        time.sleep(3)
        rate = get_traffic_rate()
        if rate < 20: 
            send_alert("System Normal", "Local Network", rate, severity="INFO")

# ================= STARTUP =================
t = threading.Thread(target=heartbeat_loop)
t.daemon = True
t.start()

print(f"==========================================")
print(f"   🛡️  HYBRID IDS (Signatures + ML AI)")
print(f"==========================================")
print(f"[*] AI Enabled: {AI_ENABLED}")
print(f"[*] Monitoring: {MY_IP}")
print(f"[*] Dashboard:  {SERVER_URL}")
print(f"[*] Press Ctrl+C to stop.")

# Store=0 prevents memory leaks
scapy.sniff(prn=process_packet, store=0)
