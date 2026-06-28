import os
import re
import json
import time
import threading
from collections import defaultdict
import datetime
import urllib.parse
import urllib.request
import urllib.error
import aegis_db

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(BASE_DIR, "rules.json")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# Stateful alert memory
# Format: { ip: [timestamp1, timestamp2, ...] }
failed_ssh_attempts = defaultdict(list)
brute_force_cooldown = {} # { ip: last_alert_time }

# Regex to extract IP from standard web server access log (first word)
WEB_IP_REGEX = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

def send_webhook_alert(source_ip, rule_name, severity, description):
    webhook_url = os.environ.get("AEGIS_WEBHOOK_URL")
    if not webhook_url:
        return
        
    # We only send webhooks for High and Critical alerts
    if severity not in ["High", "Critical"]:
        return
        
    color_map = {
        "Critical": 15548997, # Red
        "High": 15105570,     # Orange
        "Medium": 15844367,   # Yellow
        "Low": 3066993        # Green
    }
    
    is_discord = "discord.com" in webhook_url
    
    if is_discord:
        payload = {
            "embeds": [
                {
                    "title": f"🚨 AEGISGUARD ALERT: {rule_name}",
                    "description": description,
                    "color": color_map.get(severity, 10066329),
                    "fields": [
                        {"name": "Source IP", "value": source_ip, "inline": True},
                        {"name": "Severity", "value": severity, "inline": True},
                        {"name": "Timestamp", "value": datetime.datetime.now().isoformat(), "inline": True}
                    ],
                    "footer": {
                        "text": "AegisGuard Mini-SIEM"
                    }
                }
            ]
        }
    else:
        payload = {
            "text": f"🚨 *AEGISGUARD ALERT [{severity}]* - *{rule_name}*\n*IP:* `{source_ip}`\n*Description:* {description}"
        }
        
    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': 'AegisGuard-SIEM'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            pass
        print(f"[*] Webhook alert successfully sent for {rule_name}")
    except Exception as e:
        print(f"[!] Failed to send webhook alert: {e}")

def load_rules():
    try:
        with open(RULES_PATH, 'r') as f:
            data = json.load(f)
            return data.get("rules", [])
    except Exception as e:
        print(f"[!] Error loading rules.json: {e}")
        return []

def get_ip_from_web_log(line):
    match = WEB_IP_REGEX.match(line)
    if match:
        return match.group(1)
    return "Unknown-IP"

def process_log_line(log_type, line, rules):
    line = line.strip()
    if not line or line.startswith("#"):
        return
    
    # URL decode web logs so we can match URL-encoded payloads like SQLi and XSS
    decoded_line = urllib.parse.unquote(line) if log_type == "web" else line
    
    # 1. Check stateless rules first
    for rule in rules:
        if rule.get("is_stateful") or rule.get("log_type") != log_type:
            continue
            
        pattern = rule.get("pattern")
        if not pattern:
            continue
            
        match = re.search(pattern, decoded_line)
        if match:
            # Extract fields (like IP or User)
            source_ip = "Unknown"
            user = "Unknown"
            
            extract = rule.get("extract_fields", {})
            if log_type == "web":
                source_ip = get_ip_from_web_log(decoded_line)
            elif log_type == "auth":
                # For auth, use regex groups specified in rules.json
                # pattern: Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)
                # user is group 2, ip is group 3
                try:
                    if "ip" in extract:
                        source_ip = match.group(extract["ip"])
                    if "user" in extract:
                        user = match.group(extract["user"])
                except IndexError:
                    pass
            
            # Add alert to database
            severity = rule.get("severity", "Low")
            name = rule.get("name")
            desc = rule.get("description")
            if user != "Unknown":
                desc += f" (User: {user})"
                
            print(f"[*] ALERT [{severity}] {name} from {source_ip}: {desc}")
            aegis_db.add_alert(source_ip, name, severity, desc, decoded_line,
                               mitre_id=rule.get("mitre_id"), mitre_name=rule.get("mitre_name"))
            
            # Send Webhook dispatch for High/Critical alerts
            send_webhook_alert(source_ip, name, severity, desc)
            
            # Handle dependencies for stateful rules
            # (e.g. if this failed attempt triggers a brute force calculation)
            if rule.get("id") == "RULE_SSH_FAILED_PWD" and source_ip != "Unknown":
                handle_ssh_failed_login(source_ip, decoded_line, rules)

def handle_ssh_failed_login(ip, raw_line, rules):
    # Find the brute force rule definition
    brute_rule = next((r for r in rules if r.get("id") == "RULE_SSH_BRUTE_FORCE"), None)
    if not brute_rule:
        return
        
    now = time.time()
    
    # Check cooldown
    if ip in brute_force_cooldown:
        if now - brute_force_cooldown[ip] < brute_rule.get("time_window_seconds", 60):
            # In cooldown, don't spam brute force alerts
            return
            
    # Add current timestamp to failed attempts list for this IP
    failed_ssh_attempts[ip].append(now)
    
    # Filter attempts within the time window
    window = brute_rule.get("time_window_seconds", 60)
    failed_ssh_attempts[ip] = [t for t in failed_ssh_attempts[ip] if now - t <= window]
    
    # Check if threshold is reached
    threshold = brute_rule.get("threshold_count", 5)
    if len(failed_ssh_attempts[ip]) >= threshold:
        severity = brute_rule.get("severity", "High")
        name = brute_rule.get("name")
        desc = f"IP address {ip} triggered brute-force threshold: {len(failed_ssh_attempts[ip])} failed attempts within {window}s."
        
        print(f"[!] CRITICAL ALERT [{severity}] {name} from {ip}: {desc}")
        aegis_db.add_alert(ip, name, severity, desc, f"Multiple failures. Last log: {raw_line}",
                           mitre_id=brute_rule.get("mitre_id"), mitre_name=brute_rule.get("mitre_name"))
        
        # Send Webhook dispatch
        send_webhook_alert(ip, name, severity, desc)
        
        # Set cooldown and clear attempts list to reset calculation
        brute_force_cooldown[ip] = now
        failed_ssh_attempts[ip].clear()

def tail_file(filepath, log_type, rules, stop_event):
    print(f"[*] Starting tailer for {log_type} log at: {filepath}")
    
    # Make sure file exists
    if not os.path.exists(filepath):
        # Create empty file
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            pass
            
    try:
        with open(filepath, 'r', errors='ignore') as f:
            # Go to the end of the file
            f.seek(0, os.SEEK_END)
            
            while not stop_event.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                try:
                    process_log_line(log_type, line, rules)
                except Exception as ex:
                    print(f"[!] Error processing line in {log_type}: {ex}")
    except Exception as e:
        print(f"[!] Log tailer for {filepath} encountered an error: {e}")

class AegisDetector:
    def __init__(self):
        self.rules = load_rules()
        self.stop_event = threading.Event()
        self.threads = []
        
    def start(self):
        aegis_db.init_db()
        print(f"[*] Loaded {len(self.rules)} rules from rules.json")
        
        auth_log = os.path.join(LOGS_DIR, "auth.log")
        web_log = os.path.join(LOGS_DIR, "web_access.log")
        
        t1 = threading.Thread(target=tail_file, args=(auth_log, "auth", self.rules, self.stop_event), daemon=True)
        t2 = threading.Thread(target=tail_file, args=(web_log, "web", self.rules, self.stop_event), daemon=True)
        
        self.threads = [t1, t2]
        for t in self.threads:
            t.start()
            
    def stop(self):
        self.stop_event.set()
        for t in self.threads:
            t.join(timeout=1.0)
        print("[*] AegisGuard Detector stopped.")

if __name__ == "__main__":
    detector = AegisDetector()
    detector.start()
    print("[+] AegisGuard Detection Engine is running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping detector...")
        detector.stop()
