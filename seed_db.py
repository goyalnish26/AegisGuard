import sqlite3
import datetime
import random
import os
from aegis_db import DB_PATH, get_ip_geolocation, get_db_connection

def seed_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if table already has data
    cursor.execute("SELECT COUNT(*) FROM alerts")
    count = cursor.fetchone()[0]
    if count > 0:
        print(f"[*] Database already contains {count} alerts. Skipping seeding.")
        conn.close()
        return
        
    print("[*] Seeding database with realistic historical alerts...")
    
    ips = {
        "198.51.100.42": "United States",
        "203.0.113.88": "United Kingdom",
        "185.220.101.5": "Germany",
        "45.143.203.14": "Japan",
        "91.241.19.84": "Brazil",
        "182.21.43.109": "South Korea",
        "122.160.231.10": "India",
        "95.213.255.1": "Russia"
    }
    
    rules = [
        {
            "rule_name": "Failed SSH Login Attempt",
            "severity": "Low",
            "mitre_id": "T1110",
            "mitre_name": "Brute Force",
            "description": "A failed SSH authentication attempt was detected. (User: root)",
            "raw_log_template": "{} [INFO] sshd[12401]: Failed password for root from {} port 54312 ssh2"
        },
        {
            "rule_name": "SSH Login Brute Force",
            "severity": "High",
            "mitre_id": "T1110",
            "mitre_name": "Brute Force",
            "description": "IP address {} triggered brute-force threshold: 5 failed attempts within 60s.",
            "raw_log_template": "Multiple failures. Last log: Failed password for root from {}"
        },
        {
            "rule_name": "SQL Injection Attempt",
            "severity": "Critical",
            "mitre_id": "T1190",
            "mitre_name": "Exploit Public-Facing Application",
            "description": "SQL injection signatures detected in the request URL or parameters.",
            "raw_log_template": "{} - - [{}] \"GET /products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1\" 200 1204 \"-\" \"Mozilla/5.0\""
        },
        {
            "rule_name": "Directory Traversal Attempt",
            "severity": "High",
            "mitre_id": "T1083",
            "mitre_name": "File and Directory Discovery",
            "description": "Directory traversal attempt targeting sensitive files or path evasion.",
            "raw_log_template": "{} - - [{}] \"GET /download.php?file=../../../../etc/passwd HTTP/1.1\" 403 220 \"-\" \"Mozilla/5.0\""
        },
        {
            "rule_name": "Cross-Site Scripting (XSS) Attempt",
            "severity": "High",
            "mitre_id": "T1189",
            "mitre_name": "Drive-by Compromise",
            "description": "XSS script execution tags detected in incoming web request.",
            "raw_log_template": "{} - - [{}] \"GET /comment.php?msg=<script>alert('hack')</script> HTTP/1.1\" 200 450 \"-\" \"Mozilla/5.0\""
        },
        {
            "rule_name": "Sensitive Path Access",
            "severity": "Medium",
            "mitre_id": "T1595",
            "mitre_name": "Active Scanning",
            "description": "Access attempt targeting administrative, configuration, or environment files.",
            "raw_log_template": "{} - - [{}] \"GET /.env HTTP/1.1\" 404 150 \"-\" \"Mozilla/5.0\""
        }
    ]
    
    now = datetime.datetime.now()
    
    seeded_alerts = []
    
    # Generate 18 events spread over the last 7 days
    # Ensure 198.51.100.42 and 203.0.113.88 are top offenders
    for i in range(18):
        days_ago = random.uniform(0.1, 7.0)
        timestamp = (now - datetime.timedelta(days=days_ago)).isoformat()
        
        if i < 6:
            ip = "198.51.100.42"
        elif i < 10:
            ip = "203.0.113.88"
        else:
            ip = random.choice(list(ips.keys()))
            
        rule = random.choice(rules)
        
        if rule["rule_name"] == "SSH Login Brute Force":
            desc = rule["description"].format(ip)
            raw_log = rule["raw_log_template"].format(ip)
        elif "SQL" in rule["rule_name"] or "Directory" in rule["rule_name"] or "Cross-Site" in rule["rule_name"] or "Sensitive" in rule["rule_name"]:
            desc = rule["description"]
            web_ts = (now - datetime.timedelta(days=days_ago)).strftime("%d/%b/%Y:%H:%M:%S +0530")
            raw_log = rule["raw_log_template"].format(ip, web_ts)
        else:
            desc = rule["description"]
            raw_log = rule["raw_log_template"].format(timestamp, ip)
            
        geo = get_ip_geolocation(ip)
        
        status = "Resolved" if days_ago > 2 else random.choice(["New", "Resolved"])
        
        seeded_alerts.append((
            timestamp,
            ip,
            rule["rule_name"],
            rule["severity"],
            desc,
            raw_log,
            status,
            geo["lat"],
            geo["lng"],
            rule["mitre_id"],
            rule["mitre_name"]
        ))
        
    seeded_alerts.sort(key=lambda x: x[0])
    
    cursor.executemany("""
        INSERT INTO alerts (timestamp, source_ip, rule_name, severity, description, raw_log, status, lat, lng, mitre_id, mitre_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, seeded_alerts)
    
    conn.commit()
    conn.close()
    print("[+] Seeding completed successfully. Seeded 18 historical incidents.")

if __name__ == "__main__":
    seed_database()
