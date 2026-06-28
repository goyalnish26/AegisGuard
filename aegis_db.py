import sqlite3
import datetime
import os
import urllib.request
import json

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aegis.db")

# Cache for IP geolocations to prevent rate limits and speed up lookups
IP_GEO_CACHE = {
    "198.51.100.42": {"lat": 40.7128, "lng": -74.0060, "country": "United States"},
    "203.0.113.88": {"lat": 51.5074, "lng": -0.1278, "country": "United Kingdom"},
    "185.220.101.5": {"lat": 52.5200, "lng": 13.4050, "country": "Germany"},
    "45.143.203.14": {"lat": 35.6762, "lng": 139.6503, "country": "Japan"},
    "91.241.19.84": {"lat": -23.5505, "lng": -46.6333, "country": "Brazil"},
    "192.168.1.15": {"lat": 26.9124, "lng": 75.7873, "country": "India (Local)"},
    "10.0.0.4": {"lat": 26.9124, "lng": 75.7873, "country": "India (Local)"},
    "192.168.1.105": {"lat": 26.9124, "lng": 75.7873, "country": "India (Local)"},
    "182.21.43.109": {"lat": 37.5665, "lng": 126.9780, "country": "South Korea"},
    "122.160.231.10": {"lat": 28.6139, "lng": 77.2090, "country": "India"},
}

def get_ip_geolocation(ip):
    # Check cache
    if ip in IP_GEO_CACHE:
        return IP_GEO_CACHE[ip]
    
    # Check for private or local IPs
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip == "localhost" or ip == "Unknown":
        return {"lat": 26.9124, "lng": 75.7873, "country": "Local"}
        
    try:
        url = f"http://ip-api.com/json/{ip}"
        req = urllib.request.Request(url, headers={'User-Agent': 'AegisGuard'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get("status") == "success":
                geo = {
                    "lat": float(data.get("lat")),
                    "lng": float(data.get("lon")),
                    "country": data.get("country")
                }
                IP_GEO_CACHE[ip] = geo
                return geo
    except Exception as e:
        print(f"[!] Error geolocating IP {ip}: {e}")
        
    # Default fallback: Jaipur, India
    return {"lat": 26.9124, "lng": 75.7873, "country": "Unknown"}

# Alert registration callbacks for real-time WebSocket push
alert_callbacks = []

def register_alert_callback(callback):
    alert_callbacks.append(callback)

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create alerts table with expanded schema
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')) NOT NULL,
            description TEXT NOT NULL,
            raw_log TEXT NOT NULL,
            status TEXT CHECK(status IN ('New', 'Resolved', 'Dismissed')) DEFAULT 'New' NOT NULL,
            lat REAL,
            lng REAL,
            mitre_id TEXT,
            mitre_name TEXT
        )
    """)
    
    # Upgrade database schema if it already exists
    cursor.execute("PRAGMA table_info(alerts)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'lat' not in columns:
        cursor.execute("ALTER TABLE alerts ADD COLUMN lat REAL")
    if 'lng' not in columns:
        cursor.execute("ALTER TABLE alerts ADD COLUMN lng REAL")
    if 'mitre_id' not in columns:
        cursor.execute("ALTER TABLE alerts ADD COLUMN mitre_id TEXT")
    if 'mitre_name' not in columns:
        cursor.execute("ALTER TABLE alerts ADD COLUMN mitre_name TEXT")
        
    conn.commit()
    conn.close()

def add_alert(source_ip, rule_name, severity, description, raw_log, mitre_id=None, mitre_name=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    
    geo = get_ip_geolocation(source_ip)
    lat = geo["lat"]
    lng = geo["lng"]
    
    cursor.execute("""
        INSERT INTO alerts (timestamp, source_ip, rule_name, severity, description, raw_log, status, lat, lng, mitre_id, mitre_name)
        VALUES (?, ?, ?, ?, ?, ?, 'New', ?, ?, ?, ?)
    """, (timestamp, source_ip, rule_name, severity, description, raw_log, lat, lng, mitre_id, mitre_name))
    
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Broadcast to registered callbacks (like WebSocket push)
    alert_data = {
        "id": alert_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "rule_name": rule_name,
        "severity": severity,
        "description": description,
        "raw_log": raw_log,
        "status": "New",
        "lat": lat,
        "lng": lng,
        "country": geo.get("country", "Unknown"),
        "mitre_id": mitre_id,
        "mitre_name": mitre_name
    }
    
    for cb in alert_callbacks:
        try:
            cb(alert_data)
        except Exception as e:
            print(f"[!] Error invoking alert callback: {e}")
            
    return alert_id

def get_alerts(limit=100, offset=0, status=None, severity=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    
    if status:
        query += " AND status = ?"
        params.append(status)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
        
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def resolve_alert(alert_id, new_status="Resolved"):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE alerts
        SET status = ?
        WHERE id = ?
    """, (new_status, alert_id))
    conn.commit()
    conn.close()

def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Total count
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]
    
    # Active incidents (New status)
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'New'")
    active_alerts = cursor.fetchone()[0]
    
    # Breakdown by severity
    cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    severity_counts = {row[0]: row[1] for row in cursor.fetchall()}
    # Ensure all severities exist in output
    for sev in ['Low', 'Medium', 'High', 'Critical']:
        if sev not in severity_counts:
            severity_counts[sev] = 0
            
    # Top 5 offending IPs
    cursor.execute("""
        SELECT source_ip, COUNT(*) as count 
        FROM alerts 
        GROUP BY source_ip 
        ORDER BY count DESC 
        LIMIT 5
    """)
    top_ips = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    # Timeline: alerts in last 10 hours/buckets
    cursor.execute("SELECT timestamp, severity FROM alerts ORDER BY id DESC LIMIT 100")
    recent_events = [{"timestamp": row[0], "severity": row[1]} for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        "total_alerts": total_alerts,
        "active_alerts": active_alerts,
        "severity_breakdown": severity_counts,
        "top_ips": top_ips,
        "recent_events": recent_events
    }

def clear_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("AegisGuard Database initialized successfully at:", DB_PATH)

