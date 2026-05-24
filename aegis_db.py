import sqlite3
import datetime
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aegis.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')) NOT NULL,
            description TEXT NOT NULL,
            raw_log TEXT NOT NULL,
            status TEXT CHECK(status IN ('New', 'Resolved', 'Dismissed')) DEFAULT 'New' NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()

def add_alert(source_ip, rule_name, severity, description, raw_log):
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    
    cursor.execute("""
        INSERT INTO alerts (timestamp, source_ip, rule_name, severity, description, raw_log, status)
        VALUES (?, ?, ?, ?, ?, ?, 'New')
    """, (timestamp, source_ip, rule_name, severity, description, raw_log))
    
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
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
    # For local testing, let's just group by last 10 alert entries timestamps, or direct count by hour
    # We will fetch recent alerts and group them in backend or keep it basic here
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
