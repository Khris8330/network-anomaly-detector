import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = "data/network.db"

# -----------------------------
# HELPER
# -----------------------------
def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def is_unusual_hour():
    hour = datetime.now(timezone.utc).hour
    return 2 <= hour <= 5

# -----------------------------
# DATABASE INITIALIZATION
# -----------------------------
def create_database():
    Path("data").mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ---------------- DEVICE TABLE ----------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            mac TEXT NOT NULL UNIQUE,
            last_ip TEXT,
            is_known INTEGER DEFAULT 0,
            reconnect_count INTEGER DEFAULT 0,
            reconnect_timestamps TEXT DEFAULT '[]',
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ---------------- ALERTS TABLE ----------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            mac TEXT,
            ip TEXT,
            severity TEXT,
            message TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

# -----------------------------
# DEVICE STORAGE
# -----------------------------
def save_device(ip, mac):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT id, ip FROM devices WHERE mac = ?", (mac,))
    existing = cursor.fetchone()

    if existing:
        old_ip = existing[1]
        cursor.execute("""
            UPDATE devices
            SET ip = ?,
                last_ip = ?,
                is_known = 1,
                last_seen = ?
            WHERE mac = ?
        """, (ip, old_ip, now_utc(), mac))
    else:
        cursor.execute("""
            INSERT INTO devices (ip, mac, last_ip, is_known, reconnect_count, reconnect_timestamps, first_seen, last_seen)
            VALUES (?, ?, ?, 0, 0, '[]', ?, ?)
        """, (ip, mac, ip, now_utc(), now_utc()))

    conn.commit()
    conn.close()

def save_scan_results(devices):
    for device in devices:
        save_device(device["ip"], device["mac"])

def increment_reconnect(mac):
    import json
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT reconnect_count, reconnect_timestamps FROM devices WHERE mac = ?", (mac,))
    row = cursor.fetchone()

    if row:
        count = row[0] + 1
        timestamps = json.loads(row[1])
        timestamps.append(now_utc())
        # Keep only last 20 timestamps
        timestamps = timestamps[-20:]

        cursor.execute("""
            UPDATE devices
            SET reconnect_count = ?,
                reconnect_timestamps = ?
            WHERE mac = ?
        """, (count, json.dumps(timestamps), mac))

    conn.commit()
    conn.close()

def get_device_risk_data(mac):
    import json
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ip, last_ip, is_known, reconnect_count, reconnect_timestamps
        FROM devices WHERE mac = ?
    """, (mac,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    ip, last_ip, is_known, reconnect_count, reconnect_timestamps = row
    timestamps = json.loads(reconnect_timestamps)

    # Count reconnects in last hour
    now = datetime.now(timezone.utc)
    recent_reconnects = sum(
        1 for t in timestamps
        if (now - datetime.strptime(t, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)).seconds <= 3600
    )

    return {
        "ip": ip,
        "last_ip": last_ip,
        "is_known": bool(is_known),
        "reconnect_count": reconnect_count,
        "recent_reconnects": recent_reconnects,
        "active_unusual_hour": is_unusual_hour()
    }

def get_all_devices():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip, mac, first_seen, last_seen
        FROM devices
        ORDER BY last_seen DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_mac_ip_map():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT ip, mac FROM devices")
    rows = cursor.fetchall()
    conn.close()
    return {mac: ip for ip, mac in rows}

# -----------------------------
# DEVICE STATISTICS
# -----------------------------
def get_device_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM devices")
    total = cursor.fetchone()[0]

    # Active = seen in the last 10 minutes
    cursor.execute("""
        SELECT COUNT(*) FROM devices
        WHERE last_seen >= datetime('now', '-10 minutes')
    """)
    active = cursor.fetchone()[0]

    conn.close()
    return {
        "total_devices": total,
        "active_devices": active
    }

# -----------------------------
# ALERT SYSTEM
# -----------------------------
def save_alert(network, alert_type, mac, ip, severity, message):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (network, alert_type, mac, ip, severity, message, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (network, alert_type, mac, ip, severity, message, now_utc()))
    conn.commit()
    conn.close()

def get_recent_alerts(limit=20):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT network, alert_type, mac, ip, severity, message, timestamp
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows
    
def get_scan_history(limit=50):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip, mac, first_seen, last_seen
        FROM devices
        ORDER BY last_seen DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows 

# -----------------------------
# OPTIONAL TEST RUN
# -----------------------------
if __name__ == "__main__":
    create_database()
    print("Database initialized successfully.")
