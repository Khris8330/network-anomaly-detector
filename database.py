import sqlite3
from pathlib import Path
import os

def fix_permissions():

    if os.path.exists("data/network.db"):
        os.chmod("data/network.db", 0o664)

    if os.path.exists("data"):
        os.chmod("data", 0o775)

DB_PATH = "data/network.db"


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

    import os
    print("[DB PATH]", os.path.abspath(DB_PATH))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT id FROM devices WHERE mac = ?
    """, (mac,))

    existing = cursor.fetchone()

    if existing:

        cursor.execute("""
        UPDATE devices
        SET ip = ?,
            last_seen = CURRENT_TIMESTAMP
        WHERE mac = ?
        """, (ip, mac))

    else:

        cursor.execute("""
        INSERT INTO devices (ip, mac)
        VALUES (?, ?)
        """, (ip, mac))

    conn.commit()
    conn.close()
    
    print("[DB WRITE] done")


def save_scan_results(devices):

    for device in devices:
        save_device(device["ip"], device["mac"])


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

    cursor.execute("""
    SELECT ip, mac FROM devices
    """)

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

    conn.close()

    return {
        "total_devices": total
    }


# -----------------------------
# ALERT SYSTEM (NEW)
# -----------------------------
def save_alert(network, alert_type, mac, ip, severity, message):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO alerts (network, alert_type, mac, ip, severity, message)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (network, alert_type, mac, ip, severity, message))

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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data/network.db")

# -----------------------------
# OPTIONAL TEST RUN
# -----------------------------
if __name__ == "__main__":

    create_database()

    print("Database initialized successfully.")
