import sqlite3
from pathlib import Path

DB_PATH = "data/network.db"


def create_database():
    """
    Create database and tables if they don't exist.
    """

    Path("data").mkdir(exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        mac TEXT NOT NULL UNIQUE,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

def save_device(ip, mac):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id FROM devices
    WHERE mac = ?
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

def save_scan_results(devices):

    for device in devices:
        save_device(
            device["ip"],
            device["mac"]
        )

def get_all_devices():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT ip, mac, first_seen, last_seen
    FROM devices
    """)

    results = cursor.fetchall()

    conn.close()

    return results
      
   
if __name__ == "__main__":

    create_database()

    sample_devices = [
        {
            "ip": "192.168.1.10",
            "mac": "AA:BB:CC:DD:EE:FF"
        },
        {
            "ip": "192.168.1.20",
            "mac": "11:22:33:44:55:66"
        }
    ]

    save_scan_results(sample_devices)

    devices = get_all_devices()

    for device in devices:
        print(device)

def get_known_devices():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT ip, mac
    FROM devices
    """)

    devices = cursor.fetchall()

    conn.close()

    return devices
