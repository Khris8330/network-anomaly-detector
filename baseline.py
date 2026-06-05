from scanner import scan_network
from database import (
    create_database,
    save_scan_results
)

NETWORK = "10.0.2.0/24"

create_database()

devices = scan_network(NETWORK)

print(devices)

save_scan_results(devices)

print(f"{len(devices)} devices saved.")

def get_devices_dict():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT ip, mac
    FROM devices
    """)

    rows = cursor.fetchall()

    conn.close()

    return {
        mac: ip
        for ip, mac in rows
    }
