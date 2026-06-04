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
