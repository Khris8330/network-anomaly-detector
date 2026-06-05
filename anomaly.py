from scanner import scan_network
from database import get_devices_dict
from fingerprint import get_vendor

from network_utils import get_subnet

NETWORK = get_subnet()


def detect_anomalies():

    known_devices = get_devices_dict()

    current_scan = scan_network(NETWORK)

    current_devices = {
        device["mac"]: device["ip"]
        for device in current_scan
    }

    new_devices = []
    missing_devices = []
    ip_changes = []

    # Detect new devices

    for mac, ip in current_devices.items():

        if mac not in known_devices:

            new_devices.append({
                "mac": mac,
                "ip": ip
            })

    # Detect missing devices

    for mac, ip in known_devices.items():

        if mac not in current_devices:

            missing_devices.append({
                "mac": mac,
                "ip": ip
            })

    # Detect IP changes

    for mac in current_devices:

        if mac in known_devices:

            old_ip = known_devices[mac]
            new_ip = current_devices[mac]

            if old_ip != new_ip:

                ip_changes.append({
                    "mac": mac,
                    "old_ip": old_ip,
                    "new_ip": new_ip
                })

    return new_devices, missing_devices, ip_changes


if __name__ == "__main__":

    new_devices, missing_devices, ip_changes = detect_anomalies()

    print("\nANOMALY REPORT")
    print("=" * 50)

    if new_devices:

        print("\n[NEW DEVICES]")

        for device in new_devices:

            print(device)

    if missing_devices:

        print("\n[MISSING DEVICES]")

        for device in missing_devices:

            print(device)

    if ip_changes:

        print("\n[IP CHANGES]")

        for change in ip_changes:

            print(change)

    if (
        not new_devices
        and not missing_devices
        and not ip_changes
    ):
        print("No anomalies detected.")

from risk_engine import calculate_risk
from fingerprint import get_vendor
