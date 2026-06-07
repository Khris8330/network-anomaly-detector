import os
import sys

if os.geteuid() == 0:
    print("\n[ERROR] Do NOT run this project with sudo.")
    print("It will break database permissions and cause system errors.\n")
    sys.exit(1)

from scanner import scan_network
from database import get_mac_ip_map, save_alert

NETWORK = "10.0.2.0/24"


def detect_threats(network=NETWORK):

    baseline = get_mac_ip_map()
    current_scan = scan_network(network)

    baseline_macs = set(baseline.keys())
    current_macs = set()

    new_devices = []
    missing_devices = []
    ip_spoofing = []

    for device in current_scan:

        mac = device["mac"]
        ip = device["ip"]

        current_macs.add(mac)

        # NEW DEVICE
        if mac not in baseline_macs:

            new_devices.append(device)

            save_alert(
                network,
                "NEW_DEVICE",
                mac,
                ip,
                "MEDIUM",
                f"New device detected: {mac}"
            )

        # SPOOF DETECTION
        if mac in baseline and baseline[mac] != ip:

            ip_spoofing.append({
                "mac": mac,
                "old_ip": baseline[mac],
                "new_ip": ip
            })

            save_alert(
                network,
                "IP_SPOOF",
                mac,
                ip,
                "HIGH",
                f"IP changed from {baseline[mac]} to {ip}"
            )

    # MISSING DEVICES
    for mac in baseline_macs:

        if mac not in current_macs:

            missing_devices.append({
                "mac": mac,
                "ip": baseline[mac]
            })

            save_alert(
                network,
                "MISSING_DEVICE",
                mac,
                baseline[mac],
                "LOW",
                f"Device disappeared: {mac}"
            )

    return new_devices, missing_devices, ip_spoofing
