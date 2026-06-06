from scanner import scan_network
from database import get_mac_ip_map, get_all_macs

NETWORK = "10.0.2.0/24"


def detect_threats():

    baseline = get_mac_ip_map()
    baseline_macs = set(baseline.keys())

    current_scan = scan_network(NETWORK)

    current_macs = set()
    current_map = {}

    new_devices = []
    missing_devices = []
    ip_spoofing = []

    # build current state
    for device in current_scan:

        mac = device["mac"]
        ip = device["ip"]

        current_macs.add(mac)
        current_map[mac] = ip

        # NEW DEVICE DETECTION
        if mac not in baseline_macs:

            new_devices.append(device)

        # IP SPOOF DETECTION
        if mac in baseline:

            if baseline[mac] != ip:

                ip_spoofing.append({
                    "mac": mac,
                    "old_ip": baseline[mac],
                    "new_ip": ip
                })

    # MISSING DEVICE DETECTION
    for mac in baseline_macs:

        if mac not in current_macs:

            missing_devices.append({
                "mac": mac,
                "ip": baseline[mac]
            })

    return new_devices, missing_devices, ip_spoofing
