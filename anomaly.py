from scanner import scan_network
from database import get_mac_ip_map, save_alert, save_scan_results, increment_reconnect


def detect_threats(network):

    baseline = get_mac_ip_map()
    current_scan = scan_network(network)

    # Save scan results so devices are recorded/updated in the database
    save_scan_results(current_scan)

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

        # SPOOF DETECTION - only flag if on same subnet
        elif mac in baseline and baseline[mac] != ip:
            old_network = ".".join(baseline[mac].split(".")[:3])
            new_network = ".".join(ip.split(".")[:3])

            if old_network == new_network:
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

    # MISSING DEVICES + RECONNECT TRACKING
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
        else:
            # Device was previously known and is still present — track reconnect
            if mac in baseline_macs:
                increment_reconnect(mac)

    return new_devices, missing_devices, ip_spoofing
