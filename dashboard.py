import threading
from flask import Flask, render_template
from database import (
    get_all_devices,
    get_device_stats,
    get_recent_alerts,
    get_device_risk_data,
    get_scan_history,
    create_database
)
from fingerprint import get_vendor
from monitor_engine import run as start_monitor

app = Flask(__name__)

def is_randomised_mac(mac):
    first_octet = int(mac.split(":")[0], 16)
    return bool(first_octet & 0x02)

def calculate_risk(mac, vendor):
    risk_factors = []
    level = "NONE"

    data = get_device_risk_data(mac)
    if not data:
        return "NONE", []

    is_known = data["is_known"]
    ip = data["ip"]
    last_ip = data["last_ip"]
    recent_reconnects = data["recent_reconnects"]
    unusual_hour = data["active_unusual_hour"]
    is_unknown_vendor = vendor == "Unknown"
    randomised = is_randomised_mac(mac)

    # ── CRITICAL ─────────────────────────────────────────────
    high_flag_count = sum([
        ip != last_ip,
        randomised,
        recent_reconnects >= 7,
        (not is_known and is_unknown_vendor and unusual_hour)
    ])
    if high_flag_count >= 2:
        level = "CRITICAL"
        risk_factors.append("Multiple high-risk flags detected simultaneously")
        return level, risk_factors

    # ── HIGH ─────────────────────────────────────────────────
    if ip != last_ip and last_ip is not None and ip != last_ip:
        level = "HIGH"
        risk_factors.append(f"IP changed on same MAC: {last_ip} → {ip}")

    if randomised:
        level = "HIGH"
        risk_factors.append("Randomised/spoofed MAC address detected")

    if recent_reconnects >= 7:
        level = "HIGH"
        risk_factors.append(f"Frequent reconnects: {recent_reconnects} times in last hour")

    if level == "HIGH":
        return level, risk_factors

    # ── MEDIUM ────────────────────────────────────────────────
    if recent_reconnects >= 5:
        level = "MEDIUM"
        risk_factors.append(f"Reconnected {recent_reconnects} times in last hour")

    if unusual_hour:
        level = "MEDIUM"
        risk_factors.append("Device active during unusual hours (2AM–5AM)")

    if not is_known and is_unknown_vendor:
        level = "MEDIUM"
        risk_factors.append("New device with unknown vendor")

    if level == "MEDIUM":
        return level, risk_factors

    # ── LOW ───────────────────────────────────────────────────
    if not is_known and not is_unknown_vendor:
        level = "LOW"
        risk_factors.append("New device, vendor is known")

    if is_known and is_unknown_vendor:
        level = "LOW"
        risk_factors.append("Known device but vendor is unrecognised")

    if level == "LOW":
        return level, risk_factors

    # ── NONE ──────────────────────────────────────────────────
    if is_known and not is_unknown_vendor:
        level = "NONE"
        risk_factors.append("Known device with recognised vendor")

    return level, risk_factors


@app.route("/")
def home():
    devices = get_all_devices()
    stats = get_device_stats()
    alerts = get_recent_alerts()
    history = get_scan_history()

    enriched_devices = []
    for d in devices:
        ip, mac, first_seen, last_seen = d
        vendor = get_vendor(mac)
        risk_level, risk_reasons = calculate_risk(mac, vendor)
        enriched_devices.append({
            "ip": ip,
            "mac": mac,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "vendor": vendor,
            "risk": risk_level,
            "risk_reasons": risk_reasons
        })

    enriched_history = []
    for d in history:
        ip, mac, first_seen, last_seen = d
        vendor = get_vendor(mac)
        risk_level, risk_reasons = calculate_risk(mac, vendor)
        enriched_history.append({
            "ip": ip,
            "mac": mac,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "vendor": vendor,
            "risk": risk_level,
            "risk_reasons": risk_reasons
        })

    return render_template(
        "index.html",
        devices=enriched_devices,
        stats=stats,
        alerts=alerts,
        history=enriched_history
    )


if __name__ == "__main__":
    create_database()

    monitor_thread = threading.Thread(target=start_monitor, daemon=True)
    monitor_thread.start()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
