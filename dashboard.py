from flask import Flask, render_template

from database import (
    get_all_devices,
    get_device_stats,
    get_recent_devices
)

from fingerprint import get_vendor

app = Flask(__name__)


def calculate_risk(mac):

    mac_lower = mac.lower()

    if mac_lower.startswith("aa"):
        return "HIGH"
    elif mac_lower.startswith("11"):
        return "MEDIUM"
    else:
        return "LOW"


@app.route("/")
def home():

    devices = get_all_devices()
    stats = get_device_stats()
    alerts = get_recent_devices()

    enriched_devices = []

    for d in devices:

        ip, mac, first_seen, last_seen = d

        enriched_devices.append({
            "ip": ip,
            "mac": mac,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "vendor": get_vendor(mac),
            "risk": calculate_risk(mac)
        })

    return render_template(
        "index.html",
        devices=enriched_devices,
        stats=stats,
        alerts=alerts
    )


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
