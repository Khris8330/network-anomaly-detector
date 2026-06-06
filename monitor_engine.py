from anomaly import detect_threats
from alert_manager import is_new_alert
import time

INTERVAL = 5


def run_engine():

    print("Starting real threat monitoring engine...\n")

    while True:

        new_devices, missing_devices, ip_spoofing = detect_threats()

        # NEW DEVICE ALERTS
        for d in new_devices:

            alert_id = f"NEW-{d['mac']}"

            if is_new_alert(alert_id):

                print(f"[NEW DEVICE] {d['mac']} | {d['ip']}")

        # MISSING DEVICE ALERTS
        for d in missing_devices:

            alert_id = f"MISSING-{d['mac']}"

            if is_new_alert(alert_id):

                print(f"[MISSING DEVICE] {d['mac']}")

        # SPOOFING ALERTS (HIGH SEVERITY)
        for d in ip_spoofing:

            alert_id = f"SPOOF-{d['mac']}"

            if is_new_alert(alert_id):

                print(f"[⚠ SPOOFING DETECTED] {d['mac']} {d['old_ip']} → {d['new_ip']}")

        if not new_devices and not missing_devices and not ip_spoofing:
            print("No threats detected.")

        time.sleep(INTERVAL)


if __name__ == "__main__":
    run_engine()
