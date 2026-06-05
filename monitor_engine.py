import time
from datetime import datetime

from anomaly import detect_anomalies
from alert_manager import is_new_alert

INTERVAL = 5


def log_event(message):

    with open("logs/security.log", "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")


def run_monitor():

    print("Starting real-time network monitoring...\n")

    while True:

        new_devices, missing_devices, ip_changes = detect_anomalies()

        # NEW DEVICES
        for device in new_devices:

            alert_id = f"NEW-{device['mac']}"

            if is_new_alert(alert_id):

                msg = (
                    f"[NEW DEVICE] "
                    f"IP={device['ip']} "
                    f"MAC={device['mac']}"
                )

                print(msg)
                log_event(msg)

        # MISSING DEVICES
        for device in missing_devices:

            alert_id = f"MISSING-{device['mac']}"

            if is_new_alert(alert_id):

                msg = (
                    f"[MISSING DEVICE] "
                    f"IP={device['ip']} "
                    f"MAC={device['mac']}"
                )

                print(msg)
                log_event(msg)

        # IP CHANGES
        for change in ip_changes:

            alert_id = (
                f"IPCHANGE-"
                f"{change['mac']}-"
                f"{change['new_ip']}"
            )

            if is_new_alert(alert_id):

                msg = (
                    f"[IP CHANGE] "
                    f"MAC={change['mac']} "
                    f"OLD={change['old_ip']} "
                    f"NEW={change['new_ip']}"
                )

                print(msg)
                log_event(msg)

        if (
            not new_devices
            and not missing_devices
            and not ip_changes
        ):
            print("No changes detected.")

        time.sleep(INTERVAL)


if __name__ == "__main__":
    run_monitor()
