import time
from anomaly import detect_anomalies

INTERVAL = 10  # seconds


def run_monitor():
    print("Starting live monitoring...\n")

    while True:

        new, missing, changes = detect_anomalies()

        if new or missing or changes:
            print("\n=== ALERT DETECTED ===")

        if new:
            print("\nNEW DEVICES:")
            for d in new:
                print(d)

        if missing:
            print("\nMISSING DEVICES:")
            for d in missing:
                print(d)

        if changes:
            print("\nIP CHANGES:")
            for c in changes:
                print(c)

        time.sleep(INTERVAL)


if __name__ == "__main__":
    run_monitor()

from datetime import datetime


def log_alert(message):
    with open("logs/alerts.log", "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")
