import json
import os

ALERT_FILE = "state/alerts.json"


def load_alerts():

    if not os.path.exists(ALERT_FILE):
        return {}

    with open(ALERT_FILE, "r") as f:
        return json.load(f)


def save_alerts(alerts):

    with open(ALERT_FILE, "w") as f:
        json.dump(alerts, f, indent=4)


def is_new_alert(alert_id):

    alerts = load_alerts()

    if alert_id in alerts:
        return False

    alerts[alert_id] = True
    save_alerts(alerts)

    return True
