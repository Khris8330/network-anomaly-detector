from scanner import scan_network
from database import get_known_devices

NETWORK = "10.0.2.0/24"


def detect_new_devices():

    current_devices = scan_network(NETWORK)

    known_devices = get_known_devices()

    known_macs = {
        device[1]
        for device in known_devices
    }

    new_devices = []

    for device in current_devices:

        if device["mac"] not in known_macs:

            new_devices.append(device)

    return new_devices


if __name__ == "__main__":

    new_devices = detect_new_devices()

    if not new_devices:

        print("No new devices found.")

    else:

        print("\nNEW DEVICES DETECTED\n")

        for device in new_devices:

            print(device)
