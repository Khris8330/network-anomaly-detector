from anomaly import detect_threats
from network_utils import get_subnet
import time

def run():
    print("Multi-Network Threat Engine Running...\n")
    while True:
        network = get_subnet()
        if not network:
            print("[WARN] Could not detect network, retrying in 10s...")
            time.sleep(10)
            continue

        new, missing, spoof = detect_threats(network)

        # Only print if something noteworthy happened
        if new or spoof:
            print(f"\n[SCAN] {network}")
        if new:
            print(f"  NEW DEVICES    : {len(new)}")
        if spoof:
            print(f"  SPOOF DETECTED : {len(spoof)}")
        if missing:
            print(f"  MISSING        : {len(missing)}")

        time.sleep(10)

if __name__ == "__main__":
    run()
