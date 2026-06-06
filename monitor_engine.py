from anomaly import detect_threats
import time

NETWORKS = [
    "10.0.2.0/24",
    "192.168.1.0/24"
]


def run():

    print("Multi-Network Threat Engine Running...\n")

    while True:

        for net in NETWORKS:

            new, missing, spoof = detect_threats(net)

            print(f"\n[SCAN] {net}")

            if new:
                print("NEW:", len(new))

            if missing:
                print("MISSING:", len(missing))

            if spoof:
                print("SPOOF:", len(spoof))

        time.sleep(10)


if __name__ == "__main__":
    run()
