import argparse
import os

from scanner import scan_network
from database import (
    create_database,
    save_scan_results
)
from network_utils import get_subnet


parser = argparse.ArgumentParser()

parser.add_argument(
    "--rebuild",
    action="store_true",
    help="Delete existing baseline and create a new one"
)

args = parser.parse_args()


if args.rebuild:

    if os.path.exists("data/network.db"):

        os.remove("data/network.db")

        print("Old baseline removed.")


NETWORK = get_subnet()

print(f"Scanning network: {NETWORK}")

create_database()

devices = scan_network(NETWORK)

print("\nDevices Found:")
print(devices)

save_scan_results(devices)

print(f"\n{len(devices)} devices saved.")
