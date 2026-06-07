import os

OUI_FILE = "data/oui.txt"
oui_map = {}


def load_oui_database():

    global oui_map

    oui_map = {}

    with open(OUI_FILE, "r", errors="ignore") as f:

        for line in f:

            line = line.strip()

            if "(hex)" in line:

                parts = line.split("(hex)")

                if len(parts) == 2:

                    mac = parts[0].strip().replace("-", ":").upper()
                    vendor = parts[1].strip()

                    prefix = ":".join(mac.split(":")[0:3])

                    oui_map[prefix] = vendor

    print("[OK] Loaded vendors:", len(oui_map))

def normalize_mac(mac):
    return mac.upper().replace("-", ":")


def get_vendor(mac):

    if not oui_map:
        load_oui_database()

    mac = normalize_mac(mac)

    prefix = ":".join(mac.split(":")[0:3])

    return oui_map.get(prefix, "Unknown")
