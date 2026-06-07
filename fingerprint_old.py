from manuf import MacParser

parser = MacParser()


def get_vendor(mac):
    vendor = parser.get_manuf(mac)
    return vendor if vendor else "Unknown"
