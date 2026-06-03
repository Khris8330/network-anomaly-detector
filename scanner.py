from scapy.all import ARP, Ether, srp


def scan_network(network):
    """
    Scan a network range and return discovered devices.
    """

    arp_request = ARP(pdst=network)

    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = broadcast / arp_request

    answered = srp(packet, timeout=2, verbose=False)[0]

    devices = []

    for sent, received in answered:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices


def display_results(devices):

    print("\nDiscovered Devices")
    print("-" * 50)
    print(f"{'IP Address':<20}{'MAC Address'}")
    print("-" * 50)

    for device in devices:
        print(f"{device['ip']:<20}{device['mac']}")


if __name__ == "__main__":

    network = input(
        "Enter network range (example 192.168.1.0/24): "
    )

    results = scan_network(network)

    display_results(results)
