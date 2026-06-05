import socket
import ipaddress


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def get_subnet():
    ip = get_local_ip()
    network = ipaddress.IPv4Network(ip + "/24", strict=False)
    return str(network)
