import ipaddress

import numpy

def is_same_ip_type(ip1: str, ip2: str) -> bool:
    ip1 = ipaddress.IPv4Address(ip1)
    ip2 = ipaddress.IPv4Address(ip2)

    if ip1.is_reserved != ip2.is_reserved:
        return False

    if ip1.is_private != ip2.is_private:
        return False

    if ip1.is_global != ip2.is_global:
        return False

    if ip1.is_unspecified != ip2.is_unspecified:
        return False

    return True

def get_random_new_ipv4( original_ip: str | None = None) -> str:
    if original_ip is None:
        return ".".join([
            str(x)
            for x in numpy.random.randint(0, 256, (4,))
        ])

    # If an original IP address was provided, make sure they are of the same type
    new_ip = None
    while new_ip is None or not is_same_ip_type(original_ip, new_ip):
        new_ip = get_random_new_ipv4()

    return new_ip