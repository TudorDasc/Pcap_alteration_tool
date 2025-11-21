from scapy.all import Packet, Ether, IP


def get_packet_with_correct_ip_checksum(packet: Packet) -> Packet:
    packet_copy = packet.copy()
    # Delete checksums
    del packet_copy[IP].chksum
    # Recompute checksums
    packet_copy = Ether(bytes(packet_copy))

    # Apply correct checksum to original packet
    packet[IP].chksum = packet_copy[IP].chksum

    return packet


def has_correct_ip_checksum(packet: Packet):
    # Create a dummy packet with correct checksum
    packet_copy = get_packet_with_correct_ip_checksum(packet)

    if packet[IP].chksum == packet_copy[IP].chksum:
        return True

    return False
