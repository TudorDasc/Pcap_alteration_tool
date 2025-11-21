from abc import abstractmethod
import pandas
from scapy.all import Packet, Ether, Dot1Q, IP, IPv6, ARP, TCP, UDP, ICMP
from .. import utils
from typing import List, Dict, Tuple

# Define a type alias for better readability
# Flowkey = (source IP, Destination IP, source port, destination port)
FlowKey = Tuple[str, str, int, int]

class Processor:
    def __init__(self, *args, **kwargs) -> None:

        self.logger = utils.logger
        self.total_processed_packets = 0
        self.reset(*args, **kwargs)

    @abstractmethod
    def reset(self, *args, **kwargs) -> None:
        """Resets the state of the processors in the pipeline
        """
        pass

    @abstractmethod
    def _process(self, packet: Packet) -> Packet:
        """Moves to the next state of the processor based on the input packet.
        Applies transformations to the input packet and outputs altered packet

        Args:
            packet (Packet): The packet to be processed

        Returns:
            Packet: The altered packet
        """
        pass

    def process_batch(self, packets: list[Packet]) -> list[Packet]:
        """Moves to the next state of the processor based on the input packets.
        Applies transformations to the input packets and outputs altered packets

        Args:
            packets (Packet): The packets to be processed

        Returns:
            Packet: The altered packets
        """
        len_packets = len(packets)
        processed_packets: list[Packet] = []
        for packet in packets:
            processed = self._process(packet)
            if isinstance(processed, list):
                processed_packets.extend(processed)
            else:
                processed_packets.append(processed)
        self.total_processed_packets += len_packets
        self.logger.debug(f"Returned: {len(processed_packets)}/{len_packets}, "
                          f"by: {self.__class__.__name__}, total: {self.total_processed_packets}")
        if len(processed_packets) < len_packets:
            self.logger.debug(f"Removed packet count: {len_packets - len(processed_packets) }")
        elif len(processed_packets) > len_packets:
            self.logger.debug(f"Added packet count: {len(processed_packets) - len_packets }")

        return processed_packets

    @abstractmethod
    def process_label_df(self, labels_df: pandas.DataFrame) -> pandas.DataFrame:
        """Introduces additional labellings in the DataFrame that are consistent with changes made according to the
        current state of the processor.

        Args:
            labels_df (DataFrame): DataFrame containing labels

        Returns:
            labels_df (DataFrame): DataFrame containing labels and additional labels that may have been introduced
            according to the state of the processor.
        """
        pass


    def is_flow_terminated(self, flow_key: FlowKey) -> bool:
        """Check if the given TCP flow is terminated."""
        packets = self.mutation_flow_dict.get(flow_key, [])
        for packet in packets:
            if TCP in packet:
                if packet[TCP].flags.F or packet[TCP].flags.R:
                    return True
        return False

        # dataframe to list of flowkey

    def df_entry_to_flow_key(self, df) -> list[FlowKey]:
        """
        Given a dataframe with packets, returns the list of all flowkeys associated with the dataframe
        """
        flowkey_list = []
        for index, entry in df.iterrows():

            src_ip = entry['id.orig_h']
            dst_ip = entry['id.resp_h']
            src_port = entry['id.orig_p']
            dst_port = entry['id.resp_p']

            # Normalize the flow key to handle bidirectional flows
            if (src_ip, src_port) < (dst_ip, dst_port):
                flowkey_list.append((src_ip, dst_ip, src_port, dst_port))
            else:
                flowkey_list.append((dst_ip, src_ip, dst_port, src_port))

        return flowkey_list

    def get_flow_key(self, packet: Packet) -> FlowKey:
        """Generate a normalized flow key for a given packet."""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            raise ValueError("Packet is neither IPv4 nor IPv6")

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            raise ValueError("Packet is neither TCP nor UDP")

        # Normalize the flow key to handle bidirectional flows
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port)
        else:
            return (dst_ip, src_ip, dst_port, src_port)
