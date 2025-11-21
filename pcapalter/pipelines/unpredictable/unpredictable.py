from typing import List, Dict, Tuple

import numpy as np
from scapy.all import Packet, IP, TCP, UDP, IPv6
from ..processor import Processor
from ... import utils
import pandas as pd

FlowKey = Tuple[str, str, int, int]
class UnpredictableProcessor(Processor):
    def reset(self, mutation_chance=0.1, conn_path=None) -> None:
        self.logger.info("Starting Unpredictability Processor")
        self.mutation_chance = mutation_chance

        # List that contains packet flow data that need to be removed from pcap
        self.removal_list = []
        self.removed_csv = []

        # List of already removed ip addresses
        self.removed_ip = []
        self.removed_flow = []

        # List of IP that will be mutated/deleted
        self.ip_mutation = []

        # Connections from the conn.log
        conn_df = utils.read_input.read_zeek(conn_path)

        # Create a list of flow tuple
        self.conn_list = self.df_entry_to_flow_key(conn_df)
        # Create a list of all IP addresses
        self.ip_addresses = self.get_unique_hosts(conn_df)

        # Get flow from IP address to mutate
        for i in range(len(self.ip_addresses)):
            mutate_bool = np.random.choice([True, False], p=[self.mutation_chance, 1 - self.mutation_chance])
            if mutate_bool:
                self.ip_mutation.append(self.ip_addresses[i])

        self.logger.debug(f"Number of ip_addresses to be deleted: {len(self.ip_mutation)}")

        # Get packets flow to mutate based on the ip address
        for ip in self.ip_mutation:
            for conn_tuple in self.conn_list:
                if ip in conn_tuple:
                    self.removal_list.append(conn_tuple)

        # self.logger.debug(f"Tuples to be removed: {self.removal_list}")


    def _process(self, packet: Packet) -> list[Packet]:
        # Initialise return list
        packages = [packet]

        # check to see if the packet contains the needed information
        if IP not in packet or (TCP not in packet and UDP not in packet):
            return packages

        # take flow key of the packet
        flow_key = self.get_flow_key(packet)

        # remove the packet from the pcap
        if flow_key in self.removal_list:
            for ip in flow_key:
                # if the IP was deleted add it do the dictionary to be removed for next batch
                if ip in self.ip_mutation and ip not in self.removed_ip:
                    self.removed_ip.append(ip)
            if flow_key not in self.removed_flow:
                self.removed_flow.append(flow_key)
                self.removed_csv.append(flow_key)
            # Remove packet from return packages
            packages.remove(packet)
            return packages

        return packages

    def process_batch(self, packets: list[Packet]) -> list[Packet]:
        processed_packets: list[Packet] = []

        # if IP was already deleted from the previous batch remove it from the possible IP range
        for ip in self.removed_ip:
            if ip in self.ip_mutation:
                self.ip_mutation.remove(ip)

        self.logger.debug(f"New number of ip_addresses to be deleted: {len(self.ip_mutation)}")

        # remove the flow key containing IP that was previously deleted
        for flow in self.removed_flow:
            if flow in self.removal_list:
                self.removal_list.remove(flow)

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

    def _apply_mutations(self, packet: Packet) -> Packet:
        pass

    def process_label_df(self, labels_df: pd.DataFrame) -> pd.DataFrame:
        # filter only the important columns to make the processor faster
        important_labels = ['Timestamp', 'Source IP', 'Destination IP', 'Source Port',
                            'Destination Port', 'Protocol', 'Label', 'Attempted Category']
        labels_df = labels_df[important_labels]
        label_len = len(labels_df)

        remove_label_count = 0
        self.logger.debug(f"Labels to be removed: {self.removal_list}")


        for tuple in self.removed_csv:
            # create mask to choose the connections we need to remove
            mask1 = ((labels_df['Source IP'] == tuple[0]) &
                     (labels_df['Destination IP'] == tuple[1]) &
                     (labels_df['Source Port'] == tuple[2]) &
                     (labels_df['Destination Port'] == tuple[3]))

            mask2 = ((labels_df['Source IP'] == tuple[1]) &
                     (labels_df['Destination IP'] == tuple[0]) &
                     (labels_df['Source Port'] == tuple[3]) &
                     (labels_df['Destination Port'] == tuple[2]))

            mask = mask1 | mask2

            # select the connection that are not in mask
            labels_df = labels_df[~mask]

            # Get removed label count
            remove_label_count += label_len - len(labels_df)
            label_len = len(labels_df)
            # reset label length

        self.logger.debug(f'Removed label count: {remove_label_count}')

        return labels_df

    def df_entry_to_flow_key(self, df) -> list[FlowKey]:
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

    def get_unique_hosts(self, df) -> list[any]:
        '''

        Args:
            df: dataframe containing all the connections from conn.log

        Returns:
            hosts: list of all IPs that are present in the conn.log
        '''
        hosts: list = []

        for i in df["id.orig_h"]:
            if i not in hosts:
                hosts.append(i)

        for j in df["id.resp_h"]:
            if j not in hosts:
                hosts.append(j)

        return hosts

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
