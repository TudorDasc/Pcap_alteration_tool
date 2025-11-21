import datetime
import math
import random
import pandas as pd
from typing import List, Dict, Tuple

import numpy as np
from scapy.all import Packet, IP, TCP, UDP, IPv6
from ..processor import Processor
from ... import utils


FlowKey = Tuple[str, str, int, int]
class EvolutionProcessor(Processor):
    def reset(self, conn_path=None, n_hosts=1) -> None:
        self.n_hosts = n_hosts
        self.dice_roll = random.randint(0, 1)

        # List that contains packet flow data that need to be removed from pcap
        self.removal_list = []
        self.removed_csv = []
        self.removal_count = 0
        # Connections from the conn.log
        conn_df = utils.read_input.read_zeek(conn_path)
        self.timestamp = self.get_random_ts(conn_df)
        self.timestamp = self.timestamp.replace(microsecond=0)
        conn_df_filtered = self.filter_conn_by_ts(conn_df)

        # Create a list of flow tuple
        self.conn_list = self.df_entry_to_flow_key(conn_df)
        self.conn_filtered_list = self.df_entry_to_flow_key(conn_df_filtered)

        # Create a list of all IP addresses
        self.ip_addresses = self.get_unique_hosts(conn_df)
        self.logger.debug(f"ip_adresses (Len {len(self.ip_addresses)}): {self.ip_addresses}")


        # If n_hosts is greater than one then take percentage of the whole ip address range
        if self.n_hosts != 1:
            self.n_hosts = math.floor(self.n_hosts * 0.01 * len(self.ip_addresses))
        # Get flow from IP address to mutate
        self.logger.debug(f"n_hosts: {self.n_hosts}")
        self.ip_removed = random.sample(self.ip_addresses, self.n_hosts)
        self.logger.debug(f"ip_removed: {self.ip_removed}")
        # Get packets flow to mutate ba§sed on the ip address
        for ip in self.ip_removed:
            for flow_key in self.conn_filtered_list:
                if ip in flow_key:
                    self.removal_list.append(flow_key)

        self.logger.debug(f"Tuples to be removed len: {len(self.removal_list)}")

    def _process(self, packet: Packet) -> list[Packet]:
        # Initialise return list
        packages = [packet]
        if IP not in packet or (TCP not in packet and UDP not in packet):
            return packages

        flow_key = self.get_flow_key(packet)

        # check to the dice roll to see if we delete before or after the timestamp
        if flow_key in self.removal_list:
            # self.logger.debug(f"Flowkey match found for: {flow_key} ")
            if self.dice_roll and datetime.datetime.fromtimestamp(int(packet.time)) <= self.timestamp:
                self.removed_csv.append(flow_key)
                packages.remove(packet)
                # self.removal_count += 1
                # self.logger.debug(f"Removed packet, removal count: {self.removal_count}")

            elif not self.dice_roll and datetime.datetime.fromtimestamp(int(packet.time)) >= self.timestamp:
                self.removed_csv.append(flow_key)
                packages.remove(packet)
                # self.removal_count += 1
                # self.logger.debug(f"Removed packet, removal count: {self.removal_count}")

        return packages

    def _mutate_state(self) -> None:
        pass

    def _apply_mutations(self, packet: Packet) -> Packet:
        return packet

    def process_label_df(self, labels_df: pd.DataFrame) -> pd.DataFrame:
        # filter only the important columns to make the processor faster
        important_labels = ['Timestamp', 'Source IP', 'Destination IP', 'Source Port',
                            'Destination Port', 'Protocol', 'Label', 'Attempted Category']
        labels_df = labels_df[important_labels]
        label_len = len(labels_df)
        remove_label_count = 0

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
        return labels_df

    def df_entry_to_flow_key(self, df) -> list[FlowKey]:
        flowkey_list = []
        for index, entry in df.iterrows():
            src_ip = entry['id.orig_h']
            dst_ip = entry['id.resp_h']
            src_port = entry['id.orig_p']
            dst_port = entry['id.resp_p']

            flowkey_list.append((src_ip, dst_ip, src_port, dst_port))

        return flowkey_list

    def get_unique_hosts(self, df) -> list[any]:
        hosts: dict = {}
        hosts_less_ts: list = []
        final_hosts: list =[]

        # create dictionary containing IP as a key and all the timestamps as values
        for index, entry in df.iterrows():
            if entry["id.orig_h"] not in hosts.keys():
                hosts[entry["id.orig_h"]] = [index]
            elif entry["id.resp_h"] not in hosts.keys():
                hosts[entry["id.resp_h"]] = [index]
            elif entry["id.orig_h"] in hosts.keys():
                hosts[entry["id.orig_h"]].append(index)
            elif entry["id.resp_h"] in hosts.keys():
                hosts[entry["id.resp_h"]].append(index)

        # iterate through all IPs and check if that IP has connections before and after timestamp
        for key in hosts.keys():
            for value in hosts[key]:
                if value < self.timestamp and key not in hosts_less_ts:
                    hosts_less_ts.append(key)
                if value > self.timestamp and key in hosts_less_ts and key not in final_hosts:
                    final_hosts.append(key)
        # check to see if we have enough hosts selected, if not run this method again
        if len(final_hosts) < self.n_hosts:
            self.timestamp = self.get_random_ts(df)
            self.get_unique_hosts(df)

        return final_hosts

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

    def get_random_ts(self, conn_df):
        '''

        Args:
            conn_df: dataframe containing all connections from conn.log

        Returns:
            rand_time: random timestamp from the dataset
        '''
        timestamps: list = conn_df.index
        start = math.floor(len(timestamps)/4)
        end = math.ceil(len(timestamps)*3/4)
        rand_time = random.choice(timestamps[start:end])
        self.logger.debug(f"New random time: {rand_time}")
        return rand_time

    def filter_conn_by_ts(self, conn_df):
        # filter connection dataframe to take connections only before./after timestamp
        if self.dice_roll:
            conn_df = conn_df[conn_df.index < self.timestamp]
            self.logger.debug(f"Taking connections before the timestamp = {self.timestamp}")
        else:
            conn_df = conn_df[conn_df.index > self.timestamp]
            self.logger.debug(f"Taking connections after the timestamp = {self.timestamp}")

        return conn_df
