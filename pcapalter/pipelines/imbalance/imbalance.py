import pandas
from scapy.all import Packet, Ether, Dot1Q, IP, IPv6, ARP, TCP, UDP, ICMP
from ..processor import Processor
from typing import List, Dict, Tuple
import random
from ... import utils
import numpy as np

# Define a type alias for better readability
# Flowkey = (source IP, Destination IP, source port, destination port)
FlowKey = Tuple[str, str, int, int]


class ImbalanceProcessor(Processor):

    # params
    def reset(self, malicious_mutation_percentage=0, mutation_chance=0.1, benign_mutation_percentage=0,
              mal_df: pandas.DataFrame = pandas.DataFrame(), intra_class_mutation_ratio=0) -> None:
        """

        Args:
            malicious_mutation_percentage: Mutation ratio of malicious packets :
                ((-1,0) = removal of packets, (0,1)= mutation of packets)
                -1 remove all malicious packets
                1 multiply all malicious packets
            benign_mutation_percentage: Mutation ratio of malign packets :
                ((-1,0) = removal of packets, (0,1)= mutation of packets)
                -1 remove all benign packets
                1 multiply all benign packets
            mutation_chance: Mutation chance of any flow in mutation list
            mal_df: malicious connections dataframe with attack types
            intra_class_mutation_ratio: Mutation ratio of intra-class activities:
                ((-1,0) = removal ratio of most occurring attacks, (0,1)= mutation ratio of least occurring attacks)

        Returns:
            None

        """

        self.logger.info("Starting Imbalance processor")
        self.packages_removed = 0
        self.packages_added = 0

        self.malicious_mutation_percentage = malicious_mutation_percentage
        self.mutation_chance = mutation_chance

        self.benign_mutation_percentage = benign_mutation_percentage

        self.deletion_mode = False
        self.mutation_mode = False

        # Set the mode
        if (self.malicious_mutation_percentage < 0 or self.benign_mutation_percentage < 0):
            self.deletion_mode = True
        if (self.malicious_mutation_percentage > 0 or self.benign_mutation_percentage > 0):
            self.mutation_mode = True

        self.mutation_time_shift = 30  # minutes

        self.all_flows: set = set()

        # List that contains packet flow data that need to be removed from pcap
        self.removal_list = []    #TODO implement recetly used structure for faster checking when benign is being
                                  # mutated

        # List that contains packet flow data that need to be mutated
        self.mutation_list = []

        # List to keep track of mutated packages with their new timestamp
        self.mutation_csv_list = []

        # Dataframe to keep track of flows of packets that need to be mutated
        self.mutation_flow_dict: Dict[FlowKey, List[Packet]] = {}

        self.logger.info("Mapping connections to events")
        # Malicious dataframe, contains malicious packet information
        malicious_df = mal_df.copy()

        # Flow list of all malicious flows
        self.all_malicious_list = self.df_entry_to_flow_key(malicious_df)

        self.logger.info("Calculating removal/mutation lists")
        if self.malicious_mutation_percentage < 0:
            # Add sample of malicious packet information to the removal dataframe
            removal_df = malicious_df.sample(frac=-1 * self.malicious_mutation_percentage)
            self.removal_list = self.df_entry_to_flow_key(removal_df)
        elif self.malicious_mutation_percentage > 0:
            mutation_df = malicious_df.sample(frac=self.malicious_mutation_percentage)
            self.mutation_list = self.df_entry_to_flow_key(mutation_df)

        if intra_class_mutation_ratio != 0:
            self.logger.info("Choosing intra class mutations")

            # Get all unique attacks
            unique_attack_counts = malicious_df["attack_type"].value_counts().to_dict()
            print("unique attack counts imabalance" ,malicious_df["attack_type"].value_counts())

            # Remove bad-unknown from the dictionary
            del unique_attack_counts["bad-unknown"]

            # Calculate most and least occurring attacks
            top50_attacks, bottom50_attacks = self.attack_breakdown(unique_attack_counts)
            self.logger.debug(f"top50 attacks:  {top50_attacks}")
            self.logger.debug(f"bottom50 attacks: {bottom50_attacks}")

            if 1 >= intra_class_mutation_ratio > 0:  # Mutate from bottom 50 attacks
                self.mutation_mode = True
                # Filter malicious dataframe for bottom 50 attack entries
                filtered_df = malicious_df[malicious_df["attack_type"].isin(bottom50_attacks)]
                # Take random sample of the filtered dataframe
                intra_df = filtered_df.sample(frac=intra_class_mutation_ratio)
                # Take flow keys of the attacks
                intra_list = self.df_entry_to_flow_key(intra_df)

                # Add each flow key to the mutation list if not already in there
                for entry in intra_list:
                    if entry not in self.mutation_list:
                        self.mutation_list.append(entry)

            elif -1 <= intra_class_mutation_ratio < 0:  # Delete from top 50 attacks
                self.deletion_mode = True
                # Filter malicious dataframe for top 50 attack entries
                filtered_df = malicious_df[malicious_df["attack_type"].isin(top50_attacks)]
                # Take random sample of the filtered dataframe
                intra_df = filtered_df.sample(frac=-1 * intra_class_mutation_ratio)
                # Take flow keys rom the attacks
                intra_list = self.df_entry_to_flow_key(intra_df)

                # Add each flow key to the removal list if not already in there
                for entry in intra_list:
                    if entry not in self.removal_list:
                        self.removal_list.append(entry)

            else:
                self.logger.error(
                    f"Mutation ratio is invalid: {intra_class_mutation_ratio} value needs to be between -1 and 1")

        self.logger.debug(f"removal list: {self.removal_list}")
        self.logger.debug(f"removal list length: {len(self.removal_list)}")

        self.logger.debug(f"mutation list: {self.mutation_list}")
        self.logger.debug(f"mutation list length: {len(self.mutation_list)}")

        self.logger.info(f"deletion mode {self.deletion_mode}")
        self.logger.info(f"mutation mode {self.mutation_mode}")

    # Return packet if not chosen to be modified, return empty packet (stripped from payload)
    # if wanted to be removed from pcap
    def _process(self, packet: Packet) -> list[Packet]:

        # Initialise return list
        packets = [packet]

        if IP not in packet or (TCP not in packet and UDP not in packet):
            return packets

        flow_key = self.get_flow_key(packet)

        if self.deletion_mode:  # Check removal df if deletion enabled
            # If deletion chance holds, add benign flow to the deletion list only if it's the beginning of a new  flow
            if self.benign_mutation_percentage < 0:
                if (flow_key not in self.all_flows and flow_key not in self.all_malicious_list and
                        -1.0 * random.random() > self.benign_mutation_percentage):
                    self.logger.debug(f"Adding benign flowkey to deletion list:  {flow_key}")
                    self.removal_list.append(flow_key)

            # If the package is valid, check against all entries in the malicious dataframe whether the packet is
            # in any of their flows
            if flow_key in self.removal_list:
                # Add flow to all flows
                self.all_flows.add(flow_key)
                # Remove packet from return packets
                packets.remove(packet)
                self.packages_removed += 1
                self.logger.debug(f"Removal count: {self.packages_removed}, by: {self.__class__.__name__}")

                return packets

        if self.mutation_mode:  # check if the packet corresponds to any flow that need to be mutated

            # If mutation chance holds, add benign flow to the mutations list only if it's the beginning of a new  flow
            if flow_key not in self.all_flows and random.random() < self.benign_mutation_percentage:
                self.logger.debug(f"Adding benign flowkey to mutation list:  {flow_key}")
                self.mutation_list.append(flow_key)

            if flow_key in self.mutation_list:
                self.logger.debug(f"Packet mutation match found for flow: {flow_key}")
                # add the packet to the flow dictionary
                if flow_key not in self.mutation_flow_dict:
                    self.mutation_flow_dict[flow_key] = []
                self.mutation_flow_dict[flow_key].append(packet)

            packets.extend(self._apply_mutations(packet))

            self.all_flows.add(flow_key)

            return packets

        self.all_flows.add(flow_key)

        return packets

    def _apply_mutations(self, packet) -> list[Packet]:
        """
            Check and apply the mutation of packets in mutation_df
        """
        flow_packets: list[Packet] = []
        for flow_key in self.mutation_flow_dict:
            if self.is_flow_terminated(flow_key):
                self.logger.debug(f"Terminated flow found for flow: {flow_key}")

                if random.random() <= self.mutation_chance:
                    self.logger.debug(f"Mutation chance success, mutating, flowkey:  {flow_key} flow length: "
                                      f"{len(self.mutation_flow_dict[flow_key])}")

                    constant_shift_block = 0
                    # New random port
                    new_ephemeral_port = np.random.randint(49152, 65536)



                    for flow_packet in self.mutation_flow_dict[flow_key]:
                        # a shift block such that we shift the flow packet to the current packet's time and shift after
                        if constant_shift_block == 0:
                            constant_shift_block = packet.time - flow_packet.time
                            # Add the mutated packet to the csv list to be added to the ground truth file afterward
                            self.mutation_csv_list.append((flow_key, constant_shift_block +
                                                           (self.mutation_time_shift * 60)))

                        # shift the time of the packet
                        flow_packet.time += constant_shift_block + (self.mutation_time_shift * 60)

                        # Alter the port to a random ephemeral port
                        if TCP in flow_packet:
                            # old_port = packet[TCP].sport
                            flow_packet[TCP].sport = new_ephemeral_port
                        elif UDP in flow_packet:
                            # old_port = packet[UDP].sport
                            flow_packet[UDP].sport = new_ephemeral_port

                        flow_packets.append(flow_packet)



                        self.packages_added += 1
                        self.logger.debug(f"added count: {self.packages_added}")

                    # Delete the flow from the dictionary such that it is not mutated anymore
                    del self.mutation_flow_dict[flow_key]

                    break

        return flow_packets

    def attack_breakdown(self, unique_attack_counts: Dict) -> (list, list):
        # Sort the items by value in descending order
        sorted_attacks = sorted(unique_attack_counts.items(), key=lambda x: x[1], reverse=True)

        # Calculate the total sum of all values
        total_sum = sum(unique_attack_counts.values())

        # Initialize accumulators
        top_50_percent_sum = 0
        top_50_percent_keys = []
        bottom_50_percent_keys = []

        # Iterate through sorted_attacks to accumulate top 50% of the sum
        for key, value in sorted_attacks:
            if top_50_percent_sum < total_sum / 2:
                top_50_percent_keys.append(key)
                top_50_percent_sum += value
            else:
                bottom_50_percent_keys.append(key)

        return top_50_percent_keys, bottom_50_percent_keys

    def process_label_df(self, labels_df: pandas.DataFrame) -> pandas.DataFrame:
        # filter only the important columns to make the processor faster
        important_labels = ['Timestamp', 'Source IP', 'Destination IP', 'Source Port',
                            'Destination Port', 'Protocol', 'Label', 'Attempted Category']
        labels_df = labels_df[important_labels]

        # Ensure Timestamp column is in datetime format
        self.logger.debug(f"labels df: {labels_df} ")
        label_len = len(labels_df)

        remove_label_count = 0
        self.logger.debug(f"Labels to be removed: {self.removal_list}")
        for tuple in self.removal_list:
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
            # reset label length
            label_len = len(labels_df)

        self.logger.debug(f'Removed label count: {remove_label_count}')

        modified_packets = pandas.DataFrame(columns=labels_df.columns)

        label_add_count = 0
        self.logger.debug(f"Label to be added count {len(self.mutation_csv_list)}: {self.mutation_csv_list}")
        if len(self.mutation_csv_list) > 0:
            labels_df.loc[:, 'Timestamp'] = pandas.to_datetime(labels_df['Timestamp'], format='%Y-%m-%d %H:%M:%S.%f',
                                                           errors='coerce')


            for flow_key, time_delta in self.mutation_csv_list:
                # Convert time_delta to pd.Timedelta if it's an integer
                time_delta = pandas.Timedelta(seconds=float(time_delta))

                mask1 = (labels_df['Source IP'] == flow_key[0]) & \
                       (labels_df['Destination IP'] == flow_key[1]) & \
                       (labels_df['Source Port'] == flow_key[2]) & \
                       (labels_df['Destination Port'] == flow_key[3])

                mask2 = ((labels_df['Source IP'] == flow_key[1]) &
                        (labels_df['Destination IP'] == flow_key[0]) &
                        (labels_df['Source Port'] == flow_key[3]) &
                        (labels_df['Destination Port'] == flow_key[2]))

                mask = mask1 | mask2

                # Select the packets matching the flow key
                matching_packets = labels_df[mask].copy()

                # Count how many packets have been added
                label_add_count += len(matching_packets)

                # Modify the timestamp by adding the time delta
                matching_packets.loc[:, 'Timestamp'] += time_delta

                # Append the modified packets to the new DataFrame
                modified_packets = pandas.concat([modified_packets, matching_packets])

            self.logger.debug(f'Added label count: {label_add_count}')
            # Combine the original DataFrame with the modified packets DataFrame
            labels_df = pandas.concat([labels_df, modified_packets]).reset_index(drop=True)

            # Sort the dataframe by timestamp TODO: use for sorting by timestamp
            # combined_df = combined_df.sort_values(by='Timestamp').reset_index(drop=True)


        return labels_df
