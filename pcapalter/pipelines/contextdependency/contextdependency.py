from collections import OrderedDict
import pandas
from scapy.all import Packet, IP, TCP, UDP, IPv6
from ..processor import Processor
from typing import List, Dict, Tuple
import random
from ... import utils

FlowKey = Tuple[str, str, int, int]

class ContextDependencyProcessor(Processor):

    def reset(self, mal_df: pandas.DataFrame = pandas.DataFrame(),
              context_dependency_ratio=-0.3) -> None:
        """

        Args:
            mal_df: malicious connections dataframe with attack types
            context_dependency_ratio: Mutation ratio of context dependency activities:
                ((-1,0) = removal context dependent attacks, (0,1)= deletion of context independent attacks)

        Returns:
            None

        """

        self.logger.info("Starting Context Dependency processor")
        self.packages_removed = 0

        self.all_flows: set = set()

        # List that contains packet flow data that need to be removed from pcap
        self.removal_list = []

        self.logger.info("Mapping connections to events")
        # Malicious dataframe, contains malicious packet information
        malicious_df = mal_df

        if True:
            # Get all unique attacks
            unique_technique_counts = malicious_df["attack_technique"].value_counts().to_dict()
            print(unique_technique_counts)

            # Remove unclassified from the dictionary
            if 'unclassified' in unique_technique_counts:
                del unique_technique_counts["unclassified"]

            cd_attacks, ci_attacks = self.attack_breakdown(unique_technique_counts)
            self.logger.debug(f"Context dependent attacks:  {cd_attacks}")
            self.logger.debug(f"Context Independent attacks: {ci_attacks}")

            if 1 >= context_dependency_ratio > 0:  # Delete from independent attacks
                self.deletion_logic(ci_attacks, malicious_df, abs(context_dependency_ratio))

            elif -1 <= context_dependency_ratio < 0: # Delete from dependent attacks
                self.deletion_logic(cd_attacks, malicious_df, abs(context_dependency_ratio))

            else:
                self.logger.error(
                    f"Context Dependency ratio is invalid: {context_dependency_ratio} value needs to be between -1 and 1")

        self.logger.debug(f"removal list: {self.removal_list}")
        self.logger.debug(f"removal list length: {len(self.removal_list)}")

    def _process(self, packet: Packet) -> Packet:

        # Initialise return list
        packets = [packet]

        if IP not in packet or (TCP not in packet and UDP not in packet):
            return packets

        flow_key = self.get_flow_key(packet)

        if flow_key in self.removal_list:
            # Add flow to all flows
            if flow_key not in self.all_flows:
                self.all_flows.add(flow_key)
            # Remove packet from return packets
            packets.remove(packet)
            self.packages_removed += 1
            self.logger.debug(f"Removal count: {self.packages_removed}, by: {self.__class__.__name__}")

            return packets

        if flow_key not in self.all_flows:
            self.all_flows.add(flow_key)    
        
        return packets

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

    def deletion_logic(self, attacks, malicious_df, context_dependency_ratio):
        # Filter malicious dataframe for attack entries
        filtered_df = malicious_df[malicious_df["attack_technique"].isin(attacks)]
        # Take random sample of the filtered dataframe
        attacks_df = filtered_df.sample(frac=1 * context_dependency_ratio)
        # Take flow keys of the attacks
        attacks_list = self.df_entry_to_flow_key(attacks_df)

        # Add each flow key to the removal list if not already in there
        for entry in attacks_list:
            if entry not in self.removal_list:
                self.removal_list.append(entry)

        return self

    def attack_breakdown(self, unique_attack_counts: Dict) -> (list, list):
        # Initialize lists
        cd_attacks = []
        ci_attacks = []

        # Define sets for context-dependent and not context-dependent techniques
        context_dependent_techniques = {
            "T0812", 
            "T1041", 
            "T1048", 
            "T1055", 
            "T1071", 
            "T1082", 
            "T1090", 
            "T1095", 
            "T1105", 
            "T1110", 
            "T1133", 
            "T1189", 
            "T1190", 
            "T1204", 
            "T1210", 
            "T1219", 
            "T1491", 
            "T1498", 
            "T1566", 
            "T1568", 
            "T1573", 
            "T1593", 
            "T1595", 
            "T1598"
        }

        # Iterate through attacks to sort them into dependent or independent
        for key in unique_attack_counts:
            if key in context_dependent_techniques:
                cd_attacks.append(key)
            else:
                ci_attacks.append(key)
        return cd_attacks, ci_attacks