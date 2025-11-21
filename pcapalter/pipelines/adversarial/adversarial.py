import pandas
import pandas as pd
from scapy.all import Packet, Ether, Dot1Q, IP, IPv6, ARP, TCP, UDP, ICMP
from ..processor import Processor
from typing import Tuple
import numpy as np

from ... import utils

# Define a type alias for better readability
# Flowkey = (source IP, Destination IP, source port, destination port)
FlowKey = Tuple[str, str, int, int]


class AdversarialProcessor(Processor):
    """
    Adversarial Processor : implements a Processor for adversarial behaviour
    """

    def reset(self, malicious_df: pd.DataFrame, modifications: [str, int] = None,
              attack_source_alter: int = 0) -> None:
        """

        Args:
            malicious_df: the malicious dataframe with attack types
            modifications: the modification values in list format of tuples (attack_type, function_integer)
                e.g ('misc-activity', 1)
                    Attack types are of :
                        ['attempted-recon', 'trojan-activity', 'bad-unknown', 'unclassified',
                        'misc-attack', 'web-application-attack', 'attempted-user', 'successful-user', 'attempted-admin',
                        'command-and-control', 'pup-activity', 'TA0009', 'policy-violation', 'TA0011', 'TA0040',
                        'coin-mining', 'TA0042', 'misc-activity', 'domain-c2', 'string-detect', 'successful-admin',
                        'web-application-activity', 'successful-recon-limited', 'protocol-command-decode', 'TA0003',
                        'not-suspicious', 'exploit-kit', 'attempted-dos', 'credential-theft', 'targeted-activity',
                        'denial-of-service', 'successful-dos', 'shellcode-detect', 'suspicious-login',
                        'non-standard-protocol', 'default-login-attempt', 'suspicious-filename-detect',
                        'system-call-detect', 'rpc-portmap-decode', 'TA0001', 'social-engineering', 'unknown',
                        'TA0005', 'external-ip-check', 'network-scan', 'TA0043', 'unsuccessful-user', 'TA0037',
                        'unusual-client-port-connection', 'TA0006', 'successful-recon-largescale',
                        ' non-standard-protocol'])
                    function_integer are of:
                        1: Increase over time, for given attack type
                            >1: packet removal ends earlier
                            0< and <1: packet removal ends later

                        -1: Decrease over time, for given attack type
                            <-1: packet removal starts earlier
                            <0 and >-1:  packet removal starts later
                        0: Leave the given attack type constant over time (do not remove any packets)
            attack_source_alter: the frequency at which the attacker source will change
                        e.g. 3 = every 3 attacks a new attacker will emerge

        """

        self.logger.info("Starting Adversarial Processor")
        self.packages_removed = 0
        self.packages_added = 0
        self.packages_altered = 0

        self.random_new_IP: str
        self.random_new_port: int

        # Semaphore to count number of altered attack sources
        loop_semaphore = 0
        self.new_source_count = attack_source_alter

        self.removal_list = []
        self.altering_attack_source = False

        # List to keep track of mutated packages with their new IP and port
        self.malicious_IPs = malicious_df["id.orig_h"].tolist()

        if self.new_source_count > 0 and modifications is not None:
            self.logger.critical(f"Warning, both new attack source and modification to existing attack vectors requested"
                                 f"Only new attack sources will be applied!")



        # Set of flows that correspond to Type: (Flowkey: (str: IP, int: port))
        self.attacks_dict = {}

        # Check if modifications function is set
        if self.new_source_count > 0:  # If no modification function provided, check if in altering attack source mode
            self.logger.info(f"Altering attack sources")
            self.logger.debug(f"Frequency of attack source swap: {self.new_source_count}")
            self.altering_attack_source = True
            # Get list of flows that need to be altered
            self.alter_list = self.df_entry_to_flow_key(malicious_df)


            random_new_IP = '0'
            random_new_port = np.random.randint(49152, 65536)

            for flow in self.alter_list:
                if flow[0] in self.malicious_IPs:
                    attackIP = flow[0]
                else:
                    attackIP = flow[1]

                # Check if beginning of new attack source cycle
                if loop_semaphore == 0:
                    # Get new random ipv4 address as same type as the flows source
                    random_new_IP = utils.get_random_new_ipv4(attackIP)
                    self.logger.debug(f"New random ip: {random_new_IP}")
                    while random_new_IP.startswith('0'):
                        self.logger.debug(f"New ip starts with 0, regenerating")
                        random_new_IP = utils.get_random_new_ipv4(attackIP)
                        self.logger.debug(f"Regenerated ip: {random_new_IP}")
                    # Get new random ephemeral port number between (49152, 65535)
                    random_new_port = np.random.randint(49152, 65536)
                    self.logger.debug(f"New random port: {random_new_port}")
                else:
                    # Check if the current random IP is the same type as the current packet's
                    self.logger.debug(f"Is it same IP type: {utils.is_same_ip_type(random_new_IP, attackIP)}, for "
                                      f"random: {random_new_IP}, and real: {attackIP}")
                    if not utils.is_same_ip_type(random_new_IP, attackIP):
                        self.logger.debug("IP types are not same, regenerating")
                        # If not same type sample new IP and port
                        # Get new random ipv4 address as same type as the current packets
                        random_new_IP = utils.get_random_new_ipv4(attackIP)
                        self.logger.debug(f"New random ip: {random_new_IP}")
                        while random_new_IP.startswith('0'):
                            random_new_IP = utils.get_random_new_ipv4(attackIP)
                        # Get new random ephemeral port number between (49152, 65535)
                        random_new_port = np.random.randint(49152, 65536)
                        self.logger.debug(f"New random port: {random_new_port}")
                        # Set the counter back to 0, for new loop start
                        loop_semaphore = 0

                # Add the IP and source that corresponds to the given flow to the mapping set
                self.attacks_dict[flow] = (random_new_IP, random_new_port)

                loop_semaphore += 1

                if loop_semaphore == self.new_source_count:
                    loop_semaphore = 0

            self.logger.debug(f"Attack source alteration dict: {self.attacks_dict}")

        elif modifications is not None:
            self.logger.info("Altering attack vectors over time")
            self.logger.debug(f"Modifications_functions: \n{modifications}")
            # Filter rates for each attack type
            filter_rate = self.initialize_and_modify_filter_rates(malicious_df, modifications)
            filtered_malicious_df = self.apply_filter_rate(malicious_df, filter_rate)
            self.logger.debug(f"Flow to be deleted:\n{filtered_malicious_df}")
            self.removal_list = self.df_entry_to_flow_key(filtered_malicious_df)


    def _process(self, packet: Packet) -> list[Packet]:
        packets = [packet]

        if IP not in packet or (TCP not in packet and UDP not in packet):
            return packets
        # Get flowkey of the current packet
        flow_key = self.get_flow_key(packet)

        # Enter altering attack source stage
        if self.altering_attack_source:


            # Check if the current packet's flow needs to be altered
            if flow_key in self.alter_list:
                self.logger.debug(f"Flowkey in alter list: {flow_key}")
                new_IP = self.attacks_dict.get(flow_key)[0]

                if (packet[IP].src) in self.malicious_IPs:
                    # self.logger.debug("1st IP is malicious")
                    # Alter the IP address in the packet with random IP
                    packet[IP].src = new_IP
                    # Alter the port to a random ephemeral port
                    if TCP in packet:
                        # old_port = packet[TCP].sport
                        packet[TCP].sport = self.attacks_dict.get(flow_key)[1]
                    elif UDP in packet:
                        # old_port = packet[UDP].sport
                        packet[UDP].sport = self.attacks_dict.get(flow_key)[1]
                elif packet[IP].dst in self.malicious_IPs:
                    # self.logger.debug("2nd IP is malicious")
                    # Alter the IP address in the packet with random IP
                    packet[IP].dst = new_IP
                    # Alter the port to a random ephemeral port
                    if TCP in packet:
                        # old_port = packet[TCP].sport
                        packet[TCP].dport = self.attacks_dict.get(flow_key)[1]
                    elif UDP in packet:
                        # old_port = packet[UDP].sport
                        packet[UDP].dport = self.attacks_dict.get(flow_key)[1]



                if not utils.has_correct_ip_checksum(packet):
                    self.logger.debug(f"Checksum is: {utils.has_correct_ip_checksum(packet)}, for packet: {packet},"
                                      f"calculating correct checksum...")
                    packet = utils.get_packet_with_correct_ip_checksum(packet)
                    self.logger.debug(f"Packet with correct checksum: {packet}")

                # self.logger.debug(f"Replacing real ip: {packet[IP].src}:{old_port}, "
                #                   f"with random ip: {self.attacks_dict.get(flow_key)[0]}:{self.attacks_dict.get(flow_key)[1]}")
                packets = [packet]

        else:
            # Enter altering attack vectors over time stage
            if flow_key in self.removal_list:
                packets.remove(packet)
                self.packages_removed += 1
                self.logger.debug(f"Removal count: {self.packages_removed}, by: {self.__class__.__name__}")

        return packets

    # Function to initialize and modify filter rates
    def initialize_and_modify_filter_rates(self, mal_df, modifications):
        # Get unique attack types from the DataFrame
        attack_types = mal_df['attack_type'].unique()

        # Initialize filter rates with 0 for all attack types
        filter_rates = {}

        # Total length of the DataFrame
        total_length = len(mal_df)

        # Create a mapping from attack types to their corresponding filter functions
        rate_functions = {
            1: lambda x: min(1, (x / total_length) * steepness),  # Increase over time
            -1: lambda x: max(0.1, 1 - (x / total_length) * steepness),  # Decrease over time
            0: lambda x: 1  # Constant filter rate
        }

        # Initialise steepness to 1 for constant filter rate
        steepness = 1
        # Modify the filter rates based on the provided modifications
        for attack_type in attack_types:
            # Default to a constant rate if not specified in modifications
            filter_rates[attack_type] = rate_functions[0]

        self.logger.debug(f"modifications: {modifications}")
        self.logger.debug(f"attack types: {attack_types}")

        # Apply the modifications
        for attack_type, rate_indicator in modifications:
            if rate_indicator != 0:
                if attack_type in filter_rates:
                    steepness = abs(rate_indicator)
                    filter_rates[attack_type] = rate_functions[int(rate_indicator / steepness)]
                    self.logger.debug(f"attack type: {attack_type}, steepness: {steepness}, "
                                      f"rate: {filter_rates[attack_type]}")

        self.logger.debug(f"filter_rates: {filter_rates}")

        return filter_rates

    # Function to apply filter rates to the malicious df
    def apply_filter_rate(self, df: pd.DataFrame, filter_rates):
        filtered_rows = []
        for i, row in df.iterrows():
            attack_type = row['attack_type']
            if attack_type in filter_rates:
                filter_rate = filter_rates[attack_type](i)
                self.logger.debug(f"filter rate: {filter_rate}, random ex: {np.random.rand()}")
                if np.random.rand() > filter_rate:
                    filtered_rows.append(row)
        filtered_df = pd.DataFrame(filtered_rows, columns=df.columns)

        return filtered_df

    def process_label_df(self, labels_df: pd.DataFrame) -> pd.DataFrame:
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
            label_len = len(labels_df)
            # reset label length

        self.logger.debug(f'Removed label count: {remove_label_count}')
        label_add_count = 0
        if len(self.attacks_dict) > 0:

            self.logger.debug(f"Label to be added count {len(self.attacks_dict)}: {self.attacks_dict}")
            for flow_key, attack_tuple in self.attacks_dict.items():
                new_ip = attack_tuple[0]
                new_port = attack_tuple[1]
                self.logger.debug(f"New ip: {new_ip}, port: {new_port}")

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

                # Remove packets from the labels
                labels_df = labels_df[~mask]

                matching_packets['Source IP'] = new_ip
                matching_packets['Source Port'] = new_port

                # Count how many packets have been added
                label_add_count += len(matching_packets)


                labels_df = pandas.concat([labels_df, matching_packets])
        self.logger.debug(f'Added label count: {label_add_count}')

        return labels_df
