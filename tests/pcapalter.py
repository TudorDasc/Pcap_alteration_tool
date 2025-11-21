import unittest

import sys
import os
import suricata
import zeek
import shutil
import ast
import pandas as pd

import argparse

# MULTI_PCAP_PATH = "./data/pcaps"
OUTPUT_DIR = './data/out_pcap'
CSV_OUTPUT_DIR = './data/out_csv'

CONN_PATH = "./data/multi_conn.log"
EVE_PATH = "./data/eve.json"

RULES_PATH = "./data/all.rules"
GROUND_TRUTH_DIR = "./data/csvs"

NOT_DELETE_LIST = [
    "info.log",
    "debug.log",
    "eve.json",
    "multi_conn.log"
]

# If True, running zeek and suricata is disabled
TEST_MODE = True


class TestPcapAlter(unittest.TestCase):
    def test_pcap_alter(self):
        parser = argparse.ArgumentParser(description="Alter PCAP with processors")  # TODO: input sanitisation
        parser.add_argument('pcap_dir',
                            type=str,
                            help='Directory containing pcap files')
        parser.add_argument('-ground_truth',
                            type=str,
                            help='Directory containing ground truth files')

        # Subparser for the -i argument with sub-arguments
        group_i = parser.add_mutually_exclusive_group(required=False)

        group_i.add_argument('-i-mal', type=float, help='Malicious percentage value for imbalance processor')
        group_i.add_argument('-i-bngn', type=float, help='Benign percentage value for imbalance processor')
        group_i.add_argument('-i-intra', type=float, help='Intra percentage value for imbalance processor')

        parser.add_argument('-i-mut-chance', type=float, help='Mutation chance for imbalance processors')

        parser.add_argument('-a',
                            type=str,
                            help='Adversary processor, List of tuples (str)'
                                 'that specify modifications of attack types, or '
                                 'attack source alteration value (int) that will '
                                 'alter every x ip source to different ip '
                            , default=None)
        parser.add_argument('-e',
                            type=int,
                            help='Evolution processor, n_hosts (int) = number of hosts that will be altered'
                            , default=None)
        parser.add_argument('-u',
                            type=float,
                            help='Unpredictable processor, mutation chance (float) = probability of mutation to an ip')
        parser.add_argument('-c',
                            type=float,
                            help='Context dependency processor, Context Dependency Ratio should be float. +ve value indicates more context dependency, -ve indicates more independence'
                            , default=None)  # TODO

        args = parser.parse_args()

        global RULES_PATH
        self.logger = pcapalter.utils.logger
        self.logger.info("------------------------------------------NEW RUN------------------------------------------")

        self.logger.debug(f"Arguments passed: {sys.argv}")
        if len(sys.argv) <= 2:
            self.logger.error(f"Not enough arguments provided {sys.argv}, terminating")
            parser.error("Not enough arguments provided. Please provide the required arguments. "
                         "Have a look at the read.me")

        # Set the pcap path to the passed argument
        MULTI_PCAP_PATH = self.get_relative_path(args.pcap_dir)

        # Create directory for data
        target_directory = os.path.join('data')

        # Ensure the target directory exists
        if not os.path.exists(target_directory):
            os.makedirs(target_directory)

        # Use cached conn.log and eve.json for testing purposes
        if not TEST_MODE:

            # Get the current directory
            current_directory = os.getcwd()

            # assigning returned file name after mitre tagging to var
            mitre_tagged_rules = pcapalter.utils.mitre_rule_tagger.main("./data/all.rules")

            #moving mitre tagged rules to data
            file_path = os.path.join(current_directory, mitre_tagged_rules)
            target_path = os.path.join(current_directory, target_directory, mitre_tagged_rules)
            self.move_file(file_path, target_path)
            RULES_PATH = target_path
            
            # run zeek
            self.logger.info("Running zeek")
            zeek.pcap_zeek(MULTI_PCAP_PATH, self.logger)

            # run suricata
            self.logger.info("Running Suricata")
            suricata.suricata(MULTI_PCAP_PATH, RULES_PATH, self.logger)

            # Move eve.json to data folder
            eve_name = 'eve.json'
            self.logger.debug(f"Moving {eve_name} to {target_directory}")
            file_path = os.path.join(current_directory, eve_name)
            target_path = os.path.join(current_directory, target_directory, eve_name)
            self.move_file(file_path, target_path)

            # Move conn.log to data folder
            conn_name = 'multi_conn.log'
            self.logger.debug(f"Moving {conn_name} to {target_directory}")
            file_path = os.path.join(current_directory, conn_name)
            target_path = os.path.join(current_directory, target_directory, conn_name)
            self.move_file(file_path, target_path)

            # Loop through all files in the current directory to delete redundant files
            for filename in os.listdir(current_directory):
                file_path = os.path.join(current_directory, filename)
                if (filename.endswith('.log') or filename.endswith('.json')) and filename not in NOT_DELETE_LIST:
                    os.remove(file_path)
                    self.logger.debug(f"Deleted file: {file_path}")
                else:
                    self.logger.debug(f"Skipped file: {file_path}")

            self.logger.info("cleanup complete")

        # Get the current directory
        current_directory = os.getcwd()

        #filter alerts related to HUNTING|POLICY|INFO from eve.json
        target_directory, filtered_eve_name = pcapalter.utils.map_conn.filter_suricata_alerts(EVE_PATH)
        file_path = os.path.join(current_directory, filtered_eve_name)
        target_path = os.path.join(current_directory, target_directory, filtered_eve_name)
        self.move_file(file_path, target_path)

        # Start pipeline
        self.logger.info("Starting Pipeline")

        # print("Calculating Malicious DF")
        self.logger.info("Calculating Malicious DF")
        self.malicious_df = pcapalter.utils.map_conn.map_event_to_conn(EVE_PATH, CONN_PATH, with_mitre=True, with_technique=True)
        self.logger.debug(self.malicious_df)
        self.logger.debug(f"malicious df unique alerts: {self.malicious_df['attack_type'].unique()}")
        # Apply ground truth filtering if files directory supplied
        if GROUND_TRUTH_DIR is not None:
            self.logger.info(f"Filtering for ground truth in directory {GROUND_TRUTH_DIR}")
            malicious_df_filtered = pd.DataFrame()
            csv_list = self.get_ground_truth_csv(GROUND_TRUTH_DIR)
            for csv_path in csv_list:
                truth_df = pcapalter.utils.filter_ground_truth(csv_path, self.malicious_df)
                if malicious_df_filtered.empty:
                    malicious_df_filtered = truth_df
                else:
                    malicious_df_filtered = pd.concat([malicious_df_filtered, truth_df], ignore_index=True)
            self.malicious_df = malicious_df_filtered.reset_index(drop=True)
            self.logger.debug(f"Filtered Malicious df:")
            self.logger.debug(self.malicious_df)
        else:
            self.logger.info("No ground truth file found")

        # List of processors that will be used
        self.processors = []

        # Parse Imbalance parameters
        if any([args.i_mal, args.i_bngn, args.i_intra]):
            self.logger.debug(f"Using imbalance processors with mal_mut_chance= {args.i_mal}, bngn_mut_chance: "
                             f"{args.i_bngn}, intra_mut_ratio: {args.i_intra}, mutation chance: {args.i_mut_chance}")
            self.parse_imbalance_values(args)

        # Parse Adversary parameters
        if any([args.a]):
            self.logger.debug(f"Using Adversarial Processor with parameter: {args.a}")
            self.parse_adversary_values(args.a)

        # Parse Evolution parameters
        if any([args.e]):
            self.logger.debug(f"Using Evolution Processor with parameter: {args.e}")
            self.parse_evolution_values(args.e)

        # Parse Unpredictable parameters
        if any([args.u]):
            self.logger.debug(f"Using Unpredictable Processor with parameter: {args.u}")
            self.parse_unpredictable_values(args.u)

        # Parse Context Dependency parameters
        if any([args.c]):
            self.logger.debug(f"Using Context Dependency Processor with parameter: {args.c}")
            self.parse_context_dependency_values(args.c)

        self.logger.debug(f"Running processors: {self.processors}")
        pipeline = pcapalter.Pipeline(self.processors)

        pcap_out = pcapalter.alter_pcap(
            self.get_pcaps(MULTI_PCAP_PATH),
            OUTPUT_DIR,
            pipeline
        )

        label_out = pcapalter.update_labels(
            self.get_ground_truth_csv(GROUND_TRUTH_DIR),
            CSV_OUTPUT_DIR,
            pipeline
        )

        for pcap in pcap_out:
            self.assertTrue(os.path.exists(pcap))

        for label in label_out:
            self.assertTrue(os.path.exists(label))

    def move_file(self, file_path, target_path):
        try:
            shutil.move(file_path, target_path)
            self.logger.debug(f"File '{file_path}' has been moved to '{target_path}' successfully.")
        except FileNotFoundError:
            self.logger.warning(f"File '{file_path}' not found in the current directory while moving.")
        except Exception as e:
            self.logger.warning(f"An error occurred while moving the file: {e}")

    # Get pcap and pcapng file names from the given directory
    def get_pcaps(self, directory) -> list[str]:
        files_in_dir = os.listdir(directory)
        pcaps_in_dir = [os.path.join(directory, f) for f in files_in_dir if f.endswith('.pcap') or f.endswith('.pcapng')]
        return pcaps_in_dir

    # Get ground truth csv file names from the given directory
    def get_ground_truth_csv(self, directory) -> list[str]:
        files_in_dir = os.listdir(directory)
        csv_in_dir = [os.path.join(directory, f) for f in files_in_dir if f.endswith('.csv')]
        return csv_in_dir

    # Returns the relative directory compare to given target
    def get_relative_path(self, target_dir):
        current_dir = os.getcwd()
        relative_path = os.path.relpath(target_dir, current_dir)
        return relative_path

    def parse_imbalance_values(self, args):
        # Process imbalance command
        mut_chance = 0.1
        if args.i_mut_chance is not None:
            mut_chance = args.i_mut_chance

        if args.i_mal is not None:
            self.processors.append(pcapalter.ImbalanceProcessor(
                malicious_mutation_percentage=args.i_mal,
                mutation_chance=mut_chance,
                mal_df=self.malicious_df
            )
            )
        elif args.i_bngn is not None:
            self.processors.append(pcapalter.ImbalanceProcessor(
                benign_mutation_percentage=args.i_bngn,
                mutation_chance=mut_chance,
                mal_df=self.malicious_df
            )
            )
        elif args.i_intra is not None:
            self.processors.append(pcapalter.ImbalanceProcessor(
                intra_class_mutation_ratio=args.i_intra,
                mutation_chance=mut_chance,
                mal_df=self.malicious_df
            )
            )

    def parse_adversary_values(self, value):
        try:
            # If an integer is provided use it as attack source alter argument in Adversarial processor
            # Try to parse as a single integer
            int_value = int(value)
            self.processors.append(
                pcapalter.AdversarialProcessor(
                    self.malicious_df,
                    attack_source_alter=int_value
                )
            )
            return

        except ValueError:
            pass

        try:
            # If a List of attack tuples provided use it as modification list for Adversarial processor
            values = ast.literal_eval(value)
            if not isinstance(values, list) or not all(isinstance(item, tuple) and len(item) == 2 for item in values):
                raise argparse.ArgumentTypeError(
                    "Argument -a requires a list of tuples like [(‘bad-unknown’, -1), (‘policy-violation’, 1)]")
            self.processors.append(pcapalter.AdversarialProcessor(
                self.malicious_df,
                modifications=values
            )
            )
            return
        except Exception:
            raise argparse.ArgumentTypeError(
                "Argument -a requires either a single integer or a list of tuples like [(‘bad-unknown’, -1), "
                "(‘policy-violation’, 1)].")

    def parse_evolution_values(self, value):
        try:
            int_value = int(value)
            self.processors.append(
                pcapalter.EvolutionProcessor(
                    conn_path=CONN_PATH,
                    n_hosts=int_value
                )
            )
        except ValueError:
            raise argparse.ArgumentTypeError("Number of hosts must be an integer")

    def parse_unpredictable_values(self, value):
        try:
            float_value = float(value)
            self.processors.append(
                pcapalter.UnpredictableProcessor(
                    conn_path=CONN_PATH,
                    mutation_chance=float_value
                )
            )
        except ValueError:
            raise argparse.ArgumentTypeError("Mutation chance should be float")

    def parse_context_dependency_values(self, value):
        try:
            float_value = float(value)
            self.processors.append(
                pcapalter.ContextDependencyProcessor(
                    mal_df=self.malicious_df,
                    ground_truth_path=GROUND_TRUTH_PATH,
                    context_dependency_ratio=float_value
                )
            )
        except ValueError:
            raise argparse.ArgumentTypeError("Context Dependency Ratio should be float.")
        return


if __name__ == '__main__':
    sys.path.insert(0, os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..'))
                    )
    import pcapalter

    unittest.main(argv=['first-arg-is-ignored'], exit=False)
