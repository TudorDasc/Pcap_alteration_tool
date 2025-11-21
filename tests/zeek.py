# Run zeek in order to produce logs from .pcap file
# Currently implemented for a single .pcap file
# TODO: implement for multiple pcaps

import subprocess
import os


# check if conn.log exists in the current directory
# pcap_path: path to folder with pcaps
def pcap_zeek(pcap_path, lgr):
    skip_lines = 8
    chunk_size = 1024
    logger = lgr
    current_dir = os.getcwd()
    pcap_dir = os.path.join(current_dir, pcap_path)
    files_in_dir = os.listdir(pcap_dir)
    pcaps_in_dir = [f for f in files_in_dir if f.endswith('.pcap') or f.endswith('.pcapng')]

    try:
        with open("multi_conn.log", 'wb') as outfile:
            for i, pcap_name in enumerate(pcaps_in_dir):
                pcap_name_dir = os.path.join(pcap_dir, pcap_name)
                logger.debug(f"Using PCAP: {pcap_name}")
                # Run zeek command
                run_zeek_command(pcap_name_dir, logger)

                with open('conn.log', 'rb') as infile:
                    lines = infile.readlines()
                    if i != 0:
                        lines = lines[skip_lines:]

                    if i != len(pcaps_in_dir) - 1:
                        # Exclude the last line if not the last file
                        lines = lines[:-1]

                    for line in lines:
                        outfile.write(line)
                    if i != len(pcaps_in_dir) - 1:
                        outfile.write(b'\n')  # not necessary, good for debugging
    except:
        logger.debug("No PCAP file found")


def run_zeek_command(pcap_name_dir, logger):
    # List of strings to run as command
    commands = [
        "zeek",
        "-r",
        pcap_name_dir
    ]

    logger.debug(f"Running command: {' '.join(commands)}")
    try:
        subprocess.run(commands)
        logger.debug(f"Zeek command success for {pcap_name_dir}")
    except subprocess:
        logger.error(f"Zeek failed: {subprocess}")
