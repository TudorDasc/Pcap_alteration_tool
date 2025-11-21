import subprocess
import os
import concurrent.futures
import sys


def run_suricata(input_file, rules_path, lgr):
    logger = lgr
    # Check if the input file exists
    if not os.path.exists(input_file):
        logger.critical(f"Input file '{input_file}' does not exist.")
        return

    # Run Suricata
    try:
        command = ['suricata', '-s', rules_path, '-r', input_file]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL )
        logger.info(f"Suricata run successful for '{input_file}'.")
    except subprocess.CalledProcessError as e:
        logger.warning(f"Suricata run failed for '{input_file}': {e}")
        return


# param director: directory that contains the pcap files
def suricata(dir_path, rules_path, lgr):
    logger = lgr
    # Check if the provided path is a directory
    if not os.path.isdir(dir_path):
        logger.critical(f"'{dir_path}' is not a valid directory.")
        return

    # List all files in the directory
    input_files = [os.path.join(dir_path, fname) for fname in os.listdir(dir_path) if fname.endswith('.pcap') or
                   fname.endswith('.pcapng')]
    # Run Suricata on multiple files concurrently
    with (concurrent.futures.ProcessPoolExecutor() as executor):
        # Submit tasks for each input file
        future_to_file = {executor.submit(run_suricata, input_file, rules_path, logger): input_file[2:] for input_file in input_files}

        # Wait for all tasks to complete
        for future in concurrent.futures.as_completed(future_to_file):
            input_file = future_to_file[future]
            try:
                future.result()  # Retrieve the result of the task
            except Exception as e:
                logger.debug(f"Suricata run for '{input_file}' generated an exception: {e}")
