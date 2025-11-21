import json
import pandas as pd
from . import rulesparser
from zat.log_to_dataframe import LogToDataFrame
import os

log_to_df = LogToDataFrame()

current_dir = os.getcwd()

filename_rules = os.path.join(current_dir, "data", "mitre_all.rules")

grouped_by_mitres = rulesparser.grouped_by_mitre_tactic(filename_rules)
grouped_by_techniques = rulesparser.grouped_by_mitre_technique(filename_rules)

def find_mitre(signature_id):
    for key, value_list in grouped_by_mitres.items():
        if signature_id in value_list:
            return key
    return None

def find_technique(signature_id):
    for key, value_list in grouped_by_techniques.items():
        if signature_id in value_list:
            return key
    return None

def preprocess_eve(filename: str):
    chunks = []
    for chunk in pd.read_json(filename, lines=True, chunksize=1000):
        chunks.append(chunk)

    df_eve = pd.concat(chunks, ignore_index=True)
    # print("df eve dict: ", df_eve.groupby(["event_type","src_ip", "dest_ip", "src_port", "dest_port"]).size().to_dict())

    # Filter only event_type == 'alert'
    df_eve = df_eve[df_eve['event_type'] == 'alert']

    # Extract signature_id directly from the 'alert' dictionary
    df_eve['alert_sid'] = df_eve['alert'].apply(lambda x: x.get('signature_id') if isinstance(x, dict) else None)

    # Define the columns we need to identify a connection
    event_tuple = ["timestamp", "src_ip", "src_port", "dest_ip", "dest_port", "alert_sid"]

    # Filter the DataFrame to keep only the necessary columns
    df_eve = df_eve[event_tuple]

    # Apply the find_mitre function to get the attack_type
    df_eve['attack_type'] = df_eve["alert_sid"].apply(find_mitre)

    df_eve['attack_technique'] = df_eve["alert_sid"].apply(find_technique)

    # Save the filtered and processed DataFrame to a JSON file
    df_eve.to_json('alerts_eve.json', orient='records', lines=True)

    # Reset the index of the DataFrame
    df_eve = df_eve.reset_index(drop=True)

    df_eve = df_eve.rename(
        columns={'timestamp': 'ts', 'src_ip': 'id.orig_h', 'src_port': 'id.orig_p', 'dest_ip': 'id.resp_h',
                 'dest_port': 'id.resp_p'})

    return df_eve


def map_event_to_conn(eve_path: str, filename_conn: str, with_mitre: bool = False, with_technique: bool= False) -> (
        pd.DataFrame):
    df_eve = preprocess_eve(eve_path)
    # Remove timezone information from the timestamp
    df_eve['ts'] = df_eve['ts'].dt.tz_convert(None)

    # Create DataFrame from the conn log
    df_conn = log_to_df.create_dataframe(filename_conn)

    # Create tuples of relevant columns for matching
    eve_tuples = list(set(df_eve.apply(lambda row: (row['id.orig_h'], row['id.orig_p'], row['id.resp_h'], row['id.resp_p']),
                              axis=1)))
    conn_tuples = df_conn.apply(lambda row: (row['id.orig_h'], row['id.orig_p'], row['id.resp_h'], row['id.resp_p']),
                                axis=1)

    # Use the tuples for matching rows between df_eve and df_conn
    common_conn = df_conn[conn_tuples.isin(eve_tuples)]

    if with_mitre and with_technique:
        common_conn = common_conn.merge(
            df_eve[['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'attack_type', 'attack_technique']],
            on=['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
            how='left')
    else:    
        if with_mitre:
            common_conn = common_conn.merge(
                df_eve[['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'attack_type']],
                on=['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
                how='left')
        elif with_technique:
            common_conn = common_conn.merge(
                df_eve[['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'attack_technique']],
                on=['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
                how='left')


    # Drop duplicate rows based on columns, keeping the first occurrence
    common_conn = common_conn.drop_duplicates(subset=['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p'],
                                              keep='first').reset_index(drop=True)
    # print("df eve dict: ", df_eve.groupby(['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'attack_type']).size()
    # .to_dict())

    # Save the matched connections to a JSON file
    common_conn.to_json('common_conn.json', orient='records', lines=True)
    return common_conn



def filter_ground_truth(filename_csv: str, common_conn: pd.DataFrame):
    truth_df = pd.read_csv(filename_csv)
    # filter only the connections that are not BENIGN
    truth_df = truth_df[truth_df["Label"] != "BENIGN"]
    truth_df = truth_df.filter(["Timestamp", "Src IP", "Src Port", "Dst IP", "Dst Port"])

    # rename columns in the ground truth csv
    truth_df = truth_df.rename(columns={'Timestamp': 'ts', 'Src IP': 'id.orig_h', 'Src Port': 'id.orig_p',
                                        'Dst IP': 'id.resp_h', 'Dst Port': 'id.resp_p'})
    common_tuple = pd.Series(list(zip(common_conn["id.orig_h"], common_conn["id.resp_h"],
                                      common_conn["id.resp_p"])), index=common_conn.index)
    
    truth_tuples = pd.Series(list(zip(truth_df["id.orig_h"], truth_df["id.resp_h"], truth_df["id.resp_p"])),
                             index=truth_df.index)


    # mask to filter only the connections that are malicious
    mask = common_tuple.isin(truth_tuples)
    filter_truth_conn = common_conn[mask]

    filter_truth_conn.to_json('filter_common_conn.json', orient='records', lines=True)
    return filter_truth_conn


def find_corresponding_value(row, df_eve):
    # Find matching row in df2 based on criteria
    matching_row = df_eve[(df_eve['id.orig_h'] == row['id.orig_h'])
                          & (df_eve['id.orig_p'] == row['id.orig_p'])
                          & (df_eve['id.resp_p'] == row['id.resp_p'])]
    if not matching_row.empty:
        return matching_row.iloc[0]['attack_type']
    return None

def filter_suricata_alerts(filename):

    keywords = ["POLICY", "HUNTING", "INFO"]
    filtered_alerts = []

    directory, base_name = os.path.split(filename)
    output_file = f"filtered_{base_name}"
    # Read the JSON log file
    with open(filename, 'r', encoding='utf-8') as infile:
        for line in infile:
            alert = json.loads(line)
            if 'alert' in alert and 'signature' in alert['alert']:
                msg = alert['alert']['signature']
                # Check if the alert's msg field contains any of the keywords
                if not any(keyword in msg for keyword in keywords):
                    filtered_alerts.append(alert)

    # Write the filtered alerts to the output file
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for alert in filtered_alerts:
            json.dump(alert, outfile)
            outfile.write('\n')
    
    return directory, output_file