
import atexit
import multiprocessing
import multiprocessing.pool
import time
from typing import Optional
import chardet
import pandas
from scapy.all import Packet
from .io import DedicatedReader, DedicatedWriter
from .processor import Processor
from .. import utils


BATCH_SIZE = 10000

ORIGINAL_LABELS_COLUMNS = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s',
                           'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']

IMPROVED_LABELS_COLUMNS = ['id', 'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets', 'Total Length of Fwd Packet', 'Total Length of Bwd Packet', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd RST Flags', 'Bwd RST Flags', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
                           'Packet Length Min', 'Packet Length Max', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWR Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Fwd Segment Size Avg', 'Bwd Segment Size Avg', 'Fwd Bytes/Bulk Avg', 'Fwd Packet/Bulk Avg', 'Fwd Bulk Rate Avg', 'Bwd Bytes/Bulk Avg', 'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'FWD Init Win Bytes', 'Bwd Init Win Bytes', 'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'ICMP Code', 'ICMP Type', 'Total TCP Flow Time', 'Label', 'Attempted Category']


IMPROVED_LABELS_COLUMNS_MAPPING = {
    x: x.replace('Src ', 'Source ').replace('Dst ', 'Destination ')
    for x in IMPROVED_LABELS_COLUMNS
}



class Pipeline(Processor):
    def __init__(self, processors: list[Processor]) -> None:
        self.processors: list[Processor] = processors
        self.logger = utils.logger

        self.pool: Optional[multiprocessing.pool.ThreadPool] = None
        atexit.register(self.terminate)

    def terminate(self):
        if self.pool is not None:
            self.pool.terminate()
            self.pool = None

    def process_pcap(self, pcap_in: str, pcap_out: str) -> None:
        # Set up I/O
        self.logger.info(f"Setting up dedicated readers and writers for PCAP alteration for pcap_in: {pcap_in}, pcap_out: {pcap_out}")

        reader = DedicatedReader.instantiate(pcap_in)
        writer = DedicatedWriter.instantiate(pcap_out)
        self.pool = multiprocessing.pool.ThreadPool(2)

        # Process PCAP
        self.logger.info(f'Processing PCAP: {pcap_in}')

        batch: list[Packet] = self.pool.apply(
            reader.read_batch,
            (BATCH_SIZE, )
        )
        next_batch: multiprocessing.pool.AsyncResult
        last_write: Optional[multiprocessing.pool.AsyncResult] = None
        while len(batch) > 0:
            next_batch = self.pool.apply_async(
                reader.read_batch,
                (BATCH_SIZE, )
            )

            processed_batch = self.process_batch(batch)

            if last_write is not None:
                last_write.get()

            last_write = self.pool.apply_async(
                writer.write_batch,
                (processed_batch, )
            )

            batch = next_batch.get()

        # Cleanup processes
        self.logger.info('PCAP Alteration completed, cleaning up subprocesses now')

        self.pool.close()
        time.sleep(1)
        self.pool.join()
        time.sleep(1)
        self.terminate()

        reader.shutdown(3)
        writer.shutdown()

    def process_label(self, label_in: str, label_out: str):
        self.logger.debug('Reading original labels')

        with open(label_in, 'rb') as rawdata:
            encoding = chardet.detect(rawdata.read(
                None
            )).get("encoding")
        try:
            labels_df = pandas.read_csv(
                label_in,
                skipinitialspace=True,
                encoding=encoding,
                names=ORIGINAL_LABELS_COLUMNS
            )

            labels_inverted= False
        except:
            labels_df = pandas.read_csv(
                label_in,
                skipinitialspace=True,
                encoding=encoding,
                names=IMPROVED_LABELS_COLUMNS
            )

            labels_df.rename(IMPROVED_LABELS_COLUMNS_MAPPING, axis=1, inplace=True)

            labels_inverted = True

        labels_df.sort_values('Timestamp', ascending=True, inplace=True)

        self.logger.info('Altering labels')

        for processor in self.processors:
            labels_df = processor.process_label_df(labels_df)
            labels_df.sort_values('Timestamp', ascending=True, inplace=True)

        self.logger.info('Writing altered labels')

        # Restore original labelling
        if labels_inverted:
            labels_df.rename({v: k for k, v in IMPROVED_LABELS_COLUMNS_MAPPING.items()}, inplace=True)

        labels_df.to_csv(label_out, index=False)

    def process_batch(self, packets: list[Packet]) -> list[Packet]:
        for processor in self.processors:
            packets = processor.process_batch(packets)
        return packets

    def reset(self) -> None:
        """Resets the state of the processors in the pipeline
        """
        for processor in self.processors:
            processor.reset()
