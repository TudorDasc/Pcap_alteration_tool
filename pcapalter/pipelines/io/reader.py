import atexit
import inspect
from typing import Union
import warnings
from scapy.all import PcapReader, PcapNgReader, Packet
from .multi import DedicatedProcessObject
from ... import utils

class DedicatedReader:
    def __init__(self, pcap: str):
        self.logger = utils.logger
        caller = inspect.stack()[1].function

        if caller != "setup_subprocess":
            self.logger.warning(
                f"DedicatedReader should be created using DedicatedReader.instantiate() instead of calling "
                f"DedicatedReader() directly {RuntimeWarning}")
        self.logger.info("Setting up dedicated reader")

        # Set up reader
        if pcap.endswith(".pcapng"):
            self.reader = PcapNgReader(pcap)
        else:
            self.reader = PcapReader(pcap)

        atexit.register(self.__exit_handler)

    def __exit_handler(self):
        self.logger.info("DedicatedReader exiting")

        self.reader.close()

    @staticmethod
    def instantiate(pcap: str) -> Union[DedicatedProcessObject, "DedicatedReader"]:
        return DedicatedProcessObject.instantiate(DedicatedReader, pcap)

    def read_batch(self, batch_size: int = 10000) -> list[Packet]:
        # Loop over and process packets
        accumulated_packets = []

        for _ in range(batch_size):
            try:
                accumulated_packets.append(self.reader.read_packet())
            except EOFError:
                break

        return accumulated_packets

