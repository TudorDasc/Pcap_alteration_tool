import atexit
import inspect
from typing import Union
import warnings
from scapy.all import PcapWriter, PcapNgWriter, Packet
from .multi import DedicatedProcessObject
from ... import utils


class DedicatedWriter:
    def __init__(self, pcap: str):
        caller = inspect.stack()[1].function
        if caller != "setup_subprocess":
            warnings.warn(
                "DedicatedWriter should be created using DedicatedWriter.instantiate() instead of calling DedicatedWriter() directly",
                RuntimeWarning,
            )
        self.logger = utils.logger
        self.logger.info("Setting up dedicated writer")

        # Set up writer
        if pcap.endswith(".pcapng"):
            self.writer = PcapNgWriter(pcap)
        else:
            self.writer = PcapWriter(pcap)

        atexit.register(self.__exit_handler)

    def __exit_handler(self):
        self.logger.info("DedicatedWriter exiting")

        self.writer.flush()
        self.writer.close()

    @staticmethod
    def instantiate(pcap: str) -> Union[DedicatedProcessObject, "DedicatedWriter"]:
        return DedicatedProcessObject.instantiate(DedicatedWriter, pcap)

    def write_batch(self, batch: list[Packet]) -> None:
        # Loop over and process packets
        for packet in batch:
            # If the packet is empty, skip
            if not packet.payload or packet.payload.name == "NoPayload":
                print("packet is empty, skipping in write: ", packet)
                continue
            else:
                self.writer.write(packet)

        self.writer.flush()
