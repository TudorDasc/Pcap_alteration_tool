import os
from .pipelines.pipeline import Pipeline
from . import utils



logger = utils.logger


def alter_pcap(
    pcap_in: str | list[str],
    pcap_out_dir: str,
    pipeline=Pipeline,
    verbose: bool = True,
) -> list[str]:
    """Process PCAPs using the provided pipeline and output the altered PCAPs

    Args:
        pcap_in (list): Ordered list of input PCAP files that are to be altered
    """
    if isinstance(pcap_in, str):
        pcap_in = [pcap_in]

    # Create output folder if non-existent
    if not os.path.exists(pcap_out_dir):
        os.makedirs(pcap_out_dir)

    pcap_out = [
        os.path.join(pcap_out_dir, os.path.basename(p_in))
        for p_in in pcap_in
    ]

    for p_in, p_out in zip(pcap_in, pcap_out):
        if verbose:
            logger.info(f'Altering PCAP: {p_in}')

        pipeline.process_pcap(p_in, p_out)

    return pcap_out


def update_labels(
    label_in: str | list[str],
    label_out_dir: str,
    pipeline=Pipeline,
    verbose: bool = False,
) -> list[str]:
    """Process CSVs containing labels using the provided pipeline and output the labelling data consistent with the modifications made to the PCAPs by the pipeline

    Args:
        label_in (list): Ordered list of input CSV files that are to be updated
    """
    if isinstance(label_in, str):
        label_in = [label_in]

    # Create output folder if non-existent
    if not os.path.exists(label_out_dir):
        os.makedirs(label_out_dir)

    label_out = [
        os.path.join(label_out_dir, os.path.basename(p_in))
        for p_in in label_in
    ]

    for p_in, p_out in zip(label_in, label_out):
        if verbose:
            logger.info(f'Updating labels for PCAP: {p_in}')

        pipeline.process_label(p_in, p_out)

    return label_out
