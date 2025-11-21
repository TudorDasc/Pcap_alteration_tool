import logging


def setup_logger(name):
    # Check if the logger is already configured
    if name in logging.Logger.manager.loggerDict:
        return logging.getLogger(name)

    loggr = logging.getLogger(name)
    loggr.setLevel(logging.DEBUG)

    # Create handlers
    debug_handler = logging.FileHandler('debug.log')
    debug_handler.setLevel(logging.DEBUG)

    info_handler = logging.FileHandler('info.log')
    info_handler.setLevel(logging.INFO)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)

    # Create formatter and add it to handlers
    formatter = logging.Formatter('%(asctime)s - %(filename)s - %(levelname)s - %(message)s')
    debug_handler.setFormatter(formatter)
    info_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)

    # Add handlers to the logger
    loggr.addHandler(debug_handler)
    loggr.addHandler(info_handler)
    loggr.addHandler(stream_handler)

    return loggr


# Use the setup_logger function to create a logger for this module
logger = setup_logger(__name__)
