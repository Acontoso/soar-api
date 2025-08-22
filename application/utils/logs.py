import logging
from pythonjsonlogger import jsonlogger
import sys
from flask import has_request_context, g


class RequestIdFilter(logging.Filter):
    def filter(self, record):
        # Log record object that is created each time a logger is written to
        # Filter can add or modify attributes of the record before outputted
        if has_request_context() and hasattr(g, "request_id"):
            # Request context relates to global flask objects such as requess & g
            record.request_id = g.request_id
        else:
            record.request_id = None
        return True


def setup_http_access_logger():
    logger = logging.getLogger("access")
    logHandler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(levelname)s %(message)s %(pathname)s %(funcName)s %(user_ip)s %(user_agent)s %(method)s %(uri)s %(status_code)s %(bytes_in)s %(bytes_out)s %(args_size_bytes)s %(client)s %(request_id)s"
    )
    logHandler.setFormatter(formatter)
    logger.addHandler(logHandler)
    logger.setLevel(logging.INFO)
    return logger


def setup_standard_logger():
    logger = logging.getLogger("standard")
    logger.setLevel(logging.INFO)
    for handler in logger.handlers:
        logger.removeHandler(handler)
    formatter = jsonlogger.JsonFormatter(
        "%(asctime)s - %(levelname)s - %(message)s - %(request_id)s"
    )
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    logger.addFilter(RequestIdFilter())
    return logger


access_logger = setup_http_access_logger()
