import logging
from pythonjsonlogger import jsonlogger
from flask import Flask, jsonify, request
import sys


def setup_http_access_logger():
    logger = logging.getLogger("access")
    logHandler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(levelname)s %(message)s %(pathname)s %(funcName)s %(user_ip)s %(user_agent)s %(method)s %(uri)s %(status_code)s %(bytes_in)s %(bytes_out)s %(args_size_bytes)s"
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
    formatter = jsonlogger.JsonFormatter("%(asctime)s - %(levelname)s - %(message)s")
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


access_logger = setup_http_access_logger()
