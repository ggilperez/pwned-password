from http import HTTPStatus
from typing import List
from urllib import parse
from wsgiref.simple_server import make_server

import traceback
import logging
import sys
import os

# Add Parent Package to prevent import error
sys.path.insert(1, os.path.join(os.path.dirname(__file__), ".."))

# Import repo modules
from configs.base import config
from pwd_password_client import PwdPasswordClient

def setup_logger():
    # Set up logging
    logger = logging.getLogger("server_logger")

    # create console handler and set level to debug
    ch = logging.StreamHandler()

    # create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    if config.get("debug", False):
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)


    return logger

# Use global logger
logger = setup_logger()

def request_handler(env, start_response) -> List[bytes]:
    """
    Server method
    Args:
        env: environment variables + request data
        start_response: response handler method
    Returns:
        List[bytes]: return a byte array, with encoding message
    """
    headers = [("Content-Type", "text/plain")]

    # Get queryset params
    queryset = parse.parse_qs(env.get("QUERY_STRING"))

    # If no password given in queryset, return 400 Bad Request
    if not queryset or queryset.get(config["param"]) is None:
        return build_response(
            HTTPStatus.BAD_REQUEST, f'{config["param"]} param at queryset needed.', headers, start_response)

    # Get password from queryset
    password = queryset[config["param"]][0]
    client = PwdPasswordClient(config["url"])

    try:
        leaks = client.check_password(password)
    except Exception as e:
        logger.error(traceback.format_exc())
        return build_response(HTTPStatus.BAD_GATEWAY, "Third party resource not available", headers, start_response)

    if leaks:
        return build_response(HTTPStatus.OK, f"Password leaked in {leaks} sites.", headers, start_response)

    return build_response(HTTPStatus.OK, "Password is save", headers, start_response)


def build_response(status_code: int, message: str, headers: list, start_response) -> List[bytes]:
    """
    Builds an http response
    Args:
        status_code(http.HTTPStatus):
            value(int): status code
            phrase(str): status nicename
        message(str): msg to return in response
        headers(list): list of headers
        start_response(method): wsgiref response handler
    Returns:
        List[bytes]: return a byte array, with encoding message
    """
    start_response(f"{status_code.value} {status_code.phrase}", headers)
    return [bytes(message.encode(config["encoding"]))]

if __name__ == "__main__":
    with make_server(config["host"], config["port"], request_handler) as server:
        logger.info(f'Serving on port {config["port"]}...')
        server.serve_forever()
