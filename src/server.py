from http import HTTPStatus
from urllib import parse
from wsgiref.simple_server import make_server

from pwd_password_client import PwdPasswordClient

# CONSTANTS
URL = "https://api.pwnedpasswords.com/range"
ENCODING = "UTF-8"
QUERY_PARAM = "password"


def request_handler(env, start_response):
    headers = [("Content-Type", "text/plain")]

    # Get queryset params
    queryset = parse.parse_qs(env.get("QUERY_STRING"))

    # If no password given in queryset, return 400 Bad Request
    if not queryset:
        return build_response(HTTPStatus.BAD_REQUEST, f"{QUERY_PARAM} param at queryset needed.", headers, start_response)

    # Get password from queryset
    password = queryset[QUERY_PARAM][0]
    client = PwdPasswordClient(URL)

    try:
        leaks = client.check_password(password)
    except Exception as e:
        return build_response(HTTPStatus.BAD_GATEWAY, "", headers, start_response)

    if leaks:
        return build_response(HTTPStatus.OK, f"Password leaked in {leaks} sites.", headers, start_response)
        
    return build_response(HTTPStatus.OK, "Password is save", headers, start_response)


def build_response(status_code, message, headers, start_response):
    start_response(f"{status_code.value} {status_code.phrase}", headers)
    return [message.encode(ENCODING)]


server = make_server("localhost", 8000, request_handler)
server.serve_forever()
