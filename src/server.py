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
        start_response("400 Bad Request", headers)
        return []

    # Get password from queryset
    password = queryset[QUERY_PARAM][0]
    client = PwdPasswordClient(URL)

    try:
        leaks = client.check_password(password)
    except Exception as e:
        start_response("502 Bad Gateway", headers)
        return []

    start_response("200 OK", headers)

    if leaks:
        return [f"Password leaked in {leaks} sites.".encode(ENCODING)]
    return ["Password is save".encode(ENCODING)]


server = make_server("localhost", 8000, request_handler)
server.serve_forever()
