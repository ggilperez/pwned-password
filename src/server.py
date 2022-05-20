from urllib import parse
from wsgiref.simple_server import make_server
from pwd_password_client import PwdPasswordClient

# CONSTANTS
ENCODING = "UTF-8"
QUERY_PARAM = "password"


def request_handler(env, start_response):
    headers = [("Content-Type", "text/plain")]

    queryset = parse.parse_qs(env.get("QUERY_STRING"))

    # If no password given, return 400 Bad Request
    if not queryset:
        start_response("400 Bad Request", headers)
        return []

    # Get password from queryset
    password = queryset[QUERY_PARAM][0]
    client = PwdPasswordClient("https://api.pwnedpasswords.com/range")

    try:
        result = client.check_password(password)
    except Exception as e:
        start_response("502 Bad Gateway", headers)
        return []

    start_response("200 OK", headers)

    if result:
        return [f"Password leaked in {result} sites.".encode(ENCODING)]
    return ["Password is save".encode(ENCODING)]


server = make_server("localhost", 8000, request_handler)
server.serve_forever()
