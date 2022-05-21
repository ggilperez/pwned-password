from urllib import request

from configs.base import config

PASSWORD = "123"

URL = f'{config["schema"]}://{config["host"]}:{config["port"]}/?{config["param"]}={PASSWORD}'
response = request.urlopen(URL)

print(f"STATUS: {response.status}")
print(f"HEADERS:\r\n{response.headers}")
print(f"DATA: {response.read()}")
