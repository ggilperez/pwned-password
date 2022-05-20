from urllib import request

response = request.urlopen("http://localhost:8000/")

print(f"STATUS: {response.status}")
print(f"HEADERS:\r\n{response.headers}")
print(f"DATA: {response.read()}")
