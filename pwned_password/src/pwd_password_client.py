import posixpath
from hashlib import sha1
from urllib import request

from configs.base import config


class PwdPasswordClient(object):
    def __init__(self, url: str):
        self.__URL = url

    def check_password(self, password: str) -> int:
        """
        Check if password is pwned
        Args:
            password(str): clear password
        Returns:
            int: number of leaks for given password
        """

        pwd_sha1 = sha1(password.encode(config["encoding"])).hexdigest().upper()

        return self.__make_request(pwd_sha1)

    def __make_request(self, pwd_sha1: str) -> int:
        """
        Make request to the DB API
        Args:
            pwd_sha1(str): password sha1
        Returns:
            int: password leaks
            Exception: in case external API doesn't return 200 OK
        """
        # Build URL with sha1
        URL = posixpath.join(self.__URL, self.__get_sha1_pass_prefix(pwd_sha1))

        response = request.urlopen(URL, timeout=config["timeout"])

        if response.status != 200:
            raise Exception(f"{response.status_code} {response.text}")

        return self.__parse_response_text(response.read(), pwd_sha1)

    def __get_sha1_pass_prefix(self, sha1_pass: str) -> str:
        """
        Return first chars by config["prefix_length"]
        Args:
            sha1_pass(str): sha1 password
        Returns:
            str: sha1_pass substring
        """

        return sha1_pass[:config["prefix_length"]]

    def __parse_response_text(self, text: str, pwd_sha1: str) -> int:
        """
        Parse response text and return number of leaks
        Args:
            text(str): text from response
            pwd_sha1(str): sha1 password
        Returns:
            int: number of leaks
        """
        # Cast to string to get substrings
        if isinstance(text, bytes):
            text = text.decode(config["encoding"])

        # Get current pass leaks
        if pwd_sha1[config["prefix_length"]:] in text:
            return int(text[text.index(pwd_sha1[config["prefix_length"]:]):].split("\r\n")[0].split(":")[1])

        # Not leaked
        return 0


if __name__ == "__main__":
    PASS = "1234"

    client = PwdPasswordClient(config["url"])
    leaks = client.check_password(PASS)

    print(f"Pass leaks: {leaks}")
