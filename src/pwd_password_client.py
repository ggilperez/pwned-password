import posixpath
from hashlib import sha1
from urllib import request


class PwdPasswordClient(object):
    # CONSTANTS
    PREFIX_INDEX = 5
    ENCODING = "UTF-8"
    TIMEOUT = 10

    def __init__(self, url: str):
        self.__URL = url

    def check_password(self, password: str) -> int:
        """
        Check if password is pwned
        Args:
            password(str): clear password
        Return:
            int: number of leaks for given password
        """

        pwd_sha1 = sha1(password.encode(self.ENCODING)).hexdigest().upper()

        return self.__make_request(pwd_sha1)

    def __make_request(self, pwd_sha1: str) -> int:
        """
        Make request to the DB API
        Args:
            pwd_sha1(str): password sha1
        """
        # Build URL with sha1
        URL = posixpath.join(self.__URL, self.__get_sha1_pass_prefix(pwd_sha1))

        response = request.urlopen(URL, timeout=self.TIMEOUT)

        if response.status != 200:
            raise Exception(f"{response.status_code} {response.text}")

        return self.__parse_response_text(response.read(), pwd_sha1)

    def __get_sha1_pass_prefix(self, sha1_pass: str) -> str:
        """
        Return first chars by PREFIX_INDEX
        Args:
            sha1_pass(str): sha1 password
        """

        return sha1_pass[:self.PREFIX_INDEX]

    def __parse_response_text(self, text: str, pwd_sha1: str) -> int:
        """
        Parse response text and return number of leaks
        """
        # Cast to string to get substrings
        if isinstance(text, bytes):
            text = text.decode(self.ENCODING)

        # Get current pass leaks
        if pwd_sha1[self.PREFIX_INDEX:] in text:
            return int(text[text.index(pwd_sha1[self.PREFIX_INDEX:]):].split("\r\n")[0].split(":")[1])

        # Not leaked
        return 0


if __name__ == "__main__":
    URL = "https://api.pwnedpasswords.com/range"
    PASS = "1234"

    client = PwdPasswordClient(URL)
    leaks = client.check_password(PASS)

    print(f"Pass leaks: {leaks}")
