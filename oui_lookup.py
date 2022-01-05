import os
import re
import time

from getpass import getuser
from typing import ByteString
from urllib.request import urlopen


USER_HOME = "~" + getuser()
OUI_FILE_STORE = os.path.join(os.path.expanduser(USER_HOME), ".oui-cache")
CACHE_TIME = 2592000  # 30 days update
IEEE_URL = "http://standards-oui.ieee.org/oui/oui.txt"


def strip_mac(mac: ByteString) -> str:
    """
    Clean MAC address byte string and convert it to str
    """
    return "-".join(mac.decode("ascii").split("-")[:3])


def update_cached_oui():
    """
    Download oui file and update its local version
    """
    print("Updating oui_file...")

    with open(OUI_FILE_STORE, "wb") as oui_file:
        for line in urlopen(IEEE_URL).readlines():
            oui_file.write(line)

    print("Finished.")


def get_mac_vendor(mac: ByteString) -> str:
    """
    Return MAC address manufacturer
    """
    mac_to_search_for = strip_mac(mac)

    try:
        if time.time() - os.stat(OUI_FILE_STORE).st_ctime > CACHE_TIME:
            update_cached_oui()

    except OSError as err:
        if err.errno == 2:
            update_cached_oui()

    with open(OUI_FILE_STORE, "r", encoding="utf-8") as oui_file:
        for line in iter(oui_file):
            if re.search(mac_to_search_for, line, re.IGNORECASE):
                return line.split("\t")[2].rstrip()
